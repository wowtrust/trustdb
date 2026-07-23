package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/wowtrust/trustdb/internal/anchor"
	"github.com/wowtrust/trustdb/internal/app"
	"github.com/wowtrust/trustdb/internal/batch"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/globallog"
	"github.com/wowtrust/trustdb/internal/httpapi"
	"github.com/wowtrust/trustdb/internal/ingest"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/sproof"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/wal"
)

func TestDecodeSingleJSONRejectsTrailingData(t *testing.T) {
	t.Parallel()
	var dst map[string]bool
	err := decodeSingleJSON(bytes.NewBufferString(`{"ok":true}{}`), &dst)
	if err == nil {
		t.Fatal("decodeSingleJSON() error = nil, want trailing JSON rejection")
	}
}

func TestDecodeSingleJSONLimitBoundsResponseBody(t *testing.T) {
	t.Parallel()
	data := []byte(`{"ok":true}`)

	var dst map[string]bool
	if err := decodeSingleJSONLimit(bytes.NewReader(data), &dst, int64(len(data))); err != nil {
		t.Fatalf("decodeSingleJSONLimit exact boundary: %v", err)
	}
	if !dst["ok"] {
		t.Fatalf("decoded response = %#v", dst)
	}

	oversized := append(append([]byte(nil), data...), ' ')
	if err := decodeSingleJSONLimit(bytes.NewReader(oversized), &dst, int64(len(data))); err == nil {
		t.Fatal("decodeSingleJSONLimit oversized response error = nil")
	}
}

// TestVerifyCmdRemoteAnchor spins up an in-process serve backed by a
// FileSink, submits a single claim, waits for the L5 anchor to be
// published, then invokes `trustdb verify --server=... --record=...`
// and asserts the command reports ProofLevel=L5. This catches every
// seam the verify CLI relies on in a single run 鈥?HTTP decoding of
// the proof envelope, optional anchor fetch, AnchorConsistency 鈥?// without mocking anything inside the verify package itself.
func TestVerifyCmdRemoteAnchor(t *testing.T) {
	ctx := context.Background()

	server, clientPriv, clientPub, serverPub, contentPath, recordID := runServeForVerify(t, ctx)

	clientPubPath := writePubKey(t, "client-key", clientPub)
	serverPubPath := writePubKey(t, "server-key", serverPub)
	_ = clientPriv // captured so it stays alive for the server's lifetime

	rt, outBuf := newVerifyRuntime(t)
	cmd := newVerifyCommand(rt)
	cmd.SetArgs([]string{
		"--file", contentPath,
		"--server", server.URL,
		"--record", recordID,
		"--client-public-key", clientPubPath,
		"--server-public-key", serverPubPath,
	})
	cmd.SetContext(ctx)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify: %v", err)
	}

	var result struct {
		Valid      bool   `json:"valid"`
		RecordID   string `json:"record_id"`
		ProofLevel string `json:"proof_level"`
		AnchorSink string `json:"anchor_sink"`
		AnchorID   string `json:"anchor_id"`
	}
	if err := json.Unmarshal(outBuf.Bytes(), &result); err != nil {
		t.Fatalf("decode output: %v (raw=%q)", err, outBuf.String())
	}
	if !result.Valid || result.ProofLevel != "L5" {
		t.Fatalf("verify result = %+v, want L5 valid", result)
	}
	if result.AnchorSink != anchor.FileSinkName {
		t.Fatalf("anchor_sink = %q, want %q", result.AnchorSink, anchor.FileSinkName)
	}
	if result.AnchorID == "" {
		t.Fatalf("anchor_id empty, want non-empty")
	}
	if result.RecordID != recordID {
		t.Fatalf("record_id = %q, want %q", result.RecordID, recordID)
	}
}

// TestVerifyCmdRemoteSkipAnchor exercises the same remote flow but
// with --skip-anchor so the command still verifies L4 global-log evidence
// while ignoring the published L5 anchor.
func TestVerifyCmdRemoteSkipAnchor(t *testing.T) {
	ctx := context.Background()

	server, _, clientPub, serverPub, contentPath, recordID := runServeForVerify(t, ctx)

	rt, outBuf := newVerifyRuntime(t)
	cmd := newVerifyCommand(rt)
	cmd.SetArgs([]string{
		"--file", contentPath,
		"--server", server.URL,
		"--record", recordID,
		"--client-public-key", writePubKey(t, "client-key", clientPub),
		"--server-public-key", writePubKey(t, "server-key", serverPub),
		"--skip-anchor",
	})
	cmd.SetContext(ctx)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify: %v", err)
	}

	var result struct {
		Valid      bool   `json:"valid"`
		ProofLevel string `json:"proof_level"`
	}
	if err := json.Unmarshal(outBuf.Bytes(), &result); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if !result.Valid || result.ProofLevel != "L4" {
		t.Fatalf("verify result = %+v, want L4 valid", result)
	}
}

func TestVerifyCmdLocalSingleProof(t *testing.T) {
	ctx := context.Background()

	server, _, clientPub, serverPub, contentPath, recordID := runServeForVerify(t, ctx)
	bundle, global, anchorResult := fetchSingleProofInputs(t, ctx, server, recordID)
	single, err := sproof.New(bundle, sproof.Options{
		GlobalProof:     &global,
		AnchorResult:    anchorResult,
		ExportedAtUnixN: time.Unix(600, 0).UnixNano(),
	})
	if err != nil {
		t.Fatalf("sproof.New: %v", err)
	}
	sproofPath := filepath.Join(t.TempDir(), "proof.sproof")
	if err := sproof.WriteFile(sproofPath, single); err != nil {
		t.Fatalf("sproof.WriteFile: %v", err)
	}

	t.Run("default verifies L5", func(t *testing.T) {
		rt, outBuf := newVerifyRuntime(t)
		cmd := newVerifyCommand(rt)
		cmd.SetArgs([]string{
			"--file", contentPath,
			"--sproof", sproofPath,
			"--client-public-key", writePubKey(t, "client-key", clientPub),
			"--server-public-key", writePubKey(t, "server-key", serverPub),
		})
		cmd.SetContext(ctx)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("verify: %v", err)
		}
		assertVerifyLevel(t, outBuf, "L5")
	})

	t.Run("skip anchor stops at L4", func(t *testing.T) {
		rt, outBuf := newVerifyRuntime(t)
		cmd := newVerifyCommand(rt)
		cmd.SetArgs([]string{
			"--file", contentPath,
			"--sproof", sproofPath,
			"--client-public-key", writePubKey(t, "client-key", clientPub),
			"--server-public-key", writePubKey(t, "server-key", serverPub),
			"--skip-anchor",
		})
		cmd.SetContext(ctx)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("verify: %v", err)
		}
		assertVerifyLevel(t, outBuf, "L4")
	})
}

// TestVerifyCmdRejectsConflictingFlags asserts the CLI guards against
// obviously-broken flag combinations before doing any IO.
func TestVerifyCmdRejectsConflictingFlags(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pub := writePubKey(t, "client-key", mustPub(t))
	cases := []struct {
		name string
		args []string
	}{
		{
			name: "both proof and server",
			args: []string{
				"--file", filepath.Join(dir, "file.txt"),
				"--proof", filepath.Join(dir, "bundle.tdproof"),
				"--server", "http://localhost:9",
				"--record", "r",
				"--client-public-key", pub,
				"--server-public-key", pub,
			},
		},
		{
			name: "sproof with server",
			args: []string{
				"--file", filepath.Join(dir, "file.txt"),
				"--sproof", filepath.Join(dir, "proof.sproof"),
				"--server", "http://localhost:9",
				"--record", "r",
				"--client-public-key", pub,
				"--server-public-key", pub,
			},
		},
		{
			name: "sproof with proof",
			args: []string{
				"--file", filepath.Join(dir, "file.txt"),
				"--sproof", filepath.Join(dir, "proof.sproof"),
				"--proof", filepath.Join(dir, "bundle.tdproof"),
				"--client-public-key", pub,
				"--server-public-key", pub,
			},
		},
		{
			name: "sproof with global proof",
			args: []string{
				"--file", filepath.Join(dir, "file.txt"),
				"--sproof", filepath.Join(dir, "proof.sproof"),
				"--global-proof", filepath.Join(dir, "global.tdgproof"),
				"--client-public-key", pub,
				"--server-public-key", pub,
			},
		},
		{
			name: "server without record",
			args: []string{
				"--file", filepath.Join(dir, "file.txt"),
				"--server", "http://localhost:9",
				"--client-public-key", pub,
				"--server-public-key", pub,
			},
		},
		{
			name: "anchor in server mode",
			args: []string{
				"--file", filepath.Join(dir, "file.txt"),
				"--server", "http://localhost:9",
				"--record", "r",
				"--anchor", filepath.Join(dir, "anchor.cbor"),
				"--client-public-key", pub,
				"--server-public-key", pub,
			},
		},
		{
			name: "neither proof nor server",
			args: []string{
				"--file", filepath.Join(dir, "file.txt"),
				"--client-public-key", pub,
				"--server-public-key", pub,
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rt, _ := newVerifyRuntime(t)
			cmd := newVerifyCommand(rt)
			cmd.SetArgs(tc.args)
			cmd.SetContext(context.Background())
			if err := cmd.Execute(); err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestResolveVerifyClientPubPrefersExplicitKey(t *testing.T) {
	t.Parallel()
	pub := mustPub(t)
	pubPath := writePubKey(t, "client-key", pub)
	missingRegistry := filepath.Join(t.TempDir(), "missing-registry.cbor")

	got, err := resolveVerifyClientPub(model.ProofBundle{}, pubPath, missingRegistry, "")
	if err != nil {
		t.Fatalf("resolveVerifyClientPub: %v", err)
	}
	if !bytes.Equal(got.Bytes, pub) {
		t.Fatal("resolveVerifyClientPub did not return the explicit client public key")
	}
}

func fetchSingleProofInputs(
	t *testing.T,
	ctx context.Context,
	server *httptest.Server,
	recordID string,
) (model.ProofBundle, model.GlobalLogProof, *model.STHAnchorResult) {
	t.Helper()
	client := server.Client()
	bundle, err := fetchProofBundle(ctx, client, server.URL, recordID)
	if err != nil {
		t.Fatalf("fetchProofBundle: %v", err)
	}
	global, err := fetchGlobalProof(ctx, client, server.URL, bundle.CommittedReceipt.BatchID)
	if err != nil {
		t.Fatalf("fetchGlobalProof: %v", err)
	}
	anchorResult, err := fetchAnchorResult(ctx, client, server.URL, global.STH.TreeSize)
	if err != nil {
		t.Fatalf("fetchAnchorResult: %v", err)
	}
	if anchorResult == nil {
		t.Fatalf("fetchAnchorResult returned nil, want published anchor")
	}
	return bundle, global, anchorResult
}

func assertVerifyLevel(t *testing.T, out *bytes.Buffer, want string) {
	t.Helper()
	var result struct {
		Valid      bool   `json:"valid"`
		ProofLevel string `json:"proof_level"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("decode verify output: %v (raw=%q)", err, out.String())
	}
	if !result.Valid || result.ProofLevel != want {
		t.Fatalf("verify result = %+v, want valid %s", result, want)
	}
}

// runServeForVerify wires up a minimal but real L1鈫扡5 pipeline
// (engine + ingest + batch + anchor) so the verify CLI can talk to a
// genuine HTTP surface. Returns a running httptest.Server plus every
// credential the verify command needs.
func runServeForVerify(t *testing.T, ctx context.Context) (*httptest.Server, ed25519.PrivateKey, ed25519.PublicKey, ed25519.PublicKey, string, string) {
	t.Helper()

	clientPub, clientPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key client: %v", err)
	}
	serverPub, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key server: %v", err)
	}

	tmp := t.TempDir()
	walDir := filepath.Join(tmp, "wal")
	proofDir := filepath.Join(tmp, "proofs")
	anchorPath := filepath.Join(tmp, "anchors.jsonl")

	_, metrics := observability.NewRegistry()
	writer, _, err := openWALWriterWithOptions(walDir, wal.Options{})
	if err != nil {
		t.Fatalf("openWALWriterWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	engine := app.LocalEngine{
		ServerID:        "server-verify",
		LogID:           "server-verify",
		ServerKeyID:     "server-key",
		ClientPublicKey: trustcrypto.MustNewEd25519PublicKey("", clientPub),
		ServerSigner:    trustcrypto.MustNewEd25519Signer("server-key", serverPriv),
		WAL:             writer,
		Idempotency:     app.NewIdempotencyIndex(),
		Now:             func() time.Time { return time.Unix(500, 0) },
	}
	proofStore := proofstore.LocalStore{Root: proofDir}
	ingestSvc := ingest.New(engine, ingest.Options{QueueSize: 4, Workers: 1}, metrics)
	t.Cleanup(func() { _ = ingestSvc.Shutdown(context.Background()) })

	sink, err := anchor.NewFileSink(anchorPath)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	anchorKey := model.STHAnchorScheduleKey{
		NodeID: engine.ServerID, LogID: engine.ServerID, SinkName: sink.Name(),
	}
	anchorSvc, err := anchor.NewService(anchor.Config{
		Sink:         sink,
		Store:        proofStore,
		Key:          anchorKey,
		Metrics:      metrics,
		PollInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	anchorSvc.Start(ctx)
	t.Cleanup(anchorSvc.Stop)

	rt := &runtimeConfig{logger: silentLogger()}
	globalSvc, err := globallog.New(globallog.Options{
		Store:  proofStore,
		NodeID: engine.ServerID,
		LogID:  engine.ServerID,
		Signer: trustcrypto.MustNewEd25519Signer(engine.ServerKeyID, serverPriv),
	})
	if err != nil {
		t.Fatalf("globallog.New: %v", err)
	}
	globalOutbox := globallog.NewOutboxWorker(globallog.OutboxConfig{
		Store:          proofStore,
		Global:         globalSvc,
		AnchorKey:      &anchorKey,
		AnchorMaxDelay: 20 * time.Millisecond,
		OnAnchorReady:  anchorSvc.Trigger,
		PollInterval:   20 * time.Millisecond,
	})
	globalOutbox.Start(ctx)
	t.Cleanup(globalOutbox.Stop)
	batchSvc := batch.New(engine, proofStore, batch.Options{
		QueueSize:        4,
		MaxRecords:       1, // force immediate commit per claim
		MaxDelay:         20 * time.Millisecond,
		OnBatchCommitted: newGlobalLogEnqueueHook(rt, proofStore, globalOutbox),
	}, metrics)
	t.Cleanup(func() { _ = batchSvc.Shutdown(context.Background()) })

	handler := httpapi.NewWithGlobalAndAnchors(ingestSvc, nil, batchSvc, globalSvc, anchor.NewAPI(proofStore))
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	raw := bytes.Repeat([]byte{'v'}, 64)
	contentPath := filepath.Join(tmp, "content.bin")
	if err := os.WriteFile(contentPath, raw, 0o600); err != nil {
		t.Fatalf("write content: %v", err)
	}
	contentHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, raw)
	if err != nil {
		t.Fatalf("HashBytes: %v", err)
	}
	c, err := claim.NewFileClaim(
		"tenant-verify",
		"client-verify",
		"client-key",
		time.Unix(2500, 0),
		bytes.Repeat([]byte{0x11}, 16),
		"idem-verify",
		model.Content{HashAlg: model.DefaultHashAlg, ContentHash: contentHash, ContentLength: int64(len(raw))},
		model.Metadata{EventType: "file.snapshot"},
	)
	if err != nil {
		t.Fatalf("NewFileClaim: %v", err)
	}
	signed, err := claim.Sign(c, clientPriv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	body, err := cborx.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	resp, err := http.Post(server.URL+"/v1/claims", "application/cbor", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/claims: %v", err)
	}
	var decoded struct {
		RecordID string `json:"record_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		resp.Body.Close()
		t.Fatalf("decode submit: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("submit status = %d", resp.StatusCode)
	}

	waitForHTTPProof(t, server.URL, decoded.RecordID)
	waitForMetric(t, func() bool {
		return testutil.ToFloat64(metrics.AnchorPublished.WithLabelValues(anchor.FileSinkName)) >= 1
	}, "anchor published >= 1")

	return server, clientPriv, clientPub, serverPub, contentPath, decoded.RecordID
}

// newVerifyRuntime returns a runtimeConfig whose stdout is a bytes
// buffer so tests can assert the JSON the verify command prints.
// Writing to the returned buffer is what writeJSON ultimately does,
// so capturing it at the runtimeConfig level is the least invasive
// way to observe the CLI result.
func newVerifyRuntime(t *testing.T) (*runtimeConfig, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	return &runtimeConfig{
		out:    buf,
		errOut: &bytes.Buffer{},
		logger: silentLogger(),
	}, buf
}

// writePubKey serialises an Ed25519 verifier descriptor using the same helper
// as the CLI tests.
func writePubKey(t *testing.T, keyID string, pub ed25519.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), keyID+".pub")
	descriptor := keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindVerifier,
		Provider:      keydescriptor.ProviderPublic,
		CryptoSuite:   cryptosuite.INTLV1,
		KeyID:         keyID,
		Algorithm:     cryptosuite.SignatureEd25519,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: cryptosuite.Ed25519PublicKeyEncoding,
			Bytes:    append([]byte(nil), pub...),
		},
	}
	if err := writeKeyDescriptor(path, descriptor); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}
	return path
}

func mustPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	return pub
}
