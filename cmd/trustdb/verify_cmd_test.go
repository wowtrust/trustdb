package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"
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
	"github.com/wowtrust/trustdb/internal/keystore"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/sproof"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/verify"
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

func TestReadVerifyCertificateRootsAcceptsStrictDERAndPEM(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &smx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TrustDB verifier root"},
		NotBefore:             time.Unix(100, 0),
		NotAfter:              time.Unix(200, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              smx509.KeyUsageCertSign,
	}
	der, err := smx509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	derPath := filepath.Join(directory, "root.der")
	if err := os.WriteFile(derPath, der, 0o600); err != nil {
		t.Fatal(err)
	}
	pemPath := filepath.Join(directory, "roots.pem")
	pemData := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...,
	)
	if err := os.WriteFile(pemPath, pemData, 0o600); err != nil {
		t.Fatal(err)
	}

	roots, err := readVerifyCertificateRoots([]string{derPath, pemPath})
	if err != nil {
		t.Fatalf("readVerifyCertificateRoots() error = %v", err)
	}
	if len(roots) != 3 {
		t.Fatalf("readVerifyCertificateRoots() count = %d, want 3", len(roots))
	}
	for index := range roots {
		if !bytes.Equal(roots[index], der) {
			t.Fatalf("root %d differs from input DER", index)
		}
	}

	invalidPath := filepath.Join(directory, "invalid.pem")
	if err := os.WriteFile(invalidPath, append(pemData, []byte("trailing")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readVerifyCertificateRoots([]string{invalidPath}); err == nil {
		t.Fatal("readVerifyCertificateRoots() accepted trailing PEM data")
	}
}

// TestVerifyCmdRemoteLocalAnchorFallsBackToL4 spins up an in-process serve
// backed by a FileSink. The CLI must ignore that local-only result and verify
// the independently checkable global-log evidence at L4.
func TestVerifyCmdRemoteLocalAnchorFallsBackToL4(t *testing.T) {
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
	if !result.Valid || result.ProofLevel != "L4" {
		t.Fatalf("verify result = %+v, want L4 valid", result)
	}
	if result.AnchorSink != "" {
		t.Fatalf("anchor_sink = %q, want empty for local-only FileSink", result.AnchorSink)
	}
	if result.AnchorID != "" {
		t.Fatalf("anchor_id = %q, want empty for local-only FileSink", result.AnchorID)
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

func TestVerifyCmdOfflineFailureEmitsStructuredStagesAndReturnsError(t *testing.T) {
	ctx := context.Background()
	server, _, clientPub, serverPub, contentPath, recordID := runServeForVerify(t, ctx)
	bundle, global, anchorResult := fetchSingleProofInputs(t, ctx, server, recordID)
	proof, err := sproof.New(bundle, sproof.Options{
		GlobalProof:  &global,
		AnchorResult: anchorResult,
	})
	if err != nil {
		t.Fatal(err)
	}
	proofPath := filepath.Join(t.TempDir(), "offline.sproof")
	if err := sproof.WriteFile(proofPath, proof); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(contentPath)
	if err != nil {
		t.Fatal(err)
	}
	content[0] ^= 1
	tamperedContentPath := filepath.Join(t.TempDir(), "tampered-content.bin")
	if err := os.WriteFile(tamperedContentPath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	rt, outBuf := newVerifyRuntime(t)
	cmd := newVerifyCommand(rt)
	cmd.SetArgs([]string{
		"--file", tamperedContentPath,
		"--sproof", proofPath,
		"--client-public-key", writePubKey(t, "client-key", clientPub),
		"--server-public-key", writePubKey(t, "server-key", serverPub),
	})
	cmd.SetContext(ctx)
	verifyErr := cmd.Execute()
	if verifyErr == nil || !strings.Contains(verifyErr.Error(), "content hash mismatch") {
		t.Fatalf("verify error = %v, want original content hash mismatch", verifyErr)
	}

	var result sproof.OfflineResult
	if err := json.Unmarshal(outBuf.Bytes(), &result); err != nil {
		t.Fatalf("decode structured failure: %v (raw=%q)", err, outBuf.String())
	}
	if result.Valid {
		t.Fatalf("structured failure result is valid: %+v", result)
	}
	var contentFailed bool
	for _, stage := range result.Stages {
		if stage.Name == string(verify.StageContent) && stage.Status == sproof.OfflineStageFailed {
			contentFailed = true
			break
		}
	}
	if !contentFailed {
		t.Fatalf("content failure stage is missing: %+v", result.Stages)
	}
}

func TestVerifyCmdOfflineContainerFailureEmitsStructuredResult(t *testing.T) {
	directory := t.TempDir()
	contentPath := filepath.Join(directory, "content.bin")
	if err := os.WriteFile(contentPath, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	publicKeyPath := writePubKey(t, "client-key", mustPub(t))
	rt, outBuf := newVerifyRuntime(t)
	cmd := newVerifyCommand(rt)
	cmd.SetArgs([]string{
		"--file", contentPath,
		"--sproof", filepath.Join(directory, "missing.sproof"),
		"--client-public-key", publicKeyPath,
		"--server-public-key", publicKeyPath,
	})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err == nil {
		t.Fatal("verify missing .sproof error = nil")
	}

	var result sproof.OfflineResult
	if err := json.Unmarshal(outBuf.Bytes(), &result); err != nil {
		t.Fatalf("decode structured container failure: %v (raw=%q)", err, outBuf.String())
	}
	if len(result.Stages) != 11 ||
		result.Stages[0].Name != sproof.OfflineStageContainer ||
		result.Stages[0].Status != sproof.OfflineStageFailed ||
		result.Stages[1].Name != sproof.OfflineStageIdentity ||
		result.Stages[1].Status != sproof.OfflineStageNotRun {
		t.Fatalf("structured container stages = %+v", result.Stages)
	}
}

func TestWriteOfflineVerificationResultPreservesVerificationAndWriteErrors(t *testing.T) {
	verificationErr := errors.New("verification failed")
	outputErr := errors.New("output failed")
	rt := &runtimeConfig{out: failingWriter{err: outputErr}}

	err := writeOfflineVerificationResult(rt, sproof.OfflineResult{}, verificationErr)
	if !errors.Is(err, verificationErr) {
		t.Fatalf("result error %v does not preserve verification error", err)
	}
	if !errors.Is(err, outputErr) {
		t.Fatalf("result error %v does not preserve output error", err)
	}
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

func TestResolveVerifyClientPubUsesClaimSigningTime(t *testing.T) {
	t.Parallel()

	registryPublic, registryPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registrySigner, err := trustcrypto.NewEd25519Signer("registry-key", registryPrivate)
	if err != nil {
		t.Fatal(err)
	}
	registryTrust, err := trustcrypto.NewEd25519PublicKey("registry-key", registryPublic)
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(t.TempDir(), "keys.tdkeys")
	registry, err := keystore.Open(registryPath, registrySigner, registryTrust)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic := mustPub(t)
	_, clientDescriptor, err := readPublicKeyDescriptor(writePubKey(t, "client-key", clientPublic))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RegisterClientKey(
		"tenant-1",
		"client-1",
		clientDescriptor,
		time.Unix(100, 0),
		time.Unix(150, 0),
	); err != nil {
		t.Fatal(err)
	}
	registryPublicPath := writePubKey(t, "registry-key", registryPublic)
	bundle := model.ProofBundle{
		SignedClaim: model.SignedClaim{
			Claim: model.ClientClaim{
				TenantID:        "tenant-1",
				ClientID:        "client-1",
				KeyID:           "client-key",
				ProducedAtUnixN: time.Unix(125, 0).UnixNano(),
			},
		},
		AcceptedReceipt: model.AcceptedReceipt{
			ReceivedAtUnixN: time.Unix(200, 0).UnixNano(),
		},
	}

	resolved, err := resolveVerifyClientPub(bundle, "", registryPath, registryPublicPath)
	if err != nil {
		t.Fatalf("resolveVerifyClientPub() error = %v", err)
	}
	if !bytes.Equal(resolved.Bytes, clientPublic) {
		t.Fatal("resolveVerifyClientPub() returned the wrong signing-time key")
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
	writer, _, err := openBoundTestWALWriter(t, walDir, 0)
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
	proofStore := newBoundTestLocalStore(t, proofDir)
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
	batchSvc := batch.New(engine, proofStore, batch.Options{CryptoSuite: cryptosuite.INTLV1,
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
	resp, err := http.Post(server.URL+"/v2/claims", "application/cbor", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v2/claims: %v", err)
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

type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}
