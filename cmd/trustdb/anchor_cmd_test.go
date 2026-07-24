package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/anchor"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
)

// seedOtsAnchor pre-populates a file-backed proofstore with the immutable
// STHAnchorResult that the OTS sink writes after a successful publication.
// The helper returns the result so tests can diff before/after upgrade without
// reaching into the store a second time.
func seedOtsAnchor(t *testing.T, dir string, calendarURL string) model.STHAnchorResult {
	t.Helper()
	ctx := context.Background()
	store, err := proofstore.Open(newBoundTestProofstoreConfig(proofstore.BackendFile, dir))
	if err != nil {
		t.Fatalf("open file proofstore: %v", err)
	}
	defer store.Close()

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i + 1)
	}
	sth := model.SignedTreeHead{
		CryptoSuite:    cryptosuite.INTLV1,
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       1,
		RootHash:       digest,
		TimestampUnixN: 100,
		Signature:      model.Signature{Alg: model.DefaultSignatureAlg, KeyID: "test", Signature: []byte{1}},
	}
	if err := store.PutSignedTreeHead(ctx, sth); err != nil {
		t.Fatalf("PutSignedTreeHead: %v", err)
	}

	proof := anchor.OtsAnchorProof{
		SchemaVersion: anchor.SchemaOtsAnchorProof,
		TreeSize:      sth.TreeSize,
		HashAlg:       "sha256",
		Digest:        digest,
		Calendars: []anchor.OtsCalendarTimestamp{
			{URL: calendarURL, Accepted: true, RawTimestamp: []byte("pending-bytes"), StatusCode: 200},
		},
		SubmittedAtN: time.Now().UTC().UnixNano(),
	}
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	ar := model.STHAnchorResult{
		CryptoSuite:      cryptosuite.INTLV1,
		SchemaVersion:    model.SchemaSTHAnchorResult,
		EvidenceStage:    model.AnchorEvidenceStageOfflineVerified,
		TreeSize:         sth.TreeSize,
		SinkName:         anchor.OtsSinkName,
		AnchorID:         anchor.DeterministicOtsAnchorID(sth),
		RootHash:         digest,
		STH:              sth,
		Proof:            proofBytes,
		PublishedAtUnixN: time.Now().UTC().UnixNano(),
	}
	putSTHAnchorResult(t, store, ar)
	return ar
}

func putSTHAnchorResult(t *testing.T, store proofstore.Store, result model.STHAnchorResult) {
	t.Helper()
	writer, ok := store.(proofstore.STHAnchorResultWriter)
	if !ok {
		t.Fatal("proofstore does not support immutable anchor result writes")
	}
	if err := writer.PutSTHAnchorResult(context.Background(), result); err != nil {
		t.Fatalf("PutSTHAnchorResult: %v", err)
	}
}

// TestAnchorUpgradeCommand_PersistsUpgradedProof exercises the CLI
// end-to-end against a fake calendar that returns upgraded bytes. We
// verify both the JSON report and the persisted STHAnchorResult so a
// silent "forgot to write back" regression can't hide.
func TestAnchorUpgradeCommand_PersistsUpgradedProof(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	proofDir := filepath.Join(tmp, "proofs")
	upgraded := []byte("upgraded-with-btc-attestation")

	mux := http.NewServeMux()
	mux.HandleFunc("/timestamp/", func(w http.ResponseWriter, r *http.Request) {
		// The CLI sends hex(digest); we don't care which digest, we
		// just need to return the upgraded bytes for any GET here.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upgraded)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	seeded := seedOtsAnchor(t, proofDir, srv.URL)
	store := newBoundTestLocalStore(t, proofDir)
	fileResult := seeded
	fileResult.SinkName = "file"
	fileResult.AnchorID = anchor.DeterministicFileAnchorID(seeded.STH)
	fileResult.Proof = []byte("file-proof-must-remain-unchanged")
	putSTHAnchorResult(t, store, fileResult)
	if err := store.Close(); err != nil {
		t.Fatalf("close seeded proofstore: %v", err)
	}

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{
		"anchor", "upgrade",
		"--tree-size", "1",
		"--metastore-path", proofDir,
		"--crypto-suite", "INTL_V1",
		"--timeout", "5s",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("anchor upgrade: %v stderr=%s", err, errOut.String())
	}
	var report anchorUpgradeReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("report not json: %q err=%v", out.String(), err)
	}
	if !report.Changed || !report.Persisted {
		t.Fatalf("expected changed+persisted, got %+v", report)
	}
	if report.TreeSize != seeded.TreeSize || report.SinkName != anchor.OtsSinkName {
		t.Fatalf("unexpected header: %+v", report)
	}
	if len(report.Calendars) != 1 || !report.Calendars[0].Changed {
		t.Fatalf("per-calendar report missing Changed=true: %+v", report.Calendars)
	}

	reopened := newBoundTestLocalStore(t, proofDir)
	defer reopened.Close()
	keyed, ok := any(reopened).(proofstore.STHAnchorResultKeyedReader)
	if !ok {
		t.Fatal("proofstore does not support keyed anchor result reads")
	}
	got, ok, err := keyed.GetSTHAnchorResultForKey(context.Background(), model.STHAnchorResultKey{
		NodeID: seeded.NodeID, LogID: seeded.LogID, SinkName: seeded.SinkName, TreeSize: seeded.TreeSize,
	})
	if err != nil {
		t.Fatalf("GetSTHAnchorResultForKey: %v", err)
	}
	if !ok {
		t.Fatal("OTS STHAnchorResult missing after upgrade")
	}
	var after anchor.OtsAnchorProof
	if err := json.Unmarshal(got.Proof, &after); err != nil {
		t.Fatalf("decode upgraded proof: %v", err)
	}
	if string(after.Calendars[0].RawTimestamp) != string(upgraded) {
		t.Fatalf("calendar bytes not persisted: %q", after.Calendars[0].RawTimestamp)
	}
	// Digest (set by the original sink) must survive untouched.
	if hex.EncodeToString(after.Digest) != hex.EncodeToString(seeded.RootHash) {
		t.Fatalf("digest mutated across upgrade")
	}
	gotFile, ok, err := keyed.GetSTHAnchorResultForKey(context.Background(), model.STHAnchorResultKey{
		NodeID: fileResult.NodeID, LogID: fileResult.LogID, SinkName: fileResult.SinkName, TreeSize: fileResult.TreeSize,
	})
	if err != nil || !ok || !bytes.Equal(gotFile.Proof, fileResult.Proof) {
		t.Fatalf("file result changed while upgrading ots: result=%+v ok=%v err=%v", gotFile, ok, err)
	}
}

// TestAnchorUpgradeCommand_DryRunDoesNotPersist guards the --dry-run
// contract: report reflects what WOULD happen, but the on-disk
// STHAnchorResult remains byte-identical.
func TestAnchorUpgradeCommand_DryRunDoesNotPersist(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	proofDir := filepath.Join(tmp, "proofs")
	upgraded := []byte("would-be-upgraded")

	mux := http.NewServeMux()
	mux.HandleFunc("/timestamp/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upgraded)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	seeded := seedOtsAnchor(t, proofDir, srv.URL)
	originalProof := append([]byte(nil), seeded.Proof...)

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{
		"anchor", "upgrade",
		"--tree-size", "1",
		"--metastore-path", proofDir,
		"--crypto-suite", "INTL_V1",
		"--dry-run",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("anchor upgrade: %v stderr=%s", err, errOut.String())
	}
	var report anchorUpgradeReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("report not json: %v", err)
	}
	if !report.Changed {
		t.Fatal("expected Changed=true even in dry-run")
	}
	if report.Persisted {
		t.Fatal("dry-run must not persist")
	}
	if !report.DryRun {
		t.Fatal("report.DryRun should echo --dry-run")
	}

	store := newBoundTestLocalStore(t, proofDir)
	got, ok, err := store.GetSTHAnchorResult(context.Background(), seeded.TreeSize)
	if err != nil || !ok {
		t.Fatalf("GetSTHAnchorResult: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(got.Proof, originalProof) {
		t.Fatal("--dry-run mutated the stored proof")
	}
}

// TestAnchorUpgradeCommand_RejectsNonOtsSTH guards against a latent
// footgun: if someone ever wires a non-ots sink into this STH the
// command must refuse to touch it instead of trying to decode an
// alien proof envelope.
func TestAnchorUpgradeCommand_RejectsNonOtsSTH(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	proofDir := filepath.Join(tmp, "proofs")
	ctx := context.Background()
	store, err := proofstore.Open(newBoundTestProofstoreConfig(proofstore.BackendFile, proofDir))
	if err != nil {
		t.Fatalf("open file proofstore: %v", err)
	}

	root := make([]byte, 32)
	root[0] = 0x01
	sth := model.SignedTreeHead{
		CryptoSuite:    cryptosuite.INTLV1,
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       2,
		RootHash:       root,
		TimestampUnixN: 50,
		Signature:      model.Signature{Alg: model.DefaultSignatureAlg, KeyID: "test", Signature: []byte{1}},
	}
	if err := store.PutSignedTreeHead(ctx, sth); err != nil {
		t.Fatalf("PutSignedTreeHead: %v", err)
	}
	ar := model.STHAnchorResult{
		CryptoSuite:      cryptosuite.INTLV1,
		SchemaVersion:    model.SchemaSTHAnchorResult,
		EvidenceStage:    model.AnchorEvidenceStageOfflineVerified,
		TreeSize:         sth.TreeSize,
		SinkName:         "file",
		AnchorID:         "file-test",
		RootHash:         sth.RootHash,
		STH:              sth,
		Proof:            []byte("opaque"),
		PublishedAtUnixN: time.Now().UnixNano(),
	}
	putSTHAnchorResult(t, store, ar)
	if err := store.Close(); err != nil {
		t.Fatalf("close seeded proofstore: %v", err)
	}

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"anchor", "upgrade", "--tree-size", "2", "--metastore-path", proofDir, "--crypto-suite", "INTL_V1"})
	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error for non-ots STH")
	}
	if !strings.Contains(err.Error(), "ots") {
		t.Fatalf("error should mention ots: %v", err)
	}
}

func TestAnchorExportCommand_ExportsCBORForOfflineVerify(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	proofDir := filepath.Join(tmp, "proofs")
	outPath := filepath.Join(tmp, "sth-2.tdsth-anchor-result")
	ctx := context.Background()
	store, err := proofstore.Open(newBoundTestProofstoreConfig(proofstore.BackendFile, proofDir))
	if err != nil {
		t.Fatalf("open file proofstore: %v", err)
	}

	root := bytes.Repeat([]byte{0xaa}, 32)
	sth := model.SignedTreeHead{
		CryptoSuite:    cryptosuite.INTLV1,
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       2,
		RootHash:       root,
		TimestampUnixN: 50,
		Signature:      model.Signature{Alg: model.DefaultSignatureAlg, KeyID: "test", Signature: []byte{1}},
	}
	if err := store.PutSignedTreeHead(ctx, sth); err != nil {
		t.Fatalf("PutSignedTreeHead: %v", err)
	}
	result := model.STHAnchorResult{
		CryptoSuite:      cryptosuite.INTLV1,
		SchemaVersion:    model.SchemaSTHAnchorResult,
		EvidenceStage:    model.AnchorEvidenceStageOfflineVerified,
		TreeSize:         sth.TreeSize,
		SinkName:         "file",
		AnchorID:         anchor.DeterministicFileAnchorID(sth),
		RootHash:         root,
		STH:              sth,
		Proof:            []byte("file-proof"),
		PublishedAtUnixN: time.Now().UnixNano(),
	}
	putSTHAnchorResult(t, store, result)
	if err := store.Close(); err != nil {
		t.Fatalf("close seeded proofstore: %v", err)
	}

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{
		"anchor", "export",
		"--tree-size", "2",
		"--metastore-path", proofDir,
		"--crypto-suite", "INTL_V1",
		"--out", outPath,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("anchor export: %v stderr=%s", err, errOut.String())
	}
	var report struct {
		TreeSize     uint64 `json:"tree_size"`
		SinkName     string `json:"sink_name"`
		AnchorID     string `json:"anchor_id"`
		AnchorResult string `json:"anchor_result"`
		Format       string `json:"format"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("report not json: %q err=%v", out.String(), err)
	}
	if report.TreeSize != 2 || report.SinkName != "file" || report.AnchorID != result.AnchorID || report.AnchorResult != outPath || report.Format != "cbor" {
		t.Fatalf("unexpected report: %+v", report)
	}
	var exported model.STHAnchorResult
	if err := readCBORFile(outPath, &exported); err != nil {
		t.Fatalf("read exported anchor result: %v", err)
	}
	if exported.SchemaVersion != model.SchemaSTHAnchorResult || exported.TreeSize != result.TreeSize || exported.AnchorID != result.AnchorID {
		t.Fatalf("exported anchor = %+v, want %+v", exported, result)
	}
}
