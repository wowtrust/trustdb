package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/app"
	"github.com/wowtrust/trustdb/v2/internal/claim"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/globallog"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
	"github.com/wowtrust/trustdb/v2/internal/wal"
)

type proofBundleFixture struct {
	raw        []byte
	bundle     model.ProofBundle
	keys       TrustedKeys
	serverPriv ed25519.PrivateKey
}

func newProofBundleFixture(t *testing.T) proofBundleFixture {
	t.Helper()
	clientPub, clientPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate client key: %v", err)
	}
	serverPub, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate server key: %v", err)
	}
	raw := []byte("trustdb verify regression payload")
	contentHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, raw)
	if err != nil {
		t.Fatalf("HashBytes: %v", err)
	}
	c, err := claim.NewFileClaim(
		"tenant-a",
		"client-a",
		"client-key",
		time.Unix(100, 0),
		bytes.Repeat([]byte{1}, 16),
		"idem-a",
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
	walPath := filepath.Join(t.TempDir(), "000000000001.wal")
	w, err := wal.OpenWriterWithOptions(walPath, 1, wal.Options{
		CryptoSuite: cryptosuite.INTLV1,
		NodeID:      "server-a",
		LogID:       "log-a",
		NamespaceID: "wal:" + walPath,
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	engine := app.LocalEngine{
		ServerID:        "server-a",
		LogID:           "log-a",
		ServerKeyID:     "server-key",
		ClientPublicKey: trustcrypto.MustNewEd25519PublicKey("", clientPub),
		ServerSigner:    trustcrypto.MustNewEd25519Signer("server-key", serverPriv),
		WAL:             w,
		Now:             func() time.Time { return time.Unix(200, 0) },
	}
	record, accepted, _, err := engine.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	bundles, err := engine.CommitBatch(
		"batch-a",
		time.Unix(300, 0),
		[]model.SignedClaim{signed},
		[]model.ServerRecord{record},
		[]model.AcceptedReceipt{accepted},
	)
	if err != nil {
		t.Fatalf("CommitBatch: %v", err)
	}
	return proofBundleFixture{
		raw:    raw,
		bundle: bundles[0],
		keys: TrustedKeys{
			ClientPublicKey: trustcrypto.MustNewEd25519PublicKey("", clientPub),
			ServerPublicKey: trustcrypto.MustNewEd25519PublicKey("", serverPub),
		},
		serverPriv: serverPriv,
	}
}

func globalProofForBundle(t *testing.T, f proofBundleFixture) model.GlobalLogProof {
	t.Helper()
	ctx := context.Background()
	store := newBoundTestLocalStore(t, t.TempDir())
	svc, err := globallog.New(globallog.Options{
		Store:  store,
		NodeID: f.bundle.NodeID,
		LogID:  f.bundle.LogID,
		Signer: trustcrypto.MustNewEd25519Signer("server-key", f.serverPriv),
		Clock:  func() time.Time { return time.Unix(400, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("globallog.New: %v", err)
	}
	sth, err := svc.AppendBatchRoot(ctx, model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		CryptoSuite:   cryptosuite.INTLV1,
		NodeID:        f.bundle.NodeID,
		LogID:         f.bundle.LogID,
		BatchID:       f.bundle.CommittedReceipt.BatchID,
		BatchRoot:     append([]byte(nil), f.bundle.CommittedReceipt.BatchRoot...),
		TreeSize:      f.bundle.BatchProof.TreeSize,
		ClosedAtUnixN: f.bundle.CommittedReceipt.ClosedAtUnixN,
	})
	if err != nil {
		t.Fatalf("AppendBatchRoot: %v", err)
	}
	proof, err := svc.InclusionProof(ctx, f.bundle.CommittedReceipt.BatchID, sth.TreeSize)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	return proof
}

func TestProofBundleRejectsAcceptedReceiptRecordIDMismatch(t *testing.T) {
	t.Parallel()
	f := newProofBundleFixture(t)
	f.bundle.AcceptedReceipt.RecordID = "tr1wrong"

	_, err := ProofBundle(bytes.NewReader(f.raw), f.bundle, f.keys)
	if err == nil || !strings.Contains(err.Error(), "accepted receipt record_id mismatch") {
		t.Fatalf("ProofBundle error = %v, want accepted receipt record_id mismatch", err)
	}
	if stage, ok := FailedStage(err); !ok || stage != StageBundleBindings {
		t.Fatalf("FailedStage() = %q, %v, want %q", stage, ok, StageBundleBindings)
	}
}

func TestProofBundleRejectsCommittedReceiptRecordIDMismatch(t *testing.T) {
	t.Parallel()
	f := newProofBundleFixture(t)
	f.bundle.CommittedReceipt.RecordID = "tr1wrong"

	_, err := ProofBundle(bytes.NewReader(f.raw), f.bundle, f.keys)
	if err == nil || !strings.Contains(err.Error(), "committed receipt record_id mismatch") {
		t.Fatalf("ProofBundle error = %v, want committed receipt record_id mismatch", err)
	}
	if stage, ok := FailedStage(err); !ok || stage != StageBundleBindings {
		t.Fatalf("FailedStage() = %q, %v, want %q", stage, ok, StageBundleBindings)
	}
}

func TestProofBundleReportsContentFailureStage(t *testing.T) {
	t.Parallel()
	f := newProofBundleFixture(t)

	_, err := ProofBundle(bytes.NewReader(append(f.raw, '!')), f.bundle, f.keys)
	if err == nil {
		t.Fatal("ProofBundle(tampered content) error = nil")
	}
	if stage, ok := FailedStage(err); !ok || stage != StageContent {
		t.Fatalf("FailedStage() = %q, %v, want %q", stage, ok, StageContent)
	}
}

func TestProofBundleVerifiesGlobalLogSTHSignature(t *testing.T) {
	t.Parallel()
	f := newProofBundleFixture(t)
	proof := globalProofForBundle(t, f)

	result, err := ProofBundle(bytes.NewReader(f.raw), f.bundle, f.keys, WithGlobalProof(proof))
	if err != nil {
		t.Fatalf("ProofBundle with global proof: %v", err)
	}
	if result.ProofLevel != "L4" {
		t.Fatalf("ProofLevel = %s, want L4", result.ProofLevel)
	}

	proof.STH.Signature.Signature[0] ^= 0xff
	_, err = ProofBundle(bytes.NewReader(f.raw), f.bundle, f.keys, WithGlobalProof(proof))
	if err == nil || !strings.Contains(err.Error(), "verify signed tree head") {
		t.Fatalf("ProofBundle tampered STH error = %v, want signed tree head verification error", err)
	}
	if stage, ok := FailedStage(err); !ok || stage != StageGlobalLog {
		t.Fatalf("FailedStage() = %q, %v, want %q", stage, ok, StageGlobalLog)
	}
}
