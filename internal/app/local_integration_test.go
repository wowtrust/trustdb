//go:build integration

package app

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/keystore"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/verify"
	"github.com/wowtrust/trustdb/internal/wal"
)

func TestLocalEngineSubmitCommitVerify(t *testing.T) {
	t.Parallel()

	clientPub, clientPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate client key error = %v", err)
	}
	serverPub, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate server key error = %v", err)
	}
	raw := []byte("trustdb integration payload")
	contentHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, raw)
	if err != nil {
		t.Fatalf("HashBytes() error = %v", err)
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
		t.Fatalf("NewFileClaim() error = %v", err)
	}
	signed, err := claim.Sign(c, clientPriv)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	w, err := wal.OpenWriter(filepath.Join(t.TempDir(), "000000000001.wal"), 1)
	if err != nil {
		t.Fatalf("OpenWriter() error = %v", err)
	}
	defer w.Close()

	engine := LocalEngine{
		ServerID:         "server-a",
		ServerKeyID:      "server-key",
		ClientPublicKey:  clientPub,
		ServerPrivateKey: serverPriv,
		WAL:              w,
		Now:              func() time.Time { return time.Unix(200, 0) },
	}
	record, accepted, _, err := engine.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	bundles, err := engine.CommitBatch("batch-a", time.Unix(200, 0), []model.SignedClaim{signed}, []model.ServerRecord{record}, []model.AcceptedReceipt{accepted})
	if err != nil {
		t.Fatalf("CommitBatch() error = %v", err)
	}
	result, err := verify.ProofBundle(bytes.NewReader(raw), bundles[0], verify.TrustedKeys{
		ClientPublicKey: clientPub,
		ServerPublicKey: serverPub,
	})
	if err != nil {
		t.Fatalf("VerifyProofBundle() error = %v", err)
	}
	if !result.Valid || result.ProofLevel != "L3" {
		t.Fatalf("VerifyProofBundle() result = %+v", result)
	}
}

func TestLocalEngineUsesKeyRegistry(t *testing.T) {
	t.Parallel()

	clientPub, clientPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate client key error = %v", err)
	}
	regPub, regPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate registry key error = %v", err)
	}
	serverPub, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate server key error = %v", err)
	}
	reg, err := keystore.Open(filepath.Join(t.TempDir(), "keys.tdkeys"), "registry-key", regPriv, regPub)
	if err != nil {
		t.Fatalf("keystore.Open() error = %v", err)
	}
	if _, err := reg.RegisterClientKey("tenant-a", "client-a", "client-key", clientPub, time.Unix(50, 0), time.Time{}); err != nil {
		t.Fatalf("RegisterClientKey() error = %v", err)
	}

	raw := []byte("registry backed proof")
	contentHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, raw)
	if err != nil {
		t.Fatalf("HashBytes() error = %v", err)
	}
	c, err := claim.NewFileClaim(
		"tenant-a",
		"client-a",
		"client-key",
		time.Unix(100, 0),
		bytes.Repeat([]byte{1}, 16),
		"idem-registry",
		model.Content{HashAlg: model.DefaultHashAlg, ContentHash: contentHash, ContentLength: int64(len(raw))},
		model.Metadata{EventType: "file.snapshot"},
	)
	if err != nil {
		t.Fatalf("NewFileClaim() error = %v", err)
	}
	signed, err := claim.Sign(c, clientPriv)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	w, err := wal.OpenWriter(filepath.Join(t.TempDir(), "000000000001.wal"), 1)
	if err != nil {
		t.Fatalf("OpenWriter() error = %v", err)
	}
	defer w.Close()
	engine := LocalEngine{
		ServerID:         "server-a",
		ServerKeyID:      "server-key",
		ClientKeys:       reg,
		ServerPrivateKey: serverPriv,
		WAL:              w,
		Now:              func() time.Time { return time.Unix(200, 0) },
	}
	record, accepted, _, err := engine.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if record.Validation.KeyStatus != model.KeyStatusValid {
		t.Fatalf("record key status = %s", record.Validation.KeyStatus)
	}
	bundles, err := engine.CommitBatch("batch-registry", time.Unix(200, 0), []model.SignedClaim{signed}, []model.ServerRecord{record}, []model.AcceptedReceipt{accepted})
	if err != nil {
		t.Fatalf("CommitBatch() error = %v", err)
	}
	result, err := verify.ProofBundle(bytes.NewReader(raw), bundles[0], verify.TrustedKeys{
		ClientPublicKey: clientPub,
		ServerPublicKey: serverPub,
	})
	if err != nil {
		t.Fatalf("VerifyProofBundle() error = %v", err)
	}
	if !result.Valid {
		t.Fatalf("VerifyProofBundle() result = %+v", result)
	}
}
