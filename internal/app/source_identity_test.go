package app

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/wal"
)

func TestLocalEnginePropagatesSourceIdentity(t *testing.T) {
	t.Parallel()

	clientPub, clientPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate client key error = %v", err)
	}
	_, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate server key error = %v", err)
	}
	raw := []byte("source identity payload")
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
		"idem-source",
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
		ServerID:         "node-a",
		LogID:            "log-a",
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
	bundles, err := engine.CommitBatch(
		"batch-a",
		time.Unix(200, 0),
		[]model.SignedClaim{signed},
		[]model.ServerRecord{record},
		[]model.AcceptedReceipt{accepted},
	)
	if err != nil {
		t.Fatalf("CommitBatch() error = %v", err)
	}
	bundle := bundles[0]
	if bundle.NodeID != "node-a" || bundle.LogID != "log-a" {
		t.Fatalf("bundle source = (%q,%q), want (node-a,log-a)", bundle.NodeID, bundle.LogID)
	}
	if bundle.CommittedReceipt.NodeID != "node-a" || bundle.CommittedReceipt.LogID != "log-a" {
		t.Fatalf("committed source = (%q,%q)", bundle.CommittedReceipt.NodeID, bundle.CommittedReceipt.LogID)
	}
	idx := model.RecordIndexFromBundle(bundle)
	if idx.NodeID != "node-a" || idx.LogID != "log-a" {
		t.Fatalf("record index source = (%q,%q)", idx.NodeID, idx.LogID)
	}
	root, indexes, err := engine.CommitBatchIndexes(
		"batch-index-a",
		time.Unix(200, 0),
		[]model.SignedClaim{signed},
		[]model.ServerRecord{record},
		[]model.AcceptedReceipt{accepted},
	)
	if err != nil {
		t.Fatalf("CommitBatchIndexes() error = %v", err)
	}
	if root.NodeID != "node-a" || root.LogID != "log-a" {
		t.Fatalf("index root source = (%q,%q)", root.NodeID, root.LogID)
	}
	if indexes[0].NodeID != "node-a" || indexes[0].LogID != "log-a" {
		t.Fatalf("index source = (%q,%q)", indexes[0].NodeID, indexes[0].LogID)
	}
}
