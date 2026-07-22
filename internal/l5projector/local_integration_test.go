package l5projector_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/globallog"
	"github.com/wowtrust/trustdb/internal/l5projector"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func TestLocalProjectorMaterializesOlderBatchesWithoutBlockingEvidence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := proofstore.LocalStore{Root: t.TempDir()}
	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	const (
		nodeID   = "node-1"
		logID    = "log-1"
		sinkName = "file"
	)
	global, err := globallog.New(globallog.Options{
		Store: store, NodeID: nodeID, LogID: logID, KeyID: "server-key", PrivateKey: privateKey,
		AnchorSinkName: sinkName, Clock: func() time.Time { return time.Unix(100, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("globallog.New: %v", err)
	}
	roots := make([]model.BatchRoot, 5)
	for i := range roots {
		batchID := fmt.Sprintf("batch-%d", i)
		roots[i] = model.BatchRoot{
			SchemaVersion: model.SchemaBatchRoot, BatchID: batchID, BatchRoot: bytes.Repeat([]byte{byte(i + 1)}, 32),
			TreeSize: 1, ClosedAtUnixN: int64(i + 1), NodeID: nodeID, LogID: logID,
		}
		if err := store.PutRecordIndex(ctx, model.RecordIndex{
			SchemaVersion: model.SchemaRecordIndex, RecordID: fmt.Sprintf("record-%d", i), BatchID: batchID,
			NodeID: nodeID, LogID: logID, ProofLevel: "L4", ReceivedAtUnixN: int64(i + 1),
		}); err != nil {
			t.Fatalf("PutRecordIndex %d: %v", i, err)
		}
	}
	sths, err := global.AppendBatchRoots(ctx, roots)
	if err != nil {
		t.Fatalf("AppendBatchRoots: %v", err)
	}
	anchored := sths[len(sths)-1]
	result := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult, NodeID: nodeID, LogID: logID, TreeSize: anchored.TreeSize,
		SinkName: sinkName, AnchorID: "anchor-5", RootHash: append([]byte(nil), anchored.RootHash...), STH: anchored, PublishedAtUnixN: 500,
	}
	if err := store.PutSTHAnchorResult(ctx, result); err != nil {
		t.Fatalf("PutSTHAnchorResult: %v", err)
	}

	// Authoritative proof generation can use the covering anchor immediately;
	// it does not wait for the materialized L5 record-index projection.
	evidence, err := global.Evidence(ctx, "batch-0")
	if err != nil || evidence.AnchorResult == nil || evidence.GlobalProof.TreeSize != anchored.TreeSize {
		t.Fatalf("Evidence before projection=%+v err=%v", evidence, err)
	}
	idx, found, err := store.GetRecordIndex(ctx, "record-0")
	if err != nil || !found || model.RecordIndexProofLevel(idx) != "L4" {
		t.Fatalf("record before projection=%+v found=%v err=%v", idx, found, err)
	}

	projector, err := l5projector.New(l5projector.Config{
		Store: store, Key: model.STHAnchorScheduleKey{NodeID: nodeID, LogID: logID, SinkName: sinkName}, PageSize: 2,
	})
	if err != nil {
		t.Fatalf("l5projector.New: %v", err)
	}
	for {
		progressed, err := projector.ProjectPage(ctx)
		if err != nil {
			t.Fatalf("ProjectPage: %v", err)
		}
		if !progressed {
			break
		}
	}
	for i := range roots {
		idx, found, err := store.GetRecordIndex(ctx, fmt.Sprintf("record-%d", i))
		if err != nil || !found || model.RecordIndexProofLevel(idx) != "L5" {
			t.Fatalf("record-%d after projection=%+v found=%v err=%v", i, idx, found, err)
		}
	}
}
