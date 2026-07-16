package pebble

import (
	"context"
	"fmt"
	"testing"
	"time"

	pdb "github.com/cockroachdb/pebble"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

func TestBatchTreeSnapshotUsesFortyTiles(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const leafCount = 8192
	snapshot := model.BatchTreeSnapshot{
		BatchID:        "batch-8192",
		CreatedAtUnixN: time.Now().UnixNano(),
		RecordIDs:      make([]string, leafCount),
		LeafHashes:     make([][32]byte, leafCount),
	}
	for i := 0; i < leafCount; i++ {
		snapshot.RecordIDs[i] = fmt.Sprintf("record-%05d", i)
		snapshot.LeafHashes[i][0] = byte(i)
	}
	for level, width := uint64(0), uint64(1); width <= leafCount; level, width = level+1, width*2 {
		for start := uint64(0); start < leafCount; start += width {
			node := model.BatchTreeSnapshotNode{Level: level, StartIndex: start, Width: width}
			node.Hash[0] = byte(level)
			snapshot.Nodes = append(snapshot.Nodes, node)
		}
	}
	if err := store.PutBatchTreeSnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if got := countKeysWithPrefix(t, store, prefixBatchTreeLeaf); got != 16 {
		t.Fatalf("leaf tiles=%d want=16", got)
	}
	if got := countKeysWithPrefix(t, store, prefixBatchTreeNode); got != 24 {
		t.Fatalf("node tiles=%d want=24", got)
	}
	levelZero, err := store.ListBatchTreeNodes(context.Background(), model.BatchTreeNodeListOptions{BatchID: snapshot.BatchID, Level: 0, Limit: 2})
	if err != nil || len(levelZero) != 2 || levelZero[1].StartIndex != 1 {
		t.Fatalf("level zero=%+v err=%v", levelZero, err)
	}
	root, err := store.ListBatchTreeNodes(context.Background(), model.BatchTreeNodeListOptions{BatchID: snapshot.BatchID, Level: 13, Limit: 1})
	if err != nil || len(root) != 1 || root[0].Width != leafCount {
		t.Fatalf("root=%+v err=%v", root, err)
	}
}

func TestOpenRejectsLegacySchema(t *testing.T) {
	dir := t.TempDir()
	db, err := pdb.Open(dir, &pdb.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Set([]byte("legacy/key"), []byte("legacy"), pdb.Sync); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(dir)
	if store != nil {
		_ = store.Close()
	}
	if trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("Open legacy code=%s err=%v", trusterr.CodeOf(err), err)
	}
}

func BenchmarkMaterializedArtifactsTimeOnly1024(b *testing.B) {
	store, err := OpenWithOptions(b.TempDir(), Options{RecordIndexMode: RecordIndexModeTimeOnly, ArtifactSyncMode: ArtifactSyncModeBatch})
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()
	bundles := syntheticProofBundles(1024)
	indexes := make([]model.RecordIndex, len(bundles))
	for i := range bundles {
		indexes[i] = model.RecordIndexFromBundle(bundles[i])
		indexes[i].ProofLevel = "L2"
	}
	root := model.BatchRoot{SchemaVersion: model.SchemaBatchRoot, BatchID: bundles[0].CommittedReceipt.BatchID, BatchRoot: bundles[0].CommittedReceipt.BatchRoot, TreeSize: uint64(len(bundles)), ClosedAtUnixN: bundles[0].CommittedReceipt.ClosedAtUnixN}
	if err := store.PutPreparedBatchIndexesAndRoot(context.Background(), indexes, root); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := store.PutMaterializedBatchArtifacts(context.Background(), bundles); err != nil {
			b.Fatal(err)
		}
	}
}
