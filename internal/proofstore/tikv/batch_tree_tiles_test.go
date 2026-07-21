package tikv

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

func TestBatchTreeSnapshotUsesFortyTilesInOneTransaction(t *testing.T) {
	db, countingClient := newMockTiKVDB(t, "batch-tree-tiles/")
	store := &Store{db: db}
	const leafCount = 8192
	snapshot := model.BatchTreeSnapshot{
		BatchID:        "batch-8192",
		CreatedAtUnixN: time.Now().UnixNano(),
		RecordIDs:      make([]string, leafCount),
		LeafHashes:     make([][32]byte, leafCount),
	}
	for i := range leafCount {
		snapshot.RecordIDs[i] = fmt.Sprintf("record-%05d", i)
		snapshot.LeafHashes[i][0] = byte(i)
	}
	for level, width := uint64(0), uint64(1); width <= leafCount; level, width = level+1, width*2 {
		for start := uint64(0); start < leafCount; start += width {
			node := model.BatchTreeSnapshotNode{Level: level, StartIndex: start, Width: width}
			if level == 0 {
				node.Hash = snapshot.LeafHashes[start]
			} else {
				node.Hash[0] = byte(level)
			}
			snapshot.Nodes = append(snapshot.Nodes, node)
		}
	}

	countingClient.resetWriteRequests()
	if err := store.PutBatchTreeSnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("PutBatchTreeSnapshot: %v", err)
	}
	if got := countKeysWithPrefix(t, store, prefixBatchTreeLeaf); got != 16 {
		t.Fatalf("leaf tiles = %d, want 16", got)
	}
	if got := countKeysWithPrefix(t, store, prefixBatchTreeNode); got != 24 {
		t.Fatalf("node tiles = %d, want 24", got)
	}
	if got := countingClient.prewriteTransactions.Load(); got != 1 {
		t.Fatalf("prewrite transactions = %d, want 1", got)
	}
	if got := countingClient.prewriteMutations.Load(); got != 40 {
		t.Fatalf("prewrite mutations = %d, want 40", got)
	}

	leaves, err := store.ListBatchTreeLeaves(context.Background(), model.BatchTreeLeafListOptions{
		BatchID:        snapshot.BatchID,
		Limit:          2,
		AfterLeafIndex: 4095,
		HasAfter:       true,
	})
	if err != nil || len(leaves) != 2 || leaves[0].LeafIndex != 4096 || leaves[1].LeafIndex != 4097 {
		t.Fatalf("cursor leaves = %+v, err=%v", leaves, err)
	}
	if !bytes.Equal(leaves[0].LeafHash, snapshot.LeafHashes[4096][:]) {
		t.Fatalf("leaf hash differs: got=%x want=%x", leaves[0].LeafHash, snapshot.LeafHashes[4096])
	}
	allLeaves := readAllBatchTreeLeaves(t, store, snapshot.BatchID)
	if len(allLeaves) != leafCount {
		t.Fatalf("all leaves = %d, want %d", len(allLeaves), leafCount)
	}
	for i := range allLeaves {
		if allLeaves[i].LeafIndex != uint64(i) || allLeaves[i].RecordID != snapshot.RecordIDs[i] || !bytes.Equal(allLeaves[i].LeafHash, snapshot.LeafHashes[i][:]) {
			t.Fatalf("leaf %d differs: %+v", i, allLeaves[i])
		}
	}
	levelZero, err := store.ListBatchTreeNodes(context.Background(), model.BatchTreeNodeListOptions{BatchID: snapshot.BatchID, Level: 0, StartIndex: 4096, Limit: 2})
	if err != nil || len(levelZero) != 2 || levelZero[0].StartIndex != 4096 || !bytes.Equal(levelZero[0].Hash, snapshot.LeafHashes[4096][:]) {
		t.Fatalf("level-zero nodes = %+v, err=%v", levelZero, err)
	}
	root, err := store.ListBatchTreeNodes(context.Background(), model.BatchTreeNodeListOptions{BatchID: snapshot.BatchID, Level: 13, Limit: 1})
	if err != nil || len(root) != 1 || root[0].Width != leafCount || !bytes.Equal(root[0].Hash, snapshot.Nodes[len(snapshot.Nodes)-1].Hash[:]) {
		t.Fatalf("root = %+v, err=%v", root, err)
	}
	for level := uint64(0); level <= 13; level++ {
		got := readAllBatchTreeNodes(t, store, snapshot.BatchID, level)
		want := make([]model.BatchTreeSnapshotNode, 0)
		for i := range snapshot.Nodes {
			if snapshot.Nodes[i].Level == level {
				want = append(want, snapshot.Nodes[i])
			}
		}
		if len(got) != len(want) {
			t.Fatalf("level %d nodes = %d, want %d", level, len(got), len(want))
		}
		for i := range got {
			if got[i].StartIndex != want[i].StartIndex || got[i].Width != want[i].Width || !bytes.Equal(got[i].Hash, want[i].Hash[:]) {
				t.Fatalf("level %d node %d differs: got=%+v want=%+v", level, i, got[i], want[i])
			}
		}
	}
}

func readAllBatchTreeLeaves(t *testing.T, store *Store, batchID string) []model.BatchTreeLeaf {
	t.Helper()
	var leaves []model.BatchTreeLeaf
	opts := model.BatchTreeLeafListOptions{BatchID: batchID, Limit: 1000}
	for {
		page, err := store.ListBatchTreeLeaves(context.Background(), opts)
		if err != nil {
			t.Fatalf("ListBatchTreeLeaves: %v", err)
		}
		leaves = append(leaves, page...)
		if len(page) < opts.Limit {
			return leaves
		}
		opts.AfterLeafIndex = page[len(page)-1].LeafIndex
		opts.HasAfter = true
	}
}

func readAllBatchTreeNodes(t *testing.T, store *Store, batchID string, level uint64) []model.BatchTreeNode {
	t.Helper()
	var nodes []model.BatchTreeNode
	opts := model.BatchTreeNodeListOptions{BatchID: batchID, Level: level, Limit: 1000}
	for {
		page, err := store.ListBatchTreeNodes(context.Background(), opts)
		if err != nil {
			t.Fatalf("ListBatchTreeNodes(level=%d): %v", level, err)
		}
		nodes = append(nodes, page...)
		if len(page) < opts.Limit {
			return nodes
		}
		opts.AfterStartIndex = page[len(page)-1].StartIndex
		opts.HasAfter = true
	}
}

func TestBatchTreeTileReadsRejectCorruptSchema(t *testing.T) {
	db, _ := newMockTiKVDB(t, "batch-tree-corrupt/")
	store := &Store{db: db}
	tile := batchTreeLeafTile{
		SchemaVersion: "trustdb.batch-tree-leaf-tile.invalid",
		BatchID:       "corrupt",
		StartIndex:    0,
		LeafIndexes:   []uint64{0},
		RecordIDs:     []string{"record-0"},
		Hashes:        [][]byte{{1}},
	}
	if err := store.writeCBOR(batchTreeLeafKey(tile.BatchID, tile.StartIndex), tile); err != nil {
		t.Fatalf("write corrupt tile: %v", err)
	}
	_, err := store.ListBatchTreeLeaves(context.Background(), model.BatchTreeLeafListOptions{BatchID: tile.BatchID, Limit: 1})
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("corrupt tile code = %s, want %s; err=%v", trusterr.CodeOf(err), trusterr.CodeDataLoss, err)
	}
}

func TestBatchTreeReadsDoNotFallbackToLegacyKeys(t *testing.T) {
	db, _ := newMockTiKVDB(t, "batch-tree-no-legacy/")
	store := &Store{db: db}
	legacy := model.BatchTreeLeaf{SchemaVersion: model.SchemaBatchTreeLeaf, BatchID: "legacy", RecordID: "record-0", LeafIndex: 0, LeafHash: []byte{1}}
	if err := store.writeCBOR([]byte("batch-tree/leaf/legacy/00000000000000000000"), legacy); err != nil {
		t.Fatalf("write legacy leaf: %v", err)
	}
	leaves, err := store.ListBatchTreeLeaves(context.Background(), model.BatchTreeLeafListOptions{BatchID: legacy.BatchID, Limit: 1})
	if err != nil {
		t.Fatalf("ListBatchTreeLeaves: %v", err)
	}
	if len(leaves) != 0 {
		t.Fatalf("legacy leaves = %+v, want none", leaves)
	}
}
