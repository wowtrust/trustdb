package tikv

import (
	"context"
	"testing"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

func TestCommitGlobalLogAppendRejectsStaleTreeState(t *testing.T) {
	db, _ := newMockTiKVDB(t, "global-log-fence/")
	store := &Store{db: db}
	ctx := context.Background()

	winner := testGlobalLogAppend("winner", 0)
	if err := store.CommitGlobalLogAppend(ctx, winner); err != nil {
		t.Fatalf("commit winner: %v", err)
	}
	stale := testGlobalLogAppend("stale", 0)
	if err := store.CommitGlobalLogAppend(ctx, stale); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("commit stale error = %v, code = %s, want %s", err, trusterr.CodeOf(err), trusterr.CodeFailedPrecondition)
	}

	leaf, found, err := store.GetGlobalLeaf(ctx, 0)
	if err != nil {
		t.Fatalf("get winning leaf: %v", err)
	}
	if !found || leaf.BatchID != winner.Leaf.BatchID {
		t.Fatalf("leaf 0 = %#v, found = %v; want winning append", leaf, found)
	}
}

func TestCommitGlobalLogAppendsRequiresContiguousPlan(t *testing.T) {
	db, _ := newMockTiKVDB(t, "global-log-contiguous/")
	store := &Store{db: db}
	ctx := context.Background()

	err := store.CommitGlobalLogAppends(ctx, []model.GlobalLogAppend{
		testGlobalLogAppend("batch-0", 0),
		testGlobalLogAppend("batch-2", 2),
	})
	if trusterr.CodeOf(err) != trusterr.CodeInvalidArgument {
		t.Fatalf("non-contiguous append error = %v, code = %s, want %s", err, trusterr.CodeOf(err), trusterr.CodeInvalidArgument)
	}
	if _, found, err := store.GetGlobalLogState(ctx); err != nil || found {
		t.Fatalf("state after rejected plan: found = %v, err = %v", found, err)
	}
}

func TestCommitGlobalLogAppendsFencesStaleBatch(t *testing.T) {
	db, _ := newMockTiKVDB(t, "global-log-batch-fence/")
	store := &Store{db: db}
	ctx := context.Background()

	winner := []model.GlobalLogAppend{
		testGlobalLogAppend("winner-0", 0),
		testGlobalLogAppend("winner-1", 1),
	}
	if err := store.CommitGlobalLogAppends(ctx, winner); err != nil {
		t.Fatalf("commit winning batch: %v", err)
	}
	if err := store.CommitGlobalLogAppends(ctx, []model.GlobalLogAppend{testGlobalLogAppend("stale", 0)}); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("commit stale batch error = %v, code = %s, want %s", err, trusterr.CodeOf(err), trusterr.CodeFailedPrecondition)
	}

	state, found, err := store.GetGlobalLogState(ctx)
	if err != nil {
		t.Fatalf("get winning state: %v", err)
	}
	if !found || state.TreeSize != 2 {
		t.Fatalf("state = %#v, found = %v; want tree size 2", state, found)
	}
}

func testGlobalLogAppend(batchID string, leafIndex uint64) model.GlobalLogAppend {
	treeSize := leafIndex + 1
	return model.GlobalLogAppend{
		Leaf: model.GlobalLogLeaf{
			BatchID:   batchID,
			LeafIndex: leafIndex,
		},
		State: model.GlobalLogState{TreeSize: treeSize},
		STH:   model.SignedTreeHead{TreeSize: treeSize},
	}
}
