package proofstore

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestLocalStoreGlobalLeafPageUsesCommittedRange(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	for index := uint64(0); index < 3; index++ {
		if err := store.PutGlobalLeaf(ctx, model.GlobalLogLeaf{BatchID: "batch-" + strconv.FormatUint(index, 10), LeafIndex: index}); err != nil {
			t.Fatalf("PutGlobalLeaf(%d): %v", index, err)
		}
	}
	if err := store.PutGlobalLogState(ctx, model.GlobalLogState{TreeSize: 3}); err != nil {
		t.Fatalf("PutGlobalLogState: %v", err)
	}
	if err := os.WriteFile(store.globalLeafPath(999), []byte("corrupt outside committed range"), 0o600); err != nil {
		t.Fatalf("write uncommitted leaf: %v", err)
	}

	page, err := store.ListGlobalLeavesPage(ctx, model.GlobalLeafListOptions{Limit: 2})
	if err != nil {
		t.Fatalf("ListGlobalLeavesPage: %v", err)
	}
	if len(page) != 2 || page[0].LeafIndex != 2 || page[1].LeafIndex != 1 {
		t.Fatalf("page = %+v", page)
	}
	next, err := store.ListGlobalLeavesPage(ctx, model.GlobalLeafListOptions{Limit: 2, AfterLeafIndex: page[1].LeafIndex})
	if err != nil {
		t.Fatalf("ListGlobalLeavesPage next: %v", err)
	}
	if len(next) != 1 || next[0].LeafIndex != 0 {
		t.Fatalf("next page = %+v", next)
	}
	ascending, err := store.ListGlobalLeavesPage(ctx, model.GlobalLeafListOptions{Limit: 2, Direction: model.RecordListDirectionAsc})
	if err != nil {
		t.Fatalf("ListGlobalLeavesPage ascending: %v", err)
	}
	if len(ascending) != 2 || ascending[0].LeafIndex != 0 || ascending[1].LeafIndex != 1 {
		t.Fatalf("ascending page = %+v", ascending)
	}
	ascendingNext, err := store.ListGlobalLeavesPage(ctx, model.GlobalLeafListOptions{
		Limit:          2,
		Direction:      model.RecordListDirectionAsc,
		AfterLeafIndex: ascending[1].LeafIndex,
	})
	if err != nil {
		t.Fatalf("ListGlobalLeavesPage ascending next: %v", err)
	}
	if len(ascendingNext) != 1 || ascendingNext[0].LeafIndex != 2 {
		t.Fatalf("ascending next page = %+v", ascendingNext)
	}
}

func TestLocalStoreGlobalLeafPageRejectsMissingCommittedLeaf(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	if err := store.PutGlobalLeaf(ctx, model.GlobalLogLeaf{BatchID: "batch-0", LeafIndex: 0}); err != nil {
		t.Fatalf("PutGlobalLeaf: %v", err)
	}
	if err := store.PutGlobalLogState(ctx, model.GlobalLogState{TreeSize: 2}); err != nil {
		t.Fatalf("PutGlobalLogState: %v", err)
	}

	_, err := store.ListGlobalLeavesPage(ctx, model.GlobalLeafListOptions{Limit: 2})
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("ListGlobalLeavesPage error = %v, want data loss", err)
	}
}

func TestLocalStoreGlobalLeafPageFallsBackWithoutState(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	for index := uint64(0); index < 3; index++ {
		if err := store.PutGlobalLeaf(ctx, model.GlobalLogLeaf{BatchID: "batch-" + strconv.FormatUint(index, 10), LeafIndex: index}); err != nil {
			t.Fatalf("PutGlobalLeaf(%d): %v", index, err)
		}
	}

	page, err := store.ListGlobalLeavesPage(ctx, model.GlobalLeafListOptions{Limit: 2})
	if err != nil {
		t.Fatalf("ListGlobalLeavesPage: %v", err)
	}
	if len(page) != 2 || page[0].LeafIndex != 2 || page[1].LeafIndex != 1 {
		t.Fatalf("page = %+v", page)
	}
}
