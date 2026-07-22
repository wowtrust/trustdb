package proofstore

import (
	"context"
	"os"
	"testing"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestLocalStoreLatestSignedTreeHeadReferencePreservesMaximum(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	for _, treeSize := range []uint64{3, 1, 2} {
		if err := store.PutSignedTreeHead(ctx, localTestSignedTreeHead(treeSize)); err != nil {
			t.Fatalf("PutSignedTreeHead(%d): %v", treeSize, err)
		}
	}
	latest, ok, err := store.LatestSignedTreeHead(ctx)
	if err != nil || !ok || latest.TreeSize != 3 {
		t.Fatalf("LatestSignedTreeHead = %+v ok=%v err=%v", latest, ok, err)
	}
	if treeSize, ok, err := store.readLatestSignedTreeHeadReference(); err != nil || !ok || treeSize != 3 {
		t.Fatalf("latest reference = %d ok=%v err=%v", treeSize, ok, err)
	}
}

func TestLocalStoreLatestSignedTreeHeadRebuildsMissingReference(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	for _, treeSize := range []uint64{1, 2} {
		if err := store.PutSignedTreeHead(ctx, localTestSignedTreeHead(treeSize)); err != nil {
			t.Fatalf("PutSignedTreeHead(%d): %v", treeSize, err)
		}
	}
	if err := os.Remove(store.latestSignedTreeHeadReferencePath()); err != nil {
		t.Fatalf("Remove latest reference: %v", err)
	}
	latest, ok, err := store.LatestSignedTreeHead(ctx)
	if err != nil || !ok || latest.TreeSize != 2 {
		t.Fatalf("LatestSignedTreeHead = %+v ok=%v err=%v", latest, ok, err)
	}
	if treeSize, ok, err := store.readLatestSignedTreeHeadReference(); err != nil || !ok || treeSize != 2 {
		t.Fatalf("rebuilt reference = %d ok=%v err=%v", treeSize, ok, err)
	}
}

func TestLocalStoreLatestSignedTreeHeadRepairsStaleReferenceFromState(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	for _, treeSize := range []uint64{1, 2} {
		if err := store.PutSignedTreeHead(ctx, localTestSignedTreeHead(treeSize)); err != nil {
			t.Fatalf("PutSignedTreeHead(%d): %v", treeSize, err)
		}
	}
	if err := writeCBORAtomic(store.latestSignedTreeHeadReferencePath(), uint64(1)); err != nil {
		t.Fatalf("write stale reference: %v", err)
	}
	if err := store.PutGlobalLogState(ctx, model.GlobalLogState{TreeSize: 2}); err != nil {
		t.Fatalf("PutGlobalLogState: %v", err)
	}
	latest, ok, err := store.LatestSignedTreeHead(ctx)
	if err != nil || !ok || latest.TreeSize != 2 {
		t.Fatalf("LatestSignedTreeHead = %+v ok=%v err=%v", latest, ok, err)
	}
	if treeSize, ok, err := store.readLatestSignedTreeHeadReference(); err != nil || !ok || treeSize != 2 {
		t.Fatalf("repaired reference = %d ok=%v err=%v", treeSize, ok, err)
	}
}

func TestLocalStoreLatestSignedTreeHeadKeepsPublishedReferenceWhenStateIsAhead(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	if err := store.PutSignedTreeHead(ctx, localTestSignedTreeHead(1)); err != nil {
		t.Fatalf("PutSignedTreeHead: %v", err)
	}
	if err := store.PutGlobalLogState(ctx, model.GlobalLogState{TreeSize: 2}); err != nil {
		t.Fatalf("PutGlobalLogState: %v", err)
	}
	latest, ok, err := store.LatestSignedTreeHead(ctx)
	if err != nil || !ok || latest.TreeSize != 1 {
		t.Fatalf("LatestSignedTreeHead = %+v ok=%v err=%v", latest, ok, err)
	}
}

func TestLocalStoreLatestSignedTreeHeadRebuildsCorruptReference(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	if err := store.PutSignedTreeHead(ctx, localTestSignedTreeHead(1)); err != nil {
		t.Fatalf("PutSignedTreeHead: %v", err)
	}
	if err := os.WriteFile(store.latestSignedTreeHeadReferencePath(), []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("write corrupt reference: %v", err)
	}
	latest, ok, err := store.LatestSignedTreeHead(ctx)
	if err != nil || !ok || latest.TreeSize != 1 {
		t.Fatalf("LatestSignedTreeHead = %+v ok=%v err=%v", latest, ok, err)
	}
}

func TestLocalStoreLatestSignedTreeHeadRejectsCorruptCanonicalItem(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	if err := store.PutSignedTreeHead(ctx, localTestSignedTreeHead(1)); err != nil {
		t.Fatalf("PutSignedTreeHead: %v", err)
	}
	data, err := cborx.Marshal(localTestSignedTreeHead(2))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(store.sthPath(1), data, 0o600); err != nil {
		t.Fatalf("write mismatched STH: %v", err)
	}
	_, _, err = store.LatestSignedTreeHead(ctx)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("LatestSignedTreeHead error = %v, want data loss", err)
	}
}

func localTestSignedTreeHead(treeSize uint64) model.SignedTreeHead {
	return model.SignedTreeHead{
		TreeSize:       treeSize,
		RootHash:       []byte{byte(treeSize)},
		TimestampUnixN: int64(treeSize),
	}
}
