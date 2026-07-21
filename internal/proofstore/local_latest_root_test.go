package proofstore

import (
	"context"
	"os"
	"testing"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

func TestLocalStoreLatestRootReferencePreservesMaximum(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	for _, root := range []model.BatchRoot{
		{BatchID: "batch-b", ClosedAtUnixN: 300},
		{BatchID: "batch-c", ClosedAtUnixN: 200},
		{BatchID: "batch-a", ClosedAtUnixN: 300},
	} {
		if err := store.PutRoot(ctx, root); err != nil {
			t.Fatalf("PutRoot(%q): %v", root.BatchID, err)
		}
	}
	latest, err := store.LatestRoot(ctx)
	if err != nil || latest.BatchID != "batch-b" || latest.ClosedAtUnixN != 300 {
		t.Fatalf("LatestRoot = %+v err=%v", latest, err)
	}
}

func TestLocalStoreLatestRootFallsBackAcrossInterruptedPublication(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	previous := model.BatchRoot{BatchID: "batch-previous", ClosedAtUnixN: 100}
	if err := store.PutRoot(ctx, previous); err != nil {
		t.Fatalf("PutRoot previous: %v", err)
	}
	ref := localLatestRootReference{
		Candidate: localRootReferencePosition{ClosedAtUnixN: 200, BatchID: "batch-interrupted"},
		Previous:  &localRootReferencePosition{ClosedAtUnixN: previous.ClosedAtUnixN, BatchID: previous.BatchID},
	}
	if err := writeCBORAtomic(store.latestRootReferencePath(), ref); err != nil {
		t.Fatalf("write interrupted reference: %v", err)
	}
	latest, err := store.LatestRoot(ctx)
	if err != nil || latest.BatchID != previous.BatchID {
		t.Fatalf("LatestRoot = %+v err=%v", latest, err)
	}
	repaired, ok, err := store.readLatestRootReference()
	if err != nil || !ok || repaired.Candidate.BatchID != previous.BatchID || repaired.Previous != nil {
		t.Fatalf("repaired reference = %+v ok=%v err=%v", repaired, ok, err)
	}
}

func TestLocalStoreLatestRootRebuildsMissingAndCorruptReference(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	for _, root := range []model.BatchRoot{{BatchID: "batch-1", ClosedAtUnixN: 100}, {BatchID: "batch-2", ClosedAtUnixN: 200}} {
		if err := store.PutRoot(ctx, root); err != nil {
			t.Fatalf("PutRoot(%q): %v", root.BatchID, err)
		}
	}
	if err := os.Remove(store.latestRootReferencePath()); err != nil {
		t.Fatalf("Remove latest root reference: %v", err)
	}
	latest, err := store.LatestRoot(ctx)
	if err != nil || latest.BatchID != "batch-2" {
		t.Fatalf("LatestRoot missing reference = %+v err=%v", latest, err)
	}
	if err := os.WriteFile(store.latestRootReferencePath(), []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("write corrupt reference: %v", err)
	}
	latest, err = store.LatestRoot(ctx)
	if err != nil || latest.BatchID != "batch-2" {
		t.Fatalf("LatestRoot corrupt reference = %+v err=%v", latest, err)
	}
}

func TestLocalStoreLatestRootRejectsCanonicalMismatch(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	root := model.BatchRoot{BatchID: "batch-1", ClosedAtUnixN: 100}
	if err := store.PutRoot(ctx, root); err != nil {
		t.Fatalf("PutRoot: %v", err)
	}
	mismatched := root
	mismatched.BatchID = "batch-other"
	data, err := cborx.Marshal(mismatched)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(store.rootPath(root.ClosedAtUnixN, root.BatchID), data, 0o600); err != nil {
		t.Fatalf("write mismatched root: %v", err)
	}
	_, err = store.LatestRoot(ctx)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("LatestRoot error = %v, want data loss", err)
	}
}
