package proofstore

import (
	"context"
	"os"
	"testing"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

func TestLocalStoreSTHAnchorOutboxSeparatesStatuses(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	items := []model.STHAnchorOutboxItem{
		{TreeSize: 1, Status: model.AnchorStatePending, EnqueuedAtUnixN: 10},
		{TreeSize: 2, Status: model.AnchorStatePublished, EnqueuedAtUnixN: 20},
		{TreeSize: 3, Status: model.AnchorStateFailed, EnqueuedAtUnixN: 30},
	}
	for _, item := range items {
		if err := store.EnqueueSTHAnchor(ctx, item); err != nil {
			t.Fatalf("EnqueueSTHAnchor(%d): %v", item.TreeSize, err)
		}
		if _, err := os.Stat(store.sthAnchorOutboxPath(item.Status, item.TreeSize)); err != nil {
			t.Fatalf("Stat(%d): %v", item.TreeSize, err)
		}
	}
	if entries, err := os.ReadDir(store.sthAnchorOutboxDir()); err != nil || len(entries) != 3 {
		t.Fatalf("anchor outbox root entries = %+v err=%v, want three status directories", entries, err)
	}
	pending, err := store.ListPendingSTHAnchors(ctx, 100, 10)
	if err != nil || len(pending) != 1 || pending[0].TreeSize != 1 {
		t.Fatalf("pending = %+v err=%v", pending, err)
	}
	published, err := store.ListPublishedSTHAnchors(ctx, 10)
	if err != nil || len(published) != 1 || published[0].TreeSize != 2 {
		t.Fatalf("published = %+v err=%v", published, err)
	}
	all, err := store.ListSTHAnchorOutboxItemsAfter(ctx, 0, 10)
	if err != nil || len(all) != 3 || all[0].TreeSize != 1 || all[1].TreeSize != 2 || all[2].TreeSize != 3 {
		t.Fatalf("all = %+v err=%v", all, err)
	}
	page, err := store.ListSTHAnchorsPage(ctx, model.AnchorListOptions{Limit: 2, Direction: model.RecordListDirectionDesc})
	if err != nil || len(page) != 2 || page[0].TreeSize != 3 || page[1].TreeSize != 2 {
		t.Fatalf("descending page = %+v err=%v", page, err)
	}
	for _, want := range items {
		got, ok, err := store.GetSTHAnchorOutboxItem(ctx, want.TreeSize)
		if err != nil || !ok || got.Status != want.Status {
			t.Fatalf("GetSTHAnchorOutboxItem(%d) = %+v ok=%v err=%v", want.TreeSize, got, ok, err)
		}
	}
}

func TestLocalStoreSTHAnchorTransitionsStatuses(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	if err := store.EnqueueSTHAnchor(ctx, model.STHAnchorOutboxItem{TreeSize: 1, Status: model.AnchorStatePending, EnqueuedAtUnixN: 10}); err != nil {
		t.Fatalf("EnqueueSTHAnchor published transition: %v", err)
	}
	if err := store.RescheduleSTHAnchor(ctx, 1, 2, 200, "retry"); err != nil {
		t.Fatalf("RescheduleSTHAnchor: %v", err)
	}
	if err := store.MarkSTHAnchorPublished(ctx, model.STHAnchorResult{TreeSize: 1, AnchorID: "anchor-1", PublishedAtUnixN: 300}); err != nil {
		t.Fatalf("MarkSTHAnchorPublished: %v", err)
	}
	if _, err := os.Stat(store.sthAnchorOutboxPath(model.AnchorStatePending, 1)); !os.IsNotExist(err) {
		t.Fatalf("pending path after publish error = %v, want not exist", err)
	}
	item, ok, err := store.GetSTHAnchorOutboxItem(ctx, 1)
	if err != nil || !ok || item.Status != model.AnchorStatePublished || item.Attempts != 2 {
		t.Fatalf("published item = %+v ok=%v err=%v", item, ok, err)
	}
	result, ok, err := store.GetSTHAnchorResult(ctx, 1)
	if err != nil || !ok || result.AnchorID != "anchor-1" {
		t.Fatalf("published result = %+v ok=%v err=%v", result, ok, err)
	}

	if err := store.EnqueueSTHAnchor(ctx, model.STHAnchorOutboxItem{TreeSize: 2, Status: model.AnchorStatePending, EnqueuedAtUnixN: 20}); err != nil {
		t.Fatalf("EnqueueSTHAnchor failed transition: %v", err)
	}
	if err := store.MarkSTHAnchorFailed(ctx, 2, "permanent"); err != nil {
		t.Fatalf("MarkSTHAnchorFailed: %v", err)
	}
	if _, err := os.Stat(store.sthAnchorOutboxPath(model.AnchorStatePending, 2)); !os.IsNotExist(err) {
		t.Fatalf("pending path after failure error = %v, want not exist", err)
	}
	item, ok, err = store.GetSTHAnchorOutboxItem(ctx, 2)
	if err != nil || !ok || item.Status != model.AnchorStateFailed || item.LastErrorMessage != "permanent" {
		t.Fatalf("failed item = %+v ok=%v err=%v", item, ok, err)
	}
}

func TestLocalStoreLatestSTHAnchorReferenceRecoversIncompleteCandidate(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	if err := store.EnqueueSTHAnchor(ctx, model.STHAnchorOutboxItem{TreeSize: 1, Status: model.AnchorStatePending}); err != nil {
		t.Fatalf("EnqueueSTHAnchor: %v", err)
	}
	if err := store.MarkSTHAnchorPublished(ctx, model.STHAnchorResult{TreeSize: 1, AnchorID: "anchor-1"}); err != nil {
		t.Fatalf("MarkSTHAnchorPublished: %v", err)
	}
	previous := uint64(1)
	if err := writeCBORAtomic(store.latestSTHAnchorReferencePath(), localLatestAnchorReference{Candidate: 2, Previous: &previous}); err != nil {
		t.Fatalf("write incomplete latest reference: %v", err)
	}
	result, found, err := store.LatestSTHAnchorResult(ctx)
	if err != nil || !found || result.TreeSize != 1 {
		t.Fatalf("LatestSTHAnchorResult result=%+v found=%v err=%v", result, found, err)
	}
	ref, ok, err := store.readLatestSTHAnchorReference()
	if err != nil || !ok || ref.Candidate != 1 {
		t.Fatalf("repaired latest reference=%+v ok=%v err=%v", ref, ok, err)
	}
}

func TestLocalStoreSTHAnchorDuplicateTransitionConverges(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	pending := model.STHAnchorOutboxItem{
		SchemaVersion:   model.SchemaSTHAnchorOutbox,
		TreeSize:        1,
		Status:          model.AnchorStatePending,
		EnqueuedAtUnixN: 10,
	}
	if err := store.EnqueueSTHAnchor(ctx, pending); err != nil {
		t.Fatalf("EnqueueSTHAnchor: %v", err)
	}
	published := pending
	published.Status = model.AnchorStatePublished
	if err := writeCBORAtomic(store.sthAnchorOutboxPath(model.AnchorStatePublished, 1), published); err != nil {
		t.Fatalf("write duplicate published state: %v", err)
	}
	got, ok, err := store.GetSTHAnchorOutboxItem(ctx, 1)
	if err != nil || !ok || got.Status != model.AnchorStatePublished {
		t.Fatalf("GetSTHAnchorOutboxItem duplicate = %+v ok=%v err=%v", got, ok, err)
	}
	all, err := store.ListSTHAnchorOutboxItemsAfter(ctx, 0, 10)
	if err != nil || len(all) != 1 || all[0].Status != model.AnchorStatePublished {
		t.Fatalf("ListSTHAnchorOutboxItemsAfter duplicate = %+v err=%v", all, err)
	}
	if err := store.MarkSTHAnchorPublished(ctx, model.STHAnchorResult{TreeSize: 1, AnchorID: "anchor-1"}); err != nil {
		t.Fatalf("MarkSTHAnchorPublished duplicate: %v", err)
	}
	if _, err := os.Stat(store.sthAnchorOutboxPath(model.AnchorStatePending, 1)); !os.IsNotExist(err) {
		t.Fatalf("pending duplicate after convergence error = %v, want not exist", err)
	}
}

func TestLocalStoreSTHAnchorRejectsUnknownStatus(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	err := store.EnqueueSTHAnchor(context.Background(), model.STHAnchorOutboxItem{TreeSize: 1, Status: "unknown"})
	if trusterr.CodeOf(err) != trusterr.CodeInvalidArgument {
		t.Fatalf("EnqueueSTHAnchor error = %v, want invalid argument", err)
	}
}
