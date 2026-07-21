package proofstore

import (
	"context"
	"os"
	"testing"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

func TestLocalStoreGlobalOutboxSeparatesPendingAndPublished(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	items := []model.GlobalLogOutboxItem{
		{BatchID: "batch-a", Status: model.AnchorStatePending, EnqueuedAtUnixN: 10},
		{BatchID: "batch-b", Status: model.AnchorStatePublished, EnqueuedAtUnixN: 20, CompletedAtUnixN: 21},
		{BatchID: "batch/c", Status: model.AnchorStatePending, EnqueuedAtUnixN: 30, NextAttemptUnixN: 100},
	}
	for _, item := range items {
		if err := store.EnqueueGlobalLog(ctx, item); err != nil {
			t.Fatalf("EnqueueGlobalLog(%q): %v", item.BatchID, err)
		}
		if _, err := os.Stat(store.globalOutboxPath(item.Status, item.BatchID)); err != nil {
			t.Fatalf("Stat(%q): %v", item.BatchID, err)
		}
	}
	if entries, err := os.ReadDir(store.globalOutboxDir()); err != nil || len(entries) != 2 || !entries[0].IsDir() || !entries[1].IsDir() {
		t.Fatalf("global outbox root entries = %+v err=%v, want two status directories", entries, err)
	}

	pending, err := store.ListPendingGlobalLog(ctx, 50, 10)
	if err != nil {
		t.Fatalf("ListPendingGlobalLog: %v", err)
	}
	if len(pending) != 1 || pending[0].BatchID != "batch-a" {
		t.Fatalf("pending = %+v, want batch-a", pending)
	}

	all, err := store.ListGlobalLogOutboxItemsAfter(ctx, "", 10)
	if err != nil {
		t.Fatalf("ListGlobalLogOutboxItemsAfter: %v", err)
	}
	if len(all) != 3 || all[0].BatchID != "batch-a" || all[1].BatchID != "batch-b" || all[2].BatchID != "batch/c" {
		t.Fatalf("all outbox items = %+v", all)
	}
	for _, item := range items {
		got, ok, err := store.GetGlobalLogOutboxItem(ctx, item.BatchID)
		if err != nil || !ok || got.Status != item.Status {
			t.Fatalf("GetGlobalLogOutboxItem(%q) = %+v ok=%v err=%v", item.BatchID, got, ok, err)
		}
	}
}

func TestLocalStoreGlobalOutboxPublishAndRescheduleTransitionStatus(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	const batchID = "batch-transition"
	if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{
		BatchID:         batchID,
		Status:          model.AnchorStatePending,
		EnqueuedAtUnixN: 10,
	}); err != nil {
		t.Fatalf("EnqueueGlobalLog: %v", err)
	}
	if err := store.RescheduleGlobalLog(ctx, batchID, 2, 200, "retry"); err != nil {
		t.Fatalf("RescheduleGlobalLog: %v", err)
	}
	got, ok, err := store.GetGlobalLogOutboxItem(ctx, batchID)
	if err != nil || !ok || got.Status != model.AnchorStatePending || got.Attempts != 2 || got.NextAttemptUnixN != 200 {
		t.Fatalf("rescheduled item = %+v ok=%v err=%v", got, ok, err)
	}
	if _, err := os.Stat(store.globalOutboxPath(model.AnchorStatePublished, batchID)); !os.IsNotExist(err) {
		t.Fatalf("published path before publish error = %v, want not exist", err)
	}
	sth := model.SignedTreeHead{SchemaVersion: model.SchemaSignedTreeHead, TreeSize: 1}
	if err := store.MarkGlobalLogPublished(ctx, batchID, sth); err != nil {
		t.Fatalf("MarkGlobalLogPublished: %v", err)
	}
	if _, err := os.Stat(store.globalOutboxPath(model.AnchorStatePending, batchID)); !os.IsNotExist(err) {
		t.Fatalf("pending path after publish error = %v, want not exist", err)
	}
	if _, err := os.Stat(store.globalOutboxPath(model.AnchorStatePublished, batchID)); err != nil {
		t.Fatalf("published path after publish: %v", err)
	}
	got, ok, err = store.GetGlobalLogOutboxItem(ctx, batchID)
	if err != nil || !ok || got.Status != model.AnchorStatePublished || got.STH.TreeSize != 1 {
		t.Fatalf("published item = %+v ok=%v err=%v", got, ok, err)
	}
}

func TestLocalStoreGlobalOutboxDuplicateTransitionConverges(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	const batchID = "batch-duplicate"
	pending := model.GlobalLogOutboxItem{
		SchemaVersion:   model.SchemaGlobalLogOutbox,
		BatchID:         batchID,
		Status:          model.AnchorStatePending,
		EnqueuedAtUnixN: 10,
	}
	if err := store.EnqueueGlobalLog(ctx, pending); err != nil {
		t.Fatalf("EnqueueGlobalLog: %v", err)
	}
	published := pending
	published.Status = model.AnchorStatePublished
	published.CompletedAtUnixN = 20
	if err := writeCBORAtomic(store.globalOutboxPath(model.AnchorStatePublished, batchID), published); err != nil {
		t.Fatalf("write duplicate published state: %v", err)
	}

	got, ok, err := store.GetGlobalLogOutboxItem(ctx, batchID)
	if err != nil || !ok || got.Status != model.AnchorStatePublished {
		t.Fatalf("GetGlobalLogOutboxItem duplicate = %+v ok=%v err=%v", got, ok, err)
	}
	all, err := store.ListGlobalLogOutboxItemsAfter(ctx, "", 10)
	if err != nil || len(all) != 1 || all[0].Status != model.AnchorStatePublished {
		t.Fatalf("ListGlobalLogOutboxItemsAfter duplicate = %+v err=%v", all, err)
	}
	pendingItems, err := store.ListPendingGlobalLog(ctx, 100, 10)
	if err != nil || len(pendingItems) != 1 {
		t.Fatalf("ListPendingGlobalLog duplicate = %+v err=%v", pendingItems, err)
	}
	if err := store.MarkGlobalLogPublished(ctx, batchID, model.SignedTreeHead{TreeSize: 1}); err != nil {
		t.Fatalf("MarkGlobalLogPublished duplicate: %v", err)
	}
	if _, err := os.Stat(store.globalOutboxPath(model.AnchorStatePending, batchID)); !os.IsNotExist(err) {
		t.Fatalf("pending duplicate after convergence error = %v, want not exist", err)
	}
}

func TestLocalStoreGlobalOutboxRejectsUnknownStatus(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	err := store.EnqueueGlobalLog(context.Background(), model.GlobalLogOutboxItem{BatchID: "batch-invalid", Status: "unknown"})
	if trusterr.CodeOf(err) != trusterr.CodeInvalidArgument {
		t.Fatalf("EnqueueGlobalLog error = %v, want invalid argument", err)
	}
}
