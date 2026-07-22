package proofstore

import (
	"context"
	"os"
	"testing"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
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

func TestLocalStoreGlobalOutboxPublishesCandidateBeforeConverging(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	batchIDs := []string{"batch-anchor-1", "batch-anchor-2"}
	sths := []model.SignedTreeHead{localScheduleSTH(key, 1, 0x11), localScheduleSTH(key, 2, 0x22)}
	for _, batchID := range batchIDs {
		if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{BatchID: batchID, Status: model.AnchorStatePending}); err != nil {
			t.Fatalf("EnqueueGlobalLog(%q): %v", batchID, err)
		}
	}
	candidate := model.STHAnchorCandidate{Key: key, STH: sths[len(sths)-1], ObservedAtUnixN: 100, DueAtUnixN: 200}
	for attempt := 0; attempt < 2; attempt++ {
		if err := store.MarkGlobalLogPublishedBatchWithAnchorCandidate(ctx, batchIDs, sths, candidate); err != nil {
			t.Fatalf("MarkGlobalLogPublishedBatchWithAnchorCandidate attempt %d: %v", attempt+1, err)
		}
	}
	for i := range batchIDs {
		item, found, err := store.GetGlobalLogOutboxItem(ctx, batchIDs[i])
		if err != nil || !found || item.Status != model.AnchorStatePublished || item.STH.TreeSize != sths[i].TreeSize {
			t.Fatalf("global item %q = %+v found=%v err=%v", batchIDs[i], item, found, err)
		}
	}
	schedule, found, err := store.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || schedule.Pending == nil || schedule.InFlight != nil {
		t.Fatalf("anchor schedule=%+v found=%v err=%v", schedule, found, err)
	}
	if schedule.Pending.Target.TreeSize != 2 || schedule.Pending.OpenedAtUnixN != 100 || schedule.Pending.DueAtUnixN != 200 {
		t.Fatalf("coalesced candidate=%+v", schedule.Pending)
	}
}

func TestLocalStoreGlobalOutboxValidatesAnchorCandidateBeforeMutation(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	batchIDs := []string{"batch-valid-1", "batch-valid-2"}
	sths := []model.SignedTreeHead{localScheduleSTH(key, 1, 0x11), localScheduleSTH(key, 2, 0x22)}
	for _, batchID := range batchIDs {
		if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{BatchID: batchID, Status: model.AnchorStatePending}); err != nil {
			t.Fatalf("EnqueueGlobalLog(%q): %v", batchID, err)
		}
	}
	bad := model.STHAnchorCandidate{Key: key, STH: sths[0], ObservedAtUnixN: 100, DueAtUnixN: 200}
	if err := store.MarkGlobalLogPublishedBatchWithAnchorCandidate(ctx, batchIDs, sths, bad); trusterr.CodeOf(err) != trusterr.CodeInvalidArgument {
		t.Fatalf("MarkGlobalLogPublishedBatchWithAnchorCandidate error = %v, want invalid argument", err)
	}
	for _, batchID := range batchIDs {
		item, found, err := store.GetGlobalLogOutboxItem(ctx, batchID)
		if err != nil || !found || item.Status != model.AnchorStatePending {
			t.Fatalf("global item %q = %+v found=%v err=%v", batchID, item, found, err)
		}
	}
	if _, found, err := store.GetSTHAnchorSchedule(ctx, key); err != nil || found {
		t.Fatalf("anchor schedule found=%v err=%v, want absent", found, err)
	}
}

func TestLocalStoreReplaysDurableAnchorPublicationJournal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	root := t.TempDir()
	store := LocalStore{Root: root}
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	batchIDs := []string{"batch-journal-1", "batch-journal-2"}
	sths := []model.SignedTreeHead{localScheduleSTH(key, 1, 0x41), localScheduleSTH(key, 2, 0x42)}
	for i, batchID := range batchIDs {
		if err := store.PutRecordIndex(ctx, model.RecordIndex{
			SchemaVersion: model.SchemaRecordIndex, RecordID: "record-journal-" + batchID,
			BatchID: batchID, ProofLevel: "L3", ReceivedAtUnixN: int64(i + 1),
		}); err != nil {
			t.Fatalf("PutRecordIndex(%s): %v", batchID, err)
		}
		if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{
			SchemaVersion: model.SchemaGlobalLogOutbox, BatchID: batchID,
			BatchRoot: model.BatchRoot{SchemaVersion: model.SchemaBatchRoot, BatchID: batchID, BatchRoot: []byte{byte(i + 1)}, TreeSize: 1},
			Status:    model.AnchorStatePending,
		}); err != nil {
			t.Fatalf("EnqueueGlobalLog(%s): %v", batchID, err)
		}
	}
	candidate := model.STHAnchorCandidate{Key: key, STH: sths[1], ObservedAtUnixN: 100, DueAtUnixN: 200}
	schedule, changed, err := anchorschedule.MergeCandidate(model.STHAnchorSchedule{}, false, candidate, nil)
	if err != nil || !changed {
		t.Fatalf("MergeCandidate changed=%v err=%v", changed, err)
	}
	journal := localAnchorPublicationJournal{
		SchemaVersion: localAnchorPublishSchema, Key: key,
		BatchIDs: append([]string(nil), batchIDs...), STHs: append([]model.SignedTreeHead(nil), sths...), Schedule: schedule,
	}
	// Crash point: the intent journal is durable, but neither the scheduler
	// state nor L4 publication has become visible yet.
	if err := writeCBORAtomic(store.sthAnchorPublicationJournalPath(key), journal); err != nil {
		t.Fatalf("write publication journal: %v", err)
	}

	restarted := LocalStore{Root: root}
	gotSchedule, found, err := restarted.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || gotSchedule.Pending == nil || gotSchedule.Pending.Target.TreeSize != 2 {
		t.Fatalf("replayed schedule=%+v found=%v err=%v", gotSchedule, found, err)
	}
	for i, batchID := range batchIDs {
		item, found, err := restarted.GetGlobalLogOutboxItem(ctx, batchID)
		if err != nil || !found || item.Status != model.AnchorStatePublished || !sameLocalSignedTreeHead(item.STH, sths[i]) {
			t.Fatalf("replayed global item %s=%+v found=%v err=%v", batchID, item, found, err)
		}
		idx, found, err := restarted.GetRecordIndex(ctx, "record-journal-"+batchID)
		if err != nil || !found || model.RecordIndexProofLevel(idx) != "L4" {
			t.Fatalf("replayed record %s=%+v found=%v err=%v", batchID, idx, found, err)
		}
	}
	if _, err := os.Stat(restarted.sthAnchorPublicationJournalPath(key)); !os.IsNotExist(err) {
		t.Fatalf("publication journal remains after replay: %v", err)
	}
}

func TestLocalStoreJournalReplayRemovesStalePendingAfterPublishedCopy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	root := t.TempDir()
	store := LocalStore{Root: root}
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	batchID := "batch-published-before-pending-delete"
	sth := localScheduleSTH(key, 1, 0x51)
	if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{
		SchemaVersion: model.SchemaGlobalLogOutbox, BatchID: batchID,
		BatchRoot: model.BatchRoot{SchemaVersion: model.SchemaBatchRoot, BatchID: batchID, BatchRoot: []byte{0x51}, TreeSize: 1},
		Status:    model.AnchorStatePending,
	}); err != nil {
		t.Fatal(err)
	}
	candidate := model.STHAnchorCandidate{Key: key, STH: sth, ObservedAtUnixN: 100, DueAtUnixN: 200}
	schedule, _, err := anchorschedule.MergeCandidate(model.STHAnchorSchedule{}, false, candidate, nil)
	if err != nil {
		t.Fatal(err)
	}
	journal := localAnchorPublicationJournal{
		SchemaVersion: localAnchorPublishSchema, Key: key, BatchIDs: []string{batchID},
		STHs: []model.SignedTreeHead{sth}, Schedule: schedule,
	}
	if err := store.writeSTHAnchorSchedule(schedule); err != nil {
		t.Fatal(err)
	}
	published := model.GlobalLogOutboxItem{
		SchemaVersion: model.SchemaGlobalLogOutbox, BatchID: batchID,
		BatchRoot: model.BatchRoot{SchemaVersion: model.SchemaBatchRoot, BatchID: batchID, BatchRoot: []byte{0x51}, TreeSize: 1},
		Status:    model.AnchorStatePublished, STH: sth, CompletedAtUnixN: 300,
	}
	if err := writeCBORAtomic(store.globalOutboxPath(model.AnchorStatePublished, batchID), published); err != nil {
		t.Fatal(err)
	}
	if err := writeCBORAtomic(store.sthAnchorPublicationJournalPath(key), journal); err != nil {
		t.Fatal(err)
	}

	restarted := LocalStore{Root: root}
	if _, found, err := restarted.GetSTHAnchorSchedule(ctx, key); err != nil || !found {
		t.Fatalf("GetSTHAnchorSchedule found=%v err=%v", found, err)
	}
	if _, err := os.Stat(restarted.globalOutboxPath(model.AnchorStatePending, batchID)); !os.IsNotExist(err) {
		t.Fatalf("stale pending file survived journal replay: %v", err)
	}
	if _, err := os.Stat(restarted.sthAnchorPublicationJournalPath(key)); !os.IsNotExist(err) {
		t.Fatalf("publication journal survived convergence: %v", err)
	}
}

func TestLocalStoreJournalReplayRejectsPathKeyMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := LocalStore{Root: t.TempDir()}
	expected := model.STHAnchorScheduleKey{NodeID: "node-a", LogID: "log-a", SinkName: "file"}
	journalKey := model.STHAnchorScheduleKey{NodeID: "node-b", LogID: "log-b", SinkName: "file"}
	sth := localScheduleSTH(journalKey, 1, 0x61)
	candidate := model.STHAnchorCandidate{Key: journalKey, STH: sth, ObservedAtUnixN: 100, DueAtUnixN: 200}
	schedule, _, err := anchorschedule.MergeCandidate(model.STHAnchorSchedule{}, false, candidate, nil)
	if err != nil {
		t.Fatal(err)
	}
	journal := localAnchorPublicationJournal{
		SchemaVersion: localAnchorPublishSchema, Key: journalKey, BatchIDs: []string{"batch-mismatch"},
		STHs: []model.SignedTreeHead{sth}, Schedule: schedule,
	}
	if err := writeCBORAtomic(store.sthAnchorPublicationJournalPath(expected), journal); err != nil {
		t.Fatal(err)
	}

	if _, _, err := store.GetSTHAnchorSchedule(ctx, expected); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("GetSTHAnchorSchedule error=%v, want data loss", err)
	}
	if _, found, err := store.getSTHAnchorSchedule(journalKey); err != nil || found {
		t.Fatalf("mismatched journal mutated foreign schedule found=%v err=%v", found, err)
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
