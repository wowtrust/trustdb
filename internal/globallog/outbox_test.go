package globallog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

type failOnceAnchorPublicationStore struct {
	proofstore.Store
	proofstore.STHAnchorScheduleStore
	marker proofstore.GlobalLogPublishedBatchWithAnchorCandidateMarker
	latest proofstore.LatestSTHAnchorResultForKeyReader
	fail   bool
}

func (s *failOnceAnchorPublicationStore) MarkGlobalLogPublishedBatchWithAnchorCandidate(ctx context.Context, batchIDs []string, sths []model.SignedTreeHead, candidate model.STHAnchorCandidate) error {
	if s.fail {
		s.fail = false
		return errors.New("injected publication marker failure")
	}
	return s.marker.MarkGlobalLogPublishedBatchWithAnchorCandidate(ctx, batchIDs, sths, candidate)
}

func (s *failOnceAnchorPublicationStore) LatestSTHAnchorResultForKey(ctx context.Context, key model.STHAnchorScheduleKey) (model.STHAnchorResult, bool, error) {
	return s.latest.LatestSTHAnchorResultForKey(ctx, key)
}

func TestOutboxWorkerReschedulesAppendFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := proofstore.LocalStore{Root: t.TempDir()}
	root := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       "batch-retry",
		BatchRoot:     bytes.Repeat([]byte{0x42}, 32),
		TreeSize:      1,
		ClosedAtUnixN: 1,
	}
	if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{
		SchemaVersion: model.SchemaGlobalLogOutbox,
		BatchID:       root.BatchID,
		BatchRoot:     root,
		Status:        model.AnchorStatePending,
	}); err != nil {
		t.Fatalf("EnqueueGlobalLog: %v", err)
	}
	readerOnly, err := NewReader(store)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	worker := NewOutboxWorker(OutboxConfig{
		Store:          store,
		Global:         readerOnly,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     time.Millisecond,
		Clock:          func() time.Time { return time.Unix(100, 0).UTC() },
	})
	worker.tick(ctx)

	item, ok, err := store.GetGlobalLogOutboxItem(ctx, root.BatchID)
	if err != nil || !ok {
		t.Fatalf("GetGlobalLogOutboxItem ok=%v err=%v", ok, err)
	}
	if item.Status != model.AnchorStatePending || item.Attempts != 1 || item.NextAttemptUnixN == 0 {
		t.Fatalf("item not rescheduled correctly: %+v", item)
	}
	if !strings.Contains(item.LastErrorMessage, "signer") {
		t.Fatalf("last_error = %q, want signer failure", item.LastErrorMessage)
	}
}

func TestOutboxWorkerContextCancellationAllowsRestart(t *testing.T) {
	worker := NewOutboxWorker(OutboxConfig{PollInterval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	worker.Start(ctx)
	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for {
		worker.mu.Lock()
		stopped := !worker.running
		worker.mu.Unlock()
		if stopped {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("outbox worker did not clear running state after context cancellation")
		}
		time.Sleep(time.Millisecond)
	}

	restartCtx, restartCancel := context.WithCancel(context.Background())
	defer restartCancel()
	worker.Start(restartCtx)
	worker.mu.Lock()
	restarted := worker.running
	worker.mu.Unlock()
	if !restarted {
		t.Fatal("outbox worker did not restart after context cancellation")
	}
	worker.Stop()
}

func TestOutboxWorkerPublishesBatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := proofstore.LocalStore{Root: t.TempDir()}
	root := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       "batch-success",
		LogID:         "outbox-test",
		BatchRoot:     bytes.Repeat([]byte{0x24}, 32),
		TreeSize:      1,
		ClosedAtUnixN: 1,
	}
	if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{
		SchemaVersion: model.SchemaGlobalLogOutbox,
		BatchID:       root.BatchID,
		BatchRoot:     root,
		Status:        model.AnchorStatePending,
	}); err != nil {
		t.Fatalf("EnqueueGlobalLog: %v", err)
	}
	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	svc, err := New(Options{
		Store:  store,
		LogID:  "outbox-test",
		Signer: trustcrypto.MustNewEd25519Signer("outbox-key", priv),
		Clock:  func() time.Time { return time.Unix(200, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var published []string
	worker := NewOutboxWorker(OutboxConfig{
		Store:  store,
		Global: svc,
		OnBatchesPublished: func(_ context.Context, batchIDs []string) {
			published = append(published, batchIDs...)
		},
	})
	worker.tick(ctx)

	item, ok, err := store.GetGlobalLogOutboxItem(ctx, root.BatchID)
	if err != nil || !ok {
		t.Fatalf("GetGlobalLogOutboxItem ok=%v err=%v", ok, err)
	}
	if item.Status != model.AnchorStatePublished || item.STH.TreeSize != 1 {
		t.Fatalf("item not published correctly: %+v", item)
	}
	if _, ok, err := store.GetGlobalLeafByBatchID(ctx, root.BatchID); err != nil || !ok {
		t.Fatalf("GetGlobalLeafByBatchID ok=%v err=%v", ok, err)
	}
	if len(published) != 1 || published[0] != root.BatchID {
		t.Fatalf("OnBatchesPublished = %v, want [%s]", published, root.BatchID)
	}
}

func TestOutboxWorkerAtomicallyStoresOnlyFinalAnchorCandidate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := proofstore.LocalStore{Root: t.TempDir()}
	roots := make([]model.BatchRoot, 3)
	for i := range roots {
		roots[i] = model.BatchRoot{
			SchemaVersion: model.SchemaBatchRoot, BatchID: fmt.Sprintf("batch-anchor-atomic-%d", i+1),
			LogID: "outbox-anchor-test", BatchRoot: bytes.Repeat([]byte{byte(0x51 + i)}, 32),
			TreeSize: 1, ClosedAtUnixN: int64(i + 1),
		}
		if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{
			SchemaVersion: model.SchemaGlobalLogOutbox, BatchID: roots[i].BatchID,
			BatchRoot: roots[i], Status: model.AnchorStatePending,
		}); err != nil {
			t.Fatalf("EnqueueGlobalLog(%d): %v", i, err)
		}
	}
	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	svc, err := New(Options{
		Store:  store,
		LogID:  "outbox-anchor-test",
		Signer: trustcrypto.MustNewEd25519Signer("outbox-anchor-key", priv),
		Clock:  func() time.Time { return time.Unix(300, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	metrics := observability.NewMetrics()
	anchorsReady := 0
	key := model.STHAnchorScheduleKey{LogID: "outbox-anchor-test", SinkName: "file"}
	worker := NewOutboxWorker(OutboxConfig{
		Store: store, Global: svc, AnchorKey: &key, AnchorMaxDelay: 5 * time.Minute,
		Metrics: metrics,
		OnAnchorReady: func() {
			anchorsReady++
		},
		Clock: func() time.Time { return time.Unix(300, 0).UTC() },
	})
	worker.tick(ctx)

	if anchorsReady != 1 {
		t.Fatalf("OnAnchorReady calls = %d, want 1", anchorsReady)
	}
	if got := testutil.ToFloat64(metrics.GlobalLogPublished); got != float64(len(roots)) {
		t.Fatalf("published roots metric = %v, want %d", got, len(roots))
	}
	schedule, ok, err := store.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !ok || schedule.Pending == nil || schedule.InFlight != nil {
		t.Fatalf("anchor schedule ok=%v err=%v schedule=%+v", ok, err, schedule)
	}
	if schedule.Revision != 1 || schedule.Pending.Target.TreeSize != uint64(len(roots)) || schedule.Pending.OpenedAtUnixN != time.Unix(300, 0).UnixNano() || schedule.Pending.DueAtUnixN != time.Unix(300, 0).Add(5*time.Minute).UnixNano() {
		t.Fatalf("anchor pending=%+v", schedule.Pending)
	}
	for _, root := range roots {
		item, found, err := store.GetGlobalLogOutboxItem(ctx, root.BatchID)
		if err != nil || !found || item.Status != model.AnchorStatePublished {
			t.Fatalf("global item %s=%+v found=%v err=%v", root.BatchID, item, found, err)
		}
	}
}

func TestOutboxWorkerRetryPreservesOriginalFixedAnchorWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := &proofstore.LocalStore{Root: t.TempDir()}
	marker, ok := any(base).(proofstore.GlobalLogPublishedBatchWithAnchorCandidateMarker)
	if !ok {
		t.Fatal("local proofstore does not support durable anchor publication")
	}
	latest, ok := any(base).(proofstore.LatestSTHAnchorResultForKeyReader)
	if !ok {
		t.Fatal("local proofstore does not support keyed latest anchor reads")
	}
	store := &failOnceAnchorPublicationStore{Store: base, STHAnchorScheduleStore: base, marker: marker, latest: latest, fail: true}
	root := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       "batch-anchor-replay-window",
		LogID:         "outbox-anchor-replay",
		BatchRoot:     bytes.Repeat([]byte{0x71}, 32),
		TreeSize:      1,
		ClosedAtUnixN: 1,
	}
	if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{
		SchemaVersion: model.SchemaGlobalLogOutbox,
		BatchID:       root.BatchID,
		BatchRoot:     root,
		Status:        model.AnchorStatePending,
	}); err != nil {
		t.Fatalf("EnqueueGlobalLog: %v", err)
	}
	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	appendTime := time.Unix(100, 0).UTC()
	svc, err := New(Options{
		Store: store, LogID: "outbox-anchor-replay", Signer: trustcrypto.MustNewEd25519Signer("key", priv),
		Clock: func() time.Time { return appendTime },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := appendTime
	key := model.STHAnchorScheduleKey{LogID: "outbox-anchor-replay", SinkName: "file"}
	worker := NewOutboxWorker(OutboxConfig{
		Store: store, Global: svc, AnchorKey: &key, AnchorMaxDelay: 5 * time.Minute,
		Clock: func() time.Time { return now },
	})

	worker.tick(ctx)
	if _, found, err := store.GetSignedTreeHead(ctx, 1); err != nil || !found {
		t.Fatalf("durable STH after injected marker failure found=%v err=%v", found, err)
	}
	if _, found, err := base.GetSTHAnchorSchedule(ctx, key); err != nil || found {
		t.Fatalf("schedule should not exist before publication retry found=%v err=%v", found, err)
	}

	now = time.Unix(1000, 0).UTC()
	worker.tick(ctx)
	schedule, found, err := base.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || schedule.Pending == nil {
		t.Fatalf("replayed schedule=%+v found=%v err=%v", schedule, found, err)
	}
	wantObserved := appendTime.UnixNano()
	wantDue := appendTime.Add(5 * time.Minute).UnixNano()
	if schedule.Pending.OpenedAtUnixN != wantObserved || schedule.Pending.DueAtUnixN != wantDue {
		t.Fatalf("replayed window opened=%d due=%d, want opened=%d due=%d", schedule.Pending.OpenedAtUnixN, schedule.Pending.DueAtUnixN, wantObserved, wantDue)
	}
	if schedule.Pending.DueAtUnixN >= now.UnixNano() {
		t.Fatalf("replayed window should already be expired: due=%d now=%d", schedule.Pending.DueAtUnixN, now.UnixNano())
	}
}

func TestOutboxWorkerNonMonotonicCoveredRetryUsesHighestNewSTH(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := &proofstore.LocalStore{Root: t.TempDir()}
	oldRoot := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		NodeID:        "node-1",
		LogID:         "outbox-covered-prefix",
		BatchID:       "batch-covered-prefix-old",
		BatchRoot:     bytes.Repeat([]byte{0x81}, 32),
		TreeSize:      1,
		ClosedAtUnixN: 1,
	}
	newRoot := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		NodeID:        oldRoot.NodeID,
		LogID:         oldRoot.LogID,
		BatchID:       "batch-covered-prefix-new",
		BatchRoot:     bytes.Repeat([]byte{0x82}, 32),
		TreeSize:      1,
		ClosedAtUnixN: 2,
	}
	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	now := time.Unix(100, 0).UTC()
	svc, err := New(Options{
		Store: store, NodeID: oldRoot.NodeID, LogID: oldRoot.LogID, Signer: trustcrypto.MustNewEd25519Signer("key", priv),
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	oldSTH, err := svc.AppendBatchRoot(ctx, oldRoot)
	if err != nil {
		t.Fatalf("AppendBatchRoot(old): %v", err)
	}
	key := model.STHAnchorScheduleKey{NodeID: oldRoot.NodeID, LogID: oldRoot.LogID, SinkName: "file"}
	writer, ok := any(store).(proofstore.STHAnchorResultWriter)
	if !ok {
		t.Fatal("local proofstore does not support anchor result writes")
	}
	if err := writer.PutSTHAnchorResult(ctx, model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		NodeID:           key.NodeID,
		LogID:            key.LogID,
		TreeSize:         oldSTH.TreeSize,
		SinkName:         key.SinkName,
		AnchorID:         "old-covered-anchor",
		RootHash:         append([]byte(nil), oldSTH.RootHash...),
		STH:              oldSTH,
		PublishedAtUnixN: now.UnixNano(),
	}); err != nil {
		t.Fatalf("PutSTHAnchorResult(old): %v", err)
	}
	// Queue the new root before the already-appended old root. AppendBatchRoots
	// therefore returns [tree=2, tree=1], reproducing an idempotent retry whose
	// caller order is not tree-size order.
	for i, root := range []model.BatchRoot{newRoot, oldRoot} {
		if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{
			SchemaVersion:   model.SchemaGlobalLogOutbox,
			BatchID:         root.BatchID,
			BatchRoot:       root,
			Status:          model.AnchorStatePending,
			EnqueuedAtUnixN: int64(i + 1),
		}); err != nil {
			t.Fatalf("EnqueueGlobalLog(%s): %v", root.BatchID, err)
		}
	}

	now = time.Unix(1000, 0).UTC()
	worker := NewOutboxWorker(OutboxConfig{
		Store: store, Global: svc, AnchorKey: &key, AnchorMaxDelay: 5 * time.Minute,
		Clock: func() time.Time { return now },
	})
	worker.tick(ctx)
	newSTH, found, err := store.GetSignedTreeHead(ctx, 2)
	if err != nil || !found {
		t.Fatalf("GetSignedTreeHead(new) found=%v err=%v", found, err)
	}
	schedule, found, err := store.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || schedule.Pending == nil {
		t.Fatalf("anchor schedule=%+v found=%v err=%v", schedule, found, err)
	}
	if schedule.Pending.Target.TreeSize != newSTH.TreeSize || schedule.Pending.OpenedAtUnixN != newSTH.TimestampUnixN || schedule.Pending.DueAtUnixN != time.Unix(0, newSTH.TimestampUnixN).Add(5*time.Minute).UnixNano() {
		t.Fatalf("new suffix window=%+v old_sth_timestamp=%d new_sth_timestamp=%d", schedule.Pending, oldSTH.TimestampUnixN, newSTH.TimestampUnixN)
	}
	for _, batchID := range []string{newRoot.BatchID, oldRoot.BatchID} {
		item, found, err := store.GetGlobalLogOutboxItem(ctx, batchID)
		if err != nil || !found || item.Status != model.AnchorStatePublished {
			t.Fatalf("published retry item %s=%+v found=%v err=%v", batchID, item, found, err)
		}
	}
}

func TestOutboxWorkerReplayPastInFlightStartsWindowAtFirstLaterSTH(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := &proofstore.LocalStore{Root: t.TempDir()}
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "outbox-inflight-replay", SinkName: "file"}
	oldRoot := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		NodeID:        key.NodeID,
		LogID:         key.LogID,
		BatchID:       "batch-inflight-old",
		BatchRoot:     bytes.Repeat([]byte{0x91}, 32),
		TreeSize:      1,
		ClosedAtUnixN: 1,
	}
	newRoot := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		NodeID:        key.NodeID,
		LogID:         key.LogID,
		BatchID:       "batch-inflight-new",
		BatchRoot:     bytes.Repeat([]byte{0x92}, 32),
		TreeSize:      1,
		ClosedAtUnixN: 2,
	}
	seedRoot := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		NodeID:        key.NodeID,
		LogID:         key.LogID,
		BatchID:       "batch-inflight-seed",
		BatchRoot:     bytes.Repeat([]byte{0x90}, 32),
		TreeSize:      1,
		ClosedAtUnixN: 0,
	}
	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	now := time.Unix(100, 0).UTC()
	svc, err := New(Options{
		Store: store, NodeID: key.NodeID, LogID: key.LogID, Signer: trustcrypto.MustNewEd25519Signer("key", priv),
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	seedSTHs, err := svc.AppendBatchRoots(ctx, []model.BatchRoot{seedRoot, oldRoot})
	if err != nil {
		t.Fatalf("AppendBatchRoots(seed): %v", err)
	}
	oldSTH := seedSTHs[len(seedSTHs)-1]
	scheduler := proofstore.STHAnchorScheduleStore(store)
	if _, err := scheduler.UpsertSTHAnchorCandidate(ctx, model.STHAnchorCandidate{
		Key: key, STH: oldSTH, ObservedAtUnixN: oldSTH.TimestampUnixN, DueAtUnixN: oldSTH.TimestampUnixN,
	}); err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate(old): %v", err)
	}
	claimAt := oldSTH.TimestampUnixN + 1
	if _, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, key, claimAt, claimAt+int64(time.Hour), "owner", "token"); err != nil || !claimed {
		t.Fatalf("ClaimSTHAnchorAttempt claimed=%v err=%v", claimed, err)
	}
	for i, root := range []model.BatchRoot{oldRoot, newRoot} {
		if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{
			SchemaVersion:   model.SchemaGlobalLogOutbox,
			BatchID:         root.BatchID,
			BatchRoot:       root,
			Status:          model.AnchorStatePending,
			EnqueuedAtUnixN: int64(i + 1),
		}); err != nil {
			t.Fatalf("EnqueueGlobalLog(%s): %v", root.BatchID, err)
		}
	}

	now = time.Unix(200, 0).UTC()
	worker := NewOutboxWorker(OutboxConfig{
		Store: store, Global: svc, AnchorKey: &key, AnchorMaxDelay: 5 * time.Minute,
		Clock: func() time.Time { return now },
	})
	worker.tick(ctx)
	newSTH, found, err := store.GetSignedTreeHead(ctx, 3)
	if err != nil || !found {
		t.Fatalf("GetSignedTreeHead(new) found=%v err=%v", found, err)
	}
	schedule, found, err := store.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || schedule.InFlight == nil || schedule.Pending == nil {
		t.Fatalf("schedule=%+v found=%v err=%v", schedule, found, err)
	}
	if schedule.InFlight.Target.TreeSize != oldSTH.TreeSize {
		t.Fatalf("in-flight target=%d, want %d", schedule.InFlight.Target.TreeSize, oldSTH.TreeSize)
	}
	if schedule.Pending.Target.TreeSize != newSTH.TreeSize || schedule.Pending.OpenedAtUnixN != newSTH.TimestampUnixN {
		t.Fatalf("pending=%+v old_timestamp=%d new_timestamp=%d", schedule.Pending, oldSTH.TimestampUnixN, newSTH.TimestampUnixN)
	}
	if schedule.Pending.DueAtUnixN != time.Unix(0, newSTH.TimestampUnixN).Add(5*time.Minute).UnixNano() {
		t.Fatalf("pending due=%d, want %d", schedule.Pending.DueAtUnixN, time.Unix(0, newSTH.TimestampUnixN).Add(5*time.Minute).UnixNano())
	}
}

func TestOutboxWorkerAnchorPathFailsClosedWithoutDurableMarker(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := proofstore.LocalStore{Root: t.TempDir()}
	store := struct{ proofstore.Store }{Store: base}
	root := model.BatchRoot{BatchID: "batch-anchor-unsupported", LogID: "unsupported-anchor", BatchRoot: bytes.Repeat([]byte{0x61}, 32), TreeSize: 1, ClosedAtUnixN: 1}
	if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{BatchID: root.BatchID, BatchRoot: root, Status: model.AnchorStatePending}); err != nil {
		t.Fatalf("EnqueueGlobalLog: %v", err)
	}
	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	svc, err := New(Options{Store: store, LogID: "unsupported-anchor", Signer: trustcrypto.MustNewEd25519Signer("key", priv)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := model.STHAnchorScheduleKey{LogID: "unsupported-anchor", SinkName: "file"}
	worker := NewOutboxWorker(OutboxConfig{Store: store, Global: svc, AnchorKey: &key})
	worker.tick(ctx)

	item, ok, err := store.GetGlobalLogOutboxItem(ctx, root.BatchID)
	if err != nil || !ok || item.Status != model.AnchorStatePending {
		t.Fatalf("global item = %+v ok=%v err=%v, want pending", item, ok, err)
	}
}
