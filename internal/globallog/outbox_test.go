package globallog

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/observability"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
	"github.com/ryan-wong-coder/trustdb/internal/trustcrypto"
)

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

func TestOutboxWorkerPublishesBatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := proofstore.LocalStore{Root: t.TempDir()}
	root := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       "batch-success",
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
		Store:      store,
		LogID:      "outbox-test",
		KeyID:      "outbox-key",
		PrivateKey: priv,
		Clock:      func() time.Time { return time.Unix(200, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	worker := NewOutboxWorker(OutboxConfig{
		Store:  store,
		Global: svc,
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
}

func TestOutboxWorkerAtomicAnchorPathTriggersExistingOutbox(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := &anchorBatchStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	root := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       "batch-anchor-atomic",
		BatchRoot:     bytes.Repeat([]byte{0x51}, 32),
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
		Store:      store,
		LogID:      "outbox-anchor-test",
		KeyID:      "outbox-anchor-key",
		PrivateKey: priv,
		Clock:      func() time.Time { return time.Unix(300, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	metrics := observability.NewMetrics()
	anchorsReady := 0
	worker := NewOutboxWorker(OutboxConfig{
		Store:        store,
		Global:       svc,
		AnchorOutbox: true,
		Metrics:      metrics,
		OnAnchorsReady: func() {
			anchorsReady++
		},
	})
	worker.tick(ctx)

	if anchorsReady != 1 {
		t.Fatalf("OnAnchorsReady calls = %d, want 1", anchorsReady)
	}
	if got := testutil.ToFloat64(metrics.GlobalLogPublished); got != 1 {
		t.Fatalf("published roots metric = %v, want 1", got)
	}
	anchorItem, ok, err := store.GetSTHAnchorOutboxItem(ctx, 1)
	if err != nil || !ok || anchorItem.Status != model.AnchorStatePending {
		t.Fatalf("anchor item ok=%v err=%v item=%+v", ok, err, anchorItem)
	}
}

func TestOutboxWorkerAnchorPathFailsClosedWithoutDurableMarker(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := proofstore.LocalStore{Root: t.TempDir()}
	store := struct{ proofstore.Store }{Store: base}
	root := model.BatchRoot{BatchID: "batch-anchor-unsupported", BatchRoot: bytes.Repeat([]byte{0x61}, 32), TreeSize: 1, ClosedAtUnixN: 1}
	if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{BatchID: root.BatchID, BatchRoot: root, Status: model.AnchorStatePending}); err != nil {
		t.Fatalf("EnqueueGlobalLog: %v", err)
	}
	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	svc, err := New(Options{Store: store, LogID: "unsupported-anchor", KeyID: "key", PrivateKey: priv})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	worker := NewOutboxWorker(OutboxConfig{Store: store, Global: svc, AnchorOutbox: true})
	worker.tick(ctx)

	item, ok, err := store.GetGlobalLogOutboxItem(ctx, root.BatchID)
	if err != nil || !ok || item.Status != model.AnchorStatePending {
		t.Fatalf("global item = %+v ok=%v err=%v, want pending", item, ok, err)
	}
}

type anchorBatchStore struct {
	proofstore.LocalStore
}

func (s *anchorBatchStore) MarkGlobalLogPublishedBatchWithAnchors(ctx context.Context, batchIDs []string, sths []model.SignedTreeHead, anchors []model.STHAnchorOutboxItem) error {
	for i := range batchIDs {
		if err := s.MarkGlobalLogPublished(ctx, batchIDs[i], sths[i]); err != nil {
			return err
		}
		if err := s.EnqueueSTHAnchor(ctx, anchors[i]); err != nil {
			return err
		}
	}
	return nil
}
