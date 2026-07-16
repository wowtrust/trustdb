package anchor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
)

// fakeSink is a programmable Sink that returns canned results / errors
// in order so tests can drive the Service through every state
// transition deterministically.
type fakeSink struct {
	name string

	mu      sync.Mutex
	calls   int
	results []fakeResult
}

type fakeResult struct {
	result model.STHAnchorResult
	err    error
}

type concurrentSink struct {
	current atomic.Int32
	max     atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (s *concurrentSink) Name() string { return "concurrent" }

func (s *concurrentSink) Publish(ctx context.Context, sth model.SignedTreeHead) (model.STHAnchorResult, error) {
	current := s.current.Add(1)
	defer s.current.Add(-1)
	for {
		maximum := s.max.Load()
		if current <= maximum || s.max.CompareAndSwap(maximum, current) {
			break
		}
	}
	s.entered <- struct{}{}
	select {
	case <-s.release:
	case <-ctx.Done():
		return model.STHAnchorResult{}, ctx.Err()
	}
	return model.STHAnchorResult{SchemaVersion: model.SchemaSTHAnchorResult, TreeSize: sth.TreeSize, RootHash: sth.RootHash, STH: sth, AnchorID: fmt.Sprintf("anchor-%d", sth.TreeSize)}, nil
}

func (f *fakeSink) Name() string { return f.name }

func (f *fakeSink) Publish(ctx context.Context, sth model.SignedTreeHead) (model.STHAnchorResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := f.calls
	f.calls++
	if idx >= len(f.results) {
		idx = len(f.results) - 1
	}
	r := f.results[idx]
	if r.err != nil {
		return model.STHAnchorResult{}, r.err
	}
	out := r.result
	if out.TreeSize == 0 {
		out.TreeSize = sth.TreeSize
	}
	out.RootHash = sth.RootHash
	out.STH = sth
	out.SinkName = f.name
	return out, nil
}

func (f *fakeSink) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// newLocalStore spins up a fresh LocalStore in a temp dir.
func newLocalStore(t *testing.T) proofstore.Store {
	t.Helper()
	return proofstore.LocalStore{Root: t.TempDir()}
}

func testSTH(treeSize uint64) model.SignedTreeHead {
	root := make([]byte, 32)
	root[31] = byte(treeSize)
	return model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       treeSize,
		RootHash:       root,
		TimestampUnixN: int64(treeSize),
	}
}

func enqueue(t *testing.T, store proofstore.Store, treeSize uint64) {
	t.Helper()
	sth := testSTH(treeSize)
	if err := store.EnqueueSTHAnchor(context.Background(), model.STHAnchorOutboxItem{
		SchemaVersion:   model.SchemaSTHAnchorOutbox,
		TreeSize:        treeSize,
		SinkName:        "fake",
		Status:          model.AnchorStatePending,
		STH:             sth,
		EnqueuedAtUnixN: time.Now().UnixNano(),
	}); err != nil {
		t.Fatalf("EnqueueSTHAnchor: %v", err)
	}
}

func TestServicePublishesIndependentAnchorsConcurrently(t *testing.T) {
	store := newLocalStore(t)
	for i := uint64(1); i <= 4; i++ {
		enqueue(t, store, i)
	}
	sink := &concurrentSink{entered: make(chan struct{}, 4), release: make(chan struct{})}
	svc, err := NewService(Config{Sink: sink, Store: store, Workers: 4, BatchSize: 4, PerCallTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		svc.tick(context.Background())
		close(done)
	}()
	for i := 0; i < 4; i++ {
		select {
		case <-sink.entered:
		case <-time.After(time.Second):
			t.Fatal("anchor workers did not run concurrently")
		}
	}
	if got := sink.max.Load(); got != 4 {
		t.Fatalf("max concurrent publishes=%d want=4", got)
	}
	close(sink.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("anchor tick did not finish")
	}
}

func TestServicePublishesOnSuccess(t *testing.T) {
	t.Parallel()
	store := newLocalStore(t)
	sink := &fakeSink{name: "fake", results: []fakeResult{
		{result: model.STHAnchorResult{AnchorID: "ok"}},
	}}
	enqueue(t, store, 1)

	svc, err := NewService(Config{
		Sink:  sink,
		Store: store,
		// Tight poll interval is irrelevant because the test only
		// runs a single tick manually, but the defaults would
		// otherwise introduce real-time sleeps.
		PollInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	svc.tick(context.Background())

	result, ok, err := store.GetSTHAnchorResult(context.Background(), 1)
	if err != nil || !ok {
		t.Fatalf("GetSTHAnchorResult ok=%v err=%v", ok, err)
	}
	if result.AnchorID != "ok" {
		t.Fatalf("AnchorID = %q, want ok", result.AnchorID)
	}
	item, _, _ := store.GetSTHAnchorOutboxItem(context.Background(), 1)
	if item.Status != model.AnchorStatePublished {
		t.Fatalf("status = %q, want published", item.Status)
	}
	if sink.callCount() != 1 {
		t.Fatalf("sink called %d times, want 1", sink.callCount())
	}
}

func TestServiceReschedulesOnTransientError(t *testing.T) {
	t.Parallel()
	store := newLocalStore(t)
	sink := &fakeSink{name: "fake", results: []fakeResult{
		{err: errors.New("sink 5xx")},
	}}
	enqueue(t, store, 2)

	svc, err := NewService(Config{
		Sink:           sink,
		Store:          store,
		InitialBackoff: 2 * time.Second,
		MaxBackoff:     10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	svc.tick(context.Background())

	item, ok, err := store.GetSTHAnchorOutboxItem(context.Background(), 2)
	if err != nil || !ok {
		t.Fatalf("GetSTHAnchorOutboxItem ok=%v err=%v", ok, err)
	}
	if item.Status != model.AnchorStatePending {
		t.Fatalf("status = %q, want pending", item.Status)
	}
	if item.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1", item.Attempts)
	}
	if item.LastErrorMessage != "sink 5xx" {
		t.Fatalf("last_error = %q", item.LastErrorMessage)
	}
	if item.NextAttemptUnixN <= 0 {
		t.Fatalf("next_attempt not set: %d", item.NextAttemptUnixN)
	}
}

func TestServiceMarksPermanentFailure(t *testing.T) {
	t.Parallel()
	store := newLocalStore(t)
	sink := &fakeSink{name: "fake", results: []fakeResult{
		{err: fmt.Errorf("%w: bad schema", ErrPermanent)},
	}}
	enqueue(t, store, 3)

	svc, err := NewService(Config{Sink: sink, Store: store})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	svc.tick(context.Background())

	item, _, _ := store.GetSTHAnchorOutboxItem(context.Background(), 3)
	if item.Status != model.AnchorStateFailed {
		t.Fatalf("status = %q, want failed", item.Status)
	}
}

func TestServiceExhaustsRetryBudget(t *testing.T) {
	t.Parallel()
	store := newLocalStore(t)
	sink := &fakeSink{name: "fake", results: []fakeResult{
		{err: errors.New("retryable")},
	}}
	enqueue(t, store, 4)

	svc, err := NewService(Config{
		Sink:           sink,
		Store:          store,
		MaxAttempts:    2,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	// First tick: attempts -> 1, still pending.
	svc.tick(context.Background())
	if item, _, _ := store.GetSTHAnchorOutboxItem(context.Background(), 4); item.Status != model.AnchorStatePending {
		t.Fatalf("after first tick status = %q, want pending", item.Status)
	}
	// Force backoff elapsed so ListPending returns the item again.
	if err := store.RescheduleSTHAnchor(context.Background(), 4, 1, 0, "retryable"); err != nil {
		t.Fatalf("RescheduleSTHAnchor: %v", err)
	}
	// Second tick: attempts -> 2, hits max, transitions to failed.
	svc.tick(context.Background())
	item, _, _ := store.GetSTHAnchorOutboxItem(context.Background(), 4)
	if item.Status != model.AnchorStateFailed {
		t.Fatalf("after exhausted status = %q, want failed", item.Status)
	}
}

func TestServiceStartStopTrigger(t *testing.T) {
	t.Parallel()
	store := newLocalStore(t)
	var published atomic.Int32
	sink := &fakeSink{name: "fake", results: []fakeResult{
		{result: model.STHAnchorResult{AnchorID: "ok"}},
	}}
	svc, err := NewService(Config{
		Sink:         sink,
		Store:        store,
		PollInterval: time.Hour, // rely on Trigger, not the tick
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)
	defer svc.Stop()

	enqueue(t, store, 5)
	svc.Trigger()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if item, ok, _ := store.GetSTHAnchorOutboxItem(context.Background(), 5); ok && item.Status == model.AnchorStatePublished {
			published.Add(1)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if published.Load() == 0 {
		t.Fatalf("trigger did not cause publish within deadline")
	}
}

func TestComputeBackoffCapsAtMax(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		attempts int
		want     time.Duration
	}{
		{1, 1 * time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 10 * time.Second}, // capped
		{100, 10 * time.Second},
	} {
		got := computeBackoff(time.Second, 10*time.Second, tc.attempts)
		if got != tc.want {
			t.Fatalf("computeBackoff(1s, 10s, %d) = %s, want %s", tc.attempts, got, tc.want)
		}
	}
}
