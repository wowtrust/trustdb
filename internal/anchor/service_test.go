package anchor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

type fakeSink struct {
	name string

	mu        sync.Mutex
	calls     []model.SignedTreeHead
	results   []fakeResult
	onPublish func(context.Context, model.SignedTreeHead)
}

type fakeResult struct {
	result model.STHAnchorResult
	err    error
}

func (f *fakeSink) Name() string { return f.name }

func (f *fakeSink) Publish(ctx context.Context, sth model.SignedTreeHead) (model.STHAnchorResult, error) {
	if f.onPublish != nil {
		f.onPublish(ctx, sth)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, sth)
	idx := len(f.calls) - 1
	if idx >= len(f.results) {
		idx = len(f.results) - 1
	}
	if idx < 0 {
		return model.STHAnchorResult{}, errors.New("fake sink has no result")
	}
	result := f.results[idx]
	if result.err != nil {
		return model.STHAnchorResult{}, result.err
	}
	out := result.result
	if out.TreeSize == 0 {
		out.TreeSize = sth.TreeSize
	}
	out.RootHash = append([]byte(nil), sth.RootHash...)
	out.STH = sth
	out.SinkName = f.name
	return out, nil
}

func (f *fakeSink) snapshots() []model.SignedTreeHead {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.SignedTreeHead(nil), f.calls...)
}

func testScheduleKey(sink string) model.STHAnchorScheduleKey {
	return model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: sink}
}

func testSTH(key model.STHAnchorScheduleKey, treeSize uint64, seed byte) model.SignedTreeHead {
	return model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       treeSize,
		RootHash:       bytes.Repeat([]byte{seed}, 32),
		TimestampUnixN: int64(treeSize),
		NodeID:         key.NodeID,
		LogID:          key.LogID,
		Signature: model.Signature{
			Alg: model.DefaultSignatureAlg, KeyID: "server-key", Signature: bytes.Repeat([]byte{seed}, 64),
		},
	}
}

func offer(t *testing.T, store proofstore.Store, key model.STHAnchorScheduleKey, sth model.SignedTreeHead, openedAt, dueAt int64) {
	t.Helper()
	scheduler := store.(proofstore.STHAnchorScheduleStore)
	if _, err := scheduler.UpsertSTHAnchorCandidate(context.Background(), model.STHAnchorCandidate{
		Key: key, STH: sth, ObservedAtUnixN: openedAt, DueAtUnixN: dueAt,
	}); err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate: %v", err)
	}
}

func newTestService(t *testing.T, store proofstore.Store, sink Sink, key model.STHAnchorScheduleKey, now *time.Time, extra func(*Config)) *Service {
	t.Helper()
	var tokens int
	cfg := Config{
		Sink: sink, Store: store, Key: key,
		Clock:          func() time.Time { return *now },
		NewLeaseToken:  func() string { tokens++; return fmt.Sprintf("lease-%d", tokens) },
		PerCallTimeout: time.Second, LeaseDuration: time.Second,
		InitialBackoff: time.Second, MaxBackoff: 10 * time.Second,
	}
	if extra != nil {
		extra(&cfg)
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestServiceWaitsForFixedDeadline(t *testing.T) {
	t.Parallel()
	store := proofstore.LocalStore{Root: t.TempDir()}
	key := testScheduleKey("fake")
	sth := testSTH(key, 1, 0x11)
	offer(t, store, key, sth, 100, 200)
	now := time.Unix(0, 199)
	sink := &fakeSink{name: "fake", results: []fakeResult{{result: model.STHAnchorResult{AnchorID: "anchor-1"}}}}
	svc := newTestService(t, store, sink, key, &now, nil)

	svc.tick(context.Background())
	if got := len(sink.snapshots()); got != 0 {
		t.Fatalf("sink calls before deadline=%d, want 0", got)
	}
	schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.Pending == nil || schedule.Pending.DueAtUnixN != 200 {
		t.Fatalf("pending schedule=%+v found=%v err=%v", schedule, found, err)
	}
}

func TestServicePublishesExpiredPendingAndCompletes(t *testing.T) {
	t.Parallel()
	store := proofstore.LocalStore{Root: t.TempDir()}
	key := testScheduleKey("fake")
	sth := testSTH(key, 2, 0x22)
	offer(t, store, key, sth, 100, 200)
	now := time.Unix(0, 200)
	sink := &fakeSink{name: "fake", results: []fakeResult{{result: model.STHAnchorResult{AnchorID: "anchor-2"}}}}
	svc := newTestService(t, store, sink, key, &now, nil)

	svc.tick(context.Background())
	result, found, err := store.GetSTHAnchorResult(context.Background(), 2)
	if err != nil || !found || result.AnchorID != "anchor-2" || !reflect.DeepEqual(result.STH, sth) {
		t.Fatalf("anchor result=%+v found=%v err=%v", result, found, err)
	}
	schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.Pending != nil || schedule.InFlight != nil {
		t.Fatalf("completed schedule=%+v found=%v err=%v", schedule, found, err)
	}
}

func TestServiceRefreshesPendingMetricAfterCanceledCompletion(t *testing.T) {
	t.Parallel()
	store := proofstore.LocalStore{Root: t.TempDir()}
	key := testScheduleKey("fake")
	sth := testSTH(key, 12, 0x12)
	offer(t, store, key, sth, 100, 100)
	now := time.Unix(0, 100)
	metrics := observability.NewMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	sink := &fakeSink{
		name:    "fake",
		results: []fakeResult{{result: model.STHAnchorResult{AnchorID: "anchor-12"}}},
		onPublish: func(context.Context, model.SignedTreeHead) {
			cancel()
		},
	}
	svc := newTestService(t, store, sink, key, &now, func(cfg *Config) { cfg.Metrics = metrics })

	svc.tick(ctx)
	result, found, err := store.GetSTHAnchorResult(context.Background(), sth.TreeSize)
	if err != nil || !found || result.AnchorID != "anchor-12" {
		t.Fatalf("anchor result=%+v found=%v err=%v", result, found, err)
	}
	if got := testutil.ToFloat64(metrics.AnchorPending); got != 0 {
		t.Fatalf("anchor pending gauge after completion = %v, want 0", got)
	}
}

func TestServicePendingMetricIncludesCandidateAddedDuringPublish(t *testing.T) {
	t.Parallel()
	store := proofstore.LocalStore{Root: t.TempDir()}
	key := testScheduleKey("fake")
	oldSTH := testSTH(key, 13, 0x13)
	newSTH := testSTH(key, 14, 0x14)
	offer(t, store, key, oldSTH, 100, 100)
	now := time.Unix(0, 100)
	metrics := observability.NewMetrics()
	sink := &fakeSink{
		name:    "fake",
		results: []fakeResult{{result: model.STHAnchorResult{AnchorID: "anchor-13"}}},
		onPublish: func(context.Context, model.SignedTreeHead) {
			offer(t, store, key, newSTH, 110, 200)
		},
	}
	svc := newTestService(t, store, sink, key, &now, func(cfg *Config) { cfg.Metrics = metrics })

	svc.tick(context.Background())
	schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.Pending == nil || schedule.Pending.Target.TreeSize != newSTH.TreeSize {
		t.Fatalf("schedule after concurrent candidate=%+v found=%v err=%v", schedule, found, err)
	}
	if got := testutil.ToFloat64(metrics.AnchorPending); got != 1 {
		t.Fatalf("anchor pending gauge after concurrent candidate = %v, want 1", got)
	}
}

func TestServiceRetriesSameImmutableInFlight(t *testing.T) {
	t.Parallel()
	store := proofstore.LocalStore{Root: t.TempDir()}
	key := testScheduleKey("fake")
	sth := testSTH(key, 3, 0x33)
	offer(t, store, key, sth, 100, 100)
	now := time.Unix(0, 100)
	sink := &fakeSink{name: "fake", results: []fakeResult{
		{err: errors.New("temporary outage")},
		{result: model.STHAnchorResult{AnchorID: "anchor-3"}},
	}}
	svc := newTestService(t, store, sink, key, &now, nil)

	svc.tick(context.Background())
	schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.InFlight == nil || schedule.InFlight.Attempts != 1 || schedule.InFlight.Target.TreeSize != 3 {
		t.Fatalf("rescheduled state=%+v found=%v err=%v", schedule, found, err)
	}
	now = time.Unix(0, schedule.InFlight.NextAttemptUnixN)
	svc.tick(context.Background())
	calls := sink.snapshots()
	if len(calls) != 2 || !reflect.DeepEqual(calls[0], sth) || !reflect.DeepEqual(calls[1], sth) {
		t.Fatalf("retry calls=%+v, want identical STH", calls)
	}
}

func TestServicePermanentFailureIsTerminal(t *testing.T) {
	t.Parallel()
	store := proofstore.LocalStore{Root: t.TempDir()}
	key := testScheduleKey("fake")
	offer(t, store, key, testSTH(key, 4, 0x44), 100, 100)
	now := time.Unix(0, 100)
	sink := &fakeSink{name: "fake", results: []fakeResult{{err: fmt.Errorf("%w: bad schema", ErrPermanent)}}}
	metrics := observability.NewMetrics()
	svc := newTestService(t, store, sink, key, &now, func(cfg *Config) { cfg.Metrics = metrics })

	svc.tick(context.Background())
	schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.InFlight == nil || !schedule.InFlight.TerminalFailure || schedule.InFlight.Attempts != 1 {
		t.Fatalf("terminal schedule=%+v found=%v err=%v", schedule, found, err)
	}
	now = now.Add(time.Hour)
	svc.tick(context.Background())
	if got := len(sink.snapshots()); got != 1 {
		t.Fatalf("terminal target retried %d times, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.AnchorInFlight); got != 0 {
		t.Fatalf("anchor in-flight gauge after terminal publish = %v, want 0", got)
	}
}

type emptyPermanentError struct{}

func (emptyPermanentError) Error() string { return "" }
func (emptyPermanentError) Unwrap() error { return ErrPermanent }

func TestServiceEmptyProviderErrorPersistsTerminalFailure(t *testing.T) {
	t.Parallel()
	store := proofstore.LocalStore{Root: t.TempDir()}
	key := testScheduleKey("fake")
	offer(t, store, key, testSTH(key, 17, 0x17), 100, 100)
	now := time.Unix(0, 100)
	sink := &fakeSink{name: "fake", results: []fakeResult{{err: emptyPermanentError{}}}}
	svc := newTestService(t, store, sink, key, &now, nil)

	svc.tick(context.Background())
	schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.InFlight == nil || !schedule.InFlight.TerminalFailure || schedule.InFlight.Attempts != 1 {
		t.Fatalf("empty-error terminal schedule=%+v found=%v err=%v", schedule, found, err)
	}
	if schedule.InFlight.LastErrorMessage != "anchor provider returned an unspecified error" {
		t.Fatalf("empty-error fallback=%q", schedule.InFlight.LastErrorMessage)
	}
}

type invalidSuccessfulSink struct {
	name  string
	calls atomic.Int64
}

func (s *invalidSuccessfulSink) Name() string { return s.name }

func (s *invalidSuccessfulSink) Publish(_ context.Context, sth model.SignedTreeHead) (model.STHAnchorResult, error) {
	s.calls.Add(1)
	conflictingRoot := bytes.Repeat([]byte{0xff}, len(sth.RootHash))
	return model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		NodeID:        sth.NodeID,
		LogID:         sth.LogID,
		TreeSize:      sth.TreeSize,
		SinkName:      s.name,
		AnchorID:      "invalid-anchor",
		RootHash:      conflictingRoot,
		STH:           sth,
	}, nil
}

func TestServiceInvalidSuccessfulResultIsTerminal(t *testing.T) {
	t.Parallel()
	store := proofstore.LocalStore{Root: t.TempDir()}
	key := testScheduleKey("invalid-success")
	offer(t, store, key, testSTH(key, 15, 0x15), 100, 100)
	now := time.Unix(0, 100)
	sink := &invalidSuccessfulSink{name: key.SinkName}
	svc := newTestService(t, store, sink, key, &now, nil)

	svc.tick(context.Background())
	schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.InFlight == nil || !schedule.InFlight.TerminalFailure || schedule.InFlight.Attempts != 1 {
		t.Fatalf("invalid result schedule=%+v found=%v err=%v", schedule, found, err)
	}
	if !strings.Contains(schedule.InFlight.LastErrorMessage, "invalid successful sink result") {
		t.Fatalf("terminal error=%q, want invalid result context", schedule.InFlight.LastErrorMessage)
	}
	now = time.Unix(0, schedule.InFlight.LeaseUntilUnixN+1)
	svc.tick(context.Background())
	if calls := sink.calls.Load(); calls != 1 {
		t.Fatalf("invalid successful result was resubmitted %d times, want 1", calls)
	}
}

func TestServicePreservesPendingWhileOlderInFlightPublishes(t *testing.T) {
	t.Parallel()
	store := proofstore.LocalStore{Root: t.TempDir()}
	scheduler := proofstore.STHAnchorScheduleStore(store)
	key := testScheduleKey("fake")
	oldSTH := testSTH(key, 5, 0x55)
	newSTH := testSTH(key, 8, 0x88)
	offer(t, store, key, oldSTH, 100, 100)
	if _, claimed, err := scheduler.ClaimSTHAnchorAttempt(context.Background(), key, 100, 150, "dead-worker", "dead-lease"); err != nil || !claimed {
		t.Fatalf("manual claim claimed=%v err=%v", claimed, err)
	}
	offer(t, store, key, newSTH, 120, 130)
	now := time.Unix(0, 151)
	sink := &fakeSink{name: "fake", results: []fakeResult{
		{result: model.STHAnchorResult{AnchorID: "anchor-5"}},
		{result: model.STHAnchorResult{AnchorID: "anchor-8"}},
	}}
	svc := newTestService(t, store, sink, key, &now, nil)

	svc.tick(context.Background())
	schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.InFlight != nil || schedule.Pending == nil || schedule.Pending.Target.TreeSize != 8 {
		t.Fatalf("after old completion schedule=%+v found=%v err=%v", schedule, found, err)
	}
	svc.tick(context.Background())
	calls := sink.snapshots()
	if len(calls) != 2 || calls[0].TreeSize != 5 || calls[1].TreeSize != 8 {
		t.Fatalf("publish order=%+v, want [5 8]", calls)
	}
}

type failCompletionStore struct {
	proofstore.Store
	schedule          proofstore.STHAnchorScheduleStore
	failOnce          bool
	completionStarted chan struct{}
	completionRelease chan struct{}
	completionOnce    sync.Once
}

func (s *failCompletionStore) UpsertSTHAnchorCandidate(ctx context.Context, c model.STHAnchorCandidate) (model.STHAnchorSchedule, error) {
	return s.schedule.UpsertSTHAnchorCandidate(ctx, c)
}
func (s *failCompletionStore) GetSTHAnchorSchedule(ctx context.Context, key model.STHAnchorScheduleKey) (model.STHAnchorSchedule, bool, error) {
	return s.schedule.GetSTHAnchorSchedule(ctx, key)
}
func (s *failCompletionStore) ListSTHAnchorSchedules(ctx context.Context) ([]model.STHAnchorSchedule, error) {
	return s.schedule.ListSTHAnchorSchedules(ctx)
}
func (s *failCompletionStore) ClaimSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, now, leaseUntil int64, owner, token string) (model.STHAnchorAttempt, bool, error) {
	return s.schedule.ClaimSTHAnchorAttempt(ctx, key, now, leaseUntil, owner, token)
}
func (s *failCompletionStore) RescheduleSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, generation uint64, token string, attempts int, next int64, last string) error {
	return s.schedule.RescheduleSTHAnchorAttempt(ctx, key, generation, token, attempts, next, last)
}
func (s *failCompletionStore) FailSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, generation uint64, token string, attempts int, last string) error {
	return s.schedule.FailSTHAnchorAttempt(ctx, key, generation, token, attempts, last)
}
func (s *failCompletionStore) CompleteSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, generation uint64, token string, result model.STHAnchorResult) error {
	block := false
	if s.completionStarted != nil {
		s.completionOnce.Do(func() {
			block = true
			close(s.completionStarted)
		})
	}
	if block && s.completionRelease != nil {
		select {
		case <-s.completionRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if s.failOnce {
		s.failOnce = false
		return trusterr.New(trusterr.CodeDataLoss, "injected completion failure")
	}
	return s.schedule.CompleteSTHAnchorAttempt(ctx, key, generation, token, result)
}

func TestServiceLeaseCoversPublishAndCompletionBudgets(t *testing.T) {
	base := proofstore.LocalStore{Root: t.TempDir()}
	wrapped := &failCompletionStore{
		Store:             base,
		schedule:          base,
		completionStarted: make(chan struct{}),
		completionRelease: make(chan struct{}),
	}
	key := testScheduleKey("fake")
	sth := testSTH(key, 16, 0x16)
	start := time.Now().UTC()
	offer(t, wrapped, key, sth, start.UnixNano(), start.UnixNano())
	const perCallTimeout = 500 * time.Millisecond
	var nowUnixN atomic.Int64
	nowUnixN.Store(start.UnixNano())
	clock := func() time.Time { return time.Unix(0, nowUnixN.Load()).UTC() }
	firstSink := &fakeSink{
		name:    key.SinkName,
		results: []fakeResult{{result: model.STHAnchorResult{AnchorID: "anchor-16"}}},
		onPublish: func(ctx context.Context, _ model.SignedTreeHead) {
			timer := time.NewTimer(400 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
			}
		},
	}
	newService := func(sink Sink, tokenPrefix string) *Service {
		var token atomic.Int64
		svc, err := NewService(Config{
			Sink: sink, Store: wrapped, Key: key,
			Clock:          clock,
			NewLeaseToken:  func() string { return fmt.Sprintf("%s-%d", tokenPrefix, token.Add(1)) },
			PerCallTimeout: perCallTimeout,
			LeaseDuration:  2 * perCallTimeout,
			InitialBackoff: time.Millisecond,
			MaxBackoff:     time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewService(%s): %v", tokenPrefix, err)
		}
		return svc
	}
	first := newService(firstSink, "first")
	if first.cfg.LeaseDuration <= 2*perCallTimeout {
		t.Fatalf("lease duration=%s, want safely greater than two call budgets", first.cfg.LeaseDuration)
	}
	firstDone := make(chan struct{})
	go func() {
		first.tick(context.Background())
		close(firstDone)
	}()
	select {
	case <-wrapped.completionStarted:
	case <-time.After(time.Second):
		t.Fatal("completion persistence did not start")
	}

	// At the end of two nominal call budgets the first worker is still
	// persisting. The safety margin must prevent a second worker from
	// reclaiming and repeating the external side effect.
	nowUnixN.Store(start.Add(2 * perCallTimeout).UnixNano())
	secondSink := &fakeSink{name: key.SinkName, results: []fakeResult{{result: model.STHAnchorResult{AnchorID: "duplicate"}}}}
	second := newService(secondSink, "second")
	second.tick(context.Background())
	if calls := len(secondSink.snapshots()); calls != 0 {
		t.Fatalf("second worker published %d times while first completion was in budget", calls)
	}
	close(wrapped.completionRelease)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first worker did not finish completion")
	}
	if _, found, err := base.GetSTHAnchorResult(context.Background(), sth.TreeSize); err != nil || !found {
		t.Fatalf("completed anchor result found=%v err=%v", found, err)
	}
}

func TestServiceRetriesAfterProviderSuccessBeforeLocalCompletion(t *testing.T) {
	t.Parallel()
	base := proofstore.LocalStore{Root: t.TempDir()}
	wrapped := &failCompletionStore{Store: base, schedule: base, failOnce: true}
	key := testScheduleKey("fake")
	sth := testSTH(key, 9, 0x99)
	offer(t, wrapped, key, sth, 100, 100)
	now := time.Unix(0, 100)
	sink := &fakeSink{name: "fake", results: []fakeResult{{result: model.STHAnchorResult{AnchorID: "anchor-9"}}}}
	svc := newTestService(t, wrapped, sink, key, &now, nil)

	svc.tick(context.Background())
	if _, found, err := base.GetSTHAnchorResult(context.Background(), 9); err != nil || found {
		t.Fatalf("result after injected crash found=%v err=%v", found, err)
	}
	schedule, found, err := base.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.InFlight == nil {
		t.Fatalf("in-flight after injected crash=%+v found=%v err=%v", schedule, found, err)
	}
	now = time.Unix(0, schedule.InFlight.LeaseUntilUnixN+1)
	svc.tick(context.Background())
	calls := sink.snapshots()
	if len(calls) != 2 || !reflect.DeepEqual(calls[0], calls[1]) {
		t.Fatalf("provider retry calls=%+v, want exact same STH", calls)
	}
	if _, found, err := base.GetSTHAnchorResult(context.Background(), 9); err != nil || !found {
		t.Fatalf("result after retry found=%v err=%v", found, err)
	}
}

func TestServiceStopDoesNotFlushPending(t *testing.T) {
	t.Parallel()
	store := proofstore.LocalStore{Root: t.TempDir()}
	key := testScheduleKey("fake")
	offer(t, store, key, testSTH(key, 10, 0xaa), 100, 1_000)
	now := time.Unix(0, 100)
	sink := &fakeSink{name: "fake", results: []fakeResult{{result: model.STHAnchorResult{AnchorID: "anchor-10"}}}}
	svc := newTestService(t, store, sink, key, &now, func(cfg *Config) { cfg.PollInterval = time.Hour })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)
	svc.Trigger()
	svc.Stop()

	if got := len(sink.snapshots()); got != 0 {
		t.Fatalf("shutdown flushed %d pending anchors, want 0", got)
	}
	schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.Pending == nil || schedule.Pending.DueAtUnixN != 1_000 {
		t.Fatalf("persisted pending=%+v found=%v err=%v", schedule, found, err)
	}
}

type blockingSink struct {
	name    string
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingSink) Name() string { return s.name }

func (s *blockingSink) Publish(ctx context.Context, _ model.SignedTreeHead) (model.STHAnchorResult, error) {
	s.once.Do(func() { close(s.started) })
	select {
	case <-s.release:
		return model.STHAnchorResult{AnchorID: "blocking-anchor"}, nil
	case <-ctx.Done():
		return model.STHAnchorResult{}, ctx.Err()
	}
}

func TestServiceStopRejectsOverlappingRestart(t *testing.T) {
	store := proofstore.LocalStore{Root: t.TempDir()}
	key := testScheduleKey("blocking")
	offer(t, store, key, testSTH(key, 11, 0xbb), 100, 100)
	now := time.Unix(0, 100)
	sink := &blockingSink{name: "blocking", started: make(chan struct{}), release: make(chan struct{})}
	svc := newTestService(t, store, sink, key, &now, func(cfg *Config) {
		cfg.PollInterval = time.Hour
		cfg.PerCallTimeout = 5 * time.Second
		cfg.LeaseDuration = 10 * time.Second
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)
	select {
	case <-sink.started:
	case <-time.After(2 * time.Second):
		t.Fatal("anchor publish did not start")
	}

	stopped := make(chan struct{})
	go func() {
		svc.Stop()
		close(stopped)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		svc.mu.Lock()
		stopRequested := svc.stop == nil || !svc.running
		svc.mu.Unlock()
		if stopRequested {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("service stop was not observed")
		}
		time.Sleep(time.Millisecond)
	}

	// Start must remain a no-op until the old bounded publish returns.
	svc.Start(context.Background())
	close(sink.release)
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("service stop blocked after an overlapping restart attempt")
	}
	svc.mu.Lock()
	running := svc.running
	svc.mu.Unlock()
	if running {
		t.Fatal("service still running after stop")
	}
}

func TestServiceContextCancellationAllowsRestart(t *testing.T) {
	store := proofstore.LocalStore{Root: t.TempDir()}
	key := testScheduleKey("fake")
	now := time.Unix(0, 100)
	sink := &fakeSink{name: "fake", results: []fakeResult{{result: model.STHAnchorResult{AnchorID: "unused"}}}}
	svc := newTestService(t, store, sink, key, &now, func(cfg *Config) { cfg.PollInterval = time.Hour })

	ctx, cancel := context.WithCancel(context.Background())
	svc.Start(ctx)
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for {
		svc.mu.Lock()
		stopped := !svc.running
		svc.mu.Unlock()
		if stopped {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("service did not clear running state after context cancellation")
		}
		time.Sleep(time.Millisecond)
	}

	restartCtx, restartCancel := context.WithCancel(context.Background())
	defer restartCancel()
	svc.Start(restartCtx)
	svc.mu.Lock()
	restarted := svc.running
	svc.mu.Unlock()
	if !restarted {
		t.Fatal("service did not restart after context cancellation")
	}
	svc.Stop()
}

func TestComputeBackoffCapsAtMax(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		attempts int
		want     time.Duration
	}{
		{1, time.Second}, {2, 2 * time.Second}, {3, 4 * time.Second},
		{4, 8 * time.Second}, {5, 10 * time.Second}, {100, 10 * time.Second},
	} {
		if got := computeBackoff(time.Second, 10*time.Second, tc.attempts); got != tc.want {
			t.Fatalf("computeBackoff attempt=%d got=%s want=%s", tc.attempts, got, tc.want)
		}
	}
}
