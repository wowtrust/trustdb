package batch

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/observability"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

type unsafeCheckpointLocalStore struct{ proofstore.LocalStore }

func (unsafeCheckpointLocalStore) WALCheckpointPruneSafe() bool { return false }

type checkpointRecordingStore struct {
	proofstore.LocalStore

	mu        sync.Mutex
	failPuts  int
	attempts  []model.WALCheckpoint
	persisted []model.WALCheckpoint
}

func (*checkpointRecordingStore) WALCheckpointPruneSafe() bool { return true }

type checkpointSafeLocalStore struct {
	proofstore.LocalStore
}

func (checkpointSafeLocalStore) WALCheckpointPruneSafe() bool { return true }

type outOfOrderCheckpointEngine struct {
	lowEntered  chan struct{}
	lowRelease  chan struct{}
	highEntered chan struct{}
}

func (e outOfOrderCheckpointEngine) CommitBatchIndexes(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) (model.BatchRoot, []model.RecordIndex, error) {
	return fakeEngine{}.CommitBatchIndexes(batchID, closedAt, signed, records, accepted)
}

func (e outOfOrderCheckpointEngine) CommitBatch(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) ([]model.ProofBundle, error) {
	if len(records) > 0 {
		switch records[0].WAL.Sequence {
		case 1:
			select {
			case e.lowEntered <- struct{}{}:
			default:
			}
			<-e.lowRelease
		case 2:
			select {
			case e.highEntered <- struct{}{}:
			default:
			}
		}
	}
	return fakeEngine{}.CommitBatch(batchID, closedAt, signed, records, accepted)
}

func (s *checkpointRecordingStore) PutCheckpoint(ctx context.Context, cp model.WALCheckpoint) error {
	s.mu.Lock()
	s.attempts = append(s.attempts, cp)
	if s.failPuts > 0 {
		s.failPuts--
		s.mu.Unlock()
		return errors.New("injected checkpoint write failure")
	}
	s.mu.Unlock()
	if err := s.LocalStore.PutCheckpoint(ctx, cp); err != nil {
		return err
	}
	s.mu.Lock()
	s.persisted = append(s.persisted, cp)
	s.mu.Unlock()
	return nil
}

func (s *checkpointRecordingStore) snapshots() (attempts, persisted []model.WALCheckpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.WALCheckpoint(nil), s.attempts...), append([]model.WALCheckpoint(nil), s.persisted...)
}

func checkpointAccepted(recordID string, pos model.WALPosition) Accepted {
	record := recordWithWAL(recordID, pos.Sequence)
	record.WAL = pos
	return Accepted{Signed: signed(recordID), Record: record, Accepted: accepted(recordID)}
}

func persistCheckpointTestBatch(t *testing.T, svc *Service, batchID string, items ...Accepted) {
	t.Helper()
	if err := svc.persistBatch(context.Background(), batchID, time.Unix(0, int64(len(batchID))).UTC(), items); err != nil {
		t.Fatalf("persistBatch(%q) error = %v", batchID, err)
	}
}

func readCheckpointExact(t *testing.T, store interface {
	GetCheckpoint(context.Context) (model.WALCheckpoint, bool, error)
}) (model.WALCheckpoint, bool) {
	t.Helper()
	cp, found, err := store.GetCheckpoint(context.Background())
	if err != nil {
		t.Fatalf("GetCheckpoint() error = %v", err)
	}
	return cp, found
}

func TestServiceCheckpointStopsAtSparseGap(t *testing.T) {
	store := checkpointSafeLocalStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	var hooks []model.WALCheckpoint
	svc := New(fakeEngine{}, store, Options{
		OnCheckpointAdvanced: func(_ context.Context, cp model.WALCheckpoint) {
			hooks = append(hooks, cp)
		},
	}, nil)
	defer svc.Shutdown(context.Background())

	seq1 := checkpointAccepted("sparse-1", model.WALPosition{SegmentID: 1, Offset: 100, Sequence: 1})
	seq3 := checkpointAccepted("sparse-3", model.WALPosition{SegmentID: 2, Offset: 300, Sequence: 3})
	persistCheckpointTestBatch(t, svc, "batch-sparse", seq1, seq3)

	cp, found := readCheckpointExact(t, store)
	if !found || cp.LastSequence != 1 {
		t.Fatalf("checkpoint after sparse commit = %+v found=%v, want sequence 1", cp, found)
	}
	if cp.SchemaVersion != model.SchemaWALCheckpointContiguous {
		t.Fatalf("checkpoint schema = %q, want %q", cp.SchemaVersion, model.SchemaWALCheckpointContiguous)
	}
	if len(hooks) != 1 || hooks[0].LastSequence != 1 {
		t.Fatalf("checkpoint hooks after sparse commit = %+v, want [1]", hooks)
	}

	seq2 := checkpointAccepted("sparse-2", model.WALPosition{SegmentID: 1, Offset: 200, Sequence: 2})
	persistCheckpointTestBatch(t, svc, "batch-bridge", seq2)
	cp, found = readCheckpointExact(t, store)
	if !found || cp.LastSequence != 3 || cp.SegmentID != 2 || cp.LastOffset != 300 || cp.BatchID != "batch-sparse" {
		t.Fatalf("checkpoint after closing gap = %+v found=%v", cp, found)
	}
	if len(hooks) != 2 || hooks[1].LastSequence != 3 {
		t.Fatalf("checkpoint hooks after closing gap = %+v, want [1,3]", hooks)
	}
}

func TestServiceCheckpointHookRunsOutsideLockInPersistedOrder(t *testing.T) {
	store := checkpointSafeLocalStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	firstHookEntered := make(chan struct{})
	releaseFirstHook := make(chan struct{})
	hookSequences := make(chan uint64, 2)
	svc := New(fakeEngine{}, store, Options{
		OnCheckpointAdvanced: func(_ context.Context, cp model.WALCheckpoint) {
			if cp.LastSequence == 1 {
				close(firstHookEntered)
				<-releaseFirstHook
			}
			hookSequences <- cp.LastSequence
		},
	}, nil)
	defer svc.Shutdown(context.Background())

	firstDone := make(chan error, 1)
	go func() {
		pos := model.WALPosition{SegmentID: 1, Offset: 100, Sequence: 1}
		firstDone <- svc.RecordCommittedWALRange(context.Background(), pos, pos, "batch-1")
	}()
	select {
	case <-firstHookEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("sequence-1 checkpoint hook did not start")
	}

	secondDone := make(chan error, 1)
	go func() {
		pos := model.WALPosition{SegmentID: 1, Offset: 200, Sequence: 2}
		secondDone <- svc.RecordCommittedWALRange(context.Background(), pos, pos, "batch-2")
	}()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("RecordCommittedWALRange(sequence 2) error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sequence-2 checkpoint persistence blocked behind sequence-1 hook")
	}
	if cp, found := readCheckpointExact(t, store); !found || cp.LastSequence != 2 {
		t.Fatalf("checkpoint while first hook is blocked = %+v found=%v, want sequence 2", cp, found)
	}
	select {
	case seq := <-hookSequences:
		t.Fatalf("hook sequence %d completed before sequence 1 was released", seq)
	default:
	}

	close(releaseFirstHook)
	if err := <-firstDone; err != nil {
		t.Fatalf("RecordCommittedWALRange(sequence 1) error = %v", err)
	}
	for _, want := range []uint64{1, 2} {
		select {
		case got := <-hookSequences:
			if got != want {
				t.Fatalf("checkpoint hook sequence = %d, want %d", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("checkpoint hook sequence %d did not complete", want)
		}
	}
}

func TestServiceCheckpointHookCoalescesSlowPendingAdvances(t *testing.T) {
	store := checkpointSafeLocalStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	firstHookEntered := make(chan struct{})
	releaseFirstHook := make(chan struct{})
	hookSequences := make(chan uint64, 2)
	svc := New(fakeEngine{}, store, Options{
		OnCheckpointAdvanced: func(_ context.Context, cp model.WALCheckpoint) {
			if cp.LastSequence == 1 {
				close(firstHookEntered)
				<-releaseFirstHook
			}
			hookSequences <- cp.LastSequence
		},
	}, nil)
	defer svc.Shutdown(context.Background())

	firstDone := make(chan error, 1)
	go func() {
		pos := model.WALPosition{SegmentID: 1, Offset: 100, Sequence: 1}
		firstDone <- svc.RecordCommittedWALRange(context.Background(), pos, pos, "batch-1")
	}()
	select {
	case <-firstHookEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("sequence-1 checkpoint hook did not start")
	}

	for seq := uint64(2); seq <= 3; seq++ {
		pos := model.WALPosition{SegmentID: 1, Offset: int64(seq) * 100, Sequence: seq}
		if err := svc.RecordCommittedWALRange(context.Background(), pos, pos, "batch-pending"); err != nil {
			t.Fatalf("RecordCommittedWALRange(sequence %d) error = %v", seq, err)
		}
	}
	if cp, found := readCheckpointExact(t, store); !found || cp.LastSequence != 3 {
		t.Fatalf("checkpoint while first hook is blocked = %+v found=%v, want sequence 3", cp, found)
	}

	svc.checkpointMu.Lock()
	if len(svc.checkpointCallbacks) != 1 || svc.checkpointCallbacks[0].checkpoint.LastSequence != 3 {
		callbacks := append([]walCheckpointCallback(nil), svc.checkpointCallbacks...)
		svc.checkpointMu.Unlock()
		t.Fatalf("pending checkpoint callbacks = %+v, want one sequence-3 callback", callbacks)
	}
	svc.checkpointMu.Unlock()

	close(releaseFirstHook)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("RecordCommittedWALRange(sequence 1) error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("coalesced checkpoint hook drain did not finish")
	}
	for _, want := range []uint64{1, 3} {
		select {
		case got := <-hookSequences:
			if got != want {
				t.Fatalf("checkpoint hook sequence = %d, want %d", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("checkpoint hook sequence %d did not complete", want)
		}
	}
	select {
	case got := <-hookSequences:
		t.Fatalf("unexpected uncoalesced checkpoint hook sequence %d", got)
	default:
	}
}

func TestServiceCheckpointHookCanAdvanceReentrantly(t *testing.T) {
	store := checkpointSafeLocalStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	var (
		svc           *Service
		hookSequences []uint64
		reentrantErr  error
	)
	svc = New(fakeEngine{}, store, Options{
		OnCheckpointAdvanced: func(_ context.Context, cp model.WALCheckpoint) {
			hookSequences = append(hookSequences, cp.LastSequence)
			if cp.LastSequence == 1 {
				pos := model.WALPosition{SegmentID: 1, Offset: 200, Sequence: 2}
				reentrantErr = svc.RecordCommittedWALRange(context.Background(), pos, pos, "batch-2")
			}
		},
	}, nil)
	defer svc.Shutdown(context.Background())

	done := make(chan error, 1)
	go func() {
		pos := model.WALPosition{SegmentID: 1, Offset: 100, Sequence: 1}
		done <- svc.RecordCommittedWALRange(context.Background(), pos, pos, "batch-1")
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RecordCommittedWALRange(sequence 1) error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reentrant checkpoint hook deadlocked")
	}
	if reentrantErr != nil {
		t.Fatalf("reentrant RecordCommittedWALRange() error = %v", reentrantErr)
	}
	if !equalUint64s(hookSequences, []uint64{1, 2}) {
		t.Fatalf("checkpoint hooks = %v, want [1 2]", hookSequences)
	}
	if cp, found := readCheckpointExact(t, store); !found || cp.LastSequence != 2 {
		t.Fatalf("checkpoint after reentrant advance = %+v found=%v, want sequence 2", cp, found)
	}
}

func TestServiceCheckpointHookPanicDoesNotStopDrain(t *testing.T) {
	store := checkpointSafeLocalStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	var (
		svc           *Service
		hookSequences []uint64
	)
	svc = New(fakeEngine{}, store, Options{
		OnCheckpointAdvanced: func(_ context.Context, cp model.WALCheckpoint) {
			hookSequences = append(hookSequences, cp.LastSequence)
			if cp.LastSequence == 1 {
				pos := model.WALPosition{SegmentID: 1, Offset: 200, Sequence: 2}
				if err := svc.RecordCommittedWALRange(context.Background(), pos, pos, "batch-2"); err != nil {
					t.Errorf("reentrant RecordCommittedWALRange() error = %v", err)
				}
				panic("injected checkpoint hook panic")
			}
		},
	}, nil)
	defer svc.Shutdown(context.Background())

	pos := model.WALPosition{SegmentID: 1, Offset: 100, Sequence: 1}
	if err := svc.RecordCommittedWALRange(context.Background(), pos, pos, "batch-1"); err != nil {
		t.Fatalf("RecordCommittedWALRange(sequence 1) error = %v", err)
	}
	if !equalUint64s(hookSequences, []uint64{1, 2}) {
		t.Fatalf("checkpoint hooks after panic = %v, want [1 2]", hookSequences)
	}
	if err := svc.LastError(); err == nil || !strings.Contains(err.Error(), "injected checkpoint hook panic") {
		t.Fatalf("LastError() = %v, want recovered checkpoint hook panic", err)
	}
}

func TestServiceCheckpointMergesOutOfOrderCoverage(t *testing.T) {
	store := checkpointSafeLocalStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	seed := model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpointContiguous,
		SegmentID:     1,
		LastSequence:  10,
		LastOffset:    1000,
		BatchID:       "seed",
	}
	if err := store.PutCheckpoint(context.Background(), seed); err != nil {
		t.Fatalf("PutCheckpoint(seed) error = %v", err)
	}
	svc := New(fakeEngine{}, store, Options{}, nil)
	defer svc.Shutdown(context.Background())

	persistCheckpointTestBatch(t, svc, "batch-high",
		checkpointAccepted("out-14", model.WALPosition{SegmentID: 2, Offset: 1400, Sequence: 14}),
		checkpointAccepted("out-15", model.WALPosition{SegmentID: 3, Offset: 1500, Sequence: 15}),
	)
	if cp, _ := readCheckpointExact(t, store); cp.LastSequence != 10 {
		t.Fatalf("checkpoint after high island = %+v, want seed sequence 10", cp)
	}

	persistCheckpointTestBatch(t, svc, "batch-low",
		checkpointAccepted("out-11", model.WALPosition{SegmentID: 1, Offset: 1100, Sequence: 11}),
		checkpointAccepted("out-12", model.WALPosition{SegmentID: 1, Offset: 1200, Sequence: 12}),
	)
	if cp, _ := readCheckpointExact(t, store); cp.LastSequence != 12 {
		t.Fatalf("checkpoint after low run = %+v, want sequence 12", cp)
	}

	persistCheckpointTestBatch(t, svc, "batch-middle",
		checkpointAccepted("out-13", model.WALPosition{SegmentID: 2, Offset: 1300, Sequence: 13}),
	)
	cp, _ := readCheckpointExact(t, store)
	if cp.LastSequence != 15 || cp.SegmentID != 3 || cp.LastOffset != 1500 || cp.BatchID != "batch-high" {
		t.Fatalf("final checkpoint = %+v, want endpoint metadata from batch-high sequence 15", cp)
	}
}

func TestAsyncMaterializersAdvanceOnlyAfterEarlierGapCloses(t *testing.T) {
	store := checkpointSafeLocalStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	engine := outOfOrderCheckpointEngine{
		lowEntered:  make(chan struct{}, 1),
		lowRelease:  make(chan struct{}),
		highEntered: make(chan struct{}, 1),
	}
	var (
		hookMu sync.Mutex
		hooks  []model.WALCheckpoint
	)
	svc := New(engine, store, Options{
		QueueSize:             4,
		MaxRecords:            1,
		MaxDelay:              time.Hour,
		ProofMode:             ProofModeAsync,
		MaterializerWorkers:   2,
		MaterializerQueueSize: 4,
		OnCheckpointAdvanced: func(_ context.Context, cp model.WALCheckpoint) {
			hookMu.Lock()
			hooks = append(hooks, cp)
			hookMu.Unlock()
		},
	}, nil)
	defer func() {
		select {
		case <-engine.lowRelease:
		default:
			close(engine.lowRelease)
		}
		_ = svc.Shutdown(context.Background())
	}()

	seq1 := checkpointAccepted("async-low", model.WALPosition{SegmentID: 1, Offset: 100, Sequence: 1})
	if err := svc.Enqueue(context.Background(), seq1.Signed, seq1.Record, seq1.Accepted); err != nil {
		t.Fatalf("Enqueue(sequence 1) error = %v", err)
	}
	select {
	case <-engine.lowEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("sequence-1 materializer did not block")
	}

	seq2 := checkpointAccepted("async-high", model.WALPosition{SegmentID: 1, Offset: 200, Sequence: 2})
	if err := svc.Enqueue(context.Background(), seq2.Signed, seq2.Record, seq2.Accepted); err != nil {
		t.Fatalf("Enqueue(sequence 2) error = %v", err)
	}
	select {
	case <-engine.highEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("sequence-2 materializer did not start concurrently")
	}
	waitForProof(t, svc, seq2.Record.RecordID)
	if cp, found := readCheckpointExact(t, store); found {
		t.Fatalf("checkpoint advanced across blocked sequence 1: %+v", cp)
	}

	close(engine.lowRelease)
	waitForProof(t, svc, seq1.Record.RecordID)
	cp := waitForCheckpoint(t, store, 2)
	if cp.LastSequence != 2 || cp.LastOffset != 200 {
		t.Fatalf("checkpoint after releasing sequence 1 = %+v, want sequence 2", cp)
	}
	deadline := time.Now().Add(time.Second)
	for {
		hookMu.Lock()
		ready := len(hooks) == 1 && hooks[0].LastSequence == 2
		got := append([]model.WALCheckpoint(nil), hooks...)
		hookMu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("checkpoint hooks = %+v, want one sequence-2 advance", got)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestServiceCheckpointWriteFailureRetainsCoverage(t *testing.T) {
	store := &checkpointRecordingStore{
		LocalStore: proofstore.LocalStore{Root: t.TempDir()},
		failPuts:   1,
	}
	var hooks []model.WALCheckpoint
	svc := New(fakeEngine{}, store, Options{
		OnCheckpointAdvanced: func(_ context.Context, cp model.WALCheckpoint) {
			durable, found := readCheckpointExact(t, store.LocalStore)
			if !found || durable.LastSequence != cp.LastSequence {
				t.Fatalf("hook checkpoint = %+v durable=%+v found=%v", cp, durable, found)
			}
			hooks = append(hooks, cp)
		},
	}, nil)
	defer svc.Shutdown(context.Background())

	persistCheckpointTestBatch(t, svc, "batch-fail-1",
		checkpointAccepted("fail-1", model.WALPosition{SegmentID: 1, Offset: 100, Sequence: 1}),
	)
	if _, found := readCheckpointExact(t, store.LocalStore); found {
		t.Fatal("checkpoint persisted despite injected failure")
	}
	if len(hooks) != 0 {
		t.Fatalf("hook fired after failed write: %+v", hooks)
	}

	persistCheckpointTestBatch(t, svc, "batch-fail-3",
		checkpointAccepted("fail-3", model.WALPosition{SegmentID: 2, Offset: 300, Sequence: 3}),
	)
	if cp, found := readCheckpointExact(t, store.LocalStore); !found || cp.LastSequence != 1 {
		t.Fatalf("dirty checkpoint retry = %+v found=%v, want sequence 1", cp, found)
	}

	persistCheckpointTestBatch(t, svc, "batch-fail-2",
		checkpointAccepted("fail-2", model.WALPosition{SegmentID: 1, Offset: 200, Sequence: 2}),
	)
	attempts, persisted := store.snapshots()
	if got := checkpointSequences(attempts); !equalUint64s(got, []uint64{1, 1, 3}) {
		t.Fatalf("checkpoint attempts = %v, want [1 1 3]", got)
	}
	if got := checkpointSequences(persisted); !equalUint64s(got, []uint64{1, 3}) {
		t.Fatalf("persisted checkpoints = %v, want [1 3]", got)
	}
	if got := checkpointSequences(hooks); !equalUint64s(got, []uint64{1, 3}) {
		t.Fatalf("checkpoint hooks = %v, want [1 3]", got)
	}
}

func TestServiceCheckpointDeferralFlushesOnce(t *testing.T) {
	store := &checkpointRecordingStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	var hooks []model.WALCheckpoint
	svc := New(fakeEngine{}, store, Options{
		DeferCheckpointAdvance: true,
		OnCheckpointAdvanced: func(_ context.Context, cp model.WALCheckpoint) {
			hooks = append(hooks, cp)
		},
	}, nil)
	defer svc.Shutdown(context.Background())

	if err := svc.RecordCommittedWALRange(context.Background(),
		model.WALPosition{SegmentID: 1, Offset: 100, Sequence: 1},
		model.WALPosition{SegmentID: 1, Offset: 100, Sequence: 1},
		"batch-1",
	); err != nil {
		t.Fatalf("RecordCommittedWALRange(1) error = %v", err)
	}
	if err := svc.RecordCommittedWALRange(context.Background(),
		model.WALPosition{SegmentID: 1, Offset: 200, Sequence: 2},
		model.WALPosition{SegmentID: 1, Offset: 200, Sequence: 2},
		"batch-2",
	); err != nil {
		t.Fatalf("RecordCommittedWALRange(2) error = %v", err)
	}
	if attempts, _ := store.snapshots(); len(attempts) != 0 || len(hooks) != 0 {
		t.Fatalf("deferred checkpoint attempts=%+v hooks=%+v, want none", attempts, hooks)
	}
	if err := svc.StartCheckpointAdvance(context.Background()); err != nil {
		t.Fatalf("StartCheckpointAdvance() error = %v", err)
	}
	attempts, persisted := store.snapshots()
	if got := checkpointSequences(attempts); !equalUint64s(got, []uint64{2}) {
		t.Fatalf("checkpoint attempts = %v, want [2]", got)
	}
	if got := checkpointSequences(persisted); !equalUint64s(got, []uint64{2}) {
		t.Fatalf("persisted checkpoints = %v, want [2]", got)
	}
	if got := checkpointSequences(hooks); !equalUint64s(got, []uint64{2}) {
		t.Fatalf("checkpoint hooks = %v, want [2]", got)
	}
}

func TestServiceCheckpointCoverageCompressesAcrossBatches(t *testing.T) {
	store := checkpointSafeLocalStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	svc := New(fakeEngine{}, store, Options{DeferCheckpointAdvance: true}, nil)
	defer svc.Shutdown(context.Background())

	for seq := uint64(3); seq <= 10_000; seq++ {
		pos := model.WALPosition{SegmentID: 2, Offset: int64(seq) * 128, Sequence: seq}
		if err := svc.RecordCommittedWALRange(context.Background(), pos, pos, "tail"); err != nil {
			t.Fatalf("RecordCommittedWALRange(%d) error = %v", seq, err)
		}
	}
	svc.checkpointMu.Lock()
	defer svc.checkpointMu.Unlock()
	if len(svc.checkpointCoverage) != 1 || svc.checkpointCoverage[0].from != 3 || svc.checkpointCoverage[0].to.Sequence != 10_000 {
		t.Fatalf("checkpoint coverage = %+v, want one compressed run [3,10000]", svc.checkpointCoverage)
	}
}

func TestServiceMigratesLegacyCheckpointAtZeroWithoutHook(t *testing.T) {
	store := &checkpointRecordingStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	legacy := model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpoint,
		SegmentID:     9,
		LastSequence:  100,
		LastOffset:    4096,
		BatchID:       "legacy-unsafe",
	}
	if err := store.LocalStore.PutCheckpoint(context.Background(), legacy); err != nil {
		t.Fatalf("PutCheckpoint(legacy) error = %v", err)
	}
	var hooks []model.WALCheckpoint
	svc := New(fakeEngine{}, store, Options{
		DeferCheckpointAdvance: true,
		OnCheckpointAdvanced: func(_ context.Context, cp model.WALCheckpoint) {
			hooks = append(hooks, cp)
		},
	}, nil)
	defer svc.Shutdown(context.Background())

	if err := svc.StartCheckpointAdvance(context.Background()); err != nil {
		t.Fatalf("StartCheckpointAdvance() error = %v", err)
	}
	cp, found := readCheckpointExact(t, store.LocalStore)
	if !found || cp.SchemaVersion != model.SchemaWALCheckpointContiguous || cp.LastSequence != 0 || cp.SegmentID != 0 || cp.LastOffset != 0 || cp.BatchID != "" {
		t.Fatalf("migrated checkpoint = %+v found=%v, want clean v2 sequence zero", cp, found)
	}
	if len(hooks) != 0 {
		t.Fatalf("migration-only hooks = %+v, want none", hooks)
	}
	attempts, _ := store.snapshots()
	if len(attempts) != 1 || attempts[0].LastSequence != 0 {
		t.Fatalf("migration attempts = %+v, want one sequence-zero write", attempts)
	}
}

func TestServiceMigratesLegacyCheckpointFromRebuiltCoverage(t *testing.T) {
	store := &checkpointRecordingStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	if err := store.LocalStore.PutCheckpoint(context.Background(), model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpoint,
		SegmentID:     8,
		LastSequence:  80,
		LastOffset:    8000,
	}); err != nil {
		t.Fatalf("PutCheckpoint(legacy) error = %v", err)
	}
	var hooks []model.WALCheckpoint
	svc := New(fakeEngine{}, store, Options{
		DeferCheckpointAdvance: true,
		OnCheckpointAdvanced: func(_ context.Context, cp model.WALCheckpoint) {
			hooks = append(hooks, cp)
		},
	}, nil)
	defer svc.Shutdown(context.Background())

	if err := svc.RecordCommittedWALRange(context.Background(),
		model.WALPosition{SegmentID: 1, Offset: 0, Sequence: 1},
		model.WALPosition{SegmentID: 2, Offset: 256, Sequence: 3},
		"rebuilt-batch",
	); err != nil {
		t.Fatalf("RecordCommittedWALRange() error = %v", err)
	}
	if err := svc.StartCheckpointAdvance(context.Background()); err != nil {
		t.Fatalf("StartCheckpointAdvance() error = %v", err)
	}
	cp, found := readCheckpointExact(t, store.LocalStore)
	if !found || cp.SchemaVersion != model.SchemaWALCheckpointContiguous || cp.LastSequence != 3 || cp.SegmentID != 2 || cp.LastOffset != 256 || cp.BatchID != "rebuilt-batch" {
		t.Fatalf("rebuilt checkpoint = %+v found=%v", cp, found)
	}
	if len(hooks) != 1 || hooks[0].LastSequence != 3 {
		t.Fatalf("rebuilt hooks = %+v, want [3]", hooks)
	}
}

func TestServiceRetriesLegacyCheckpointMigration(t *testing.T) {
	store := &checkpointRecordingStore{
		LocalStore: proofstore.LocalStore{Root: t.TempDir()},
		failPuts:   1,
	}
	if err := store.LocalStore.PutCheckpoint(context.Background(), model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpoint,
		LastSequence:  0,
	}); err != nil {
		t.Fatalf("PutCheckpoint(legacy) error = %v", err)
	}
	svc := New(fakeEngine{}, store, Options{DeferCheckpointAdvance: true}, nil)
	defer svc.Shutdown(context.Background())

	if err := svc.StartCheckpointAdvance(context.Background()); err == nil {
		t.Fatal("first StartCheckpointAdvance() error = nil, want injected failure")
	}
	if cp, _ := readCheckpointExact(t, store.LocalStore); cp.SchemaVersion != model.SchemaWALCheckpoint {
		t.Fatalf("checkpoint after failed migration = %+v, want legacy v1 retained", cp)
	}
	if err := svc.StartCheckpointAdvance(context.Background()); err != nil {
		t.Fatalf("second StartCheckpointAdvance() error = %v", err)
	}
	cp, _ := readCheckpointExact(t, store.LocalStore)
	if cp.SchemaVersion != model.SchemaWALCheckpointContiguous || cp.LastSequence != 0 {
		t.Fatalf("checkpoint after migration retry = %+v, want v2 zero", cp)
	}
	attempts, _ := store.snapshots()
	if len(attempts) != 2 {
		t.Fatalf("migration attempts = %+v, want two", attempts)
	}
}

func TestServiceRejectsUnknownCheckpointSchema(t *testing.T) {
	store := &checkpointRecordingStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	if err := store.LocalStore.PutCheckpoint(context.Background(), model.WALCheckpoint{
		SchemaVersion: "trustdb.wal-checkpoint.v999",
		LastSequence:  12,
	}); err != nil {
		t.Fatalf("PutCheckpoint(unknown) error = %v", err)
	}
	svc := New(fakeEngine{}, store, Options{DeferCheckpointAdvance: true}, nil)
	defer svc.Shutdown(context.Background())

	err := svc.StartCheckpointAdvance(context.Background())
	if trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("StartCheckpointAdvance() code=%s err=%v, want failed_precondition", trusterr.CodeOf(err), err)
	}
	cp, _ := readCheckpointExact(t, store.LocalStore)
	if cp.SchemaVersion != "trustdb.wal-checkpoint.v999" {
		t.Fatalf("unknown checkpoint overwritten: %+v", cp)
	}
	if attempts, _ := store.snapshots(); len(attempts) != 0 {
		t.Fatalf("unknown schema write attempts = %+v, want none", attempts)
	}
}

func TestServiceBoundsAndReportsCheckpointCoverageIslands(t *testing.T) {
	store := &checkpointRecordingStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	_, metrics := observability.NewRegistry()
	svc := New(fakeEngine{}, store, Options{DeferCheckpointAdvance: true}, metrics)
	defer svc.Shutdown(context.Background())

	for i := 0; i <= maxCheckpointCoverageRuns; i++ {
		seq := uint64(3 + 2*i)
		pos := model.WALPosition{SegmentID: 2, Offset: int64(seq) * 128, Sequence: seq}
		if err := svc.RecordCommittedWALRange(context.Background(), pos, pos, "island"); err != nil {
			t.Fatalf("RecordCommittedWALRange(%d) error = %v", seq, err)
		}
	}
	svc.checkpointMu.Lock()
	if len(svc.checkpointCoverage) != maxCheckpointCoverageRuns {
		t.Fatalf("coverage runs = %d, want cap %d", len(svc.checkpointCoverage), maxCheckpointCoverageRuns)
	}
	first := svc.checkpointCoverage[0].from
	last := svc.checkpointCoverage[len(svc.checkpointCoverage)-1].to.Sequence
	svc.checkpointMu.Unlock()
	if first != 3 || last != uint64(3+2*(maxCheckpointCoverageRuns-1)) {
		t.Fatalf("retained island range = [%d,%d], want lowest %d islands", first, last, maxCheckpointCoverageRuns)
	}
	if got := testutil.ToFloat64(metrics.WALCheckpointCoverageDropped); got != 1 {
		t.Fatalf("wal_checkpoint_coverage_dropped_total = %v, want 1", got)
	}
	if err := svc.RecordCommittedWALRange(context.Background(),
		model.WALPosition{SegmentID: 1, Offset: 0, Sequence: 1},
		model.WALPosition{SegmentID: 2, Offset: 3 * 128, Sequence: 3},
		"bridge",
	); err != nil {
		t.Fatalf("RecordCommittedWALRange(bridge) error = %v", err)
	}
	if err := svc.StartCheckpointAdvance(context.Background()); err != nil {
		t.Fatalf("StartCheckpointAdvance() error = %v", err)
	}
	cp, found := readCheckpointExact(t, store.LocalStore)
	if !found || cp.LastSequence != 3 {
		t.Fatalf("checkpoint after bridge = %+v found=%v, want sequence 3 before gap 4", cp, found)
	}
}

func TestServiceDoesNotCheckpointDuplicateUnprotectedRecordID(t *testing.T) {
	store := &checkpointRecordingStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	_, metrics := observability.NewRegistry()
	svc := New(fakeEngine{}, store, Options{}, metrics)
	defer svc.Shutdown(context.Background())

	first := checkpointAccepted("duplicate-record", model.WALPosition{SegmentID: 1, Offset: 100, Sequence: 1})
	second := checkpointAccepted("duplicate-record", model.WALPosition{SegmentID: 1, Offset: 200, Sequence: 2})
	first.Signed.Claim.IdempotencyKey = ""
	second.Signed.Claim.IdempotencyKey = ""
	persistCheckpointTestBatch(t, svc, "batch-duplicate-record", first, second)
	if cp, found := readCheckpointExact(t, store); found {
		t.Fatalf("checkpoint after duplicate record id = %+v, want none", cp)
	}
	if err := svc.LastError(); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("LastError() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
	if got := testutil.ToFloat64(metrics.WALCheckpointFailures); got != 1 {
		t.Fatalf("wal_checkpoint_failures_total = %v, want 1", got)
	}
}

func TestServiceDisablesCheckpointForUnsafeStore(t *testing.T) {
	store := proofstore.LocalStore{Root: t.TempDir()}
	var hookCalls int
	svc := New(fakeEngine{}, store, Options{
		OnCheckpointAdvanced: func(context.Context, model.WALCheckpoint) { hookCalls++ },
	}, nil)
	defer svc.Shutdown(context.Background())

	persistCheckpointTestBatch(t, svc, "unsafe-store", checkpointAccepted("unsafe-1", model.WALPosition{SegmentID: 1, Sequence: 1}))
	if _, found := readCheckpointExact(t, store); found {
		t.Fatal("unsafe store persisted an automatic checkpoint")
	}
	if hookCalls != 0 {
		t.Fatalf("unsafe store checkpoint hook calls = %d, want 0", hookCalls)
	}
}

func checkpointSequences(checkpoints []model.WALCheckpoint) []uint64 {
	sequences := make([]uint64, len(checkpoints))
	for i := range checkpoints {
		sequences[i] = checkpoints[i].LastSequence
	}
	return sequences
}

func equalUint64s(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
