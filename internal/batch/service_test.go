package batch

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/wowtrust/trustdb/internal/merkle"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const asyncProofWaitTimeout = 10 * time.Second

func TestServiceCommitsFullBatch(t *testing.T) {
	t.Parallel()

	store := proofstore.LocalStore{Root: t.TempDir()}
	svc := New(fakeEngine{}, store, Options{QueueSize: 4, MaxRecords: 2, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())

	if err := svc.Enqueue(context.Background(), signed("tr1a"), record("tr1a"), accepted("tr1a")); err != nil {
		t.Fatalf("Enqueue(a) error = %v", err)
	}
	if err := svc.Enqueue(context.Background(), signed("tr1b"), record("tr1b"), accepted("tr1b")); err != nil {
		t.Fatalf("Enqueue(b) error = %v", err)
	}

	got := waitForProof(t, svc, "tr1b")
	if got.RecordID != "tr1b" || got.BatchProof.TreeSize != 2 {
		t.Fatalf("Proof() = %+v", got)
	}
	// persistBatch writes bundles before the root, so the bundle becoming
	// visible to Proof() does not yet imply the root file has landed.
	// Poll briefly to close that window instead of asserting immediately.
	root := waitForLatestRoot(t, svc, 2)
	if len(root.BatchRoot) != 32 {
		t.Fatalf("LatestRoot() = %+v", root)
	}
	leaves := waitForBatchTreeLeaves(t, store, root.BatchID, 2)
	if len(leaves) != 2 || leaves[0].RecordID != "tr1a" || leaves[1].RecordID != "tr1b" {
		t.Fatalf("ListBatchTreeLeaves() = %+v", leaves)
	}
	nodes := waitForBatchTreeNodes(t, store, root.BatchID, 1, 1)
	if len(nodes) != 1 || nodes[0].Width != 2 {
		t.Fatalf("ListBatchTreeNodes() = %+v", nodes)
	}
}

func TestServiceShutdownFlushesPartialBatch(t *testing.T) {
	t.Parallel()

	store := proofstore.LocalStore{Root: t.TempDir()}
	svc := New(fakeEngine{}, store, Options{QueueSize: 4, MaxRecords: 10, MaxDelay: time.Hour}, nil)
	if err := svc.Enqueue(context.Background(), signed("tr1partial"), record("tr1partial"), accepted("tr1partial")); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if err := svc.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	got, err := svc.Proof(context.Background(), "tr1partial")
	if err != nil {
		t.Fatalf("Proof() error = %v", err)
	}
	if got.BatchProof.TreeSize != 1 {
		t.Fatalf("Proof() = %+v", got)
	}
}

func TestServiceRejectsFullQueue(t *testing.T) {
	t.Parallel()

	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	svc := New(blockingEngine{block: block, entered: entered}, proofstore.LocalStore{Root: t.TempDir()}, Options{QueueSize: 1, MaxRecords: 1, MaxDelay: time.Hour}, nil)
	defer func() {
		close(block)
		_ = svc.Shutdown(context.Background())
	}()
	if err := svc.Enqueue(context.Background(), signed("tr1a"), record("tr1a"), accepted("tr1a")); err != nil {
		t.Fatalf("Enqueue(a) error = %v", err)
	}
	<-entered
	if err := svc.Enqueue(context.Background(), signed("tr1b"), record("tr1b"), accepted("tr1b")); err != nil {
		t.Fatalf("Enqueue(b) error = %v", err)
	}
	err := svc.Enqueue(context.Background(), signed("tr1c"), record("tr1c"), accepted("tr1c"))
	if trusterr.CodeOf(err) != trusterr.CodeResourceExhausted {
		t.Fatalf("Enqueue(c) code = %s err=%v", trusterr.CodeOf(err), err)
	}
}

// TestServiceAdvancesCheckpointAfterCommit verifies that a successful batch
// commit persists a WAL checkpoint whose LastSequence equals the contiguous
// committed frontier, so future restarts can skip those records when replaying
// the WAL.
func TestServiceAdvancesCheckpointAfterCommit(t *testing.T) {
	t.Parallel()

	store := checkpointSafeLocalStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	svc := New(fakeEngine{}, store, Options{QueueSize: 4, MaxRecords: 2, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())

	if err := svc.Enqueue(context.Background(), signed("rec-1"), recordWithWAL("rec-1", 1), accepted("rec-1")); err != nil {
		t.Fatalf("Enqueue(a) error = %v", err)
	}
	if err := svc.Enqueue(context.Background(), signed("rec-2"), recordWithWAL("rec-2", 2), accepted("rec-2")); err != nil {
		t.Fatalf("Enqueue(b) error = %v", err)
	}
	waitForProof(t, svc, "rec-2")

	cp := waitForCheckpoint(t, store, 2)
	if cp.SegmentID != 1 || cp.LastOffset != 2*128 {
		t.Fatalf("GetCheckpoint() = %+v", cp)
	}
}

// TestServiceCheckpointMonotonic verifies that advancing with a lower
// sequence does not regress the checkpoint, which protects against
// out-of-order commits during crash recovery (RecoverManifest may process an
// older prepared manifest after newer batches have already advanced the
// checkpoint).
func TestServiceCheckpointMonotonic(t *testing.T) {
	t.Parallel()

	store := checkpointSafeLocalStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	if err := store.PutCheckpoint(context.Background(), model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpointContiguous,
		SegmentID:     1,
		LastSequence:  98,
		LastOffset:    98 * 128,
		BatchID:       "seed",
	}); err != nil {
		t.Fatalf("PutCheckpoint(seed) error = %v", err)
	}
	svc := New(fakeEngine{}, store, Options{QueueSize: 4, MaxRecords: 1, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())

	if err := svc.Enqueue(context.Background(), signed("rec-high"), recordWithWAL("rec-high", 99), accepted("rec-high")); err != nil {
		t.Fatalf("Enqueue(high) error = %v", err)
	}
	waitForProof(t, svc, "rec-high")

	if err := svc.Enqueue(context.Background(), signed("rec-low"), recordWithWAL("rec-low", 5), accepted("rec-low")); err != nil {
		t.Fatalf("Enqueue(low) error = %v", err)
	}
	waitForProof(t, svc, "rec-low")

	// rec-low committed after rec-high, but checkpoint must remain at 99.
	// Give the worker a moment to observe the PutManifest for rec-low
	// before asserting the checkpoint did not regress.
	time.Sleep(20 * time.Millisecond)
	cp, found, err := store.GetCheckpoint(context.Background())
	if err != nil || !found {
		t.Fatalf("GetCheckpoint() err=%v found=%v", err, found)
	}
	if cp.LastSequence != 99 {
		t.Fatalf("GetCheckpoint() LastSequence = %d, want 99 (never regress)", cp.LastSequence)
	}
	if cp.BatchID == "" {
		t.Fatalf("GetCheckpoint() BatchID empty, want the first batch that advanced to 99")
	}
}

// TestServiceSkipsCheckpointOnZeroSequence keeps the store clean when a batch
// completes with no valid WAL positions (e.g. tests using legacy helpers that
// default to sequence 0). This prevents us from writing a meaningless
// checkpoint that would otherwise confuse downstream replays.
func TestServiceSkipsCheckpointOnZeroSequence(t *testing.T) {
	t.Parallel()

	store := proofstore.LocalStore{Root: t.TempDir()}
	svc := New(fakeEngine{}, store, Options{QueueSize: 4, MaxRecords: 1, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())

	if err := svc.Enqueue(context.Background(), signed("rec"), record("rec"), accepted("rec")); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	waitForProof(t, svc, "rec")

	_, found, err := store.GetCheckpoint(context.Background())
	if err != nil {
		t.Fatalf("GetCheckpoint() error = %v", err)
	}
	if found {
		t.Fatalf("GetCheckpoint() found = true, want no checkpoint when WAL sequences are zero")
	}
}

// TestServiceUpdatesCheckpointGauge verifies that advancing the checkpoint
// also updates the exposed prometheus gauge so dashboards track the batcher's
// progress without polling the proof store.
func TestServiceUpdatesCheckpointGauge(t *testing.T) {
	t.Parallel()

	_, metrics := observability.NewRegistry()
	store := checkpointSafeLocalStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	svc := New(fakeEngine{}, store, Options{QueueSize: 4, MaxRecords: 1, MaxDelay: time.Hour}, metrics)
	defer svc.Shutdown(context.Background())

	if err := svc.Enqueue(context.Background(), signed("rec-gauge"), recordWithWAL("rec-gauge", 1), accepted("rec-gauge")); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	waitForProof(t, svc, "rec-gauge")
	waitForCheckpoint(t, store, 1)

	// The gauge is updated inside advanceCheckpoint after the proof store
	// persist succeeds, so a post-proof poll may race. Give the batch
	// worker a short window to publish before asserting.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if testutil.ToFloat64(metrics.WALCheckpointLastSequence) == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := testutil.ToFloat64(metrics.WALCheckpointLastSequence); got != 1 {
		t.Fatalf("wal_checkpoint_last_sequence = %v, want 1", got)
	}
}

// TestServiceInvokesOnCheckpointAdvanced verifies the hook is called with
// each advanced checkpoint and is only called when the checkpoint actually
// moves forward (monotonic advance; the hook is a best-effort observer and
// should not fire for no-op advances).
func TestServiceInvokesOnCheckpointAdvanced(t *testing.T) {
	t.Parallel()

	var (
		hookMu   sync.Mutex
		hookCPs  []model.WALCheckpoint
		hookFire = make(chan struct{}, 8)
	)
	store := checkpointSafeLocalStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	svc := New(fakeEngine{}, store, Options{
		QueueSize:  4,
		MaxRecords: 1,
		MaxDelay:   time.Hour,
		OnCheckpointAdvanced: func(_ context.Context, cp model.WALCheckpoint) {
			hookMu.Lock()
			hookCPs = append(hookCPs, cp)
			hookMu.Unlock()
			hookFire <- struct{}{}
		},
	}, nil)
	defer svc.Shutdown(context.Background())

	if err := svc.Enqueue(context.Background(), signed("rec-a"), recordWithWAL("rec-a", 1), accepted("rec-a")); err != nil {
		t.Fatalf("Enqueue(a) error = %v", err)
	}
	waitForProof(t, svc, "rec-a")
	waitForCheckpoint(t, store, 1)
	<-hookFire

	if err := svc.Enqueue(context.Background(), signed("rec-b"), recordWithWAL("rec-b", 2), accepted("rec-b")); err != nil {
		t.Fatalf("Enqueue(b) error = %v", err)
	}
	waitForProof(t, svc, "rec-b")
	waitForCheckpoint(t, store, 2)
	<-hookFire

	// rec-regress has a lower sequence than the existing checkpoint: the
	// service must not invoke the hook for a no-op advance so the prune
	// side does not observe a phantom checkpoint advance.
	if err := svc.Enqueue(context.Background(), signed("rec-regress"), recordWithWAL("rec-regress", 1), accepted("rec-regress")); err != nil {
		t.Fatalf("Enqueue(regress) error = %v", err)
	}
	waitForProof(t, svc, "rec-regress")
	time.Sleep(20 * time.Millisecond)

	hookMu.Lock()
	defer hookMu.Unlock()
	if len(hookCPs) != 2 {
		t.Fatalf("hook fired %d times, want 2 (regress must not advance)", len(hookCPs))
	}
	if hookCPs[0].LastSequence != 1 || hookCPs[1].LastSequence != 2 {
		t.Fatalf("hook checkpoints = %+v, want [1,2]", hookCPs)
	}
}

func TestServiceKeepsWorkerCheckpointFailureVisible(t *testing.T) {
	store := &checkpointRecordingStore{
		LocalStore: proofstore.LocalStore{Root: t.TempDir()},
		failPuts:   1,
	}
	_, metrics := observability.NewRegistry()
	svc := New(fakeEngine{}, store, Options{QueueSize: 2, MaxRecords: 1, MaxDelay: time.Hour}, metrics)
	defer svc.Shutdown(context.Background())

	if err := svc.Enqueue(context.Background(), signed("checkpoint-error"), recordWithWAL("checkpoint-error", 1), accepted("checkpoint-error")); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	waitForProof(t, svc, "checkpoint-error")
	deadline := time.Now().Add(5 * time.Second)
	var checkpointErr error
	for time.Now().Before(deadline) {
		if err := svc.LastError(); err != nil {
			if !strings.Contains(err.Error(), "injected checkpoint write failure") {
				t.Fatalf("LastError() = %v, want checkpoint failure", err)
			}
			if got := testutil.ToFloat64(metrics.WALCheckpointFailures); got != 1 {
				t.Fatalf("wal_checkpoint_failures_total = %v, want 1", got)
			}
			checkpointErr = err
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if checkpointErr == nil {
		t.Fatal("checkpoint write failure was not published through LastError")
	}

	if err := svc.Enqueue(context.Background(), signed("checkpoint-retry"), recordWithWAL("checkpoint-retry", 2), accepted("checkpoint-retry")); err != nil {
		t.Fatalf("Enqueue(retry) error = %v", err)
	}
	waitForProof(t, svc, "checkpoint-retry")
	waitForCheckpoint(t, store, 2)
	if got := svc.LastError(); got != checkpointErr {
		t.Fatalf("LastError() after successful retry = %v, want sticky error %v", got, checkpointErr)
	}
}

func TestServiceAsyncProofModePublishesIndexBeforeBundle(t *testing.T) {
	t.Parallel()

	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	engine := blockingMaterializeEngine{block: block, entered: entered}
	store := proofstore.LocalStore{Root: t.TempDir()}
	svc := New(engine, store, Options{QueueSize: 4, MaxRecords: 1, MaxDelay: time.Hour, ProofMode: ProofModeAsync}, nil)
	defer func() {
		close(block)
		_ = svc.Shutdown(context.Background())
	}()

	if err := svc.Enqueue(context.Background(), signed("async-rec"), recordWithWAL("async-rec", 31), accepted("async-rec")); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	idx := waitForRecordIndex(t, svc, "async-rec")
	if idx.BatchID == "" {
		t.Fatalf("RecordIndex() missing batch_id: %+v", idx)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("async materializer did not start")
	}
	if _, err := svc.Proof(context.Background(), "async-rec"); trusterr.CodeOf(err) != trusterr.CodeNotFound {
		t.Fatalf("Proof() before async materialization code = %s err=%v", trusterr.CodeOf(err), err)
	}

	close(block)
	block = make(chan struct{}) // keep deferred close safe after the real unblock.
	got := waitForProof(t, svc, "async-rec")
	if got.RecordID != "async-rec" {
		t.Fatalf("Proof() = %+v", got)
	}
	manifest := waitForManifestState(t, store, idx.BatchID, model.BatchStateCommitted)
	if manifest.WALRange.To.Sequence != 31 {
		t.Fatalf("manifest WAL range = %+v", manifest.WALRange)
	}
}

func TestServiceNonInlineFallbackRejectsInconsistentProofCount(t *testing.T) {
	t.Parallel()

	store := proofstore.LocalStore{Root: t.TempDir()}
	svc := New(emptyBundleEngine{}, store, Options{
		QueueSize:  4,
		MaxRecords: 1,
		MaxDelay:   time.Hour,
		ProofMode:  ProofModeAsync,
	}, nil)
	defer svc.Shutdown(context.Background())

	if err := svc.Enqueue(context.Background(), signed("bad-count"), recordWithWAL("bad-count", 33), accepted("bad-count")); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	err := waitForLastError(t, svc)
	if trusterr.CodeOf(err) != trusterr.CodeInternal {
		t.Fatalf("LastError() code = %s err=%v, want internal", trusterr.CodeOf(err), err)
	}
	if !strings.Contains(err.Error(), "inconsistent proof count") {
		t.Fatalf("LastError() = %v, want inconsistent proof count", err)
	}
	if _, ok, err := store.GetRecordIndex(context.Background(), "bad-count"); err != nil || ok {
		t.Fatalf("GetRecordIndex() ok=%v err=%v, want no index after failed plan", ok, err)
	}
}

func TestServiceOnDemandProofModeMaterializesOnce(t *testing.T) {
	t.Parallel()

	engine := &countingMaterializeEngine{}
	store := proofstore.LocalStore{Root: t.TempDir()}
	svc := New(engine, store, Options{QueueSize: 4, MaxRecords: 1, MaxDelay: time.Hour, ProofMode: ProofModeOnDemand}, nil)
	defer svc.Shutdown(context.Background())

	if err := svc.Enqueue(context.Background(), signed("ondemand-rec"), recordWithWAL("ondemand-rec", 41), accepted("ondemand-rec")); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	idx := waitForRecordIndex(t, svc, "ondemand-rec")
	if idx.BatchID == "" {
		t.Fatalf("RecordIndex() missing batch_id: %+v", idx)
	}
	waitForManifestState(t, store, idx.BatchID, model.BatchStatePrepared)
	if _, err := store.GetBundle(context.Background(), "ondemand-rec"); trusterr.CodeOf(err) != trusterr.CodeNotFound {
		t.Fatalf("GetBundle() before on-demand proof code = %s err=%v", trusterr.CodeOf(err), err)
	}

	got := waitForProof(t, svc, "ondemand-rec")
	if got.RecordID != "ondemand-rec" {
		t.Fatalf("Proof() = %+v", got)
	}
	if commits := engine.CommitCount(); commits != 1 {
		t.Fatalf("materialize CommitBatch calls = %d, want 1", commits)
	}
	waitForManifestState(t, store, idx.BatchID, model.BatchStateCommitted)
	if _, err := svc.Proof(context.Background(), "ondemand-rec"); err != nil {
		t.Fatalf("cached Proof() error = %v", err)
	}
	if commits := engine.CommitCount(); commits != 1 {
		t.Fatalf("cached proof materialize CommitBatch calls = %d, want 1", commits)
	}
}

func TestServiceOnDemandRecoverManifestKeepsBundleLazy(t *testing.T) {
	t.Parallel()

	items := []Accepted{{Signed: signed("recover-ondemand"), Record: recordWithWAL("recover-ondemand", 51), Accepted: accepted("recover-ondemand")}}
	engine := &countingMaterializeEngine{}
	store := proofstore.LocalStore{Root: t.TempDir()}
	closedAt := time.Unix(0, 1234).UTC()
	root, indexes, err := engine.CommitBatchIndexes("recover-batch", closedAt, []model.SignedClaim{items[0].Signed}, []model.ServerRecord{items[0].Record}, []model.AcceptedReceipt{items[0].Accepted})
	if err != nil {
		t.Fatalf("CommitBatchIndexes: %v", err)
	}
	manifest := model.BatchManifest{
		SchemaVersion:   model.SchemaBatchManifest,
		BatchID:         "recover-batch",
		State:           model.BatchStatePrepared,
		TreeAlg:         model.DefaultMerkleTreeAlg,
		TreeSize:        1,
		BatchRoot:       root.BatchRoot,
		RecordIDs:       []string{"recover-ondemand"},
		WALRange:        walRangeFor(items),
		ClosedAtUnixN:   root.ClosedAtUnixN,
		PreparedAtUnixN: closedAt.UnixNano(),
	}
	if err := store.PutManifest(context.Background(), manifest); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	if len(indexes) != 1 {
		t.Fatalf("indexes = %+v", indexes)
	}

	svc := New(engine, store, Options{
		QueueSize:  4,
		MaxRecords: 1,
		MaxDelay:   time.Hour,
		ProofMode:  ProofModeOnDemand,
		LoadBatchItems: func(context.Context, model.BatchManifest) ([]Accepted, error) {
			return cloneAcceptedItems(items), nil
		},
	}, nil)
	defer svc.Shutdown(context.Background())
	if err := svc.RecoverManifest(context.Background(), manifest, items); err != nil {
		t.Fatalf("RecoverManifest: %v", err)
	}
	if _, err := store.GetBundle(context.Background(), "recover-ondemand"); trusterr.CodeOf(err) != trusterr.CodeNotFound {
		t.Fatalf("GetBundle() after on-demand recovery code = %s err=%v", trusterr.CodeOf(err), err)
	}
	idx, ok, err := store.GetRecordIndex(context.Background(), "recover-ondemand")
	if err != nil || !ok || idx.BatchID != "recover-batch" {
		t.Fatalf("GetRecordIndex() = %+v ok=%v err=%v", idx, ok, err)
	}
	waitForManifestState(t, store, "recover-batch", model.BatchStatePrepared)
	if commits := engine.CommitCount(); commits != 0 {
		t.Fatalf("materialize CommitBatch calls after recovery = %d, want 0", commits)
	}
	waitForProof(t, svc, "recover-ondemand")
	if commits := engine.CommitCount(); commits != 1 {
		t.Fatalf("materialize CommitBatch calls after proof = %d, want 1", commits)
	}
	waitForManifestState(t, store, "recover-batch", model.BatchStateCommitted)
}

func waitForCheckpoint(t *testing.T, store interface {
	GetCheckpoint(context.Context) (model.WALCheckpoint, bool, error)
}, wantSeq uint64) model.WALCheckpoint {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cp, found, err := store.GetCheckpoint(context.Background())
		if err == nil && found && cp.LastSequence >= wantSeq {
			return cp
		}
		time.Sleep(5 * time.Millisecond)
	}
	cp, found, err := store.GetCheckpoint(context.Background())
	t.Fatalf("GetCheckpoint() after wait = %+v found=%v err=%v (want LastSequence >= %d)", cp, found, err, wantSeq)
	return model.WALCheckpoint{}
}

func waitForRecordIndex(t *testing.T, svc *Service, recordID string) model.RecordIndex {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		idx, ok, err := svc.RecordIndex(context.Background(), recordID)
		if err == nil && ok {
			return idx
		}
		time.Sleep(5 * time.Millisecond)
	}
	idx, ok, err := svc.RecordIndex(context.Background(), recordID)
	t.Fatalf("RecordIndex(%q) after wait = %+v ok=%v err=%v lastErr=%v", recordID, idx, ok, err, svc.LastError())
	return model.RecordIndex{}
}

func waitForManifestState(t *testing.T, store proofstore.LocalStore, batchID, state string) model.BatchManifest {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		manifest, err := store.GetManifest(context.Background(), batchID)
		if err == nil && manifest.State == state {
			return manifest
		}
		time.Sleep(5 * time.Millisecond)
	}
	manifest, err := store.GetManifest(context.Background(), batchID)
	t.Fatalf("GetManifest(%q) after wait = %+v err=%v want state=%s", batchID, manifest, err, state)
	return model.BatchManifest{}
}

// waitForLatestRoot polls LatestRoot until the committed batch has published
// its root (bundles land before the root inside persistBatch, so callers
// that observed a proof cannot assume the root is immediately readable).
func waitForLatestRoot(t *testing.T, svc *Service, wantTreeSize uint64) model.BatchRoot {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		root, err := svc.LatestRoot(context.Background())
		if err == nil && root.TreeSize == wantTreeSize {
			return root
		}
		time.Sleep(5 * time.Millisecond)
	}
	root, err := svc.LatestRoot(context.Background())
	t.Fatalf("LatestRoot() after wait = %+v err=%v (want TreeSize=%d)", root, err, wantTreeSize)
	return model.BatchRoot{}
}

func waitForBatchTreeLeaves(t *testing.T, store proofstore.LocalStore, batchID string, want int) []model.BatchTreeLeaf {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		leaves, err := store.ListBatchTreeLeaves(context.Background(), model.BatchTreeLeafListOptions{BatchID: batchID, Limit: want})
		if err == nil && len(leaves) >= want {
			return leaves
		}
		time.Sleep(5 * time.Millisecond)
	}
	leaves, err := store.ListBatchTreeLeaves(context.Background(), model.BatchTreeLeafListOptions{BatchID: batchID, Limit: want})
	t.Fatalf("ListBatchTreeLeaves(%q) after wait = %+v err=%v want len=%d", batchID, leaves, err, want)
	return nil
}

func waitForBatchTreeNodes(t *testing.T, store proofstore.LocalStore, batchID string, level uint64, want int) []model.BatchTreeNode {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	opts := model.BatchTreeNodeListOptions{BatchID: batchID, Level: level, Limit: want}
	for time.Now().Before(deadline) {
		nodes, err := store.ListBatchTreeNodes(context.Background(), opts)
		if err == nil && len(nodes) >= want {
			return nodes
		}
		time.Sleep(5 * time.Millisecond)
	}
	nodes, err := store.ListBatchTreeNodes(context.Background(), opts)
	t.Fatalf("ListBatchTreeNodes(%q, level=%d) after wait = %+v err=%v want len=%d", batchID, level, nodes, err, want)
	return nil
}

func waitForProof(t *testing.T, svc *Service, recordID string) model.ProofBundle {
	t.Helper()
	deadline := time.Now().Add(asyncProofWaitTimeout)
	for time.Now().Before(deadline) {
		got, err := svc.Proof(context.Background(), recordID)
		if err == nil {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	got, err := svc.Proof(context.Background(), recordID)
	t.Fatalf("Proof(%q) after %s = %+v err=%v lastErr=%v", recordID, asyncProofWaitTimeout, got, err, svc.LastError())
	return model.ProofBundle{}
}

func waitForLastError(t *testing.T, svc *Service) error {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := svc.LastError(); err != nil {
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
	err := svc.LastError()
	t.Fatalf("LastError() after wait = %v, want non-nil", err)
	return nil
}

type fakeEngine struct{}

func (fakeEngine) CommitBatch(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) ([]model.ProofBundle, error) {
	out := make([]model.ProofBundle, len(records))
	tree, err := merkle.Build(records)
	if err != nil {
		return nil, err
	}
	root := tree.Root()
	for i := range records {
		leaf, err := tree.LeafHash(i)
		if err != nil {
			return nil, err
		}
		proof, err := tree.Proof(i)
		if err != nil {
			return nil, err
		}
		out[i] = model.ProofBundle{
			SchemaVersion:   model.SchemaProofBundle,
			RecordID:        records[i].RecordID,
			SignedClaim:     signed[i],
			ServerRecord:    records[i],
			AcceptedReceipt: accepted[i],
			CommittedReceipt: model.CommittedReceipt{
				SchemaVersion: model.SchemaCommittedReceipt,
				RecordID:      records[i].RecordID,
				Status:        "committed",
				BatchID:       batchID,
				LeafIndex:     uint64(i),
				LeafHash:      leaf,
				BatchRoot:     root,
				ClosedAtUnixN: closedAt.UnixNano(),
			},
			BatchProof: model.BatchProof{
				TreeAlg:   model.DefaultMerkleTreeAlg,
				LeafIndex: uint64(i),
				TreeSize:  uint64(len(records)),
				AuditPath: proof,
			},
		}
	}
	return out, nil
}

func (fakeEngine) CommitBatchIndexes(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) (model.BatchRoot, []model.RecordIndex, error) {
	bundles, err := fakeEngine{}.CommitBatch(batchID, closedAt, signed, records, accepted)
	if err != nil {
		return model.BatchRoot{}, nil, err
	}
	root := rootFromBundles(batchID, bundles)
	indexes := make([]model.RecordIndex, len(bundles))
	for i := range bundles {
		indexes[i] = model.RecordIndexFromBundle(bundles[i])
	}
	return root, indexes, nil
}

type blockingEngine struct {
	block   chan struct{}
	entered chan struct{}
}

func (e blockingEngine) CommitBatch(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) ([]model.ProofBundle, error) {
	select {
	case e.entered <- struct{}{}:
	default:
	}
	<-e.block
	return fakeEngine{}.CommitBatch(batchID, closedAt, signed, records, accepted)
}

type emptyBundleEngine struct{}

func (emptyBundleEngine) CommitBatch(string, time.Time, []model.SignedClaim, []model.ServerRecord, []model.AcceptedReceipt) ([]model.ProofBundle, error) {
	return nil, nil
}

type blockingMaterializeEngine struct {
	block   chan struct{}
	entered chan struct{}
}

func (e blockingMaterializeEngine) CommitBatchIndexes(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) (model.BatchRoot, []model.RecordIndex, error) {
	return fakeEngine{}.CommitBatchIndexes(batchID, closedAt, signed, records, accepted)
}

func (e blockingMaterializeEngine) CommitBatch(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) ([]model.ProofBundle, error) {
	select {
	case e.entered <- struct{}{}:
	default:
	}
	<-e.block
	return fakeEngine{}.CommitBatch(batchID, closedAt, signed, records, accepted)
}

type countingMaterializeEngine struct {
	mu      sync.Mutex
	commits int
}

func (e *countingMaterializeEngine) CommitBatchIndexes(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) (model.BatchRoot, []model.RecordIndex, error) {
	return fakeEngine{}.CommitBatchIndexes(batchID, closedAt, signed, records, accepted)
}

func (e *countingMaterializeEngine) CommitBatch(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) ([]model.ProofBundle, error) {
	e.mu.Lock()
	e.commits++
	e.mu.Unlock()
	return fakeEngine{}.CommitBatch(batchID, closedAt, signed, records, accepted)
}

func (e *countingMaterializeEngine) CommitCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.commits
}

func signed(recordID string) model.SignedClaim {
	return model.SignedClaim{SchemaVersion: model.SchemaSignedClaim, Claim: model.ClientClaim{IdempotencyKey: recordID}}
}

func record(recordID string) model.ServerRecord {
	return model.ServerRecord{SchemaVersion: model.SchemaServerRecord, RecordID: recordID}
}

func recordWithWAL(recordID string, seq uint64) model.ServerRecord {
	return model.ServerRecord{
		SchemaVersion: model.SchemaServerRecord,
		RecordID:      recordID,
		WAL:           model.WALPosition{SegmentID: 1, Offset: int64(seq) * 128, Sequence: seq},
	}
}

func accepted(recordID string) model.AcceptedReceipt {
	return model.AcceptedReceipt{SchemaVersion: model.SchemaAcceptedReceipt, RecordID: recordID, Status: "accepted"}
}

// TestServiceInitialSeqResumesSuffix locks in the cross-restart fix
// for the "every fresh server emits batch_id ending in -000001"
// regression. With InitialSeq=42, the very first batch this service
// commits must be -000043 (counter is bumped before formatting).
func TestServiceInitialSeqResumesSuffix(t *testing.T) {
	t.Parallel()

	store := proofstore.LocalStore{Root: t.TempDir()}
	svc := New(fakeEngine{}, store, Options{
		QueueSize:  4,
		MaxRecords: 1, // commit immediately, no batching delay
		MaxDelay:   time.Hour,
		InitialSeq: 42,
	}, nil)
	defer svc.Shutdown(context.Background())

	if err := svc.Enqueue(context.Background(), signed("seq-a"), record("seq-a"), accepted("seq-a")); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	root := waitForLatestRoot(t, svc, 1)
	const want = "-000043"
	if !strings.HasSuffix(root.BatchID, want) {
		t.Fatalf("first batch_id = %q, want suffix %q", root.BatchID, want)
	}

	// A second commit on the same Service should keep climbing — the
	// in-memory counter is preserved across commits regardless of
	// where the seed came from.
	if err := svc.Enqueue(context.Background(), signed("seq-b"), record("seq-b"), accepted("seq-b")); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	// Wait for the second bundle to materialize via Proof, then read
	// the corresponding batch root by listing all roots and picking
	// the second one (LatestRoot only returns the newest, which is
	// what we want anyway, but TreeSize is still 1 for either, so
	// we have to disambiguate by batch_id suffix).
	got := waitForProof(t, svc, "seq-b")
	const wantNext = "-000044"
	if !strings.HasSuffix(got.CommittedReceipt.BatchID, wantNext) {
		t.Fatalf("second batch_id = %q, want suffix %q", got.CommittedReceipt.BatchID, wantNext)
	}
}

// TestServiceInitialSeqZeroPreservesLegacyBehaviour ensures the
// default zero value of InitialSeq still produces -000001 on the
// very first batch, matching every existing test/operator.
func TestServiceInitialSeqZeroPreservesLegacyBehaviour(t *testing.T) {
	t.Parallel()

	store := proofstore.LocalStore{Root: t.TempDir()}
	svc := New(fakeEngine{}, store, Options{
		QueueSize:  4,
		MaxRecords: 1,
		MaxDelay:   time.Hour,
	}, nil)
	defer svc.Shutdown(context.Background())

	if err := svc.Enqueue(context.Background(), signed("seq-zero"), record("seq-zero"), accepted("seq-zero")); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	root := waitForLatestRoot(t, svc, 1)
	const want = "-000001"
	if !strings.HasSuffix(root.BatchID, want) {
		t.Fatalf("first batch_id = %q, want suffix %q", root.BatchID, want)
	}
}
