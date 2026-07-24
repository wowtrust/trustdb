package l5projector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/l5coverage"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestProjectPagePromotesCoveredPrefixAcrossPages(t *testing.T) {
	key := projectorKey()
	store := newProjectorStore(key, 6)
	store.result = projectorResult(key, 5)
	var promoted []string
	service, err := New(Config{
		Store: store, Key: key, PageSize: 2, Clock: func() time.Time { return time.Unix(0, 500) },
		OnBatchesPromoted: func(_ context.Context, batchIDs []string) {
			promoted = append(promoted, batchIDs...)
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i, wantProgress := range []bool{true, true, true, false} {
		progressed, err := service.ProjectPage(context.Background())
		if err != nil || progressed != wantProgress {
			t.Fatalf("ProjectPage %d progressed=%v err=%v, want %v", i, progressed, err, wantProgress)
		}
	}
	checkpoint, found, err := store.GetL5CoverageCheckpoint(context.Background(), key)
	if err != nil || !found || checkpoint.CoveredTreeSize != 5 {
		t.Fatalf("checkpoint=%+v found=%v err=%v", checkpoint, found, err)
	}
	for i := 0; i < 5; i++ {
		if got := store.level(fmt.Sprintf("batch-%d", i)); got != "L5" {
			t.Fatalf("batch-%d level=%q, want L5", i, got)
		}
	}
	if got := store.level("batch-5"); got != "L4" {
		t.Fatalf("uncovered batch level=%q, want L4", got)
	}
	if len(promoted) != 5 {
		t.Fatalf("OnBatchesPromoted = %v, want five batches", promoted)
	}
}

func TestProjectPageRetriesWholePageBeforeCheckpoint(t *testing.T) {
	key := projectorKey()
	store := newProjectorStore(key, 3)
	store.result = projectorResult(key, 3)
	store.failBatch = "batch-1"
	store.failuresRemaining = 1
	service, err := New(Config{Store: store, Key: key, PageSize: 3})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if progressed, err := service.ProjectPage(context.Background()); err == nil || progressed {
		t.Fatalf("ProjectPage failure progressed=%v err=%v", progressed, err)
	}
	if _, found, err := store.GetL5CoverageCheckpoint(context.Background(), key); err != nil || found {
		t.Fatalf("checkpoint after partial failure found=%v err=%v", found, err)
	}
	if got := store.level("batch-0"); got != "L5" {
		t.Fatalf("idempotent partial promotion level=%q, want L5", got)
	}
	if progressed, err := service.ProjectPage(context.Background()); err != nil || !progressed {
		t.Fatalf("ProjectPage retry progressed=%v err=%v", progressed, err)
	}
	checkpoint, found, err := store.GetL5CoverageCheckpoint(context.Background(), key)
	if err != nil || !found || checkpoint.CoveredTreeSize != 3 {
		t.Fatalf("checkpoint after retry=%+v found=%v err=%v", checkpoint, found, err)
	}
}

func TestProjectPageFailsClosedOnMissingLeaf(t *testing.T) {
	key := projectorKey()
	store := newProjectorStore(key, 3)
	delete(store.leaves, 1)
	store.result = projectorResult(key, 3)
	service, err := New(Config{Store: store, Key: key, PageSize: 3})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := service.ProjectPage(context.Background()); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("ProjectPage missing leaf=%v", err)
	}
	if _, found, err := store.GetL5CoverageCheckpoint(context.Background(), key); err != nil || found {
		t.Fatalf("checkpoint after missing leaf found=%v err=%v", found, err)
	}
}

func TestProjectPageResumesAndExtendsWhenAnchorGrows(t *testing.T) {
	key := projectorKey()
	store := newProjectorStore(key, 4)
	store.result = projectorResult(key, 2)
	first, err := New(Config{Store: store, Key: key, PageSize: 8})
	if err != nil {
		t.Fatalf("New first: %v", err)
	}
	if progressed, err := first.ProjectPage(context.Background()); err != nil || !progressed {
		t.Fatalf("ProjectPage first progressed=%v err=%v", progressed, err)
	}

	store.result = projectorResult(key, 4)
	restarted, err := New(Config{Store: store, Key: key, PageSize: 8})
	if err != nil {
		t.Fatalf("New restarted: %v", err)
	}
	if progressed, err := restarted.ProjectPage(context.Background()); err != nil || !progressed {
		t.Fatalf("ProjectPage restarted progressed=%v err=%v", progressed, err)
	}
	checkpoint, found, err := store.GetL5CoverageCheckpoint(context.Background(), key)
	if err != nil || !found || checkpoint.CoveredTreeSize != 4 {
		t.Fatalf("checkpoint after growth=%+v found=%v err=%v", checkpoint, found, err)
	}
}

func TestProjectPageWithoutAnchorLeavesL4(t *testing.T) {
	key := projectorKey()
	store := newProjectorStore(key, 1)
	service, err := New(Config{Store: store, Key: key})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if progressed, err := service.ProjectPage(context.Background()); err != nil || progressed {
		t.Fatalf("ProjectPage progressed=%v err=%v", progressed, err)
	}
	if got := store.level("batch-0"); got != "L4" {
		t.Fatalf("unanchored batch level=%q, want L4", got)
	}
}

func TestStopCancelsProjectionWithoutForcingCheckpoint(t *testing.T) {
	key := projectorKey()
	base := newProjectorStore(key, 1)
	base.result = projectorResult(key, 1)
	store := &blockingProjectorStore{projectorStore: base, started: make(chan struct{})}
	service, err := New(Config{Store: store, Key: key, PollInterval: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	service.Start(context.Background())
	select {
	case <-store.started:
	case <-time.After(5 * time.Second):
		t.Fatal("projection did not start")
	}
	service.Stop()
	if _, found, err := store.GetL5CoverageCheckpoint(context.Background(), key); err != nil || found {
		t.Fatalf("checkpoint after canceled shutdown found=%v err=%v", found, err)
	}
}

type projectorStore struct {
	mu                sync.Mutex
	key               model.STHAnchorScheduleKey
	result            model.STHAnchorResult
	leaves            map[uint64]model.GlobalLogLeaf
	levels            map[string]string
	checkpoint        model.L5CoverageCheckpoint
	checkpointFound   bool
	failBatch         string
	failuresRemaining int
}

type blockingProjectorStore struct {
	*projectorStore
	started chan struct{}
	once    sync.Once
}

func (s *blockingProjectorStore) PromoteBatchProofLevel(ctx context.Context, _, _ string) error {
	s.once.Do(func() { close(s.started) })
	<-ctx.Done()
	return ctx.Err()
}

func newProjectorStore(key model.STHAnchorScheduleKey, leaves int) *projectorStore {
	store := &projectorStore{
		key: key, leaves: make(map[uint64]model.GlobalLogLeaf, leaves), levels: make(map[string]string, leaves),
	}
	for i := 0; i < leaves; i++ {
		batchID := fmt.Sprintf("batch-%d", i)
		store.leaves[uint64(i)] = model.GlobalLogLeaf{
			SchemaVersion: model.SchemaGlobalLogLeaf, NodeID: key.NodeID, LogID: key.LogID, BatchID: batchID, LeafIndex: uint64(i),
		}
		store.levels[batchID] = "L4"
	}
	return store
}

func (s *projectorStore) GetSTHAnchorResultForKey(_ context.Context, key model.STHAnchorResultKey) (model.STHAnchorResult, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.result.TreeSize == 0 || !anchorschedule.SameResultKey(anchorschedule.ResultKey(s.result), key) {
		return model.STHAnchorResult{}, false, nil
	}
	return s.result, true, nil
}

func (s *projectorStore) LatestSTHAnchorResultForKey(_ context.Context, key model.STHAnchorScheduleKey) (model.STHAnchorResult, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.result.TreeSize == 0 || !anchorschedule.SameKey(key, s.key) {
		return model.STHAnchorResult{}, false, nil
	}
	return s.result, true, nil
}

func (s *projectorStore) GetL5CoverageCheckpoint(_ context.Context, key model.STHAnchorScheduleKey) (model.L5CoverageCheckpoint, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !anchorschedule.SameKey(key, s.key) || !s.checkpointFound {
		return model.L5CoverageCheckpoint{}, false, nil
	}
	return s.checkpoint, true, nil
}

func (s *projectorStore) AdvanceL5CoverageCheckpoint(_ context.Context, key model.STHAnchorScheduleKey, coveredTreeSize uint64, updatedAtUnixN int64) (model.L5CoverageCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, changed, err := l5coverage.Advance(s.checkpoint, s.checkpointFound, key, coveredTreeSize, updatedAtUnixN)
	if err != nil {
		return model.L5CoverageCheckpoint{}, err
	}
	if changed {
		s.checkpoint = next
		s.checkpointFound = true
	}
	return s.checkpoint, nil
}

func (s *projectorStore) ListGlobalLeavesRange(_ context.Context, start uint64, limit int) ([]model.GlobalLogLeaf, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	leaves := make([]model.GlobalLogLeaf, 0, limit)
	for i := 0; i < limit; i++ {
		leaf, ok := s.leaves[start+uint64(i)]
		if !ok {
			break
		}
		leaves = append(leaves, leaf)
	}
	return leaves, nil
}

func (s *projectorStore) PromoteBatchProofLevel(_ context.Context, batchID, proofLevel string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if batchID == s.failBatch && s.failuresRemaining > 0 {
		s.failuresRemaining--
		return errors.New("injected promotion failure")
	}
	if model.ProofLevelRank(s.levels[batchID]) < model.ProofLevelRank(proofLevel) {
		s.levels[batchID] = proofLevel
	}
	return nil
}

func (s *projectorStore) level(batchID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.levels[batchID]
}

func projectorKey() model.STHAnchorScheduleKey {
	return model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
}

func projectorResult(key model.STHAnchorScheduleKey, treeSize uint64) model.STHAnchorResult {
	sth := model.SignedTreeHead{
		SchemaVersion: model.SchemaSignedTreeHead, TreeAlg: model.DefaultMerkleTreeAlg, TreeSize: treeSize,
		RootHash: bytes.Repeat([]byte{byte(treeSize)}, 32), TimestampUnixN: int64(treeSize), NodeID: key.NodeID, LogID: key.LogID,
		Signature: model.Signature{Alg: model.DefaultSignatureAlg, KeyID: "server-key", Signature: bytes.Repeat([]byte{byte(treeSize)}, 64)},
	}
	return model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult, NodeID: key.NodeID, LogID: key.LogID, TreeSize: treeSize,
		SinkName: key.SinkName, AnchorID: fmt.Sprintf("anchor-%d", treeSize), RootHash: append([]byte(nil), sth.RootHash...), STH: sth,
		PublishedAtUnixN: int64(treeSize),
	}
}
