package globallog

import (
	"context"
	"math/bits"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const (
	defaultGlobalLogBenchTreeSize = 8192
	globalLogBenchTreeSizeEnv     = "TRUSTDB_GLOBAL_LOG_BENCH_TREE_SIZE"
)

type globalLogBenchFixture struct {
	store    *memoryGlobalStore
	batchIDs []string
	treeSize uint64
}

func newGlobalLogBenchFixture(tb testing.TB, treeSize uint64) globalLogBenchFixture {
	tb.Helper()
	if treeSize < 2 {
		tb.Fatalf("treeSize = %d, want >= 2", treeSize)
	}
	store := newMemoryGlobalStore()
	svc := newTestServiceForStore(tb, store)
	ctx := context.Background()
	batchIDs := make([]string, treeSize)
	for i := uint64(0); i < treeSize; i++ {
		batchID := "bench-" + strconv.FormatUint(i+1, 10)
		if _, err := svc.AppendBatchRoot(ctx, batchRoot(batchID, byte(i%255+1))); err != nil {
			tb.Fatalf("AppendBatchRoot(%d): %v", i+1, err)
		}
		batchIDs[i] = batchID
	}
	return globalLogBenchFixture{store: store, batchIDs: batchIDs, treeSize: treeSize}
}

func TestGlobalLogHistoryProofReadCountsStayLogarithmic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const treeSize = 2048
	fixture := newGlobalLogBenchFixture(t, treeSize)

	counting := newCountingGlobalStore(fixture.store)
	reader, err := NewReader(counting)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	proof, err := reader.InclusionProof(ctx, fixture.batchIDs[treeSize/2], treeSize)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	if !VerifyInclusion(proof) {
		t.Fatal("VerifyInclusion returned false")
	}
	inclusionReads := counting.Snapshot()
	if inclusionReads.LeafByBatchReads != 1 || inclusionReads.STHReads != 1 {
		t.Fatalf("inclusion lookup reads = %+v, want one batch index read and one STH read", inclusionReads)
	}
	if max := int64(bits.Len64(treeSize) * 2); inclusionReads.TotalProofTreeReads() > max {
		t.Fatalf("inclusion proof tree reads = %d, want <= %d for tree_size=%d", inclusionReads.TotalProofTreeReads(), max, treeSize)
	}

	counting.Reset()
	consistency, err := reader.ConsistencyProof(ctx, treeSize/2+1, treeSize)
	if err != nil {
		t.Fatalf("ConsistencyProof: %v", err)
	}
	if len(consistency.AuditPath) == 0 {
		t.Fatal("expected non-empty consistency path")
	}
	consistencyReads := counting.Snapshot()
	if max := int64(bits.Len64(treeSize) * 4); consistencyReads.TotalProofTreeReads() > max {
		t.Fatalf("consistency proof tree reads = %d, want <= %d for tree_size=%d", consistencyReads.TotalProofTreeReads(), max, treeSize)
	}

	counting.Reset()
	if _, found, err := reader.STH(ctx, treeSize/2); err != nil || !found {
		t.Fatalf("STH found=%v err=%v", found, err)
	}
	sthReads := counting.Snapshot()
	if sthReads.STHReads != 1 || sthReads.TotalProofTreeReads() != 0 {
		t.Fatalf("historical STH direct reads = %+v, want one STH read and no proof-tree reads", sthReads)
	}

	counting.Reset()
	page, err := reader.ListSTHs(ctx, model.TreeHeadListOptions{
		Limit:         16,
		Direction:     model.RecordListDirectionDesc,
		AfterTreeSize: treeSize,
	})
	if err != nil {
		t.Fatalf("ListSTHs: %v", err)
	}
	if len(page) != 16 {
		t.Fatalf("ListSTHs returned %d entries, want 16", len(page))
	}
	pageReads := counting.Snapshot()
	if pageReads.STHPageCalls != 1 || pageReads.STHPageReturned != 16 {
		t.Fatalf("historical STH page reads = %+v, want one page call returning 16", pageReads)
	}
}

func TestConsistencyProofAllocationBoundLargeTree(t *testing.T) {
	ctx := context.Background()
	const treeSize = 2048
	fixture := newGlobalLogBenchFixture(t, treeSize)
	reader, err := NewReader(fixture.store)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	allocs := testing.AllocsPerRun(50, func() {
		if _, err := reader.ConsistencyProof(ctx, treeSize/2+1, treeSize); err != nil {
			t.Fatalf("ConsistencyProof: %v", err)
		}
	})
	if max := float64(treeSize / 8); allocs > max {
		t.Fatalf("ConsistencyProof allocs/run = %.2f, want <= %.2f for tree_size=%d", allocs, max, treeSize)
	}
}

func BenchmarkGlobalLogHistoryProofsLargeTree(b *testing.B) {
	ctx := context.Background()
	treeSize := benchmarkGlobalLogTreeSize(b)
	fixture := newGlobalLogBenchFixture(b, treeSize)

	b.Run("inclusion_latest_middle", func(b *testing.B) {
		counting := newCountingGlobalStore(fixture.store)
		reader := mustNewReader(b, counting)
		batchID := fixture.batchIDs[treeSize/2]
		runGlobalLogBenchmark(b, counting, func() {
			proof, err := reader.InclusionProof(ctx, batchID, treeSize)
			if err != nil {
				b.Fatalf("InclusionProof: %v", err)
			}
			if !VerifyInclusion(proof) {
				b.Fatal("VerifyInclusion returned false")
			}
		})
	})

	b.Run("inclusion_historical_quarter", func(b *testing.B) {
		counting := newCountingGlobalStore(fixture.store)
		reader := mustNewReader(b, counting)
		historicalTreeSize := treeSize / 2
		batchID := fixture.batchIDs[historicalTreeSize/2]
		runGlobalLogBenchmark(b, counting, func() {
			proof, err := reader.InclusionProof(ctx, batchID, historicalTreeSize)
			if err != nil {
				b.Fatalf("InclusionProof: %v", err)
			}
			if !VerifyInclusion(proof) {
				b.Fatal("VerifyInclusion returned false")
			}
		})
	})

	b.Run("consistency_half_to_latest", func(b *testing.B) {
		counting := newCountingGlobalStore(fixture.store)
		reader := mustNewReader(b, counting)
		from := treeSize / 2
		runGlobalLogBenchmark(b, counting, func() {
			proof, err := reader.ConsistencyProof(ctx, from, treeSize)
			if err != nil {
				b.Fatalf("ConsistencyProof: %v", err)
			}
			if proof.FromTreeSize != from || proof.ToTreeSize != treeSize {
				b.Fatalf("ConsistencyProof range = %d..%d", proof.FromTreeSize, proof.ToTreeSize)
			}
		})
	})

	b.Run("consistency_sparse_to_latest", func(b *testing.B) {
		counting := newCountingGlobalStore(fixture.store)
		reader := mustNewReader(b, counting)
		from := treeSize/3 + 1
		runGlobalLogBenchmark(b, counting, func() {
			proof, err := reader.ConsistencyProof(ctx, from, treeSize)
			if err != nil {
				b.Fatalf("ConsistencyProof: %v", err)
			}
			if len(proof.AuditPath) == 0 {
				b.Fatal("expected non-empty consistency path")
			}
		})
	})

	b.Run("historical_sth_get_middle", func(b *testing.B) {
		counting := newCountingGlobalStore(fixture.store)
		reader := mustNewReader(b, counting)
		target := treeSize / 2
		runGlobalLogBenchmark(b, counting, func() {
			sth, found, err := reader.STH(ctx, target)
			if err != nil {
				b.Fatalf("STH: %v", err)
			}
			if !found || sth.TreeSize != target {
				b.Fatalf("STH found=%v tree_size=%d, want %d", found, sth.TreeSize, target)
			}
		})
	})

	b.Run("historical_sth_page_desc", func(b *testing.B) {
		counting := newCountingGlobalStore(fixture.store)
		reader := mustNewReader(b, counting)
		opts := model.TreeHeadListOptions{
			Limit:         32,
			Direction:     model.RecordListDirectionDesc,
			AfterTreeSize: treeSize,
		}
		runGlobalLogBenchmark(b, counting, func() {
			sths, err := reader.ListSTHs(ctx, opts)
			if err != nil {
				b.Fatalf("ListSTHs: %v", err)
			}
			if len(sths) != opts.Limit {
				b.Fatalf("ListSTHs returned %d entries, want %d", len(sths), opts.Limit)
			}
		})
	})
}

func benchmarkGlobalLogTreeSize(b *testing.B) uint64 {
	b.Helper()
	raw := strings.TrimSpace(os.Getenv(globalLogBenchTreeSizeEnv))
	if raw == "" {
		return defaultGlobalLogBenchTreeSize
	}
	size, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || size < 2 {
		b.Fatalf("%s must be an integer >= 2", globalLogBenchTreeSizeEnv)
	}
	return size
}

func mustNewReader(tb testing.TB, store Store) *Service {
	tb.Helper()
	reader, err := NewReader(store)
	if err != nil {
		tb.Fatalf("NewReader: %v", err)
	}
	return reader
}

func runGlobalLogBenchmark(b *testing.B, counting *countingGlobalStore, fn func()) {
	b.Helper()
	b.ReportAllocs()
	counting.Reset()
	b.ResetTimer()
	for b.Loop() {
		fn()
	}
	b.StopTimer()
	reportGlobalLogReadMetrics(b, counting.Snapshot())
}

func reportGlobalLogReadMetrics(b *testing.B, counts globalLogReadCounts) {
	b.Helper()
	if b.N == 0 {
		return
	}
	n := float64(b.N)
	b.ReportMetric(float64(counts.LeafReads)/n, "leaf_reads/op")
	b.ReportMetric(float64(counts.LeafByBatchReads)/n, "batch_leaf_reads/op")
	b.ReportMetric(float64(counts.NodeReads)/n, "node_reads/op")
	b.ReportMetric(float64(counts.STHReads)/n, "sth_reads/op")
	b.ReportMetric(float64(counts.LatestSTHReads)/n, "latest_sth_reads/op")
	b.ReportMetric(float64(counts.STHPageCalls)/n, "sth_page_calls/op")
	b.ReportMetric(float64(counts.STHPageReturned)/n, "sth_page_returned/op")
}

type globalLogReadCounts struct {
	LeafReads        int64
	LeafByBatchReads int64
	NodeReads        int64
	STHReads         int64
	LatestSTHReads   int64
	STHPageCalls     int64
	STHPageReturned  int64
}

func (c globalLogReadCounts) TotalProofTreeReads() int64 {
	return c.LeafReads + c.NodeReads
}

type countingGlobalStore struct {
	base             Store
	leafReads        atomic.Int64
	leafByBatchReads atomic.Int64
	nodeReads        atomic.Int64
	sthReads         atomic.Int64
	latestSTHReads   atomic.Int64
	sthPageCalls     atomic.Int64
	sthPageReturned  atomic.Int64
}

func newCountingGlobalStore(base Store) *countingGlobalStore {
	return &countingGlobalStore{base: base}
}

func (s *countingGlobalStore) Reset() {
	s.leafReads.Store(0)
	s.leafByBatchReads.Store(0)
	s.nodeReads.Store(0)
	s.sthReads.Store(0)
	s.latestSTHReads.Store(0)
	s.sthPageCalls.Store(0)
	s.sthPageReturned.Store(0)
}

func (s *countingGlobalStore) Snapshot() globalLogReadCounts {
	return globalLogReadCounts{
		LeafReads:        s.leafReads.Load(),
		LeafByBatchReads: s.leafByBatchReads.Load(),
		NodeReads:        s.nodeReads.Load(),
		STHReads:         s.sthReads.Load(),
		LatestSTHReads:   s.latestSTHReads.Load(),
		STHPageCalls:     s.sthPageCalls.Load(),
		STHPageReturned:  s.sthPageReturned.Load(),
	}
}

func (s *countingGlobalStore) PutGlobalLeaf(ctx context.Context, leaf model.GlobalLogLeaf) error {
	return s.base.PutGlobalLeaf(ctx, leaf)
}

func (s *countingGlobalStore) CommitGlobalLogAppend(ctx context.Context, entry model.GlobalLogAppend) error {
	return s.base.CommitGlobalLogAppend(ctx, entry)
}

func (s *countingGlobalStore) GetGlobalLeaf(ctx context.Context, index uint64) (model.GlobalLogLeaf, bool, error) {
	s.leafReads.Add(1)
	return s.base.GetGlobalLeaf(ctx, index)
}

func (s *countingGlobalStore) GetGlobalLeafByBatchID(ctx context.Context, batchID string) (model.GlobalLogLeaf, bool, error) {
	s.leafByBatchReads.Add(1)
	return s.base.GetGlobalLeafByBatchID(ctx, batchID)
}

func (s *countingGlobalStore) ListGlobalLeaves(ctx context.Context) ([]model.GlobalLogLeaf, error) {
	return s.base.ListGlobalLeaves(ctx)
}

func (s *countingGlobalStore) ListGlobalLeavesRange(ctx context.Context, startIndex uint64, limit int) ([]model.GlobalLogLeaf, error) {
	return s.base.ListGlobalLeavesRange(ctx, startIndex, limit)
}

func (s *countingGlobalStore) ListGlobalLeavesPage(ctx context.Context, opts model.GlobalLeafListOptions) ([]model.GlobalLogLeaf, error) {
	return s.base.ListGlobalLeavesPage(ctx, opts)
}

func (s *countingGlobalStore) PutGlobalLogNode(ctx context.Context, node model.GlobalLogNode) error {
	return s.base.PutGlobalLogNode(ctx, node)
}

func (s *countingGlobalStore) GetGlobalLogNode(ctx context.Context, level, startIndex uint64) (model.GlobalLogNode, bool, error) {
	s.nodeReads.Add(1)
	return s.base.GetGlobalLogNode(ctx, level, startIndex)
}

func (s *countingGlobalStore) ListGlobalLogNodesAfter(ctx context.Context, afterLevel, afterStartIndex uint64, limit int) ([]model.GlobalLogNode, error) {
	return s.base.ListGlobalLogNodesAfter(ctx, afterLevel, afterStartIndex, limit)
}

func (s *countingGlobalStore) PutGlobalLogState(ctx context.Context, state model.GlobalLogState) error {
	return s.base.PutGlobalLogState(ctx, state)
}

func (s *countingGlobalStore) GetGlobalLogState(ctx context.Context) (model.GlobalLogState, bool, error) {
	return s.base.GetGlobalLogState(ctx)
}

func (s *countingGlobalStore) PutSignedTreeHead(ctx context.Context, sth model.SignedTreeHead) error {
	return s.base.PutSignedTreeHead(ctx, sth)
}

func (s *countingGlobalStore) GetSignedTreeHead(ctx context.Context, treeSize uint64) (model.SignedTreeHead, bool, error) {
	s.sthReads.Add(1)
	return s.base.GetSignedTreeHead(ctx, treeSize)
}

func (s *countingGlobalStore) ListSignedTreeHeadsPage(ctx context.Context, opts model.TreeHeadListOptions) ([]model.SignedTreeHead, error) {
	s.sthPageCalls.Add(1)
	sths, err := s.base.ListSignedTreeHeadsPage(ctx, opts)
	s.sthPageReturned.Add(int64(len(sths)))
	return sths, err
}

func (s *countingGlobalStore) LatestSignedTreeHead(ctx context.Context) (model.SignedTreeHead, bool, error) {
	s.latestSTHReads.Add(1)
	return s.base.LatestSignedTreeHead(ctx)
}

func (s *countingGlobalStore) PutGlobalLogTile(ctx context.Context, tile model.GlobalLogTile) error {
	return s.base.PutGlobalLogTile(ctx, tile)
}

func (s *countingGlobalStore) ListGlobalLogTiles(ctx context.Context) ([]model.GlobalLogTile, error) {
	return s.base.ListGlobalLogTiles(ctx)
}

type memoryGlobalStore struct {
	mu            sync.RWMutex
	leaves        map[uint64]model.GlobalLogLeaf
	leavesByBatch map[string]model.GlobalLogLeaf
	nodes         map[globalNodeKey]model.GlobalLogNode
	state         model.GlobalLogState
	hasState      bool
	sths          map[uint64]model.SignedTreeHead
	latestSTH     uint64
	tiles         []model.GlobalLogTile
}

type globalNodeKey struct {
	level uint64
	start uint64
}

func newMemoryGlobalStore() *memoryGlobalStore {
	return &memoryGlobalStore{
		leaves:        make(map[uint64]model.GlobalLogLeaf),
		leavesByBatch: make(map[string]model.GlobalLogLeaf),
		nodes:         make(map[globalNodeKey]model.GlobalLogNode),
		sths:          make(map[uint64]model.SignedTreeHead),
	}
}

func (s *memoryGlobalStore) PutGlobalLeaf(ctx context.Context, leaf model.GlobalLogLeaf) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory global leaf put canceled", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	leaf = cloneGlobalLogLeaf(leaf)
	s.leaves[leaf.LeafIndex] = leaf
	s.leavesByBatch[leaf.BatchID] = leaf
	return nil
}

func (s *memoryGlobalStore) CommitGlobalLogAppend(ctx context.Context, entry model.GlobalLogAppend) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory global log append canceled", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	leaf := cloneGlobalLogLeaf(entry.Leaf)
	s.leaves[leaf.LeafIndex] = leaf
	s.leavesByBatch[leaf.BatchID] = leaf
	for _, node := range entry.Nodes {
		s.nodes[globalNodeKey{level: node.Level, start: node.StartIndex}] = cloneGlobalLogNode(node)
	}
	s.state = cloneGlobalLogState(entry.State)
	s.hasState = true
	sth := cloneSignedTreeHead(entry.STH)
	s.sths[sth.TreeSize] = sth
	if sth.TreeSize > s.latestSTH {
		s.latestSTH = sth.TreeSize
	}
	return nil
}

func (s *memoryGlobalStore) GetGlobalLeaf(ctx context.Context, index uint64) (model.GlobalLogLeaf, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.GlobalLogLeaf{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory global leaf get canceled", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	leaf, ok := s.leaves[index]
	return cloneGlobalLogLeaf(leaf), ok, nil
}

func (s *memoryGlobalStore) GetGlobalLeafByBatchID(ctx context.Context, batchID string) (model.GlobalLogLeaf, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.GlobalLogLeaf{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory global leaf by batch get canceled", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	leaf, ok := s.leavesByBatch[batchID]
	return cloneGlobalLogLeaf(leaf), ok, nil
}

func (s *memoryGlobalStore) ListGlobalLeaves(ctx context.Context) ([]model.GlobalLogLeaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory global leaf list canceled", err)
	}
	s.mu.RLock()
	limit := len(s.leaves)
	s.mu.RUnlock()
	return s.ListGlobalLeavesRange(ctx, 0, limit)
}

func (s *memoryGlobalStore) ListGlobalLeavesRange(ctx context.Context, startIndex uint64, limit int) ([]model.GlobalLogLeaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory global leaf range canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.GlobalLogLeaf, 0, limit)
	for i := startIndex; len(out) < limit; i++ {
		leaf, ok := s.leaves[i]
		if !ok {
			break
		}
		out = append(out, cloneGlobalLogLeaf(leaf))
	}
	return out, nil
}

func (s *memoryGlobalStore) ListGlobalLeavesPage(ctx context.Context, opts model.GlobalLeafListOptions) ([]model.GlobalLogLeaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory global leaf page canceled", err)
	}
	limit := normaliseMemoryLimit(opts.Limit)
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]uint64, 0, len(s.leaves))
	for key := range s.leaves {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if strings.EqualFold(opts.Direction, model.RecordListDirectionAsc) {
			return keys[i] < keys[j]
		}
		return keys[i] > keys[j]
	})
	out := make([]model.GlobalLogLeaf, 0, limit)
	for _, key := range keys {
		if len(out) >= limit {
			break
		}
		leaf := s.leaves[key]
		if model.Uint64AfterCursor(leaf.LeafIndex, opts.AfterLeafIndex, opts.Direction) {
			out = append(out, cloneGlobalLogLeaf(leaf))
		}
	}
	return out, nil
}

func (s *memoryGlobalStore) PutGlobalLogNode(ctx context.Context, node model.GlobalLogNode) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory global node put canceled", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[globalNodeKey{level: node.Level, start: node.StartIndex}] = cloneGlobalLogNode(node)
	return nil
}

func (s *memoryGlobalStore) GetGlobalLogNode(ctx context.Context, level, startIndex uint64) (model.GlobalLogNode, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.GlobalLogNode{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory global node get canceled", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	node, ok := s.nodes[globalNodeKey{level: level, start: startIndex}]
	return cloneGlobalLogNode(node), ok, nil
}

func (s *memoryGlobalStore) ListGlobalLogNodesAfter(ctx context.Context, afterLevel, afterStartIndex uint64, limit int) ([]model.GlobalLogNode, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory global node list canceled", err)
	}
	limit = normaliseMemoryLimit(limit)
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]globalNodeKey, 0, len(s.nodes))
	for key := range s.nodes {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].level == keys[j].level {
			return keys[i].start < keys[j].start
		}
		return keys[i].level < keys[j].level
	})
	hasCursor := afterLevel != ^uint64(0) || afterStartIndex != ^uint64(0)
	out := make([]model.GlobalLogNode, 0, limit)
	for _, key := range keys {
		if hasCursor && (key.level < afterLevel || key.level == afterLevel && key.start <= afterStartIndex) {
			continue
		}
		out = append(out, cloneGlobalLogNode(s.nodes[key]))
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *memoryGlobalStore) PutGlobalLogState(ctx context.Context, state model.GlobalLogState) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory global state put canceled", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = cloneGlobalLogState(state)
	s.hasState = true
	return nil
}

func (s *memoryGlobalStore) GetGlobalLogState(ctx context.Context) (model.GlobalLogState, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.GlobalLogState{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory global state get canceled", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneGlobalLogState(s.state), s.hasState, nil
}

func (s *memoryGlobalStore) PutSignedTreeHead(ctx context.Context, sth model.SignedTreeHead) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory sth put canceled", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sths[sth.TreeSize] = cloneSignedTreeHead(sth)
	if sth.TreeSize > s.latestSTH {
		s.latestSTH = sth.TreeSize
	}
	return nil
}

func (s *memoryGlobalStore) GetSignedTreeHead(ctx context.Context, treeSize uint64) (model.SignedTreeHead, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory sth get canceled", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	sth, ok := s.sths[treeSize]
	return cloneSignedTreeHead(sth), ok, nil
}

func (s *memoryGlobalStore) ListSignedTreeHeadsPage(ctx context.Context, opts model.TreeHeadListOptions) ([]model.SignedTreeHead, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory sth page canceled", err)
	}
	limit := normaliseMemoryLimit(opts.Limit)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.SignedTreeHead, 0, limit)
	if strings.EqualFold(opts.Direction, model.RecordListDirectionAsc) {
		for treeSize := opts.AfterTreeSize + 1; treeSize <= s.latestSTH && len(out) < limit; treeSize++ {
			sth, ok := s.sths[treeSize]
			if !ok {
				break
			}
			out = append(out, cloneSignedTreeHead(sth))
		}
		return out, nil
	}
	start := s.latestSTH
	if opts.AfterTreeSize > 0 && opts.AfterTreeSize <= start {
		start = opts.AfterTreeSize - 1
	}
	for treeSize := start; treeSize > 0 && len(out) < limit; treeSize-- {
		sth, ok := s.sths[treeSize]
		if !ok {
			break
		}
		if model.Uint64AfterCursor(sth.TreeSize, opts.AfterTreeSize, opts.Direction) {
			out = append(out, cloneSignedTreeHead(sth))
		}
	}
	return out, nil
}

func (s *memoryGlobalStore) LatestSignedTreeHead(ctx context.Context) (model.SignedTreeHead, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory latest sth canceled", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.latestSTH == 0 {
		return model.SignedTreeHead{}, false, nil
	}
	return cloneSignedTreeHead(s.sths[s.latestSTH]), true, nil
}

func (s *memoryGlobalStore) PutGlobalLogTile(ctx context.Context, tile model.GlobalLogTile) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory tile put canceled", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tiles = append(s.tiles, cloneGlobalLogTile(tile))
	return nil
}

func (s *memoryGlobalStore) ListGlobalLogTiles(ctx context.Context) ([]model.GlobalLogTile, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "memory tile list canceled", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.GlobalLogTile, len(s.tiles))
	for i := range s.tiles {
		out[i] = cloneGlobalLogTile(s.tiles[i])
	}
	return out, nil
}

func normaliseMemoryLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	return limit
}

func cloneGlobalLogLeaf(in model.GlobalLogLeaf) model.GlobalLogLeaf {
	out := in
	out.BatchRoot = append([]byte(nil), in.BatchRoot...)
	out.LeafHash = append([]byte(nil), in.LeafHash...)
	return out
}

func cloneGlobalLogNode(in model.GlobalLogNode) model.GlobalLogNode {
	out := in
	out.Hash = append([]byte(nil), in.Hash...)
	return out
}

func cloneGlobalLogState(in model.GlobalLogState) model.GlobalLogState {
	out := in
	out.RootHash = append([]byte(nil), in.RootHash...)
	out.Frontier = cloneFrontier(in.Frontier)
	return out
}

func cloneSignedTreeHead(in model.SignedTreeHead) model.SignedTreeHead {
	out := in
	out.RootHash = append([]byte(nil), in.RootHash...)
	out.Signature.Signature = append([]byte(nil), in.Signature.Signature...)
	return out
}

func cloneGlobalLogTile(in model.GlobalLogTile) model.GlobalLogTile {
	out := in
	out.Hashes = make([][]byte, len(in.Hashes))
	for i := range in.Hashes {
		out.Hashes[i] = append([]byte(nil), in.Hashes[i]...)
	}
	return out
}
