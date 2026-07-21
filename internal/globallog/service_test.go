package globallog

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/anchor"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
	"github.com/ryan-wong-coder/trustdb/internal/trustcrypto"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

type conflictingBatchStore struct {
	Store
	once     sync.Once
	conflict func() error
}

func (s *conflictingBatchStore) CommitGlobalLogAppends(ctx context.Context, appends []model.GlobalLogAppend) error {
	var conflictErr error
	s.once.Do(func() { conflictErr = s.conflict() })
	if conflictErr != nil {
		return conflictErr
	}
	for i := range appends {
		if err := s.Store.CommitGlobalLogAppend(ctx, appends[i]); err != nil {
			return err
		}
	}
	return nil
}

func newTestService(t testing.TB) (*Service, proofstore.LocalStore) {
	t.Helper()
	store := proofstore.LocalStore{Root: t.TempDir()}
	return newTestServiceForStore(t, store), store
}

func newTestServiceForStore(t testing.TB, store Store) *Service {
	t.Helper()
	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	svc, err := New(Options{
		Store:      store,
		LogID:      "test-log",
		KeyID:      "test-key",
		PrivateKey: priv,
		Clock:      func() time.Time { return time.Unix(100, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc
}

func batchRoot(id string, seed byte) model.BatchRoot {
	root := bytes.Repeat([]byte{seed}, 32)
	return model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       id,
		BatchRoot:     root,
		TreeSize:      uint64(seed),
		ClosedAtUnixN: int64(seed),
	}
}

func TestAppendBatchRootProducesStableSTHAndInclusionProof(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, store := newTestService(t)

	var latest model.SignedTreeHead
	for _, root := range []model.BatchRoot{
		batchRoot("b1", 1),
		batchRoot("b2", 2),
		batchRoot("b3", 3),
	} {
		sth, err := svc.AppendBatchRoot(ctx, root)
		if err != nil {
			t.Fatalf("AppendBatchRoot(%s): %v", root.BatchID, err)
		}
		latest = sth
	}
	if latest.TreeSize != 3 {
		t.Fatalf("latest tree_size = %d, want 3", latest.TreeSize)
	}
	again, err := svc.AppendBatchRoot(ctx, batchRoot("b2", 2))
	if err != nil {
		t.Fatalf("AppendBatchRoot duplicate: %v", err)
	}
	if again.TreeSize != 2 {
		t.Fatalf("duplicate append returned tree_size=%d, want original STH size 2", again.TreeSize)
	}
	leaves, err := store.ListGlobalLeaves(ctx)
	if err != nil {
		t.Fatalf("ListGlobalLeaves: %v", err)
	}
	if len(leaves) != 3 {
		t.Fatalf("global leaves = %d, want 3", len(leaves))
	}

	proof, err := svc.InclusionProof(ctx, "b2", latest.TreeSize)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	if !VerifyInclusion(proof) {
		t.Fatal("VerifyInclusion returned false")
	}
	if proof.STH.TreeSize != latest.TreeSize || !bytes.Equal(proof.STH.RootHash, latest.RootHash) {
		t.Fatalf("proof STH = %+v, want latest %+v", proof.STH, latest)
	}
}

func TestEvidenceUsesLatestCoveringAnchoredSTH(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, store := newTestService(t)
	sths, err := svc.AppendBatchRoots(ctx, []model.BatchRoot{
		batchRoot("b1", 1),
		batchRoot("b2", 2),
		batchRoot("b3", 3),
	})
	if err != nil {
		t.Fatalf("AppendBatchRoots: %v", err)
	}
	anchored := sths[len(sths)-1]
	if err := store.EnqueueSTHAnchor(ctx, model.STHAnchorOutboxItem{
		SchemaVersion: model.SchemaSTHAnchorOutbox,
		TreeSize:      anchored.TreeSize,
		Status:        model.AnchorStatePending,
		SinkName:      anchor.NoopSinkName,
		STH:           anchored,
	}); err != nil {
		t.Fatalf("EnqueueSTHAnchor: %v", err)
	}
	result := model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		NodeID:           anchored.NodeID,
		LogID:            anchored.LogID,
		TreeSize:         anchored.TreeSize,
		SinkName:         anchor.NoopSinkName,
		AnchorID:         anchor.DeterministicNoopAnchorID(anchored),
		RootHash:         append([]byte(nil), anchored.RootHash...),
		STH:              anchored,
		PublishedAtUnixN: time.Unix(101, 0).UnixNano(),
	}
	if err := store.MarkSTHAnchorPublished(ctx, result); err != nil {
		t.Fatalf("MarkSTHAnchorPublished: %v", err)
	}
	for _, batchID := range []string{"b1", "b2", "b3"} {
		evidence, err := svc.Evidence(ctx, batchID)
		if err != nil {
			t.Fatalf("Evidence(%s): %v", batchID, err)
		}
		if evidence.AnchorResult == nil {
			t.Fatalf("Evidence(%s) anchor result is nil", batchID)
		}
		if evidence.GlobalProof.TreeSize != anchored.TreeSize || evidence.AnchorResult.TreeSize != anchored.TreeSize {
			t.Fatalf("Evidence(%s) tree sizes proof=%d anchor=%d, want %d", batchID, evidence.GlobalProof.TreeSize, evidence.AnchorResult.TreeSize, anchored.TreeSize)
		}
		if !VerifyInclusion(evidence.GlobalProof) {
			t.Fatalf("Evidence(%s) inclusion proof failed", batchID)
		}
	}

	latest, err := svc.AppendBatchRoot(ctx, batchRoot("b4", 4))
	if err != nil {
		t.Fatalf("AppendBatchRoot(b4): %v", err)
	}
	evidence, err := svc.Evidence(ctx, "b4")
	if err != nil {
		t.Fatalf("Evidence(b4): %v", err)
	}
	if evidence.AnchorResult != nil {
		t.Fatalf("Evidence(b4) anchor=%+v, want nil", evidence.AnchorResult)
	}
	if evidence.GlobalProof.TreeSize != latest.TreeSize || !VerifyInclusion(evidence.GlobalProof) {
		t.Fatalf("Evidence(b4) proof=%+v, want latest L4 proof", evidence.GlobalProof)
	}
}

func TestAppendBatchRootsPreservesSTHSequence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, store := newTestService(t)
	roots := []model.BatchRoot{batchRoot("batch-1", 1), batchRoot("batch-2", 2), batchRoot("batch-3", 3)}
	sths, err := svc.AppendBatchRoots(ctx, roots)
	if err != nil {
		t.Fatal(err)
	}
	if len(sths) != len(roots) {
		t.Fatalf("sths=%d want=%d", len(sths), len(roots))
	}
	for i := range sths {
		if sths[i].TreeSize != uint64(i+1) {
			t.Fatalf("sth[%d].tree_size=%d", i, sths[i].TreeSize)
		}
	}
	duplicate, err := svc.AppendBatchRoots(ctx, []model.BatchRoot{roots[1], batchRoot("batch-4", 4)})
	if err != nil {
		t.Fatal(err)
	}
	if duplicate[0].TreeSize != 2 || duplicate[1].TreeSize != 4 {
		t.Fatalf("duplicate sequence=%+v", duplicate)
	}
	leaves, err := store.ListGlobalLeaves(ctx)
	if err != nil || len(leaves) != 4 {
		t.Fatalf("leaves=%d err=%v", len(leaves), err)
	}
}

func TestAppendBatchRootRetriesConflictBeforeWinningStateIsVisible(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := proofstore.LocalStore{Root: t.TempDir()}
	conflictingStore := &conflictingBatchStore{Store: store}
	conflictingStore.conflict = func() error {
		return trusterr.New(trusterr.CodeFailedPrecondition, "global log append lost concurrent write")
	}
	svc := newTestServiceForStore(t, conflictingStore)

	sth, err := svc.AppendBatchRoot(ctx, batchRoot("eventual-winner", 1))
	if err != nil {
		t.Fatalf("AppendBatchRoot: %v", err)
	}
	if sth.TreeSize != 1 {
		t.Fatalf("STH tree_size = %d, want 1", sth.TreeSize)
	}
	leaf, found, err := store.GetGlobalLeafByBatchID(ctx, "eventual-winner")
	if err != nil || !found || leaf.LeafIndex != 0 {
		t.Fatalf("persisted leaf = %+v, found=%v err=%v", leaf, found, err)
	}
}

func TestAppendBatchRootReplansAfterConcurrentWriterAdvancesTree(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := proofstore.LocalStore{Root: t.TempDir()}
	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	newService := func(store Store) *Service {
		svc, err := New(Options{
			Store:      store,
			LogID:      "test-log",
			KeyID:      "test-key",
			PrivateKey: privateKey,
			Clock:      func() time.Time { return time.Unix(100, 0).UTC() },
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return svc
	}
	competitor := newService(store)
	conflictingStore := &conflictingBatchStore{Store: store}
	conflictingStore.conflict = func() error {
		if _, err := competitor.AppendBatchRoot(ctx, batchRoot("competitor", 1)); err != nil {
			return err
		}
		return trusterr.New(trusterr.CodeFailedPrecondition, "global log append is based on stale tree state")
	}
	svc := newService(conflictingStore)

	sth, err := svc.AppendBatchRoot(ctx, batchRoot("primary", 2))
	if err != nil {
		t.Fatalf("AppendBatchRoot: %v", err)
	}
	if sth.TreeSize != 2 {
		t.Fatalf("primary STH tree_size = %d, want 2", sth.TreeSize)
	}
	for batchID, wantIndex := range map[string]uint64{"competitor": 0, "primary": 1} {
		leaf, found, err := store.GetGlobalLeafByBatchID(ctx, batchID)
		if err != nil || !found {
			t.Fatalf("GetGlobalLeafByBatchID(%q) found=%v err=%v", batchID, found, err)
		}
		if leaf.LeafIndex != wantIndex {
			t.Fatalf("%s leaf_index = %d, want %d", batchID, leaf.LeafIndex, wantIndex)
		}
	}
	state, found, err := store.GetGlobalLogState(ctx)
	if err != nil || !found {
		t.Fatalf("GetGlobalLogState found=%v err=%v", found, err)
	}
	if state.TreeSize != 2 {
		t.Fatalf("state tree_size = %d, want 2", state.TreeSize)
	}
}

func TestAppendBatchRootRefusesPartialExistingLeafWithoutSTH(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, store := newTestService(t)

	root := batchRoot("partial-batch", 1)
	leaf := model.GlobalLogLeaf{
		SchemaVersion:      model.SchemaGlobalLogLeaf,
		BatchID:            root.BatchID,
		BatchRoot:          append([]byte(nil), root.BatchRoot...),
		BatchTreeSize:      root.TreeSize,
		BatchClosedAtUnixN: root.ClosedAtUnixN,
		LeafIndex:          0,
		AppendedAtUnixN:    time.Unix(100, 0).UTC().UnixNano(),
	}
	hash, err := HashLeaf(leaf)
	if err != nil {
		t.Fatalf("HashLeaf: %v", err)
	}
	leaf.LeafHash = hash
	if err := store.PutGlobalLeaf(ctx, leaf); err != nil {
		t.Fatalf("PutGlobalLeaf: %v", err)
	}
	if err := store.PutGlobalLogState(ctx, model.GlobalLogState{
		SchemaVersion:  model.SchemaGlobalLogState,
		TreeSize:       1,
		RootHash:       append([]byte(nil), hash...),
		Frontier:       [][]byte{append([]byte(nil), hash...)},
		UpdatedAtUnixN: time.Unix(101, 0).UTC().UnixNano(),
	}); err != nil {
		t.Fatalf("PutGlobalLogState: %v", err)
	}

	_, err = svc.AppendBatchRoot(ctx, root)
	if err == nil {
		t.Fatal("AppendBatchRoot succeeded for leaf without matching STH")
	}
	if got := trusterr.CodeOf(err); got != trusterr.CodeDataLoss {
		t.Fatalf("CodeOf(err) = %s, want %s; err=%v", got, trusterr.CodeDataLoss, err)
	}
	if _, ok, err := store.GetGlobalLeaf(ctx, 1); err != nil || ok {
		t.Fatalf("GetGlobalLeaf(1) ok=%v err=%v, want no duplicate append", ok, err)
	}
	state, ok, err := store.GetGlobalLogState(ctx)
	if err != nil || !ok {
		t.Fatalf("GetGlobalLogState ok=%v err=%v", ok, err)
	}
	if state.TreeSize != 1 {
		t.Fatalf("state tree_size = %d, want 1", state.TreeSize)
	}
}

func TestCompactHistoryPreservesInclusionProof(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, store := newTestService(t)
	for _, root := range []model.BatchRoot{
		batchRoot("b1", 1),
		batchRoot("b2", 2),
		batchRoot("b3", 3),
	} {
		if _, err := svc.AppendBatchRoot(ctx, root); err != nil {
			t.Fatalf("AppendBatchRoot: %v", err)
		}
	}
	before, err := svc.InclusionProof(ctx, "b1", 3)
	if err != nil {
		t.Fatalf("InclusionProof before compact: %v", err)
	}
	written, err := svc.CompactHistory(ctx, 2)
	if err != nil {
		t.Fatalf("CompactHistory: %v", err)
	}
	if written != 2 {
		t.Fatalf("tiles written = %d, want 2", written)
	}
	tiles, err := store.ListGlobalLogTiles(ctx)
	if err != nil {
		t.Fatalf("ListGlobalLogTiles: %v", err)
	}
	if len(tiles) != 2 {
		t.Fatalf("tiles = %d, want 2", len(tiles))
	}
	after, err := svc.InclusionProof(ctx, "b1", 3)
	if err != nil {
		t.Fatalf("InclusionProof after compact: %v", err)
	}
	if !bytes.Equal(before.LeafHash, after.LeafHash) || !bytes.Equal(before.STH.RootHash, after.STH.RootHash) {
		t.Fatalf("proof changed after compact: before=%+v after=%+v", before, after)
	}
}

func TestConsistencyProofMatchesSmallTreeReference(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, _ := newTestService(t)
	for i := 1; i <= 9; i++ {
		if _, err := svc.AppendBatchRoot(ctx, batchRoot("b"+string(rune('0'+i)), byte(i))); err != nil {
			t.Fatalf("AppendBatchRoot(%d): %v", i, err)
		}
	}
	leaves, err := leafHashesForReferenceTest(ctx, svc.store, 9)
	if err != nil {
		t.Fatalf("leafHashes: %v", err)
	}
	for from := uint64(1); from <= 9; from++ {
		got, err := svc.ConsistencyProof(ctx, from, 9)
		if err != nil {
			t.Fatalf("ConsistencyProof(%d,9): %v", from, err)
		}
		want, err := consistencyProof(leaves, from)
		if err != nil {
			t.Fatalf("reference consistencyProof(%d): %v", from, err)
		}
		if len(got.AuditPath) != len(want) {
			t.Fatalf("path len for from=%d got=%d want=%d", from, len(got.AuditPath), len(want))
		}
		for i := range want {
			if !bytes.Equal(got.AuditPath[i], want[i]) {
				t.Fatalf("path[%d] for from=%d changed", i, from)
			}
		}
	}
}

func leafHashesForReferenceTest(ctx context.Context, store Store, treeSize uint64) ([][]byte, error) {
	hashes := make([][]byte, treeSize)
	for i := uint64(0); i < treeSize; i++ {
		leaf, ok, err := store.GetGlobalLeaf(ctx, i)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, trusterr.New(trusterr.CodeNotFound, "requested STH is beyond global log size")
		}
		hashes[i] = append([]byte(nil), leaf.LeafHash...)
	}
	return hashes, nil
}

func TestConsistencyProofUsesIndexedNodesInsteadOfFullLeafScan(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const treeSize = 512
	fixture := newGlobalLogBenchFixture(t, treeSize)

	counting := newCountingGlobalStore(fixture.store)
	reader, err := NewReader(counting)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	proof, err := reader.ConsistencyProof(ctx, 256, treeSize)
	if err != nil {
		t.Fatalf("ConsistencyProof: %v", err)
	}
	if len(proof.AuditPath) == 0 {
		t.Fatal("expected non-empty consistency path")
	}
	counts := counting.Snapshot()
	if got := counts.TotalProofTreeReads(); got > 16 {
		t.Fatalf("ConsistencyProof read %d proof tree nodes/leaves for tree_size=%d; want indexed-node path, not a full scan", got, treeSize)
	}
}

func BenchmarkConsistencyProofLargeTree(b *testing.B) {
	ctx := context.Background()
	treeSize := benchmarkGlobalLogTreeSize(b)
	fixture := newGlobalLogBenchFixture(b, treeSize)
	counting := newCountingGlobalStore(fixture.store)
	reader := mustNewReader(b, counting)
	from := treeSize / 2
	runGlobalLogBenchmark(b, counting, func() {
		if _, err := reader.ConsistencyProof(ctx, from, treeSize); err != nil {
			b.Fatalf("ConsistencyProof: %v", err)
		}
	})
}
