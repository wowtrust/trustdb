// Package proofstoretest exports a conformance suite used by every
// proofstore backend to prove it round-trips identical bytes and iteration
// order. Keeping the suite in its own package lets the file-based and
// Pebble-based tests share the same assertions without an import cycle.
package proofstoretest

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/ryan-wong-coder/trustdb/internal/anchorschedule"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

// Factory lazily builds a fresh Store for each sub-test. Returning a
// closer (rather than relying on t.Cleanup) keeps the helper backend-
// agnostic even when the caller wants to drive the lifecycle manually.
type Factory func(t *testing.T) (proofstore.Store, func())

// RunConformance exercises every contract a proofstore backend must
// honour. Each sub-test uses its own Store instance so backends that
// hold file locks (Pebble) don't deadlock themselves.
func RunConformance(t *testing.T, newStore Factory) {
	t.Helper()
	t.Run("BundleRoundTrip", func(t *testing.T) { testBundleRoundTrip(t, newStore) })
	t.Run("BatchArtifactsOptional", func(t *testing.T) { testBatchArtifactsOptional(t, newStore) })
	t.Run("BundleNotFound", func(t *testing.T) { testBundleNotFound(t, newStore) })
	t.Run("BundleOverwrite", func(t *testing.T) { testBundleOverwrite(t, newStore) })
	t.Run("RecordIndexListAndFilters", func(t *testing.T) { testRecordIndexListAndFilters(t, newStore) })
	t.Run("RecordIndexProofLevelPromotes", func(t *testing.T) { testRecordIndexProofLevelPromotes(t, newStore) })
	t.Run("ManifestRoundTrip", func(t *testing.T) { testManifestRoundTrip(t, newStore) })
	t.Run("ManifestListIsSorted", func(t *testing.T) { testManifestListIsSorted(t, newStore) })
	t.Run("ManifestListAfterPaginates", func(t *testing.T) { testManifestListAfterPaginates(t, newStore) })
	t.Run("RootListIsReverseChrono", func(t *testing.T) { testRootListIsReverseChrono(t, newStore) })
	t.Run("RootListAcceptsHugeLimit", func(t *testing.T) { testRootListAcceptsHugeLimit(t, newStore) })
	t.Run("LatestRootSelectsNewest", func(t *testing.T) { testLatestRoot(t, newStore) })
	t.Run("RootListPagePaginates", func(t *testing.T) { testRootListPagePaginates(t, newStore) })
	t.Run("BatchTreeArtifactsRoundTrip", func(t *testing.T) { testBatchTreeArtifactsRoundTrip(t, newStore) })
	t.Run("CheckpointRoundTrip", func(t *testing.T) { testCheckpointRoundTrip(t, newStore) })
	t.Run("CheckpointMissing", func(t *testing.T) { testCheckpointMissing(t, newStore) })
	t.Run("ConcurrentPutBundle", func(t *testing.T) { testConcurrentPutBundle(t, newStore) })
	t.Run("GlobalLogRoundTrip", func(t *testing.T) { testGlobalLogRoundTrip(t, newStore) })
	t.Run("GlobalLogListPendingRespectsBackoff", func(t *testing.T) { testGlobalLogListPendingRespectsBackoff(t, newStore) })
	t.Run("GlobalLogAppendCommitRoundTrip", func(t *testing.T) { testGlobalLogAppendCommitRoundTrip(t, newStore) })
	t.Run("GlobalLogPublishedBatchWithAnchorsOptional", func(t *testing.T) { testGlobalLogPublishedBatchWithAnchorsOptional(t, newStore) })
	t.Run("GlobalLogAppendCommitRejectsInvalidNodeWithoutPartialWrite", func(t *testing.T) {
		testGlobalLogAppendCommitRejectsInvalidNodeWithoutPartialWrite(t, newStore)
	})
	t.Run("GlobalLogPagedStateRoundTrip", func(t *testing.T) { testGlobalLogPagedStateRoundTrip(t, newStore) })
	t.Run("GlobalLeafListPagePaginates", func(t *testing.T) { testGlobalLeafListPagePaginates(t, newStore) })
	t.Run("GlobalLogTileRoundTrip", func(t *testing.T) { testGlobalLogTileRoundTrip(t, newStore) })
	t.Run("GlobalLogTileListAfterPaginates", func(t *testing.T) { testGlobalLogTileListAfterPaginates(t, newStore) })
	t.Run("STHAnchorEnqueueIsIdempotent", func(t *testing.T) { testSTHAnchorEnqueueIsIdempotent(t, newStore) })
	t.Run("STHAnchorBatchEnqueueOptional", func(t *testing.T) { testSTHAnchorBatchEnqueueOptional(t, newStore) })
	t.Run("SignedTreeHeadListPagePaginates", func(t *testing.T) { testSignedTreeHeadListPagePaginates(t, newStore) })
	t.Run("STHAnchorListPagePaginates", func(t *testing.T) { testSTHAnchorListPagePaginates(t, newStore) })
	t.Run("STHAnchorListAfterPaginates", func(t *testing.T) { testSTHAnchorListAfterPaginates(t, newStore) })
	t.Run("STHAnchorListPendingRespectsBackoff", func(t *testing.T) { testSTHAnchorListPendingRespectsBackoff(t, newStore) })
	t.Run("STHAnchorListPendingIsCommitOrdered", func(t *testing.T) { testSTHAnchorListPendingIsCommitOrdered(t, newStore) })
	t.Run("STHAnchorListPublishedFiltersTerminalOnly", func(t *testing.T) { testSTHAnchorListPublishedFilters(t, newStore) })
	t.Run("STHAnchorMarkPublished", func(t *testing.T) { testSTHAnchorMarkPublished(t, newStore) })
	t.Run("LatestSTHAnchorResultIsMonotonic", func(t *testing.T) { testLatestSTHAnchorResultIsMonotonic(t, newStore) })
	t.Run("STHAnchorScheduleStateMachineOptional", func(t *testing.T) { testSTHAnchorScheduleStateMachineOptional(t, newStore) })
	t.Run("STHAnchorMarkFailed", func(t *testing.T) { testSTHAnchorMarkFailed(t, newStore) })
	t.Run("STHAnchorRescheduleKeepsPending", func(t *testing.T) { testSTHAnchorRescheduleKeepsPending(t, newStore) })
	t.Run("STHAnchorMissing", func(t *testing.T) { testSTHAnchorMissing(t, newStore) })
}

func testBatchArtifactsOptional(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	writer, ok := store.(proofstore.BatchArtifactWriter)
	if !ok {
		t.Skip("store does not implement BatchArtifactWriter")
	}
	ctx := context.Background()
	bundles := []model.ProofBundle{
		recordBundle("bulk-rec-1", "tenant-a", "client-a", "bulk-batch", 100),
		recordBundle("bulk-rec-2", "tenant-a", "client-b", "bulk-batch", 200),
	}
	root := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       "bulk-batch",
		BatchRoot:     []byte{1, 2, 3},
		TreeSize:      uint64(len(bundles)),
		ClosedAtUnixN: 500,
	}
	for i := 0; i < 2; i++ {
		if err := writer.PutBatchArtifacts(ctx, bundles, root); err != nil {
			t.Fatalf("PutBatchArtifacts attempt %d: %v", i+1, err)
		}
	}
	for _, bundle := range bundles {
		got, err := store.GetBundle(ctx, bundle.RecordID)
		if err != nil {
			t.Fatalf("GetBundle %s: %v", bundle.RecordID, err)
		}
		if got.RecordID != bundle.RecordID {
			t.Fatalf("GetBundle %s = %+v", bundle.RecordID, got)
		}
		idx, ok, err := store.GetRecordIndex(ctx, bundle.RecordID)
		if err != nil || !ok {
			t.Fatalf("GetRecordIndex %s ok=%v err=%v", bundle.RecordID, ok, err)
		}
		if idx.BatchID != root.BatchID || model.RecordIndexProofLevel(idx) != "L3" {
			t.Fatalf("RecordIndex %s = %+v", bundle.RecordID, idx)
		}
	}
	gotRoot, err := store.LatestRoot(ctx)
	if err != nil {
		t.Fatalf("LatestRoot: %v", err)
	}
	if gotRoot.BatchID != root.BatchID || gotRoot.TreeSize != root.TreeSize {
		t.Fatalf("LatestRoot = %+v, want %+v", gotRoot, root)
	}
}

func testBundleRoundTrip(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	bundle := model.ProofBundle{SchemaVersion: model.SchemaProofBundle, RecordID: "rec/1"}
	if err := store.PutBundle(ctx, bundle); err != nil {
		t.Fatalf("PutBundle: %v", err)
	}
	got, err := store.GetBundle(ctx, "rec/1")
	if err != nil {
		t.Fatalf("GetBundle: %v", err)
	}
	if got.RecordID != bundle.RecordID {
		t.Fatalf("GetBundle() = %+v, want %+v", got, bundle)
	}
}

func testBundleNotFound(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()

	_, err := store.GetBundle(context.Background(), "no-such")
	if err == nil {
		t.Fatalf("GetBundle() = nil, want NotFound")
	}
	if got := trusterr.CodeOf(err); got != trusterr.CodeNotFound {
		t.Fatalf("CodeOf(err) = %s, want %s", got, trusterr.CodeNotFound)
	}
}

func testBundleOverwrite(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	first := model.ProofBundle{SchemaVersion: model.SchemaProofBundle, RecordID: "rec-1"}
	if err := store.PutBundle(ctx, first); err != nil {
		t.Fatalf("first PutBundle: %v", err)
	}
	second := model.ProofBundle{SchemaVersion: "v2", RecordID: "rec-1"}
	if err := store.PutBundle(ctx, second); err != nil {
		t.Fatalf("second PutBundle: %v", err)
	}
	got, err := store.GetBundle(ctx, "rec-1")
	if err != nil {
		t.Fatalf("GetBundle: %v", err)
	}
	if got.SchemaVersion != "v2" {
		t.Fatalf("overwrite did not stick: %+v", got)
	}
}

func testRecordIndexListAndFilters(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	for _, bundle := range []model.ProofBundle{
		recordBundle("rec-1", "tenant-a", "client-a", "batch-1", 100),
		recordBundle("rec-2", "tenant-a", "client-b", "batch-1", 200),
		recordBundle("rec-3", "tenant-b", "client-b", "batch-2", 300),
	} {
		if err := store.PutBundle(ctx, bundle); err != nil {
			t.Fatalf("PutBundle %s: %v", bundle.RecordID, err)
		}
	}
	idx, ok, err := store.GetRecordIndex(ctx, "rec-2")
	if err != nil || !ok {
		t.Fatalf("GetRecordIndex ok=%v err=%v", ok, err)
	}
	if idx.BatchID != "batch-1" || idx.ClientID != "client-b" {
		t.Fatalf("GetRecordIndex = %+v", idx)
	}

	page, err := store.ListRecordIndexes(ctx, model.RecordListOptions{Limit: 2})
	if err != nil {
		t.Fatalf("ListRecordIndexes page: %v", err)
	}
	if len(page) != 2 || page[0].RecordID != "rec-3" || page[1].RecordID != "rec-2" {
		t.Fatalf("default page = %+v", page)
	}
	next, err := store.ListRecordIndexes(ctx, model.RecordListOptions{
		Limit:                2,
		AfterReceivedAtUnixN: page[1].ReceivedAtUnixN,
		AfterRecordID:        page[1].RecordID,
	})
	if err != nil {
		t.Fatalf("ListRecordIndexes next: %v", err)
	}
	if len(next) != 1 || next[0].RecordID != "rec-1" {
		t.Fatalf("next page = %+v", next)
	}
	byBatch, err := store.ListRecordIndexes(ctx, model.RecordListOptions{BatchID: "batch-1", Limit: 10, Direction: model.RecordListDirectionAsc})
	if err != nil {
		t.Fatalf("ListRecordIndexes batch: %v", err)
	}
	if len(byBatch) != 2 || byBatch[0].RecordID != "rec-1" || byBatch[1].RecordID != "rec-2" {
		t.Fatalf("batch page = %+v", byBatch)
	}
	byTenant, err := store.ListRecordIndexes(ctx, model.RecordListOptions{TenantID: "tenant-a", Limit: 10})
	if err != nil {
		t.Fatalf("ListRecordIndexes tenant: %v", err)
	}
	if len(byTenant) != 2 {
		t.Fatalf("tenant page = %+v", byTenant)
	}
	byHash, err := store.ListRecordIndexes(ctx, model.RecordListOptions{ContentHash: []byte("rec-2"), Limit: 10})
	if err != nil {
		t.Fatalf("ListRecordIndexes hash: %v", err)
	}
	if len(byHash) != 1 || byHash[0].RecordID != "rec-2" {
		t.Fatalf("hash page = %+v", byHash)
	}
	byQuery, err := store.ListRecordIndexes(ctx, model.RecordListOptions{Query: "rec-2", Limit: 10})
	if err != nil {
		t.Fatalf("ListRecordIndexes query: %v", err)
	}
	if len(byQuery) != 1 || byQuery[0].RecordID != "rec-2" {
		t.Fatalf("query page = %+v", byQuery)
	}
	byRange, err := store.ListRecordIndexes(ctx, model.RecordListOptions{ReceivedFromUnixN: 150, ReceivedToUnixN: 250, Limit: 10})
	if err != nil {
		t.Fatalf("ListRecordIndexes range: %v", err)
	}
	if len(byRange) != 1 || byRange[0].RecordID != "rec-2" {
		t.Fatalf("range page = %+v", byRange)
	}
}

func testRecordIndexProofLevelPromotes(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	bundle := recordBundle("rec-1", "tenant-a", "client-a", "batch-1", 100)
	if err := store.PutBundle(ctx, bundle); err != nil {
		t.Fatalf("PutBundle: %v", err)
	}
	if err := store.PutGlobalLeaf(ctx, model.GlobalLogLeaf{
		SchemaVersion: model.SchemaGlobalLogLeaf,
		BatchID:       "batch-1",
		BatchRoot:     []byte{1},
		LeafIndex:     0,
	}); err != nil {
		t.Fatalf("PutGlobalLeaf: %v", err)
	}
	sth := model.SignedTreeHead{SchemaVersion: model.SchemaSignedTreeHead, TreeSize: 1, RootHash: []byte{1}}
	if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{
		SchemaVersion: model.SchemaGlobalLogOutbox,
		BatchID:       "batch-1",
		BatchRoot:     model.BatchRoot{SchemaVersion: model.SchemaBatchRoot, BatchID: "batch-1", BatchRoot: []byte{1}, TreeSize: 1},
		Status:        model.AnchorStatePending,
	}); err != nil {
		t.Fatalf("EnqueueGlobalLog: %v", err)
	}
	if err := store.MarkGlobalLogPublished(ctx, "batch-1", sth); err != nil {
		t.Fatalf("MarkGlobalLogPublished: %v", err)
	}
	idx, ok, err := store.GetRecordIndex(ctx, "rec-1")
	if err != nil || !ok {
		t.Fatalf("GetRecordIndex L4 ok=%v err=%v", ok, err)
	}
	if level := model.RecordIndexProofLevel(idx); level != "L4" {
		t.Fatalf("proof level after global publish = %s, want L4", level)
	}
	if err := store.EnqueueSTHAnchor(ctx, sthAnchorItem(1, "ots", 100)); err != nil {
		t.Fatalf("EnqueueSTHAnchor: %v", err)
	}
	if err := store.MarkSTHAnchorPublished(ctx, sthAnchorResult(1, "ots", "anchor-1")); err != nil {
		t.Fatalf("MarkSTHAnchorPublished: %v", err)
	}
	idx, ok, err = store.GetRecordIndex(ctx, "rec-1")
	if err != nil || !ok {
		t.Fatalf("GetRecordIndex L5 ok=%v err=%v", ok, err)
	}
	if level := model.RecordIndexProofLevel(idx); level != "L5" {
		t.Fatalf("proof level after anchor publish = %s, want L5", level)
	}
	byLevel, err := store.ListRecordIndexes(ctx, model.RecordListOptions{ProofLevel: "L5", Limit: 10})
	if err != nil {
		t.Fatalf("ListRecordIndexes level: %v", err)
	}
	if len(byLevel) != 1 || byLevel[0].RecordID != "rec-1" {
		t.Fatalf("ListRecordIndexes level page = %+v", byLevel)
	}
}

func testManifestRoundTrip(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	manifest := model.BatchManifest{
		SchemaVersion: model.SchemaBatchManifest,
		BatchID:       "batch-1",
		State:         model.BatchStatePrepared,
		RecordIDs:     []string{"a", "b"},
		TreeSize:      2,
	}
	if err := store.PutManifest(ctx, manifest); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	got, err := store.GetManifest(ctx, "batch-1")
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if got.BatchID != manifest.BatchID || len(got.RecordIDs) != 2 {
		t.Fatalf("GetManifest() = %+v", got)
	}
}

func testManifestListIsSorted(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	ids := []string{"batch-3", "batch-1", "batch-2"}
	for _, id := range ids {
		if err := store.PutManifest(ctx, model.BatchManifest{
			SchemaVersion: model.SchemaBatchManifest,
			BatchID:       id,
			State:         model.BatchStatePrepared,
		}); err != nil {
			t.Fatalf("PutManifest %s: %v", id, err)
		}
	}
	got, err := store.ListManifests(ctx)
	if err != nil {
		t.Fatalf("ListManifests: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ListManifests len = %d, want 3", len(got))
	}
	for i, want := range []string{"batch-1", "batch-2", "batch-3"} {
		if got[i].BatchID != want {
			t.Fatalf("ListManifests[%d] = %s, want %s", i, got[i].BatchID, want)
		}
	}
}

func testManifestListAfterPaginates(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	for _, id := range []string{"batch-3", "batch-1", "batch-2"} {
		if err := store.PutManifest(ctx, model.BatchManifest{
			SchemaVersion: model.SchemaBatchManifest,
			BatchID:       id,
			State:         model.BatchStatePrepared,
		}); err != nil {
			t.Fatalf("PutManifest %s: %v", id, err)
		}
	}
	first, err := store.ListManifestsAfter(ctx, "", 2)
	if err != nil {
		t.Fatalf("ListManifestsAfter first: %v", err)
	}
	if len(first) != 2 || first[0].BatchID != "batch-1" || first[1].BatchID != "batch-2" {
		t.Fatalf("first page = %+v", first)
	}
	next, err := store.ListManifestsAfter(ctx, first[len(first)-1].BatchID, 2)
	if err != nil {
		t.Fatalf("ListManifestsAfter next: %v", err)
	}
	if len(next) != 1 || next[0].BatchID != "batch-3" {
		t.Fatalf("next page = %+v", next)
	}
}

func testRootListIsReverseChrono(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	for i, ts := range []int64{100, 200, 150} {
		if err := store.PutRoot(ctx, model.BatchRoot{
			SchemaVersion: model.SchemaBatchRoot,
			BatchID:       []string{"a", "b", "c"}[i],
			BatchRoot:     []byte{byte(i)},
			ClosedAtUnixN: ts,
		}); err != nil {
			t.Fatalf("PutRoot %d: %v", i, err)
		}
	}
	roots, err := store.ListRoots(ctx, 10)
	if err != nil {
		t.Fatalf("ListRoots: %v", err)
	}
	if len(roots) != 3 {
		t.Fatalf("ListRoots len = %d, want 3", len(roots))
	}
	for i, want := range []int64{200, 150, 100} {
		if roots[i].ClosedAtUnixN != want {
			t.Fatalf("ListRoots[%d] = %d, want %d", i, roots[i].ClosedAtUnixN, want)
		}
	}
}

func testRootListAcceptsHugeLimit(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	const hugeLimit = int(^uint(0) >> 1)
	roots, err := store.ListRoots(ctx, hugeLimit)
	if err != nil {
		t.Fatalf("ListRoots empty store with huge limit: %v", err)
	}
	if len(roots) != 0 {
		t.Fatalf("ListRoots empty store len = %d, want 0", len(roots))
	}
	if err := store.PutRoot(ctx, model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       "batch-huge-limit",
		BatchRoot:     []byte{1, 2, 3},
		ClosedAtUnixN: 123,
	}); err != nil {
		t.Fatalf("PutRoot: %v", err)
	}
	roots, err = store.ListRoots(ctx, hugeLimit)
	if err != nil {
		t.Fatalf("ListRoots populated store with huge limit: %v", err)
	}
	if len(roots) != 1 || roots[0].BatchID != "batch-huge-limit" {
		t.Fatalf("ListRoots huge limit = %+v, want batch-huge-limit", roots)
	}
}

func testLatestRoot(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	for i, ts := range []int64{100, 300, 200} {
		if err := store.PutRoot(ctx, model.BatchRoot{
			SchemaVersion: model.SchemaBatchRoot,
			BatchID:       []string{"a", "b", "c"}[i],
			ClosedAtUnixN: ts,
		}); err != nil {
			t.Fatalf("PutRoot %d: %v", i, err)
		}
	}
	got, err := store.LatestRoot(ctx)
	if err != nil {
		t.Fatalf("LatestRoot: %v", err)
	}
	if got.ClosedAtUnixN != 300 {
		t.Fatalf("LatestRoot ts = %d, want 300", got.ClosedAtUnixN)
	}
}

func testRootListPagePaginates(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	for _, root := range []model.BatchRoot{
		{SchemaVersion: model.SchemaBatchRoot, BatchID: "batch-1", ClosedAtUnixN: 100},
		{SchemaVersion: model.SchemaBatchRoot, BatchID: "batch-2", ClosedAtUnixN: 200},
		{SchemaVersion: model.SchemaBatchRoot, BatchID: "batch-3", ClosedAtUnixN: 300},
	} {
		if err := store.PutRoot(ctx, root); err != nil {
			t.Fatalf("PutRoot %s: %v", root.BatchID, err)
		}
	}
	first, err := store.ListRootsPage(ctx, model.RootListOptions{Limit: 2, Direction: model.RecordListDirectionDesc})
	if err != nil {
		t.Fatalf("ListRootsPage first: %v", err)
	}
	if len(first) != 2 || first[0].BatchID != "batch-3" || first[1].BatchID != "batch-2" {
		t.Fatalf("first roots page = %+v", first)
	}
	next, err := store.ListRootsPage(ctx, model.RootListOptions{
		Limit:              2,
		Direction:          model.RecordListDirectionDesc,
		AfterClosedAtUnixN: first[1].ClosedAtUnixN,
		AfterBatchID:       first[1].BatchID,
	})
	if err != nil {
		t.Fatalf("ListRootsPage next: %v", err)
	}
	if len(next) != 1 || next[0].BatchID != "batch-1" {
		t.Fatalf("next roots page = %+v", next)
	}
}

func testBatchTreeArtifactsRoundTrip(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	leaves := []model.BatchTreeLeaf{
		{SchemaVersion: model.SchemaBatchTreeLeaf, BatchID: "batch-tree", RecordID: "rec-0", LeafIndex: 0, LeafHash: []byte{1}},
		{SchemaVersion: model.SchemaBatchTreeLeaf, BatchID: "batch-tree", RecordID: "rec-1", LeafIndex: 1, LeafHash: []byte{2}},
		{SchemaVersion: model.SchemaBatchTreeLeaf, BatchID: "batch-tree", RecordID: "rec-2", LeafIndex: 2, LeafHash: []byte{3}},
	}
	nodes := []model.BatchTreeNode{
		{SchemaVersion: model.SchemaBatchTreeNode, BatchID: "batch-tree", Level: 0, StartIndex: 0, Width: 1, Hash: []byte{1}},
		{SchemaVersion: model.SchemaBatchTreeNode, BatchID: "batch-tree", Level: 0, StartIndex: 1, Width: 1, Hash: []byte{2}},
		{SchemaVersion: model.SchemaBatchTreeNode, BatchID: "batch-tree", Level: 1, StartIndex: 0, Width: 2, Hash: []byte{4}},
		{SchemaVersion: model.SchemaBatchTreeNode, BatchID: "batch-tree", Level: 2, StartIndex: 0, Width: 3, Hash: []byte{5}},
	}
	if err := store.PutBatchTreeArtifacts(ctx, leaves, nodes); err != nil {
		t.Fatalf("PutBatchTreeArtifacts: %v", err)
	}
	firstLeaves, err := store.ListBatchTreeLeaves(ctx, model.BatchTreeLeafListOptions{BatchID: "batch-tree", Limit: 2})
	if err != nil {
		t.Fatalf("ListBatchTreeLeaves first: %v", err)
	}
	if len(firstLeaves) != 2 || firstLeaves[0].RecordID != "rec-0" || firstLeaves[1].RecordID != "rec-1" {
		t.Fatalf("first leaves page = %+v", firstLeaves)
	}
	nextLeaves, err := store.ListBatchTreeLeaves(ctx, model.BatchTreeLeafListOptions{BatchID: "batch-tree", Limit: 2, AfterLeafIndex: firstLeaves[1].LeafIndex, HasAfter: true})
	if err != nil {
		t.Fatalf("ListBatchTreeLeaves next: %v", err)
	}
	if len(nextLeaves) != 1 || nextLeaves[0].RecordID != "rec-2" {
		t.Fatalf("next leaves page = %+v", nextLeaves)
	}
	levelZero, err := store.ListBatchTreeNodes(ctx, model.BatchTreeNodeListOptions{BatchID: "batch-tree", Level: 0, Limit: 10})
	if err != nil {
		t.Fatalf("ListBatchTreeNodes level0: %v", err)
	}
	if len(levelZero) != 3 || levelZero[0].StartIndex != 0 || levelZero[1].StartIndex != 1 || levelZero[2].StartIndex != 2 {
		t.Fatalf("level0 nodes = %+v", levelZero)
	}
	levelOne, err := store.ListBatchTreeNodes(ctx, model.BatchTreeNodeListOptions{BatchID: "batch-tree", Level: 1, StartIndex: 0, Limit: 1})
	if err != nil {
		t.Fatalf("ListBatchTreeNodes level1: %v", err)
	}
	if len(levelOne) != 1 || levelOne[0].Width != 2 {
		t.Fatalf("level1 nodes = %+v", levelOne)
	}
}

func testCheckpointRoundTrip(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	cp := model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpoint,
		SegmentID:     7,
		LastSequence:  101,
		LastOffset:    512,
		BatchID:       "batch-7",
	}
	if err := store.PutCheckpoint(ctx, cp); err != nil {
		t.Fatalf("PutCheckpoint: %v", err)
	}
	got, ok, err := store.GetCheckpoint(ctx)
	if err != nil || !ok {
		t.Fatalf("GetCheckpoint ok=%v err=%v", ok, err)
	}
	if got.SegmentID != cp.SegmentID || got.LastSequence != cp.LastSequence {
		t.Fatalf("GetCheckpoint() = %+v, want %+v", got, cp)
	}
}

func testCheckpointMissing(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()

	_, ok, err := store.GetCheckpoint(context.Background())
	if err != nil {
		t.Fatalf("GetCheckpoint: %v", err)
	}
	if ok {
		t.Fatalf("GetCheckpoint ok = true, want false for fresh store")
	}
}

// testConcurrentPutBundle hammers a single store with N goroutines each
// putting a unique bundle, then asserts every bundle is retrievable. For
// the Pebble backend this also transitively verifies that the underlying
// DB handle survives heavy concurrent Set traffic without corruption.
func testConcurrentPutBundle(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	const workers = 16
	const perWorker = 32
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				id := idForWorker(worker, j)
				if err := store.PutBundle(ctx, model.ProofBundle{
					SchemaVersion: model.SchemaProofBundle,
					RecordID:      id,
				}); err != nil {
					t.Errorf("PutBundle %s: %v", id, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < workers; i++ {
		for j := 0; j < perWorker; j++ {
			id := idForWorker(i, j)
			if _, err := store.GetBundle(ctx, id); err != nil {
				t.Fatalf("GetBundle %s: %v", id, err)
			}
		}
	}
}

func testGlobalLogRoundTrip(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	leaf := model.GlobalLogLeaf{
		SchemaVersion:      model.SchemaGlobalLogLeaf,
		BatchID:            "batch-1",
		BatchRoot:          []byte{1, 2, 3},
		BatchTreeSize:      3,
		BatchClosedAtUnixN: 99,
		LeafIndex:          0,
		LeafHash:           []byte{9},
		AppendedAtUnixN:    100,
	}
	if err := store.PutGlobalLeaf(ctx, leaf); err != nil {
		t.Fatalf("PutGlobalLeaf: %v", err)
	}
	byIndex, ok, err := store.GetGlobalLeaf(ctx, 0)
	if err != nil || !ok {
		t.Fatalf("GetGlobalLeaf ok=%v err=%v", ok, err)
	}
	if byIndex.BatchID != leaf.BatchID {
		t.Fatalf("GetGlobalLeaf() = %+v", byIndex)
	}
	byBatch, ok, err := store.GetGlobalLeafByBatchID(ctx, "batch-1")
	if err != nil || !ok {
		t.Fatalf("GetGlobalLeafByBatchID ok=%v err=%v", ok, err)
	}
	if byBatch.LeafIndex != 0 {
		t.Fatalf("GetGlobalLeafByBatchID leaf_index = %d, want 0", byBatch.LeafIndex)
	}
	leaves, err := store.ListGlobalLeaves(ctx)
	if err != nil {
		t.Fatalf("ListGlobalLeaves: %v", err)
	}
	if len(leaves) != 1 || leaves[0].BatchID != "batch-1" {
		t.Fatalf("ListGlobalLeaves = %+v", leaves)
	}
	sth := model.SignedTreeHead{SchemaVersion: model.SchemaSignedTreeHead, TreeSize: 1, RootHash: []byte{8}, TimestampUnixN: 123}
	if err := store.PutSignedTreeHead(ctx, sth); err != nil {
		t.Fatalf("PutSignedTreeHead: %v", err)
	}
	gotSTH, ok, err := store.GetSignedTreeHead(ctx, 1)
	if err != nil || !ok {
		t.Fatalf("GetSignedTreeHead ok=%v err=%v", ok, err)
	}
	if gotSTH.TreeSize != 1 {
		t.Fatalf("GetSignedTreeHead() = %+v", gotSTH)
	}
	latest, ok, err := store.LatestSignedTreeHead(ctx)
	if err != nil || !ok {
		t.Fatalf("LatestSignedTreeHead ok=%v err=%v", ok, err)
	}
	if latest.TreeSize != 1 {
		t.Fatalf("LatestSignedTreeHead tree_size = %d, want 1", latest.TreeSize)
	}
}

func testGlobalLogListPendingRespectsBackoff(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	for _, item := range []model.GlobalLogOutboxItem{
		{BatchID: "batch-ready", EnqueuedAtUnixN: 100, NextAttemptUnixN: 100},
		{BatchID: "batch-future", EnqueuedAtUnixN: 200, NextAttemptUnixN: 200},
	} {
		if err := store.EnqueueGlobalLog(ctx, item); err != nil {
			t.Fatalf("EnqueueGlobalLog %s: %v", item.BatchID, err)
		}
	}
	empty, err := store.ListPendingGlobalLog(ctx, 50, 10)
	if err != nil {
		t.Fatalf("ListPendingGlobalLog before backoff: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("ListPendingGlobalLog before backoff = %+v, want empty", empty)
	}
	ready, err := store.ListPendingGlobalLog(ctx, 150, 10)
	if err != nil {
		t.Fatalf("ListPendingGlobalLog ready: %v", err)
	}
	if len(ready) != 1 || ready[0].BatchID != "batch-ready" {
		t.Fatalf("ListPendingGlobalLog ready = %+v, want batch-ready", ready)
	}
	all, err := store.ListPendingGlobalLog(ctx, 300, 10)
	if err != nil {
		t.Fatalf("ListPendingGlobalLog all: %v", err)
	}
	if len(all) != 2 || all[0].BatchID != "batch-ready" || all[1].BatchID != "batch-future" {
		t.Fatalf("ListPendingGlobalLog all = %+v", all)
	}
}

func testGlobalLogAppendCommitRoundTrip(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	leaf := model.GlobalLogLeaf{
		SchemaVersion:      model.SchemaGlobalLogLeaf,
		BatchID:            "batch-append-1",
		BatchRoot:          []byte{1, 2, 3},
		BatchTreeSize:      3,
		BatchClosedAtUnixN: 99,
		LeafIndex:          0,
		LeafHash:           []byte{9},
		AppendedAtUnixN:    100,
	}
	node := model.GlobalLogNode{
		SchemaVersion:  model.SchemaGlobalLogNode,
		Level:          0,
		StartIndex:     0,
		Width:          1,
		Hash:           []byte{9},
		CreatedAtUnixN: 101,
	}
	state := model.GlobalLogState{
		SchemaVersion:  model.SchemaGlobalLogState,
		TreeSize:       1,
		RootHash:       []byte{9},
		Frontier:       [][]byte{{9}},
		UpdatedAtUnixN: 102,
	}
	sth := model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeSize:       1,
		RootHash:       []byte{9},
		TimestampUnixN: 103,
	}
	if err := store.CommitGlobalLogAppend(ctx, model.GlobalLogAppend{
		Leaf:  leaf,
		Nodes: []model.GlobalLogNode{node},
		State: state,
		STH:   sth,
	}); err != nil {
		t.Fatalf("CommitGlobalLogAppend: %v", err)
	}

	byBatch, ok, err := store.GetGlobalLeafByBatchID(ctx, leaf.BatchID)
	if err != nil || !ok {
		t.Fatalf("GetGlobalLeafByBatchID ok=%v err=%v", ok, err)
	}
	if byBatch.LeafIndex != leaf.LeafIndex {
		t.Fatalf("batch index leaf_index = %d, want %d", byBatch.LeafIndex, leaf.LeafIndex)
	}
	gotNode, ok, err := store.GetGlobalLogNode(ctx, node.Level, node.StartIndex)
	if err != nil || !ok {
		t.Fatalf("GetGlobalLogNode ok=%v err=%v", ok, err)
	}
	if gotNode.Width != node.Width {
		t.Fatalf("GetGlobalLogNode width = %d, want %d", gotNode.Width, node.Width)
	}
	gotState, ok, err := store.GetGlobalLogState(ctx)
	if err != nil || !ok {
		t.Fatalf("GetGlobalLogState ok=%v err=%v", ok, err)
	}
	if gotState.TreeSize != state.TreeSize {
		t.Fatalf("state tree_size = %d, want %d", gotState.TreeSize, state.TreeSize)
	}
	gotSTH, ok, err := store.GetSignedTreeHead(ctx, sth.TreeSize)
	if err != nil || !ok {
		t.Fatalf("GetSignedTreeHead ok=%v err=%v", ok, err)
	}
	if gotSTH.TreeSize != sth.TreeSize {
		t.Fatalf("sth tree_size = %d, want %d", gotSTH.TreeSize, sth.TreeSize)
	}
}

func testGlobalLogPublishedBatchWithAnchorsOptional(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	marker, ok := store.(proofstore.GlobalLogPublishedBatchWithAnchorsMarker)
	if !ok {
		t.Skip("store does not implement GlobalLogPublishedBatchWithAnchorsMarker")
	}
	ctx := context.Background()
	batchIDs := []string{"anchor-batch-1", "anchor-batch-2"}
	sths := []model.SignedTreeHead{
		{SchemaVersion: model.SchemaSignedTreeHead, TreeSize: 1, RootHash: []byte{1}},
		{SchemaVersion: model.SchemaSignedTreeHead, TreeSize: 2, RootHash: []byte{2}},
	}
	anchors := make([]model.STHAnchorOutboxItem, len(sths))
	for i := range batchIDs {
		if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{
			SchemaVersion: model.SchemaGlobalLogOutbox,
			BatchID:       batchIDs[i],
			BatchRoot: model.BatchRoot{
				SchemaVersion: model.SchemaBatchRoot,
				BatchID:       batchIDs[i],
				BatchRoot:     []byte{byte(i + 1)},
				TreeSize:      1,
			},
			Status: model.AnchorStatePending,
		}); err != nil {
			t.Fatalf("EnqueueGlobalLog %s: %v", batchIDs[i], err)
		}
		anchors[i] = model.STHAnchorOutboxItem{
			SchemaVersion: model.SchemaSTHAnchorOutbox,
			TreeSize:      sths[i].TreeSize,
			Status:        model.AnchorStatePending,
			STH:           sths[i],
		}
	}
	if err := marker.MarkGlobalLogPublishedBatchWithAnchors(ctx, batchIDs, sths, anchors); err != nil {
		t.Fatalf("MarkGlobalLogPublishedBatchWithAnchors: %v", err)
	}
	for i := range batchIDs {
		globalItem, ok, err := store.GetGlobalLogOutboxItem(ctx, batchIDs[i])
		if err != nil || !ok || globalItem.Status != model.AnchorStatePublished {
			t.Fatalf("global item %s ok=%v err=%v item=%+v", batchIDs[i], ok, err, globalItem)
		}
		anchorItem, ok, err := store.GetSTHAnchorOutboxItem(ctx, sths[i].TreeSize)
		if err != nil || !ok || anchorItem.Status != model.AnchorStatePending {
			t.Fatalf("anchor item %d ok=%v err=%v item=%+v", sths[i].TreeSize, ok, err, anchorItem)
		}
	}
}

func testGlobalLogAppendCommitRejectsInvalidNodeWithoutPartialWrite(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	err := store.CommitGlobalLogAppend(ctx, model.GlobalLogAppend{
		Leaf: model.GlobalLogLeaf{
			SchemaVersion:      model.SchemaGlobalLogLeaf,
			BatchID:            "batch-invalid-node",
			BatchRoot:          []byte{1, 2, 3},
			BatchTreeSize:      3,
			BatchClosedAtUnixN: 99,
			LeafIndex:          0,
			LeafHash:           []byte{9},
			AppendedAtUnixN:    100,
		},
		Nodes: []model.GlobalLogNode{{
			SchemaVersion:  model.SchemaGlobalLogNode,
			Level:          0,
			StartIndex:     0,
			Hash:           []byte{9},
			CreatedAtUnixN: 101,
		}},
		State: model.GlobalLogState{
			SchemaVersion:  model.SchemaGlobalLogState,
			TreeSize:       1,
			RootHash:       []byte{9},
			Frontier:       [][]byte{{9}},
			UpdatedAtUnixN: 102,
		},
		STH: model.SignedTreeHead{
			SchemaVersion:  model.SchemaSignedTreeHead,
			TreeSize:       1,
			RootHash:       []byte{9},
			TimestampUnixN: 103,
		},
	})
	if got := trusterr.CodeOf(err); got != trusterr.CodeInvalidArgument {
		t.Fatalf("CodeOf(CommitGlobalLogAppend error) = %s, want %s; err=%v", got, trusterr.CodeInvalidArgument, err)
	}
	if _, ok, err := store.GetGlobalLeafByBatchID(ctx, "batch-invalid-node"); err != nil || ok {
		t.Fatalf("GetGlobalLeafByBatchID after invalid append ok=%v err=%v, want no partial leaf", ok, err)
	}
	if _, ok, err := store.GetGlobalLogNode(ctx, 0, 0); err != nil || ok {
		t.Fatalf("GetGlobalLogNode after invalid append ok=%v err=%v, want no partial node", ok, err)
	}
	if _, ok, err := store.GetGlobalLogState(ctx); err != nil || ok {
		t.Fatalf("GetGlobalLogState after invalid append ok=%v err=%v, want no partial state", ok, err)
	}
	if _, ok, err := store.GetSignedTreeHead(ctx, 1); err != nil || ok {
		t.Fatalf("GetSignedTreeHead after invalid append ok=%v err=%v, want no partial STH", ok, err)
	}
}

func testGlobalLogTileRoundTrip(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	tile := model.GlobalLogTile{
		SchemaVersion: model.SchemaGlobalLogTile,
		Level:         0,
		StartIndex:    0,
		Width:         2,
		Hashes:        [][]byte{{1}, {2}},
		Compressed:    true,
	}
	if err := store.PutGlobalLogTile(ctx, tile); err != nil {
		t.Fatalf("PutGlobalLogTile: %v", err)
	}
	got, err := store.ListGlobalLogTiles(ctx)
	if err != nil {
		t.Fatalf("ListGlobalLogTiles: %v", err)
	}
	if len(got) != 1 || got[0].Width != 2 || !got[0].Compressed {
		t.Fatalf("ListGlobalLogTiles = %+v", got)
	}
}

func testGlobalLogPagedStateRoundTrip(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	for i := uint64(0); i < 2; i++ {
		leaf := model.GlobalLogLeaf{
			SchemaVersion:   model.SchemaGlobalLogLeaf,
			BatchID:         []string{"batch-1", "batch-2"}[i],
			LeafIndex:       i,
			LeafHash:        []byte{byte(i + 1)},
			AppendedAtUnixN: int64(100 + i),
		}
		if err := store.PutGlobalLeaf(ctx, leaf); err != nil {
			t.Fatalf("PutGlobalLeaf %d: %v", i, err)
		}
		node := model.GlobalLogNode{
			SchemaVersion:  model.SchemaGlobalLogNode,
			Level:          0,
			StartIndex:     i,
			Width:          1,
			Hash:           []byte{byte(i + 1)},
			CreatedAtUnixN: int64(100 + i),
		}
		if err := store.PutGlobalLogNode(ctx, node); err != nil {
			t.Fatalf("PutGlobalLogNode %d: %v", i, err)
		}
	}
	parent := model.GlobalLogNode{
		SchemaVersion:  model.SchemaGlobalLogNode,
		Level:          1,
		StartIndex:     0,
		Width:          2,
		Hash:           []byte{9},
		CreatedAtUnixN: 103,
	}
	if err := store.PutGlobalLogNode(ctx, parent); err != nil {
		t.Fatalf("PutGlobalLogNode parent: %v", err)
	}
	if err := store.PutGlobalLogState(ctx, model.GlobalLogState{
		SchemaVersion:  model.SchemaGlobalLogState,
		TreeSize:       2,
		RootHash:       []byte{9},
		Frontier:       [][]byte{{1}, {9}},
		UpdatedAtUnixN: 104,
	}); err != nil {
		t.Fatalf("PutGlobalLogState: %v", err)
	}

	leaves, err := store.ListGlobalLeavesRange(ctx, 1, 10)
	if err != nil {
		t.Fatalf("ListGlobalLeavesRange: %v", err)
	}
	if len(leaves) != 1 || leaves[0].LeafIndex != 1 {
		t.Fatalf("ListGlobalLeavesRange = %+v", leaves)
	}
	nodes, err := store.ListGlobalLogNodesAfter(ctx, ^uint64(0), ^uint64(0), 2)
	if err != nil {
		t.Fatalf("ListGlobalLogNodesAfter first: %v", err)
	}
	if len(nodes) != 2 || nodes[0].Level != 0 || nodes[0].StartIndex != 0 || nodes[1].StartIndex != 1 {
		t.Fatalf("first node page = %+v", nodes)
	}
	next, err := store.ListGlobalLogNodesAfter(ctx, nodes[1].Level, nodes[1].StartIndex, 2)
	if err != nil {
		t.Fatalf("ListGlobalLogNodesAfter next: %v", err)
	}
	if len(next) != 1 || next[0].Level != 1 || next[0].StartIndex != 0 {
		t.Fatalf("next node page = %+v", next)
	}
	state, ok, err := store.GetGlobalLogState(ctx)
	if err != nil || !ok {
		t.Fatalf("GetGlobalLogState ok=%v err=%v", ok, err)
	}
	if state.TreeSize != 2 {
		t.Fatalf("state = %+v", state)
	}
}

func testGlobalLeafListPagePaginates(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	for i := uint64(0); i < 3; i++ {
		if err := store.PutGlobalLeaf(ctx, model.GlobalLogLeaf{
			SchemaVersion: model.SchemaGlobalLogLeaf,
			BatchID:       "batch-" + itoa(int(i+1)),
			LeafIndex:     i,
			LeafHash:      []byte{byte(i + 1)},
		}); err != nil {
			t.Fatalf("PutGlobalLeaf %d: %v", i, err)
		}
	}
	first, err := store.ListGlobalLeavesPage(ctx, model.GlobalLeafListOptions{Limit: 2, Direction: model.RecordListDirectionDesc})
	if err != nil {
		t.Fatalf("ListGlobalLeavesPage first: %v", err)
	}
	if len(first) != 2 || first[0].LeafIndex != 2 || first[1].LeafIndex != 1 {
		t.Fatalf("first global leaf page = %+v", first)
	}
	next, err := store.ListGlobalLeavesPage(ctx, model.GlobalLeafListOptions{
		Limit:          2,
		Direction:      model.RecordListDirectionDesc,
		AfterLeafIndex: first[1].LeafIndex,
	})
	if err != nil {
		t.Fatalf("ListGlobalLeavesPage next: %v", err)
	}
	if len(next) != 1 || next[0].LeafIndex != 0 {
		t.Fatalf("next global leaf page = %+v", next)
	}
	ascending, err := store.ListGlobalLeavesPage(ctx, model.GlobalLeafListOptions{Limit: 2, Direction: model.RecordListDirectionAsc})
	if err != nil {
		t.Fatalf("ListGlobalLeavesPage ascending: %v", err)
	}
	if len(ascending) != 2 || ascending[0].LeafIndex != 0 || ascending[1].LeafIndex != 1 {
		t.Fatalf("ascending global leaf page = %+v", ascending)
	}
	ascendingNext, err := store.ListGlobalLeavesPage(ctx, model.GlobalLeafListOptions{Limit: 2, Direction: model.RecordListDirectionAsc, AfterLeafIndex: ascending[1].LeafIndex})
	if err != nil {
		t.Fatalf("ListGlobalLeavesPage ascending next: %v", err)
	}
	if len(ascendingNext) != 1 || ascendingNext[0].LeafIndex != 2 {
		t.Fatalf("ascending next global leaf page = %+v", ascendingNext)
	}
}

func testSignedTreeHeadListPagePaginates(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	for _, size := range []uint64{1, 2, 3} {
		if err := store.PutSignedTreeHead(ctx, model.SignedTreeHead{
			SchemaVersion: model.SchemaSignedTreeHead,
			TreeSize:      size,
			RootHash:      []byte{byte(size)},
		}); err != nil {
			t.Fatalf("PutSignedTreeHead %d: %v", size, err)
		}
	}
	first, err := store.ListSignedTreeHeadsPage(ctx, model.TreeHeadListOptions{Limit: 2, Direction: model.RecordListDirectionDesc})
	if err != nil {
		t.Fatalf("ListSignedTreeHeadsPage first: %v", err)
	}
	if len(first) != 2 || first[0].TreeSize != 3 || first[1].TreeSize != 2 {
		t.Fatalf("first sth page = %+v", first)
	}
	next, err := store.ListSignedTreeHeadsPage(ctx, model.TreeHeadListOptions{
		Limit:         2,
		Direction:     model.RecordListDirectionDesc,
		AfterTreeSize: first[1].TreeSize,
	})
	if err != nil {
		t.Fatalf("ListSignedTreeHeadsPage next: %v", err)
	}
	if len(next) != 1 || next[0].TreeSize != 1 {
		t.Fatalf("next sth page = %+v", next)
	}
	ascending, err := store.ListSignedTreeHeadsPage(ctx, model.TreeHeadListOptions{Limit: 2, Direction: model.RecordListDirectionAsc})
	if err != nil {
		t.Fatalf("ListSignedTreeHeadsPage ascending: %v", err)
	}
	if len(ascending) != 2 || ascending[0].TreeSize != 1 || ascending[1].TreeSize != 2 {
		t.Fatalf("ascending sth page = %+v", ascending)
	}
	ascendingNext, err := store.ListSignedTreeHeadsPage(ctx, model.TreeHeadListOptions{Limit: 2, Direction: model.RecordListDirectionAsc, AfterTreeSize: ascending[1].TreeSize})
	if err != nil {
		t.Fatalf("ListSignedTreeHeadsPage ascending next: %v", err)
	}
	if len(ascendingNext) != 1 || ascendingNext[0].TreeSize != 3 {
		t.Fatalf("ascending next sth page = %+v", ascendingNext)
	}
}

func testGlobalLogTileListAfterPaginates(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	for _, tile := range []model.GlobalLogTile{
		{SchemaVersion: model.SchemaGlobalLogTile, Level: 0, StartIndex: 0, Width: 2, Hashes: [][]byte{{1}, {2}}, Compressed: true},
		{SchemaVersion: model.SchemaGlobalLogTile, Level: 0, StartIndex: 2, Width: 2, Hashes: [][]byte{{3}, {4}}, Compressed: true},
		{SchemaVersion: model.SchemaGlobalLogTile, Level: 1, StartIndex: 0, Width: 1, Hashes: [][]byte{{9}}, Compressed: true},
	} {
		if err := store.PutGlobalLogTile(ctx, tile); err != nil {
			t.Fatalf("PutGlobalLogTile %+v: %v", tile, err)
		}
	}
	first, err := store.ListGlobalLogTilesAfter(ctx, ^uint64(0), ^uint64(0), 2)
	if err != nil {
		t.Fatalf("ListGlobalLogTilesAfter first: %v", err)
	}
	if len(first) != 2 || first[0].StartIndex != 0 || first[1].StartIndex != 2 {
		t.Fatalf("first tile page = %+v", first)
	}
	next, err := store.ListGlobalLogTilesAfter(ctx, first[1].Level, first[1].StartIndex, 2)
	if err != nil {
		t.Fatalf("ListGlobalLogTilesAfter next: %v", err)
	}
	if len(next) != 1 || next[0].Level != 1 || next[0].StartIndex != 0 {
		t.Fatalf("next tile page = %+v", next)
	}
}

func testSTHAnchorListAfterPaginates(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	for _, size := range []uint64{3, 1, 2} {
		if err := store.EnqueueSTHAnchor(ctx, sthAnchorItem(size, "file", int64(size))); err != nil {
			t.Fatalf("EnqueueSTHAnchor %d: %v", size, err)
		}
	}
	first, err := store.ListSTHAnchorOutboxItemsAfter(ctx, 0, 2)
	if err != nil {
		t.Fatalf("ListSTHAnchorOutboxItemsAfter first: %v", err)
	}
	if len(first) != 2 || first[0].TreeSize != 1 || first[1].TreeSize != 2 {
		t.Fatalf("first anchor page = %+v", first)
	}
	next, err := store.ListSTHAnchorOutboxItemsAfter(ctx, first[1].TreeSize, 2)
	if err != nil {
		t.Fatalf("ListSTHAnchorOutboxItemsAfter next: %v", err)
	}
	if len(next) != 1 || next[0].TreeSize != 3 {
		t.Fatalf("next anchor page = %+v", next)
	}
}

func testSTHAnchorEnqueueIsIdempotent(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	item := sthAnchorItem(1, "file", 100)
	if err := store.EnqueueSTHAnchor(ctx, item); err != nil {
		t.Fatalf("first EnqueueSTHAnchor: %v", err)
	}
	err := store.EnqueueSTHAnchor(ctx, item)
	if err == nil {
		t.Fatalf("second EnqueueSTHAnchor: want AlreadyExists, got nil")
	}
	if got := trusterr.CodeOf(err); got != trusterr.CodeAlreadyExists {
		t.Fatalf("CodeOf(err) = %s, want %s", got, trusterr.CodeAlreadyExists)
	}
}

func testSTHAnchorBatchEnqueueOptional(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	batcher, ok := store.(proofstore.STHAnchorBatchEnqueuer)
	if !ok {
		t.Skip("store does not implement STHAnchorBatchEnqueuer")
	}
	ctx := context.Background()
	items := []model.STHAnchorOutboxItem{
		sthAnchorItem(21, "file", 100),
		sthAnchorItem(22, "file", 101),
	}
	if err := batcher.EnqueueSTHAnchors(ctx, items); err != nil {
		t.Fatalf("EnqueueSTHAnchors: %v", err)
	}
	if err := batcher.EnqueueSTHAnchors(ctx, items); err != nil {
		t.Fatalf("EnqueueSTHAnchors idempotent retry: %v", err)
	}
	got, err := store.ListPendingSTHAnchors(ctx, 1000, 10)
	if err != nil {
		t.Fatalf("ListPendingSTHAnchors: %v", err)
	}
	if len(got) != 2 || got[0].TreeSize != 21 || got[1].TreeSize != 22 {
		t.Fatalf("pending anchors = %+v", got)
	}
}

func testSTHAnchorListPagePaginates(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	for _, size := range []uint64{1, 2, 3} {
		if err := store.EnqueueSTHAnchor(ctx, sthAnchorItem(size, "ots", int64(size))); err != nil {
			t.Fatalf("EnqueueSTHAnchor %d: %v", size, err)
		}
	}
	first, err := store.ListSTHAnchorsPage(ctx, model.AnchorListOptions{Limit: 2, Direction: model.RecordListDirectionDesc})
	if err != nil {
		t.Fatalf("ListSTHAnchorsPage first: %v", err)
	}
	if len(first) != 2 || first[0].TreeSize != 3 || first[1].TreeSize != 2 {
		t.Fatalf("first anchor page = %+v", first)
	}
	next, err := store.ListSTHAnchorsPage(ctx, model.AnchorListOptions{
		Limit:         2,
		Direction:     model.RecordListDirectionDesc,
		AfterTreeSize: first[1].TreeSize,
	})
	if err != nil {
		t.Fatalf("ListSTHAnchorsPage next: %v", err)
	}
	if len(next) != 1 || next[0].TreeSize != 1 {
		t.Fatalf("next anchor page = %+v", next)
	}
	ascending, err := store.ListSTHAnchorsPage(ctx, model.AnchorListOptions{Limit: 2, Direction: model.RecordListDirectionAsc})
	if err != nil {
		t.Fatalf("ListSTHAnchorsPage ascending: %v", err)
	}
	if len(ascending) != 2 || ascending[0].TreeSize != 1 || ascending[1].TreeSize != 2 {
		t.Fatalf("ascending anchor page = %+v", ascending)
	}
	ascendingNext, err := store.ListSTHAnchorsPage(ctx, model.AnchorListOptions{Limit: 2, Direction: model.RecordListDirectionAsc, AfterTreeSize: ascending[1].TreeSize})
	if err != nil {
		t.Fatalf("ListSTHAnchorsPage ascending next: %v", err)
	}
	if len(ascendingNext) != 1 || ascendingNext[0].TreeSize != 3 {
		t.Fatalf("ascending next anchor page = %+v", ascendingNext)
	}
}

func testSTHAnchorListPendingRespectsBackoff(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	now := int64(1_000)
	if err := store.EnqueueSTHAnchor(ctx, sthAnchorItem(1, "file", now-1)); err != nil {
		t.Fatalf("EnqueueSTHAnchor ready: %v", err)
	}
	if err := store.EnqueueSTHAnchor(ctx, model.STHAnchorOutboxItem{
		SchemaVersion:    model.SchemaSTHAnchorOutbox,
		TreeSize:         2,
		SinkName:         "file",
		Status:           model.AnchorStatePending,
		STH:              model.SignedTreeHead{TreeSize: 2, RootHash: []byte{2}},
		EnqueuedAtUnixN:  now,
		NextAttemptUnixN: now + 10_000,
	}); err != nil {
		t.Fatalf("EnqueueSTHAnchor not-yet: %v", err)
	}
	pending, err := store.ListPendingSTHAnchors(ctx, now, 10)
	if err != nil {
		t.Fatalf("ListPendingSTHAnchors: %v", err)
	}
	if len(pending) != 1 || pending[0].TreeSize != 1 {
		t.Fatalf("ListPendingSTHAnchors = %+v, want only tree_size=1", pending)
	}
}

func testSTHAnchorListPendingIsCommitOrdered(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	for _, e := range []struct {
		size uint64
		ts   int64
	}{{3, 100}, {1, 200}, {2, 300}} {
		if err := store.EnqueueSTHAnchor(ctx, sthAnchorItem(e.size, "file", e.ts)); err != nil {
			t.Fatalf("EnqueueSTHAnchor %d: %v", e.size, err)
		}
	}
	pending, err := store.ListPendingSTHAnchors(ctx, 1_000, 10)
	if err != nil {
		t.Fatalf("ListPendingSTHAnchors: %v", err)
	}
	want := []uint64{3, 1, 2}
	if len(pending) != len(want) {
		t.Fatalf("ListPendingSTHAnchors len = %d, want %d", len(pending), len(want))
	}
	for i, size := range want {
		if pending[i].TreeSize != size {
			t.Fatalf("ListPendingSTHAnchors[%d] = %d, want %d", i, pending[i].TreeSize, size)
		}
	}
}

func testSTHAnchorListPublishedFilters(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	for _, e := range []struct {
		size uint64
		ts   int64
	}{{1, 50}, {3, 300}, {2, 200}, {4, 400}} {
		if err := store.EnqueueSTHAnchor(ctx, sthAnchorItem(e.size, "ots", e.ts)); err != nil {
			t.Fatalf("EnqueueSTHAnchor %d: %v", e.size, err)
		}
	}
	if err := store.MarkSTHAnchorPublished(ctx, sthAnchorResult(3, "ots", "z")); err != nil {
		t.Fatalf("MarkSTHAnchorPublished z: %v", err)
	}
	if err := store.MarkSTHAnchorPublished(ctx, sthAnchorResult(2, "ots", "a")); err != nil {
		t.Fatalf("MarkSTHAnchorPublished a: %v", err)
	}
	if err := store.MarkSTHAnchorFailed(ctx, 4, "permanent boom"); err != nil {
		t.Fatalf("MarkSTHAnchorFailed: %v", err)
	}
	got, err := store.ListPublishedSTHAnchors(ctx, 100)
	if err != nil {
		t.Fatalf("ListPublishedSTHAnchors: %v", err)
	}
	want := []uint64{2, 3}
	if len(got) != len(want) {
		t.Fatalf("ListPublishedSTHAnchors = %+v", got)
	}
	for i, size := range want {
		if got[i].TreeSize != size {
			t.Fatalf("ListPublishedSTHAnchors[%d] = %d, want %d", i, got[i].TreeSize, size)
		}
		if got[i].Status != model.AnchorStatePublished {
			t.Fatalf("ListPublishedSTHAnchors[%d] status = %s, want published", i, got[i].Status)
		}
	}

	emptyStore, emptyCleanup := newStore(t)
	defer emptyCleanup()
	empty, err := emptyStore.ListPublishedSTHAnchors(ctx, 10)
	if err != nil {
		t.Fatalf("ListPublishedSTHAnchors on empty store: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("ListPublishedSTHAnchors on empty store = %+v, want []", empty)
	}
}

func testSTHAnchorMarkPublished(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	if err := store.EnqueueSTHAnchor(ctx, sthAnchorItem(7, "file", 50)); err != nil {
		t.Fatalf("EnqueueSTHAnchor: %v", err)
	}
	result := sthAnchorResult(7, "file", "anchor-42")
	result.Proof = []byte("proof-blob")
	result.PublishedAtUnixN = 9_999
	if err := store.MarkSTHAnchorPublished(ctx, result); err != nil {
		t.Fatalf("MarkSTHAnchorPublished: %v", err)
	}
	got, ok, err := store.GetSTHAnchorResult(ctx, 7)
	if err != nil || !ok {
		t.Fatalf("GetSTHAnchorResult ok=%v err=%v", ok, err)
	}
	if got.AnchorID != result.AnchorID || string(got.Proof) != "proof-blob" {
		t.Fatalf("GetSTHAnchorResult() = %+v, want %+v", got, result)
	}
	item, ok, err := store.GetSTHAnchorOutboxItem(ctx, 7)
	if err != nil || !ok {
		t.Fatalf("GetSTHAnchorOutboxItem ok=%v err=%v", ok, err)
	}
	if item.Status != model.AnchorStatePublished {
		t.Fatalf("item status = %q, want %q", item.Status, model.AnchorStatePublished)
	}
	pending, err := store.ListPendingSTHAnchors(ctx, 1_000_000_000_000, 10)
	if len(pending) != 0 {
		t.Fatalf("ListPendingSTHAnchors after publish = %+v, want empty", pending)
	}
}

func testLatestSTHAnchorResultIsMonotonic(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	reader, ok := store.(proofstore.LatestSTHAnchorResultReader)
	if !ok {
		t.Skip("store does not implement LatestSTHAnchorResultReader")
	}
	ctx := context.Background()
	if _, found, err := reader.LatestSTHAnchorResult(ctx); err != nil || found {
		t.Fatalf("LatestSTHAnchorResult empty found=%v err=%v", found, err)
	}
	for _, treeSize := range []uint64{3, 2} {
		if err := store.EnqueueSTHAnchor(ctx, sthAnchorItem(treeSize, "file", int64(treeSize))); err != nil {
			t.Fatalf("EnqueueSTHAnchor(%d): %v", treeSize, err)
		}
		if err := store.MarkSTHAnchorPublished(ctx, sthAnchorResult(treeSize, "file", "anchor")); err != nil {
			t.Fatalf("MarkSTHAnchorPublished(%d): %v", treeSize, err)
		}
	}
	latest, found, err := reader.LatestSTHAnchorResult(ctx)
	if err != nil || !found {
		t.Fatalf("LatestSTHAnchorResult found=%v err=%v", found, err)
	}
	if latest.TreeSize != 3 {
		t.Fatalf("LatestSTHAnchorResult tree_size=%d, want 3", latest.TreeSize)
	}
}

func testSTHAnchorScheduleStateMachineOptional(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	scheduler, ok := store.(proofstore.STHAnchorScheduleStore)
	if !ok {
		t.Skip("store does not implement STHAnchorScheduleStore")
	}
	resultLister, ok := store.(proofstore.STHAnchorResultLister)
	if !ok {
		t.Fatalf("STHAnchorScheduleStore must also implement STHAnchorResultLister")
	}
	resultWriter, ok := store.(proofstore.STHAnchorResultWriter)
	if !ok {
		t.Fatalf("STHAnchorScheduleStore must also implement STHAnchorResultWriter")
	}
	keyedReader, ok := store.(proofstore.STHAnchorResultKeyedReader)
	if !ok {
		t.Fatalf("STHAnchorScheduleStore must also implement STHAnchorResultKeyedReader")
	}
	ctx := context.Background()
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}

	if schedules, err := scheduler.ListSTHAnchorSchedules(ctx); err != nil || len(schedules) != 0 {
		t.Fatalf("ListSTHAnchorSchedules empty = %+v err=%v", schedules, err)
	}
	if _, found, err := scheduler.GetSTHAnchorSchedule(ctx, key); err != nil || found {
		t.Fatalf("GetSTHAnchorSchedule empty found=%v err=%v", found, err)
	}

	first, err := scheduler.UpsertSTHAnchorCandidate(ctx, scheduleCandidate(key, 1, 0x11, 100, 200))
	if err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate first: %v", err)
	}
	merged, err := scheduler.UpsertSTHAnchorCandidate(ctx, scheduleCandidate(key, 3, 0x33, 150, 900))
	if err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate merged: %v", err)
	}
	if first.Pending == nil || merged.Pending == nil || merged.Pending.Target.TreeSize != 3 || merged.Pending.OpenedAtUnixN != 100 || merged.Pending.DueAtUnixN != 200 {
		t.Fatalf("non-sliding pending window first=%+v merged=%+v", first.Pending, merged.Pending)
	}

	if _, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, key, 199, 250, "worker-1", "lease-early"); err != nil || claimed {
		t.Fatalf("ClaimSTHAnchorAttempt before deadline claimed=%v err=%v", claimed, err)
	}
	attempt, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, key, 200, 250, "worker-1", "lease-1")
	if err != nil || !claimed || attempt.Target.TreeSize != 3 {
		t.Fatalf("ClaimSTHAnchorAttempt attempt=%+v claimed=%v err=%v", attempt, claimed, err)
	}
	advanced, err := scheduler.UpsertSTHAnchorCandidate(ctx, scheduleCandidate(key, 5, 0x55, 220, 320))
	if err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate while in-flight: %v", err)
	}
	if advanced.InFlight == nil || advanced.InFlight.Target.TreeSize != 3 || advanced.Pending == nil || advanced.Pending.Target.TreeSize != 5 {
		t.Fatalf("bounded scheduler state = %+v", advanced)
	}

	if err := scheduler.RescheduleSTHAnchorAttempt(ctx, key, attempt.Generation+1, "lease-1", 1, 300, "retry"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("RescheduleSTHAnchorAttempt wrong generation error=%v", err)
	}
	if err := scheduler.RescheduleSTHAnchorAttempt(ctx, key, attempt.Generation, "wrong", 1, 300, "retry"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("RescheduleSTHAnchorAttempt wrong token error=%v", err)
	}
	if err := scheduler.RescheduleSTHAnchorAttempt(ctx, key, attempt.Generation, "lease-1", 1, 300, "retry"); err != nil {
		t.Fatalf("RescheduleSTHAnchorAttempt: %v", err)
	}
	if _, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, key, 299, 350, "worker-2", "lease-too-soon"); err != nil || claimed {
		t.Fatalf("ClaimSTHAnchorAttempt before retry claimed=%v err=%v", claimed, err)
	}
	attempt, claimed, err = scheduler.ClaimSTHAnchorAttempt(ctx, key, 300, 400, "worker-2", "lease-2")
	if err != nil || !claimed || attempt.Attempts != 1 || attempt.Target.TreeSize != 3 {
		t.Fatalf("ClaimSTHAnchorAttempt retry attempt=%+v claimed=%v err=%v", attempt, claimed, err)
	}

	result := scheduleResult(key, attempt.Target, "anchor-3", 310)
	if err := scheduler.CompleteSTHAnchorAttempt(ctx, key, attempt.Generation, "lease-2", result); err != nil {
		t.Fatalf("CompleteSTHAnchorAttempt: %v", err)
	}
	if err := scheduler.CompleteSTHAnchorAttempt(ctx, key, attempt.Generation, "lease-2", result); err != nil {
		t.Fatalf("CompleteSTHAnchorAttempt idempotent retry: %v", err)
	}
	completed, found, err := scheduler.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found {
		t.Fatalf("GetSTHAnchorSchedule completed found=%v err=%v", found, err)
	}
	if completed.InFlight != nil || completed.Pending == nil || completed.Pending.Target.TreeSize != 5 {
		t.Fatalf("completed scheduler state = %+v", completed)
	}
	storedResult, found, err := store.GetSTHAnchorResult(ctx, 3)
	if err != nil || !found || storedResult.AnchorID != result.AnchorID {
		t.Fatalf("GetSTHAnchorResult completed result=%+v found=%v err=%v", storedResult, found, err)
	}
	results, err := resultLister.ListSTHAnchorResultsAfter(ctx, model.STHAnchorResultKey{}, 10)
	if err != nil || len(results) != 1 || results[0].TreeSize != 3 {
		t.Fatalf("ListSTHAnchorResultsAfter results=%+v err=%v", results, err)
	}

	conflict := scheduleCandidate(key, 5, 0x99, 230, 330)
	if _, err := scheduler.UpsertSTHAnchorCandidate(ctx, conflict); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("UpsertSTHAnchorCandidate conflicting root error=%v", err)
	}
	attempt, claimed, err = scheduler.ClaimSTHAnchorAttempt(ctx, key, 320, 400, "worker-3", "lease-3")
	if err != nil || !claimed || attempt.Target.TreeSize != 5 {
		t.Fatalf("ClaimSTHAnchorAttempt next window attempt=%+v claimed=%v err=%v", attempt, claimed, err)
	}
	if err := scheduler.FailSTHAnchorAttempt(ctx, key, attempt.Generation, "lease-3", 1, "schema rejected"); err != nil {
		t.Fatalf("FailSTHAnchorAttempt: %v", err)
	}
	if _, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, key, 500, 600, "worker-4", "lease-4"); err != nil || claimed {
		t.Fatalf("ClaimSTHAnchorAttempt terminal claimed=%v err=%v", claimed, err)
	}
	terminal, err := scheduler.UpsertSTHAnchorCandidate(ctx, scheduleCandidate(key, 7, 0x77, 500, 600))
	if err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate after terminal failure: %v", err)
	}
	if terminal.InFlight == nil || !terminal.InFlight.TerminalFailure || terminal.InFlight.Target.TreeSize != 5 || terminal.Pending == nil || terminal.Pending.Target.TreeSize != 7 {
		t.Fatalf("terminal bounded scheduler state = %+v", terminal)
	}

	crashKey := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "crash-test"}
	if _, err := scheduler.UpsertSTHAnchorCandidate(ctx, scheduleCandidate(crashKey, 11, 0x11, 700, 700)); err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate crash recovery: %v", err)
	}
	crashAttempt, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, crashKey, 700, 750, "worker-5", "lease-5")
	if err != nil || !claimed {
		t.Fatalf("ClaimSTHAnchorAttempt crash recovery claimed=%v err=%v", claimed, err)
	}
	crashResult := scheduleResult(crashKey, crashAttempt.Target, "anchor-11", 710)
	if err := resultWriter.PutSTHAnchorResult(ctx, crashResult); err != nil {
		t.Fatalf("PutSTHAnchorResult crash recovery: %v", err)
	}
	if _, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, crashKey, 800, 900, "worker-6", "lease-6"); err != nil || claimed {
		t.Fatalf("ClaimSTHAnchorAttempt after durable result claimed=%v err=%v", claimed, err)
	}
	recovered, found, err := scheduler.GetSTHAnchorSchedule(ctx, crashKey)
	if err != nil || !found || recovered.InFlight != nil {
		t.Fatalf("crash-recovered schedule=%+v found=%v err=%v", recovered, found, err)
	}

	// Results are sink-specific even when two providers publish the same STH.
	// Keyed reads and composite pagination must retain both envelopes.
	multiA := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "multi-a"}
	multiB := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "multi-b"}
	sharedSTH := scheduleSTH(multiA, 23, 0x23)
	for _, tc := range []struct {
		key      model.STHAnchorScheduleKey
		anchorID string
	}{{multiA, "anchor-23-a"}, {multiB, "anchor-23-b"}} {
		if err := resultWriter.PutSTHAnchorResult(ctx, scheduleResult(tc.key, sharedSTH, tc.anchorID, 230)); err != nil {
			t.Fatalf("PutSTHAnchorResult %s: %v", tc.key.SinkName, err)
		}
		resultKey := model.STHAnchorResultKey{NodeID: tc.key.NodeID, LogID: tc.key.LogID, SinkName: tc.key.SinkName, TreeSize: sharedSTH.TreeSize}
		got, found, err := keyedReader.GetSTHAnchorResultForKey(ctx, resultKey)
		if err != nil || !found || got.AnchorID != tc.anchorID {
			t.Fatalf("GetSTHAnchorResultForKey %s result=%+v found=%v err=%v", tc.key.SinkName, got, found, err)
		}
		latest, found, err := keyedReader.LatestSTHAnchorResultForKey(ctx, tc.key)
		if err != nil || !found || latest.AnchorID != tc.anchorID {
			t.Fatalf("LatestSTHAnchorResultForKey %s result=%+v found=%v err=%v", tc.key.SinkName, latest, found, err)
		}
	}
	cursor := model.STHAnchorResultKey{}
	multiCount := 0
	for {
		page, err := resultLister.ListSTHAnchorResultsAfter(ctx, cursor, 1)
		if err != nil {
			t.Fatalf("ListSTHAnchorResultsAfter composite page: %v", err)
		}
		if len(page) == 0 {
			break
		}
		cursor = anchorschedule.ResultKey(page[0])
		if page[0].TreeSize == sharedSTH.TreeSize && (page[0].SinkName == multiA.SinkName || page[0].SinkName == multiB.SinkName) {
			multiCount++
		}
	}
	if multiCount != 2 {
		t.Fatalf("composite result pagination retained %d same-tree sinks, want 2", multiCount)
	}
	otherLog := model.STHAnchorScheduleKey{NodeID: "node-2", LogID: "log-2", SinkName: "multi-a"}
	otherSTH := scheduleSTH(otherLog, 23, 0x99)
	if err := resultWriter.PutSTHAnchorResult(ctx, scheduleResult(otherLog, otherSTH, "anchor-other-log", 231)); err != nil {
		t.Fatalf("PutSTHAnchorResult same tree in another log: %v", err)
	}
	if _, err := scheduler.UpsertSTHAnchorCandidate(ctx, scheduleCandidate(multiB, 23, 0x99, 850, 950)); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("UpsertSTHAnchorCandidate cross-sink conflicting root error=%v", err)
	}

	// A result at the same historical tree size remains authoritative even
	// after a later result becomes latest. Candidate upsert must consult the
	// exact immutable result and fail closed on a split-view root.
	historyKey := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "history-test"}
	for _, treeSize := range []uint64{13, 19} {
		sth := scheduleSTH(historyKey, treeSize, byte(treeSize))
		if err := resultWriter.PutSTHAnchorResult(ctx, scheduleResult(historyKey, sth, fmt.Sprintf("anchor-%d", treeSize), int64(treeSize*10))); err != nil {
			t.Fatalf("PutSTHAnchorResult historical %d: %v", treeSize, err)
		}
	}
	if _, err := scheduler.UpsertSTHAnchorCandidate(ctx, scheduleCandidate(historyKey, 13, 0x99, 900, 1000)); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("UpsertSTHAnchorCandidate historical conflicting root error=%v", err)
	}
}

func scheduleCandidate(key model.STHAnchorScheduleKey, treeSize uint64, seed byte, observedAt, dueAt int64) model.STHAnchorCandidate {
	return model.STHAnchorCandidate{
		Key:             key,
		STH:             scheduleSTH(key, treeSize, seed),
		ObservedAtUnixN: observedAt,
		DueAtUnixN:      dueAt,
	}
}

func scheduleSTH(key model.STHAnchorScheduleKey, treeSize uint64, seed byte) model.SignedTreeHead {
	return model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       treeSize,
		RootHash:       bytes.Repeat([]byte{seed}, 32),
		TimestampUnixN: int64(treeSize),
		NodeID:         key.NodeID,
		LogID:          key.LogID,
		Signature: model.Signature{
			Alg:       model.DefaultSignatureAlg,
			KeyID:     "server-key",
			Signature: bytes.Repeat([]byte{seed}, 64),
		},
	}
}

func scheduleResult(key model.STHAnchorScheduleKey, sth model.SignedTreeHead, anchorID string, publishedAt int64) model.STHAnchorResult {
	return model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		NodeID:           key.NodeID,
		LogID:            key.LogID,
		TreeSize:         sth.TreeSize,
		SinkName:         key.SinkName,
		AnchorID:         anchorID,
		RootHash:         append([]byte(nil), sth.RootHash...),
		STH:              sth,
		Proof:            []byte("anchor-proof"),
		PublishedAtUnixN: publishedAt,
	}
}

func testSTHAnchorMarkFailed(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	if err := store.EnqueueSTHAnchor(ctx, sthAnchorItem(9, "file", 10)); err != nil {
		t.Fatalf("EnqueueSTHAnchor: %v", err)
	}
	if err := store.MarkSTHAnchorFailed(ctx, 9, "schema rejected"); err != nil {
		t.Fatalf("MarkSTHAnchorFailed: %v", err)
	}
	item, _, err := store.GetSTHAnchorOutboxItem(ctx, 9)
	if err != nil {
		t.Fatalf("GetSTHAnchorOutboxItem: %v", err)
	}
	if item.Status != model.AnchorStateFailed || item.LastErrorMessage != "schema rejected" {
		t.Fatalf("item = %+v, want failed+schema rejected", item)
	}
	pending, err := store.ListPendingSTHAnchors(ctx, 1_000_000, 10)
	if err != nil {
		t.Fatalf("ListPendingSTHAnchors: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("ListPendingSTHAnchors after failed = %+v, want empty", pending)
	}
}

func testSTHAnchorRescheduleKeepsPending(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	if err := store.EnqueueSTHAnchor(ctx, sthAnchorItem(11, "file", 100)); err != nil {
		t.Fatalf("EnqueueSTHAnchor: %v", err)
	}
	if err := store.RescheduleSTHAnchor(ctx, 11, 2, 5_000, "sink 5xx"); err != nil {
		t.Fatalf("RescheduleSTHAnchor: %v", err)
	}
	item, _, err := store.GetSTHAnchorOutboxItem(ctx, 11)
	if err != nil {
		t.Fatalf("GetSTHAnchorOutboxItem: %v", err)
	}
	if item.Status != model.AnchorStatePending || item.Attempts != 2 || item.NextAttemptUnixN != 5_000 || item.LastErrorMessage != "sink 5xx" {
		t.Fatalf("item = %+v", item)
	}

	pending, err := store.ListPendingSTHAnchors(ctx, 4_000, 10)
	if err != nil {
		t.Fatalf("ListPendingSTHAnchors pre-backoff: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("ListPendingSTHAnchors pre-backoff = %+v, want empty", pending)
	}
	pending, err = store.ListPendingSTHAnchors(ctx, 10_000, 10)
	if err != nil {
		t.Fatalf("ListPendingSTHAnchors post-backoff: %v", err)
	}
	if len(pending) != 1 || pending[0].TreeSize != 11 {
		t.Fatalf("ListPendingSTHAnchors post-backoff = %+v", pending)
	}
}

func testSTHAnchorMissing(t *testing.T, newStore Factory) {
	t.Parallel()
	store, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()

	_, ok, err := store.GetSTHAnchorOutboxItem(ctx, 99)
	if err != nil {
		t.Fatalf("GetSTHAnchorOutboxItem: %v", err)
	}
	if ok {
		t.Fatalf("GetSTHAnchorOutboxItem ok = true, want false for missing item")
	}
	_, ok, err = store.GetSTHAnchorResult(ctx, 99)
	if err != nil {
		t.Fatalf("GetSTHAnchorResult: %v", err)
	}
	if ok {
		t.Fatalf("GetSTHAnchorResult ok = true, want false for missing item")
	}
	if err := store.RescheduleSTHAnchor(ctx, 99, 1, 0, "x"); err == nil {
		t.Fatalf("RescheduleSTHAnchor: want NotFound, got nil")
	} else if trusterr.CodeOf(err) != trusterr.CodeNotFound {
		t.Fatalf("CodeOf(err) = %s, want NotFound", trusterr.CodeOf(err))
	}
}

func sthAnchorItem(treeSize uint64, sink string, enqueuedAt int64) model.STHAnchorOutboxItem {
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: sink}
	return model.STHAnchorOutboxItem{
		SchemaVersion:   model.SchemaSTHAnchorOutbox,
		TreeSize:        treeSize,
		SinkName:        sink,
		Status:          model.AnchorStatePending,
		STH:             scheduleSTH(key, treeSize, byte(treeSize)),
		EnqueuedAtUnixN: enqueuedAt,
	}
}

func sthAnchorResult(treeSize uint64, sink, anchorID string) model.STHAnchorResult {
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: sink}
	sth := scheduleSTH(key, treeSize, byte(treeSize))
	return scheduleResult(key, sth, anchorID, int64(treeSize))
}

func idForWorker(worker, seq int) string {
	return "rec-" + itoa(worker) + "-" + itoa(seq)
}

func recordBundle(recordID, tenantID, clientID, batchID string, receivedAt int64) model.ProofBundle {
	return model.ProofBundle{
		SchemaVersion: model.SchemaProofBundle,
		RecordID:      recordID,
		SignedClaim: model.SignedClaim{
			SchemaVersion: model.SchemaSignedClaim,
			Claim: model.ClientClaim{
				SchemaVersion: model.SchemaClientClaim,
				TenantID:      tenantID,
				ClientID:      clientID,
				KeyID:         "client-key",
				Content: model.Content{
					HashAlg:       model.DefaultHashAlg,
					ContentHash:   []byte(recordID),
					ContentLength: int64(len(recordID)),
					MediaType:     "text/plain",
					StorageURI:    "file://" + recordID,
				},
				Metadata: model.Metadata{EventType: "test.record", Source: clientID},
			},
		},
		ServerRecord: model.ServerRecord{
			SchemaVersion:   model.SchemaServerRecord,
			RecordID:        recordID,
			TenantID:        tenantID,
			ClientID:        clientID,
			KeyID:           "client-key",
			ReceivedAtUnixN: receivedAt,
		},
		CommittedReceipt: model.CommittedReceipt{
			SchemaVersion: model.SchemaCommittedReceipt,
			RecordID:      recordID,
			BatchID:       batchID,
			LeafIndex:     uint64(receivedAt / 100),
			ClosedAtUnixN: receivedAt + 10,
		},
	}
}

// itoa avoids pulling in strconv just for tiny identifiers; it keeps
// the generated ids deterministic and allocation-free enough for the
// concurrency test to not be dominated by fmt overhead.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	negative := n < 0
	if negative {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
