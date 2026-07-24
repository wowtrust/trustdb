package tikv

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/tikv/client-go/v2/testutils"
	tikvclient "github.com/tikv/client-go/v2/tikv"
	"github.com/tikv/client-go/v2/tikvrpc"
	"github.com/tikv/client-go/v2/txnkv"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/idempotency"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstoremeta"
	"github.com/wowtrust/trustdb/internal/proofstoremeta/proofstoremetatest"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestTiKVSuiteBindingConformance(t *testing.T) {
	proofstoremetatest.Run(t, func(t *testing.T) proofstoremetatest.Harness {
		db, _ := newMockTiKVDB(t, "suite-conformance/"+t.Name()+"/")
		return proofstoremetatest.Harness{
			Open: func(suiteID cryptosuite.ID) (cryptosuite.ID, error) {
				marker, err := ensureStorageSchema(db, suiteID, "node-1", "log-1", "test")
				return marker.CryptoSuite, err
			},
			SeedUnbound: func() error {
				return db.Set([]byte("unbound"), []byte("data"), syncWrite)
			},
			WriteRawMarker: func(data []byte) error {
				return db.Set([]byte(storageSchemaKey), data, syncWrite)
			},
		}
	})
}

func TestNormalizePDAddresses(t *testing.T) {
	t.Parallel()

	got := NormalizePDAddresses([]string{"127.0.0.1:2379, 127.0.0.2:2379", ""}, "127.0.0.3:2379")
	want := []string{"127.0.0.1:2379", "127.0.0.2:2379", "127.0.0.3:2379"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestOpenWithOptionsRequiresPDEndpoints(t *testing.T) {
	t.Parallel()

	if _, err := OpenWithOptions(Options{}); trusterr.CodeOf(err) != trusterr.CodeInvalidArgument {
		t.Fatalf("OpenWithOptions without endpoints error code = %s, want %s", trusterr.CodeOf(err), trusterr.CodeInvalidArgument)
	}
}

func TestEnsureStorageSchemaInitializesAndReopensCurrentNamespace(t *testing.T) {
	db, _ := newMockTiKVDB(t, "storage-schema-current/")
	marker, err := ensureStorageSchema(db, cryptosuite.INTLV1, "node-1", "log-1", "test")
	if err != nil {
		t.Fatalf("ensureStorageSchema(empty) error = %v", err)
	}
	if err := proofstoremeta.Validate(marker, cryptosuite.INTLV1); err != nil {
		t.Fatalf("initialized marker = %+v: %v", marker, err)
	}
	value, closer, err := db.Get([]byte(storageSchemaKey))
	if err != nil {
		t.Fatalf("read storage schema: %v", err)
	}
	defer closer.Close()
	stored, err := proofstoremeta.Decode(value)
	if err != nil {
		t.Fatalf("decode storage marker: %v", err)
	}
	if err := proofstoremeta.Validate(stored, cryptosuite.INTLV1); err != nil {
		t.Fatalf("stored marker = %+v: %v", stored, err)
	}
	if _, err := ensureStorageSchema(db, cryptosuite.INTLV1, "node-1", "log-1", "test"); err != nil {
		t.Fatalf("ensureStorageSchema(current) error = %v", err)
	}
	if _, err := ensureStorageSchema(db, cryptosuite.CNSMV1, "node-1", "log-1", "test"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("ensureStorageSchema(mismatch) code=%s err=%v", trusterr.CodeOf(err), err)
	}
}

func TestEnsureStorageSchemaRejectsLegacyVersion(t *testing.T) {
	db, _ := newMockTiKVDB(t, "storage-schema-legacy/")
	if err := db.Set([]byte(storageSchemaKey), []byte("trustdb-proofstore-v3"), syncWrite); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}
	if _, err := ensureStorageSchema(db, cryptosuite.INTLV1, "node-1", "log-1", "test"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("ensureStorageSchema(v3) code=%s err=%v, want failed_precondition", trusterr.CodeOf(err), err)
	}
}

func TestEnsureStorageSchemaRejectsUnversionedLegacyQueue(t *testing.T) {
	db, _ := newMockTiKVDB(t, "storage-schema-unversioned/")
	if err := db.Set([]byte("anchor/sth-outbox/00000000000000000001"), []byte("legacy"), syncWrite); err != nil {
		t.Fatalf("seed legacy queue item: %v", err)
	}
	if _, err := ensureStorageSchema(db, cryptosuite.INTLV1, "node-1", "log-1", "test"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("ensureStorageSchema(unversioned) code=%s err=%v, want failed_precondition", trusterr.CodeOf(err), err)
	}
}

func TestEnsureStorageSchemaIgnoresOtherNamespaces(t *testing.T) {
	db, _ := newMockTiKVDB(t, "storage-schema-target/")
	other := &tikvDB{client: db.client, namespace: []byte("storage-schema-other/")}
	if err := other.Set([]byte("anchor/sth-outbox/00000000000000000001"), []byte("legacy"), syncWrite); err != nil {
		t.Fatalf("seed other namespace: %v", err)
	}
	if _, err := ensureStorageSchema(db, cryptosuite.INTLV1, "node-1", "log-1", "test"); err != nil {
		t.Fatalf("ensureStorageSchema(target) error = %v", err)
	}
}

func TestEnsureStorageSchemaAcceptsConcurrentInitialization(t *testing.T) {
	db, _ := newMockTiKVDB(t, "storage-schema-concurrent/")
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := ensureStorageSchema(db, cryptosuite.INTLV1, "node-1", "log-1", "test")
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent initializer: %v", err)
		}
	}
}

func TestEnsureStorageSchemaRejectsCorruptUnknownAndConflictingMarkers(t *testing.T) {
	t.Parallel()
	t.Run("corrupt", func(t *testing.T) {
		db, _ := newMockTiKVDB(t, "storage-schema-corrupt/")
		if err := db.Set([]byte(storageSchemaKey), []byte{0xff}, syncWrite); err != nil {
			t.Fatal(err)
		}
		if _, err := ensureStorageSchema(db, cryptosuite.INTLV1, "node-1", "log-1", "test"); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
			t.Fatalf("corrupt marker code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		db, _ := newMockTiKVDB(t, "storage-schema-unknown/")
		marker, _ := proofstoremeta.New(cryptosuite.INTLV1, "node-1", "log-1", "test")
		marker.CryptoSuite = cryptosuite.ID("UNKNOWN")
		data, _ := cborx.Marshal(marker)
		if err := db.Set([]byte(storageSchemaKey), data, syncWrite); err != nil {
			t.Fatal(err)
		}
		if _, err := ensureStorageSchema(db, cryptosuite.INTLV1, "node-1", "log-1", "test"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("unknown marker code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
	t.Run("conflicting", func(t *testing.T) {
		db, _ := newMockTiKVDB(t, "storage-schema-conflicting/")
		if _, err := ensureStorageSchema(db, cryptosuite.CNSMV1, "node-1", "log-1", "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := ensureStorageSchema(db, cryptosuite.INTLV1, "node-1", "log-1", "test"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("conflicting marker code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
}

func TestGetBundleMissUsesOnePointRead(t *testing.T) {
	db, countingClient := newMockTiKVDB(t, "bundle-miss/")
	store := &Store{binding: testStoreBinding(), db: db}

	if _, err := store.GetBundle(context.Background(), "missing-record"); trusterr.CodeOf(err) != trusterr.CodeNotFound {
		t.Fatalf("GetBundle error = %v, code = %s, want %s", err, trusterr.CodeOf(err), trusterr.CodeNotFound)
	}
	if requests := countingClient.getRequests.Load(); requests != 1 {
		t.Fatalf("GetBundle point-get requests = %d, want 1", requests)
	}
}

func TestTiKVLatestAnchorCachedReferenceValidatesResultEnvelope(t *testing.T) {
	db, _ := newMockTiKVDB(t, "latest-anchor-validation/")
	store := &Store{binding: testStoreBinding(), db: db}
	ctx := context.Background()
	result := model.STHAnchorResult{CryptoSuite: "INTL_V1",
		SchemaVersion: model.SchemaSTHAnchorResult,
		EvidenceStage: model.AnchorEvidenceStageOfflineVerified,
		NodeID:        "node-1",
		LogID:         "log-1",
		TreeSize:      7,
		SinkName:      "file",
		AnchorID:      "anchor-7",
		RootHash:      bytes.Repeat([]byte{0x77}, 32),
		STH: model.SignedTreeHead{CryptoSuite: "INTL_V1",
			SchemaVersion:  model.SchemaSignedTreeHead,
			TreeAlg:        model.DefaultMerkleTreeAlg,
			TreeSize:       7,
			RootHash:       bytes.Repeat([]byte{0x77}, 32),
			TimestampUnixN: 700,
			NodeID:         "node-1",
			LogID:          "log-1",
			Signature: model.Signature{
				Alg:       model.DefaultSignatureAlg,
				KeyID:     "server-key",
				Signature: bytes.Repeat([]byte{0x77}, 64),
			},
		},
		PublishedAtUnixN: 701,
	}
	if err := store.PutSTHAnchorResult(ctx, result); err != nil {
		t.Fatalf("PutSTHAnchorResult: %v", err)
	}

	// Keep the key, root and anchor ID intact so the cached reference still
	// matches, but corrupt an STH field that the reference does not duplicate.
	corrupt := result
	corrupt.STH.TimestampUnixN = 0
	encoded, err := cborx.Marshal(corrupt)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Set(anchorResultKey(anchorschedule.ResultKey(result)), encoded, syncWrite); err != nil {
		t.Fatalf("overwrite corrupt anchor result: %v", err)
	}

	if _, _, err := store.LatestSTHAnchorResult(ctx); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("LatestSTHAnchorResult error=%v, want data loss", err)
	}
	key := model.STHAnchorScheduleKey{NodeID: result.NodeID, LogID: result.LogID, SinkName: result.SinkName}
	if _, _, err := store.LatestSTHAnchorResultForKey(ctx, key); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("LatestSTHAnchorResultForKey error=%v, want data loss", err)
	}
}

func TestTiKVGlobalPublicationChunksL4Promotions(t *testing.T) {
	db, countingClient := newMockTiKVDB(t, "global-publication-chunks/")
	store := &Store{binding: testStoreBinding(), db: db, recordIndexMode: RecordIndexModeFull}
	ctx := context.Background()
	const recordCount = batchArtifactChunkSize*2 + 17
	const batchID = "batch-global-publication-chunks"

	seed := db.NewBatch()
	defer seed.Close()
	for index := range recordCount {
		idx := model.RecordIndex{CryptoSuite: "INTL_V1",
			SchemaVersion:   model.SchemaRecordIndex,
			RecordID:        fmt.Sprintf("tr1-global-publication-%04d", index),
			ReceivedAtUnixN: int64(index + 1),
			BatchID:         batchID,
			ProofLevel:      "L3",
		}
		if err := store.stageRecordIndexSet(seed, idx); err != nil {
			t.Fatalf("stageRecordIndexSet(%d): %v", index, err)
		}
	}
	if err := seed.Commit(syncWrite); err != nil {
		t.Fatalf("seed record indexes: %v", err)
	}
	if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{CryptoSuite: "INTL_V1",
		SchemaVersion: model.SchemaGlobalLogOutbox,
		BatchID:       batchID,
		BatchRoot: model.BatchRoot{CryptoSuite: "INTL_V1",
			SchemaVersion: model.SchemaBatchRoot,
			BatchID:       batchID,
			BatchRoot:     bytes.Repeat([]byte{0x31}, 32),
			TreeSize:      recordCount,
		},
		Status: model.AnchorStatePending,
	}); err != nil {
		t.Fatalf("EnqueueGlobalLog: %v", err)
	}
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	sth := tikvPublicationSTH(key, 1, 0x41)
	candidate := model.STHAnchorCandidate{Key: key, STH: sth, ObservedAtUnixN: 100, DueAtUnixN: 200}

	countingClient.resetWriteRequests()
	if err := store.MarkGlobalLogPublishedBatchWithAnchorCandidate(ctx, []string{batchID}, []model.SignedTreeHead{sth}, candidate); err != nil {
		t.Fatalf("MarkGlobalLogPublishedBatchWithAnchorCandidate: %v", err)
	}
	transactions := countingClient.prewriteTransactions.Load()
	totalMutations := countingClient.prewriteMutations.Load()
	maxMutations := countingClient.prewriteMaxMutations.Load()
	if transactions < 5 {
		t.Fatalf("prewrite transactions = %d, want at least prepare + 3 promotion chunks + publish", transactions)
	}
	if totalMutations == 0 || maxMutations == 0 || maxMutations >= totalMutations {
		t.Fatalf("prewrite mutations total=%d max_per_request=%d, want bounded multi-transaction writes", totalMutations, maxMutations)
	}
	for _, index := range []int{0, batchArtifactChunkSize, recordCount - 1} {
		recordID := fmt.Sprintf("tr1-global-publication-%04d", index)
		got, found, err := store.GetRecordIndex(ctx, recordID)
		if err != nil || !found || model.RecordIndexProofLevel(got) != "L4" {
			t.Fatalf("GetRecordIndex(%s)=%+v found=%v err=%v", recordID, got, found, err)
		}
	}
	item, found, err := store.GetGlobalLogOutboxItem(ctx, batchID)
	if err != nil || !found || item.Status != model.AnchorStatePublished {
		t.Fatalf("global outbox item=%+v found=%v err=%v", item, found, err)
	}
	schedule, found, err := store.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || schedule.Pending == nil || schedule.Pending.Target.TreeSize != sth.TreeSize {
		t.Fatalf("anchor schedule=%+v found=%v err=%v", schedule, found, err)
	}
}

func TestTiKVGlobalPublicationPersistsIntentBeforeL4ProjectionFailure(t *testing.T) {
	db, _ := newMockTiKVDB(t, "global-publication-intent-first/")
	store := &Store{binding: testStoreBinding(), db: db, recordIndexMode: RecordIndexModeFull}
	ctx := context.Background()
	const batchID = "batch-global-publication-intent-first"
	if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{CryptoSuite: "INTL_V1",
		SchemaVersion: model.SchemaGlobalLogOutbox,
		BatchID:       batchID,
		BatchRoot: model.BatchRoot{CryptoSuite: "INTL_V1",
			SchemaVersion: model.SchemaBatchRoot,
			BatchID:       batchID,
			BatchRoot:     bytes.Repeat([]byte{0x32}, 32),
			TreeSize:      1,
		},
		Status: model.AnchorStatePending,
	}); err != nil {
		t.Fatalf("EnqueueGlobalLog: %v", err)
	}
	danglingID := "tr1-dangling-global-publication"
	danglingKey := appendRecordIndexEncodedPrefix(nil, prefixRecordByBatch, batchID, 1, danglingID)
	danglingValue := append(append([]byte(nil), recordIndexRefPrefix...), danglingID...)
	if err := db.Set(danglingKey, danglingValue, syncWrite); err != nil {
		t.Fatalf("seed dangling batch index: %v", err)
	}
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	sth := tikvPublicationSTH(key, 1, 0x42)
	candidate := model.STHAnchorCandidate{Key: key, STH: sth, ObservedAtUnixN: 100, DueAtUnixN: 200}

	err := store.MarkGlobalLogPublishedBatchWithAnchorCandidate(ctx, []string{batchID}, []model.SignedTreeHead{sth}, candidate)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("MarkGlobalLogPublishedBatchWithAnchorCandidate error=%v, want data loss", err)
	}
	schedule, found, getErr := store.GetSTHAnchorSchedule(ctx, key)
	if getErr != nil || !found || schedule.Pending == nil || schedule.Pending.Target.TreeSize != sth.TreeSize {
		t.Fatalf("durable anchor intent=%+v found=%v err=%v", schedule, found, getErr)
	}
	item, found, getErr := store.GetGlobalLogOutboxItem(ctx, batchID)
	if getErr != nil || !found || item.Status != model.AnchorStatePending {
		t.Fatalf("outbox after failed projection=%+v found=%v err=%v", item, found, getErr)
	}
}

func tikvPublicationSTH(key model.STHAnchorScheduleKey, treeSize uint64, fill byte) model.SignedTreeHead {
	return model.SignedTreeHead{CryptoSuite: "INTL_V1",
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       treeSize,
		RootHash:       bytes.Repeat([]byte{fill}, 32),
		TimestampUnixN: int64(treeSize) + 100,
		NodeID:         key.NodeID,
		LogID:          key.LogID,
		Signature: model.Signature{
			Alg:       model.DefaultSignatureAlg,
			KeyID:     "server-key",
			Signature: bytes.Repeat([]byte{fill}, 64),
		},
	}
}

func TestTiKVCheckpointPruneSafetyRequiresCompleteScope(t *testing.T) {
	t.Parallel()
	for _, store := range []*Store{nil, {}, {checkpointNodeID: "node"}, {checkpointWALID: "wal"}} {
		if store.WALCheckpointPruneSafe() {
			t.Fatalf("WALCheckpointPruneSafe() = true for incomplete scope: %+v", store)
		}
	}
	ready := &Store{binding: testStoreBinding(), checkpointNodeID: "node", checkpointWALID: "wal"}
	ready.idempotencyReady.Store(true)
	if !ready.WALCheckpointPruneSafe() {
		t.Fatal("WALCheckpointPruneSafe() = false for complete scope")
	}
}

func TestTiKVCheckpointScopesDoNotShareStateOrLegacyFallback(t *testing.T) {
	db, _ := newMockTiKVDB(t, "checkpoint-scope/")
	nodeA := &Store{binding: testStoreBinding(), db: db, checkpointNodeID: "node-a", checkpointWALID: "wal-a"}
	nodeB := &Store{binding: testStoreBinding(), db: db, checkpointNodeID: "node-b", checkpointWALID: "wal-b"}
	nodeA.idempotencyReady.Store(true)
	nodeB.idempotencyReady.Store(true)
	ctx := context.Background()

	legacy, err := cborx.Marshal(model.WALCheckpoint{CryptoSuite: "INTL_V1", LastSequence: 99})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Set([]byte("checkpoint/wal"), legacy, syncWrite); err != nil {
		t.Fatal(err)
	}
	if _, found, err := nodeA.GetCheckpoint(ctx); err != nil || found {
		t.Fatalf("nodeA legacy GetCheckpoint found=%v err=%v", found, err)
	}

	if err := nodeA.PutCheckpoint(ctx, model.WALCheckpoint{CryptoSuite: "INTL_V1", LastSequence: 7}); err != nil {
		t.Fatal(err)
	}
	if _, found, err := nodeB.GetCheckpoint(ctx); err != nil || found {
		t.Fatalf("nodeB GetCheckpoint found=%v err=%v", found, err)
	}
	got, found, err := nodeA.GetCheckpoint(ctx)
	if err != nil || !found || got.LastSequence != 7 || got.NodeID != "node-a" || got.WALID != "wal-a" {
		t.Fatalf("nodeA GetCheckpoint = %+v found=%v err=%v", got, found, err)
	}
}

func TestTiKVCheckpointNeverRegressesWithinScope(t *testing.T) {
	db, _ := newMockTiKVDB(t, "checkpoint-monotonic/")
	store := &Store{binding: testStoreBinding(), db: db, checkpointNodeID: "node", checkpointWALID: "wal"}
	store.idempotencyReady.Store(true)
	ctx := context.Background()
	if err := store.PutCheckpoint(ctx, model.WALCheckpoint{CryptoSuite: "INTL_V1", LastSequence: 12, BatchID: "new"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutCheckpoint(ctx, model.WALCheckpoint{CryptoSuite: "INTL_V1", LastSequence: 4, BatchID: "old"}); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.GetCheckpoint(ctx)
	if err != nil || !found || got.LastSequence != 12 || got.BatchID != "new" {
		t.Fatalf("GetCheckpoint = %+v found=%v err=%v", got, found, err)
	}
}

func TestTiKVIdempotencyProjectionPublishesWithCommittedManifest(t *testing.T) {
	db, _ := newMockTiKVDB(t, "idempotency-publication/")
	store := &Store{binding: testStoreBinding(), db: db, checkpointNodeID: "node", checkpointWALID: "wal"}
	ctx := context.Background()
	if err := store.EnsureIdempotencyProjection(ctx); err != nil {
		t.Fatal(err)
	}
	bundle, wantDecision := tikvIdempotencyFixture(t, "batch-idempotency")
	if err := store.PutBundle(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	prepared := model.BatchManifest{CryptoSuite: "INTL_V1",
		SchemaVersion: model.SchemaBatchManifest,
		BatchID:       "batch-idempotency",
		State:         model.BatchStatePrepared,
		TreeSize:      1,
		RecordIDs:     []string{bundle.RecordID},
	}
	if err := store.PutManifest(ctx, prepared); err != nil {
		t.Fatal(err)
	}
	committed := prepared
	committed.State = model.BatchStateCommitted
	decisions, err := store.PublishCommittedBatch(ctx, committed, []model.ProofBundle{bundle})
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 || !idempotency.Equivalent(decisions[0], wantDecision) {
		t.Fatalf("decisions=%+v, want %+v", decisions, wantDecision)
	}
	got, found, err := store.GetIdempotencyDecision(ctx, wantDecision.Identity)
	if err != nil || !found || !idempotency.Equivalent(got, wantDecision) {
		t.Fatalf("GetIdempotencyDecision=%+v found=%v err=%v", got, found, err)
	}
	manifest, err := store.GetManifest(ctx, committed.BatchID)
	if err != nil || manifest.State != model.BatchStateCommitted {
		t.Fatalf("GetManifest=%+v err=%v", manifest, err)
	}
}

func TestTiKVIdempotencyProjectionRejectsCommittedHistoryWithoutMarker(t *testing.T) {
	db, _ := newMockTiKVDB(t, "idempotency-no-compat/")
	store := &Store{binding: testStoreBinding(), db: db}
	if err := store.PutManifest(context.Background(), model.BatchManifest{CryptoSuite: "INTL_V1",
		SchemaVersion: model.SchemaBatchManifest,
		BatchID:       "old-committed",
		State:         model.BatchStateCommitted,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureIdempotencyProjection(context.Background()); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("EnsureIdempotencyProjection error=%v, want failed_precondition", err)
	}
}

func TestTiKVGenericCommitChecksSharedProjectionReadiness(t *testing.T) {
	db, _ := newMockTiKVDB(t, "idempotency-shared-readiness/")
	initializer := &Store{binding: testStoreBinding(), db: db}
	staleWriter := &Store{binding: testStoreBinding(), db: db}
	ctx := context.Background()
	if err := initializer.EnsureIdempotencyProjection(ctx); err != nil {
		t.Fatal(err)
	}
	if err := staleWriter.PutManifest(ctx, model.BatchManifest{CryptoSuite: "INTL_V1",
		SchemaVersion: model.SchemaBatchManifest,
		BatchID:       "generic-commit",
		State:         model.BatchStateCommitted,
	}); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("PutManifest(committed) error=%v, want failed_precondition", err)
	}
	if err := staleWriter.PutManifest(ctx, model.BatchManifest{CryptoSuite: "INTL_V1",
		SchemaVersion: model.SchemaBatchManifest,
		BatchID:       "prepared",
		State:         model.BatchStatePrepared,
	}); err != nil {
		t.Fatalf("PutManifest(prepared): %v", err)
	}
}

func TestTiKVProjectionInitializationFencesConcurrentGenericCommit(t *testing.T) {
	for attempt := 0; attempt < 8; attempt++ {
		db, _ := newMockTiKVDB(t, fmt.Sprintf("idempotency-fence-%d/", attempt))
		initializer := &Store{binding: testStoreBinding(), db: db}
		writer := &Store{binding: testStoreBinding(), db: db}
		start := make(chan struct{})
		var initializeErr, writeErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			initializeErr = initializer.EnsureIdempotencyProjection(context.Background())
		}()
		go func() {
			defer wg.Done()
			<-start
			writeErr = writer.PutManifest(context.Background(), model.BatchManifest{CryptoSuite: "INTL_V1",
				SchemaVersion: model.SchemaBatchManifest,
				BatchID:       "concurrent-commit",
				State:         model.BatchStateCommitted,
			})
		}()
		close(start)
		wg.Wait()
		if initializeErr == nil && writeErr == nil {
			t.Fatal("projection readiness and generic committed manifest both succeeded")
		}
	}
}

func TestTiKVPreparedManifestIndexBoundsAndTransitions(t *testing.T) {
	db, countingClient := newMockTiKVDB(t, "prepared-manifests/")
	store := &Store{binding: testStoreBinding(), db: db}
	ctx := context.Background()

	for i := range 128 {
		if err := store.PutManifest(ctx, model.BatchManifest{CryptoSuite: "INTL_V1",
			SchemaVersion: model.SchemaBatchManifest,
			BatchID:       fmt.Sprintf("committed-%03d", i),
			State:         model.BatchStateCommitted,
		}); err != nil {
			t.Fatalf("PutManifest(committed %d): %v", i, err)
		}
	}
	readyA := model.BatchManifest{CryptoSuite: "INTL_V1", SchemaVersion: model.SchemaBatchManifest, BatchID: "ready-a", NodeID: "node-a", State: model.BatchStatePrepared, MaterializeNextUnixN: 10}
	readyB := model.BatchManifest{CryptoSuite: "INTL_V1", SchemaVersion: model.SchemaBatchManifest, BatchID: "ready-b", NodeID: "node-b", State: model.BatchStatePrepared, MaterializeNextUnixN: 20}
	readyC := model.BatchManifest{CryptoSuite: "INTL_V1", SchemaVersion: model.SchemaBatchManifest, BatchID: "ready-c", NodeID: "node-a", State: model.BatchStatePrepared, MaterializeNextUnixN: 30}
	future := model.BatchManifest{CryptoSuite: "INTL_V1", SchemaVersion: model.SchemaBatchManifest, BatchID: "future", NodeID: "node-a", State: model.BatchStatePrepared, MaterializeNextUnixN: 1_000}
	for _, manifest := range []model.BatchManifest{readyC, future, readyB, readyA} {
		if err := store.PutManifest(ctx, manifest); err != nil {
			t.Fatalf("PutManifest(%s): %v", manifest.BatchID, err)
		}
	}

	countingClient.resetReadRequests()
	got, err := store.ListPreparedManifests(ctx, "node-a", 100, 10)
	if err != nil {
		t.Fatalf("ListPreparedManifests: %v", err)
	}
	if len(got) != 2 || got[0].BatchID != "ready-a" || got[1].BatchID != "ready-c" {
		t.Fatalf("prepared manifests = %#v", got)
	}
	if scans := countingClient.scanRequests.Load(); scans != 1 {
		t.Fatalf("prepared scan requests = %d, want 1 independent of committed history", scans)
	}
	if gets := countingClient.getRequests.Load(); gets != 0 {
		t.Fatalf("prepared point reads = %d, want 0", gets)
	}

	readyA.State = model.BatchStateCommitted
	if err := store.PutManifest(ctx, readyA); err != nil {
		t.Fatalf("PutManifest(commit ready-a): %v", err)
	}
	readyC.MaterializeNextUnixN = 2_000
	if err := store.PutManifest(ctx, readyC); err != nil {
		t.Fatalf("PutManifest(reschedule ready-c): %v", err)
	}
	got, err = store.ListPreparedManifests(ctx, "node-a", 100, 10)
	if err != nil {
		t.Fatalf("ListPreparedManifests(after transitions): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("prepared manifests after transitions = %#v", got)
	}
}

func TestTiKVPreparedManifestIndexFailsClosedOnMismatch(t *testing.T) {
	db, _ := newMockTiKVDB(t, "prepared-manifest-mismatch/")
	store := &Store{binding: testStoreBinding(), db: db}
	indexed := model.BatchManifest{CryptoSuite: "INTL_V1", SchemaVersion: model.SchemaBatchManifest, BatchID: "indexed", State: model.BatchStatePrepared}
	wrong := model.BatchManifest{CryptoSuite: "INTL_V1", SchemaVersion: model.SchemaBatchManifest, BatchID: "wrong", State: model.BatchStatePrepared}
	data, err := cborx.Marshal(wrong)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := db.Set(preparedManifestKey(indexed), data, syncWrite); err != nil {
		t.Fatalf("seed mismatched index: %v", err)
	}

	_, err = store.ListPreparedManifests(context.Background(), "", time.Now().UnixNano(), 10)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("ListPreparedManifests code = %s, err=%v", trusterr.CodeOf(err), err)
	}
}

func TestNormalizeNamespace(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		namespace string
		want      string
	}{
		{name: "empty defaults", namespace: "", want: "default"},
		{name: "trims whitespace", namespace: " tenant-a/log-a ", want: "tenant-a/log-a"},
		{name: "keeps unicode text", namespace: "租户/日志", want: "租户/日志"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeNamespace(tt.namespace); got != tt.want {
				t.Fatalf("NormalizeNamespace(%q) = %q, want %q", tt.namespace, got, tt.want)
			}
		})
	}
}

func TestNamespaceKeyPrefix(t *testing.T) {
	t.Parallel()

	got := namespaceKeyPrefix("tenant-a/log-a")
	wantSuffix := base64.RawURLEncoding.EncodeToString([]byte("tenant-a/log-a")) + "/"
	if wantPrefix := "trustdb/proofstore/v5/ns/"; namespacePrefix != wantPrefix || !bytes.HasPrefix(got, []byte(wantPrefix)) {
		t.Fatalf("namespace prefix %q does not start with v5 prefix %q", got, wantPrefix)
	}
	if !bytes.HasSuffix(got, []byte(wantSuffix)) {
		t.Fatalf("namespace prefix %q does not end with encoded namespace %q", got, wantSuffix)
	}
}

func TestV5NamespaceDoesNotReadV1PhysicalKeys(t *testing.T) {
	t.Parallel()

	namespace := "tenant-a/log-a"
	currentPrefix := namespaceKeyPrefix(namespace)
	db, _ := newMockTiKVDB(t, string(currentPrefix))
	encoded := base64.RawURLEncoding.EncodeToString([]byte(namespace))
	legacyKey := []byte("trustdb/proofstore/v1/ns/" + encoded + "/" + storageSchemaKey)
	if err := db.rawSet(legacyKey, []byte("legacy-marker")); err != nil {
		t.Fatalf("seed v1 physical key: %v", err)
	}
	if _, closer, err := db.Get([]byte(storageSchemaKey)); !errors.Is(err, errNotFound) {
		if err == nil {
			_ = closer.Close()
		}
		t.Fatalf("v5 namespace read v1 key: %v", err)
	}
	if _, err := ensureStorageSchema(db, cryptosuite.INTLV1, "node-v5", "log-v5", namespace); err != nil {
		t.Fatalf("initialize empty v5 namespace: %v", err)
	}
}

func TestTiKVIterPrevAdvancesExistingScanner(t *testing.T) {
	t.Parallel()

	namespace := []byte("tenant/")
	scanner := &scriptedTiKVIterator{entries: []scriptedTiKVEntry{
		{key: []byte("tenant/c"), value: []byte("three")},
		{key: []byte("tenant/b"), value: []byte("two")},
		{key: []byte("tenant/a"), value: []byte("one")},
	}}
	iter := &tikvIter{
		namespace:      namespace,
		stripNamespace: true,
		lower:          []byte("tenant/b"),
		scanner:        scanner,
		reverse:        true,
	}
	defer iter.Close()

	if !iter.captureReverse() || !bytes.Equal(iter.key, []byte("c")) {
		t.Fatalf("initial key = %q", iter.key)
	}
	if !iter.Prev() || !bytes.Equal(iter.key, []byte("b")) || !bytes.Equal(iter.value, []byte("two")) {
		t.Fatalf("previous item = key %q value %q", iter.key, iter.value)
	}
	if iter.Prev() {
		t.Fatalf("Prev crossed lower bound with key %q", iter.key)
	}
	if scanner.nextCalls != 2 {
		t.Fatalf("scanner Next calls = %d, want 2", scanner.nextCalls)
	}
	if scanner.closeCalls != 0 {
		t.Fatalf("scanner was reopened during reverse iteration: close calls = %d", scanner.closeCalls)
	}
}

func TestTiKVIterPrevPreservesScannerError(t *testing.T) {
	t.Parallel()

	wantErr := fmt.Errorf("reverse scan failed")
	scanner := &scriptedTiKVIterator{
		entries: []scriptedTiKVEntry{{key: []byte("b"), value: []byte("value")}},
		nextErr: wantErr,
	}
	iter := &tikvIter{scanner: scanner, reverse: true}
	defer iter.Close()

	if !iter.captureReverse() {
		t.Fatal("initial reverse item is invalid")
	}
	if iter.Prev() {
		t.Fatal("Prev succeeded after scanner error")
	}
	if iter.Error() != wantErr {
		t.Fatalf("iterator error = %v, want %v", iter.Error(), wantErr)
	}
}

func TestTiKVIterPrevReusesReverseScanBatches(t *testing.T) {
	db, countingClient := newMockTiKVDB(t, "reverse-scan/")

	batch := db.NewBatch()
	defer batch.Close()
	const recordCount = 1000
	for index := range recordCount {
		key := []byte(fmt.Sprintf("record/%04d", index))
		if err := batch.Set(key, key, nil); err != nil {
			t.Fatalf("Set(%d): %v", index, err)
		}
	}
	if err := batch.Commit(syncWrite); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	countingClient.resetReadRequests()

	lower, upper := prefixBounds("record/")
	iter, err := db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		t.Fatalf("NewIter: %v", err)
	}
	defer iter.Close()
	count := 0
	for ok := iter.Last(); ok; ok = iter.Prev() {
		want := fmt.Sprintf("record/%04d", recordCount-1-count)
		if string(iter.key) != want || string(iter.value) != want {
			t.Fatalf("item %d = key %q value %q, want %q", count, iter.key, iter.value, want)
		}
		count++
	}
	if err := iter.Error(); err != nil {
		t.Fatalf("iterator error: %v", err)
	}
	if count != recordCount {
		t.Fatalf("record count = %d, want %d", count, recordCount)
	}
	requests := countingClient.scanRequests.Load()
	const wantScanRequests = 4 // 1000 records at client-go's default batch size of 256.
	if requests != wantScanRequests {
		t.Fatalf("reverse scan requests = %d, want %d batched requests", requests, wantScanRequests)
	}
	t.Logf("reused the reverse scanner across %d records with %d scan requests", count, requests)

	forwardIter, err := db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		t.Fatalf("NewIter for direction switch: %v", err)
	}
	defer forwardIter.Close()
	if !forwardIter.First() || !forwardIter.Next() || string(forwardIter.key) != "record/0001" {
		t.Fatalf("forward item before Prev = %q", forwardIter.key)
	}
	if !forwardIter.Prev() || string(forwardIter.key) != "record/0000" {
		t.Fatalf("Prev after forward scan = %q, want record/0000", forwardIter.key)
	}
}

func TestListRecordIndexesBatchesReferences(t *testing.T) {
	db, countingClient := newMockTiKVDB(t, "record-list-batch/")
	store := &Store{binding: testStoreBinding(), db: db, recordIndexMode: RecordIndexModeFull}

	batch := db.NewBatch()
	defer batch.Close()
	const recordCount = 1000
	for index := range recordCount {
		idx := model.RecordIndex{CryptoSuite: "INTL_V1",
			SchemaVersion:   model.SchemaRecordIndex,
			RecordID:        fmt.Sprintf("tr1%04d", index),
			ReceivedAtUnixN: int64(index + 1),
			BatchID:         "batch-shared",
			TenantID:        fmt.Sprintf("tenant-%d", index%2),
		}
		if err := store.stageRecordIndexSet(batch, idx); err != nil {
			t.Fatalf("stageRecordIndexSet(%d): %v", index, err)
		}
	}
	if err := batch.Commit(syncWrite); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := store.ListRecordIndexes(context.Background(), model.RecordListOptions{
		Limit:     recordCount,
		Direction: model.RecordListDirectionAsc,
	}); err != nil {
		t.Fatalf("prime committed record indexes: %v", err)
	}
	for _, test := range []struct {
		name      string
		direction string
		recordID  func(int) string
	}{
		{
			name:      "ascending",
			direction: model.RecordListDirectionAsc,
			recordID:  func(index int) string { return fmt.Sprintf("tr1%04d", index) },
		},
		{
			name:      "descending",
			direction: model.RecordListDirectionDesc,
			recordID:  func(index int) string { return fmt.Sprintf("tr1%04d", recordCount-1-index) },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			countingClient.resetReadRequests()
			records, err := store.ListRecordIndexes(context.Background(), model.RecordListOptions{
				Limit:     recordCount,
				Direction: test.direction,
			})
			if err != nil {
				t.Fatalf("ListRecordIndexes: %v", err)
			}
			if len(records) != recordCount {
				t.Fatalf("record count = %d, want %d", len(records), recordCount)
			}
			for index, record := range records {
				if want := test.recordID(index); record.RecordID != want {
					t.Fatalf("record %d ID = %q, want %q", index, record.RecordID, want)
				}
			}
			if requests := countingClient.getRequests.Load(); requests != 0 {
				t.Fatalf("point-get requests = %d, want 0", requests)
			}
			if requests := countingClient.batchGetRequests.Load(); requests != 1 {
				t.Fatalf("batch-get requests = %d, want 1", requests)
			}
			if keys := countingClient.batchGetKeys.Load(); keys != recordCount {
				t.Fatalf("batch-get keys = %d, want %d", keys, recordCount)
			}
			scanVersion := countingClient.scanVersion.Load()
			batchGetVersion := countingClient.batchGetVersion.Load()
			if scanVersion == 0 || batchGetVersion != scanVersion {
				t.Fatalf("scan version = %d, batch-get version = %d; want one non-zero snapshot", scanVersion, batchGetVersion)
			}
			t.Logf("listed %d references with one batch-get at snapshot %d", len(records), scanVersion)
		})
	}

	for _, direction := range []string{model.RecordListDirectionAsc, model.RecordListDirectionDesc} {
		t.Run(direction+" narrow time range", func(t *testing.T) {
			countingClient.resetReadRequests()
			records, err := store.ListRecordIndexes(context.Background(), model.RecordListOptions{
				Limit:             recordCount,
				Direction:         direction,
				ReceivedFromUnixN: 500,
				ReceivedToUnixN:   500,
			})
			if err != nil {
				t.Fatalf("ListRecordIndexes: %v", err)
			}
			if len(records) != 1 || records[0].RecordID != "tr10499" {
				t.Fatalf("narrow time range records = %+v", records)
			}
			if keys := countingClient.batchGetKeys.Load(); keys != 1 {
				t.Fatalf("narrow time range batch-get keys = %d, want 1", keys)
			}
			if requests := countingClient.batchGetRequests.Load(); requests != 1 {
				t.Fatalf("narrow time range batch-get requests = %d, want 1", requests)
			}
		})
	}

	for _, test := range []struct {
		name string
		opts model.RecordListOptions
	}{
		{
			name: "ascending cursor beyond range",
			opts: model.RecordListOptions{
				Limit:                recordCount,
				Direction:            model.RecordListDirectionAsc,
				ReceivedToUnixN:      500,
				AfterReceivedAtUnixN: 600,
				AfterRecordID:        "tr10599",
			},
		},
		{
			name: "descending cursor beyond range",
			opts: model.RecordListOptions{
				Limit:                recordCount,
				Direction:            model.RecordListDirectionDesc,
				ReceivedFromUnixN:    500,
				AfterReceivedAtUnixN: 400,
				AfterRecordID:        "tr10399",
			},
		},
		{
			name: "inverted time range",
			opts: model.RecordListOptions{
				Limit:             recordCount,
				Direction:         model.RecordListDirectionAsc,
				ReceivedFromUnixN: 501,
				ReceivedToUnixN:   500,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			countingClient.resetReadRequests()
			records, err := store.ListRecordIndexes(context.Background(), test.opts)
			if err != nil {
				t.Fatalf("ListRecordIndexes: %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("records = %+v, want empty", records)
			}
			if scans := countingClient.scanRequests.Load(); scans != 0 {
				t.Fatalf("scan requests = %d, want 0", scans)
			}
			if batchGets := countingClient.batchGetRequests.Load(); batchGets != 0 {
				t.Fatalf("batch-get requests = %d, want 0", batchGets)
			}
		})
	}

	for _, test := range []struct {
		name      string
		direction string
		afterTime int64
		afterID   string
		want      []string
	}{
		{
			name:      "ascending composite filter",
			direction: model.RecordListDirectionAsc,
			want:      []string{"tr10000", "tr10002"},
		},
		{
			name:      "descending composite filter",
			direction: model.RecordListDirectionDesc,
			want:      []string{"tr10998", "tr10996"},
		},
		{
			name:      "ascending composite filter after cursor",
			direction: model.RecordListDirectionAsc,
			afterTime: 3,
			afterID:   "tr10002",
			want:      []string{"tr10004", "tr10006"},
		},
		{
			name:      "descending composite filter after cursor",
			direction: model.RecordListDirectionDesc,
			afterTime: 997,
			afterID:   "tr10996",
			want:      []string{"tr10994", "tr10992"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			records, err := store.ListRecordIndexes(context.Background(), model.RecordListOptions{
				Limit:                len(test.want),
				Direction:            test.direction,
				BatchID:              "batch-shared",
				TenantID:             "tenant-0",
				AfterReceivedAtUnixN: test.afterTime,
				AfterRecordID:        test.afterID,
			})
			if err != nil {
				t.Fatalf("ListRecordIndexes: %v", err)
			}
			if len(records) != len(test.want) {
				t.Fatalf("filtered record count = %d, want %d", len(records), len(test.want))
			}
			for index, record := range records {
				if record.RecordID != test.want[index] {
					t.Fatalf("filtered record %d ID = %q, want %q", index, record.RecordID, test.want[index])
				}
			}
		})
	}
}

func TestListRecordIndexesBatchGetPreservesPageBoundaryAndLegacyInline(t *testing.T) {
	db, countingClient := newMockTiKVDB(t, "record-list-legacy/")
	store := &Store{binding: testStoreBinding(), db: db, recordIndexMode: RecordIndexModeFull}
	first := model.RecordIndex{CryptoSuite: "INTL_V1",
		SchemaVersion:   model.SchemaRecordIndex,
		RecordID:        "tr1-reference",
		ReceivedAtUnixN: 1,
	}
	legacy := model.RecordIndex{CryptoSuite: "INTL_V1",
		SchemaVersion:   model.SchemaRecordIndex,
		RecordID:        "tr2-legacy-inline",
		ReceivedAtUnixN: 2,
	}
	legacyValue, err := cborx.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy record index: %v", err)
	}

	batch := db.NewBatch()
	defer batch.Close()
	if err := store.stageRecordIndexSet(batch, first); err != nil {
		t.Fatalf("stage first record index: %v", err)
	}
	if err := batch.Set(recordIndexKey(prefixRecordByTime, legacy.ReceivedAtUnixN, legacy.RecordID), legacyValue, nil); err != nil {
		t.Fatalf("stage legacy record index: %v", err)
	}
	if err := stageRecordIndexRef(batch, recordIndexKey(prefixRecordByTime, 3, "tr3-missing"), "tr3-missing"); err != nil {
		t.Fatalf("stage dangling record index reference: %v", err)
	}
	if err := batch.Commit(syncWrite); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := store.ListRecordIndexes(context.Background(), model.RecordListOptions{
		Limit:     2,
		Direction: model.RecordListDirectionAsc,
	}); err != nil {
		t.Fatalf("prime committed record indexes: %v", err)
	}
	countingClient.resetReadRequests()
	cancelCtx, cancel := context.WithCancel(context.Background())
	countingClient.batchGetHook = cancel
	_, cancelErr := store.ListRecordIndexes(cancelCtx, model.RecordListOptions{
		Limit:     1,
		Direction: model.RecordListDirectionAsc,
	})
	countingClient.batchGetHook = nil
	cancel()
	if trusterr.CodeOf(cancelErr) != trusterr.CodeDeadlineExceeded {
		t.Fatalf("canceled BatchGet error code = %s, want %s", trusterr.CodeOf(cancelErr), trusterr.CodeDeadlineExceeded)
	}
	countingClient.resetReadRequests()

	records, err := store.ListRecordIndexes(context.Background(), model.RecordListOptions{
		Limit:     2,
		Direction: model.RecordListDirectionAsc,
	})
	if err != nil {
		t.Fatalf("ListRecordIndexes(limit=2): %v", err)
	}
	if len(records) != 2 || records[0].RecordID != first.RecordID || records[1].RecordID != legacy.RecordID {
		t.Fatalf("ListRecordIndexes(limit=2) = %+v", records)
	}
	if keys := countingClient.batchGetKeys.Load(); keys != 1 {
		t.Fatalf("page batch-get keys = %d, want 1 without fetching the next page", keys)
	}
	if requests := countingClient.batchGetRequests.Load(); requests != 1 {
		t.Fatalf("page batch-get requests = %d, want 1", requests)
	}
	if requests := countingClient.getRequests.Load(); requests != 0 {
		t.Fatalf("page point-get requests = %d, want 0", requests)
	}

	countingClient.resetReadRequests()
	if _, err := store.ListRecordIndexes(context.Background(), model.RecordListOptions{
		Limit:     3,
		Direction: model.RecordListDirectionAsc,
	}); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("ListRecordIndexes(limit=3) error code = %s, want %s", trusterr.CodeOf(err), trusterr.CodeDataLoss)
	}
}

func newMockTiKVDB(t *testing.T, namespace string) (*tikvDB, *countingTiKVClient) {
	t.Helper()
	client, cluster, pdClient, err := testutils.NewMockTiKV("", nil)
	if err != nil {
		t.Fatalf("NewMockTiKV: %v", err)
	}
	testutils.BootstrapWithSingleStore(cluster)
	countingClient := &countingTiKVClient{}
	kvStore, err := tikvclient.NewTestTiKVStore(client, pdClient, func(client tikvclient.Client) tikvclient.Client {
		countingClient.Client = client
		return countingClient
	}, nil, 0)
	if err != nil {
		t.Fatalf("NewTestTiKVStore: %v", err)
	}
	txnClient := &txnkv.Client{KVStore: kvStore}
	t.Cleanup(func() {
		if err := txnClient.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return &tikvDB{client: txnClient, namespace: []byte(namespace)}, countingClient
}

type scriptedTiKVEntry struct {
	key   []byte
	value []byte
}

type scriptedTiKVIterator struct {
	entries    []scriptedTiKVEntry
	index      int
	nextCalls  int
	closeCalls int
	nextErr    error
	closed     bool
}

type countingTiKVClient struct {
	tikvclient.Client
	scanRequests         atomic.Int64
	getRequests          atomic.Int64
	batchGetRequests     atomic.Int64
	batchGetKeys         atomic.Int64
	batchGetMaxKeys      atomic.Int64
	prewriteRequests     atomic.Int64
	prewriteMutations    atomic.Int64
	prewriteMaxMutations atomic.Int64
	prewriteTransactions atomic.Int64
	prewriteVersions     sync.Map
	scanVersion          atomic.Uint64
	batchGetVersion      atomic.Uint64
	readVersionDrift     atomic.Bool
	batchGetHook         func()
	getHook              func()
}

func (client *countingTiKVClient) SendRequest(ctx context.Context, address string, request *tikvrpc.Request, timeout time.Duration) (*tikvrpc.Response, error) {
	switch request.Type {
	case tikvrpc.CmdScan:
		client.scanRequests.Add(1)
		client.scanVersion.Store(request.Scan().Version)
	case tikvrpc.CmdGet:
		client.getRequests.Add(1)
		if client.getHook != nil {
			client.getHook()
		}
	case tikvrpc.CmdBatchGet:
		client.batchGetRequests.Add(1)
		keyCount := int64(len(request.BatchGet().Keys))
		client.batchGetKeys.Add(keyCount)
		for current := client.batchGetMaxKeys.Load(); keyCount > current; current = client.batchGetMaxKeys.Load() {
			if client.batchGetMaxKeys.CompareAndSwap(current, keyCount) {
				break
			}
		}
		batchGetVersion := request.BatchGet().Version
		if previous := client.batchGetVersion.Load(); previous != 0 && previous != batchGetVersion {
			client.readVersionDrift.Store(true)
		}
		client.batchGetVersion.Store(batchGetVersion)
		if scanVersion := client.scanVersion.Load(); scanVersion != 0 && scanVersion != batchGetVersion {
			client.readVersionDrift.Store(true)
		}
		if client.batchGetHook != nil {
			client.batchGetHook()
		}
	case tikvrpc.CmdPrewrite:
		client.prewriteRequests.Add(1)
		mutationCount := int64(len(request.Prewrite().Mutations))
		client.prewriteMutations.Add(mutationCount)
		for current := client.prewriteMaxMutations.Load(); mutationCount > current; current = client.prewriteMaxMutations.Load() {
			if client.prewriteMaxMutations.CompareAndSwap(current, mutationCount) {
				break
			}
		}
		if _, loaded := client.prewriteVersions.LoadOrStore(request.Prewrite().StartVersion, struct{}{}); !loaded {
			client.prewriteTransactions.Add(1)
		}
	}
	return client.Client.SendRequest(ctx, address, request, timeout)
}

func (client *countingTiKVClient) resetWriteRequests() {
	client.prewriteRequests.Store(0)
	client.prewriteMutations.Store(0)
	client.prewriteMaxMutations.Store(0)
	client.prewriteTransactions.Store(0)
	client.prewriteVersions.Range(func(key, _ any) bool {
		client.prewriteVersions.Delete(key)
		return true
	})
}

func (client *countingTiKVClient) resetReadRequests() {
	client.scanRequests.Store(0)
	client.getRequests.Store(0)
	client.batchGetRequests.Store(0)
	client.batchGetKeys.Store(0)
	client.batchGetMaxKeys.Store(0)
	client.scanVersion.Store(0)
	client.batchGetVersion.Store(0)
	client.readVersionDrift.Store(false)
}

func (it *scriptedTiKVIterator) Valid() bool {
	return it != nil && !it.closed && it.index >= 0 && it.index < len(it.entries)
}

func (it *scriptedTiKVIterator) Key() []byte {
	if !it.Valid() {
		return nil
	}
	return it.entries[it.index].key
}

func (it *scriptedTiKVIterator) Value() []byte {
	if !it.Valid() {
		return nil
	}
	return it.entries[it.index].value
}

func (it *scriptedTiKVIterator) Next() error {
	it.nextCalls++
	if it.nextErr != nil {
		return it.nextErr
	}
	it.index++
	return nil
}

func (it *scriptedTiKVIterator) Close() {
	it.closeCalls++
	it.closed = true
}

func TestDeferredSetFinishTransfersBuffers(t *testing.T) {
	t.Parallel()

	db := &tikvDB{namespace: namespaceKeyPrefix("test")}
	batch := &tikvBatch{db: db}
	op := batch.SetDeferred(3, 5)
	copy(op.Key, "key")
	copy(op.Value, "value")
	if err := op.Finish(); err != nil {
		t.Fatal(err)
	}
	if len(batch.ops) != 1 {
		t.Fatalf("ops = %d, want 1", len(batch.ops))
	}
	wantKey := append(append([]byte(nil), db.namespace...), "key"...)
	if !bytes.Equal(batch.ops[0].key, wantKey) || !bytes.Equal(batch.ops[0].value, []byte("value")) {
		t.Fatalf("staged op = key %q value %q", batch.ops[0].key, batch.ops[0].value)
	}
	if &batch.ops[0].value[0] != &op.Value[0] {
		t.Fatal("deferred value was copied instead of transferred")
	}
	if &batch.ops[0].key[len(db.namespace)] != &op.Key[0] {
		t.Fatal("deferred logical key was copied instead of embedded in the physical key")
	}

	raw := &tikvBatch{db: db, raw: true}
	rawOp := raw.SetDeferred(3, 5)
	copy(rawOp.Key, "key")
	copy(rawOp.Value, "value")
	if err := rawOp.Finish(); err != nil {
		t.Fatal(err)
	}
	if &raw.ops[0].key[0] != &rawOp.Key[0] || &raw.ops[0].value[0] != &rawOp.Value[0] {
		t.Fatal("raw deferred buffers were copied instead of transferred")
	}
}

func TestEncodeBatchArtifactIntoMatchesWrapper(t *testing.T) {
	t.Parallel()

	bundle := syntheticTiKVProofBundles(1)[0]
	want, err := encodeBatchArtifact(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer want.release()
	var got encodedBatchArtifact
	if err := encodeBatchArtifactInto(&got, &bundle); err != nil {
		t.Fatal(err)
	}
	defer got.release()
	if got.recordID != want.recordID || !bytes.Equal(got.bundleValue, want.bundleValue) {
		t.Fatal("direct batch artifact bundle differs from wrapper")
	}
	if got.index.idx.RecordID != want.index.idx.RecordID || !bytes.Equal(got.index.value, want.index.value) {
		t.Fatal("direct batch artifact record index differs from wrapper")
	}
}

func TestDecodeStoredProofBundleRejectsInvalidEnvelopePayloads(t *testing.T) {
	t.Parallel()

	oversized := make([]byte, binary.MaxVarintLen64)
	oversized = oversized[:binary.PutUvarint(oversized, uint64(maxStoredObjectBytes+1))]
	tests := []struct {
		name     string
		envelope storedProofBundleEnvelope
	}{
		{name: "unsupported codec", envelope: storedProofBundleEnvelope{SchemaVersion: schemaStoredProofBundleV2, Codec: "unknown"}},
		{name: "corrupt snappy", envelope: storedProofBundleEnvelope{SchemaVersion: schemaStoredProofBundleV2, Codec: storedBundleCodecSnappy, Data: []byte{0xff}}},
		{name: "oversized decoded payload", envelope: storedProofBundleEnvelope{SchemaVersion: schemaStoredProofBundleV2, Codec: storedBundleCodecSnappy, Data: oversized}},
		{name: "malformed decoded cbor", envelope: storedProofBundleEnvelope{SchemaVersion: schemaStoredProofBundleV2, Codec: storedBundleCodecSnappy, Data: snappy.Encode(nil, []byte{0xff})}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := cborx.Marshal(tt.envelope)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeStoredProofBundle(data); err == nil {
				t.Fatal("decodeStoredProofBundle error = nil")
			}
		})
	}
}

func BenchmarkTiKVEncodeBatchArtifacts1024(b *testing.B) {
	bundles := syntheticTiKVProofBundles(1024)
	b.ReportAllocs()
	for b.Loop() {
		artifacts, err := encodeBatchArtifacts(context.Background(), bundles)
		if err != nil {
			b.Fatal(err)
		}
		releaseBatchArtifacts(artifacts)
	}
}

func BenchmarkTiKVStageDeferredSets1024(b *testing.B) {
	db := &tikvDB{namespace: namespaceKeyPrefix("bench")}
	key := []byte("bundle-v2/tr1-bench-record")
	value := bytes.Repeat([]byte{1}, 1024)
	b.ReportAllocs()
	for b.Loop() {
		batch := &tikvBatch{db: db}
		for range 1024 {
			if err := stageSet(batch, key, value); err != nil {
				b.Fatal(err)
			}
		}
		_ = batch.Close()
	}
}

func BenchmarkTiKVDecodeStoredProofBundleV2(b *testing.B) {
	bundle := syntheticTiKVProofBundles(1)[0]
	for i := range 256 {
		bundle.BatchProof.AuditPath = append(bundle.BatchProof.AuditPath, bytes.Repeat([]byte{byte(i % 8)}, 32))
	}
	data, buf, err := encodeStoredProofBundle(&bundle)
	if err != nil {
		b.Fatal(err)
	}
	defer putArtifactBuffer(buf)
	var envelope storedProofBundleEnvelope
	if err := cborx.UnmarshalLimit(data, &envelope, maxStoredObjectBytes); err != nil {
		b.Fatal(err)
	}
	if envelope.Codec != storedBundleCodecSnappy {
		b.Fatalf("codec = %q, want %q", envelope.Codec, storedBundleCodecSnappy)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		got, err := decodeStoredProofBundle(data)
		if err != nil {
			b.Fatal(err)
		}
		if got.RecordID != bundle.RecordID {
			b.Fatalf("record_id = %q, want %q", got.RecordID, bundle.RecordID)
		}
	}
}

func tikvIdempotencyFixture(t testing.TB, batchID string) (model.ProofBundle, model.IdempotencyDecision) {
	t.Helper()
	clientClaim := model.ClientClaim{CryptoSuite: "INTL_V1",
		SchemaVersion:   model.SchemaClientClaim,
		TenantID:        "tenant-a",
		ClientID:        "client-a",
		KeyID:           "client-key",
		ProducedAtUnixN: 10,
		Nonce:           bytes.Repeat([]byte{1}, 16),
		IdempotencyKey:  "idem-a",
		Content: model.Content{
			HashAlg:       model.DefaultHashAlg,
			ContentHash:   bytes.Repeat([]byte{2}, 32),
			ContentLength: 1,
		},
	}
	canonical, err := claim.Canonical(clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	signed := model.SignedClaim{CryptoSuite: "INTL_V1",
		SchemaVersion: model.SchemaSignedClaim,
		Claim:         clientClaim,
		Signature: model.Signature{
			Alg:       model.DefaultSignatureAlg,
			KeyID:     clientClaim.KeyID,
			Signature: bytes.Repeat([]byte{3}, 64),
		},
	}
	claimHash, _ := trustcrypto.HashBytes(model.DefaultHashAlg, canonical)
	signatureHash, _ := trustcrypto.HashBytes(model.DefaultHashAlg, signed.Signature.Signature)
	position := model.WALPosition{SegmentID: 1, Offset: 64, Sequence: 1}
	record := model.ServerRecord{CryptoSuite: "INTL_V1",
		SchemaVersion:       model.SchemaServerRecord,
		RecordID:            claim.RecordID(canonical, signed.Signature),
		TenantID:            clientClaim.TenantID,
		ClientID:            clientClaim.ClientID,
		KeyID:               clientClaim.KeyID,
		ClaimHash:           claimHash,
		ClientSignatureHash: signatureHash,
		ReceivedAtUnixN:     20,
		WAL:                 position,
	}
	accepted := model.AcceptedReceipt{CryptoSuite: "INTL_V1",
		SchemaVersion:   model.SchemaAcceptedReceipt,
		RecordID:        record.RecordID,
		Status:          "accepted",
		ServerID:        "node",
		ReceivedAtUnixN: record.ReceivedAtUnixN,
		WAL:             position,
		ServerSig: model.Signature{
			Alg:       model.DefaultSignatureAlg,
			KeyID:     "server-key",
			Signature: bytes.Repeat([]byte{4}, 64),
		},
	}
	decision, err := idempotency.BuildDecision(batchID, signed, record, accepted)
	if err != nil {
		t.Fatal(err)
	}
	bundle := model.ProofBundle{CryptoSuite: "INTL_V1",
		SchemaVersion:   model.SchemaProofBundle,
		RecordID:        record.RecordID,
		SignedClaim:     signed,
		ServerRecord:    record,
		AcceptedReceipt: accepted,
		CommittedReceipt: model.CommittedReceipt{CryptoSuite: "INTL_V1",
			SchemaVersion: model.SchemaCommittedReceipt,
			RecordID:      record.RecordID,
			Status:        "committed",
			BatchID:       batchID,
			LeafIndex:     0,
		},
		BatchProof: model.BatchProof{TreeAlg: model.DefaultMerkleTreeAlg, LeafIndex: 0, TreeSize: 1},
	}
	return bundle, decision
}

func syntheticTiKVProofBundles(n int) []model.ProofBundle {
	bundles := make([]model.ProofBundle, n)
	for i := range bundles {
		recordID := fmt.Sprintf("bench-record-%04d", i)
		bundles[i] = model.ProofBundle{CryptoSuite: "INTL_V1",
			SchemaVersion: model.SchemaProofBundle,
			RecordID:      recordID,
			SignedClaim: model.SignedClaim{CryptoSuite: "INTL_V1",
				SchemaVersion: model.SchemaSignedClaim,
				Claim: model.ClientClaim{CryptoSuite: "INTL_V1",
					SchemaVersion: model.SchemaClientClaim,
					TenantID:      "bench-tenant",
					ClientID:      "bench-client",
					KeyID:         "bench-key",
					Content: model.Content{
						HashAlg:       model.DefaultHashAlg,
						ContentHash:   bytes.Repeat([]byte{byte(i % 251)}, 32),
						ContentLength: 1024,
						StorageURI:    "bench://" + recordID,
					},
					Metadata: model.Metadata{EventType: "bench.synthetic"},
				},
			},
			ServerRecord: model.ServerRecord{CryptoSuite: "INTL_V1",
				SchemaVersion:   model.SchemaServerRecord,
				RecordID:        recordID,
				TenantID:        "bench-tenant",
				ClientID:        "bench-client",
				KeyID:           "bench-key",
				ReceivedAtUnixN: int64(1_000 + i),
				WAL:             model.WALPosition{SegmentID: 1, Offset: int64(i * 512), Sequence: uint64(i + 1)},
			},
			CommittedReceipt: model.CommittedReceipt{CryptoSuite: "INTL_V1",
				SchemaVersion: model.SchemaCommittedReceipt,
				RecordID:      recordID,
				BatchID:       "bench-batch",
				LeafIndex:     uint64(i),
				BatchRoot:     bytes.Repeat([]byte{1}, 32),
				ClosedAtUnixN: 1_000,
			},
			BatchProof: model.BatchProof{
				TreeAlg:   model.DefaultMerkleTreeAlg,
				LeafIndex: uint64(i),
				TreeSize:  uint64(n),
				AuditPath: [][]byte{bytes.Repeat([]byte{byte((i + 1) % 251)}, 32)},
			},
		}
	}
	return bundles
}
