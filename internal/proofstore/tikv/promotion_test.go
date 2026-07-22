package tikv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestStageRecordIndexPromotionMutationCounts(t *testing.T) {
	t.Parallel()

	const namespace = "promotion-count/"
	store := &Store{
		db:              &tikvDB{namespace: []byte(namespace)},
		recordIndexMode: RecordIndexModeFull,
	}
	for _, test := range []struct {
		name            string
		idx             model.RecordIndex
		wantTokens      int
		wantSpecialized int
		wantFullReplace int
	}{
		{name: "without storage tokens", idx: promotionRecordIndex(false), wantTokens: 0, wantSpecialized: 8, wantFullReplace: 14},
		{name: "with maximum storage tokens", idx: promotionRecordIndex(true), wantTokens: 64, wantSpecialized: 72, wantFullReplace: 142},
	} {
		t.Run(test.name, func(t *testing.T) {
			next := test.idx
			next.ProofLevel = "L4"
			tokenCount := len(model.RecordIndexStorageTokens(test.idx))
			if tokenCount != test.wantTokens {
				t.Fatalf("storage token count = %d, want %d", tokenCount, test.wantTokens)
			}

			batch := store.db.NewBatch()
			if err := store.stageRecordIndexPromotion(batch, recordIndexPromotion{old: test.idx, next: next}); err != nil {
				t.Fatalf("stageRecordIndexPromotion: %v", err)
			}
			if got := len(batch.ops); got != test.wantSpecialized {
				t.Fatalf("specialized mutation count = %d, want %d", got, test.wantSpecialized)
			}
			assertTiKVPromotionCoreOps(t, batch.ops, []byte(namespace), test.idx, next)

			batch = store.db.NewBatch()
			if err := store.stageRecordIndexPromotion(batch, recordIndexPromotion{old: test.idx, next: next, replaceAll: true}); err != nil {
				t.Fatalf("stage legacy promotion: %v", err)
			}
			if got := len(batch.ops); got != test.wantFullReplace {
				t.Fatalf("full replacement mutation count = %d, want %d", got, test.wantFullReplace)
			}
		})
	}

	rich := promotionRecordIndex(true)
	next := rich
	next.ProofLevel = "L4"
	for _, test := range []struct {
		mode string
		want int
	}{
		{mode: RecordIndexModeNoStorageTokens, want: 78},
		{mode: RecordIndexModeTimeOnly, want: 73},
	} {
		t.Run(test.mode+" fallback", func(t *testing.T) {
			store.recordIndexMode = test.mode
			batch := store.db.NewBatch()
			if err := store.stageRecordIndexPromotion(batch, recordIndexPromotion{old: rich, next: next}); err != nil {
				t.Fatalf("stageRecordIndexPromotion: %v", err)
			}
			if got := len(batch.ops); got != test.want {
				t.Fatalf("fallback mutation count = %d, want %d", got, test.want)
			}
		})
	}
}

func TestCollectRecordIndexPromotionsBatchGetsScanSnapshot(t *testing.T) {
	for _, test := range []struct {
		name         string
		count        int
		wantRequests int64
	}{
		{name: "default batch", count: promotionReferenceBatchSize, wantRequests: 1},
		{name: "crosses read boundary", count: promotionReferenceBatchSize + 1, wantRequests: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, reads := newMockTiKVDB(t, "promotion-batch-get-"+strings.ReplaceAll(test.name, " ", "-")+"/")
			store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
			records := seedPromotionReferences(t, store, "batch-read-count", test.count, -1)
			if _, err := store.collectRecordIndexPromotions(context.Background(), records[0].BatchID, "L4"); err != nil {
				t.Fatalf("prime committed record indexes: %v", err)
			}
			reads.resetReadRequests()

			updates, err := store.collectRecordIndexPromotions(context.Background(), records[0].BatchID, "L4")
			if err != nil {
				t.Fatalf("collectRecordIndexPromotions: %v", err)
			}
			if len(updates) != len(records) {
				t.Fatalf("promotion count = %d, want %d", len(updates), len(records))
			}
			for index, update := range updates {
				if update.old.RecordID != records[index].RecordID {
					t.Fatalf("promotion %d record ID = %q, want %q", index, update.old.RecordID, records[index].RecordID)
				}
				if update.next.ProofLevel != "L4" || update.replaceAll {
					t.Fatalf("promotion %d = level %q replaceAll=%v", index, update.next.ProofLevel, update.replaceAll)
				}
			}
			if requests := reads.getRequests.Load(); requests != 0 {
				t.Fatalf("point-get requests = %d, want 0 (batch-get requests=%d keys=%d scan requests=%d)", requests, reads.batchGetRequests.Load(), reads.batchGetKeys.Load(), reads.scanRequests.Load())
			}
			if requests := reads.batchGetRequests.Load(); requests != test.wantRequests {
				t.Fatalf("batch-get requests = %d, want %d", requests, test.wantRequests)
			}
			if keys := reads.batchGetKeys.Load(); keys != int64(test.count) {
				t.Fatalf("batch-get keys = %d, want %d", keys, test.count)
			}
			if keys := reads.batchGetMaxKeys.Load(); keys != promotionReferenceBatchSize {
				t.Fatalf("maximum batch-get keys = %d, want %d", keys, promotionReferenceBatchSize)
			}
			if reads.scanRequests.Load() == 0 {
				t.Fatal("scan requests = 0, want at least 1")
			}
			if scanVersion, batchGetVersion := reads.scanVersion.Load(), reads.batchGetVersion.Load(); scanVersion == 0 || scanVersion != batchGetVersion {
				t.Fatalf("scan version = %d, batch-get version = %d", scanVersion, batchGetVersion)
			}
			if reads.readVersionDrift.Load() {
				t.Fatal("at least one batch-get request used a different version from the scan")
			}
		})
	}
}

func TestCollectRecordIndexPromotionsPreservesMixedOrderAndDuplicates(t *testing.T) {
	db, reads := newMockTiKVDB(t, "promotion-mixed-read/")
	store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
	const batchID = "batch-mixed-read"
	first := minimalPromotionRecordIndex(batchID, 1)
	inline := minimalPromotionRecordIndex(batchID, 2)
	third := minimalPromotionRecordIndex(batchID, 3)

	batch := db.NewBatch()
	defer batch.Close()
	stagePromotionReference(t, batch, first, true)
	inlineValue, err := cborx.Marshal(inline)
	if err != nil {
		t.Fatalf("marshal inline record index: %v", err)
	}
	if err := batch.Set(promotionBatchIndexKey(inline), inlineValue, nil); err != nil {
		t.Fatalf("stage inline record index: %v", err)
	}
	stagePromotionReference(t, batch, third, true)
	for ordinal := 4; ordinal <= 5; ordinal++ {
		aliasKey := appendRecordIndexEncodedPrefix(nil, prefixRecordByBatch, batchID, int64(ordinal), fmt.Sprintf("alias-%d", ordinal))
		if err := stageRecordIndexRef(batch, aliasKey, first.RecordID); err != nil {
			t.Fatalf("stage duplicate reference: %v", err)
		}
	}
	if err := batch.Commit(syncWrite); err != nil {
		t.Fatalf("commit mixed record indexes: %v", err)
	}
	if _, err := store.collectRecordIndexPromotions(context.Background(), batchID, "L4"); err != nil {
		t.Fatalf("prime committed record indexes: %v", err)
	}
	reads.resetReadRequests()

	updates, err := store.collectRecordIndexPromotions(context.Background(), batchID, "L4")
	if err != nil {
		t.Fatalf("collectRecordIndexPromotions: %v", err)
	}
	wantIDs := []string{first.RecordID, inline.RecordID, third.RecordID, first.RecordID, first.RecordID}
	wantReplaceAll := []bool{false, true, false, false, false}
	if len(updates) != len(wantIDs) {
		t.Fatalf("promotion count = %d, want %d", len(updates), len(wantIDs))
	}
	for index, update := range updates {
		if update.old.RecordID != wantIDs[index] || update.replaceAll != wantReplaceAll[index] {
			t.Fatalf("promotion %d = ID %q replaceAll=%v, want ID %q replaceAll=%v", index, update.old.RecordID, update.replaceAll, wantIDs[index], wantReplaceAll[index])
		}
	}
	if requests := reads.getRequests.Load(); requests != 0 {
		t.Fatalf("point-get requests = %d, want 0", requests)
	}
	if requests := reads.batchGetRequests.Load(); requests != 2 {
		t.Fatalf("batch-get requests = %d, want 2 reference runs", requests)
	}
	if scanVersion, batchGetVersion := reads.scanVersion.Load(), reads.batchGetVersion.Load(); scanVersion == 0 || scanVersion != batchGetVersion {
		t.Fatalf("scan version = %d, batch-get version = %d", scanVersion, batchGetVersion)
	}
	if reads.readVersionDrift.Load() {
		t.Fatal("at least one batch-get request used a different version from the scan")
	}
}

func TestPromoteBatchRecordsBatchesReadAndTransactionGuard(t *testing.T) {
	db, reads := newMockTiKVDB(t, "promotion-read-and-guard/")
	store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
	records := seedPromotionReferences(t, store, "batch-read-and-guard", promotionReferenceBatchSize, -1)
	if _, err := store.collectRecordIndexPromotions(context.Background(), records[0].BatchID, "L4"); err != nil {
		t.Fatalf("prime committed record indexes: %v", err)
	}
	reads.resetReadRequests()

	if err := store.promoteBatchRecords(context.Background(), records[0].BatchID, "L4"); err != nil {
		t.Fatalf("promoteBatchRecords: %v", err)
	}
	if requests := reads.getRequests.Load(); requests != 0 {
		t.Fatalf("point-get requests = %d, want 0", requests)
	}
	if requests := reads.batchGetRequests.Load(); requests != 2 {
		t.Fatalf("batch-get requests = %d, want 2 (scan read and transaction guard)", requests)
	}
	if keys := reads.batchGetKeys.Load(); keys != 2*promotionReferenceBatchSize {
		t.Fatalf("batch-get keys = %d, want %d", keys, 2*promotionReferenceBatchSize)
	}
	if keys := reads.batchGetMaxKeys.Load(); keys != promotionReferenceBatchSize {
		t.Fatalf("maximum batch-get keys = %d, want %d", keys, promotionReferenceBatchSize)
	}
	if scans := reads.scanRequests.Load(); scans != 5 {
		t.Fatalf("scan requests = %d, want 5", scans)
	}
	assertRecordProofLevel(t, store, records[0].RecordID, "L4")
	assertRecordProofLevel(t, store, records[len(records)-1].RecordID, "L4")
}

func TestPromoteBatchRecordsReadFailuresDoNotCommit(t *testing.T) {
	t.Run("missing reference in later read batch", func(t *testing.T) {
		db, reads := newMockTiKVDB(t, "promotion-missing-ref/")
		store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
		records := seedPromotionReferences(t, store, "batch-missing-ref", promotionReferenceBatchSize+1, promotionReferenceBatchSize)
		_, _ = store.collectRecordIndexPromotions(context.Background(), records[0].BatchID, "L4")
		reads.resetReadRequests()

		err := store.promoteBatchRecords(context.Background(), records[0].BatchID, "L4")
		if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
			t.Fatalf("promoteBatchRecords error code = %s, want %s", trusterr.CodeOf(err), trusterr.CodeDataLoss)
		}
		if requests := reads.getRequests.Load(); requests != 0 {
			t.Fatalf("point-get requests = %d, want 0 (batch-get requests=%d keys=%d scan requests=%d)", requests, reads.batchGetRequests.Load(), reads.batchGetKeys.Load(), reads.scanRequests.Load())
		}
		if requests := reads.batchGetRequests.Load(); requests != 2 {
			t.Fatalf("batch-get requests = %d, want 2", requests)
		}
		if keys := reads.batchGetKeys.Load(); keys != promotionReferenceBatchSize+1 {
			t.Fatalf("batch-get keys = %d, want %d", keys, promotionReferenceBatchSize+1)
		}
		if keys := reads.batchGetMaxKeys.Load(); keys > promotionReferenceBatchSize {
			t.Fatalf("maximum batch-get keys = %d, want at most %d", keys, promotionReferenceBatchSize)
		}
		if reads.readVersionDrift.Load() {
			t.Fatal("at least one batch-get request used a different version from the scan")
		}
		assertRecordProofLevel(t, store, records[0].RecordID, "L3")
	})

	t.Run("malformed referenced primary", func(t *testing.T) {
		db, reads := newMockTiKVDB(t, "promotion-malformed-primary/")
		store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
		records := seedPromotionReferences(t, store, "batch-malformed-primary", 2, -1)
		if err := db.Set(recordByIDKey(records[1].RecordID), []byte{0xff}, syncWrite); err != nil {
			t.Fatalf("write malformed primary: %v", err)
		}
		_, _ = store.collectRecordIndexPromotions(context.Background(), records[0].BatchID, "L4")
		reads.resetReadRequests()

		err := store.promoteBatchRecords(context.Background(), records[0].BatchID, "L4")
		if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
			t.Fatalf("promoteBatchRecords error code = %s, want %s", trusterr.CodeOf(err), trusterr.CodeDataLoss)
		}
		if requests := reads.getRequests.Load(); requests != 0 {
			t.Fatalf("point-get requests = %d, want 0", requests)
		}
		assertRecordProofLevel(t, store, records[0].RecordID, "L3")
	})

	t.Run("malformed legacy inline value", func(t *testing.T) {
		db, reads := newMockTiKVDB(t, "promotion-malformed-inline/")
		store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
		records := seedPromotionReferences(t, store, "batch-malformed-inline", 1, -1)
		malformedKey := appendRecordIndexEncodedPrefix(nil, prefixRecordByBatch, records[0].BatchID, 2, "malformed-inline")
		if err := db.Set(malformedKey, []byte{0xff}, syncWrite); err != nil {
			t.Fatalf("write malformed inline value: %v", err)
		}
		_, _ = store.collectRecordIndexPromotions(context.Background(), records[0].BatchID, "L4")
		reads.resetReadRequests()

		err := store.promoteBatchRecords(context.Background(), records[0].BatchID, "L4")
		if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
			t.Fatalf("promoteBatchRecords error code = %s, want %s", trusterr.CodeOf(err), trusterr.CodeDataLoss)
		}
		if requests := reads.getRequests.Load(); requests != 0 {
			t.Fatalf("point-get requests = %d, want 0", requests)
		}
		assertRecordProofLevel(t, store, records[0].RecordID, "L3")
	})

	t.Run("pre-canceled context", func(t *testing.T) {
		db, reads := newMockTiKVDB(t, "promotion-pre-canceled-read/")
		store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
		records := seedPromotionReferences(t, store, "batch-pre-canceled-read", 1, -1)
		if _, err := store.collectRecordIndexPromotions(context.Background(), records[0].BatchID, "L4"); err != nil {
			t.Fatalf("prime committed record indexes: %v", err)
		}
		reads.resetReadRequests()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := store.promoteBatchRecords(ctx, records[0].BatchID, "L4")
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("promoteBatchRecords error = %v, want wrapped context cancellation", err)
		}
		if scans := reads.scanRequests.Load(); scans != 0 {
			t.Fatalf("scan requests = %d, want 0", scans)
		}
		if gets := reads.getRequests.Load(); gets != 0 {
			t.Fatalf("point-get requests = %d, want 0", gets)
		}
		if batchGets := reads.batchGetRequests.Load(); batchGets != 0 {
			t.Fatalf("batch-get requests = %d, want 0", batchGets)
		}
		assertRecordProofLevel(t, store, records[0].RecordID, "L3")
	})

	t.Run("canceled later batch get", func(t *testing.T) {
		db, reads := newMockTiKVDB(t, "promotion-canceled-read/")
		store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
		records := seedPromotionReferences(t, store, "batch-canceled-read", promotionReferenceBatchSize+1, -1)
		if _, err := store.collectRecordIndexPromotions(context.Background(), records[0].BatchID, "L4"); err != nil {
			t.Fatalf("prime committed record indexes: %v", err)
		}
		reads.resetReadRequests()
		ctx, cancel := context.WithCancel(context.Background())
		reads.batchGetHook = func() {
			if reads.batchGetRequests.Load() == 2 {
				cancel()
			}
		}
		t.Cleanup(func() {
			reads.batchGetHook = nil
			cancel()
		})

		err := store.promoteBatchRecords(ctx, records[0].BatchID, "L4")
		reads.batchGetHook = nil
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("promoteBatchRecords error = %v, want wrapped context cancellation", err)
		}
		if requests := reads.getRequests.Load(); requests != 0 {
			t.Fatalf("point-get requests = %d, want 0", requests)
		}
		if requests := reads.batchGetRequests.Load(); requests != 2 {
			t.Fatalf("batch-get requests = %d, want cancellation in request 2", requests)
		}
		if reads.readVersionDrift.Load() {
			t.Fatal("at least one batch-get request used a different version from the scan")
		}
		assertRecordProofLevel(t, store, records[0].RecordID, "L3")
	})
}

func TestCommitRecordIndexPromotionsDoesNotDowngradeConcurrentLevel(t *testing.T) {
	db, _ := newMockTiKVDB(t, "promotion-monotonic/")
	store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
	records := seedPromotionReferences(t, store, "batch-monotonic", 1, -1)
	updates, err := store.collectRecordIndexPromotions(context.Background(), records[0].BatchID, "L4")
	if err != nil {
		t.Fatalf("collect L4 promotions: %v", err)
	}
	if len(updates) != 1 || updates[0].next.ProofLevel != "L4" {
		t.Fatalf("L4 promotions = %+v", updates)
	}

	l5 := records[0]
	l5.ProofLevel = "L5"
	if err := store.PutRecordIndex(context.Background(), l5); err != nil {
		t.Fatalf("commit concurrent L5 record: %v", err)
	}
	if err := store.commitRecordIndexPromotions(context.Background(), updates); err != nil {
		t.Fatalf("commit stale L4 promotions: %v", err)
	}
	assertRecordProofLevel(t, store, l5.RecordID, "L5")
	for level, want := range map[string]int{"L3": 0, "L4": 0, "L5": 1} {
		prefix := prefixRecordByLevel + recordSecondaryPart(level) + "/"
		if got := countKeysWithPrefix(t, store, prefix); got != want {
			t.Fatalf("%s proof-level keys = %d, want %d", level, got, want)
		}
	}
}

func TestCommitRecordIndexPromotionsRetriesWriteConflict(t *testing.T) {
	db, reads := newMockTiKVDB(t, "promotion-conflict-retry/")
	store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
	records := seedPromotionReferences(t, store, "batch-conflict-retry", 1, -1)
	updates, err := store.collectRecordIndexPromotions(context.Background(), records[0].BatchID, "L5")
	if err != nil {
		t.Fatalf("collect L5 promotions: %v", err)
	}
	reads.resetReadRequests()

	guardStarted := make(chan struct{})
	releaseGuard := make(chan struct{})
	var blockOnce sync.Once
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseGuard) })
	}
	reads.batchGetHook = func() {
		blockOnce.Do(func() {
			close(guardStarted)
			<-releaseGuard
		})
	}
	t.Cleanup(func() {
		release()
		reads.batchGetHook = nil
	})

	commitDone := make(chan error, 1)
	go func() {
		commitDone <- store.commitRecordIndexPromotions(context.Background(), updates)
	}()
	select {
	case <-guardStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the first guarded transaction")
	}

	l4 := records[0]
	l4.ProofLevel = "L4"
	if err := store.PutRecordIndex(context.Background(), l4); err != nil {
		t.Fatalf("commit overlapping L4 record: %v", err)
	}
	release()
	select {
	case err := <-commitDone:
		if err != nil {
			t.Fatalf("commit L5 promotions after conflict: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the retried promotion")
	}
	reads.batchGetHook = nil
	if requests := reads.batchGetRequests.Load(); requests < 2 {
		t.Fatalf("guard batch-get requests = %d, want at least 2 attempts", requests)
	}
	assertRecordProofLevel(t, store, records[0].RecordID, "L5")
}

func TestCommitRecordIndexPromotionsRepairsDivergedLegacyProjection(t *testing.T) {
	db, _ := newMockTiKVDB(t, "promotion-diverged-legacy/")
	store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
	legacy := promotionRecordIndex(true)
	legacy.RecordID = "tr-diverged-legacy"
	legacy.BatchID = "batch-legacy-projection"
	legacy.TenantID = "tenant-legacy-projection"
	legacy.ClientID = "client-legacy-projection"
	legacy.ContentHash = []byte("legacy-projection-hash")
	legacy.FileName = "legacy-projection.bin"
	legacy.ReceivedAtUnixN = 1_000

	current := legacy
	current.BatchID = "batch-current-projection"
	current.ProofLevel = "L5"
	current.TenantID = "tenant-current-projection"
	current.ClientID = "client-current-projection"
	current.ContentHash = []byte("current-projection-hash")
	current.FileName = "current-projection.json"
	current.ReceivedAtUnixN = 2_000
	if err := store.PutRecordIndex(context.Background(), current); err != nil {
		t.Fatalf("PutRecordIndex(current): %v", err)
	}

	legacyValue, err := cborx.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy projection: %v", err)
	}
	batch := db.NewBatch()
	defer batch.Close()
	if err := visitRecordIndexKeys(legacy, RecordIndexModeFull, func(key []byte) error {
		if isRecordByIDKey(key) {
			return nil
		}
		return batch.Set(key, legacyValue, nil)
	}); err != nil {
		t.Fatalf("stage legacy projection: %v", err)
	}
	if err := batch.Commit(syncWrite); err != nil {
		t.Fatalf("commit legacy projection: %v", err)
	}

	if err := store.promoteBatchRecords(context.Background(), legacy.BatchID, "L4"); err != nil {
		t.Fatalf("promoteBatchRecords: %v", err)
	}
	got, found, err := store.GetRecordIndex(context.Background(), current.RecordID)
	if err != nil || !found {
		t.Fatalf("GetRecordIndex found=%v err=%v", found, err)
	}
	if got.ProofLevel != "L5" || got.BatchID != current.BatchID || got.TenantID != current.TenantID || got.ClientID != current.ClientID || got.ReceivedAtUnixN != current.ReceivedAtUnixN || !bytes.Equal(got.ContentHash, current.ContentHash) {
		t.Fatalf("repaired current record = %+v, want %+v", got, current)
	}
	if err := visitRecordIndexKeys(legacy, RecordIndexModeFull, func(key []byte) error {
		if isRecordByIDKey(key) {
			return nil
		}
		_, closer, err := db.Get(key)
		if err == nil {
			_ = closer.Close()
			return fmt.Errorf("legacy secondary %q still exists", key)
		}
		if !isNotFound(err) {
			return fmt.Errorf("read legacy secondary %q: %w", key, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := visitRecordIndexKeys(current, RecordIndexModeFull, func(key []byte) error {
		value, closer, err := db.Get(key)
		if err != nil {
			return fmt.Errorf("read current index %q: %w", key, err)
		}
		defer closer.Close()
		if isRecordByIDKey(key) {
			return nil
		}
		if recordID, ok := decodeRecordIndexRef(value); !ok || recordID != current.RecordID {
			return fmt.Errorf("current secondary %q is not canonical", key)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for level, want := range map[string]int{"L3": 0, "L4": 0, "L5": 1} {
		prefix := prefixRecordByLevel + recordSecondaryPart(level) + "/"
		if got := countKeysWithPrefix(t, store, prefix); got != want {
			t.Fatalf("%s proof-level keys = %d, want %d", level, got, want)
		}
	}
}

func TestPromoteBatchRecordsPreservesIndexModeTransitions(t *testing.T) {
	t.Run("no storage tokens to full backfills tokens", func(t *testing.T) {
		db, _ := newMockTiKVDB(t, "promotion-backfill/")
		store := &Store{db: db, recordIndexMode: RecordIndexModeNoStorageTokens}
		idx := promotionRecordIndex(true)
		if err := store.PutRecordIndex(context.Background(), idx); err != nil {
			t.Fatalf("PutRecordIndex: %v", err)
		}
		if got := countKeysWithPrefix(t, store, prefixRecordByToken); got != 0 {
			t.Fatalf("initial token keys = %d, want 0", got)
		}

		store.recordIndexMode = RecordIndexModeFull
		if err := store.promoteBatchRecords(context.Background(), idx.BatchID, "L4"); err != nil {
			t.Fatalf("promoteBatchRecords: %v", err)
		}
		if got, want := countKeysWithPrefix(t, store, prefixRecordByToken), len(model.RecordIndexStorageTokens(idx)); got != want {
			t.Fatalf("backfilled token keys = %d, want %d", got, want)
		}
		assertPromotedRecordQueries(t, store, idx, "L4")
	})

	for _, mode := range []string{RecordIndexModeNoStorageTokens, RecordIndexModeTimeOnly} {
		t.Run("full to "+mode+" cleans stale indexes", func(t *testing.T) {
			db, _ := newMockTiKVDB(t, "promotion-cleanup-"+mode+"/")
			store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
			idx := promotionRecordIndex(true)
			if err := store.PutRecordIndex(context.Background(), idx); err != nil {
				t.Fatalf("PutRecordIndex: %v", err)
			}

			store.recordIndexMode = mode
			if err := store.promoteBatchRecords(context.Background(), idx.BatchID, "L4"); err != nil {
				t.Fatalf("promoteBatchRecords: %v", err)
			}
			if got := countKeysWithPrefix(t, store, prefixRecordByToken); got != 0 {
				t.Fatalf("token keys after transition = %d, want 0", got)
			}
			if mode == RecordIndexModeTimeOnly {
				for _, prefix := range []string{prefixRecordByBatch, prefixRecordByLevel, prefixRecordByTenant, prefixRecordByClient, prefixRecordByHash} {
					if got := countKeysWithPrefix(t, store, prefix); got != 0 {
						t.Fatalf("%s keys after time-only transition = %d, want 0", prefix, got)
					}
				}
			}
			got, found, err := store.GetRecordIndex(context.Background(), idx.RecordID)
			if err != nil || !found || got.ProofLevel != "L4" {
				t.Fatalf("promoted record found=%v level=%q err=%v", found, got.ProofLevel, err)
			}
		})
	}
}

func TestPromoteBatchRecordsMigratesLegacyInlineIndexes(t *testing.T) {
	for _, test := range []struct {
		name  string
		mixed bool
	}{
		{name: "all inline"},
		{name: "canonical batch with mixed and missing secondaries", mixed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, reads := newMockTiKVDB(t, "promotion-legacy-"+strings.ReplaceAll(test.name, " ", "-")+"/")
			store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
			idx := promotionRecordIndex(true)
			value, err := cborx.Marshal(idx)
			if err != nil {
				t.Fatalf("marshal legacy record index: %v", err)
			}
			batchKey := appendRecordIndexEncodedPrefix(nil, prefixRecordByBatch, idx.BatchID, idx.ReceivedAtUnixN, idx.RecordID)
			missingKey := appendRecordIndexEncodedPrefix(nil, prefixRecordByClient, idx.ClientID, idx.ReceivedAtUnixN, idx.RecordID)
			batch := store.db.NewBatch()
			if err := visitRecordIndexKeys(idx, RecordIndexModeFull, func(key []byte) error {
				if isRecordByIDKey(key) {
					if test.mixed {
						return batch.Set(key, value, nil)
					}
					return nil
				}
				if test.mixed && bytes.Equal(key, batchKey) {
					return stageRecordIndexRef(batch, key, idx.RecordID)
				}
				if test.mixed && bytes.Equal(key, missingKey) {
					return nil
				}
				return batch.Set(key, value, nil)
			}); err != nil {
				t.Fatalf("stage legacy indexes: %v", err)
			}
			if err := batch.Commit(syncWrite); err != nil {
				t.Fatalf("commit legacy indexes: %v", err)
			}
			if _, err := store.collectRecordIndexPromotions(context.Background(), idx.BatchID, "L4"); err != nil {
				t.Fatalf("prime committed record indexes: %v", err)
			}
			reads.resetReadRequests()

			if err := store.promoteBatchRecords(context.Background(), idx.BatchID, "L4"); err != nil {
				t.Fatalf("promoteBatchRecords: %v", err)
			}
			if requests := reads.getRequests.Load(); requests != 0 {
				t.Fatalf("point-get requests = %d, want 0", requests)
			}
			wantBatchGets := int64(1)
			if test.mixed {
				wantBatchGets = 2
			}
			if requests := reads.batchGetRequests.Load(); requests != wantBatchGets {
				t.Fatalf("batch-get requests = %d, want %d", requests, wantBatchGets)
			}
			next := idx
			next.ProofLevel = "L4"
			if err := visitRecordIndexKeys(next, RecordIndexModeFull, func(key []byte) error {
				value, closer, err := store.db.Get(key)
				if err != nil {
					return fmt.Errorf("get %q: %w", key, err)
				}
				defer closer.Close()
				if isRecordByIDKey(key) {
					var got model.RecordIndex
					if err := cborx.UnmarshalLimit(value, &got, maxStoredObjectBytes); err != nil {
						return err
					}
					if got.ProofLevel != "L4" {
						return fmt.Errorf("primary proof level = %q, want L4", got.ProofLevel)
					}
					return nil
				}
				if recordID, ok := decodeRecordIndexRef(value); !ok || recordID != idx.RecordID {
					return fmt.Errorf("secondary %q is not a canonical reference", key)
				}
				return nil
			}); err != nil {
				t.Fatalf("verify migrated indexes: %v", err)
			}
			assertPromotedRecordQueries(t, store, idx, "L4")
		})
	}
}

func seedPromotionReferences(t *testing.T, store *Store, batchID string, count, missingPrimary int) []model.RecordIndex {
	t.Helper()
	records := make([]model.RecordIndex, count)
	batch := store.db.NewBatch()
	defer batch.Close()
	for index := range records {
		records[index] = minimalPromotionRecordIndex(batchID, index+1)
		stagePromotionReference(t, batch, records[index], index != missingPrimary)
	}
	if err := batch.Commit(syncWrite); err != nil {
		t.Fatalf("commit promotion references: %v", err)
	}
	return records
}

func minimalPromotionRecordIndex(batchID string, ordinal int) model.RecordIndex {
	return model.RecordIndex{
		SchemaVersion:   model.SchemaRecordIndex,
		RecordID:        fmt.Sprintf("tr-promotion-%06d", ordinal),
		BatchID:         batchID,
		ProofLevel:      "L3",
		ReceivedAtUnixN: int64(ordinal),
	}
}

func stagePromotionReference(t *testing.T, batch *tikvBatch, idx model.RecordIndex, includePrimary bool) {
	t.Helper()
	if includePrimary {
		value, err := cborx.Marshal(idx)
		if err != nil {
			t.Fatalf("marshal record index %q: %v", idx.RecordID, err)
		}
		if err := batch.Set(recordByIDKey(idx.RecordID), value, nil); err != nil {
			t.Fatalf("stage record primary %q: %v", idx.RecordID, err)
		}
	}
	if err := stageRecordIndexRef(batch, promotionBatchIndexKey(idx), idx.RecordID); err != nil {
		t.Fatalf("stage record reference %q: %v", idx.RecordID, err)
	}
}

func promotionBatchIndexKey(idx model.RecordIndex) []byte {
	return appendRecordIndexEncodedPrefix(nil, prefixRecordByBatch, idx.BatchID, idx.ReceivedAtUnixN, idx.RecordID)
}

func assertRecordProofLevel(t *testing.T, store *Store, recordID, want string) {
	t.Helper()
	idx, found, err := store.GetRecordIndex(context.Background(), recordID)
	if err != nil || !found || idx.ProofLevel != want {
		t.Fatalf("record %q found=%v proof level=%q err=%v, want %q", recordID, found, idx.ProofLevel, err, want)
	}
}

func promotionRecordIndex(withTokens bool) model.RecordIndex {
	idx := model.RecordIndex{
		SchemaVersion:   model.SchemaRecordIndex,
		RecordID:        "tr-promotion-0001",
		BatchID:         "batch-promotion",
		ProofLevel:      "L3",
		TenantID:        "tenant-promotion",
		ClientID:        "client-promotion",
		ContentHash:     []byte("promotion-content-hash"),
		ReceivedAtUnixN: 1_000,
	}
	if withTokens {
		parts := make([]string, 80)
		for index := range parts {
			parts[index] = fmt.Sprintf("segment%03d", index)
		}
		idx.FileName = strings.Join(parts, "-") + ".bin"
	}
	return idx
}

func assertTiKVPromotionCoreOps(t *testing.T, ops []batchOp, namespace []byte, old, next model.RecordIndex) {
	t.Helper()
	if len(ops) < 3 {
		t.Fatalf("promotion ops = %d, want at least 3", len(ops))
	}
	logicalKey := func(op batchOp) []byte {
		return bytes.TrimPrefix(op.key, namespace)
	}
	if ops[0].delete || !bytes.Equal(logicalKey(ops[0]), recordByIDKey(next.RecordID)) {
		t.Fatalf("primary op = key %q delete=%v", logicalKey(ops[0]), ops[0].delete)
	}
	var stored model.RecordIndex
	if err := cborx.UnmarshalLimit(ops[0].value, &stored, maxStoredObjectBytes); err != nil {
		t.Fatalf("decode primary op: %v", err)
	}
	if stored.ProofLevel != next.ProofLevel {
		t.Fatalf("primary proof level = %q, want %q", stored.ProofLevel, next.ProofLevel)
	}
	wantOldLevel := appendRecordIndexEncodedPrefix(nil, prefixRecordByLevel, old.ProofLevel, old.ReceivedAtUnixN, old.RecordID)
	if !ops[1].delete || !bytes.Equal(logicalKey(ops[1]), wantOldLevel) {
		t.Fatalf("old level op = key %q delete=%v", logicalKey(ops[1]), ops[1].delete)
	}
	wantNewLevel := appendRecordIndexEncodedPrefix(nil, prefixRecordByLevel, next.ProofLevel, next.ReceivedAtUnixN, next.RecordID)
	foundNewLevel := false
	for index := 2; index < len(ops); index++ {
		if ops[index].delete {
			t.Fatalf("secondary op %d unexpectedly deletes %q", index, logicalKey(ops[index]))
		}
		if recordID, ok := decodeRecordIndexRef(ops[index].value); !ok || recordID != next.RecordID {
			t.Fatalf("secondary op %d is not a reference: id=%q ok=%v", index, recordID, ok)
		}
		if bytes.Equal(logicalKey(ops[index]), wantNewLevel) {
			foundNewLevel = true
		}
	}
	if !foundNewLevel {
		t.Fatalf("new proof-level key %q was not staged", wantNewLevel)
	}
}

func countKeysWithPrefix(t *testing.T, store *Store, prefix string) int {
	t.Helper()
	lower, upper := prefixBounds(prefix)
	iter, err := store.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		t.Fatalf("NewIter(%s): %v", prefix, err)
	}
	defer iter.Close()
	count := 0
	for ok := iter.First(); ok; ok = iter.Next() {
		count++
	}
	if err := iter.Error(); err != nil {
		t.Fatalf("iterate %s: %v", prefix, err)
	}
	return count
}

func assertPromotedRecordQueries(t *testing.T, store *Store, idx model.RecordIndex, level string) {
	t.Helper()
	got, found, err := store.GetRecordIndex(context.Background(), idx.RecordID)
	if err != nil || !found || got.ProofLevel != level {
		t.Fatalf("promoted record found=%v level=%q err=%v", found, got.ProofLevel, err)
	}
	for name, opts := range map[string]model.RecordListOptions{
		"time":          {},
		"batch":         {BatchID: idx.BatchID},
		"tenant":        {TenantID: idx.TenantID},
		"client":        {ClientID: idx.ClientID},
		"content hash":  {ContentHash: idx.ContentHash},
		"proof level":   {ProofLevel: level},
		"storage token": {Query: idx.FileName},
	} {
		records, err := store.ListRecordIndexes(context.Background(), opts)
		if err != nil {
			t.Fatalf("ListRecordIndexes(%s): %v", name, err)
		}
		if len(records) != 1 || records[0].RecordID != idx.RecordID {
			t.Fatalf("ListRecordIndexes(%s) = %+v", name, records)
		}
	}
	records, err := store.ListRecordIndexes(context.Background(), model.RecordListOptions{ProofLevel: idx.ProofLevel})
	if err != nil {
		t.Fatalf("ListRecordIndexes(old proof level): %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("old proof-level records = %+v, want empty", records)
	}
	if got := countKeysWithPrefix(t, store, prefixRecordByLevel+recordSecondaryPart(idx.ProofLevel)+"/"); got != 0 {
		t.Fatalf("old proof-level physical keys = %d, want 0", got)
	}
	if got := countKeysWithPrefix(t, store, prefixRecordByLevel+recordSecondaryPart(level)+"/"); got != 1 {
		t.Fatalf("new proof-level physical keys = %d, want 1", got)
	}
}
