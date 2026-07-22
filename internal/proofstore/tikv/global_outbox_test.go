package tikv

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestReadGlobalLogOutboxItemsBatchGetsSnapshot(t *testing.T) {
	for _, test := range []struct {
		name             string
		count            int
		wantRequests     int64
		wantMaxBatchKeys int64
	}{
		{name: "default worker batch", count: 128, wantRequests: 1, wantMaxBatchKeys: 128},
		{name: "crosses read boundary", count: globalOutboxReadBatchSize + 1, wantRequests: 2, wantMaxBatchKeys: globalOutboxReadBatchSize},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, reads := newMockTiKVDB(t, "global-outbox-read-"+strings.ReplaceAll(test.name, " ", "-")+"/")
			store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
			batchIDs := seedGlobalLogOutboxItems(t, store, test.count)
			reads.resetReadRequests()

			items, err := store.readGlobalLogOutboxItems(context.Background(), batchIDs)
			if err != nil {
				t.Fatalf("readGlobalLogOutboxItems: %v", err)
			}
			if len(items) != len(batchIDs) {
				t.Fatalf("item count = %d, want %d", len(items), len(batchIDs))
			}
			for index := range items {
				if items[index].BatchID != batchIDs[index] {
					t.Fatalf("item %d batch ID = %q, want %q", index, items[index].BatchID, batchIDs[index])
				}
			}
			if requests := reads.getRequests.Load(); requests != 0 {
				t.Fatalf("point-get requests = %d, want 0", requests)
			}
			if requests := reads.batchGetRequests.Load(); requests != test.wantRequests {
				t.Fatalf("batch-get requests = %d, want %d", requests, test.wantRequests)
			}
			if keys := reads.batchGetKeys.Load(); keys != int64(test.count) {
				t.Fatalf("batch-get keys = %d, want %d", keys, test.count)
			}
			if keys := reads.batchGetMaxKeys.Load(); keys != test.wantMaxBatchKeys {
				t.Fatalf("maximum batch-get keys = %d, want %d", keys, test.wantMaxBatchKeys)
			}
			if reads.readVersionDrift.Load() {
				t.Fatal("batch-get chunks used different snapshot versions")
			}
		})
	}
}

func TestReadGlobalLogOutboxItemsPreservesDuplicateOrder(t *testing.T) {
	db, reads := newMockTiKVDB(t, "global-outbox-duplicate-read/")
	store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
	batchIDs := seedGlobalLogOutboxItems(t, store, 2)
	input := []string{batchIDs[1], batchIDs[0], batchIDs[1]}
	reads.resetReadRequests()

	items, err := store.readGlobalLogOutboxItems(context.Background(), input)
	if err != nil {
		t.Fatalf("readGlobalLogOutboxItems: %v", err)
	}
	for index := range input {
		if items[index].BatchID != input[index] {
			t.Fatalf("item %d batch ID = %q, want %q", index, items[index].BatchID, input[index])
		}
	}
	if keys := reads.batchGetKeys.Load(); keys != 2 {
		t.Fatalf("batch-get keys = %d, want 2 unique transport keys", keys)
	}
	if requests := reads.batchGetRequests.Load(); requests != 1 {
		t.Fatalf("batch-get requests = %d, want 1", requests)
	}
	if requests := reads.getRequests.Load(); requests != 0 {
		t.Fatalf("point-get requests = %d, want 0", requests)
	}
}

func TestReadGlobalLogOutboxItemsFailurePaths(t *testing.T) {
	t.Run("empty batch ID", func(t *testing.T) {
		db, reads := newMockTiKVDB(t, "global-outbox-empty-id-read/")
		store := &Store{db: db, recordIndexMode: RecordIndexModeFull}

		_, err := store.readGlobalLogOutboxItems(context.Background(), []string{""})
		if trusterr.CodeOf(err) != trusterr.CodeInvalidArgument {
			t.Fatalf("empty batch ID error code = %s err=%v, want %s", trusterr.CodeOf(err), err, trusterr.CodeInvalidArgument)
		}
		if reads.getRequests.Load() != 0 || reads.batchGetRequests.Load() != 0 {
			t.Fatalf("read requests = get:%d batch-get:%d, want 0/0", reads.getRequests.Load(), reads.batchGetRequests.Load())
		}
	})

	t.Run("missing item", func(t *testing.T) {
		db, reads := newMockTiKVDB(t, "global-outbox-missing-read/")
		store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
		batchIDs := seedGlobalLogOutboxItems(t, store, 1)
		reads.resetReadRequests()

		_, err := store.readGlobalLogOutboxItems(context.Background(), []string{batchIDs[0], "batch-missing"})
		if trusterr.CodeOf(err) != trusterr.CodeNotFound {
			t.Fatalf("missing item error code = %s err=%v, want %s", trusterr.CodeOf(err), err, trusterr.CodeNotFound)
		}
		if reads.getRequests.Load() != 0 || reads.batchGetRequests.Load() != 1 {
			t.Fatalf("read requests = get:%d batch-get:%d, want 0/1", reads.getRequests.Load(), reads.batchGetRequests.Load())
		}
	})

	t.Run("malformed item", func(t *testing.T) {
		db, reads := newMockTiKVDB(t, "global-outbox-malformed-read/")
		store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
		batchIDs := seedGlobalLogOutboxItems(t, store, 2)
		if err := db.Set(globalOutboxKey(batchIDs[1]), []byte{0xff}, syncWrite); err != nil {
			t.Fatalf("seed malformed outbox item: %v", err)
		}
		if _, err := store.readGlobalLogOutboxItems(context.Background(), batchIDs); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
			t.Fatalf("prime malformed outbox item error code = %s err=%v, want %s", trusterr.CodeOf(err), err, trusterr.CodeDataLoss)
		}
		reads.resetReadRequests()

		_, err := store.readGlobalLogOutboxItems(context.Background(), batchIDs)
		if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
			t.Fatalf("malformed item error code = %s err=%v, want %s", trusterr.CodeOf(err), err, trusterr.CodeDataLoss)
		}
		if reads.getRequests.Load() != 0 || reads.batchGetRequests.Load() != 1 {
			t.Fatalf("read requests = get:%d batch-get:%d, want 0/1", reads.getRequests.Load(), reads.batchGetRequests.Load())
		}
	})

	t.Run("pre-canceled context", func(t *testing.T) {
		db, reads := newMockTiKVDB(t, "global-outbox-pre-canceled-read/")
		store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
		batchIDs := seedGlobalLogOutboxItems(t, store, 1)
		reads.resetReadRequests()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := store.readGlobalLogOutboxItems(ctx, batchIDs)
		if trusterr.CodeOf(err) != trusterr.CodeDeadlineExceeded || !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-canceled error code = %s err=%v, want wrapped cancellation", trusterr.CodeOf(err), err)
		}
		if reads.getRequests.Load() != 0 || reads.batchGetRequests.Load() != 0 {
			t.Fatalf("read requests = get:%d batch-get:%d, want 0/0", reads.getRequests.Load(), reads.batchGetRequests.Load())
		}
	})

	t.Run("canceled later batch get", func(t *testing.T) {
		db, reads := newMockTiKVDB(t, "global-outbox-canceled-read/")
		store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
		batchIDs := seedGlobalLogOutboxItems(t, store, globalOutboxReadBatchSize+1)
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

		_, err := store.readGlobalLogOutboxItems(ctx, batchIDs)
		reads.batchGetHook = nil
		if trusterr.CodeOf(err) != trusterr.CodeDeadlineExceeded || !errors.Is(err, context.Canceled) {
			t.Fatalf("mid-read cancellation code = %s err=%v, want wrapped cancellation", trusterr.CodeOf(err), err)
		}
		if reads.getRequests.Load() != 0 || reads.batchGetRequests.Load() != 2 {
			t.Fatalf("read requests = get:%d batch-get:%d, want 0/2", reads.getRequests.Load(), reads.batchGetRequests.Load())
		}
		if reads.readVersionDrift.Load() {
			t.Fatal("batch-get chunks used different snapshot versions")
		}
	})

	t.Run("first chunk missing precedes later cancellation", func(t *testing.T) {
		db, reads := newMockTiKVDB(t, "global-outbox-ordered-missing-read/")
		store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
		batchIDs := seedGlobalLogOutboxItems(t, store, globalOutboxReadBatchSize+1)
		batchIDs[0] = "batch-missing"
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

		_, err := store.readGlobalLogOutboxItems(ctx, batchIDs)
		reads.batchGetHook = nil
		if trusterr.CodeOf(err) != trusterr.CodeNotFound {
			t.Fatalf("ordered missing error code = %s err=%v, want %s", trusterr.CodeOf(err), err, trusterr.CodeNotFound)
		}
		if reads.getRequests.Load() != 0 || reads.batchGetRequests.Load() != 1 {
			t.Fatalf("read requests = get:%d batch-get:%d, want 0/1 before later chunk", reads.getRequests.Load(), reads.batchGetRequests.Load())
		}
	})

	t.Run("first chunk malformed precedes later cancellation", func(t *testing.T) {
		db, reads := newMockTiKVDB(t, "global-outbox-ordered-malformed-read/")
		store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
		batchIDs := seedGlobalLogOutboxItems(t, store, globalOutboxReadBatchSize+1)
		if err := db.Set(globalOutboxKey(batchIDs[0]), []byte{0xff}, syncWrite); err != nil {
			t.Fatalf("seed malformed outbox item: %v", err)
		}
		if _, err := store.readGlobalLogOutboxItems(context.Background(), batchIDs[:1]); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
			t.Fatalf("prime malformed outbox item error code = %s err=%v, want %s", trusterr.CodeOf(err), err, trusterr.CodeDataLoss)
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

		_, err := store.readGlobalLogOutboxItems(ctx, batchIDs)
		reads.batchGetHook = nil
		if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
			t.Fatalf("ordered malformed error code = %s err=%v, want %s", trusterr.CodeOf(err), err, trusterr.CodeDataLoss)
		}
		if reads.getRequests.Load() != 0 || reads.batchGetRequests.Load() != 1 {
			t.Fatalf("read requests = get:%d batch-get:%d, want 0/1 before later chunk", reads.getRequests.Load(), reads.batchGetRequests.Load())
		}
	})
}

func TestMarkGlobalLogPublishedBatchValidatesBeforePromotion(t *testing.T) {
	t.Run("missing item", func(t *testing.T) {
		db, reads := newMockTiKVDB(t, "global-outbox-missing-before-promote/")
		store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
		batchIDs := seedGlobalLogOutboxItems(t, store, 1)
		records := seedPromotionReferences(t, store, batchIDs[0], 1, -1)
		reads.resetReadRequests()

		err := store.MarkGlobalLogPublishedBatch(context.Background(), []string{batchIDs[0], "batch-missing"}, []model.SignedTreeHead{{TreeSize: 1}, {TreeSize: 2}})
		if trusterr.CodeOf(err) != trusterr.CodeNotFound {
			t.Fatalf("MarkGlobalLogPublishedBatch error code = %s err=%v, want %s", trusterr.CodeOf(err), err, trusterr.CodeNotFound)
		}
		assertGlobalOutboxReadFailedBeforePromotion(t, store, reads, records[0])
	})

	t.Run("malformed item", func(t *testing.T) {
		db, reads := newMockTiKVDB(t, "global-outbox-malformed-before-promote/")
		store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
		batchIDs := seedGlobalLogOutboxItems(t, store, 2)
		records := seedPromotionReferences(t, store, batchIDs[0], 1, -1)
		if err := db.Set(globalOutboxKey(batchIDs[1]), []byte{0xff}, syncWrite); err != nil {
			t.Fatalf("seed malformed outbox item: %v", err)
		}
		if _, err := store.readGlobalLogOutboxItems(context.Background(), batchIDs); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
			t.Fatalf("prime malformed outbox item error code = %s err=%v, want %s", trusterr.CodeOf(err), err, trusterr.CodeDataLoss)
		}
		reads.resetReadRequests()

		err := store.MarkGlobalLogPublishedBatch(context.Background(), batchIDs, []model.SignedTreeHead{{TreeSize: 1}, {TreeSize: 2}})
		if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
			t.Fatalf("MarkGlobalLogPublishedBatch error code = %s err=%v, want %s", trusterr.CodeOf(err), err, trusterr.CodeDataLoss)
		}
		assertGlobalOutboxReadFailedBeforePromotion(t, store, reads, records[0])
	})
}

func TestMarkGlobalLogPublishedBatchBatchesDefaultOutboxReads(t *testing.T) {
	db, reads := newMockTiKVDB(t, "global-outbox-default-mark/")
	store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
	batchIDs := seedGlobalLogOutboxItems(t, store, 128)
	sths := make([]model.SignedTreeHead, len(batchIDs))
	for index := range sths {
		sths[index] = model.SignedTreeHead{TreeSize: uint64(index + 1), RootHash: []byte(fmt.Sprintf("root-%03d", index))}
	}
	reads.resetReadRequests()

	if err := store.MarkGlobalLogPublishedBatch(context.Background(), batchIDs, sths); err != nil {
		t.Fatalf("MarkGlobalLogPublishedBatch: %v", err)
	}
	if gets := reads.getRequests.Load(); gets != 0 {
		t.Fatalf("point-get requests = %d, want 0", gets)
	}
	if requests := reads.batchGetRequests.Load(); requests != 2 {
		t.Fatalf("outbox batch-get requests = %d, want 2 validation/publication snapshots", requests)
	}
	if keys := reads.batchGetKeys.Load(); keys != int64(2*len(batchIDs)) {
		t.Fatalf("outbox batch-get keys = %d, want %d", keys, 2*len(batchIDs))
	}
	for _, index := range []int{0, len(batchIDs) - 1} {
		item, found, err := store.GetGlobalLogOutboxItem(context.Background(), batchIDs[index])
		if err != nil || !found {
			t.Fatalf("GetGlobalLogOutboxItem(%d) found=%v err=%v", index, found, err)
		}
		if item.Status != model.AnchorStatePublished || item.STH.TreeSize != sths[index].TreeSize {
			t.Fatalf("published item %d = %+v, want STH tree size %d", index, item, sths[index].TreeSize)
		}
	}
}

func assertGlobalOutboxReadFailedBeforePromotion(t *testing.T, store *Store, reads *countingTiKVClient, record model.RecordIndex) {
	t.Helper()
	if scans := reads.scanRequests.Load(); scans != 0 {
		t.Fatalf("promotion scan requests = %d, want 0 after read validation failure", scans)
	}
	if gets := reads.getRequests.Load(); gets != 0 {
		t.Fatalf("point-get requests = %d, want 0", gets)
	}
	if batchGets := reads.batchGetRequests.Load(); batchGets != 1 {
		t.Fatalf("batch-get requests = %d, want 1", batchGets)
	}
	assertRecordProofLevel(t, store, record.RecordID, "L3")
	item, found, err := store.GetGlobalLogOutboxItem(context.Background(), record.BatchID)
	if err != nil || !found || item.Status != model.AnchorStatePending {
		t.Fatalf("outbox item found=%v status=%q err=%v, want unchanged pending item", found, item.Status, err)
	}
}

func TestMarkGlobalLogPublishedBatchPreservesDuplicateLastWrite(t *testing.T) {
	db, reads := newMockTiKVDB(t, "global-outbox-duplicate-mark/")
	store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
	batchIDs := seedGlobalLogOutboxItems(t, store, 1)
	reads.resetReadRequests()
	wantSTH := model.SignedTreeHead{TreeSize: 2, RootHash: []byte("second")}

	if err := store.MarkGlobalLogPublishedBatch(context.Background(), []string{batchIDs[0], batchIDs[0]}, []model.SignedTreeHead{{TreeSize: 1, RootHash: []byte("first")}, wantSTH}); err != nil {
		t.Fatalf("MarkGlobalLogPublishedBatch: %v", err)
	}
	if gets := reads.getRequests.Load(); gets != 0 {
		t.Fatalf("point-get requests = %d, want 0", gets)
	}
	if keys := reads.batchGetKeys.Load(); keys != 2 {
		t.Fatalf("batch-get keys = %d, want 2 validation/publication reads of one unique outbox key", keys)
	}
	item, found, err := store.GetGlobalLogOutboxItem(context.Background(), batchIDs[0])
	if err != nil || !found {
		t.Fatalf("GetGlobalLogOutboxItem found=%v err=%v", found, err)
	}
	if item.Status != model.AnchorStatePublished || item.STH.TreeSize != wantSTH.TreeSize || string(item.STH.RootHash) != string(wantSTH.RootHash) {
		t.Fatalf("published item = %+v, want last duplicate STH %+v", item, wantSTH)
	}
}

func seedGlobalLogOutboxItems(t *testing.T, store *Store, count int) []string {
	t.Helper()
	batchIDs := make([]string, count)
	batch := store.db.NewBatch()
	defer batch.Close()
	for index := range count {
		batchID := fmt.Sprintf("batch-outbox-%06d", index)
		batchIDs[index] = batchID
		item := model.GlobalLogOutboxItem{
			SchemaVersion:   model.SchemaGlobalLogOutbox,
			BatchID:         batchID,
			BatchRoot:       model.BatchRoot{BatchID: batchID, TreeSize: uint64(index + 1)},
			Status:          model.AnchorStatePending,
			EnqueuedAtUnixN: int64(index + 1),
		}
		data, err := cborx.Marshal(item)
		if err != nil {
			t.Fatalf("marshal outbox item %q: %v", batchID, err)
		}
		if err := batch.Set(globalOutboxKey(batchID), data, nil); err != nil {
			t.Fatalf("stage outbox item %q: %v", batchID, err)
		}
		if err := batch.Set(globalStatusKey(item.Status, globalStatusSortUnixN(item), batchID), data, nil); err != nil {
			t.Fatalf("stage outbox status %q: %v", batchID, err)
		}
	}
	if err := batch.Commit(syncWrite); err != nil {
		t.Fatalf("commit outbox items: %v", err)
	}
	// Mock TiKV commits may leave secondary-lock cleanup asynchronous. Prime
	// the just-written transaction before request-count assertions so lock
	// resolution traffic is not attributed to the read path under test.
	items, err := store.readGlobalLogOutboxItems(context.Background(), batchIDs)
	if err != nil || len(items) != len(batchIDs) {
		t.Fatalf("prime outbox items count=%d err=%v, want %d", len(items), err, len(batchIDs))
	}
	return batchIDs
}
