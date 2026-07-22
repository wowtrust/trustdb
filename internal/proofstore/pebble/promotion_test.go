package pebble

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	pdb "github.com/cockroachdb/pebble"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestGlobalPublicationPersistsIntentBeforeChunkedL4Projection(t *testing.T) {
	store, err := OpenWithOptions(t.TempDir(), Options{RecordIndexMode: RecordIndexModeFull})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	const batchID = "batch-pebble-intent-first"
	if err := store.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{
		SchemaVersion: model.SchemaGlobalLogOutbox,
		BatchID:       batchID,
		BatchRoot: model.BatchRoot{
			SchemaVersion: model.SchemaBatchRoot,
			BatchID:       batchID,
			BatchRoot:     bytes.Repeat([]byte{0x31}, 32),
			TreeSize:      1,
		},
		Status: model.AnchorStatePending,
	}); err != nil {
		t.Fatalf("EnqueueGlobalLog: %v", err)
	}
	danglingID := "tr1-pebble-dangling"
	danglingKey := appendRecordIndexEncodedPrefix(nil, prefixRecordByBatch, batchID, 1, danglingID)
	seed := store.db.NewBatch()
	if err := stageRecordIndexRef(seed, danglingKey, danglingID); err != nil {
		_ = seed.Close()
		t.Fatalf("stage dangling batch index: %v", err)
	}
	if err := seed.Commit(pdb.Sync); err != nil {
		_ = seed.Close()
		t.Fatalf("commit dangling batch index: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close dangling batch index: %v", err)
	}
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	sth := model.SignedTreeHead{
		SchemaVersion: model.SchemaSignedTreeHead, TreeAlg: model.DefaultMerkleTreeAlg,
		TreeSize: 1, RootHash: bytes.Repeat([]byte{0x41}, 32), TimestampUnixN: 101,
		NodeID: key.NodeID, LogID: key.LogID,
		Signature: model.Signature{Alg: model.DefaultSignatureAlg, KeyID: "server-key", Signature: bytes.Repeat([]byte{0x41}, 64)},
	}
	candidate := model.STHAnchorCandidate{Key: key, STH: sth, ObservedAtUnixN: 100, DueAtUnixN: 200}
	err = store.MarkGlobalLogPublishedBatchWithAnchorCandidate(ctx, []string{batchID}, []model.SignedTreeHead{sth}, candidate)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("MarkGlobalLogPublishedBatchWithAnchorCandidate error=%v, want data loss", err)
	}
	schedule, found, err := store.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || schedule.Pending == nil || schedule.Pending.Target.TreeSize != sth.TreeSize || schedule.Revision != 1 {
		t.Fatalf("durable anchor intent=%+v found=%v err=%v", schedule, found, err)
	}
	item, found, err := store.GetGlobalLogOutboxItem(ctx, batchID)
	if err != nil || !found || item.Status != model.AnchorStatePending {
		t.Fatalf("outbox after failed projection=%+v found=%v err=%v", item, found, err)
	}

	if err := store.db.Delete(danglingKey, pdb.Sync); err != nil {
		t.Fatalf("remove injected dangling index: %v", err)
	}
	if err := store.MarkGlobalLogPublishedBatchWithAnchorCandidate(ctx, []string{batchID}, []model.SignedTreeHead{sth}, candidate); err != nil {
		t.Fatalf("retry global publication: %v", err)
	}
	schedule, found, err = store.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || schedule.Revision != 1 {
		t.Fatalf("retry duplicated candidate schedule=%+v found=%v err=%v", schedule, found, err)
	}
	item, found, err = store.GetGlobalLogOutboxItem(ctx, batchID)
	if err != nil || !found || item.Status != model.AnchorStatePublished {
		t.Fatalf("outbox after retry=%+v found=%v err=%v", item, found, err)
	}
}

func TestStageRecordIndexPromotionMutationCounts(t *testing.T) {
	t.Parallel()

	store, err := OpenWithOptions(t.TempDir(), Options{RecordIndexMode: RecordIndexModeFull})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

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
				_ = batch.Close()
				t.Fatalf("stageRecordIndexPromotion: %v", err)
			}
			if got := int(batch.Count()); got != test.wantSpecialized {
				_ = batch.Close()
				t.Fatalf("specialized mutation count = %d, want %d", got, test.wantSpecialized)
			}
			if err := batch.Close(); err != nil {
				t.Fatalf("close specialized batch: %v", err)
			}

			batch = store.db.NewBatch()
			if err := store.stageRecordIndexPromotion(batch, recordIndexPromotion{old: test.idx, next: next, replaceAll: true}); err != nil {
				_ = batch.Close()
				t.Fatalf("stage legacy promotion: %v", err)
			}
			if got := int(batch.Count()); got != test.wantFullReplace {
				_ = batch.Close()
				t.Fatalf("full replacement mutation count = %d, want %d", got, test.wantFullReplace)
			}
			if err := batch.Close(); err != nil {
				t.Fatalf("close full replacement batch: %v", err)
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
				_ = batch.Close()
				t.Fatalf("stageRecordIndexPromotion: %v", err)
			}
			if got := int(batch.Count()); got != test.want {
				_ = batch.Close()
				t.Fatalf("fallback mutation count = %d, want %d", got, test.want)
			}
			if err := batch.Close(); err != nil {
				t.Fatalf("close fallback batch: %v", err)
			}
		})
	}
}

func TestPromoteBatchRecordsPreservesIndexModeTransitions(t *testing.T) {
	t.Parallel()

	t.Run("no storage tokens to full backfills tokens", func(t *testing.T) {
		store, err := OpenWithOptions(t.TempDir(), Options{RecordIndexMode: RecordIndexModeNoStorageTokens})
		if err != nil {
			t.Fatalf("OpenWithOptions: %v", err)
		}
		defer store.Close()
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
			store, err := OpenWithOptions(t.TempDir(), Options{RecordIndexMode: RecordIndexModeFull})
			if err != nil {
				t.Fatalf("OpenWithOptions: %v", err)
			}
			defer store.Close()
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
	t.Parallel()

	for _, test := range []struct {
		name  string
		mixed bool
	}{
		{name: "all inline"},
		{name: "canonical batch with mixed and missing secondaries", mixed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := OpenWithOptions(t.TempDir(), Options{RecordIndexMode: RecordIndexModeFull})
			if err != nil {
				t.Fatalf("OpenWithOptions: %v", err)
			}
			defer store.Close()
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
				_ = batch.Close()
				t.Fatalf("stage legacy indexes: %v", err)
			}
			if err := batch.Commit(pdb.Sync); err != nil {
				_ = batch.Close()
				t.Fatalf("commit legacy indexes: %v", err)
			}
			if err := batch.Close(); err != nil {
				t.Fatalf("close legacy batch: %v", err)
			}

			if err := store.promoteBatchRecords(context.Background(), idx.BatchID, "L4"); err != nil {
				t.Fatalf("promoteBatchRecords: %v", err)
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
