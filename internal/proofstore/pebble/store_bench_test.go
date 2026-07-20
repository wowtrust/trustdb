package pebble

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	pdb "github.com/cockroachdb/pebble"
	"github.com/golang/snappy"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/model"
)

func BenchmarkPebblePutBatchArtifacts1024(b *testing.B) {
	benchmarkPebblePutBatchArtifacts(b, 1024, Options{RecordIndexMode: RecordIndexModeFull})
}

func BenchmarkPebblePutBatchArtifacts8192(b *testing.B) {
	benchmarkPebblePutBatchArtifacts(b, 8192, Options{RecordIndexMode: RecordIndexModeFull})
}

func BenchmarkPebblePutBatchArtifacts1024TokenIndexDisabled(b *testing.B) {
	benchmarkPebblePutBatchArtifacts(b, 1024, Options{RecordIndexMode: RecordIndexModeNoStorageTokens})
}

func BenchmarkPebblePutBatchArtifacts8192TokenIndexDisabled(b *testing.B) {
	benchmarkPebblePutBatchArtifacts(b, 8192, Options{RecordIndexMode: RecordIndexModeNoStorageTokens})
}

func BenchmarkPebbleArtifactSyncModeBatch1024(b *testing.B) {
	benchmarkPebblePutBatchArtifacts(b, 1024, Options{RecordIndexMode: RecordIndexModeFull, ArtifactSyncMode: ArtifactSyncModeBatch})
}

func BenchmarkPebbleArtifactSyncModeBatch8192(b *testing.B) {
	benchmarkPebblePutBatchArtifacts(b, 8192, Options{RecordIndexMode: RecordIndexModeFull, ArtifactSyncMode: ArtifactSyncModeBatch})
}

func BenchmarkRecordIndexModeTimeOnly1024(b *testing.B) {
	benchmarkPebblePutBatchArtifacts(b, 1024, Options{RecordIndexMode: RecordIndexModeTimeOnly})
}

func BenchmarkRecordIndexModeTimeOnly8192(b *testing.B) {
	benchmarkPebblePutBatchArtifacts(b, 8192, Options{RecordIndexMode: RecordIndexModeTimeOnly})
}

func benchmarkPebblePutBatchArtifacts(b *testing.B, n int, opts Options) {
	store, err := OpenWithOptions(b.TempDir(), opts)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close() })
	bundles := syntheticProofBundles(n)
	root := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       "bench-batch",
		BatchRoot:     bytes.Repeat([]byte{1}, 32),
		TreeSize:      uint64(len(bundles)),
		ClosedAtUnixN: 1_000,
	}
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		if err := store.PutBatchArtifacts(ctx, bundles, root); err != nil {
			b.Fatal(err)
		}
	}
}

var benchmarkRecordIndexKeyCount int

func BenchmarkRecordIndexKeyBuild(b *testing.B) {
	idx := model.RecordIndexFromBundle(syntheticProofBundles(1)[0])
	idx.FileName = "bench-record-0001.txt"
	idx.StorageURI = "bench://tenant/client/bench-record-0001.txt"

	b.ReportAllocs()
	for b.Loop() {
		count := 0
		if err := visitRecordIndexKeys(idx, RecordIndexModeFull, func([]byte) error {
			count++
			return nil
		}); err != nil {
			b.Fatal(err)
		}
		benchmarkRecordIndexKeyCount = count
	}
}

func BenchmarkPebbleGetBundleV2(b *testing.B) {
	store, err := Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close() })
	bundle := syntheticCompressibleProofBundle("bench-record-v2")
	if err := store.PutBundle(context.Background(), bundle); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		got, err := store.GetBundle(context.Background(), bundle.RecordID)
		if err != nil {
			b.Fatal(err)
		}
		if got.RecordID == "" {
			b.Fatal("empty proof bundle")
		}
	}
}

func TestStageSetRecordKeyMatchesKeyBuilders(t *testing.T) {
	t.Parallel()

	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const recordID = "tr1-stage-record-key"
	value := []byte("value")
	tests := []struct {
		name   string
		prefix string
		key    []byte
	}{
		{name: "bundle", prefix: prefixBundleV2, key: bundleV2Key(recordID)},
		{name: "record index", prefix: prefixRecordByID, key: recordByIDKey(recordID)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			batch := store.db.NewBatch()
			defer batch.Close()
			if err := stageSetRecordKey(batch, tt.prefix, recordID, value); err != nil {
				t.Fatal(err)
			}
			if err := batch.Commit(pdb.NoSync); err != nil {
				t.Fatal(err)
			}
			got, closer, err := store.db.Get(tt.key)
			if err != nil {
				t.Fatal(err)
			}
			defer closer.Close()
			if !bytes.Equal(got, value) {
				t.Fatalf("value = %q, want %q", got, value)
			}
		})
	}
}

func TestEncodeBatchArtifactIntoMatchesWrapper(t *testing.T) {
	t.Parallel()

	bundle := syntheticProofBundles(1)[0]
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

func TestStorePutBundleWritesCompressedV2AndRoundTrips(t *testing.T) {
	t.Parallel()

	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()
	bundle := syntheticCompressibleProofBundle("tr-compressed")
	if err := store.PutBundle(context.Background(), bundle); err != nil {
		t.Fatalf("PutBundle: %v", err)
	}
	val, closer, err := store.db.Get(bundleV2Key(bundle.RecordID))
	if err != nil {
		t.Fatalf("get v2 bundle key: %v", err)
	}
	var envelope storedProofBundleEnvelope
	if err := cborx.UnmarshalLimit(val, &envelope, maxStoredObjectBytes); err != nil {
		_ = closer.Close()
		t.Fatalf("decode v2 envelope: %v", err)
	}
	_ = closer.Close()
	if envelope.SchemaVersion != schemaStoredProofBundleV2 || envelope.Codec != storedBundleCodecSnappy {
		t.Fatalf("envelope = %+v", envelope)
	}
	got, err := store.GetBundle(context.Background(), bundle.RecordID)
	if err != nil {
		t.Fatalf("GetBundle: %v", err)
	}
	if got.RecordID != bundle.RecordID || len(got.BatchProof.AuditPath) != len(bundle.BatchProof.AuditPath) {
		t.Fatalf("round trip = %+v", got)
	}
}

func TestStoreGetBundleReadsLegacyBundle(t *testing.T) {
	t.Parallel()

	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()
	bundle := syntheticProofBundles(1)[0]
	data, err := cborx.Marshal(bundle)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := store.db.Set(bundleKey(bundle.RecordID), data, pdb.Sync); err != nil {
		t.Fatalf("write legacy bundle: %v", err)
	}
	got, err := store.GetBundle(context.Background(), bundle.RecordID)
	if err != nil {
		t.Fatalf("GetBundle: %v", err)
	}
	if got.RecordID != bundle.RecordID || got.CommittedReceipt.BatchID != bundle.CommittedReceipt.BatchID {
		t.Fatalf("legacy round trip = %+v", got)
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

func TestStoreSecondaryRecordIndexesUseRefs(t *testing.T) {
	t.Parallel()

	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()
	bundle := syntheticProofBundles(1)[0]
	if err := store.PutBundle(context.Background(), bundle); err != nil {
		t.Fatalf("PutBundle: %v", err)
	}
	iter, err := store.db.NewIter(&pdb.IterOptions{
		LowerBound: []byte(prefixRecordByBatch),
		UpperBound: []byte("record/by-batch0"),
	})
	if err != nil {
		t.Fatalf("NewIter: %v", err)
	}
	defer iter.Close()
	if ok := iter.First(); !ok {
		t.Fatalf("missing batch secondary index: %v", iter.Error())
	}
	recordID, ok := decodeRecordIndexRef(iter.Value())
	if !ok || recordID != bundle.RecordID {
		t.Fatalf("secondary index value is not a record ref: id=%q ok=%v raw=%x", recordID, ok, iter.Value())
	}
	records, err := store.ListRecordIndexes(context.Background(), model.RecordListOptions{BatchID: bundle.CommittedReceipt.BatchID})
	if err != nil {
		t.Fatalf("ListRecordIndexes: %v", err)
	}
	if len(records) != 1 || records[0].RecordID != bundle.RecordID {
		t.Fatalf("records = %+v", records)
	}
}

func TestStoreCanDisableStorageTokenIndexes(t *testing.T) {
	t.Parallel()

	store, err := OpenWithOptions(t.TempDir(), Options{RecordIndexMode: RecordIndexModeNoStorageTokens})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer store.Close()
	bundle := syntheticProofBundles(1)[0]
	bundle.SignedClaim.Claim.Content.StorageURI = "bench://tenant/searchable-file-0001"
	bundle.SignedClaim.Claim.Metadata.Custom = map[string]string{"file_name": "searchable-file-0001.txt"}
	if err := store.PutBundle(context.Background(), bundle); err != nil {
		t.Fatalf("PutBundle: %v", err)
	}
	if got := countKeysWithPrefix(t, store, prefixRecordByToken); got != 0 {
		t.Fatalf("token index keys = %d, want 0", got)
	}
	records, err := store.ListRecordIndexes(context.Background(), model.RecordListOptions{Query: "searchable"})
	if err != nil {
		t.Fatalf("ListRecordIndexes: %v", err)
	}
	if len(records) != 1 || records[0].RecordID != bundle.RecordID {
		t.Fatalf("query records = %+v", records)
	}
}

func TestStoreDisablingStorageTokenIndexesRemovesOldTokenKeys(t *testing.T) {
	t.Parallel()

	store, err := OpenWithOptions(t.TempDir(), Options{RecordIndexMode: RecordIndexModeFull})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer store.Close()
	bundle := syntheticProofBundles(1)[0]
	bundle.SignedClaim.Claim.Content.StorageURI = "bench://tenant/toggle-file-0001"
	bundle.SignedClaim.Claim.Metadata.Custom = map[string]string{"file_name": "toggle-file-0001.txt"}
	if err := store.PutBundle(context.Background(), bundle); err != nil {
		t.Fatalf("PutBundle enabled: %v", err)
	}
	if got := countKeysWithPrefix(t, store, prefixRecordByToken); got == 0 {
		t.Fatal("token index keys = 0, want enabled store to write token indexes")
	}

	store.recordIndexMode = RecordIndexModeNoStorageTokens
	bundle.AcceptedReceipt.Status = "accepted-again"
	if err := store.PutBundle(context.Background(), bundle); err != nil {
		t.Fatalf("PutBundle disabled: %v", err)
	}
	if got := countKeysWithPrefix(t, store, prefixRecordByToken); got != 0 {
		t.Fatalf("token index keys after disabled replace = %d, want 0", got)
	}
	records, err := store.ListRecordIndexes(context.Background(), model.RecordListOptions{Query: "toggle"})
	if err != nil {
		t.Fatalf("ListRecordIndexes: %v", err)
	}
	if len(records) != 1 || records[0].RecordID != bundle.RecordID {
		t.Fatalf("query records = %+v", records)
	}
}

func TestStoreRecordIndexModeTimeOnlyScansAndFilters(t *testing.T) {
	t.Parallel()

	store, err := OpenWithOptions(t.TempDir(), Options{RecordIndexMode: RecordIndexModeTimeOnly})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer store.Close()
	bundle := syntheticProofBundles(1)[0]
	bundle.SignedClaim.Claim.TenantID = "tenant-time-only"
	bundle.SignedClaim.Claim.ClientID = "client-time-only"
	bundle.SignedClaim.Claim.Content.StorageURI = "bench://tenant-time-only/searchable-file-0001"
	bundle.SignedClaim.Claim.Metadata.Custom = map[string]string{"file_name": "searchable-file-0001.txt"}
	bundle.ServerRecord.TenantID = bundle.SignedClaim.Claim.TenantID
	bundle.ServerRecord.ClientID = bundle.SignedClaim.Claim.ClientID
	if err := store.PutBundle(context.Background(), bundle); err != nil {
		t.Fatalf("PutBundle: %v", err)
	}
	for _, prefix := range []string{
		prefixRecordByBatch,
		prefixRecordByLevel,
		prefixRecordByTenant,
		prefixRecordByClient,
		prefixRecordByHash,
		prefixRecordByToken,
	} {
		if got := countKeysWithPrefix(t, store, prefix); got != 0 {
			t.Fatalf("%s keys = %d, want 0", prefix, got)
		}
	}
	for name, opts := range map[string]model.RecordListOptions{
		"tenant":       {TenantID: "tenant-time-only"},
		"client":       {ClientID: "client-time-only"},
		"proof-level":  {ProofLevel: "L3"},
		"content-hash": {ContentHash: bundle.SignedClaim.Claim.Content.ContentHash},
		"query":        {Query: "searchable"},
		"time-range": {
			ReceivedFromUnixN: bundle.ServerRecord.ReceivedAtUnixN - 1,
			ReceivedToUnixN:   bundle.ServerRecord.ReceivedAtUnixN + 1,
		},
	} {
		records, err := store.ListRecordIndexes(context.Background(), opts)
		if err != nil {
			t.Fatalf("ListRecordIndexes(%s): %v", name, err)
		}
		if len(records) != 1 || records[0].RecordID != bundle.RecordID {
			t.Fatalf("ListRecordIndexes(%s) = %+v", name, records)
		}
	}
}

func TestStoreBatchArtifactsReplaceOldSecondaryIndexes(t *testing.T) {
	t.Parallel()

	store, err := OpenWithOptions(t.TempDir(), Options{RecordIndexMode: RecordIndexModeFull})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer store.Close()
	bundles := syntheticProofBundles(1)
	bundles[0].SignedClaim.Claim.Content.StorageURI = "bench://tenant/batch-toggle-file-0001"
	bundles[0].SignedClaim.Claim.Metadata.Custom = map[string]string{"file_name": "batch-toggle-file-0001.txt"}
	root := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       bundles[0].CommittedReceipt.BatchID,
		BatchRoot:     bundles[0].CommittedReceipt.BatchRoot,
		TreeSize:      1,
		ClosedAtUnixN: bundles[0].CommittedReceipt.ClosedAtUnixN,
	}
	if err := store.PutBatchArtifacts(context.Background(), bundles, root); err != nil {
		t.Fatalf("PutBatchArtifacts full: %v", err)
	}
	if got := countKeysWithPrefix(t, store, prefixRecordByToken); got == 0 {
		t.Fatal("token index keys = 0, want full batch artifact write to create tokens")
	}

	store.recordIndexMode = RecordIndexModeTimeOnly
	if err := store.PutBatchArtifacts(context.Background(), bundles, root); err != nil {
		t.Fatalf("PutBatchArtifacts time_only: %v", err)
	}
	for _, prefix := range []string{prefixRecordByBatch, prefixRecordByTenant, prefixRecordByClient, prefixRecordByHash, prefixRecordByToken} {
		if got := countKeysWithPrefix(t, store, prefix); got != 0 {
			t.Fatalf("%s keys after time_only replace = %d, want 0", prefix, got)
		}
	}
	records, err := store.ListRecordIndexes(context.Background(), model.RecordListOptions{Query: "batch-toggle"})
	if err != nil {
		t.Fatalf("ListRecordIndexes: %v", err)
	}
	if len(records) != 1 || records[0].RecordID != bundles[0].RecordID {
		t.Fatalf("query records = %+v", records)
	}
}

func TestStoreBatchIndexesReplaceOldStorageTokenIndexes(t *testing.T) {
	t.Parallel()

	store, err := OpenWithOptions(t.TempDir(), Options{RecordIndexMode: RecordIndexModeFull})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer store.Close()
	bundle := syntheticProofBundles(1)[0]
	bundle.SignedClaim.Claim.Content.StorageURI = "bench://tenant/batch-index-toggle-file-0001"
	bundle.SignedClaim.Claim.Metadata.Custom = map[string]string{"file_name": "batch-index-toggle-file-0001.txt"}
	idx := model.RecordIndexFromBundle(bundle)
	root := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       idx.BatchID,
		BatchRoot:     bundle.CommittedReceipt.BatchRoot,
		TreeSize:      1,
		ClosedAtUnixN: bundle.CommittedReceipt.ClosedAtUnixN,
	}
	if err := store.PutBatchIndexesAndRoot(context.Background(), []model.RecordIndex{idx}, root); err != nil {
		t.Fatalf("PutBatchIndexesAndRoot full: %v", err)
	}
	if got := countKeysWithPrefix(t, store, prefixRecordByToken); got == 0 {
		t.Fatal("token index keys = 0, want full batch index write to create tokens")
	}

	store.recordIndexMode = RecordIndexModeNoStorageTokens
	if err := store.PutBatchIndexesAndRoot(context.Background(), []model.RecordIndex{idx}, root); err != nil {
		t.Fatalf("PutBatchIndexesAndRoot no_storage_tokens: %v", err)
	}
	if got := countKeysWithPrefix(t, store, prefixRecordByToken); got != 0 {
		t.Fatalf("token index keys after no_storage_tokens replace = %d, want 0", got)
	}
	records, err := store.ListRecordIndexes(context.Background(), model.RecordListOptions{Query: "batch-index-toggle"})
	if err != nil {
		t.Fatalf("ListRecordIndexes: %v", err)
	}
	if len(records) != 1 || records[0].RecordID != idx.RecordID {
		t.Fatalf("query records = %+v", records)
	}
}

func countKeysWithPrefix(t *testing.T, store *Store, prefix string) int {
	t.Helper()
	lower, upper := prefixBounds(prefix)
	iter, err := store.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		t.Fatalf("NewIter: %v", err)
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

func syntheticProofBundles(n int) []model.ProofBundle {
	bundles := make([]model.ProofBundle, n)
	for i := range bundles {
		recordID := fmt.Sprintf("bench-record-%04d", i)
		bundles[i] = model.ProofBundle{
			SchemaVersion: model.SchemaProofBundle,
			RecordID:      recordID,
			SignedClaim: model.SignedClaim{
				SchemaVersion: model.SchemaSignedClaim,
				Claim: model.ClientClaim{
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
			ServerRecord: model.ServerRecord{
				SchemaVersion:   model.SchemaServerRecord,
				RecordID:        recordID,
				TenantID:        "bench-tenant",
				ClientID:        "bench-client",
				KeyID:           "bench-key",
				ReceivedAtUnixN: int64(1_000 + i),
				WAL:             model.WALPosition{SegmentID: 1, Offset: int64(i * 512), Sequence: uint64(i + 1)},
			},
			CommittedReceipt: model.CommittedReceipt{
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

func syntheticCompressibleProofBundle(recordID string) model.ProofBundle {
	bundle := syntheticProofBundles(1)[0]
	bundle.RecordID = recordID
	bundle.SignedClaim.Signature.Signature = bytes.Repeat([]byte{7}, 4096)
	bundle.AcceptedReceipt.ServerSig.Signature = bytes.Repeat([]byte{8}, 4096)
	bundle.CommittedReceipt.ServerSig.Signature = bytes.Repeat([]byte{9}, 4096)
	bundle.BatchProof.AuditPath = make([][]byte, 128)
	for i := range bundle.BatchProof.AuditPath {
		bundle.BatchProof.AuditPath[i] = bytes.Repeat([]byte{byte(i % 8)}, 32)
	}
	return bundle
}
