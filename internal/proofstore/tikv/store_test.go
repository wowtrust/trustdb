package tikv

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
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

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

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

func TestGetBundleMissUsesOnePointRead(t *testing.T) {
	db, countingClient := newMockTiKVDB(t, "bundle-miss/")
	store := &Store{db: db}

	if _, err := store.GetBundle(context.Background(), "missing-record"); trusterr.CodeOf(err) != trusterr.CodeNotFound {
		t.Fatalf("GetBundle error = %v, code = %s, want %s", err, trusterr.CodeOf(err), trusterr.CodeNotFound)
	}
	if requests := countingClient.getRequests.Load(); requests != 1 {
		t.Fatalf("GetBundle point-get requests = %d, want 1", requests)
	}
}

func TestTiKVDoesNotUseSharedCheckpointForLocalWALPruning(t *testing.T) {
	t.Parallel()
	var store *Store
	if store.WALCheckpointPruneSafe() {
		t.Fatal("TiKV store reported a shared checkpoint safe for a node-local WAL")
	}
}

func TestTiKVPreparedManifestIndexBoundsAndTransitions(t *testing.T) {
	db, countingClient := newMockTiKVDB(t, "prepared-manifests/")
	store := &Store{db: db}
	ctx := context.Background()

	for i := range 128 {
		if err := store.PutManifest(ctx, model.BatchManifest{
			SchemaVersion: model.SchemaBatchManifest,
			BatchID:       fmt.Sprintf("committed-%03d", i),
			State:         model.BatchStateCommitted,
		}); err != nil {
			t.Fatalf("PutManifest(committed %d): %v", i, err)
		}
	}
	readyA := model.BatchManifest{SchemaVersion: model.SchemaBatchManifest, BatchID: "ready-a", NodeID: "node-a", State: model.BatchStatePrepared, MaterializeNextUnixN: 10}
	readyB := model.BatchManifest{SchemaVersion: model.SchemaBatchManifest, BatchID: "ready-b", NodeID: "node-b", State: model.BatchStatePrepared, MaterializeNextUnixN: 20}
	readyC := model.BatchManifest{SchemaVersion: model.SchemaBatchManifest, BatchID: "ready-c", NodeID: "node-a", State: model.BatchStatePrepared, MaterializeNextUnixN: 30}
	future := model.BatchManifest{SchemaVersion: model.SchemaBatchManifest, BatchID: "future", NodeID: "node-a", State: model.BatchStatePrepared, MaterializeNextUnixN: 1_000}
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
	store := &Store{db: db}
	indexed := model.BatchManifest{SchemaVersion: model.SchemaBatchManifest, BatchID: "indexed", State: model.BatchStatePrepared}
	wrong := model.BatchManifest{SchemaVersion: model.SchemaBatchManifest, BatchID: "wrong", State: model.BatchStatePrepared}
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
	if !bytes.HasPrefix(got, []byte(namespacePrefix)) {
		t.Fatalf("namespace prefix %q does not start with %q", got, namespacePrefix)
	}
	if !bytes.HasSuffix(got, []byte(wantSuffix)) {
		t.Fatalf("namespace prefix %q does not end with encoded namespace %q", got, wantSuffix)
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
	store := &Store{db: db, recordIndexMode: RecordIndexModeFull}

	batch := db.NewBatch()
	defer batch.Close()
	const recordCount = 1000
	for index := range recordCount {
		idx := model.RecordIndex{
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
	store := &Store{db: db, recordIndexMode: RecordIndexModeFull}
	first := model.RecordIndex{
		SchemaVersion:   model.SchemaRecordIndex,
		RecordID:        "tr1-reference",
		ReceivedAtUnixN: 1,
	}
	legacy := model.RecordIndex{
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
	prewriteTransactions atomic.Int64
	prewriteVersions     sync.Map
	scanVersion          atomic.Uint64
	batchGetVersion      atomic.Uint64
	readVersionDrift     atomic.Bool
	batchGetHook         func()
}

func (client *countingTiKVClient) SendRequest(ctx context.Context, address string, request *tikvrpc.Request, timeout time.Duration) (*tikvrpc.Response, error) {
	switch request.Type {
	case tikvrpc.CmdScan:
		client.scanRequests.Add(1)
		client.scanVersion.Store(request.Scan().Version)
	case tikvrpc.CmdGet:
		client.getRequests.Add(1)
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
		client.prewriteMutations.Add(int64(len(request.Prewrite().Mutations)))
		if _, loaded := client.prewriteVersions.LoadOrStore(request.Prewrite().StartVersion, struct{}{}); !loaded {
			client.prewriteTransactions.Add(1)
		}
	}
	return client.Client.SendRequest(ctx, address, request, timeout)
}

func (client *countingTiKVClient) resetWriteRequests() {
	client.prewriteRequests.Store(0)
	client.prewriteMutations.Store(0)
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

func syntheticTiKVProofBundles(n int) []model.ProofBundle {
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
