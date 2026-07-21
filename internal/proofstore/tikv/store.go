// Package tikv provides a TiKV-backed implementation of proofstore.Store.
package tikv

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/snappy"
	tikverr "github.com/tikv/client-go/v2/error"
	"github.com/tikv/client-go/v2/kv"
	tikvclient "github.com/tikv/client-go/v2/tikv"
	"github.com/tikv/client-go/v2/txnkv"
	"github.com/tikv/client-go/v2/txnkv/txnsnapshot"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/idempotency"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

const (
	defaultNamespace = "default"
	namespacePrefix  = "trustdb/proofstore/v1/ns/"
)

// maxStoredObjectBytes caps decode input size to guard against corrupt
// values that claim to be multi-gigabyte CBOR payloads. Mirrors the same
// constant in the file backend.
const maxStoredObjectBytes = 64 << 20
const (
	batchArtifactChunkSize       = 1024
	batchTreeTileSize            = 512
	batchTreeTilesPerTransaction = 64
	bundleCompressionMinBytes    = 4 << 10
	maxBatchArtifactEncodeWorker = 16
	globalOutboxReadBatchSize    = 1024
	checkpointCommitMaxAttempts  = 16
	promotionCommitMaxAttempts   = 3
	promotionReferenceBatchSize  = 1024
)

var errStopScan = errors.New("stop scan")

var errNotFound = errors.New("tikv key not found")

type writeOptions struct{}

var (
	syncWrite = &writeOptions{}
	noSync    = &writeOptions{}
)

type valueCloser struct{}

func (valueCloser) Close() error { return nil }

type tikvDB struct {
	client    *txnkv.Client
	namespace []byte
}

func (db *tikvDB) Close() error {
	if db == nil || db.client == nil {
		return nil
	}
	return db.client.Close()
}

func (db *tikvDB) Get(key []byte) ([]byte, valueCloser, error) {
	if db == nil || db.client == nil {
		return nil, valueCloser{}, trusterr.New(trusterr.CodeFailedPrecondition, "tikv proofstore is closed")
	}
	return db.rawGet(db.physicalKey(key))
}

func (db *tikvDB) rawGet(key []byte) ([]byte, valueCloser, error) {
	ctx := context.Background()
	ts, err := db.client.GetTimestamp(ctx)
	if err != nil {
		return nil, valueCloser{}, err
	}
	value, err := db.client.GetSnapshot(ts).Get(ctx, key)
	if err != nil {
		if tikverr.IsErrNotFound(err) {
			return nil, valueCloser{}, errNotFound
		}
		return nil, valueCloser{}, err
	}
	return append([]byte(nil), value...), valueCloser{}, nil
}

func (db *tikvDB) Set(key, value []byte, _ *writeOptions) error {
	batch := db.NewBatch()
	defer batch.Close()
	if err := batch.Set(key, value, nil); err != nil {
		return err
	}
	return batch.Commit(syncWrite)
}

func (db *tikvDB) NewBatch() *tikvBatch {
	return &tikvBatch{db: db}
}

func (db *tikvDB) NewIter(opts *iterOptions) (*tikvIter, error) {
	if db == nil || db.client == nil {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "tikv proofstore is closed")
	}
	var physicalOpts *iterOptions
	if opts != nil {
		physicalOpts = &iterOptions{
			LowerBound: db.physicalKey(opts.LowerBound),
			UpperBound: db.physicalKey(opts.UpperBound),
		}
	}
	iter, err := db.rawNewIter(physicalOpts)
	if err != nil {
		return nil, err
	}
	iter.namespace = db.namespace
	iter.stripNamespace = true
	return iter, nil
}

func (db *tikvDB) rawNewIter(opts *iterOptions) (*tikvIter, error) {
	ctx := context.Background()
	ts, err := db.client.GetTimestamp(ctx)
	if err != nil {
		return nil, err
	}
	iter := &tikvIter{snapshot: db.client.GetSnapshot(ts)}
	if opts != nil {
		iter.lower = append([]byte(nil), opts.LowerBound...)
		iter.upper = append([]byte(nil), opts.UpperBound...)
	}
	return iter, nil
}

func (db *tikvDB) physicalKey(key []byte) []byte {
	out := make([]byte, 0, len(db.namespace)+len(key))
	out = append(out, db.namespace...)
	return append(out, key...)
}

func (db *tikvDB) rawSet(key, value []byte) error {
	batch := &tikvBatch{db: db, raw: true}
	defer batch.Close()
	if err := batch.Set(key, value, nil); err != nil {
		return err
	}
	return batch.Commit(syncWrite)
}

func (db *tikvDB) rawDelete(key []byte) error {
	batch := &tikvBatch{db: db, raw: true}
	defer batch.Close()
	if err := batch.Delete(key, nil); err != nil {
		return err
	}
	return batch.Commit(syncWrite)
}

type batchOp struct {
	key    []byte
	value  []byte
	delete bool
}

type deferredSet struct {
	batch       *tikvBatch
	physicalKey []byte
	Key         []byte
	Value       []byte
}

func (op deferredSet) Finish() error {
	key := op.physicalKey
	if key == nil {
		key = op.Key
	}
	op.batch.ops = append(op.batch.ops, batchOp{key: key, value: op.Value})
	return nil
}

type tikvBatch struct {
	db  *tikvDB
	ops []batchOp
	raw bool
}

func (b *tikvBatch) SetDeferred(keyLen, valueLen int) deferredSet {
	if b.raw {
		return deferredSet{batch: b, Key: make([]byte, keyLen), Value: make([]byte, valueLen)}
	}
	physicalKey := make([]byte, len(b.db.namespace)+keyLen)
	copy(physicalKey, b.db.namespace)
	return deferredSet{
		batch:       b,
		physicalKey: physicalKey,
		Key:         physicalKey[len(b.db.namespace):],
		Value:       make([]byte, valueLen),
	}
}

func (b *tikvBatch) Set(key, value []byte, _ any) error {
	if !b.raw {
		key = b.db.physicalKey(key)
	}
	b.ops = append(b.ops, batchOp{key: append([]byte(nil), key...), value: append([]byte(nil), value...)})
	return nil
}

func (b *tikvBatch) Delete(key []byte, _ any) error {
	if !b.raw {
		key = b.db.physicalKey(key)
	}
	b.ops = append(b.ops, batchOp{key: append([]byte(nil), key...), delete: true})
	return nil
}

func (b *tikvBatch) Commit(_ *writeOptions) error {
	if b == nil || b.db == nil || b.db.client == nil {
		return trusterr.New(trusterr.CodeFailedPrecondition, "tikv proofstore is closed")
	}
	ctx := context.Background()
	txn, err := b.db.client.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = txn.Rollback()
		}
	}()
	if err := b.apply(txn); err != nil {
		return err
	}
	if err := txn.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (b *tikvBatch) commitWithGlobalLogFence(ctx context.Context, expectedTreeSize uint64) error {
	if b == nil || b.db == nil || b.db.client == nil {
		return trusterr.New(trusterr.CodeFailedPrecondition, "tikv proofstore is closed")
	}
	txn, err := b.db.client.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = txn.Rollback()
		}
	}()

	var persisted model.GlobalLogState
	stateData, err := txn.Get(ctx, b.db.physicalKey([]byte(globalStateKey)))
	switch {
	case err == nil:
		if err := cborx.UnmarshalLimit(stateData, &persisted, maxStoredObjectBytes); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "decode global log state fence", err)
		}
	case tikverr.IsErrNotFound(err):
		// A missing state is the initial empty tree.
	case ctx.Err() != nil:
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "read global log state fence canceled", ctx.Err())
	default:
		return trusterr.Wrap(trusterr.CodeDataLoss, "read global log state fence", err)
	}
	if persisted.TreeSize != expectedTreeSize {
		return trusterr.New(trusterr.CodeFailedPrecondition, "global log append is based on stale tree state")
	}
	if err := b.apply(txn); err != nil {
		return err
	}
	if err := txn.Commit(ctx); err != nil {
		return globalLogCommitError(err)
	}
	committed = true
	return nil
}

func globalLogCommitError(err error) error {
	if tikverr.IsErrWriteConflict(err) {
		return trusterr.Wrap(trusterr.CodeFailedPrecondition, "global log append lost concurrent write", err)
	}
	var latchConflict *tikverr.ErrWriteConflictInLatch
	if errors.As(err, &latchConflict) {
		return trusterr.Wrap(trusterr.CodeFailedPrecondition, "global log append lost concurrent write", err)
	}
	return err
}

func (b *tikvBatch) apply(txn *txnkv.KVTxn) error {
	for _, op := range b.ops {
		if op.delete {
			if err := txn.Delete(op.key); err != nil {
				return err
			}
			continue
		}
		if err := txn.Set(op.key, op.value); err != nil {
			return err
		}
	}
	return nil
}

func (b *tikvBatch) Close() error {
	if b != nil {
		b.ops = nil
	}
	return nil
}

type iterOptions struct {
	LowerBound []byte
	UpperBound []byte
}

type tikvIter struct {
	snapshot       *txnsnapshot.KVSnapshot
	namespace      []byte
	stripNamespace bool
	lower          []byte
	upper          []byte
	scanner        tikvclient.Iterator
	reverse        bool
	key            []byte
	value          []byte
	err            error
}

func (it *tikvIter) First() bool { return it.openForward(it.lower) }
func (it *tikvIter) Last() bool  { return it.openReverse(it.upper) }

func (it *tikvIter) SeekGE(key []byte) bool {
	start := it.physicalKey(key)
	if len(it.lower) > 0 && kv.CmpKey(start, it.lower) < 0 {
		start = it.lower
	}
	return it.openForward(start)
}

func (it *tikvIter) SeekLT(key []byte) bool {
	end := it.physicalKey(key)
	if len(it.upper) > 0 && (len(end) == 0 || kv.CmpKey(end, it.upper) > 0) {
		end = it.upper
	}
	return it.openReverse(end)
}

func (it *tikvIter) Next() bool {
	if it.scanner == nil || !it.scanner.Valid() {
		return false
	}
	if err := it.scanner.Next(); err != nil {
		it.err = err
		return false
	}
	return it.captureForward()
}

func (it *tikvIter) Prev() bool {
	if !it.reverse {
		if len(it.key) == 0 {
			return false
		}
		return it.openReverse(it.physicalKey(it.key))
	}
	if it.scanner == nil || !it.scanner.Valid() {
		return false
	}
	if err := it.scanner.Next(); err != nil {
		it.err = err
		return false
	}
	return it.captureReverse()
}

func (it *tikvIter) Value() []byte { return it.value }
func (it *tikvIter) Error() error  { return it.err }

func (it *tikvIter) Close() error {
	if it.scanner != nil {
		it.scanner.Close()
		it.scanner = nil
	}
	it.key = nil
	it.value = nil
	return nil
}

func (it *tikvIter) openForward(start []byte) bool {
	it.Close()
	scanner, err := it.snapshot.Iter(start, it.upper)
	if err != nil {
		it.err = err
		return false
	}
	it.scanner = scanner
	it.reverse = false
	return it.captureForward()
}

func (it *tikvIter) openReverse(end []byte) bool {
	it.Close()
	scanner, err := it.snapshot.IterReverse(end)
	if err != nil {
		it.err = err
		return false
	}
	it.scanner = scanner
	it.reverse = true
	return it.captureReverse()
}

func (it *tikvIter) captureForward() bool {
	if it.scanner == nil || !it.scanner.Valid() {
		return false
	}
	key := it.scanner.Key()
	if len(it.upper) > 0 && kv.CmpKey(key, it.upper) >= 0 {
		return false
	}
	return it.captureCurrent()
}

func (it *tikvIter) captureReverse() bool {
	if it.scanner == nil || !it.scanner.Valid() {
		return false
	}
	key := it.scanner.Key()
	if len(it.lower) > 0 && kv.CmpKey(key, it.lower) < 0 {
		return false
	}
	return it.captureCurrent()
}

func (it *tikvIter) captureCurrent() bool {
	key := it.scanner.Key()
	if it.stripNamespace && bytes.HasPrefix(key, it.namespace) {
		key = key[len(it.namespace):]
	}
	it.key = append(it.key[:0], key...)
	it.value = append(it.value[:0], it.scanner.Value()...)
	return true
}

func (it *tikvIter) physicalKey(key []byte) []byte {
	out := make([]byte, 0, len(it.namespace)+len(key))
	out = append(out, it.namespace...)
	return append(out, key...)
}

const (
	prefixBundle         = "bundle/"
	prefixBundleV2       = "bundle-v2/"
	prefixRecordByID     = "record/by-id/"
	prefixRecordByTime   = "record/by-time/"
	prefixRecordByBatch  = "record/by-batch/"
	prefixRecordByLevel  = "record/by-proof-level/"
	prefixRecordByTenant = "record/by-tenant/"
	prefixRecordByClient = "record/by-client/"
	prefixRecordByHash   = "record/by-content/"
	prefixRecordByToken  = "record/by-storage-token/"
	prefixManifest       = "manifest/"
	prefixManifestReady  = "manifest-prepared/"
	prefixRoot           = "root/"
	prefixBatchTreeLeaf  = "batch-tree/v2/leaf/"
	prefixBatchTreeNode  = "batch-tree/v2/node/"
	prefixGlobalLeaf     = "global/leaf/"
	prefixGlobalBatch    = "global/leaf-by-batch/"
	prefixGlobalNode     = "global/node/"
	prefixSTH            = "global/sth/"
	prefixGlobalTile     = "global/tile/"
	prefixGlobalOutbox   = "global/outbox/"
	prefixGlobalStatus   = "global/outbox-status/"
	prefixAnchorOutbox   = "anchor/sth-outbox/"
	prefixAnchorStatus   = "anchor/sth-status/"
	prefixAnchorResult   = "anchor/sth-result/"
	prefixCheckpoint     = "checkpoint/wal/v2/"
	prefixIdempotency    = "idempotency/decision/"
	idempotencyReadyKey  = "meta/idempotency-projection/ready"
	idempotencyFenceKey  = "meta/idempotency-projection/fence"
	globalStateKey       = "global/state/latest"
	rootSortKeyWidth     = 20
	idempotencyReadyV1   = "trustdb.idempotency-projection.ready.v1"
)

const (
	schemaStoredProofBundleV2 = "trustdb.pebble-proof-bundle.v2"
	storedBundleCodecSnappy   = "snappy"
	schemaBatchTreeLeafTileV2 = "trustdb.batch-tree-leaf-tile.v2"
	schemaBatchTreeNodeTileV2 = "trustdb.batch-tree-node-tile.v2"
)

type batchTreeLeafTile struct {
	SchemaVersion  string   `cbor:"schema_version"`
	BatchID        string   `cbor:"batch_id"`
	StartIndex     uint64   `cbor:"start_index"`
	LeafIndexes    []uint64 `cbor:"leaf_indexes"`
	RecordIDs      []string `cbor:"record_ids"`
	Hashes         [][]byte `cbor:"hashes"`
	CreatedAtUnixN int64    `cbor:"created_at_unix_nano"`
}

type batchTreeNodeTile struct {
	SchemaVersion  string   `cbor:"schema_version"`
	BatchID        string   `cbor:"batch_id"`
	Level          uint64   `cbor:"level"`
	StartIndex     uint64   `cbor:"start_index"`
	StartIndexes   []uint64 `cbor:"start_indexes"`
	Widths         []uint64 `cbor:"widths"`
	Hashes         [][]byte `cbor:"hashes"`
	CreatedAtUnixN int64    `cbor:"created_at_unix_nano"`
}

const (
	RecordIndexModeFull            = "full"
	RecordIndexModeNoStorageTokens = "no_storage_tokens"
	RecordIndexModeTimeOnly        = "time_only"

	ArtifactSyncModeChunk = "chunk"
	ArtifactSyncModeBatch = "batch"
)

var (
	recordIndexRefPrefix = []byte("trustdb.record-index-ref.v1\x00")
	recordByIDPrefix     = []byte(prefixRecordByID)
)

type storedProofBundleEnvelope struct {
	SchemaVersion string `cbor:"schema_version" json:"schema_version"`
	Codec         string `cbor:"codec" json:"codec"`
	Data          []byte `cbor:"data" json:"data"`
}

type Options struct {
	PDAddresses                  []string
	PDAddressText                string
	Keyspace                     string
	Namespace                    string
	CheckpointNodeID             string
	CheckpointWALID              string
	RecordIndexMode              string
	ArtifactSyncMode             string
	IndexStorageTokens           bool
	IndexStorageTokensConfigured bool
}

type encodedBatchArtifact struct {
	recordID    string
	bundleValue []byte
	bundleBuf   *bytes.Buffer
	index       encodedRecordIndex
}

func (a encodedBatchArtifact) release() {
	putArtifactBuffer(a.bundleBuf)
	a.index.release()
}

type encodedRecordIndex struct {
	idx      model.RecordIndex
	value    []byte
	valueBuf *bytes.Buffer
}

func (idx encodedRecordIndex) release() {
	putArtifactBuffer(idx.valueBuf)
}

var artifactBufferPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// Store is a TiKV-backed proof store. It is safe for concurrent use
// from multiple goroutines; TiKV transactions provide atomic multi-key commits for write batches.
type Store struct {
	db               *tikvDB
	recordIndexMode  string
	artifactSyncMode string
	checkpointNodeID string
	checkpointWALID  string
	idempotencyReady atomic.Bool

	// closeOnce guards the underlying db.Close so that duplicate
	// Close calls from defers and shutdown hooks cannot panic on a
	// double-free inside the TiKV client.
	closeOnce sync.Once
	closeErr  error
}

// WALCheckpointPruneSafe is true only when this shared store is bound to the
// exact compute node and local WAL whose recovery boundary it persists.
func (s *Store) WALCheckpointPruneSafe() bool {
	return s != nil && s.hasCheckpointScope() && s.idempotencyReady.Load()
}

func (s *Store) hasCheckpointScope() bool {
	return s != nil && s.checkpointNodeID != "" && s.checkpointWALID != ""
}

// Open connects to a TiKV cluster using PD addresses and wraps it in a Store.
func Open(pdAddresses []string) (*Store, error) {
	return OpenWithOptions(Options{
		PDAddresses:      pdAddresses,
		Namespace:        defaultNamespace,
		RecordIndexMode:  RecordIndexModeFull,
		ArtifactSyncMode: ArtifactSyncModeChunk,
	})
}

func OpenWithOptions(opts Options) (*Store, error) {
	pdAddresses := NormalizePDAddresses(opts.PDAddresses, opts.PDAddressText)
	if len(pdAddresses) == 0 {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "tikv proofstore requires at least one PD endpoint")
	}
	clientOpts := []txnkv.ClientOpt{}
	if strings.TrimSpace(opts.Keyspace) != "" {
		clientOpts = append(clientOpts, txnkv.WithKeyspace(strings.TrimSpace(opts.Keyspace)))
	}
	client, err := txnkv.NewClient(pdAddresses, clientOpts...)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeInternal, "open tikv proofstore", err)
	}
	return &Store{
		db:               &tikvDB{client: client, namespace: namespaceKeyPrefix(opts.Namespace)},
		recordIndexMode:  normalizeRecordIndexMode(opts),
		artifactSyncMode: normalizeArtifactSyncMode(opts.ArtifactSyncMode),
		checkpointNodeID: strings.TrimSpace(opts.CheckpointNodeID),
		checkpointWALID:  strings.TrimSpace(opts.CheckpointWALID),
	}, nil
}

func NormalizeNamespace(namespace string) string {
	trimmed := strings.TrimSpace(namespace)
	if trimmed == "" {
		return defaultNamespace
	}
	return trimmed
}

func namespaceKeyPrefix(namespace string) []byte {
	normalized := NormalizeNamespace(namespace)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(normalized))
	out := make([]byte, 0, len(namespacePrefix)+len(encoded)+1)
	out = append(out, namespacePrefix...)
	out = append(out, encoded...)
	return append(out, '/')
}

func normalizeRecordIndexMode(opts Options) string {
	mode := strings.ToLower(strings.TrimSpace(opts.RecordIndexMode))
	if mode == "" && opts.IndexStorageTokensConfigured && !opts.IndexStorageTokens {
		mode = RecordIndexModeNoStorageTokens
	}
	switch mode {
	case "", RecordIndexModeFull:
		return RecordIndexModeFull
	case RecordIndexModeNoStorageTokens:
		return RecordIndexModeNoStorageTokens
	case RecordIndexModeTimeOnly:
		return RecordIndexModeTimeOnly
	default:
		return RecordIndexModeFull
	}
}

func normalizeArtifactSyncMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case ArtifactSyncModeBatch:
		return ArtifactSyncModeBatch
	default:
		return ArtifactSyncModeChunk
	}
}

// Close releases the underlying TiKV client. It is safe to call
// multiple times and from multiple goroutines; subsequent calls return
// the result of the first close.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.db.Close()
	})
	return s.closeErr
}

// bundleKey returns the KV key used to store a proof bundle. The record_id is
// written raw because TiKV, unlike the filesystem, has no filename escaping
// constraints.
func bundleKey(recordID string) []byte {
	return append([]byte(prefixBundle), recordID...)
}

func bundleV2Key(recordID string) []byte {
	return append([]byte(prefixBundleV2), recordID...)
}

func recordByIDKey(recordID string) []byte {
	return append([]byte(prefixRecordByID), recordID...)
}

func recordSecondaryPart(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func appendRecordSecondaryPart(dst []byte, value string) []byte {
	return base64.RawURLEncoding.AppendEncode(dst, []byte(value))
}

func appendZeroPaddedInt(dst []byte, value int64, width int) []byte {
	var tmp [32]byte
	digits := strconv.AppendInt(tmp[:0], value, 10)
	if len(digits) < width {
		for i := 0; i < width-len(digits); i++ {
			dst = append(dst, '0')
		}
	}
	return append(dst, digits...)
}

func appendRecordIndexSuffix(dst []byte, receivedAtUnixN int64, recordID string) []byte {
	dst = appendZeroPaddedInt(dst, receivedAtUnixN, rootSortKeyWidth)
	dst = append(dst, '/')
	return append(dst, recordID...)
}

func recordIndexKey(prefix string, receivedAtUnixN int64, recordID string) []byte {
	key := make([]byte, 0, len(prefix)+rootSortKeyWidth+1+len(recordID))
	key = append(key, prefix...)
	return appendRecordIndexSuffix(key, receivedAtUnixN, recordID)
}

func recordIndexUpperTimeKey(prefix string, receivedAtUnixN int64) []byte {
	key := make([]byte, 0, len(prefix)+rootSortKeyWidth+1)
	key = append(key, prefix...)
	key = appendZeroPaddedInt(key, receivedAtUnixN, rootSortKeyWidth)
	return append(key, '0')
}

func visitRecordIndexKeys(idx model.RecordIndex, mode string, visit func([]byte) error) error {
	if idx.RecordID == "" {
		return nil
	}
	mode = normalizeRecordIndexMode(Options{RecordIndexMode: mode})
	key := make([]byte, 0, recordIndexKeyCap(idx))
	key = append(key, recordByIDPrefix...)
	key = append(key, idx.RecordID...)
	if err := visit(key); err != nil {
		return err
	}
	key = appendRecordIndexKeyPrefix(key[:0], prefixRecordByTime, idx.ReceivedAtUnixN, idx.RecordID)
	if err := visit(key); err != nil {
		return err
	}
	if mode == RecordIndexModeTimeOnly {
		return nil
	}
	if idx.BatchID != "" {
		key = appendRecordIndexEncodedPrefix(key[:0], prefixRecordByBatch, idx.BatchID, idx.ReceivedAtUnixN, idx.RecordID)
		if err := visit(key); err != nil {
			return err
		}
	}
	if idx.ProofLevel != "" {
		key = appendRecordIndexEncodedPrefix(key[:0], prefixRecordByLevel, idx.ProofLevel, idx.ReceivedAtUnixN, idx.RecordID)
		if err := visit(key); err != nil {
			return err
		}
	}
	if idx.TenantID != "" {
		key = appendRecordIndexEncodedPrefix(key[:0], prefixRecordByTenant, idx.TenantID, idx.ReceivedAtUnixN, idx.RecordID)
		if err := visit(key); err != nil {
			return err
		}
	}
	if idx.ClientID != "" {
		key = appendRecordIndexEncodedPrefix(key[:0], prefixRecordByClient, idx.ClientID, idx.ReceivedAtUnixN, idx.RecordID)
		if err := visit(key); err != nil {
			return err
		}
	}
	if len(idx.ContentHash) > 0 {
		key = append(key[:0], prefixRecordByHash...)
		key = hex.AppendEncode(key, idx.ContentHash)
		key = append(key, '/')
		key = appendRecordIndexSuffix(key, idx.ReceivedAtUnixN, idx.RecordID)
		if err := visit(key); err != nil {
			return err
		}
	}
	if mode == RecordIndexModeFull {
		for _, token := range model.RecordIndexStorageTokens(idx) {
			key = appendRecordIndexEncodedPrefix(key[:0], prefixRecordByToken, token, idx.ReceivedAtUnixN, idx.RecordID)
			if err := visit(key); err != nil {
				return err
			}
		}
	}
	return nil
}

func appendRecordIndexKeyPrefix(dst []byte, prefix string, receivedAtUnixN int64, recordID string) []byte {
	dst = append(dst, prefix...)
	return appendRecordIndexSuffix(dst, receivedAtUnixN, recordID)
}

func appendRecordIndexEncodedPrefix(dst []byte, prefix, value string, receivedAtUnixN int64, recordID string) []byte {
	dst = append(dst, prefix...)
	dst = appendRecordSecondaryPart(dst, value)
	dst = append(dst, '/')
	return appendRecordIndexSuffix(dst, receivedAtUnixN, recordID)
}

func recordIndexKeyCap(idx model.RecordIndex) int {
	maxPart := len(idx.BatchID)
	if n := len(idx.ProofLevel); n > maxPart {
		maxPart = n
	}
	if n := len(idx.TenantID); n > maxPart {
		maxPart = n
	}
	if n := len(idx.ClientID); n > maxPart {
		maxPart = n
	}
	if maxPart < 64 {
		maxPart = 64
	}
	capHint := len(prefixRecordByToken) + base64.RawURLEncoding.EncodedLen(maxPart) + 1 + rootSortKeyWidth + 1 + len(idx.RecordID)
	if capHint < len(prefixRecordByID)+len(idx.RecordID) {
		capHint = len(prefixRecordByID) + len(idx.RecordID)
	}
	if capHint < 128 {
		return 128
	}
	return capHint
}

func manifestKey(batchID string) []byte {
	return append([]byte(prefixManifest), batchID...)
}

func preparedManifestKey(manifest model.BatchManifest) []byte {
	nextAttempt := manifest.MaterializeNextUnixN
	if nextAttempt < 0 {
		nextAttempt = 0
	}
	return []byte(fmt.Sprintf("%s%0*d/%s/%s", prefixManifestReady, rootSortKeyWidth, nextAttempt, recordSecondaryPart(manifest.NodeID), recordSecondaryPart(manifest.BatchID)))
}

// rootKey preserves the same %020d sort-order trick used by the file
// backend's filenames: zero-padding the nanosecond timestamp guarantees
// that lexical byte-order matches time-order so an iterator can read
// roots newest-first with SeekLT + Prev.
func rootKey(closedAtUnixN int64, batchID string) []byte {
	k := make([]byte, 0, len(prefixRoot)+rootSortKeyWidth+1+len(batchID))
	k = append(k, prefixRoot...)
	k = fmt.Appendf(k, "%0*d", rootSortKeyWidth, closedAtUnixN)
	k = append(k, '/')
	k = append(k, batchID...)
	return k
}

func batchTreeLeafKey(batchID string, leafIndex uint64) []byte {
	return []byte(fmt.Sprintf("%s%s/%0*d", prefixBatchTreeLeaf, batchID, rootSortKeyWidth, leafIndex))
}

func batchTreeNodeKey(batchID string, level, startIndex uint64) []byte {
	return []byte(fmt.Sprintf("%s%s/%0*d/%0*d", prefixBatchTreeNode, batchID, rootSortKeyWidth, level, rootSortKeyWidth, startIndex))
}

func isNotFound(err error) bool {
	return errors.Is(err, errNotFound)
}

// writeCBOR marshals v and writes it at key with Sync durability so the
// write is readable after an immediate crash. The sync flush mirrors
// the writeCBORAtomic + rename guarantee of the file backend.
func (s *Store) writeCBOR(key []byte, v any) error {
	data, err := cborx.Marshal(v)
	if err != nil {
		return err
	}
	if err := s.db.Set(key, data, syncWrite); err != nil {
		return err
	}
	return nil
}

// readCBOR fetches key and decodes it into v. TiKV point reads return owned bytes; the closer exists only to keep this
// implementation aligned with the Pebble store helper shape.
func (s *Store) readCBOR(key []byte, v any) (bool, error) {
	val, closer, err := s.db.Get(key)
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	defer closer.Close()
	if err := cborx.UnmarshalLimit(val, v, maxStoredObjectBytes); err != nil {
		return false, err
	}
	return true, nil
}

func getArtifactBuffer() *bytes.Buffer {
	buf := artifactBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

func putArtifactBuffer(buf *bytes.Buffer) {
	if buf == nil {
		return
	}
	if buf.Cap() > maxStoredObjectBytes {
		return
	}
	buf.Reset()
	artifactBufferPool.Put(buf)
}

func marshalArtifact(v any) ([]byte, *bytes.Buffer, error) {
	buf := getArtifactBuffer()
	if err := cborx.MarshalBuffer(buf, v); err != nil {
		putArtifactBuffer(buf)
		return nil, nil, err
	}
	return buf.Bytes(), buf, nil
}

func encodeStoredProofBundle(bundle *model.ProofBundle) ([]byte, *bytes.Buffer, error) {
	if bundle.RecordID == "" {
		return nil, nil, trusterr.New(trusterr.CodeInvalidArgument, "proof bundle record_id is required")
	}
	raw, rawBuf, err := marshalArtifact(bundle)
	if err != nil {
		return nil, nil, trusterr.Wrap(trusterr.CodeDataLoss, "encode proof bundle", err)
	}
	if len(raw) < bundleCompressionMinBytes {
		return raw, rawBuf, nil
	}
	compressedBuf := getArtifactBuffer()
	compressedBuf.Grow(snappy.MaxEncodedLen(len(raw)))
	compressed := snappy.Encode(compressedBuf.Bytes()[:0], raw)
	if len(compressed)*8 >= len(raw)*7 {
		putArtifactBuffer(compressedBuf)
		return raw, rawBuf, nil
	}
	envelopeBuf := getArtifactBuffer()
	if err := cborx.MarshalBuffer(envelopeBuf, storedProofBundleEnvelope{
		SchemaVersion: schemaStoredProofBundleV2,
		Codec:         storedBundleCodecSnappy,
		Data:          compressed,
	}); err != nil {
		putArtifactBuffer(rawBuf)
		putArtifactBuffer(compressedBuf)
		putArtifactBuffer(envelopeBuf)
		return nil, nil, trusterr.Wrap(trusterr.CodeDataLoss, "encode proof bundle envelope", err)
	}
	putArtifactBuffer(rawBuf)
	putArtifactBuffer(compressedBuf)
	return envelopeBuf.Bytes(), envelopeBuf, nil
}

func decodeStoredProofBundle(data []byte) (model.ProofBundle, error) {
	var envelope storedProofBundleEnvelope
	if err := cborx.UnmarshalLimit(data, &envelope, maxStoredObjectBytes); err == nil && envelope.SchemaVersion == schemaStoredProofBundleV2 {
		if envelope.Codec != storedBundleCodecSnappy {
			return model.ProofBundle{}, trusterr.New(trusterr.CodeDataLoss, "unsupported proof bundle codec")
		}
		decodedLen, err := snappy.DecodedLen(envelope.Data)
		if err != nil {
			return model.ProofBundle{}, trusterr.Wrap(trusterr.CodeDataLoss, "decode proof bundle envelope length", err)
		}
		if decodedLen > maxStoredObjectBytes {
			return model.ProofBundle{}, trusterr.New(trusterr.CodeDataLoss, "proof bundle envelope payload too large")
		}
		decodeBuf := getArtifactBuffer()
		defer putArtifactBuffer(decodeBuf)
		decodeBuf.Grow(decodedLen)
		raw, err := snappy.Decode(decodeBuf.Bytes()[:decodedLen], envelope.Data)
		if err != nil {
			return model.ProofBundle{}, trusterr.Wrap(trusterr.CodeDataLoss, "decompress proof bundle", err)
		}
		var bundle model.ProofBundle
		if err := cborx.UnmarshalLimit(raw, &bundle, maxStoredObjectBytes); err != nil {
			return model.ProofBundle{}, err
		}
		return bundle, nil
	}
	var bundle model.ProofBundle
	if err := cborx.UnmarshalLimit(data, &bundle, maxStoredObjectBytes); err != nil {
		return model.ProofBundle{}, err
	}
	return bundle, nil
}

func (s *Store) readStoredProofBundle(key []byte) (model.ProofBundle, bool, error) {
	val, closer, err := s.db.Get(key)
	if err != nil {
		if isNotFound(err) {
			return model.ProofBundle{}, false, nil
		}
		return model.ProofBundle{}, false, err
	}
	defer closer.Close()
	bundle, err := decodeStoredProofBundle(val)
	if err != nil {
		return model.ProofBundle{}, false, err
	}
	return bundle, true, nil
}

func encodeRecordIndexArtifact(idx model.RecordIndex) (encodedRecordIndex, error) {
	var encoded encodedRecordIndex
	if err := encodeRecordIndexArtifactInto(&encoded, idx); err != nil {
		return encodedRecordIndex{}, err
	}
	return encoded, nil
}

func encodeRecordIndexArtifactInto(encoded *encodedRecordIndex, idx model.RecordIndex) error {
	if idx.RecordID == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "record index record_id is required")
	}
	idx.ProofLevel = model.RecordIndexProofLevel(idx)
	if idx.SchemaVersion == "" {
		idx.SchemaVersion = model.SchemaRecordIndex
	}
	encoded.idx = idx
	indexData, indexBuf, err := marshalArtifact(&encoded.idx)
	if err != nil {
		*encoded = encodedRecordIndex{}
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode record index", err)
	}
	encoded.value = indexData
	encoded.valueBuf = indexBuf
	return nil
}

func encodeBatchArtifact(bundle model.ProofBundle) (encodedBatchArtifact, error) {
	var artifact encodedBatchArtifact
	if err := encodeBatchArtifactInto(&artifact, &bundle); err != nil {
		return encodedBatchArtifact{}, err
	}
	return artifact, nil
}

func encodeBatchArtifactInto(artifact *encodedBatchArtifact, bundle *model.ProofBundle) error {
	bundleValue, bundleBuf, err := encodeStoredProofBundle(bundle)
	if err != nil {
		return err
	}
	artifact.recordID = bundle.RecordID
	artifact.bundleValue = bundleValue
	artifact.bundleBuf = bundleBuf
	if err := encodeRecordIndexArtifactInto(&artifact.index, model.RecordIndexFromBundle(*bundle)); err != nil {
		putArtifactBuffer(bundleBuf)
		*artifact = encodedBatchArtifact{}
		return err
	}
	return nil
}

func encodeBatchArtifacts(ctx context.Context, bundles []model.ProofBundle) ([]encodedBatchArtifact, error) {
	artifacts := make([]encodedBatchArtifact, len(bundles))
	if len(bundles) == 0 {
		return artifacts, nil
	}
	workers := runtime.GOMAXPROCS(0)
	if workers > maxBatchArtifactEncodeWorker {
		workers = maxBatchArtifactEncodeWorker
	}
	if workers > len(bundles) {
		workers = len(bundles)
	}
	jobs := make(chan int)
	errs := make([]error, len(bundles))
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if err := ctx.Err(); err != nil {
					errs[i] = trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore encode batch artifacts canceled", err)
					continue
				}
				if err := encodeBatchArtifactInto(&artifacts[i], &bundles[i]); err != nil {
					errs[i] = err
					continue
				}
			}
		}()
	}
	for i := range bundles {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			releaseBatchArtifacts(artifacts)
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore encode batch artifacts canceled", ctx.Err())
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		releaseBatchArtifacts(artifacts)
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore encode batch artifacts canceled", err)
	}
	for i := range errs {
		if errs[i] != nil {
			releaseBatchArtifacts(artifacts)
			return nil, errs[i]
		}
	}
	return artifacts, nil
}

func releaseBatchArtifacts(artifacts []encodedBatchArtifact) {
	for i := range artifacts {
		artifacts[i].release()
	}
}

func stageSet(batch *tikvBatch, key, value []byte) error {
	op := batch.SetDeferred(len(key), len(value))
	copy(op.Key, key)
	copy(op.Value, value)
	return op.Finish()
}

func stageSetRecordKey(batch *tikvBatch, prefix, recordID string, value []byte) error {
	op := batch.SetDeferred(len(prefix)+len(recordID), len(value))
	n := copy(op.Key, prefix)
	copy(op.Key[n:], recordID)
	copy(op.Value, value)
	return op.Finish()
}

func stageRecordIndexRef(batch *tikvBatch, key []byte, recordID string) error {
	op := batch.SetDeferred(len(key), len(recordIndexRefPrefix)+len(recordID))
	copy(op.Key, key)
	copy(op.Value, recordIndexRefPrefix)
	copy(op.Value[len(recordIndexRefPrefix):], recordID)
	return op.Finish()
}

func (s *Store) artifactWriteOptions() *writeOptions {
	if s != nil && s.artifactSyncMode == ArtifactSyncModeBatch {
		return noSync
	}
	return syncWrite
}

func decodeRecordIndexRef(value []byte) (string, bool) {
	if !bytes.HasPrefix(value, recordIndexRefPrefix) {
		return "", false
	}
	recordID := string(value[len(recordIndexRefPrefix):])
	return recordID, recordID != ""
}

func (s *Store) visitRecordIndexRefs(ctx context.Context, iter *tikvIter, recordIDs []string, visit func(model.RecordIndex) bool) error {
	if len(recordIDs) == 0 {
		return nil
	}
	if s == nil || s.db == nil || iter == nil || iter.snapshot == nil {
		return trusterr.New(trusterr.CodeFailedPrecondition, "tikv record index iterator is unavailable")
	}
	keys := make([][]byte, len(recordIDs))
	for index, recordID := range recordIDs {
		key := make([]byte, 0, len(s.db.namespace)+len(recordByIDPrefix)+len(recordID))
		key = append(key, s.db.namespace...)
		key = append(key, recordByIDPrefix...)
		keys[index] = append(key, recordID...)
	}
	values, err := iter.snapshot.BatchGet(ctx, keys)
	if err != nil {
		return err
	}
	// BatchGet returns an unordered map, so consume values in scan order.
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
		value, found := values[string(key)]
		if !found {
			return trusterr.New(trusterr.CodeDataLoss, "record index reference target not found")
		}
		var idx model.RecordIndex
		if err := cborx.UnmarshalLimit(value, &idx, maxStoredObjectBytes); err != nil {
			return err
		}
		if !visit(idx) {
			return nil
		}
	}
	return nil
}

func (s *Store) PutBundle(ctx context.Context, bundle model.ProofBundle) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put bundle canceled", err)
	}
	if bundle.RecordID == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "proof bundle record_id is required")
	}
	artifact, err := encodeBatchArtifact(bundle)
	if err != nil {
		return err
	}
	defer artifact.release()
	var old model.RecordIndex
	oldFound, err := s.readCBOR(recordByIDKey(bundle.RecordID), &old)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "read existing record index", err)
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := stageSetRecordKey(batch, prefixBundleV2, bundle.RecordID, artifact.bundleValue); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage proof bundle", err)
	}
	if err := s.stageEncodedRecordIndexReplace(batch, artifact.index, old, oldFound); err != nil {
		return err
	}
	if err := batch.Commit(syncWrite); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit proof bundle", err)
	}
	return nil
}

func (s *Store) PutBatchArtifacts(ctx context.Context, bundles []model.ProofBundle, root model.BatchRoot) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put batch artifacts canceled", err)
	}
	if len(bundles) == 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "proofstore batch artifacts require at least one bundle")
	}
	root, err := normalizeBatchRoot(root, len(bundles))
	if err != nil {
		return err
	}
	for start := 0; start < len(bundles); start += batchArtifactChunkSize {
		end := start + batchArtifactChunkSize
		if end > len(bundles) {
			end = len(bundles)
		}
		if err := ctx.Err(); err != nil {
			return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put batch artifacts canceled", err)
		}
		artifacts, err := encodeBatchArtifacts(ctx, bundles[start:end])
		if err != nil {
			return err
		}
		batch := s.db.NewBatch()
		for i := range artifacts {
			if err := s.stageEncodedBatchArtifact(batch, artifacts[i]); err != nil {
				for j := i; j < len(artifacts); j++ {
					artifacts[j].release()
				}
				_ = batch.Close()
				return err
			}
			artifacts[i].release()
		}
		if end == len(bundles) {
			if err := s.stageRoot(batch, root); err != nil {
				_ = batch.Close()
				return err
			}
		}
		if err := batch.Commit(s.artifactWriteOptions()); err != nil {
			_ = batch.Close()
			return trusterr.Wrap(trusterr.CodeDataLoss, "commit batch artifacts", err)
		}
		if err := batch.Close(); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "close batch artifacts", err)
		}
	}
	return nil
}

func (s *Store) PutMaterializedBatchArtifacts(ctx context.Context, bundles []model.ProofBundle) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put materialized batch artifacts canceled", err)
	}
	if len(bundles) == 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "proofstore materialized batch artifacts require at least one bundle")
	}
	for start := 0; start < len(bundles); start += batchArtifactChunkSize {
		end := start + batchArtifactChunkSize
		if end > len(bundles) {
			end = len(bundles)
		}
		if err := ctx.Err(); err != nil {
			return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put materialized batch artifacts canceled", err)
		}
		artifacts, err := encodeBatchArtifacts(ctx, bundles[start:end])
		if err != nil {
			return err
		}
		batch := s.db.NewBatch()
		for i := range artifacts {
			if err := s.stageEncodedMaterializedBatchArtifact(batch, artifacts[i]); err != nil {
				for j := i; j < len(artifacts); j++ {
					artifacts[j].release()
				}
				_ = batch.Close()
				return err
			}
			artifacts[i].release()
		}
		if err := batch.Commit(s.artifactWriteOptions()); err != nil {
			_ = batch.Close()
			return trusterr.Wrap(trusterr.CodeDataLoss, "commit materialized batch artifacts", err)
		}
		if err := batch.Close(); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "close materialized batch artifacts", err)
		}
	}
	return nil
}

func (s *Store) PutBatchIndexesAndRoot(ctx context.Context, indexes []model.RecordIndex, root model.BatchRoot) error {
	return s.putBatchIndexesAndRoot(ctx, indexes, root, true)
}

func (s *Store) PutPreparedBatchIndexesAndRoot(ctx context.Context, indexes []model.RecordIndex, root model.BatchRoot) error {
	return s.putBatchIndexesAndRoot(ctx, indexes, root, false)
}

func (s *Store) putBatchIndexesAndRoot(ctx context.Context, indexes []model.RecordIndex, root model.BatchRoot, replace bool) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put batch indexes canceled", err)
	}
	if len(indexes) == 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "proofstore batch indexes require at least one record index")
	}
	root, err := normalizeBatchRoot(root, len(indexes))
	if err != nil {
		return err
	}
	for start := 0; start < len(indexes); start += batchArtifactChunkSize {
		end := start + batchArtifactChunkSize
		if end > len(indexes) {
			end = len(indexes)
		}
		if err := ctx.Err(); err != nil {
			return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put batch indexes canceled", err)
		}
		encoded := make([]encodedRecordIndex, end-start)
		for i := range encoded {
			idx, err := encodeRecordIndexArtifact(indexes[start+i])
			if err != nil {
				for j := 0; j < i; j++ {
					encoded[j].release()
				}
				return err
			}
			encoded[i] = idx
		}
		batch := s.db.NewBatch()
		for i := range encoded {
			var stageErr error
			if replace {
				stageErr = s.stageEncodedRecordIndexSetForMode(batch, encoded[i])
			} else {
				stageErr = s.stageEncodedRecordIndexSet(batch, encoded[i])
			}
			if stageErr != nil {
				for j := i; j < len(encoded); j++ {
					encoded[j].release()
				}
				_ = batch.Close()
				return err
			}
			encoded[i].release()
		}
		if end == len(indexes) {
			if err := s.stageRoot(batch, root); err != nil {
				_ = batch.Close()
				return err
			}
		}
		if err := batch.Commit(s.artifactWriteOptions()); err != nil {
			_ = batch.Close()
			return trusterr.Wrap(trusterr.CodeDataLoss, "commit batch indexes", err)
		}
		if err := batch.Close(); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "close batch indexes", err)
		}
	}
	return nil
}

func (s *Store) stageNewBundle(batch *tikvBatch, bundle model.ProofBundle) error {
	artifact, err := encodeBatchArtifact(bundle)
	if err != nil {
		return err
	}
	defer artifact.release()
	return s.stageEncodedBatchArtifact(batch, artifact)
}

func (s *Store) stageEncodedBatchArtifact(batch *tikvBatch, artifact encodedBatchArtifact) error {
	if err := stageSetRecordKey(batch, prefixBundleV2, artifact.recordID, artifact.bundleValue); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage proof bundle", err)
	}
	return s.stageEncodedRecordIndexSetForMode(batch, artifact.index)
}

func (s *Store) stageEncodedMaterializedBatchArtifact(batch *tikvBatch, artifact encodedBatchArtifact) error {
	if err := stageSetRecordKey(batch, prefixBundleV2, artifact.recordID, artifact.bundleValue); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage proof bundle", err)
	}
	if err := stageSetRecordKey(batch, prefixRecordByID, artifact.recordID, artifact.index.value); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage materialized record index", err)
	}
	if s.recordIndexMode == RecordIndexModeTimeOnly {
		return nil
	}
	oldLevelKey := appendRecordIndexEncodedPrefix(nil, prefixRecordByLevel, "L2", artifact.index.idx.ReceivedAtUnixN, artifact.index.idx.RecordID)
	if err := batch.Delete(oldLevelKey, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage old proof level delete", err)
	}
	newLevelKey := appendRecordIndexEncodedPrefix(nil, prefixRecordByLevel, "L3", artifact.index.idx.ReceivedAtUnixN, artifact.index.idx.RecordID)
	if err := stageRecordIndexRef(batch, newLevelKey, artifact.index.idx.RecordID); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage materialized proof level", err)
	}
	return nil
}

func (s *Store) PutRecordIndex(ctx context.Context, idx model.RecordIndex) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put record index canceled", err)
	}
	if idx.RecordID == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "record index record_id is required")
	}
	var old model.RecordIndex
	oldFound, err := s.readCBOR(recordByIDKey(idx.RecordID), &old)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "read existing record index", err)
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := s.stageRecordIndexReplace(batch, idx, old, oldFound); err != nil {
		return err
	}
	if err := batch.Commit(syncWrite); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit record index", err)
	}
	return nil
}

func (s *Store) GetBundle(ctx context.Context, recordID string) (model.ProofBundle, error) {
	if err := ctx.Err(); err != nil {
		return model.ProofBundle{}, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get bundle canceled", err)
	}
	if recordID == "" {
		return model.ProofBundle{}, trusterr.New(trusterr.CodeInvalidArgument, "record_id is required")
	}
	var bundle model.ProofBundle
	bundle, found, err := s.readStoredProofBundle(bundleV2Key(recordID))
	if err != nil {
		return model.ProofBundle{}, trusterr.Wrap(trusterr.CodeDataLoss, "read proof bundle", err)
	}
	if found {
		return bundle, nil
	}
	return model.ProofBundle{}, trusterr.New(trusterr.CodeNotFound, "proof bundle not found")
}

func (s *Store) GetRecordIndex(ctx context.Context, recordID string) (model.RecordIndex, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.RecordIndex{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get record index canceled", err)
	}
	if recordID == "" {
		return model.RecordIndex{}, false, trusterr.New(trusterr.CodeInvalidArgument, "record_id is required")
	}
	var idx model.RecordIndex
	found, err := s.readCBOR(recordByIDKey(recordID), &idx)
	if err != nil {
		return model.RecordIndex{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read record index", err)
	}
	return idx, found, nil
}

func (s *Store) ListRecordIndexes(ctx context.Context, opts model.RecordListOptions) ([]model.RecordIndex, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list record indexes canceled", err)
	}
	limit := normaliseRecordLimit(opts.Limit)
	prefix := s.recordListPrefix(opts)
	lower, upper := prefixBounds(prefix)
	if opts.ReceivedFromUnixN > 0 {
		rangeLower := recordIndexKey(prefix, opts.ReceivedFromUnixN, "")
		if bytes.Compare(rangeLower, lower) > 0 {
			lower = rangeLower
		}
	}
	if opts.ReceivedToUnixN > 0 {
		rangeUpper := recordIndexUpperTimeKey(prefix, opts.ReceivedToUnixN)
		if len(upper) == 0 || bytes.Compare(rangeUpper, upper) < 0 {
			upper = rangeUpper
		}
	}
	if len(upper) > 0 && bytes.Compare(lower, upper) >= 0 {
		return make([]model.RecordIndex, 0, limit), nil
	}
	desc := !strings.EqualFold(opts.Direction, model.RecordListDirectionAsc)
	hasCursor := opts.AfterReceivedAtUnixN != 0 || opts.AfterRecordID != ""
	if hasCursor {
		cursorKey := recordIndexKey(prefix, opts.AfterReceivedAtUnixN, opts.AfterRecordID)
		if (!desc && len(upper) > 0 && bytes.Compare(cursorKey, upper) >= 0) ||
			(desc && bytes.Compare(cursorKey, lower) <= 0) {
			return make([]model.RecordIndex, 0, limit), nil
		}
	}
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open record index iterator", err)
	}
	defer iter.Close()

	var ok bool
	if desc {
		if hasCursor {
			ok = iter.SeekLT(recordIndexKey(prefix, opts.AfterReceivedAtUnixN, opts.AfterRecordID))
		} else if opts.ReceivedToUnixN > 0 {
			ok = iter.SeekLT(recordIndexUpperTimeKey(prefix, opts.ReceivedToUnixN))
		} else {
			ok = iter.Last()
		}
	} else if hasCursor {
		ok = iter.SeekGE(recordIndexKey(prefix, opts.AfterReceivedAtUnixN, opts.AfterRecordID))
	} else if opts.ReceivedFromUnixN > 0 {
		ok = iter.SeekGE(recordIndexKey(prefix, opts.ReceivedFromUnixN, ""))
	} else {
		ok = iter.First()
	}

	records := make([]model.RecordIndex, 0, limit)
	exhausted := false
	consume := func(idx model.RecordIndex) bool {
		if recordRangeExhausted(idx, opts, desc) {
			exhausted = true
			return false
		}
		if model.RecordIndexMatchesListOptions(idx, opts) && model.RecordIndexAfterCursor(idx, opts) {
			records = append(records, idx)
		}
		return len(records) < limit
	}
	// Bound each request by the remaining page capacity. Filters may require
	// multiple batches, but a complete page never prefetches the next one.
	pendingRecordIDs := make([]string, 0, limit)
	flushPending := func() error {
		if len(pendingRecordIDs) == 0 {
			return nil
		}
		err := s.visitRecordIndexRefs(ctx, iter, pendingRecordIDs, consume)
		pendingRecordIDs = pendingRecordIDs[:0]
		return err
	}
	readError := func(err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list record indexes canceled", ctxErr)
		}
		return trusterr.Wrap(trusterr.CodeDataLoss, "decode record index", err)
	}
	advance := func() {
		if desc {
			ok = iter.Prev()
		} else {
			ok = iter.Next()
		}
	}

	for ok && !exhausted && len(records) < limit {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list record indexes canceled", err)
		}
		if recordID, isReference := decodeRecordIndexRef(iter.Value()); isReference {
			pendingRecordIDs = append(pendingRecordIDs, recordID)
			advance()
			if len(pendingRecordIDs) >= limit-len(records) {
				if err := flushPending(); err != nil {
					return nil, readError(err)
				}
			}
			continue
		}
		if err := flushPending(); err != nil {
			return nil, readError(err)
		}
		if exhausted || len(records) >= limit {
			break
		}
		var idx model.RecordIndex
		if err := cborx.UnmarshalLimit(iter.Value(), &idx, maxStoredObjectBytes); err != nil {
			return nil, readError(err)
		}
		consume(idx)
		if exhausted {
			break
		}
		advance()
	}
	if !exhausted && len(records) < limit {
		if err := flushPending(); err != nil {
			return nil, readError(err)
		}
	}
	if !exhausted {
		if err := iter.Error(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate record indexes", err)
		}
	}
	return records, nil
}

func (s *Store) PutRoot(ctx context.Context, root model.BatchRoot) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put root canceled", err)
	}
	root, err := normalizeBatchRoot(root, 0)
	if err != nil {
		return err
	}
	if err := s.writeCBOR(rootKey(root.ClosedAtUnixN, root.BatchID), root); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write batch root", err)
	}
	return nil
}

func normalizeBatchRoot(root model.BatchRoot, expectedTreeSize int) (model.BatchRoot, error) {
	if root.BatchID == "" {
		return model.BatchRoot{}, trusterr.New(trusterr.CodeInvalidArgument, "batch root batch_id is required")
	}
	if root.SchemaVersion == "" {
		root.SchemaVersion = model.SchemaBatchRoot
	}
	if expectedTreeSize > 0 {
		if root.TreeSize == 0 {
			root.TreeSize = uint64(expectedTreeSize)
		}
		if root.TreeSize != uint64(expectedTreeSize) {
			return model.BatchRoot{}, trusterr.New(trusterr.CodeInvalidArgument, "batch root tree_size does not match bundle count")
		}
	}
	if root.ClosedAtUnixN == 0 {
		root.ClosedAtUnixN = time.Now().UTC().UnixNano()
	}
	return root, nil
}

func (s *Store) stageRoot(batch *tikvBatch, root model.BatchRoot) error {
	rootData, err := cborx.Marshal(root)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode batch root", err)
	}
	if err := stageSet(batch, rootKey(root.ClosedAtUnixN, root.BatchID), rootData); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage batch root", err)
	}
	return nil
}

// rootBounds returns the half-open iterator bounds covering every root
// key. UpperBound uses the next byte after '/' so it captures every
// timestamp suffix without colliding with other prefixes.
func rootBounds() (lower, upper []byte) {
	lower = []byte(prefixRoot)
	// '0' is the byte immediately after '/', so "root0" is the exclusive
	// upper bound for every key that starts with "root/".
	upper = []byte("root0")
	return lower, upper
}

func (s *Store) ListRoots(ctx context.Context, limit int) ([]model.BatchRoot, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list roots canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	lower, upper := rootBounds()
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open root iterator", err)
	}
	defer iter.Close()

	capHint := limit
	if capHint > 1024 {
		capHint = 1024
	}
	roots := make([]model.BatchRoot, 0, capHint)
	// Reverse iteration gives newest-first ordering because our root
	// keys are zero-padded nanosecond timestamps.
	for ok := iter.Last(); ok; ok = iter.Prev() {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list roots canceled", err)
		}
		if len(roots) >= limit {
			break
		}
		var root model.BatchRoot
		if err := cborx.UnmarshalLimit(iter.Value(), &root, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch root", err)
		}
		roots = append(roots, root)
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate roots", err)
	}
	return roots, nil
}

func (s *Store) ListRootsAfter(ctx context.Context, afterClosedAtUnixN int64, limit int) ([]model.BatchRoot, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list roots after canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	lower, upper := rootBounds()
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open root iterator", err)
	}
	defer iter.Close()
	startKey := rootKey(afterClosedAtUnixN+1, "")
	ok := iter.SeekGE(startKey)
	roots := make([]model.BatchRoot, 0, limit)
	for ; ok; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list roots after canceled", err)
		}
		if len(roots) >= limit {
			break
		}
		var root model.BatchRoot
		if err := cborx.UnmarshalLimit(iter.Value(), &root, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch root", err)
		}
		if root.ClosedAtUnixN <= afterClosedAtUnixN {
			continue
		}
		roots = append(roots, root)
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate roots after", err)
	}
	return roots, nil
}

func (s *Store) ListRootsPage(ctx context.Context, opts model.RootListOptions) ([]model.BatchRoot, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list roots page canceled", err)
	}
	limit := normaliseRecordLimit(opts.Limit)
	lower, upper := rootBounds()
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open root iterator", err)
	}
	defer iter.Close()

	desc := !strings.EqualFold(opts.Direction, model.RecordListDirectionAsc)
	hasCursor := opts.AfterClosedAtUnixN != 0 || opts.AfterBatchID != ""
	var ok bool
	if desc {
		if hasCursor {
			ok = iter.SeekLT(rootKey(opts.AfterClosedAtUnixN, opts.AfterBatchID))
		} else {
			ok = iter.Last()
		}
	} else if hasCursor {
		ok = iter.SeekGE(rootKey(opts.AfterClosedAtUnixN, opts.AfterBatchID))
	} else {
		ok = iter.First()
	}

	roots := make([]model.BatchRoot, 0, limit)
	for ok {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list roots page canceled", err)
		}
		if len(roots) >= limit {
			break
		}
		var root model.BatchRoot
		if err := cborx.UnmarshalLimit(iter.Value(), &root, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch root", err)
		}
		if model.BatchRootAfterCursor(root, opts) {
			roots = append(roots, root)
		}
		if desc {
			ok = iter.Prev()
		} else {
			ok = iter.Next()
		}
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate roots page", err)
	}
	return roots, nil
}

func (s *Store) LatestRoot(ctx context.Context) (model.BatchRoot, error) {
	roots, err := s.ListRoots(ctx, 1)
	if err != nil {
		return model.BatchRoot{}, err
	}
	if len(roots) == 0 {
		return model.BatchRoot{}, trusterr.New(trusterr.CodeNotFound, "batch root not found")
	}
	return roots[0], nil
}

func (s *Store) PutBatchTreeArtifacts(ctx context.Context, leaves []model.BatchTreeLeaf, nodes []model.BatchTreeNode) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put batch tree artifacts canceled", err)
	}
	if len(leaves) == 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "batch tree artifacts require at least one leaf")
	}
	batchID := leaves[0].BatchID
	if batchID == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "batch tree artifact batch_id is required")
	}
	now := time.Now().UTC().UnixNano()
	sortedLeaves := append([]model.BatchTreeLeaf(nil), leaves...)
	sort.Slice(sortedLeaves, func(i, j int) bool { return sortedLeaves[i].LeafIndex < sortedLeaves[j].LeafIndex })
	for i := range sortedLeaves {
		if sortedLeaves[i].BatchID != batchID || sortedLeaves[i].RecordID == "" || len(sortedLeaves[i].LeafHash) == 0 || (i > 0 && sortedLeaves[i].LeafIndex <= sortedLeaves[i-1].LeafIndex) {
			return trusterr.New(trusterr.CodeInvalidArgument, "invalid batch tree leaf sequence")
		}
	}
	leafTiles := make([]batchTreeLeafTile, 0, (len(sortedLeaves)+batchTreeTileSize-1)/batchTreeTileSize)
	for start := 0; start < len(sortedLeaves); start += batchTreeTileSize {
		end := min(start+batchTreeTileSize, len(sortedLeaves))
		tile := batchTreeLeafTile{
			SchemaVersion:  schemaBatchTreeLeafTileV2,
			BatchID:        batchID,
			StartIndex:     sortedLeaves[start].LeafIndex,
			LeafIndexes:    make([]uint64, end-start),
			RecordIDs:      make([]string, end-start),
			Hashes:         make([][]byte, end-start),
			CreatedAtUnixN: now,
		}
		for i := start; i < end; i++ {
			leaf := sortedLeaves[i]
			pos := i - start
			tile.LeafIndexes[pos] = leaf.LeafIndex
			tile.RecordIDs[pos] = leaf.RecordID
			tile.Hashes[pos] = append([]byte(nil), leaf.LeafHash...)
			if leaf.CreatedAtUnixN > 0 {
				tile.CreatedAtUnixN = leaf.CreatedAtUnixN
			}
		}
		leafTiles = append(leafTiles, tile)
	}
	sortedNodes := append([]model.BatchTreeNode(nil), nodes...)
	sort.Slice(sortedNodes, func(i, j int) bool {
		if sortedNodes[i].Level != sortedNodes[j].Level {
			return sortedNodes[i].Level < sortedNodes[j].Level
		}
		return sortedNodes[i].StartIndex < sortedNodes[j].StartIndex
	})
	for i := range sortedNodes {
		if sortedNodes[i].BatchID != batchID || sortedNodes[i].Width == 0 || (i > 0 && sortedNodes[i].Level == sortedNodes[i-1].Level && sortedNodes[i].StartIndex <= sortedNodes[i-1].StartIndex) {
			return trusterr.New(trusterr.CodeInvalidArgument, "invalid batch tree node sequence")
		}
	}
	nodeTiles := make([]batchTreeNodeTile, 0)
	for levelStart := 0; levelStart < len(sortedNodes); {
		level := sortedNodes[levelStart].Level
		levelEnd := levelStart
		for levelEnd < len(sortedNodes) && sortedNodes[levelEnd].Level == level {
			levelEnd++
		}
		if level != 0 {
			for start := levelStart; start < levelEnd; start += batchTreeTileSize {
				end := min(start+batchTreeTileSize, levelEnd)
				tile := batchTreeNodeTile{
					SchemaVersion:  schemaBatchTreeNodeTileV2,
					BatchID:        batchID,
					Level:          level,
					StartIndex:     sortedNodes[start].StartIndex,
					StartIndexes:   make([]uint64, end-start),
					Widths:         make([]uint64, end-start),
					Hashes:         make([][]byte, end-start),
					CreatedAtUnixN: now,
				}
				for i := start; i < end; i++ {
					node := sortedNodes[i]
					pos := i - start
					tile.StartIndexes[pos] = node.StartIndex
					tile.Widths[pos] = node.Width
					tile.Hashes[pos] = append([]byte(nil), node.Hash...)
					if node.CreatedAtUnixN > 0 {
						tile.CreatedAtUnixN = node.CreatedAtUnixN
					}
				}
				nodeTiles = append(nodeTiles, tile)
			}
		}
		levelStart = levelEnd
	}
	return s.putBatchTreeTiles(ctx, leafTiles, nodeTiles)
}

func (s *Store) PutBatchTreeSnapshot(ctx context.Context, snapshot model.BatchTreeSnapshot) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put batch tree snapshot canceled", err)
	}
	if snapshot.BatchID == "" || len(snapshot.LeafHashes) == 0 || len(snapshot.LeafHashes) != len(snapshot.RecordIDs) {
		return trusterr.New(trusterr.CodeInvalidArgument, "invalid batch tree snapshot")
	}
	for i := range snapshot.RecordIDs {
		if snapshot.RecordIDs[i] == "" {
			return trusterr.New(trusterr.CodeInvalidArgument, "batch tree snapshot record_id is required")
		}
	}
	createdAt := snapshot.CreatedAtUnixN
	if createdAt == 0 {
		createdAt = time.Now().UTC().UnixNano()
	}
	leafTiles := make([]batchTreeLeafTile, 0, (len(snapshot.LeafHashes)+batchTreeTileSize-1)/batchTreeTileSize)
	for start := 0; start < len(snapshot.LeafHashes); start += batchTreeTileSize {
		end := min(start+batchTreeTileSize, len(snapshot.LeafHashes))
		tile := batchTreeLeafTile{
			SchemaVersion:  schemaBatchTreeLeafTileV2,
			BatchID:        snapshot.BatchID,
			StartIndex:     uint64(start),
			LeafIndexes:    make([]uint64, end-start),
			RecordIDs:      append([]string(nil), snapshot.RecordIDs[start:end]...),
			Hashes:         make([][]byte, end-start),
			CreatedAtUnixN: createdAt,
		}
		for i := start; i < end; i++ {
			pos := i - start
			tile.LeafIndexes[pos] = uint64(i)
			tile.Hashes[pos] = append([]byte(nil), snapshot.LeafHashes[i][:]...)
		}
		leafTiles = append(leafTiles, tile)
	}
	sortedNodes := append([]model.BatchTreeSnapshotNode(nil), snapshot.Nodes...)
	sort.Slice(sortedNodes, func(i, j int) bool {
		if sortedNodes[i].Level != sortedNodes[j].Level {
			return sortedNodes[i].Level < sortedNodes[j].Level
		}
		return sortedNodes[i].StartIndex < sortedNodes[j].StartIndex
	})
	for i := range sortedNodes {
		if sortedNodes[i].Width == 0 || (i > 0 && sortedNodes[i].Level == sortedNodes[i-1].Level && sortedNodes[i].StartIndex <= sortedNodes[i-1].StartIndex) {
			return trusterr.New(trusterr.CodeInvalidArgument, "invalid batch tree snapshot node sequence")
		}
	}
	nodeTiles := make([]batchTreeNodeTile, 0)
	for levelStart := 0; levelStart < len(sortedNodes); {
		level := sortedNodes[levelStart].Level
		levelEnd := levelStart
		for levelEnd < len(sortedNodes) && sortedNodes[levelEnd].Level == level {
			levelEnd++
		}
		if level != 0 {
			for start := levelStart; start < levelEnd; start += batchTreeTileSize {
				end := min(start+batchTreeTileSize, levelEnd)
				tile := batchTreeNodeTile{
					SchemaVersion:  schemaBatchTreeNodeTileV2,
					BatchID:        snapshot.BatchID,
					Level:          level,
					StartIndex:     sortedNodes[start].StartIndex,
					StartIndexes:   make([]uint64, end-start),
					Widths:         make([]uint64, end-start),
					Hashes:         make([][]byte, end-start),
					CreatedAtUnixN: createdAt,
				}
				for i := start; i < end; i++ {
					pos := i - start
					tile.StartIndexes[pos] = sortedNodes[i].StartIndex
					tile.Widths[pos] = sortedNodes[i].Width
					tile.Hashes[pos] = append([]byte(nil), sortedNodes[i].Hash[:]...)
				}
				nodeTiles = append(nodeTiles, tile)
			}
		}
		levelStart = levelEnd
	}
	return s.putBatchTreeTiles(ctx, leafTiles, nodeTiles)
}

func (s *Store) putBatchTreeTiles(ctx context.Context, leaves []batchTreeLeafTile, nodes []batchTreeNodeTile) error {
	type encodedTile struct {
		key   []byte
		value []byte
	}
	tiles := make([]encodedTile, 0, len(leaves)+len(nodes))
	for i := range leaves {
		data, err := cborx.Marshal(leaves[i])
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "encode batch tree leaf tile", err)
		}
		tiles = append(tiles, encodedTile{key: batchTreeLeafKey(leaves[i].BatchID, leaves[i].StartIndex), value: data})
	}
	for i := range nodes {
		data, err := cborx.Marshal(nodes[i])
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "encode batch tree node tile", err)
		}
		tiles = append(tiles, encodedTile{key: batchTreeNodeKey(nodes[i].BatchID, nodes[i].Level, nodes[i].StartIndex), value: data})
	}
	for start := 0; start < len(tiles); start += batchTreeTilesPerTransaction {
		if err := ctx.Err(); err != nil {
			return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put batch tree tiles canceled", err)
		}
		end := min(start+batchTreeTilesPerTransaction, len(tiles))
		batch := s.db.NewBatch()
		for i := start; i < end; i++ {
			if err := stageSet(batch, tiles[i].key, tiles[i].value); err != nil {
				_ = batch.Close()
				return trusterr.Wrap(trusterr.CodeDataLoss, "stage batch tree tile", err)
			}
		}
		if err := batch.Commit(s.artifactWriteOptions()); err != nil {
			_ = batch.Close()
			return trusterr.Wrap(trusterr.CodeDataLoss, "commit batch tree tiles", err)
		}
		if err := batch.Close(); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "close batch tree tiles", err)
		}
	}
	return nil
}

func (s *Store) ListBatchTreeLeaves(ctx context.Context, opts model.BatchTreeLeafListOptions) ([]model.BatchTreeLeaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list batch tree leaves canceled", err)
	}
	if opts.BatchID == "" {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "batch_id is required")
	}
	limit := normaliseRecordLimit(opts.Limit)
	prefix := fmt.Sprintf("%s%s/", prefixBatchTreeLeaf, opts.BatchID)
	lower, upper := prefixBounds(prefix)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open batch tree leaf iterator", err)
	}
	defer iter.Close()
	ok := iter.First()
	if opts.HasAfter && opts.AfterLeafIndex < ^uint64(0) {
		if iter.SeekLT(batchTreeLeafKey(opts.BatchID, opts.AfterLeafIndex+1)) {
			key := append([]byte(nil), iter.key...)
			ok = iter.SeekGE(key)
		} else {
			ok = iter.First()
		}
	}
	leaves := make([]model.BatchTreeLeaf, 0, limit)
	for ; ok; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list batch tree leaves canceled", err)
		}
		if len(leaves) >= limit {
			break
		}
		var tile batchTreeLeafTile
		if err := cborx.UnmarshalLimit(iter.Value(), &tile, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch tree leaf tile", err)
		}
		if err := validateBatchTreeLeafTile(tile, opts.BatchID); err != nil {
			return nil, err
		}
		for i := range tile.LeafIndexes {
			if len(leaves) >= limit {
				break
			}
			if opts.HasAfter && tile.LeafIndexes[i] <= opts.AfterLeafIndex {
				continue
			}
			leaves = append(leaves, model.BatchTreeLeaf{
				SchemaVersion:  model.SchemaBatchTreeLeaf,
				BatchID:        tile.BatchID,
				RecordID:       tile.RecordIDs[i],
				LeafIndex:      tile.LeafIndexes[i],
				LeafHash:       append([]byte(nil), tile.Hashes[i]...),
				CreatedAtUnixN: tile.CreatedAtUnixN,
			})
		}
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate batch tree leaves", err)
	}
	return leaves, nil
}

func (s *Store) ListBatchTreeNodes(ctx context.Context, opts model.BatchTreeNodeListOptions) ([]model.BatchTreeNode, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list batch tree nodes canceled", err)
	}
	if opts.BatchID == "" {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "batch_id is required")
	}
	limit := normaliseRecordLimit(opts.Limit)
	if opts.Level == 0 {
		after := opts.AfterStartIndex
		hasAfter := opts.HasAfter
		if !hasAfter && opts.StartIndex > 0 {
			after = opts.StartIndex - 1
			hasAfter = true
		}
		leaves, err := s.ListBatchTreeLeaves(ctx, model.BatchTreeLeafListOptions{BatchID: opts.BatchID, Limit: limit, AfterLeafIndex: after, HasAfter: hasAfter})
		if err != nil {
			return nil, err
		}
		nodes := make([]model.BatchTreeNode, len(leaves))
		for i := range leaves {
			nodes[i] = model.BatchTreeNode{SchemaVersion: model.SchemaBatchTreeNode, BatchID: leaves[i].BatchID, Level: 0, StartIndex: leaves[i].LeafIndex, Width: 1, Hash: append([]byte(nil), leaves[i].LeafHash...), CreatedAtUnixN: leaves[i].CreatedAtUnixN}
		}
		return nodes, nil
	}
	prefix := fmt.Sprintf("%s%s/%0*d/", prefixBatchTreeNode, opts.BatchID, rootSortKeyWidth, opts.Level)
	lower, upper := prefixBounds(prefix)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open batch tree node iterator", err)
	}
	defer iter.Close()
	seekIndex := opts.StartIndex
	if opts.HasAfter && opts.AfterStartIndex > seekIndex {
		seekIndex = opts.AfterStartIndex
	}
	ok := iter.First()
	if seekIndex < ^uint64(0) {
		if iter.SeekLT(batchTreeNodeKey(opts.BatchID, opts.Level, seekIndex+1)) {
			key := append([]byte(nil), iter.key...)
			ok = iter.SeekGE(key)
		} else {
			ok = iter.First()
		}
	}
	nodes := make([]model.BatchTreeNode, 0, limit)
	for ; ok; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list batch tree nodes canceled", err)
		}
		if len(nodes) >= limit {
			break
		}
		var tile batchTreeNodeTile
		if err := cborx.UnmarshalLimit(iter.Value(), &tile, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch tree node tile", err)
		}
		if err := validateBatchTreeNodeTile(tile, opts.BatchID, opts.Level); err != nil {
			return nil, err
		}
		for i := range tile.StartIndexes {
			if len(nodes) >= limit {
				break
			}
			if tile.StartIndexes[i] < opts.StartIndex {
				continue
			}
			if opts.HasAfter && tile.StartIndexes[i] <= opts.AfterStartIndex {
				continue
			}
			nodes = append(nodes, model.BatchTreeNode{
				SchemaVersion:  model.SchemaBatchTreeNode,
				BatchID:        tile.BatchID,
				Level:          tile.Level,
				StartIndex:     tile.StartIndexes[i],
				Width:          tile.Widths[i],
				Hash:           append([]byte(nil), tile.Hashes[i]...),
				CreatedAtUnixN: tile.CreatedAtUnixN,
			})
		}
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate batch tree nodes", err)
	}
	return nodes, nil
}

func validateBatchTreeLeafTile(tile batchTreeLeafTile, batchID string) error {
	count := len(tile.LeafIndexes)
	if tile.SchemaVersion != schemaBatchTreeLeafTileV2 || tile.BatchID != batchID || count == 0 || count > batchTreeTileSize || count != len(tile.RecordIDs) || count != len(tile.Hashes) || tile.StartIndex != tile.LeafIndexes[0] {
		return trusterr.New(trusterr.CodeDataLoss, "invalid batch tree leaf tile")
	}
	for i := range tile.LeafIndexes {
		if tile.RecordIDs[i] == "" || len(tile.Hashes[i]) == 0 || (i > 0 && tile.LeafIndexes[i] <= tile.LeafIndexes[i-1]) {
			return trusterr.New(trusterr.CodeDataLoss, "invalid batch tree leaf tile ordering")
		}
	}
	return nil
}

func validateBatchTreeNodeTile(tile batchTreeNodeTile, batchID string, level uint64) error {
	count := len(tile.StartIndexes)
	if tile.SchemaVersion != schemaBatchTreeNodeTileV2 || tile.BatchID != batchID || tile.Level != level || count == 0 || count > batchTreeTileSize || count != len(tile.Widths) || count != len(tile.Hashes) || tile.StartIndex != tile.StartIndexes[0] {
		return trusterr.New(trusterr.CodeDataLoss, "invalid batch tree node tile")
	}
	for i := range tile.StartIndexes {
		if tile.Widths[i] == 0 || len(tile.Hashes[i]) == 0 || (i > 0 && tile.StartIndexes[i] <= tile.StartIndexes[i-1]) {
			return trusterr.New(trusterr.CodeDataLoss, "invalid batch tree node tile ordering")
		}
	}
	return nil
}

func (s *Store) PutManifest(ctx context.Context, manifest model.BatchManifest) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put manifest canceled", err)
	}
	if manifest.BatchID == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "batch manifest batch_id is required")
	}
	if !model.ValidBatchManifestState(manifest.State) {
		return trusterr.New(trusterr.CodeInvalidArgument, "invalid batch manifest state")
	}
	if manifest.SchemaVersion == "" {
		manifest.SchemaVersion = model.SchemaBatchManifest
	}
	data, err := cborx.Marshal(manifest)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode batch manifest", err)
	}
	txn, err := s.db.client.Begin()
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "begin batch manifest transaction", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = txn.Rollback()
		}
	}()
	readyOnDisk := false
	readyData, err := txn.Get(ctx, s.db.physicalKey([]byte(idempotencyReadyKey)))
	switch {
	case err == nil:
		if string(readyData) != idempotencyReadyV1 {
			return trusterr.New(trusterr.CodeDataLoss, "invalid idempotency projection readiness marker")
		}
		readyOnDisk = true
	case tikverr.IsErrNotFound(err):
	case ctx.Err() != nil:
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "read idempotency projection readiness canceled", ctx.Err())
	default:
		return trusterr.Wrap(trusterr.CodeDataLoss, "read idempotency projection readiness", err)
	}
	physicalManifestKey := s.db.physicalKey(manifestKey(manifest.BatchID))
	oldData, err := txn.Get(ctx, physicalManifestKey)
	oldCommitted := false
	switch {
	case err == nil:
		var old model.BatchManifest
		if err := cborx.UnmarshalLimit(oldData, &old, maxStoredObjectBytes); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "decode old batch manifest", err)
		}
		oldCommitted = old.State == model.BatchStateCommitted
		if old.State == model.BatchStatePrepared {
			if err := txn.Delete(s.db.physicalKey(preparedManifestKey(old))); err != nil {
				return trusterr.Wrap(trusterr.CodeDataLoss, "delete old prepared manifest index", err)
			}
		}
	case tikverr.IsErrNotFound(err):
	case ctx.Err() != nil:
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "read old batch manifest canceled", ctx.Err())
	default:
		return trusterr.Wrap(trusterr.CodeDataLoss, "read old batch manifest", err)
	}
	if readyOnDisk && (manifest.State == model.BatchStateCommitted || oldCommitted) {
		return trusterr.New(trusterr.CodeFailedPrecondition, "committed manifests require atomic idempotency publication")
	}
	if err := txn.Set(physicalManifestKey, data); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage batch manifest", err)
	}
	if manifest.State == model.BatchStatePrepared {
		if err := txn.Set(s.db.physicalKey(preparedManifestKey(manifest)), data); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage prepared manifest index", err)
		}
	}
	if err := txn.Set(s.db.physicalKey([]byte(idempotencyFenceKey)), []byte(idempotencyReadyV1)); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage idempotency projection fence", err)
	}
	if err := txn.Commit(ctx); err != nil {
		if ctx.Err() != nil {
			return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "commit batch manifest canceled", ctx.Err())
		}
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit batch manifest", err)
	}
	committed = true
	return nil
}

func (s *Store) GetManifest(ctx context.Context, batchID string) (model.BatchManifest, error) {
	if err := ctx.Err(); err != nil {
		return model.BatchManifest{}, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get manifest canceled", err)
	}
	if batchID == "" {
		return model.BatchManifest{}, trusterr.New(trusterr.CodeInvalidArgument, "batch_id is required")
	}
	var manifest model.BatchManifest
	found, err := s.readCBOR(manifestKey(batchID), &manifest)
	if err != nil {
		return model.BatchManifest{}, trusterr.Wrap(trusterr.CodeDataLoss, "read batch manifest", err)
	}
	if !found {
		return model.BatchManifest{}, trusterr.New(trusterr.CodeNotFound, "batch manifest not found")
	}
	return manifest, nil
}

func manifestBounds() (lower, upper []byte) {
	lower = []byte(prefixManifest)
	// "manifest/" → upper = "manifest0", same "next byte after /" trick.
	upper = []byte("manifest0")
	return lower, upper
}

func (s *Store) ListManifests(ctx context.Context) ([]model.BatchManifest, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list manifests canceled", err)
	}
	lower, upper := manifestBounds()
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open manifest iterator", err)
	}
	defer iter.Close()

	var manifests []model.BatchManifest
	for ok := iter.First(); ok; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list manifests canceled", err)
		}
		var manifest model.BatchManifest
		if err := cborx.UnmarshalLimit(iter.Value(), &manifest, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch manifest", err)
		}
		manifests = append(manifests, manifest)
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate manifests", err)
	}
	return manifests, nil
}

func (s *Store) ListManifestsAfter(ctx context.Context, afterBatchID string, limit int) ([]model.BatchManifest, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list manifests after canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	lower, upper := manifestBounds()
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open manifest iterator", err)
	}
	defer iter.Close()

	ok := iter.SeekGE(manifestKey(afterBatchID))
	manifests := make([]model.BatchManifest, 0, limit)
	for ; ok; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list manifests after canceled", err)
		}
		if len(manifests) >= limit {
			break
		}
		var manifest model.BatchManifest
		if err := cborx.UnmarshalLimit(iter.Value(), &manifest, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch manifest", err)
		}
		if afterBatchID != "" && manifest.BatchID <= afterBatchID {
			continue
		}
		manifests = append(manifests, manifest)
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate manifests after", err)
	}
	return manifests, nil
}

func (s *Store) ListPreparedManifests(ctx context.Context, nodeID string, nowUnixN int64, limit int) ([]model.BatchManifest, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list prepared manifests canceled", err)
	}
	if limit <= 0 {
		limit = 128
	}
	lower, upper := prefixBounds(prefixManifestReady)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open prepared manifest iterator", err)
	}
	defer iter.Close()
	manifests := make([]model.BatchManifest, 0, limit)
	for ok := iter.First(); ok && len(manifests) < limit; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list prepared manifests canceled", err)
		}
		var manifest model.BatchManifest
		if err := cborx.UnmarshalLimit(iter.Value(), &manifest, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode prepared manifest", err)
		}
		if manifest.State != model.BatchStatePrepared || !bytes.Equal(iter.key, preparedManifestKey(manifest)) {
			return nil, trusterr.New(trusterr.CodeDataLoss, "prepared manifest index does not match value")
		}
		if manifest.MaterializeNextUnixN > nowUnixN {
			break
		}
		if nodeID != "" && manifest.NodeID != "" && manifest.NodeID != nodeID {
			continue
		}
		manifests = append(manifests, manifest)
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate prepared manifests", err)
	}
	return manifests, nil
}

func idempotencyDecisionKey(identity model.IdempotencyIdentity) []byte {
	return append([]byte(prefixIdempotency), idempotency.StorageKey(identity)...)
}

// EnsureIdempotencyProjection initializes the native TiKV point-read
// projection only for a store with no committed history. There is deliberately
// no compatibility rebuild: encountering committed manifests without the
// readiness marker fails closed.
func (s *Store) EnsureIdempotencyProjection(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "ensure idempotency projection canceled", err)
	}
	s.idempotencyReady.Store(false)
	for attempt := 0; attempt < checkpointCommitMaxAttempts; attempt++ {
		ready, err := s.tryEnsureIdempotencyProjection(ctx)
		if err == nil && ready {
			s.idempotencyReady.Store(true)
			return nil
		}
		if err == nil {
			continue
		}
		if !isRetryablePromotionCommitError(err) {
			return err
		}
	}
	return trusterr.New(trusterr.CodeDataLoss, "publish idempotency projection readiness exhausted retries")
}

func (s *Store) tryEnsureIdempotencyProjection(ctx context.Context) (bool, error) {
	txn, err := s.db.client.Begin()
	if err != nil {
		return false, trusterr.Wrap(trusterr.CodeDataLoss, "begin idempotency projection transaction", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = txn.Rollback()
		}
	}()
	readyData, err := txn.Get(ctx, s.db.physicalKey([]byte(idempotencyReadyKey)))
	switch {
	case err == nil:
		if string(readyData) != idempotencyReadyV1 {
			return false, trusterr.New(trusterr.CodeDataLoss, "invalid idempotency projection readiness marker")
		}
		return true, nil
	case tikverr.IsErrNotFound(err):
	case ctx.Err() != nil:
		return false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "read idempotency projection readiness canceled", ctx.Err())
	default:
		return false, trusterr.Wrap(trusterr.CodeDataLoss, "read idempotency projection readiness", err)
	}
	for afterBatchID := ""; ; {
		manifests, err := s.ListManifestsAfter(ctx, afterBatchID, 128)
		if err != nil {
			return false, err
		}
		if len(manifests) == 0 {
			break
		}
		for i := range manifests {
			if manifests[i].State == model.BatchStateCommitted {
				return false, trusterr.New(trusterr.CodeFailedPrecondition, "tikv idempotency projection cannot initialize over committed history")
			}
		}
		afterBatchID = manifests[len(manifests)-1].BatchID
	}
	if err := txn.Set(s.db.physicalKey([]byte(idempotencyFenceKey)), []byte(idempotencyReadyV1)); err != nil {
		return false, err
	}
	if err := txn.Set(s.db.physicalKey([]byte(idempotencyReadyKey)), []byte(idempotencyReadyV1)); err != nil {
		return false, err
	}
	if err := txn.Commit(ctx); err != nil {
		return false, err
	}
	committed = true
	return true, nil
}

func (s *Store) GetIdempotencyDecision(ctx context.Context, identity model.IdempotencyIdentity) (model.IdempotencyDecision, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.IdempotencyDecision{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "get idempotency decision canceled", err)
	}
	if identity.TenantID == "" || identity.ClientID == "" || identity.IdempotencyKey == "" {
		return model.IdempotencyDecision{}, false, trusterr.New(trusterr.CodeInvalidArgument, "idempotency identity is incomplete")
	}
	if !s.idempotencyReady.Load() {
		return model.IdempotencyDecision{}, false, trusterr.New(trusterr.CodeFailedPrecondition, "idempotency projection is not ready")
	}
	var decision model.IdempotencyDecision
	found, err := s.readCBOR(idempotencyDecisionKey(identity), &decision)
	if err != nil {
		return model.IdempotencyDecision{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read idempotency decision", err)
	}
	if !found {
		return model.IdempotencyDecision{}, false, nil
	}
	if err := idempotency.ValidateDecision(identity, decision); err != nil {
		return model.IdempotencyDecision{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "validate stored idempotency decision", err)
	}
	return decision, true, nil
}

func (s *Store) PublishCommittedBatch(ctx context.Context, manifest model.BatchManifest, bundles []model.ProofBundle) ([]model.IdempotencyDecision, error) {
	if !s.idempotencyReady.Load() {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "idempotency projection is not ready")
	}
	manifestData, decisions, encoded, err := prepareCommittedIdempotencyPublication(manifest, bundles)
	if err != nil {
		return nil, err
	}
	for i := range bundles {
		persisted, err := s.GetBundle(ctx, bundles[i].RecordID)
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read committed bundle before publication", err)
		}
		if !reflect.DeepEqual(persisted, bundles[i]) {
			return nil, trusterr.New(trusterr.CodeDataLoss, "persisted bundle differs from committed publication")
		}
	}
	var commitErr error
	for attempt := 0; attempt < checkpointCommitMaxAttempts; attempt++ {
		commitErr = s.tryPublishCommittedBatch(ctx, manifest, manifestData, decisions, encoded)
		if commitErr == nil || !isRetryablePromotionCommitError(commitErr) {
			break
		}
	}
	if commitErr != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "commit manifest and idempotency decisions", commitErr)
	}
	return decisions, nil
}

func prepareCommittedIdempotencyPublication(manifest model.BatchManifest, bundles []model.ProofBundle) ([]byte, []model.IdempotencyDecision, map[string][]byte, error) {
	if manifest.BatchID == "" || manifest.State != model.BatchStateCommitted {
		return nil, nil, nil, trusterr.New(trusterr.CodeInvalidArgument, "a committed batch manifest is required")
	}
	if len(bundles) != len(manifest.RecordIDs) {
		return nil, nil, nil, trusterr.New(trusterr.CodeInvalidArgument, "committed manifest and bundle counts differ")
	}
	if manifest.SchemaVersion == "" {
		manifest.SchemaVersion = model.SchemaBatchManifest
	}
	manifestData, err := cborx.Marshal(manifest)
	if err != nil {
		return nil, nil, nil, trusterr.Wrap(trusterr.CodeDataLoss, "encode committed batch manifest", err)
	}
	decisions := make([]model.IdempotencyDecision, 0, len(bundles))
	seenRecords := make(map[string]struct{}, len(bundles))
	seenIdentities := make(map[string]model.IdempotencyDecision, len(bundles))
	encoded := make(map[string][]byte, len(bundles))
	for i := range bundles {
		recordID := manifest.RecordIDs[i]
		bundle := bundles[i]
		if recordID == "" {
			return nil, nil, nil, trusterr.New(trusterr.CodeInvalidArgument, "committed manifest contains an empty record_id")
		}
		if _, exists := seenRecords[recordID]; exists {
			return nil, nil, nil, trusterr.New(trusterr.CodeInvalidArgument, "committed manifest contains a duplicate record_id")
		}
		seenRecords[recordID] = struct{}{}
		if bundle.SchemaVersion != model.SchemaProofBundle || bundle.RecordID != recordID ||
			bundle.ServerRecord.RecordID != recordID || bundle.AcceptedReceipt.RecordID != recordID ||
			bundle.CommittedReceipt.SchemaVersion != model.SchemaCommittedReceipt ||
			bundle.CommittedReceipt.RecordID != recordID || bundle.CommittedReceipt.Status != "committed" ||
			bundle.CommittedReceipt.BatchID != manifest.BatchID || bundle.CommittedReceipt.LeafIndex != uint64(i) ||
			bundle.BatchProof.LeafIndex != uint64(i) || bundle.BatchProof.TreeSize != manifest.TreeSize {
			return nil, nil, nil, trusterr.New(trusterr.CodeInvalidArgument, "committed bundle does not match manifest record order")
		}
		if bundle.SignedClaim.Claim.IdempotencyKey == "" {
			continue
		}
		decision, err := idempotency.BuildDecision(manifest.BatchID, bundle.SignedClaim, bundle.ServerRecord, bundle.AcceptedReceipt)
		if err != nil {
			return nil, nil, nil, trusterr.Wrap(trusterr.CodeDataLoss, "build committed idempotency decision", err)
		}
		if err := idempotency.ValidateDecision(decision.Identity, decision); err != nil {
			return nil, nil, nil, trusterr.Wrap(trusterr.CodeInvalidArgument, "validate idempotency decision", err)
		}
		storageKey := idempotency.StorageKey(decision.Identity)
		if prior, exists := seenIdentities[storageKey]; exists {
			if !idempotency.Equivalent(prior, decision) {
				return nil, nil, nil, trusterr.New(trusterr.CodeAlreadyExists, "idempotency identity has conflicting decisions")
			}
			continue
		}
		data, err := cborx.Marshal(decision)
		if err != nil {
			return nil, nil, nil, trusterr.Wrap(trusterr.CodeDataLoss, "encode idempotency decision", err)
		}
		seenIdentities[storageKey] = decision
		encoded[storageKey] = data
		decisions = append(decisions, decision)
	}
	return manifestData, decisions, encoded, nil
}

func (s *Store) tryPublishCommittedBatch(ctx context.Context, manifest model.BatchManifest, manifestData []byte, decisions []model.IdempotencyDecision, encoded map[string][]byte) error {
	txn, err := s.db.client.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = txn.Rollback()
		}
	}()
	ready, err := txn.Get(ctx, s.db.physicalKey([]byte(idempotencyReadyKey)))
	if err != nil {
		return err
	}
	if string(ready) != idempotencyReadyV1 {
		return trusterr.New(trusterr.CodeDataLoss, "invalid idempotency projection readiness marker")
	}
	manifestPhysicalKey := s.db.physicalKey(manifestKey(manifest.BatchID))
	oldData, err := txn.Get(ctx, manifestPhysicalKey)
	switch {
	case err == nil:
		var old model.BatchManifest
		if err := cborx.UnmarshalLimit(oldData, &old, maxStoredObjectBytes); err != nil {
			return err
		}
		if old.State == model.BatchStateCommitted && !bytes.Equal(oldData, manifestData) {
			return trusterr.New(trusterr.CodeAlreadyExists, "committed batch manifest already exists with different contents")
		}
		if old.State == model.BatchStatePrepared {
			if err := txn.Delete(s.db.physicalKey(preparedManifestKey(old))); err != nil {
				return err
			}
		}
	case tikverr.IsErrNotFound(err):
	default:
		return err
	}
	for i := range decisions {
		storageKey := idempotency.StorageKey(decisions[i].Identity)
		physicalKey := s.db.physicalKey(idempotencyDecisionKey(decisions[i].Identity))
		existingData, err := txn.Get(ctx, physicalKey)
		switch {
		case err == nil:
			var existing model.IdempotencyDecision
			if err := cborx.UnmarshalLimit(existingData, &existing, maxStoredObjectBytes); err != nil {
				return err
			}
			if !idempotency.Equivalent(existing, decisions[i]) {
				return trusterr.New(trusterr.CodeAlreadyExists, "idempotency identity already has a different committed decision")
			}
		case tikverr.IsErrNotFound(err):
			if err := txn.Set(physicalKey, encoded[storageKey]); err != nil {
				return err
			}
		default:
			return err
		}
	}
	if err := txn.Set(manifestPhysicalKey, manifestData); err != nil {
		return err
	}
	if err := txn.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *Store) PutCheckpoint(ctx context.Context, cp model.WALCheckpoint) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put checkpoint canceled", err)
	}
	key, err := s.scopedCheckpointKey()
	if err != nil {
		return err
	}
	if cp.NodeID != "" && cp.NodeID != s.checkpointNodeID {
		return trusterr.New(trusterr.CodeInvalidArgument, "wal checkpoint node_id does not match store scope")
	}
	if cp.WALID != "" && cp.WALID != s.checkpointWALID {
		return trusterr.New(trusterr.CodeInvalidArgument, "wal checkpoint wal_id does not match store scope")
	}
	cp.NodeID = s.checkpointNodeID
	cp.WALID = s.checkpointWALID
	if cp.SchemaVersion == "" {
		cp.SchemaVersion = model.SchemaWALCheckpoint
	}
	if cp.RecordedAtUnixN == 0 {
		cp.RecordedAtUnixN = time.Now().UTC().UnixNano()
	}
	data, err := cborx.Marshal(cp)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode wal checkpoint", err)
	}
	var commitErr error
	for attempt := 0; attempt < checkpointCommitMaxAttempts; attempt++ {
		commitErr = s.tryPutCheckpoint(ctx, key, cp, data)
		if commitErr == nil || !isRetryablePromotionCommitError(commitErr) {
			break
		}
	}
	if commitErr != nil {
		if ctx.Err() != nil {
			return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "write wal checkpoint canceled", ctx.Err())
		}
		return trusterr.Wrap(trusterr.CodeDataLoss, "write wal checkpoint", commitErr)
	}
	return nil
}

func (s *Store) GetCheckpoint(ctx context.Context) (model.WALCheckpoint, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.WALCheckpoint{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get checkpoint canceled", err)
	}
	key, err := s.scopedCheckpointKey()
	if err != nil {
		return model.WALCheckpoint{}, false, err
	}
	var cp model.WALCheckpoint
	found, err := s.readCBOR(key, &cp)
	if err != nil {
		return model.WALCheckpoint{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read wal checkpoint", err)
	}
	if !found {
		return model.WALCheckpoint{}, false, nil
	}
	if cp.NodeID != s.checkpointNodeID || cp.WALID != s.checkpointWALID {
		return model.WALCheckpoint{}, false, trusterr.New(trusterr.CodeDataLoss, "wal checkpoint payload does not match key scope")
	}
	return cp, true, nil
}

func (s *Store) scopedCheckpointKey() ([]byte, error) {
	if !s.hasCheckpointScope() {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "tikv wal checkpoint requires node and wal identity")
	}
	if !s.idempotencyReady.Load() {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "tikv wal checkpoint requires a ready idempotency projection")
	}
	return []byte(prefixCheckpoint + recordSecondaryPart(s.checkpointNodeID) + "/" + recordSecondaryPart(s.checkpointWALID)), nil
}

func (s *Store) tryPutCheckpoint(ctx context.Context, key []byte, cp model.WALCheckpoint, data []byte) error {
	if s == nil || s.db == nil || s.db.client == nil {
		return trusterr.New(trusterr.CodeFailedPrecondition, "tikv proofstore is closed")
	}
	txn, err := s.db.client.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = txn.Rollback()
		}
	}()
	physicalKey := s.db.physicalKey(key)
	currentData, err := txn.Get(ctx, physicalKey)
	switch {
	case err == nil:
		var current model.WALCheckpoint
		if err := cborx.UnmarshalLimit(currentData, &current, maxStoredObjectBytes); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "decode current wal checkpoint", err)
		}
		if current.NodeID != s.checkpointNodeID || current.WALID != s.checkpointWALID {
			return trusterr.New(trusterr.CodeDataLoss, "current wal checkpoint payload does not match key scope")
		}
		if current.LastSequence >= cp.LastSequence {
			return nil
		}
	case tikverr.IsErrNotFound(err):
	case ctx.Err() != nil:
		return ctx.Err()
	default:
		return err
	}
	if err := txn.Set(physicalKey, data); err != nil {
		return err
	}
	if err := txn.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *Store) WithWALCheckpointPruneGuard(ctx context.Context, expected model.WALCheckpoint, prune func() error) (bool, error) {
	if prune == nil {
		return false, trusterr.New(trusterr.CodeInvalidArgument, "wal checkpoint prune callback is required")
	}
	current, found, err := s.GetCheckpoint(ctx)
	if err != nil || !found {
		return false, err
	}
	if expected.NodeID != "" && expected.NodeID != s.checkpointNodeID {
		return false, nil
	}
	if expected.WALID != "" && expected.WALID != s.checkpointWALID {
		return false, nil
	}
	if current.LastSequence < expected.LastSequence {
		return false, nil
	}
	if err := prune(); err != nil {
		return false, err
	}
	return true, nil
}

func globalLeafKey(index uint64) []byte {
	return []byte(fmt.Sprintf("%s%0*d", prefixGlobalLeaf, rootSortKeyWidth, index))
}

func globalBatchKey(batchID string) []byte {
	return append([]byte(prefixGlobalBatch), batchID...)
}

func globalNodeKey(level, startIndex uint64) []byte {
	return []byte(fmt.Sprintf("%s%0*d/%0*d", prefixGlobalNode, rootSortKeyWidth, level, rootSortKeyWidth, startIndex))
}

func sthKey(treeSize uint64) []byte {
	return []byte(fmt.Sprintf("%s%0*d", prefixSTH, rootSortKeyWidth, treeSize))
}

func globalTileKey(tile model.GlobalLogTile) []byte {
	return []byte(fmt.Sprintf(
		"%s%0*d/%0*d/%0*d",
		prefixGlobalTile,
		rootSortKeyWidth,
		tile.Level,
		rootSortKeyWidth,
		tile.StartIndex,
		rootSortKeyWidth,
		tile.Width,
	))
}

func globalOutboxKey(batchID string) []byte {
	return append([]byte(prefixGlobalOutbox), batchID...)
}

func globalStatusKey(status string, sortUnixN int64, batchID string) []byte {
	return []byte(fmt.Sprintf("%s%s/%0*d/%s", prefixGlobalStatus, status, rootSortKeyWidth, sortUnixN, batchID))
}

func globalStatusPrefix(status string) string {
	return prefixGlobalStatus + status + "/"
}

func globalStatusSortUnixN(item model.GlobalLogOutboxItem) int64 {
	switch item.Status {
	case model.AnchorStatePending:
		if item.NextAttemptUnixN > 0 {
			return item.NextAttemptUnixN
		}
		return item.EnqueuedAtUnixN
	case model.AnchorStatePublished:
		if item.CompletedAtUnixN > 0 {
			return item.CompletedAtUnixN
		}
		return item.LastAttemptUnixN
	default:
		return item.EnqueuedAtUnixN
	}
}

func anchorOutboxKey(treeSize uint64) []byte {
	return []byte(fmt.Sprintf("%s%0*d", prefixAnchorOutbox, rootSortKeyWidth, treeSize))
}

func anchorStatusKey(status string, sortUnixN int64, treeSize uint64) []byte {
	return []byte(fmt.Sprintf("%s%s/%0*d/%0*d", prefixAnchorStatus, status, rootSortKeyWidth, sortUnixN, rootSortKeyWidth, treeSize))
}

func anchorStatusPrefix(status string) string {
	return prefixAnchorStatus + status + "/"
}

func anchorStatusSortUnixN(item model.STHAnchorOutboxItem) int64 {
	switch item.Status {
	case model.AnchorStatePending:
		if item.NextAttemptUnixN > 0 {
			return item.NextAttemptUnixN
		}
		return item.EnqueuedAtUnixN
	case model.AnchorStatePublished:
		return item.EnqueuedAtUnixN
	case model.AnchorStateFailed:
		return item.EnqueuedAtUnixN
	default:
		return item.EnqueuedAtUnixN
	}
}

func anchorResultKey(treeSize uint64) []byte {
	return []byte(fmt.Sprintf("%s%0*d", prefixAnchorResult, rootSortKeyWidth, treeSize))
}

func (s *Store) PutGlobalLeaf(ctx context.Context, leaf model.GlobalLogLeaf) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put global leaf canceled", err)
	}
	if leaf.BatchID == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "global log leaf batch_id is required")
	}
	if leaf.SchemaVersion == "" {
		leaf.SchemaVersion = model.SchemaGlobalLogLeaf
	}
	if leaf.AppendedAtUnixN == 0 {
		leaf.AppendedAtUnixN = time.Now().UTC().UnixNano()
	}
	data, err := cborx.Marshal(leaf)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode global leaf", err)
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(globalLeafKey(leaf.LeafIndex), data, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage global leaf", err)
	}
	if err := batch.Set(globalBatchKey(leaf.BatchID), data, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage global leaf batch index", err)
	}
	if err := batch.Commit(syncWrite); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit global leaf", err)
	}
	return nil
}

func (s *Store) GetGlobalLeaf(ctx context.Context, index uint64) (model.GlobalLogLeaf, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.GlobalLogLeaf{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get global leaf canceled", err)
	}
	var leaf model.GlobalLogLeaf
	found, err := s.readCBOR(globalLeafKey(index), &leaf)
	if err != nil {
		return model.GlobalLogLeaf{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read global leaf", err)
	}
	return leaf, found, nil
}

func (s *Store) GetGlobalLeafByBatchID(ctx context.Context, batchID string) (model.GlobalLogLeaf, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.GlobalLogLeaf{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get global leaf by batch canceled", err)
	}
	if batchID == "" {
		return model.GlobalLogLeaf{}, false, trusterr.New(trusterr.CodeInvalidArgument, "batch_id is required")
	}
	var leaf model.GlobalLogLeaf
	found, err := s.readCBOR(globalBatchKey(batchID), &leaf)
	if err != nil {
		return model.GlobalLogLeaf{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read global leaf batch index", err)
	}
	return leaf, found, nil
}

func (s *Store) PutGlobalLogNode(ctx context.Context, node model.GlobalLogNode) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put global node canceled", err)
	}
	if node.Width == 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "global log node width is required")
	}
	if node.SchemaVersion == "" {
		node.SchemaVersion = model.SchemaGlobalLogNode
	}
	if node.CreatedAtUnixN == 0 {
		node.CreatedAtUnixN = time.Now().UTC().UnixNano()
	}
	if err := s.writeCBOR(globalNodeKey(node.Level, node.StartIndex), node); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write global node", err)
	}
	return nil
}

func (s *Store) GetGlobalLogNode(ctx context.Context, level, startIndex uint64) (model.GlobalLogNode, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.GlobalLogNode{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get global node canceled", err)
	}
	var node model.GlobalLogNode
	found, err := s.readCBOR(globalNodeKey(level, startIndex), &node)
	if err != nil {
		return model.GlobalLogNode{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read global node", err)
	}
	return node, found, nil
}

func (s *Store) ListGlobalLogNodesAfter(ctx context.Context, afterLevel, afterStartIndex uint64, limit int) ([]model.GlobalLogNode, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global nodes after canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	lower, upper := prefixBounds(prefixGlobalNode)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open global node iterator", err)
	}
	defer iter.Close()

	hasCursor := afterLevel != ^uint64(0) || afterStartIndex != ^uint64(0)
	ok := iter.First()
	if hasCursor {
		ok = iter.SeekGE(globalNodeKey(afterLevel, afterStartIndex))
	}
	nodes := make([]model.GlobalLogNode, 0, limit)
	for ; ok; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global nodes after canceled", err)
		}
		if len(nodes) >= limit {
			break
		}
		var node model.GlobalLogNode
		if err := cborx.UnmarshalLimit(iter.Value(), &node, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global node", err)
		}
		if hasCursor && (node.Level < afterLevel || node.Level == afterLevel && node.StartIndex <= afterStartIndex) {
			continue
		}
		nodes = append(nodes, node)
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate global nodes after", err)
	}
	return nodes, nil
}

func (s *Store) PutGlobalLogState(ctx context.Context, state model.GlobalLogState) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put global state canceled", err)
	}
	if state.SchemaVersion == "" {
		state.SchemaVersion = model.SchemaGlobalLogState
	}
	if state.UpdatedAtUnixN == 0 {
		state.UpdatedAtUnixN = time.Now().UTC().UnixNano()
	}
	if err := s.writeCBOR([]byte(globalStateKey), state); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write global state", err)
	}
	return nil
}

func (s *Store) GetGlobalLogState(ctx context.Context) (model.GlobalLogState, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.GlobalLogState{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get global state canceled", err)
	}
	var state model.GlobalLogState
	found, err := s.readCBOR([]byte(globalStateKey), &state)
	if err != nil {
		return model.GlobalLogState{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read global state", err)
	}
	return state, found, nil
}

func (s *Store) ListGlobalLeaves(ctx context.Context) ([]model.GlobalLogLeaf, error) {
	var leaves []model.GlobalLogLeaf
	err := s.scanPrefix(ctx, prefixGlobalLeaf, func(value []byte) error {
		var leaf model.GlobalLogLeaf
		if err := cborx.UnmarshalLimit(value, &leaf, maxStoredObjectBytes); err != nil {
			return err
		}
		leaves = append(leaves, leaf)
		return nil
	})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "list global leaves", err)
	}
	return leaves, nil
}

func (s *Store) ListGlobalLeavesRange(ctx context.Context, startIndex uint64, limit int) ([]model.GlobalLogLeaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global leaves range canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	lower, upper := prefixBounds(prefixGlobalLeaf)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open global leaf iterator", err)
	}
	defer iter.Close()

	leaves := make([]model.GlobalLogLeaf, 0, limit)
	for ok := iter.SeekGE(globalLeafKey(startIndex)); ok; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global leaves range canceled", err)
		}
		if len(leaves) >= limit {
			break
		}
		var leaf model.GlobalLogLeaf
		if err := cborx.UnmarshalLimit(iter.Value(), &leaf, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global leaf", err)
		}
		leaves = append(leaves, leaf)
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate global leaves range", err)
	}
	return leaves, nil
}

func (s *Store) ListGlobalLeavesPage(ctx context.Context, opts model.GlobalLeafListOptions) ([]model.GlobalLogLeaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global leaves page canceled", err)
	}
	limit := normaliseRecordLimit(opts.Limit)
	lower, upper := prefixBounds(prefixGlobalLeaf)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open global leaf iterator", err)
	}
	defer iter.Close()

	desc := !strings.EqualFold(opts.Direction, model.RecordListDirectionAsc)
	var ok bool
	if desc {
		if opts.AfterLeafIndex > 0 {
			ok = iter.SeekLT(globalLeafKey(opts.AfterLeafIndex))
		} else {
			ok = iter.Last()
		}
	} else if opts.AfterLeafIndex > 0 {
		ok = iter.SeekGE(globalLeafKey(opts.AfterLeafIndex))
	} else {
		ok = iter.First()
	}

	leaves := make([]model.GlobalLogLeaf, 0, limit)
	for ok {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global leaves page canceled", err)
		}
		if len(leaves) >= limit {
			break
		}
		var leaf model.GlobalLogLeaf
		if err := cborx.UnmarshalLimit(iter.Value(), &leaf, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log leaf", err)
		}
		if model.Uint64AfterCursor(leaf.LeafIndex, opts.AfterLeafIndex, opts.Direction) {
			leaves = append(leaves, leaf)
		}
		if desc {
			ok = iter.Prev()
		} else {
			ok = iter.Next()
		}
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate global leaves page", err)
	}
	return leaves, nil
}

func (s *Store) PutSignedTreeHead(ctx context.Context, sth model.SignedTreeHead) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put sth canceled", err)
	}
	if sth.TreeSize == 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "sth tree_size is required")
	}
	if sth.SchemaVersion == "" {
		sth.SchemaVersion = model.SchemaSignedTreeHead
	}
	if sth.TimestampUnixN == 0 {
		sth.TimestampUnixN = time.Now().UTC().UnixNano()
	}
	if err := s.writeCBOR(sthKey(sth.TreeSize), sth); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write signed tree head", err)
	}
	return nil
}

func (s *Store) CommitGlobalLogAppend(ctx context.Context, entry model.GlobalLogAppend) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore commit global log append canceled", err)
	}
	if entry.Leaf.BatchID == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "global log append leaf batch_id is required")
	}
	if entry.STH.TreeSize == 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "global log append STH tree_size is required")
	}
	if entry.Leaf.LeafIndex != entry.STH.TreeSize-1 {
		return trusterr.New(trusterr.CodeInvalidArgument, "global log append STH tree_size must match leaf index")
	}
	if entry.State.TreeSize != entry.STH.TreeSize {
		return trusterr.New(trusterr.CodeInvalidArgument, "global log append state and STH tree_size must match")
	}
	for _, node := range entry.Nodes {
		if node.Width == 0 {
			return trusterr.New(trusterr.CodeInvalidArgument, "global log append node width is required")
		}
	}
	if entry.Leaf.SchemaVersion == "" {
		entry.Leaf.SchemaVersion = model.SchemaGlobalLogLeaf
	}
	if entry.Leaf.AppendedAtUnixN == 0 {
		entry.Leaf.AppendedAtUnixN = time.Now().UTC().UnixNano()
	}
	if entry.State.SchemaVersion == "" {
		entry.State.SchemaVersion = model.SchemaGlobalLogState
	}
	if entry.State.UpdatedAtUnixN == 0 {
		entry.State.UpdatedAtUnixN = time.Now().UTC().UnixNano()
	}
	if entry.STH.SchemaVersion == "" {
		entry.STH.SchemaVersion = model.SchemaSignedTreeHead
	}
	if entry.STH.TimestampUnixN == 0 {
		entry.STH.TimestampUnixN = time.Now().UTC().UnixNano()
	}

	leafData, err := cborx.Marshal(entry.Leaf)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode global log append leaf", err)
	}
	stateData, err := cborx.Marshal(entry.State)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode global log append state", err)
	}
	sthData, err := cborx.Marshal(entry.STH)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode global log append STH", err)
	}

	batch := s.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(globalLeafKey(entry.Leaf.LeafIndex), leafData, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log append leaf", err)
	}
	if err := batch.Set(globalBatchKey(entry.Leaf.BatchID), leafData, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log append leaf batch index", err)
	}
	for _, node := range entry.Nodes {
		if node.SchemaVersion == "" {
			node.SchemaVersion = model.SchemaGlobalLogNode
		}
		if node.CreatedAtUnixN == 0 {
			node.CreatedAtUnixN = time.Now().UTC().UnixNano()
		}
		nodeData, err := cborx.Marshal(node)
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "encode global log append node", err)
		}
		if err := batch.Set(globalNodeKey(node.Level, node.StartIndex), nodeData, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log append node", err)
		}
	}
	if err := batch.Set([]byte(globalStateKey), stateData, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log append state", err)
	}
	if err := batch.Set(sthKey(entry.STH.TreeSize), sthData, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log append STH", err)
	}
	if err := batch.commitWithGlobalLogFence(ctx, entry.Leaf.LeafIndex); err != nil {
		if trusterr.CodeOf(err) == trusterr.CodeFailedPrecondition {
			return err
		}
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit global log append", err)
	}
	return nil
}

func (s *Store) CommitGlobalLogAppends(ctx context.Context, entries []model.GlobalLogAppend) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore commit global log appends canceled", err)
	}
	if len(entries) == 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "global log appends require at least one entry")
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	var finalState model.GlobalLogState
	for i := range entries {
		entry := entries[i]
		if entry.Leaf.BatchID == "" || entry.STH.TreeSize == 0 || entry.Leaf.LeafIndex != entry.STH.TreeSize-1 || entry.State.TreeSize != entry.STH.TreeSize {
			return trusterr.New(trusterr.CodeInvalidArgument, "invalid global log append")
		}
		if entry.Leaf.LeafIndex != entries[0].Leaf.LeafIndex+uint64(i) {
			return trusterr.New(trusterr.CodeInvalidArgument, "global log appends must be contiguous")
		}
		if entry.Leaf.SchemaVersion == "" {
			entry.Leaf.SchemaVersion = model.SchemaGlobalLogLeaf
		}
		if entry.Leaf.AppendedAtUnixN == 0 {
			entry.Leaf.AppendedAtUnixN = time.Now().UTC().UnixNano()
		}
		if entry.State.SchemaVersion == "" {
			entry.State.SchemaVersion = model.SchemaGlobalLogState
		}
		if entry.State.UpdatedAtUnixN == 0 {
			entry.State.UpdatedAtUnixN = time.Now().UTC().UnixNano()
		}
		if entry.STH.SchemaVersion == "" {
			entry.STH.SchemaVersion = model.SchemaSignedTreeHead
		}
		if entry.STH.TimestampUnixN == 0 {
			entry.STH.TimestampUnixN = time.Now().UTC().UnixNano()
		}
		leafData, err := cborx.Marshal(entry.Leaf)
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "encode global log append leaf", err)
		}
		if err := batch.Set(globalLeafKey(entry.Leaf.LeafIndex), leafData, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log append leaf", err)
		}
		if err := batch.Set(globalBatchKey(entry.Leaf.BatchID), leafData, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log append leaf batch index", err)
		}
		for j := range entry.Nodes {
			node := entry.Nodes[j]
			if node.Width == 0 {
				return trusterr.New(trusterr.CodeInvalidArgument, "global log append node width is required")
			}
			if node.SchemaVersion == "" {
				node.SchemaVersion = model.SchemaGlobalLogNode
			}
			if node.CreatedAtUnixN == 0 {
				node.CreatedAtUnixN = time.Now().UTC().UnixNano()
			}
			nodeData, err := cborx.Marshal(node)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeDataLoss, "encode global log append node", err)
			}
			if err := batch.Set(globalNodeKey(node.Level, node.StartIndex), nodeData, nil); err != nil {
				return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log append node", err)
			}
		}
		sthData, err := cborx.Marshal(entry.STH)
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "encode global log append STH", err)
		}
		if err := batch.Set(sthKey(entry.STH.TreeSize), sthData, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log append STH", err)
		}
		finalState = entry.State
	}
	stateData, err := cborx.Marshal(finalState)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode global log append state", err)
	}
	if err := batch.Set([]byte(globalStateKey), stateData, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log append state", err)
	}
	if err := batch.commitWithGlobalLogFence(ctx, entries[0].Leaf.LeafIndex); err != nil {
		if trusterr.CodeOf(err) == trusterr.CodeFailedPrecondition {
			return err
		}
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit global log appends", err)
	}
	return nil
}

func (s *Store) GetSignedTreeHead(ctx context.Context, treeSize uint64) (model.SignedTreeHead, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get sth canceled", err)
	}
	if treeSize == 0 {
		return model.SignedTreeHead{}, false, trusterr.New(trusterr.CodeInvalidArgument, "sth tree_size is required")
	}
	var sth model.SignedTreeHead
	found, err := s.readCBOR(sthKey(treeSize), &sth)
	if err != nil {
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read signed tree head", err)
	}
	return sth, found, nil
}

func (s *Store) ListSignedTreeHeadsAfter(ctx context.Context, afterTreeSize uint64, limit int) ([]model.SignedTreeHead, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth after canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	lower, upper := prefixBounds(prefixSTH)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open sth iterator", err)
	}
	defer iter.Close()

	sths := make([]model.SignedTreeHead, 0, limit)
	for ok := iter.SeekGE(sthKey(afterTreeSize + 1)); ok; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth after canceled", err)
		}
		if len(sths) >= limit {
			break
		}
		var sth model.SignedTreeHead
		if err := cborx.UnmarshalLimit(iter.Value(), &sth, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode signed tree head", err)
		}
		sths = append(sths, sth)
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate sth after", err)
	}
	return sths, nil
}

func (s *Store) ListSignedTreeHeadsPage(ctx context.Context, opts model.TreeHeadListOptions) ([]model.SignedTreeHead, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list signed tree heads page canceled", err)
	}
	limit := normaliseRecordLimit(opts.Limit)
	lower, upper := prefixBounds(prefixSTH)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open signed tree head iterator", err)
	}
	defer iter.Close()

	desc := !strings.EqualFold(opts.Direction, model.RecordListDirectionAsc)
	var ok bool
	if desc {
		if opts.AfterTreeSize > 0 {
			ok = iter.SeekLT(sthKey(opts.AfterTreeSize))
		} else {
			ok = iter.Last()
		}
	} else if opts.AfterTreeSize > 0 {
		ok = iter.SeekGE(sthKey(opts.AfterTreeSize))
	} else {
		ok = iter.First()
	}

	sths := make([]model.SignedTreeHead, 0, limit)
	for ok {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list signed tree heads page canceled", err)
		}
		if len(sths) >= limit {
			break
		}
		var sth model.SignedTreeHead
		if err := cborx.UnmarshalLimit(iter.Value(), &sth, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode signed tree head", err)
		}
		if model.Uint64AfterCursor(sth.TreeSize, opts.AfterTreeSize, opts.Direction) {
			sths = append(sths, sth)
		}
		if desc {
			ok = iter.Prev()
		} else {
			ok = iter.Next()
		}
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate signed tree heads page", err)
	}
	return sths, nil
}

func (s *Store) LatestSignedTreeHead(ctx context.Context) (model.SignedTreeHead, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore latest sth canceled", err)
	}
	lower, upper := prefixBounds(prefixSTH)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "open sth iterator", err)
	}
	defer iter.Close()
	if !iter.Last() {
		if err := iter.Error(); err != nil {
			return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "iterate sth", err)
		}
		return model.SignedTreeHead{}, false, nil
	}
	var sth model.SignedTreeHead
	if err := cborx.UnmarshalLimit(iter.Value(), &sth, maxStoredObjectBytes); err != nil {
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode latest sth", err)
	}
	return sth, true, nil
}

func (s *Store) PutGlobalLogTile(ctx context.Context, tile model.GlobalLogTile) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put global tile canceled", err)
	}
	if tile.SchemaVersion == "" {
		tile.SchemaVersion = model.SchemaGlobalLogTile
	}
	if tile.Width == 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "global log tile width is required")
	}
	if tile.CreatedAtUnixN == 0 {
		tile.CreatedAtUnixN = time.Now().UTC().UnixNano()
	}
	return s.writeCBOR(globalTileKey(tile), tile)
}

func (s *Store) ListGlobalLogTiles(ctx context.Context) ([]model.GlobalLogTile, error) {
	var tiles []model.GlobalLogTile
	err := s.scanPrefix(ctx, prefixGlobalTile, func(value []byte) error {
		var tile model.GlobalLogTile
		if err := cborx.UnmarshalLimit(value, &tile, maxStoredObjectBytes); err != nil {
			return err
		}
		tiles = append(tiles, tile)
		return nil
	})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "list global tiles", err)
	}
	return tiles, nil
}

func (s *Store) ListGlobalLogTilesAfter(ctx context.Context, afterLevel, afterStartIndex uint64, limit int) ([]model.GlobalLogTile, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global tiles after canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	lower, upper := prefixBounds(prefixGlobalTile)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open global tile iterator", err)
	}
	defer iter.Close()

	hasCursor := afterLevel != ^uint64(0) || afterStartIndex != ^uint64(0)
	ok := iter.First()
	if hasCursor {
		start := []byte(fmt.Sprintf("%s%0*d/%0*d/", prefixGlobalTile, rootSortKeyWidth, afterLevel, rootSortKeyWidth, afterStartIndex))
		ok = iter.SeekGE(start)
	}
	tiles := make([]model.GlobalLogTile, 0, limit)
	for ; ok; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global tiles after canceled", err)
		}
		if len(tiles) >= limit {
			break
		}
		var tile model.GlobalLogTile
		if err := cborx.UnmarshalLimit(iter.Value(), &tile, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global tile", err)
		}
		if hasCursor && (tile.Level < afterLevel || tile.Level == afterLevel && tile.StartIndex <= afterStartIndex) {
			continue
		}
		tiles = append(tiles, tile)
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate global tiles after", err)
	}
	return tiles, nil
}

func (s *Store) EnqueueGlobalLog(ctx context.Context, item model.GlobalLogOutboxItem) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore enqueue global log canceled", err)
	}
	if item.BatchID == "" {
		item.BatchID = item.BatchRoot.BatchID
	}
	if item.BatchID == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "global log outbox batch_id is required")
	}
	if item.SchemaVersion == "" {
		item.SchemaVersion = model.SchemaGlobalLogOutbox
	}
	if item.Status == "" {
		item.Status = model.AnchorStatePending
	}
	if item.EnqueuedAtUnixN == 0 {
		item.EnqueuedAtUnixN = time.Now().UTC().UnixNano()
	}
	key := globalOutboxKey(item.BatchID)
	if _, closer, err := s.db.Get(key); err == nil {
		closer.Close()
		return trusterr.New(trusterr.CodeAlreadyExists, "global log outbox item already exists")
	} else if !isNotFound(err) {
		return trusterr.Wrap(trusterr.CodeDataLoss, "check global log outbox item", err)
	}
	data, err := cborx.Marshal(item)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode global log outbox item", err)
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(key, data, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log outbox item", err)
	}
	if err := batch.Set(globalStatusKey(item.Status, globalStatusSortUnixN(item), item.BatchID), data, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log status index", err)
	}
	if err := batch.Commit(syncWrite); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit global log outbox item", err)
	}
	return nil
}

func (s *Store) ListPendingGlobalLog(ctx context.Context, nowUnixN int64, limit int) ([]model.GlobalLogOutboxItem, error) {
	if limit <= 0 {
		limit = 100
	}
	items := make([]model.GlobalLogOutboxItem, 0)
	err := s.scanPrefix(ctx, globalStatusPrefix(model.AnchorStatePending), func(value []byte) error {
		if len(items) >= limit {
			return errStopScan
		}
		var item model.GlobalLogOutboxItem
		if err := cborx.UnmarshalLimit(value, &item, maxStoredObjectBytes); err != nil {
			return err
		}
		if item.NextAttemptUnixN > nowUnixN {
			return errStopScan
		}
		if len(items) == 0 {
			items = make([]model.GlobalLogOutboxItem, 0, limit)
		}
		items = append(items, item)
		return nil
	})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "list pending global log outbox", err)
	}
	return items, nil
}

func (s *Store) ListGlobalLogOutboxItemsAfter(ctx context.Context, afterBatchID string, limit int) ([]model.GlobalLogOutboxItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global log outbox after canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	lower, upper := prefixBounds(prefixGlobalOutbox)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open global log outbox iterator", err)
	}
	defer iter.Close()

	items := make([]model.GlobalLogOutboxItem, 0, limit)
	startKey := globalOutboxKey(afterBatchID)
	if afterBatchID == "" {
		startKey = []byte(prefixGlobalOutbox)
	}
	for ok := iter.SeekGE(startKey); ok; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global log outbox after canceled", err)
		}
		if len(items) >= limit {
			break
		}
		var item model.GlobalLogOutboxItem
		if err := cborx.UnmarshalLimit(iter.Value(), &item, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log outbox item", err)
		}
		if item.BatchID <= afterBatchID {
			continue
		}
		items = append(items, item)
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate global log outbox after", err)
	}
	return items, nil
}

func (s *Store) GetGlobalLogOutboxItem(ctx context.Context, batchID string) (model.GlobalLogOutboxItem, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.GlobalLogOutboxItem{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get global log outbox canceled", err)
	}
	if batchID == "" {
		return model.GlobalLogOutboxItem{}, false, trusterr.New(trusterr.CodeInvalidArgument, "batch_id is required")
	}
	var item model.GlobalLogOutboxItem
	found, err := s.readCBOR(globalOutboxKey(batchID), &item)
	if err != nil {
		return model.GlobalLogOutboxItem{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read global log outbox item", err)
	}
	return item, found, nil
}

// readGlobalLogOutboxItems resolves a caller-ordered batch from one TiKV
// snapshot. BatchGet returns an unordered map, so orderedKeys retains the
// original order (and duplicates) while uniqueKeys avoids redundant transport
// work. Chunks bound each request without obtaining another timestamp.
func (s *Store) readGlobalLogOutboxItems(ctx context.Context, batchIDs []string) ([]model.GlobalLogOutboxItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore read global log outbox batch canceled", err)
	}
	if len(batchIDs) == 0 {
		return []model.GlobalLogOutboxItem{}, nil
	}
	if s == nil || s.db == nil || s.db.client == nil {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "tikv proofstore is closed")
	}

	orderedKeys := make([]string, len(batchIDs))
	uniqueKeys := make([][]byte, 0, len(batchIDs))
	uniqueOrdinals := make(map[string]int, len(batchIDs))
	for index, batchID := range batchIDs {
		if batchID == "" {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "batch_id is required")
		}
		key := s.db.physicalKey(globalOutboxKey(batchID))
		keyString := string(key)
		orderedKeys[index] = keyString
		if _, duplicate := uniqueOrdinals[keyString]; duplicate {
			continue
		}
		uniqueOrdinals[keyString] = len(uniqueKeys)
		uniqueKeys = append(uniqueKeys, key)
	}

	ts, err := s.db.client.GetTimestamp(ctx)
	if err != nil {
		return nil, globalOutboxBatchReadError(ctx, err)
	}
	snapshot := s.db.client.GetSnapshot(ts)
	values := make(map[string][]byte, len(uniqueKeys))
	items := make([]model.GlobalLogOutboxItem, len(batchIDs))
	nextDecode := 0
	for start := 0; start < len(uniqueKeys); start += globalOutboxReadBatchSize {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore read global log outbox batch canceled", err)
		}
		end := min(start+globalOutboxReadBatchSize, len(uniqueKeys))
		chunk, err := snapshot.BatchGet(ctx, uniqueKeys[start:end])
		if err != nil {
			return nil, globalOutboxBatchReadError(ctx, err)
		}
		for key, value := range chunk {
			values[key] = value
		}
		// Validate every now-resolvable caller-order item before issuing the
		// next request. This preserves the old point-read loop's error order:
		// an early missing or malformed item cannot be masked by a later
		// chunk's cancellation or transport failure.
		for nextDecode < len(orderedKeys) && uniqueOrdinals[orderedKeys[nextDecode]] < end {
			if err := ctx.Err(); err != nil {
				return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore read global log outbox batch canceled", err)
			}
			value, found := values[orderedKeys[nextDecode]]
			if !found {
				return nil, trusterr.New(trusterr.CodeNotFound, "global log outbox item not found")
			}
			if err := cborx.UnmarshalLimit(value, &items[nextDecode], maxStoredObjectBytes); err != nil {
				return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global log outbox item", err)
			}
			nextDecode++
		}
	}
	return items, nil
}

func globalOutboxBatchReadError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore read global log outbox batch canceled", ctxErr)
	}
	return trusterr.Wrap(trusterr.CodeDataLoss, "read global log outbox batch", err)
}

func (s *Store) MarkGlobalLogPublished(ctx context.Context, batchID string, sth model.SignedTreeHead) error {
	item, ok, err := s.GetGlobalLogOutboxItem(ctx, batchID)
	if err != nil {
		return err
	}
	if !ok {
		return trusterr.New(trusterr.CodeNotFound, "global log outbox item not found")
	}
	old := item
	now := time.Now().UTC().UnixNano()
	item.Status = model.AnchorStatePublished
	item.STH = sth
	item.LastErrorMessage = ""
	item.LastAttemptUnixN = now
	item.NextAttemptUnixN = 0
	item.CompletedAtUnixN = now
	if err := s.promoteBatchRecords(ctx, batchID, "L4"); err != nil {
		return err
	}
	if err := s.replaceGlobalLogOutbox(ctx, old, item); err != nil {
		return err
	}
	return nil
}

func (s *Store) MarkGlobalLogPublishedBatch(ctx context.Context, batchIDs []string, sths []model.SignedTreeHead) error {
	return s.markGlobalLogPublishedBatch(ctx, batchIDs, sths, nil)
}

func (s *Store) MarkGlobalLogPublishedBatchWithAnchors(ctx context.Context, batchIDs []string, sths []model.SignedTreeHead, anchors []model.STHAnchorOutboxItem) error {
	return s.markGlobalLogPublishedBatch(ctx, batchIDs, sths, anchors)
}

func (s *Store) markGlobalLogPublishedBatch(ctx context.Context, batchIDs []string, sths []model.SignedTreeHead, anchors []model.STHAnchorOutboxItem) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore mark global log batch published canceled", err)
	}
	if len(batchIDs) == 0 || len(batchIDs) != len(sths) {
		return trusterr.New(trusterr.CodeInvalidArgument, "global log published batch inputs are inconsistent")
	}
	if len(anchors) != 0 && len(anchors) != len(sths) {
		return trusterr.New(trusterr.CodeInvalidArgument, "global log anchor batch inputs are inconsistent")
	}
	type update struct {
		old  model.GlobalLogOutboxItem
		next model.GlobalLogOutboxItem
		data []byte
	}
	updates := make([]update, len(batchIDs))
	type anchorUpdate struct {
		item model.STHAnchorOutboxItem
		data []byte
	}
	anchorUpdates := make([]anchorUpdate, len(anchors))
	now := time.Now().UTC().UnixNano()
	items, err := s.readGlobalLogOutboxItems(ctx, batchIDs)
	if err != nil {
		return err
	}
	for i := range batchIDs {
		item := items[i]
		next := item
		next.Status = model.AnchorStatePublished
		next.STH = sths[i]
		next.LastErrorMessage = ""
		next.LastAttemptUnixN = now
		next.NextAttemptUnixN = 0
		next.CompletedAtUnixN = now
		data, err := cborx.Marshal(next)
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "encode global log outbox item", err)
		}
		updates[i] = update{old: item, next: next, data: data}
	}
	for i := range anchors {
		item := anchors[i]
		if item.TreeSize == 0 || item.TreeSize != sths[i].TreeSize {
			return trusterr.New(trusterr.CodeInvalidArgument, "sth anchor tree_size is inconsistent")
		}
		if item.SchemaVersion == "" {
			item.SchemaVersion = model.SchemaSTHAnchorOutbox
		}
		if item.Status == "" {
			item.Status = model.AnchorStatePending
		}
		if item.EnqueuedAtUnixN == 0 {
			item.EnqueuedAtUnixN = now
		}
		data, err := cborx.Marshal(item)
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "encode sth anchor outbox item", err)
		}
		anchorUpdates[i] = anchorUpdate{item: item, data: data}
	}
	for i := range batchIDs {
		if err := s.promoteBatchRecords(ctx, batchIDs[i], "L4"); err != nil {
			return err
		}
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	for i := range updates {
		if err := batch.Set(globalOutboxKey(updates[i].next.BatchID), updates[i].data, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log outbox item", err)
		}
		if err := batch.Delete(globalStatusKey(updates[i].old.Status, globalStatusSortUnixN(updates[i].old), updates[i].old.BatchID), nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage old global log status delete", err)
		}
		if err := batch.Set(globalStatusKey(updates[i].next.Status, globalStatusSortUnixN(updates[i].next), updates[i].next.BatchID), updates[i].data, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log status index", err)
		}
	}
	for i := range anchorUpdates {
		if err := batch.Set(anchorOutboxKey(anchorUpdates[i].item.TreeSize), anchorUpdates[i].data, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor outbox item", err)
		}
		if err := batch.Set(anchorStatusKey(anchorUpdates[i].item.Status, anchorStatusSortUnixN(anchorUpdates[i].item), anchorUpdates[i].item.TreeSize), anchorUpdates[i].data, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor status index", err)
		}
	}
	if err := batch.Commit(syncWrite); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit global log outbox batch", err)
	}
	return nil
}

func (s *Store) RescheduleGlobalLog(ctx context.Context, batchID string, attempts int, nextAttemptUnixN int64, lastErrorMessage string) error {
	item, ok, err := s.GetGlobalLogOutboxItem(ctx, batchID)
	if err != nil {
		return err
	}
	if !ok {
		return trusterr.New(trusterr.CodeNotFound, "global log outbox item not found")
	}
	old := item
	item.Status = model.AnchorStatePending
	item.Attempts = attempts
	item.NextAttemptUnixN = nextAttemptUnixN
	item.LastErrorMessage = lastErrorMessage
	item.LastAttemptUnixN = time.Now().UTC().UnixNano()
	return s.replaceGlobalLogOutbox(ctx, old, item)
}

func (s *Store) EnqueueSTHAnchor(ctx context.Context, item model.STHAnchorOutboxItem) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore enqueue sth anchor canceled", err)
	}
	if item.TreeSize == 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "sth anchor tree_size is required")
	}
	if item.SchemaVersion == "" {
		item.SchemaVersion = model.SchemaSTHAnchorOutbox
	}
	if item.Status == "" {
		item.Status = model.AnchorStatePending
	}
	if item.EnqueuedAtUnixN == 0 {
		item.EnqueuedAtUnixN = time.Now().UTC().UnixNano()
	}
	key := anchorOutboxKey(item.TreeSize)
	if _, closer, err := s.db.Get(key); err == nil {
		closer.Close()
		return trusterr.New(trusterr.CodeAlreadyExists, "sth anchor outbox item already exists")
	} else if !isNotFound(err) {
		return trusterr.Wrap(trusterr.CodeDataLoss, "check sth anchor outbox item", err)
	}
	data, err := cborx.Marshal(item)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode sth anchor outbox item", err)
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(key, data, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor outbox item", err)
	}
	if err := batch.Set(anchorStatusKey(item.Status, anchorStatusSortUnixN(item), item.TreeSize), data, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor status index", err)
	}
	if err := batch.Commit(syncWrite); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit sth anchor outbox item", err)
	}
	return nil
}

func (s *Store) EnqueueSTHAnchors(ctx context.Context, items []model.STHAnchorOutboxItem) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore enqueue sth anchor batch canceled", err)
	}
	type encodedItem struct {
		item model.STHAnchorOutboxItem
		data []byte
	}
	encoded := make([]encodedItem, 0, len(items))
	now := time.Now().UTC().UnixNano()
	for i := range items {
		item := items[i]
		if item.TreeSize == 0 {
			return trusterr.New(trusterr.CodeInvalidArgument, "sth anchor tree_size is required")
		}
		if item.SchemaVersion == "" {
			item.SchemaVersion = model.SchemaSTHAnchorOutbox
		}
		if item.Status == "" {
			item.Status = model.AnchorStatePending
		}
		if item.EnqueuedAtUnixN == 0 {
			item.EnqueuedAtUnixN = now
		}
		key := anchorOutboxKey(item.TreeSize)
		if _, closer, err := s.db.Get(key); err == nil {
			closer.Close()
			continue
		} else if !isNotFound(err) {
			return trusterr.Wrap(trusterr.CodeDataLoss, "check sth anchor outbox item", err)
		}
		data, err := cborx.Marshal(item)
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "encode sth anchor outbox item", err)
		}
		encoded = append(encoded, encodedItem{item: item, data: data})
	}
	if len(encoded) == 0 {
		return nil
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	for i := range encoded {
		if err := batch.Set(anchorOutboxKey(encoded[i].item.TreeSize), encoded[i].data, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor outbox item", err)
		}
		if err := batch.Set(anchorStatusKey(encoded[i].item.Status, anchorStatusSortUnixN(encoded[i].item), encoded[i].item.TreeSize), encoded[i].data, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor status index", err)
		}
	}
	if err := batch.Commit(syncWrite); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit sth anchor outbox batch", err)
	}
	return nil
}

func (s *Store) ListPendingSTHAnchors(ctx context.Context, nowUnixN int64, limit int) ([]model.STHAnchorOutboxItem, error) {
	if limit <= 0 {
		limit = 100
	}
	items := make([]model.STHAnchorOutboxItem, 0)
	err := s.scanPrefix(ctx, anchorStatusPrefix(model.AnchorStatePending), func(value []byte) error {
		if len(items) >= limit {
			return errStopScan
		}
		var item model.STHAnchorOutboxItem
		if err := cborx.UnmarshalLimit(value, &item, maxStoredObjectBytes); err != nil {
			return err
		}
		if item.NextAttemptUnixN > nowUnixN {
			return errStopScan
		}
		if len(items) == 0 {
			items = make([]model.STHAnchorOutboxItem, 0, limit)
		}
		items = append(items, item)
		return nil
	})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "list pending sth anchors", err)
	}
	return items, nil
}

func (s *Store) ListPublishedSTHAnchors(ctx context.Context, limit int) ([]model.STHAnchorOutboxItem, error) {
	if limit <= 0 {
		limit = 100
	}
	items := make([]model.STHAnchorOutboxItem, 0)
	err := s.scanPrefix(ctx, anchorStatusPrefix(model.AnchorStatePublished), func(value []byte) error {
		if len(items) >= limit {
			return errStopScan
		}
		var item model.STHAnchorOutboxItem
		if err := cborx.UnmarshalLimit(value, &item, maxStoredObjectBytes); err != nil {
			return err
		}
		if len(items) == 0 {
			items = make([]model.STHAnchorOutboxItem, 0, limit)
		}
		items = append(items, item)
		return nil
	})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "list published sth anchors", err)
	}
	return items, nil
}

func (s *Store) GetSTHAnchorOutboxItem(ctx context.Context, treeSize uint64) (model.STHAnchorOutboxItem, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorOutboxItem{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get sth anchor canceled", err)
	}
	if treeSize == 0 {
		return model.STHAnchorOutboxItem{}, false, trusterr.New(trusterr.CodeInvalidArgument, "tree_size is required")
	}
	var item model.STHAnchorOutboxItem
	found, err := s.readCBOR(anchorOutboxKey(treeSize), &item)
	if err != nil {
		return model.STHAnchorOutboxItem{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor outbox item", err)
	}
	return item, found, nil
}

func (s *Store) ListSTHAnchorOutboxItemsAfter(ctx context.Context, afterTreeSize uint64, limit int) ([]model.STHAnchorOutboxItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor outbox after canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	lower, upper := prefixBounds(prefixAnchorOutbox)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open sth anchor outbox iterator", err)
	}
	defer iter.Close()

	items := make([]model.STHAnchorOutboxItem, 0, limit)
	for ok := iter.SeekGE(anchorOutboxKey(afterTreeSize + 1)); ok; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor outbox after canceled", err)
		}
		if len(items) >= limit {
			break
		}
		var item model.STHAnchorOutboxItem
		if err := cborx.UnmarshalLimit(iter.Value(), &item, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode sth anchor outbox item", err)
		}
		items = append(items, item)
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate sth anchor outbox after", err)
	}
	return items, nil
}

func (s *Store) ListSTHAnchorsPage(ctx context.Context, opts model.AnchorListOptions) ([]model.STHAnchorOutboxItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchors page canceled", err)
	}
	limit := normaliseRecordLimit(opts.Limit)
	lower, upper := prefixBounds(prefixAnchorOutbox)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open sth anchor outbox iterator", err)
	}
	defer iter.Close()

	desc := !strings.EqualFold(opts.Direction, model.RecordListDirectionAsc)
	var ok bool
	if desc {
		if opts.AfterTreeSize > 0 {
			ok = iter.SeekLT(anchorOutboxKey(opts.AfterTreeSize))
		} else {
			ok = iter.Last()
		}
	} else if opts.AfterTreeSize > 0 {
		ok = iter.SeekGE(anchorOutboxKey(opts.AfterTreeSize))
	} else {
		ok = iter.First()
	}

	items := make([]model.STHAnchorOutboxItem, 0, limit)
	for ok {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchors page canceled", err)
		}
		if len(items) >= limit {
			break
		}
		var item model.STHAnchorOutboxItem
		if err := cborx.UnmarshalLimit(iter.Value(), &item, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode sth anchor outbox item", err)
		}
		if model.Uint64AfterCursor(item.TreeSize, opts.AfterTreeSize, opts.Direction) {
			items = append(items, item)
		}
		if desc {
			ok = iter.Prev()
		} else {
			ok = iter.Next()
		}
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate sth anchors page", err)
	}
	return items, nil
}

func (s *Store) RescheduleSTHAnchor(ctx context.Context, treeSize uint64, attempts int, nextAttemptUnixN int64, lastErrorMessage string) error {
	item, ok, err := s.GetSTHAnchorOutboxItem(ctx, treeSize)
	if err != nil {
		return err
	}
	if !ok {
		return trusterr.New(trusterr.CodeNotFound, "sth anchor outbox item not found")
	}
	old := item
	item.Status = model.AnchorStatePending
	item.Attempts = attempts
	item.NextAttemptUnixN = nextAttemptUnixN
	item.LastErrorMessage = lastErrorMessage
	item.LastAttemptUnixN = time.Now().UTC().UnixNano()
	return s.replaceSTHAnchorOutbox(ctx, old, item)
}

func (s *Store) MarkSTHAnchorPublished(ctx context.Context, result model.STHAnchorResult) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore mark sth anchor published canceled", err)
	}
	if result.TreeSize == 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "sth anchor result tree_size is required")
	}
	if result.SchemaVersion == "" {
		result.SchemaVersion = model.SchemaSTHAnchorResult
	}
	if result.PublishedAtUnixN == 0 {
		result.PublishedAtUnixN = time.Now().UTC().UnixNano()
	}
	item, ok, err := s.GetSTHAnchorOutboxItem(ctx, result.TreeSize)
	if err != nil {
		return err
	}
	if !ok {
		return trusterr.New(trusterr.CodeNotFound, "sth anchor outbox item not found")
	}
	old := item
	item.Status = model.AnchorStatePublished
	item.LastErrorMessage = ""
	item.LastAttemptUnixN = result.PublishedAtUnixN
	item.NextAttemptUnixN = 0

	resultBytes, err := cborx.Marshal(result)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode sth anchor result", err)
	}
	itemBytes, err := cborx.Marshal(item)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode sth anchor outbox item", err)
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(anchorResultKey(result.TreeSize), resultBytes, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor result", err)
	}
	if err := batch.Set(anchorOutboxKey(result.TreeSize), itemBytes, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor outbox item", err)
	}
	if err := batch.Delete(anchorStatusKey(old.Status, anchorStatusSortUnixN(old), old.TreeSize), nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage old sth anchor status delete", err)
	}
	if err := batch.Set(anchorStatusKey(item.Status, anchorStatusSortUnixN(item), item.TreeSize), itemBytes, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor status index", err)
	}
	if err := batch.Commit(syncWrite); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit sth anchor published batch", err)
	}
	leaf, ok, err := s.GetGlobalLeaf(ctx, result.TreeSize-1)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	return s.promoteBatchRecords(ctx, leaf.BatchID, "L5")
}

func (s *Store) MarkSTHAnchorFailed(ctx context.Context, treeSize uint64, lastErrorMessage string) error {
	item, ok, err := s.GetSTHAnchorOutboxItem(ctx, treeSize)
	if err != nil {
		return err
	}
	if !ok {
		return trusterr.New(trusterr.CodeNotFound, "sth anchor outbox item not found")
	}
	old := item
	item.Status = model.AnchorStateFailed
	item.LastErrorMessage = lastErrorMessage
	item.LastAttemptUnixN = time.Now().UTC().UnixNano()
	item.NextAttemptUnixN = 0
	return s.replaceSTHAnchorOutbox(ctx, old, item)
}

func (s *Store) GetSTHAnchorResult(ctx context.Context, treeSize uint64) (model.STHAnchorResult, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get sth anchor result canceled", err)
	}
	if treeSize == 0 {
		return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeInvalidArgument, "tree_size is required")
	}
	var result model.STHAnchorResult
	found, err := s.readCBOR(anchorResultKey(treeSize), &result)
	if err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor result", err)
	}
	return result, found, nil
}

func (s *Store) LatestSTHAnchorResult(ctx context.Context) (model.STHAnchorResult, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore latest sth anchor result canceled", err)
	}
	lower, upper := prefixBounds(prefixAnchorResult)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "open sth anchor result iterator", err)
	}
	defer iter.Close()
	if !iter.Last() {
		if err := iter.Error(); err != nil {
			return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "iterate sth anchor results", err)
		}
		return model.STHAnchorResult{}, false, nil
	}
	var result model.STHAnchorResult
	if err := cborx.UnmarshalLimit(iter.Value(), &result, maxStoredObjectBytes); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode latest sth anchor result", err)
	}
	if result.TreeSize == 0 || !bytes.Equal(iter.key, anchorResultKey(result.TreeSize)) {
		return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeDataLoss, "latest sth anchor result key does not match item")
	}
	return result, true, nil
}

func (s *Store) listSTHAnchors(ctx context.Context, limit int, include func(model.STHAnchorOutboxItem) bool) ([]model.STHAnchorOutboxItem, error) {
	if limit <= 0 {
		limit = 100
	}
	items := []model.STHAnchorOutboxItem{}
	err := s.scanPrefix(ctx, prefixAnchorOutbox, func(value []byte) error {
		var item model.STHAnchorOutboxItem
		if err := cborx.UnmarshalLimit(value, &item, maxStoredObjectBytes); err != nil {
			return err
		}
		if include(item) {
			items = append(items, item)
		}
		return nil
	})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "list sth anchors", err)
	}
	sortSTHAnchorItems(items)
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func sortSTHAnchorItems(items []model.STHAnchorOutboxItem) {
	for i := 1; i < len(items); i++ {
		j := i
		for j > 0 && items[j-1].EnqueuedAtUnixN > items[j].EnqueuedAtUnixN {
			items[j-1], items[j] = items[j], items[j-1]
			j--
		}
	}
}

func (s *Store) recordListPrefix(opts model.RecordListOptions) string {
	mode := RecordIndexModeFull
	if s != nil {
		mode = s.recordIndexMode
	}
	useSecondary := mode != RecordIndexModeTimeOnly
	switch {
	case useSecondary && len(opts.ContentHash) > 0:
		return prefixRecordByHash + hex.EncodeToString(opts.ContentHash) + "/"
	case mode == RecordIndexModeFull && model.RecordStorageQueryToken(opts.Query) != "":
		return prefixRecordByToken + recordSecondaryPart(model.RecordStorageQueryToken(opts.Query)) + "/"
	case useSecondary && opts.BatchID != "":
		return prefixRecordByBatch + recordSecondaryPart(opts.BatchID) + "/"
	case useSecondary && opts.ProofLevel != "":
		return prefixRecordByLevel + recordSecondaryPart(opts.ProofLevel) + "/"
	case useSecondary && opts.TenantID != "":
		return prefixRecordByTenant + recordSecondaryPart(opts.TenantID) + "/"
	case useSecondary && opts.ClientID != "":
		return prefixRecordByClient + recordSecondaryPart(opts.ClientID) + "/"
	default:
		return prefixRecordByTime
	}
}

func normaliseRecordLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func recordRangeExhausted(idx model.RecordIndex, opts model.RecordListOptions, desc bool) bool {
	if desc {
		return opts.ReceivedFromUnixN > 0 && idx.ReceivedAtUnixN < opts.ReceivedFromUnixN
	}
	return opts.ReceivedToUnixN > 0 && idx.ReceivedAtUnixN > opts.ReceivedToUnixN
}

func (s *Store) stageRecordIndexReplace(batch *tikvBatch, idx, old model.RecordIndex, oldFound bool) error {
	encoded, err := encodeRecordIndexArtifact(idx)
	if err != nil {
		return err
	}
	defer encoded.release()
	return s.stageEncodedRecordIndexReplace(batch, encoded, old, oldFound)
}

func (s *Store) stageEncodedRecordIndexReplace(batch *tikvBatch, idx encodedRecordIndex, old model.RecordIndex, oldFound bool) error {
	if oldFound {
		if err := stageRecordIndexDelete(batch, old); err != nil {
			return err
		}
	}
	return s.stageEncodedRecordIndexSet(batch, idx)
}

func stageRecordIndexDelete(batch *tikvBatch, idx model.RecordIndex) error {
	return visitRecordIndexKeys(idx, RecordIndexModeFull, func(key []byte) error {
		if err := batch.Delete(key, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage old record index delete", err)
		}
		return nil
	})
}

func (s *Store) stageEncodedRecordIndexSetForMode(batch *tikvBatch, idx encodedRecordIndex) error {
	if s == nil || s.recordIndexMode == RecordIndexModeFull {
		return s.stageEncodedRecordIndexSet(batch, idx)
	}
	return s.stageEncodedRecordIndexReplaceSame(batch, idx)
}

func (s *Store) stageEncodedRecordIndexReplaceSame(batch *tikvBatch, idx encodedRecordIndex) error {
	if err := visitRecordIndexKeys(idx.idx, RecordIndexModeFull, func(key []byte) error {
		if err := batch.Delete(key, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage record index delete", err)
		}
		return nil
	}); err != nil {
		return err
	}
	return s.stageEncodedRecordIndexSet(batch, idx)
}

func (s *Store) stageRecordIndexSet(batch *tikvBatch, idx model.RecordIndex) error {
	encoded, err := encodeRecordIndexArtifact(idx)
	if err != nil {
		return err
	}
	defer encoded.release()
	return s.stageEncodedRecordIndexSet(batch, encoded)
}

func (s *Store) stageEncodedRecordIndexSet(batch *tikvBatch, idx encodedRecordIndex) error {
	mode := RecordIndexModeFull
	if s != nil {
		mode = s.recordIndexMode
	}
	if err := visitRecordIndexKeys(idx.idx, mode, func(key []byte) error {
		if isRecordByIDKey(key) {
			if err := stageSet(batch, key, idx.value); err != nil {
				return trusterr.Wrap(trusterr.CodeDataLoss, "stage record index", err)
			}
			return nil
		}
		if err := stageRecordIndexRef(batch, key, idx.idx.RecordID); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage secondary record index", err)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func isRecordByIDKey(key []byte) bool {
	return bytes.HasPrefix(key, recordByIDPrefix)
}

func (s *Store) replaceGlobalLogOutbox(ctx context.Context, old, next model.GlobalLogOutboxItem) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore update global log outbox canceled", err)
	}
	data, err := cborx.Marshal(next)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode global log outbox item", err)
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(globalOutboxKey(next.BatchID), data, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log outbox item", err)
	}
	if old.BatchID != "" && old.Status != "" {
		if err := batch.Delete(globalStatusKey(old.Status, globalStatusSortUnixN(old), old.BatchID), nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage old global log status delete", err)
		}
	}
	if err := batch.Set(globalStatusKey(next.Status, globalStatusSortUnixN(next), next.BatchID), data, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log status index", err)
	}
	if err := batch.Commit(syncWrite); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit global log outbox update", err)
	}
	return nil
}

func (s *Store) promoteBatchRecords(ctx context.Context, batchID, proofLevel string) error {
	if batchID == "" {
		return nil
	}
	updates, err := s.collectRecordIndexPromotions(ctx, batchID, proofLevel)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "scan batch record indexes", err)
	}
	return s.commitRecordIndexPromotions(ctx, updates)
}

func (s *Store) collectRecordIndexPromotions(ctx context.Context, batchID, proofLevel string) ([]recordIndexPromotion, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prefix := prefixRecordByBatch + recordSecondaryPart(batchID) + "/"
	lower, upper := prefixBounds(prefix)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	updates := make([]recordIndexPromotion, 0, 16)
	appendPromotion := func(idx model.RecordIndex, replaceAll bool) bool {
		if model.ProofLevelRank(model.RecordIndexProofLevel(idx)) >= model.ProofLevelRank(proofLevel) {
			return true
		}
		next := idx
		next.ProofLevel = proofLevel
		updates = append(updates, recordIndexPromotion{old: idx, next: next, replaceAll: replaceAll})
		return true
	}
	// Resolve references through the scan's snapshot in bounded runs. Keep all
	// candidates in memory until every read and decode succeeds so a read-phase
	// failure cannot commit an earlier promotion chunk.
	pendingRecordIDs := make([]string, 0, promotionReferenceBatchSize)
	flushPending := func() error {
		if len(pendingRecordIDs) == 0 {
			return nil
		}
		err := s.visitRecordIndexRefs(ctx, iter, pendingRecordIDs, func(idx model.RecordIndex) bool {
			return appendPromotion(idx, false)
		})
		pendingRecordIDs = pendingRecordIDs[:0]
		return err
	}

	for ok := iter.First(); ok; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if recordID, isReference := decodeRecordIndexRef(iter.Value()); isReference {
			pendingRecordIDs = append(pendingRecordIDs, recordID)
			if len(pendingRecordIDs) >= promotionReferenceBatchSize {
				if err := flushPending(); err != nil {
					return nil, err
				}
			}
			continue
		}
		if err := flushPending(); err != nil {
			return nil, err
		}
		var idx model.RecordIndex
		if err := cborx.UnmarshalLimit(iter.Value(), &idx, maxStoredObjectBytes); err != nil {
			return nil, err
		}
		appendPromotion(idx, true)
	}
	if err := flushPending(); err != nil {
		return nil, err
	}
	if err := iter.Error(); err != nil {
		return nil, err
	}
	return updates, nil
}

type recordIndexPromotion struct {
	old        model.RecordIndex
	next       model.RecordIndex
	stale      model.RecordIndex
	replaceAll bool
}

func (s *Store) stageRecordIndexPromotion(batch *tikvBatch, promotion recordIndexPromotion) error {
	encoded, err := encodeRecordIndexArtifact(promotion.next)
	if err != nil {
		return err
	}
	defer encoded.release()
	mode := RecordIndexModeFull
	if s != nil {
		mode = normalizeRecordIndexMode(Options{RecordIndexMode: s.recordIndexMode})
	}
	if promotion.replaceAll || mode != RecordIndexModeFull {
		if promotion.stale.RecordID != "" {
			if err := stageRecordIndexDelete(batch, promotion.stale); err != nil {
				return err
			}
		}
		return s.stageEncodedRecordIndexReplace(batch, encoded, promotion.old, true)
	}
	if err := stageSetRecordKey(batch, prefixRecordByID, encoded.idx.RecordID, encoded.value); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage record index", err)
	}
	if promotion.old.ProofLevel != "" {
		oldLevelKey := appendRecordIndexEncodedPrefix(nil, prefixRecordByLevel, promotion.old.ProofLevel, promotion.old.ReceivedAtUnixN, promotion.old.RecordID)
		if err := batch.Delete(oldLevelKey, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage old record index delete", err)
		}
	}
	// Re-set every secondary as a canonical reference without deleting the
	// unchanged keys first. Besides reducing writes, this preserves the old
	// path's repair of mixed legacy layouts and reduced-to-full transitions.
	if err := visitRecordIndexKeys(encoded.idx, RecordIndexModeFull, func(key []byte) error {
		if isRecordByIDKey(key) {
			return nil
		}
		if err := stageRecordIndexRef(batch, key, encoded.idx.RecordID); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage secondary record index", err)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func (s *Store) commitRecordIndexPromotions(ctx context.Context, updates []recordIndexPromotion) error {
	for start := 0; start < len(updates); start += batchArtifactChunkSize {
		end := start + batchArtifactChunkSize
		if end > len(updates) {
			end = len(updates)
		}
		if err := ctx.Err(); err != nil {
			return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore promote batch records canceled", err)
		}
		if err := s.commitRecordIndexPromotionChunk(ctx, updates[start:end]); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "commit promoted record indexes", err)
		}
	}
	return nil
}

func (s *Store) commitRecordIndexPromotionChunk(ctx context.Context, updates []recordIndexPromotion) error {
	var err error
	for attempt := 0; attempt < promotionCommitMaxAttempts; attempt++ {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		err = s.tryCommitRecordIndexPromotionChunk(ctx, updates)
		if err == nil || !isRetryablePromotionCommitError(err) {
			return err
		}
	}
	return err
}

func (s *Store) tryCommitRecordIndexPromotionChunk(ctx context.Context, updates []recordIndexPromotion) error {
	if s == nil || s.db == nil || s.db.client == nil {
		return trusterr.New(trusterr.CodeFailedPrecondition, "tikv proofstore is closed")
	}
	txn, err := s.db.client.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = txn.Rollback()
		}
	}()

	keys := make([][]byte, len(updates))
	for index := range updates {
		keys[index] = s.db.physicalKey(recordByIDKey(updates[index].next.RecordID))
	}
	currentValues, err := txn.BatchGet(ctx, keys)
	if err != nil {
		return err
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	for index := range updates {
		promotion := updates[index]
		if value, found := currentValues[string(keys[index])]; found {
			var current model.RecordIndex
			if err := cborx.UnmarshalLimit(value, &current, maxStoredObjectBytes); err != nil {
				return err
			}
			targetLevel := promotion.next.ProofLevel
			if model.ProofLevelRank(model.RecordIndexProofLevel(current)) >= model.ProofLevelRank(targetLevel) {
				if !promotion.replaceAll {
					continue
				}
				promotion.stale = promotion.old
				promotion.old = current
				promotion.next = current
			} else {
				if promotion.replaceAll {
					promotion.stale = promotion.old
				}
				promotion.old = current
				promotion.next = current
				promotion.next.ProofLevel = targetLevel
			}
		} else if !promotion.replaceAll {
			return trusterr.New(trusterr.CodeDataLoss, "record index reference target not found")
		}
		if err := s.stageRecordIndexPromotion(batch, promotion); err != nil {
			return err
		}
	}
	if len(batch.ops) == 0 {
		return nil
	}
	if err := batch.apply(txn); err != nil {
		return err
	}
	if err := txn.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func isRetryablePromotionCommitError(err error) bool {
	if tikverr.IsErrWriteConflict(err) {
		return true
	}
	var latchConflict *tikverr.ErrWriteConflictInLatch
	if errors.As(err, &latchConflict) {
		return true
	}
	var retryable *tikverr.ErrRetryable
	if errors.As(err, &retryable) {
		return true
	}
	var deadlock *tikverr.ErrDeadlock
	return errors.As(err, &deadlock) && deadlock.IsRetryable
}

func (s *Store) replaceSTHAnchorOutbox(ctx context.Context, old, next model.STHAnchorOutboxItem) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore update sth anchor canceled", err)
	}
	data, err := cborx.Marshal(next)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode sth anchor outbox item", err)
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(anchorOutboxKey(next.TreeSize), data, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor outbox item", err)
	}
	if old.TreeSize != 0 && old.Status != "" {
		if err := batch.Delete(anchorStatusKey(old.Status, anchorStatusSortUnixN(old), old.TreeSize), nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage old sth anchor status delete", err)
		}
	}
	if err := batch.Set(anchorStatusKey(next.Status, anchorStatusSortUnixN(next), next.TreeSize), data, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor status index", err)
	}
	if err := batch.Commit(syncWrite); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit sth anchor update", err)
	}
	return nil
}

func (s *Store) scanPrefix(ctx context.Context, prefix string, visit func([]byte) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	lower, upper := prefixBounds(prefix)
	iter, err := s.db.NewIter(&iterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return err
	}
	defer iter.Close()
	for ok := iter.First(); ok; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := visit(iter.Value()); err != nil {
			if errors.Is(err, errStopScan) {
				return nil
			}
			return err
		}
	}
	return iter.Error()
}

func prefixBounds(prefix string) (lower, upper []byte) {
	lower = []byte(prefix)
	upper = append([]byte(prefix), 0xff)
	return lower, upper
}

func NormalizePDAddresses(values []string, text string) []string {
	out := make([]string, 0, len(values)+1)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				out = append(out, trimmed)
			}
		}
	}
	for _, part := range strings.Split(text, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
