// Package pebble provides a Pebble-backed implementation of
// proofstore.Store. Values are CBOR-encoded exactly like the file-based
// LocalStore, so the two backends round-trip identical bytes and can be
// migrated between by copying raw values. The key schema mirrors the
// on-disk layout documented in docs/TRUSTDB_DESIGN.md §17.2.
package pebble

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

	pdb "github.com/cockroachdb/pebble"
	"github.com/golang/snappy"

	"github.com/ryan-wong-coder/trustdb/internal/anchorschedule"
	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/idempotency"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

// maxStoredObjectBytes caps decode input size to guard against corrupt
// values that claim to be multi-gigabyte CBOR payloads. Mirrors the same
// constant in the file backend.
const maxStoredObjectBytes = 64 << 20
const (
	batchArtifactChunkSize       = 1024
	batchTreeTileSize            = 512
	bundleCompressionMinBytes    = 4 << 10
	maxBatchArtifactEncodeWorker = 16
)

var errStopScan = errors.New("stop scan")

const (
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
	prefixManifestState  = "manifest-state/"
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
	prefixAnchorResult   = "anchor/sth-result/v2/"
	prefixAnchorLatest   = "anchor/sth-latest/v1/"
	prefixAnchorSchedule = "anchor/schedule/v1/"
	prefixIdempotency    = "idempotency/decision/"
	checkpointKey        = "checkpoint/wal"
	globalStateKey       = "global/state/latest"
	storageSchemaKey     = "meta/storage-schema"
	idempotencyReadyKey  = "meta/idempotency-projection/ready"
	committedBatchesKey  = "meta/committed-batches/present"
	anchorLatestAllKey   = "anchor/sth-latest-all/v1"
	storageSchemaV3      = "trustdb-proofstore-v3"
	idempotencyReadyV1   = "trustdb.idempotency-projection.ready.v1"
	committedBatchesV1   = "trustdb.committed-batches.present.v1"
	rootSortKeyWidth     = 20
)

const (
	schemaStoredProofBundleV2 = "trustdb.pebble-proof-bundle.v2"
	storedBundleCodecSnappy   = "snappy"
	schemaBatchTreeLeafTileV2 = "trustdb.batch-tree-leaf-tile.v2"
	schemaBatchTreeNodeTileV2 = "trustdb.batch-tree-node-tile.v2"
)

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

type Options struct {
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

// Store is a Pebble-backed proof store. It is safe for concurrent use
// from multiple goroutines; Pebble's internal locking guarantees that
// all Store methods see a linearizable view of the underlying key space.
type Store struct {
	db               *pdb.DB
	recordIndexMode  string
	artifactSyncMode string

	// closeOnce guards the underlying db.Close so that duplicate
	// Close calls from defers and shutdown hooks cannot panic on a
	// double-free inside Pebble.
	closeOnce sync.Once
	closeErr  error

	idempotencyMu     sync.RWMutex
	idempotencyReady  atomic.Bool
	hasCommittedBatch atomic.Bool
	anchorScheduleMu  sync.Mutex
}

// WALCheckpointPruneSafe becomes true only after the durable projection is
// complete. Generic committed-manifest writes invalidate it until the next
// bounded rebuild.
func (s *Store) WALCheckpointPruneSafe() bool {
	return s != nil && s.idempotencyReady.Load()
}

// Open creates or opens a Pebble database at path and wraps it in a
// Store. The caller owns the returned *Store and must call Close to
// release the underlying file locks; Pebble refuses a second Open at
// the same path while the first handle is still live.
func Open(path string) (*Store, error) {
	return OpenWithOptions(path, Options{RecordIndexMode: RecordIndexModeFull, ArtifactSyncMode: ArtifactSyncModeChunk})
}

func OpenWithOptions(path string, opts Options) (*Store, error) {
	if path == "" {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "pebble proofstore path is required")
	}
	db, err := pdb.Open(path, &pdb.Options{})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeInternal, "open pebble proofstore", err)
	}
	if err := ensureStorageSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	store := &Store{
		db:               db,
		recordIndexMode:  normalizeRecordIndexMode(opts),
		artifactSyncMode: normalizeArtifactSyncMode(opts.ArtifactSyncMode),
	}
	ready, err := store.projectionReadyOnDisk()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	store.idempotencyReady.Store(ready)
	hasCommittedBatch, err := store.committedBatchesOnDisk()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	store.hasCommittedBatch.Store(hasCommittedBatch)
	return store, nil
}

func ensureStorageSchema(db *pdb.DB) error {
	value, closer, err := db.Get([]byte(storageSchemaKey))
	if err == nil {
		defer closer.Close()
		if string(value) != storageSchemaV3 {
			return trusterr.New(trusterr.CodeFailedPrecondition, "unsupported pebble proofstore schema; clear or rebuild the proofstore")
		}
		return nil
	}
	if !errors.Is(err, pdb.ErrNotFound) {
		return trusterr.Wrap(trusterr.CodeDataLoss, "read pebble proofstore schema", err)
	}
	iter, err := db.NewIter(nil)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "inspect pebble proofstore schema", err)
	}
	hasExistingData := iter.First()
	iterErr := iter.Error()
	if closeErr := iter.Close(); iterErr == nil {
		iterErr = closeErr
	}
	if iterErr != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "inspect pebble proofstore contents", iterErr)
	}
	if hasExistingData {
		return trusterr.New(trusterr.CodeFailedPrecondition, "unversioned pebble proofstore detected; clear or rebuild the proofstore")
	}
	batch := db.NewBatch()
	defer batch.Close()
	if err := batch.Set([]byte(storageSchemaKey), []byte(storageSchemaV3), nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage pebble proofstore schema", err)
	}
	if err := batch.Set([]byte(idempotencyReadyKey), []byte(idempotencyReadyV1), nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage empty idempotency projection readiness", err)
	}
	if err := batch.Commit(pdb.Sync); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "initialize pebble proofstore schema", err)
	}
	return nil
}

const (
	idempotencyManifestPageSize = 64
	idempotencyDecisionPageSize = 256
)

func idempotencyDecisionKey(identity model.IdempotencyIdentity) []byte {
	return append([]byte(prefixIdempotency), idempotency.StorageKey(identity)...)
}

func (s *Store) projectionReadyOnDisk() (bool, error) {
	value, closer, err := s.db.Get([]byte(idempotencyReadyKey))
	if errors.Is(err, pdb.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, trusterr.Wrap(trusterr.CodeDataLoss, "read idempotency projection readiness", err)
	}
	defer closer.Close()
	if string(value) != idempotencyReadyV1 {
		return false, trusterr.New(trusterr.CodeDataLoss, "invalid idempotency projection readiness marker")
	}
	return true, nil
}

func (s *Store) committedBatchesOnDisk() (bool, error) {
	value, closer, err := s.db.Get([]byte(committedBatchesKey))
	if errors.Is(err, pdb.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, trusterr.Wrap(trusterr.CodeDataLoss, "read committed batch marker", err)
	}
	defer closer.Close()
	if string(value) != committedBatchesV1 {
		return false, trusterr.New(trusterr.CodeDataLoss, "invalid committed batch marker")
	}
	return true, nil
}

// EnsureIdempotencyProjection rebuilds the point-read projection only when a
// prior generic committed-manifest write invalidated it. Normal restarts read
// one marker and do no historical scan. Rebuild pages are individually synced;
// readiness is published last, and a stale WAL checkpoint is removed first.
func (s *Store) EnsureIdempotencyProjection(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "ensure idempotency projection canceled", err)
	}
	s.idempotencyMu.Lock()
	defer s.idempotencyMu.Unlock()

	ready, err := s.projectionReadyOnDisk()
	if err != nil {
		s.idempotencyReady.Store(false)
		return err
	}
	if ready {
		s.idempotencyReady.Store(true)
		return nil
	}
	s.idempotencyReady.Store(false)

	reset := s.db.NewBatch()
	lower, upper := prefixBounds(prefixIdempotency)
	if err := reset.DeleteRange(lower, upper, nil); err != nil {
		_ = reset.Close()
		return trusterr.Wrap(trusterr.CodeDataLoss, "clear idempotency projection", err)
	}
	if err := reset.Delete([]byte(idempotencyReadyKey), nil); err != nil {
		_ = reset.Close()
		return trusterr.Wrap(trusterr.CodeDataLoss, "clear idempotency projection readiness", err)
	}
	if err := reset.Delete([]byte(checkpointKey), nil); err != nil {
		_ = reset.Close()
		return trusterr.Wrap(trusterr.CodeDataLoss, "clear stale wal checkpoint", err)
	}
	if err := reset.Commit(pdb.Sync); err != nil {
		_ = reset.Close()
		return trusterr.Wrap(trusterr.CodeDataLoss, "reset idempotency projection", err)
	}
	if err := reset.Close(); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "close idempotency projection reset", err)
	}

	for afterBatchID := ""; ; {
		manifests, err := s.ListManifestsAfter(ctx, afterBatchID, idempotencyManifestPageSize)
		if err != nil {
			return err
		}
		if len(manifests) == 0 {
			break
		}
		for i := range manifests {
			if manifests[i].State == model.BatchStateCommitted {
				if err := s.rebuildManifestIdempotency(ctx, manifests[i]); err != nil {
					return err
				}
			}
		}
		afterBatchID = manifests[len(manifests)-1].BatchID
	}
	if err := s.db.Set([]byte(idempotencyReadyKey), []byte(idempotencyReadyV1), pdb.Sync); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "publish idempotency projection readiness", err)
	}
	s.idempotencyReady.Store(true)
	return nil
}

func (s *Store) rebuildManifestIdempotency(ctx context.Context, manifest model.BatchManifest) error {
	for start := 0; start < len(manifest.RecordIDs); start += idempotencyDecisionPageSize {
		end := start + idempotencyDecisionPageSize
		if end > len(manifest.RecordIDs) {
			end = len(manifest.RecordIDs)
		}
		decisions := make([]model.IdempotencyDecision, 0, end-start)
		for _, recordID := range manifest.RecordIDs[start:end] {
			if err := ctx.Err(); err != nil {
				return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "rebuild idempotency projection canceled", err)
			}
			bundle, err := s.GetBundle(ctx, recordID)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeDataLoss, "load committed bundle for idempotency projection", err)
			}
			if bundle.RecordID != recordID {
				return trusterr.New(trusterr.CodeDataLoss, "committed bundle does not match manifest record")
			}
			if bundle.SignedClaim.Claim.IdempotencyKey == "" {
				continue
			}
			if bundle.ServerRecord.RecordID != recordID {
				return trusterr.New(trusterr.CodeDataLoss, "committed bundle server record does not match manifest record")
			}
			decision, err := idempotency.BuildDecision(
				manifest.BatchID,
				bundle.SignedClaim,
				bundle.ServerRecord,
				bundle.AcceptedReceipt,
			)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeDataLoss, "rebuild committed idempotency decision", err)
			}
			decisions = append(decisions, decision)
		}
		if err := s.writeIdempotencyDecisionPage(decisions); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) writeIdempotencyDecisionPage(decisions []model.IdempotencyDecision) error {
	if len(decisions) == 0 {
		return nil
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	seen := make(map[string]model.IdempotencyDecision, len(decisions))
	for i := range decisions {
		storageKey := idempotency.StorageKey(decisions[i].Identity)
		if prior, ok := seen[storageKey]; ok {
			if !idempotency.Equivalent(prior, decisions[i]) {
				return trusterr.New(trusterr.CodeDataLoss, "conflicting idempotency decisions in committed history")
			}
			continue
		}
		seen[storageKey] = decisions[i]
		var existing model.IdempotencyDecision
		found, err := s.readCBOR(idempotencyDecisionKey(decisions[i].Identity), &existing)
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "read rebuilt idempotency decision", err)
		}
		if found {
			if !idempotency.Equivalent(existing, decisions[i]) {
				return trusterr.New(trusterr.CodeDataLoss, "committed history contains conflicting idempotency decisions")
			}
			continue
		}
		data, err := cborx.Marshal(decisions[i])
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "encode rebuilt idempotency decision", err)
		}
		if err := stageSet(batch, idempotencyDecisionKey(decisions[i].Identity), data); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage rebuilt idempotency decision", err)
		}
	}
	if err := batch.Commit(pdb.Sync); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write rebuilt idempotency decisions", err)
	}
	return nil
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

// Close releases the underlying Pebble database. It is safe to call
// multiple times and from multiple goroutines; subsequent calls return
// the result of the first close.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.db.Close()
	})
	return s.closeErr
}

// PebbleMetrics returns a point-in-time snapshot of the underlying
// Pebble engine metrics. The snapshot is cheap to read and safe for
// concurrent use by observability collectors.
func (s *Store) PebbleMetrics() *pdb.Metrics {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Metrics()
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

func manifestStateKey(manifest model.BatchManifest) []byte {
	nextAttempt := manifest.MaterializeNextUnixN
	if nextAttempt < 0 {
		nextAttempt = 0
	}
	return []byte(fmt.Sprintf("%s%s/%0*d/%s/%s", prefixManifestState, manifest.State, rootSortKeyWidth, nextAttempt, recordSecondaryPart(manifest.NodeID), recordSecondaryPart(manifest.BatchID)))
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
	return errors.Is(err, pdb.ErrNotFound)
}

// writeCBOR marshals v and writes it at key with Sync durability so the
// write is readable after an immediate crash. The sync flush mirrors
// the writeCBORAtomic + rename guarantee of the file backend.
func (s *Store) writeCBOR(key []byte, v any) error {
	data, err := cborx.Marshal(v)
	if err != nil {
		return err
	}
	if err := s.db.Set(key, data, pdb.Sync); err != nil {
		return err
	}
	return nil
}

// readCBOR fetches key and decodes it into v. Pebble's Get returns
// borrowed bytes that must be copied before the closer runs; the
// cbor decoder copies into v so we can release the closer immediately
// after the decode.
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

func stageSet(batch *pdb.Batch, key, value []byte) error {
	op := batch.SetDeferred(len(key), len(value))
	copy(op.Key, key)
	copy(op.Value, value)
	return op.Finish()
}

func stageSetRecordKey(batch *pdb.Batch, prefix, recordID string, value []byte) error {
	op := batch.SetDeferred(len(prefix)+len(recordID), len(value))
	n := copy(op.Key, prefix)
	copy(op.Key[n:], recordID)
	copy(op.Value, value)
	return op.Finish()
}

func stageRecordIndexRef(batch *pdb.Batch, key []byte, recordID string) error {
	op := batch.SetDeferred(len(key), len(recordIndexRefPrefix)+len(recordID))
	copy(op.Key, key)
	copy(op.Value, recordIndexRefPrefix)
	copy(op.Value[len(recordIndexRefPrefix):], recordID)
	return op.Finish()
}

func (s *Store) artifactWriteOptions() *pdb.WriteOptions {
	if s != nil && s.artifactSyncMode == ArtifactSyncModeBatch {
		return pdb.NoSync
	}
	return pdb.Sync
}

func decodeRecordIndexRef(value []byte) (string, bool) {
	if !bytes.HasPrefix(value, recordIndexRefPrefix) {
		return "", false
	}
	recordID := string(value[len(recordIndexRefPrefix):])
	return recordID, recordID != ""
}

func (s *Store) readRecordIndexScanValue(value []byte) (model.RecordIndex, error) {
	if recordID, ok := decodeRecordIndexRef(value); ok {
		var idx model.RecordIndex
		found, err := s.readCBOR(recordByIDKey(recordID), &idx)
		if err != nil {
			return model.RecordIndex{}, err
		}
		if !found {
			return model.RecordIndex{}, trusterr.New(trusterr.CodeDataLoss, "record index reference target not found")
		}
		return idx, nil
	}
	var idx model.RecordIndex
	if err := cborx.UnmarshalLimit(value, &idx, maxStoredObjectBytes); err != nil {
		return model.RecordIndex{}, err
	}
	return idx, nil
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
	s.idempotencyMu.RLock()
	defer s.idempotencyMu.RUnlock()
	var old model.RecordIndex
	oldFound, err := s.readCBOR(recordByIDKey(bundle.RecordID), &old)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "read existing record index", err)
	}
	if err := s.ensureEncodedArtifactMutable(artifact, old, oldFound, nil); err != nil {
		return err
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := stageSetRecordKey(batch, prefixBundleV2, bundle.RecordID, artifact.bundleValue); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage proof bundle", err)
	}
	if err := s.stageEncodedRecordIndexReplace(batch, artifact.index, old, oldFound); err != nil {
		return err
	}
	if err := batch.Commit(pdb.Sync); err != nil {
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
		var finalRoot *model.BatchRoot
		if end == len(bundles) {
			finalRoot = &root
		}
		if err := s.commitBatchArtifactChunk(artifacts, finalRoot); err != nil {
			return err
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
		if err := s.commitMaterializedArtifactChunk(artifacts); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) commitBatchArtifactChunk(artifacts []encodedBatchArtifact, root *model.BatchRoot) error {
	s.idempotencyMu.RLock()
	defer s.idempotencyMu.RUnlock()
	if err := s.ensureEncodedArtifactsMutable(artifacts); err != nil {
		releaseBatchArtifacts(artifacts)
		return err
	}
	batch := s.db.NewBatchWithSize(estimateBatchArtifactBytes(artifacts))
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
	if root != nil {
		if err := s.stageRoot(batch, *root); err != nil {
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
	return nil
}

func (s *Store) commitMaterializedArtifactChunk(artifacts []encodedBatchArtifact) error {
	s.idempotencyMu.RLock()
	defer s.idempotencyMu.RUnlock()
	if err := s.ensureEncodedArtifactsMutable(artifacts); err != nil {
		releaseBatchArtifacts(artifacts)
		return err
	}
	batch := s.db.NewBatchWithSize(estimateMaterializedBatchArtifactBytes(artifacts))
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
	return nil
}

func (s *Store) ensureEncodedArtifactsMutable(artifacts []encodedBatchArtifact) error {
	if !s.hasCommittedBatch.Load() {
		return nil
	}
	manifests := make(map[string]model.BatchManifest)
	for i := range artifacts {
		var old model.RecordIndex
		oldFound, err := s.readCBOR(recordByIDKey(artifacts[i].recordID), &old)
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "read existing artifact index", err)
		}
		if err := s.ensureEncodedArtifactMutable(artifacts[i], old, oldFound, manifests); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureEncodedArtifactMutable(artifact encodedBatchArtifact, old model.RecordIndex, oldFound bool, manifests map[string]model.BatchManifest) error {
	if !s.hasCommittedBatch.Load() {
		return nil
	}
	if !oldFound || old.BatchID == "" {
		return nil
	}
	manifest, cached := manifests[old.BatchID]
	if !cached {
		found, err := s.readCBOR(manifestKey(old.BatchID), &manifest)
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "read existing artifact manifest", err)
		}
		if manifests != nil {
			manifests[old.BatchID] = manifest
		}
		if !found || manifest.State != model.BatchStateCommitted {
			return nil
		}
	}
	if manifest.State != model.BatchStateCommitted {
		return nil
	}
	value, closer, err := s.db.Get(bundleV2Key(artifact.recordID))
	if errors.Is(err, pdb.ErrNotFound) {
		return trusterr.New(trusterr.CodeDataLoss, "committed record index has no proof bundle")
	}
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "read committed proof bundle", err)
	}
	defer closer.Close()
	if !bytes.Equal(value, artifact.bundleValue) {
		return trusterr.New(trusterr.CodeAlreadyExists, "committed proof bundle is immutable")
	}
	return nil
}

func estimateBatchArtifactBytes(artifacts []encodedBatchArtifact) int {
	total := 0
	for i := range artifacts {
		total += len(artifacts[i].bundleValue) + len(artifacts[i].index.value) + len(artifacts[i].recordID) + 512
	}
	return total
}

func estimateMaterializedBatchArtifactBytes(artifacts []encodedBatchArtifact) int {
	total := 0
	for i := range artifacts {
		total += len(artifacts[i].bundleValue) + len(artifacts[i].index.value) + len(artifacts[i].recordID)*4 + 256
	}
	return total
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
		batchSize := 0
		for i := range encoded {
			batchSize += len(encoded[i].value) + len(encoded[i].idx.RecordID) + 512
		}
		batch := s.db.NewBatchWithSize(batchSize)
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

func (s *Store) stageNewBundle(batch *pdb.Batch, bundle model.ProofBundle) error {
	artifact, err := encodeBatchArtifact(bundle)
	if err != nil {
		return err
	}
	defer artifact.release()
	return s.stageEncodedBatchArtifact(batch, artifact)
}

func (s *Store) stageEncodedBatchArtifact(batch *pdb.Batch, artifact encodedBatchArtifact) error {
	if err := stageSetRecordKey(batch, prefixBundleV2, artifact.recordID, artifact.bundleValue); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage proof bundle", err)
	}
	return s.stageEncodedRecordIndexSetForMode(batch, artifact.index)
}

func (s *Store) stageEncodedMaterializedBatchArtifact(batch *pdb.Batch, artifact encodedBatchArtifact) error {
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
	if err := batch.Commit(pdb.Sync); err != nil {
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open record index iterator", err)
	}
	defer iter.Close()

	desc := !strings.EqualFold(opts.Direction, model.RecordListDirectionAsc)
	hasCursor := opts.AfterReceivedAtUnixN != 0 || opts.AfterRecordID != ""
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
	for ok {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list record indexes canceled", err)
		}
		if len(records) >= limit {
			break
		}
		idx, err := s.readRecordIndexScanValue(iter.Value())
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode record index", err)
		}
		if recordRangeExhausted(idx, opts, desc) {
			break
		}
		if model.RecordIndexMatchesListOptions(idx, opts) && model.RecordIndexAfterCursor(idx, opts) {
			records = append(records, idx)
		}
		if desc {
			ok = iter.Prev()
		} else {
			ok = iter.Next()
		}
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate record indexes", err)
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

func (s *Store) stageRoot(batch *pdb.Batch, root model.BatchRoot) error {
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
			if leaf.BatchID != batchID {
				return trusterr.New(trusterr.CodeInvalidArgument, "batch tree leaves must share batch_id")
			}
			pos := i - start
			tile.LeafIndexes[pos] = leaf.LeafIndex
			tile.RecordIDs[pos] = leaf.RecordID
			tile.Hashes[pos] = leaf.LeafHash
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
					if node.BatchID != batchID || node.Width == 0 {
						return trusterr.New(trusterr.CodeInvalidArgument, "invalid batch tree node")
					}
					pos := i - start
					tile.StartIndexes[pos] = node.StartIndex
					tile.Widths[pos] = node.Width
					tile.Hashes[pos] = node.Hash
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
			RecordIDs:      snapshot.RecordIDs[start:end],
			Hashes:         make([][]byte, end-start),
			CreatedAtUnixN: createdAt,
		}
		for i := start; i < end; i++ {
			pos := i - start
			tile.LeafIndexes[pos] = uint64(i)
			tile.Hashes[pos] = snapshot.LeafHashes[i][:]
		}
		leafTiles = append(leafTiles, tile)
	}
	nodeTiles := make([]batchTreeNodeTile, 0)
	for levelStart := 0; levelStart < len(snapshot.Nodes); {
		level := snapshot.Nodes[levelStart].Level
		levelEnd := levelStart
		for levelEnd < len(snapshot.Nodes) && snapshot.Nodes[levelEnd].Level == level {
			levelEnd++
		}
		if level != 0 {
			for start := levelStart; start < levelEnd; start += batchTreeTileSize {
				end := min(start+batchTreeTileSize, levelEnd)
				tile := batchTreeNodeTile{
					SchemaVersion:  schemaBatchTreeNodeTileV2,
					BatchID:        snapshot.BatchID,
					Level:          level,
					StartIndex:     snapshot.Nodes[start].StartIndex,
					StartIndexes:   make([]uint64, end-start),
					Widths:         make([]uint64, end-start),
					Hashes:         make([][]byte, end-start),
					CreatedAtUnixN: createdAt,
				}
				for i := start; i < end; i++ {
					pos := i - start
					tile.StartIndexes[pos] = snapshot.Nodes[i].StartIndex
					tile.Widths[pos] = snapshot.Nodes[i].Width
					tile.Hashes[pos] = snapshot.Nodes[i].Hash[:]
				}
				nodeTiles = append(nodeTiles, tile)
			}
		}
		levelStart = levelEnd
	}
	return s.putBatchTreeTiles(ctx, leafTiles, nodeTiles)
}

func (s *Store) putBatchTreeTiles(ctx context.Context, leaves []batchTreeLeafTile, nodes []batchTreeNodeTile) error {
	encodedLeaves := make([][]byte, len(leaves))
	encodedNodes := make([][]byte, len(nodes))
	batchSize := 0
	for i := range leaves {
		data, err := cborx.Marshal(leaves[i])
		if err != nil {
			return err
		}
		encodedLeaves[i] = data
		batchSize += len(data) + 128
	}
	for i := range nodes {
		data, err := cborx.Marshal(nodes[i])
		if err != nil {
			return err
		}
		encodedNodes[i] = data
		batchSize += len(data) + 128
	}
	batch := s.db.NewBatchWithSize(batchSize)
	defer batch.Close()
	for i := range leaves {
		if err := stageSet(batch, batchTreeLeafKey(leaves[i].BatchID, leaves[i].StartIndex), encodedLeaves[i]); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage batch tree leaf tile", err)
		}
	}
	for i := range nodes {
		if err := stageSet(batch, batchTreeNodeKey(nodes[i].BatchID, nodes[i].Level, nodes[i].StartIndex), encodedNodes[i]); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage batch tree node tile", err)
		}
	}
	if err := batch.Commit(s.artifactWriteOptions()); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit batch tree tiles", err)
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open batch tree leaf iterator", err)
	}
	defer iter.Close()
	ok := iter.First()
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
		if len(tile.LeafIndexes) != len(tile.RecordIDs) || len(tile.LeafIndexes) != len(tile.Hashes) {
			return nil, trusterr.New(trusterr.CodeDataLoss, "invalid batch tree leaf tile")
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
		leaves, err := s.ListBatchTreeLeaves(ctx, model.BatchTreeLeafListOptions{
			BatchID:        opts.BatchID,
			Limit:          limit,
			AfterLeafIndex: after,
			HasAfter:       hasAfter,
		})
		if err != nil {
			return nil, err
		}
		nodes := make([]model.BatchTreeNode, len(leaves))
		for i := range leaves {
			nodes[i] = model.BatchTreeNode{
				SchemaVersion:  model.SchemaBatchTreeNode,
				BatchID:        leaves[i].BatchID,
				Level:          0,
				StartIndex:     leaves[i].LeafIndex,
				Width:          1,
				Hash:           append([]byte(nil), leaves[i].LeafHash...),
				CreatedAtUnixN: leaves[i].CreatedAtUnixN,
			}
		}
		return nodes, nil
	}
	prefix := fmt.Sprintf("%s%s/%0*d/", prefixBatchTreeNode, opts.BatchID, rootSortKeyWidth, opts.Level)
	lower, upper := prefixBounds(prefix)
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open batch tree node iterator", err)
	}
	defer iter.Close()
	ok := iter.First()
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
		if len(tile.StartIndexes) != len(tile.Widths) || len(tile.StartIndexes) != len(tile.Hashes) {
			return nil, trusterr.New(trusterr.CodeDataLoss, "invalid batch tree node tile")
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
	s.idempotencyMu.Lock()
	defer s.idempotencyMu.Unlock()
	var old model.BatchManifest
	oldFound, err := s.readCBOR(manifestKey(manifest.BatchID), &old)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "read old batch manifest", err)
	}
	batch := s.db.NewBatchWithSize(len(data)*2 + 512)
	defer batch.Close()
	if oldFound {
		if err := batch.Delete(manifestStateKey(old), nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "delete old batch manifest state", err)
		}
	}
	if err := stageSet(batch, manifestKey(manifest.BatchID), data); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage batch manifest", err)
	}
	if err := stageSet(batch, manifestStateKey(manifest), data); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage batch manifest state", err)
	}
	invalidateProjection := manifest.State == model.BatchStateCommitted ||
		(oldFound && old.State == model.BatchStateCommitted)
	if invalidateProjection {
		// Fail closed in memory before making the generic committed write
		// durable. The same Pebble batch removes both readiness and the local
		// checkpoint that depended on it.
		s.idempotencyReady.Store(false)
		if err := batch.Delete([]byte(idempotencyReadyKey), nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "invalidate idempotency projection readiness", err)
		}
		if err := batch.Delete([]byte(checkpointKey), nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "invalidate wal checkpoint", err)
		}
	}
	if manifest.State == model.BatchStateCommitted {
		if err := stageSet(batch, []byte(committedBatchesKey), []byte(committedBatchesV1)); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage committed batch marker", err)
		}
	}
	if err := batch.Commit(pdb.Sync); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write batch manifest", err)
	}
	if manifest.State == model.BatchStateCommitted {
		s.hasCommittedBatch.Store(true)
	}
	return nil
}

// PublishCommittedBatch makes the committed manifest and its durable keyed
// responses visible in one synced Pebble batch. Existing identities are
// conditional: an exact replay is harmless, while a conflicting response is
// rejected without changing the manifest.
func (s *Store) PublishCommittedBatch(ctx context.Context, manifest model.BatchManifest, bundles []model.ProofBundle) ([]model.IdempotencyDecision, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "publish committed batch canceled", err)
	}
	if manifest.BatchID == "" || manifest.State != model.BatchStateCommitted {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "a committed batch manifest is required")
	}
	if manifest.SchemaVersion == "" {
		manifest.SchemaVersion = model.SchemaBatchManifest
	}
	manifestData, err := cborx.Marshal(manifest)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "encode committed batch manifest", err)
	}

	if len(bundles) != len(manifest.RecordIDs) {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "committed manifest and bundle counts differ")
	}
	decisions := make([]model.IdempotencyDecision, 0, len(bundles))
	recordIDs := make(map[string]struct{}, len(manifest.RecordIDs))
	for i, recordID := range manifest.RecordIDs {
		if recordID == "" {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "committed manifest contains an empty record_id")
		}
		if _, exists := recordIDs[recordID]; exists {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "committed manifest contains a duplicate record_id")
		}
		recordIDs[recordID] = struct{}{}
		if bundles[i].SchemaVersion != model.SchemaProofBundle ||
			bundles[i].RecordID != recordID ||
			bundles[i].ServerRecord.RecordID != recordID ||
			bundles[i].AcceptedReceipt.RecordID != recordID ||
			bundles[i].CommittedReceipt.SchemaVersion != model.SchemaCommittedReceipt ||
			bundles[i].CommittedReceipt.RecordID != recordID ||
			bundles[i].CommittedReceipt.Status != "committed" ||
			bundles[i].CommittedReceipt.BatchID != manifest.BatchID ||
			bundles[i].CommittedReceipt.LeafIndex != uint64(i) ||
			bundles[i].BatchProof.LeafIndex != uint64(i) ||
			bundles[i].BatchProof.TreeSize != manifest.TreeSize {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "committed bundle does not match manifest record order")
		}
		if bundles[i].SignedClaim.Claim.IdempotencyKey == "" {
			continue
		}
		decision, err := idempotency.BuildDecision(
			manifest.BatchID,
			bundles[i].SignedClaim,
			bundles[i].ServerRecord,
			bundles[i].AcceptedReceipt,
		)
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "build committed idempotency decision", err)
		}
		decisions = append(decisions, decision)
	}
	encoded := make(map[string][]byte, len(decisions))
	prepared := make(map[string]model.IdempotencyDecision, len(decisions))
	decisionRecords := make(map[string]struct{}, len(decisions))
	for i := range decisions {
		if decisions[i].BatchID != manifest.BatchID {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "idempotency decision belongs to a different batch")
		}
		if _, ok := recordIDs[decisions[i].Record.RecordID]; !ok {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "idempotency decision record is absent from committed manifest")
		}
		if _, exists := decisionRecords[decisions[i].Record.RecordID]; exists {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "duplicate idempotency decision record")
		}
		decisionRecords[decisions[i].Record.RecordID] = struct{}{}
		if err := idempotency.ValidateDecision(decisions[i].Identity, decisions[i]); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeInvalidArgument, "validate idempotency decision", err)
		}
		storageKey := idempotency.StorageKey(decisions[i].Identity)
		if prior, exists := prepared[storageKey]; exists {
			if !idempotency.Equivalent(prior, decisions[i]) {
				return nil, trusterr.New(trusterr.CodeAlreadyExists, "idempotency identity has conflicting decisions")
			}
			continue
		}
		data, err := cborx.Marshal(decisions[i])
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "encode idempotency decision", err)
		}
		prepared[storageKey] = decisions[i]
		encoded[storageKey] = data
	}

	s.idempotencyMu.Lock()
	defer s.idempotencyMu.Unlock()
	if !s.idempotencyReady.Load() {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "idempotency projection is not ready")
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
	for storageKey, decision := range prepared {
		var existing model.IdempotencyDecision
		found, err := s.readCBOR(append([]byte(prefixIdempotency), storageKey...), &existing)
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read existing idempotency decision", err)
		}
		if found && !idempotency.Equivalent(existing, decision) {
			return nil, trusterr.New(trusterr.CodeAlreadyExists, "idempotency identity already has a different committed decision")
		}
	}

	var old model.BatchManifest
	oldFound, err := s.readCBOR(manifestKey(manifest.BatchID), &old)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read old batch manifest", err)
	}
	if oldFound && old.State == model.BatchStateCommitted {
		oldData, err := cborx.Marshal(old)
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "encode old committed manifest", err)
		}
		if !bytes.Equal(oldData, manifestData) {
			return nil, trusterr.New(trusterr.CodeAlreadyExists, "committed batch manifest already exists with different contents")
		}
	}

	batch := s.db.NewBatchWithSize(len(manifestData)*2 + len(decisions)*512 + 512)
	defer batch.Close()
	if oldFound {
		if err := batch.Delete(manifestStateKey(old), nil); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "delete old batch manifest state", err)
		}
	}
	if err := stageSet(batch, manifestKey(manifest.BatchID), manifestData); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "stage committed batch manifest", err)
	}
	if err := stageSet(batch, manifestStateKey(manifest), manifestData); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "stage committed batch manifest state", err)
	}
	for storageKey, data := range encoded {
		if err := stageSet(batch, append([]byte(prefixIdempotency), storageKey...), data); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "stage idempotency decision", err)
		}
	}
	if err := stageSet(batch, []byte(committedBatchesKey), []byte(committedBatchesV1)); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "stage committed batch marker", err)
	}
	if err := batch.Commit(pdb.Sync); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "commit manifest and idempotency decisions", err)
	}
	s.hasCommittedBatch.Store(true)
	return decisions, nil
}

func (s *Store) GetIdempotencyDecision(ctx context.Context, identity model.IdempotencyIdentity) (model.IdempotencyDecision, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.IdempotencyDecision{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "get idempotency decision canceled", err)
	}
	if identity.TenantID == "" || identity.ClientID == "" || identity.IdempotencyKey == "" {
		return model.IdempotencyDecision{}, false, trusterr.New(trusterr.CodeInvalidArgument, "idempotency identity is incomplete")
	}
	s.idempotencyMu.RLock()
	defer s.idempotencyMu.RUnlock()
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

func (s *Store) ListPreparedManifests(ctx context.Context, nodeID string, nowUnixN int64, limit int) ([]model.BatchManifest, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list prepared manifests canceled", err)
	}
	if limit <= 0 {
		limit = 128
	}
	prefix := prefixManifestState + model.BatchStatePrepared + "/"
	lower, upper := prefixBounds(prefix)
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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

func (s *Store) PutCheckpoint(ctx context.Context, cp model.WALCheckpoint) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put checkpoint canceled", err)
	}
	if cp.SchemaVersion == "" {
		cp.SchemaVersion = model.SchemaWALCheckpoint
	}
	if cp.RecordedAtUnixN == 0 {
		cp.RecordedAtUnixN = time.Now().UTC().UnixNano()
	}
	s.idempotencyMu.RLock()
	defer s.idempotencyMu.RUnlock()
	if !s.idempotencyReady.Load() {
		return trusterr.New(trusterr.CodeFailedPrecondition, "cannot persist wal checkpoint before idempotency projection is ready")
	}
	if err := s.writeCBOR([]byte(checkpointKey), cp); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write wal checkpoint", err)
	}
	return nil
}

func (s *Store) GetCheckpoint(ctx context.Context) (model.WALCheckpoint, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.WALCheckpoint{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get checkpoint canceled", err)
	}
	var cp model.WALCheckpoint
	found, err := s.readCBOR([]byte(checkpointKey), &cp)
	if err != nil {
		return model.WALCheckpoint{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read wal checkpoint", err)
	}
	if !found {
		return model.WALCheckpoint{}, false, nil
	}
	return cp, true, nil
}

func (s *Store) WithWALCheckpointPruneGuard(ctx context.Context, expected model.WALCheckpoint, prune func() error) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "wal checkpoint prune guard canceled", err)
	}
	if prune == nil {
		return false, trusterr.New(trusterr.CodeInvalidArgument, "wal checkpoint prune callback is required")
	}
	s.idempotencyMu.RLock()
	defer s.idempotencyMu.RUnlock()
	if !s.idempotencyReady.Load() {
		return false, nil
	}
	var current model.WALCheckpoint
	found, err := s.readCBOR([]byte(checkpointKey), &current)
	if err != nil {
		return false, trusterr.Wrap(trusterr.CodeDataLoss, "read guarded wal checkpoint", err)
	}
	if !found || current != expected {
		return false, nil
	}
	if err := prune(); err != nil {
		return true, err
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

func anchorResultKey(key model.STHAnchorResultKey) []byte {
	return []byte(fmt.Sprintf(
		"%s%0*d/%s/%s/%s",
		prefixAnchorResult,
		rootSortKeyWidth,
		key.TreeSize,
		recordSecondaryPart(key.NodeID),
		recordSecondaryPart(key.LogID),
		recordSecondaryPart(key.SinkName),
	))
}

func anchorResultTreePrefix(treeSize uint64) []byte {
	return []byte(fmt.Sprintf("%s%0*d/", prefixAnchorResult, rootSortKeyWidth, treeSize))
}

func anchorLatestKey(key model.STHAnchorScheduleKey) []byte {
	return []byte(fmt.Sprintf(
		"%s%s/%s/%s",
		prefixAnchorLatest,
		recordSecondaryPart(key.NodeID),
		recordSecondaryPart(key.LogID),
		recordSecondaryPart(key.SinkName),
	))
}

func anchorScheduleKey(key model.STHAnchorScheduleKey) []byte {
	return []byte(fmt.Sprintf(
		"%s%s/%s/%s",
		prefixAnchorSchedule,
		recordSecondaryPart(key.NodeID),
		recordSecondaryPart(key.LogID),
		recordSecondaryPart(key.SinkName),
	))
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
	if err := batch.Commit(pdb.Sync); err != nil {
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
	if err := batch.Commit(pdb.Sync); err != nil {
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
	type encodedAppend struct {
		entry    model.GlobalLogAppend
		leafData []byte
		sthData  []byte
		nodes    [][]byte
	}
	encoded := make([]encodedAppend, len(entries))
	batchSize := 0
	for i := range entries {
		entry := entries[i]
		if entry.Leaf.BatchID == "" || entry.STH.TreeSize == 0 || entry.Leaf.LeafIndex != entry.STH.TreeSize-1 || entry.State.TreeSize != entry.STH.TreeSize {
			return trusterr.New(trusterr.CodeInvalidArgument, "invalid global log append")
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
		sthData, err := cborx.Marshal(entry.STH)
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "encode global log append STH", err)
		}
		nodeData := make([][]byte, len(entry.Nodes))
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
			entry.Nodes[j] = node
			nodeData[j], err = cborx.Marshal(node)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeDataLoss, "encode global log append node", err)
			}
			batchSize += len(nodeData[j]) + 128
		}
		encoded[i] = encodedAppend{entry: entry, leafData: leafData, sthData: sthData, nodes: nodeData}
		batchSize += len(leafData)*2 + len(sthData) + 512
	}
	stateData, err := cborx.Marshal(encoded[len(encoded)-1].entry.State)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode global log append state", err)
	}
	batch := s.db.NewBatchWithSize(batchSize + len(stateData))
	defer batch.Close()
	for i := range encoded {
		entry := encoded[i].entry
		if err := batch.Set(globalLeafKey(entry.Leaf.LeafIndex), encoded[i].leafData, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log append leaf", err)
		}
		if err := batch.Set(globalBatchKey(entry.Leaf.BatchID), encoded[i].leafData, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log append leaf batch index", err)
		}
		for j := range entry.Nodes {
			if err := batch.Set(globalNodeKey(entry.Nodes[j].Level, entry.Nodes[j].StartIndex), encoded[i].nodes[j], nil); err != nil {
				return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log append node", err)
			}
		}
		if err := batch.Set(sthKey(entry.STH.TreeSize), encoded[i].sthData, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log append STH", err)
		}
	}
	if err := batch.Set([]byte(globalStateKey), stateData, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log append state", err)
	}
	if err := batch.Commit(pdb.Sync); err != nil {
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
	if err := batch.Commit(pdb.Sync); err != nil {
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
	batchSize := 0
	now := time.Now().UTC().UnixNano()
	for i := range batchIDs {
		item, ok, err := s.GetGlobalLogOutboxItem(ctx, batchIDs[i])
		if err != nil {
			return err
		}
		if !ok {
			return trusterr.New(trusterr.CodeNotFound, "global log outbox item not found")
		}
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
		batchSize += len(data)*2 + len(batchIDs[i])*3 + 256
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
		batchSize += len(data)*2 + 128
	}
	for i := range batchIDs {
		if err := s.promoteBatchRecords(ctx, batchIDs[i], "L4"); err != nil {
			return err
		}
	}
	batch := s.db.NewBatchWithSize(batchSize)
	for i := range updates {
		if err := batch.Set(globalOutboxKey(updates[i].next.BatchID), updates[i].data, nil); err != nil {
			_ = batch.Close()
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log outbox item", err)
		}
		if err := batch.Delete(globalStatusKey(updates[i].old.Status, globalStatusSortUnixN(updates[i].old), updates[i].old.BatchID), nil); err != nil {
			_ = batch.Close()
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage old global log status delete", err)
		}
		if err := batch.Set(globalStatusKey(updates[i].next.Status, globalStatusSortUnixN(updates[i].next), updates[i].next.BatchID), updates[i].data, nil); err != nil {
			_ = batch.Close()
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage global log status index", err)
		}
	}
	for i := range anchorUpdates {
		if err := batch.Set(anchorOutboxKey(anchorUpdates[i].item.TreeSize), anchorUpdates[i].data, nil); err != nil {
			_ = batch.Close()
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor outbox item", err)
		}
		if err := batch.Set(anchorStatusKey(anchorUpdates[i].item.Status, anchorStatusSortUnixN(anchorUpdates[i].item), anchorUpdates[i].item.TreeSize), anchorUpdates[i].data, nil); err != nil {
			_ = batch.Close()
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor status index", err)
		}
	}
	if err := batch.Commit(pdb.Sync); err != nil {
		_ = batch.Close()
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit global log outbox batch", err)
	}
	if err := batch.Close(); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "close global log outbox batch", err)
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
	if err := batch.Commit(pdb.Sync); err != nil {
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
	batchSize := 0
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
		batchSize += len(data)*2 + 128
	}
	if len(encoded) == 0 {
		return nil
	}
	batch := s.db.NewBatchWithSize(batchSize)
	defer batch.Close()
	for i := range encoded {
		if err := batch.Set(anchorOutboxKey(encoded[i].item.TreeSize), encoded[i].data, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor outbox item", err)
		}
		if err := batch.Set(anchorStatusKey(encoded[i].item.Status, anchorStatusSortUnixN(encoded[i].item), encoded[i].item.TreeSize), encoded[i].data, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor status index", err)
		}
	}
	if err := batch.Commit(pdb.Sync); err != nil {
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
	item, ok, err := s.GetSTHAnchorOutboxItem(ctx, result.TreeSize)
	if err != nil {
		return err
	}
	if !ok {
		return trusterr.New(trusterr.CodeNotFound, "sth anchor outbox item not found")
	}
	result, err = anchorschedule.BindOutboxResult(item, result, time.Now().UTC().UnixNano())
	if err != nil {
		return err
	}
	old := item
	item.Status = model.AnchorStatePublished
	item.LastErrorMessage = ""
	item.LastAttemptUnixN = result.PublishedAtUnixN
	item.NextAttemptUnixN = 0

	itemBytes, err := cborx.Marshal(item)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode sth anchor outbox item", err)
	}
	s.anchorScheduleMu.Lock()
	defer s.anchorScheduleMu.Unlock()
	if existing, found, err := s.readSTHAnchorResult(anchorschedule.ResultKey(result)); err != nil {
		return err
	} else if found && !anchorschedule.SameResultBinding(existing, result) {
		return trusterr.New(trusterr.CodeDataLoss, "stored STH anchor result conflicts with publication update")
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := s.stageSTHAnchorResultLocked(ctx, batch, result, true); err != nil {
		return err
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
	if err := batch.Commit(pdb.Sync); err != nil {
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
	lower := anchorResultTreePrefix(treeSize)
	upper := append(append([]byte(nil), lower...), 0xff)
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "open sth anchor result iterator", err)
	}
	defer iter.Close()
	if !iter.First() {
		if err := iter.Error(); err != nil {
			return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "iterate sth anchor results", err)
		}
		return model.STHAnchorResult{}, false, nil
	}
	result, err := decodePebbleSTHAnchorResult(iter.Key(), iter.Value())
	return result, err == nil, err
}

func (s *Store) LatestSTHAnchorResult(ctx context.Context) (model.STHAnchorResult, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore latest sth anchor result canceled", err)
	}
	s.anchorScheduleMu.Lock()
	defer s.anchorScheduleMu.Unlock()
	return s.latestSTHAnchorResultLocked(ctx, nil)
}

func (s *Store) PutSTHAnchorResult(ctx context.Context, result model.STHAnchorResult) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put sth anchor result canceled", err)
	}
	key := model.STHAnchorScheduleKey{NodeID: result.NodeID, LogID: result.LogID, SinkName: result.SinkName}
	if err := anchorschedule.ValidateResult(key, result); err != nil {
		return err
	}

	s.anchorScheduleMu.Lock()
	defer s.anchorScheduleMu.Unlock()

	existing, found, err := s.readSTHAnchorResult(anchorschedule.ResultKey(result))
	if err != nil {
		return err
	}
	if found {
		if err := validateStoredSTHAnchorResult(existing); err != nil {
			return err
		}
		if !anchorschedule.SameResultBinding(existing, result) {
			return trusterr.New(trusterr.CodeDataLoss, "stored STH anchor result conflicts with replacement")
		}
		result = existing
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	// Proof bytes may have been enriched after the original publication. An
	// idempotent restore or retry never replaces that newer value, but it still
	// repairs missing derived latest references.
	if err := s.stageSTHAnchorResultLocked(ctx, batch, result, !found); err != nil {
		return err
	}
	if err := batch.Commit(pdb.Sync); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit sth anchor result", err)
	}
	return nil
}

func (s *Store) GetSTHAnchorResultForKey(ctx context.Context, key model.STHAnchorResultKey) (model.STHAnchorResult, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get keyed sth anchor result canceled", err)
	}
	if err := anchorschedule.ValidateResultKey(key); err != nil {
		return model.STHAnchorResult{}, false, err
	}
	return s.readSTHAnchorResult(key)
}

func (s *Store) LatestSTHAnchorResultForKey(ctx context.Context, key model.STHAnchorScheduleKey) (model.STHAnchorResult, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore latest keyed sth anchor result canceled", err)
	}
	if err := anchorschedule.ValidateKey(key); err != nil {
		return model.STHAnchorResult{}, false, err
	}
	s.anchorScheduleMu.Lock()
	defer s.anchorScheduleMu.Unlock()
	return s.latestSTHAnchorResultLocked(ctx, &key)
}

func (s *Store) ListSTHAnchorResultsAfter(ctx context.Context, after model.STHAnchorResultKey, limit int) ([]model.STHAnchorResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor results canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	if after.TreeSize != 0 {
		if err := anchorschedule.ValidateResultKey(after); err != nil {
			return nil, err
		}
	}
	lower, upper := prefixBounds(prefixAnchorResult)
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open sth anchor result iterator", err)
	}
	defer iter.Close()

	results := make([]model.STHAnchorResult, 0, limit)
	var ok bool
	if after.TreeSize == 0 {
		ok = iter.First()
	} else {
		ok = iter.SeekGE(anchorResultKey(after))
		if ok && bytes.Equal(iter.Key(), anchorResultKey(after)) {
			ok = iter.Next()
		}
	}
	for ; ok && len(results) < limit; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor results canceled", err)
		}
		result, err := decodePebbleSTHAnchorResult(iter.Key(), iter.Value())
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate sth anchor results", err)
	}
	return results, nil
}

func (s *Store) UpsertSTHAnchorCandidate(ctx context.Context, candidate model.STHAnchorCandidate) (model.STHAnchorSchedule, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorSchedule{}, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore upsert sth anchor candidate canceled", err)
	}
	if err := anchorschedule.ValidateCandidate(candidate); err != nil {
		return model.STHAnchorSchedule{}, err
	}

	s.anchorScheduleMu.Lock()
	defer s.anchorScheduleMu.Unlock()

	current, found, err := s.readSTHAnchorSchedule(candidate.Key)
	if err != nil {
		return model.STHAnchorSchedule{}, err
	}
	if err := s.validateSTHAnchorCandidateTreeLocked(candidate); err != nil {
		return model.STHAnchorSchedule{}, err
	}
	latest, err := s.latestSTHAnchorResultForKey(ctx, candidate.Key)
	if err != nil {
		return model.STHAnchorSchedule{}, err
	}
	exactKey := model.STHAnchorResultKey{
		NodeID: candidate.Key.NodeID, LogID: candidate.Key.LogID, SinkName: candidate.Key.SinkName, TreeSize: candidate.STH.TreeSize,
	}
	exact, exactFound, err := s.readSTHAnchorResult(exactKey)
	if err != nil {
		return model.STHAnchorSchedule{}, err
	}
	if exactFound {
		if err := anchorschedule.ValidateCandidateAgainstExactResult(candidate, exact); err != nil {
			return model.STHAnchorSchedule{}, err
		}
		if latest == nil || exact.TreeSize > latest.TreeSize {
			latest = &exact
		}
	}
	next, changed, err := anchorschedule.MergeCandidate(current, found, candidate, latest)
	if err != nil {
		return model.STHAnchorSchedule{}, err
	}
	if !changed {
		return next, nil
	}
	if err := s.commitSTHAnchorSchedule(next, "commit sth anchor candidate"); err != nil {
		return model.STHAnchorSchedule{}, err
	}
	return next, nil
}

func (s *Store) GetSTHAnchorSchedule(ctx context.Context, key model.STHAnchorScheduleKey) (model.STHAnchorSchedule, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorSchedule{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get sth anchor schedule canceled", err)
	}
	if err := anchorschedule.ValidateKey(key); err != nil {
		return model.STHAnchorSchedule{}, false, err
	}
	return s.readSTHAnchorSchedule(key)
}

func (s *Store) ListSTHAnchorSchedules(ctx context.Context) ([]model.STHAnchorSchedule, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor schedules canceled", err)
	}
	lower, upper := prefixBounds(prefixAnchorSchedule)
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open sth anchor schedule iterator", err)
	}
	defer iter.Close()

	schedules := make([]model.STHAnchorSchedule, 0)
	for ok := iter.First(); ok; ok = iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor schedules canceled", err)
		}
		var schedule model.STHAnchorSchedule
		if err := cborx.UnmarshalLimit(iter.Value(), &schedule, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode sth anchor schedule", err)
		}
		if err := anchorschedule.ValidateSchedule(schedule); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "validate stored sth anchor schedule", err)
		}
		if !bytes.Equal(iter.Key(), anchorScheduleKey(schedule.Key)) {
			return nil, trusterr.New(trusterr.CodeDataLoss, "sth anchor schedule key does not match item")
		}
		schedules = append(schedules, schedule)
	}
	if err := iter.Error(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "iterate sth anchor schedules", err)
	}
	anchorschedule.Sort(schedules)
	return schedules, nil
}

func (s *Store) ClaimSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, nowUnixN, leaseUntilUnixN int64, leaseOwner, leaseToken string) (model.STHAnchorAttempt, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorAttempt{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore claim sth anchor attempt canceled", err)
	}
	if err := anchorschedule.ValidateKey(key); err != nil {
		return model.STHAnchorAttempt{}, false, err
	}

	s.anchorScheduleMu.Lock()
	defer s.anchorScheduleMu.Unlock()

	current, found, err := s.readSTHAnchorSchedule(key)
	if err != nil {
		return model.STHAnchorAttempt{}, false, err
	}
	if !found {
		return model.STHAnchorAttempt{}, false, nil
	}
	reconciled := false
	if current.InFlight != nil {
		resultKey := model.STHAnchorResultKey{NodeID: key.NodeID, LogID: key.LogID, SinkName: key.SinkName, TreeSize: current.InFlight.Target.TreeSize}
		result, resultFound, err := s.readSTHAnchorResult(resultKey)
		if err != nil {
			return model.STHAnchorAttempt{}, false, err
		}
		if resultFound {
			if err := validateStoredSTHAnchorResult(result); err != nil {
				return model.STHAnchorAttempt{}, false, err
			}
			current, reconciled, err = anchorschedule.ReconcileCompleted(current, result)
			if err != nil {
				return model.STHAnchorAttempt{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "reconcile completed sth anchor attempt", err)
			}
		}
	}
	next, attempt, claimed, err := anchorschedule.Claim(current, nowUnixN, leaseUntilUnixN, leaseOwner, leaseToken)
	if err != nil {
		return model.STHAnchorAttempt{}, false, err
	}
	if !claimed {
		if reconciled {
			if err := s.commitSTHAnchorSchedule(current, "commit reconciled sth anchor attempt"); err != nil {
				return model.STHAnchorAttempt{}, false, err
			}
		}
		return model.STHAnchorAttempt{}, false, nil
	}
	if err := s.commitSTHAnchorSchedule(next, "commit claimed sth anchor attempt"); err != nil {
		return model.STHAnchorAttempt{}, false, err
	}
	return attempt, true, nil
}

func (s *Store) RescheduleSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, generation uint64, leaseToken string, attempts int, nextAttemptUnixN int64, lastErrorMessage string) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore reschedule sth anchor attempt canceled", err)
	}
	if err := anchorschedule.ValidateKey(key); err != nil {
		return err
	}

	s.anchorScheduleMu.Lock()
	defer s.anchorScheduleMu.Unlock()

	current, found, err := s.readSTHAnchorSchedule(key)
	if err != nil {
		return err
	}
	if !found {
		return trusterr.New(trusterr.CodeNotFound, "sth anchor schedule not found")
	}
	next, err := anchorschedule.Reschedule(current, generation, leaseToken, attempts, nextAttemptUnixN, lastErrorMessage)
	if err != nil {
		return err
	}
	return s.commitSTHAnchorSchedule(next, "commit rescheduled sth anchor attempt")
}

func (s *Store) FailSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, generation uint64, leaseToken string, attempts int, lastErrorMessage string) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore fail sth anchor attempt canceled", err)
	}
	if err := anchorschedule.ValidateKey(key); err != nil {
		return err
	}

	s.anchorScheduleMu.Lock()
	defer s.anchorScheduleMu.Unlock()

	current, found, err := s.readSTHAnchorSchedule(key)
	if err != nil {
		return err
	}
	if !found {
		return trusterr.New(trusterr.CodeNotFound, "sth anchor schedule not found")
	}
	next, err := anchorschedule.Fail(current, generation, leaseToken, attempts, lastErrorMessage)
	if err != nil {
		return err
	}
	return s.commitSTHAnchorSchedule(next, "commit failed sth anchor attempt")
}

func (s *Store) CompleteSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, generation uint64, leaseToken string, result model.STHAnchorResult) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore complete sth anchor attempt canceled", err)
	}
	if err := anchorschedule.ValidateResult(key, result); err != nil {
		return err
	}

	s.anchorScheduleMu.Lock()
	defer s.anchorScheduleMu.Unlock()

	current, scheduleFound, err := s.readSTHAnchorSchedule(key)
	if err != nil {
		return err
	}
	existing, resultFound, err := s.readSTHAnchorResult(anchorschedule.ResultKey(result))
	if err != nil {
		return err
	}
	if resultFound {
		if err := validateStoredSTHAnchorResult(existing); err != nil {
			return err
		}
		if !anchorschedule.SameResultBinding(existing, result) {
			return trusterr.New(trusterr.CodeDataLoss, "stored STH anchor result conflicts with completed attempt")
		}
		if !scheduleFound {
			return nil
		}
		if current.InFlight != nil && current.InFlight.Target.TreeSize != existing.TreeSize {
			return nil
		}
		next, changed, err := anchorschedule.ReconcileCompleted(current, existing)
		if err != nil {
			return err
		}
		if !changed {
			return nil
		}
		return s.commitSTHAnchorSchedule(next, "commit idempotent sth anchor completion")
	}
	if !scheduleFound {
		return trusterr.New(trusterr.CodeNotFound, "sth anchor schedule not found")
	}
	next, err := anchorschedule.Complete(current, generation, leaseToken, result)
	if err != nil {
		return err
	}
	scheduleBytes, err := cborx.Marshal(next)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode sth anchor schedule", err)
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := s.stageSTHAnchorResultLocked(ctx, batch, result, true); err != nil {
		return err
	}
	if err := batch.Set(anchorScheduleKey(next.Key), scheduleBytes, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage completed sth anchor schedule", err)
	}
	if err := batch.Commit(pdb.Sync); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit sth anchor completion", err)
	}
	return nil
}

func (s *Store) PutSTHAnchorSchedule(ctx context.Context, schedule model.STHAnchorSchedule) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore restore sth anchor schedule canceled", err)
	}
	if err := anchorschedule.ValidateSchedule(schedule); err != nil {
		return err
	}
	if schedule.InFlight != nil && (schedule.InFlight.LeaseOwner != "" || schedule.InFlight.LeaseToken != "" || schedule.InFlight.LeaseUntilUnixN != 0) {
		return trusterr.New(trusterr.CodeFailedPrecondition, "restored STH anchor schedule must not retain a process lease")
	}

	s.anchorScheduleMu.Lock()
	defer s.anchorScheduleMu.Unlock()

	existing, found, err := s.readSTHAnchorSchedule(schedule.Key)
	if err != nil {
		return err
	}
	if found {
		if reflect.DeepEqual(existing, schedule) {
			return nil
		}
		return trusterr.New(trusterr.CodeDataLoss, "stored STH anchor schedule conflicts with restore snapshot")
	}
	return s.commitSTHAnchorSchedule(schedule, "commit restored sth anchor schedule")
}

func (s *Store) readSTHAnchorSchedule(key model.STHAnchorScheduleKey) (model.STHAnchorSchedule, bool, error) {
	var schedule model.STHAnchorSchedule
	found, err := s.readCBOR(anchorScheduleKey(key), &schedule)
	if err != nil {
		return model.STHAnchorSchedule{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor schedule", err)
	}
	if !found {
		return model.STHAnchorSchedule{}, false, nil
	}
	if err := anchorschedule.ValidateSchedule(schedule); err != nil {
		return model.STHAnchorSchedule{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "validate stored sth anchor schedule", err)
	}
	if !anchorschedule.SameKey(schedule.Key, key) {
		return model.STHAnchorSchedule{}, false, trusterr.New(trusterr.CodeDataLoss, "stored STH anchor schedule key does not match lookup")
	}
	return schedule, true, nil
}

func (s *Store) readSTHAnchorResult(key model.STHAnchorResultKey) (model.STHAnchorResult, bool, error) {
	var result model.STHAnchorResult
	found, err := s.readCBOR(anchorResultKey(key), &result)
	if err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor result", err)
	}
	if found {
		if err := validateStoredSTHAnchorResult(result); err != nil {
			return model.STHAnchorResult{}, false, err
		}
		if !anchorschedule.SameResultKey(anchorschedule.ResultKey(result), key) {
			return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeDataLoss, "stored STH anchor result key does not match item")
		}
	}
	return result, found, nil
}

func validateStoredSTHAnchorResult(result model.STHAnchorResult) error {
	key := model.STHAnchorScheduleKey{NodeID: result.NodeID, LogID: result.LogID, SinkName: result.SinkName}
	if err := anchorschedule.ValidateResult(key, result); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "validate stored sth anchor result", err)
	}
	return nil
}

func decodePebbleSTHAnchorResult(storageKey, value []byte) (model.STHAnchorResult, error) {
	var result model.STHAnchorResult
	if err := cborx.UnmarshalLimit(value, &result, maxStoredObjectBytes); err != nil {
		return model.STHAnchorResult{}, trusterr.Wrap(trusterr.CodeDataLoss, "decode sth anchor result", err)
	}
	if err := validateStoredSTHAnchorResult(result); err != nil {
		return model.STHAnchorResult{}, err
	}
	if !bytes.Equal(storageKey, anchorResultKey(anchorschedule.ResultKey(result))) {
		return model.STHAnchorResult{}, trusterr.New(trusterr.CodeDataLoss, "sth anchor result key does not match item")
	}
	return result, nil
}

func (s *Store) latestSTHAnchorResultForKey(ctx context.Context, key model.STHAnchorScheduleKey) (*model.STHAnchorResult, error) {
	result, found, err := s.latestSTHAnchorResultLocked(ctx, &key)
	if err != nil || !found {
		return nil, err
	}
	return &result, nil
}

func (s *Store) latestSTHAnchorResultLocked(ctx context.Context, stream *model.STHAnchorScheduleKey) (model.STHAnchorResult, bool, error) {
	storageKey := []byte(anchorLatestAllKey)
	if stream != nil {
		storageKey = anchorLatestKey(*stream)
	}
	var ref model.STHAnchorLatestReference
	found, err := s.readCBOR(storageKey, &ref)
	if err == nil && found && anchorschedule.ValidateLatestReference(ref) == nil {
		result, resultFound, readErr := s.readSTHAnchorResult(ref.Key)
		if readErr == nil && resultFound && anchorschedule.ReferenceMatchesResult(ref, result) && (stream == nil || anchorschedule.SameKey(*stream, anchorschedule.ScheduleKey(ref.Key))) {
			return result, true, nil
		}
	}
	return s.rebuildLatestSTHAnchorResultLocked(ctx, stream, storageKey)
}

func (s *Store) rebuildLatestSTHAnchorResultLocked(ctx context.Context, stream *model.STHAnchorScheduleKey, storageKey []byte) (model.STHAnchorResult, bool, error) {
	lower, upper := prefixBounds(prefixAnchorResult)
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "open latest sth anchor result iterator", err)
	}
	defer iter.Close()
	for ok := iter.Last(); ok; ok = iter.Prev() {
		if err := ctx.Err(); err != nil {
			return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore find latest sth anchor result canceled", err)
		}
		result, err := decodePebbleSTHAnchorResult(iter.Key(), iter.Value())
		if err != nil {
			return model.STHAnchorResult{}, false, err
		}
		resultStream := model.STHAnchorScheduleKey{NodeID: result.NodeID, LogID: result.LogID, SinkName: result.SinkName}
		if stream != nil && !anchorschedule.SameKey(resultStream, *stream) {
			continue
		}
		data, err := cborx.Marshal(anchorschedule.LatestReference(result))
		if err != nil {
			return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "encode rebuilt latest sth anchor reference", err)
		}
		if err := s.db.Set(storageKey, data, pdb.Sync); err != nil {
			return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "rebuild latest sth anchor reference", err)
		}
		return result, true, nil
	}
	if err := iter.Error(); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "iterate latest sth anchor results", err)
	}
	if err := s.db.Delete(storageKey, pdb.Sync); err != nil && err != pdb.ErrNotFound {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "clear stale latest sth anchor reference", err)
	}
	return model.STHAnchorResult{}, false, nil
}

func (s *Store) stageSTHAnchorResultLocked(ctx context.Context, batch *pdb.Batch, result model.STHAnchorResult, writeResult bool) error {
	if err := s.validateSTHAnchorResultTreeLocked(result); err != nil {
		return err
	}
	if writeResult {
		data, err := cborx.Marshal(result)
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "encode sth anchor result", err)
		}
		if err := batch.Set(anchorResultKey(anchorschedule.ResultKey(result)), data, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor result", err)
		}
	}
	stream := model.STHAnchorScheduleKey{NodeID: result.NodeID, LogID: result.LogID, SinkName: result.SinkName}
	for _, target := range []struct {
		key    []byte
		stream *model.STHAnchorScheduleKey
	}{{key: []byte(anchorLatestAllKey)}, {key: anchorLatestKey(stream), stream: &stream}} {
		latest, found, err := s.latestSTHAnchorResultLocked(ctx, target.stream)
		if err != nil {
			return err
		}
		if found && anchorschedule.CompareResultKeys(anchorschedule.ResultKey(result), anchorschedule.ResultKey(latest)) <= 0 {
			continue
		}
		data, err := cborx.Marshal(anchorschedule.LatestReference(result))
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "encode latest sth anchor reference", err)
		}
		if err := batch.Set(target.key, data, nil); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stage latest sth anchor reference", err)
		}
	}
	return nil
}

func (s *Store) validateSTHAnchorResultTreeLocked(result model.STHAnchorResult) error {
	return s.validateSTHAnchorTreeRootLocked(result.NodeID, result.LogID, result.TreeSize, result.RootHash)
}

func (s *Store) validateSTHAnchorCandidateTreeLocked(candidate model.STHAnchorCandidate) error {
	return s.validateSTHAnchorTreeRootLocked(candidate.Key.NodeID, candidate.Key.LogID, candidate.STH.TreeSize, candidate.STH.RootHash)
}

func (s *Store) validateSTHAnchorTreeRootLocked(nodeID, logID string, treeSize uint64, rootHash []byte) error {
	lower := anchorResultTreePrefix(treeSize)
	upper := append(append([]byte(nil), lower...), 0xff)
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "open same-tree sth anchor result iterator", err)
	}
	defer iter.Close()
	for ok := iter.First(); ok; ok = iter.Next() {
		result, err := decodePebbleSTHAnchorResult(iter.Key(), iter.Value())
		if err != nil {
			return err
		}
		if result.NodeID == nodeID && result.LogID == logID && !bytes.Equal(result.RootHash, rootHash) {
			return trusterr.New(trusterr.CodeDataLoss, "anchor tree size has conflicting root hash")
		}
	}
	if err := iter.Error(); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "iterate same-tree sth anchor results", err)
	}
	return nil
}

func (s *Store) commitSTHAnchorSchedule(schedule model.STHAnchorSchedule, operation string) error {
	data, err := cborx.Marshal(schedule)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "encode sth anchor schedule", err)
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(anchorScheduleKey(schedule.Key), data, nil); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stage sth anchor schedule", err)
	}
	if err := batch.Commit(pdb.Sync); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, operation, err)
	}
	return nil
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

func (s *Store) stageRecordIndexReplace(batch *pdb.Batch, idx, old model.RecordIndex, oldFound bool) error {
	encoded, err := encodeRecordIndexArtifact(idx)
	if err != nil {
		return err
	}
	defer encoded.release()
	return s.stageEncodedRecordIndexReplace(batch, encoded, old, oldFound)
}

func (s *Store) stageEncodedRecordIndexReplace(batch *pdb.Batch, idx encodedRecordIndex, old model.RecordIndex, oldFound bool) error {
	if oldFound {
		if err := visitRecordIndexKeys(old, RecordIndexModeFull, func(key []byte) error {
			if err := batch.Delete(key, nil); err != nil {
				return trusterr.Wrap(trusterr.CodeDataLoss, "stage old record index delete", err)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return s.stageEncodedRecordIndexSet(batch, idx)
}

func (s *Store) stageEncodedRecordIndexSetForMode(batch *pdb.Batch, idx encodedRecordIndex) error {
	if s == nil || s.recordIndexMode == RecordIndexModeFull {
		return s.stageEncodedRecordIndexSet(batch, idx)
	}
	return s.stageEncodedRecordIndexReplaceSame(batch, idx)
}

func (s *Store) stageEncodedRecordIndexReplaceSame(batch *pdb.Batch, idx encodedRecordIndex) error {
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

func (s *Store) stageRecordIndexSet(batch *pdb.Batch, idx model.RecordIndex) error {
	encoded, err := encodeRecordIndexArtifact(idx)
	if err != nil {
		return err
	}
	defer encoded.release()
	return s.stageEncodedRecordIndexSet(batch, encoded)
}

func (s *Store) stageEncodedRecordIndexSet(batch *pdb.Batch, idx encodedRecordIndex) error {
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
	if err := batch.Commit(pdb.Sync); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit global log outbox update", err)
	}
	return nil
}

func (s *Store) promoteBatchRecords(ctx context.Context, batchID, proofLevel string) error {
	if batchID == "" {
		return nil
	}
	prefix := prefixRecordByBatch + recordSecondaryPart(batchID) + "/"
	updates := make([]recordIndexPromotion, 0, 16)
	err := s.scanPrefix(ctx, prefix, func(value []byte) error {
		_, isReference := decodeRecordIndexRef(value)
		idx, err := s.readRecordIndexScanValue(value)
		if err != nil {
			return err
		}
		if model.ProofLevelRank(model.RecordIndexProofLevel(idx)) >= model.ProofLevelRank(proofLevel) {
			return nil
		}
		next := idx
		next.ProofLevel = proofLevel
		updates = append(updates, recordIndexPromotion{old: idx, next: next, replaceAll: !isReference})
		return nil
	})
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "scan batch record indexes", err)
	}
	return s.commitRecordIndexPromotions(ctx, updates)
}

type recordIndexPromotion struct {
	old        model.RecordIndex
	next       model.RecordIndex
	replaceAll bool
}

func (s *Store) stageRecordIndexPromotion(batch *pdb.Batch, promotion recordIndexPromotion) error {
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
		batch := s.db.NewBatch()
		for i := start; i < end; i++ {
			if err := s.stageRecordIndexPromotion(batch, updates[i]); err != nil {
				_ = batch.Close()
				return err
			}
		}
		if err := batch.Commit(pdb.Sync); err != nil {
			_ = batch.Close()
			return trusterr.Wrap(trusterr.CodeDataLoss, "commit promoted record indexes", err)
		}
		if err := batch.Close(); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "close promoted record indexes", err)
		}
	}
	return nil
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
	if err := batch.Commit(pdb.Sync); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "commit sth anchor update", err)
	}
	return nil
}

func (s *Store) scanPrefix(ctx context.Context, prefix string, visit func([]byte) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	lower, upper := prefixBounds(prefix)
	iter, err := s.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
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
