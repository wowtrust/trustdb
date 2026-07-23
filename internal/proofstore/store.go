package proofstore

import (
	"context"
	"io"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

// Store is the unified persistence interface implemented by every proof
// store backend (file-based LocalStore and the Pebble KV backend). It is
// purposefully narrow: read/write proof bundles, write batch roots and
// their manifests, and maintain a single WAL checkpoint pointer. Any
// backend that satisfies this interface can be plugged into the serve
// command via the proofstore factory.
//
// Close is part of the interface so a caller that opened the store via
// the factory can always release resources without introspecting the
// concrete backend; LocalStore returns nil because it owns only a
// directory, while the Pebble backend closes its database handle.
type Store interface {
	PutBundle(ctx context.Context, bundle model.ProofBundle) error
	GetBundle(ctx context.Context, recordID string) (model.ProofBundle, error)
	PutRecordIndex(ctx context.Context, idx model.RecordIndex) error
	GetRecordIndex(ctx context.Context, recordID string) (model.RecordIndex, bool, error)
	ListRecordIndexes(ctx context.Context, opts model.RecordListOptions) ([]model.RecordIndex, error)
	PutRoot(ctx context.Context, root model.BatchRoot) error
	ListRoots(ctx context.Context, limit int) ([]model.BatchRoot, error)
	ListRootsAfter(ctx context.Context, afterClosedAtUnixN int64, limit int) ([]model.BatchRoot, error)
	ListRootsPage(ctx context.Context, opts model.RootListOptions) ([]model.BatchRoot, error)
	LatestRoot(ctx context.Context) (model.BatchRoot, error)
	PutBatchTreeArtifacts(ctx context.Context, leaves []model.BatchTreeLeaf, nodes []model.BatchTreeNode) error
	ListBatchTreeLeaves(ctx context.Context, opts model.BatchTreeLeafListOptions) ([]model.BatchTreeLeaf, error)
	ListBatchTreeNodes(ctx context.Context, opts model.BatchTreeNodeListOptions) ([]model.BatchTreeNode, error)
	PutManifest(ctx context.Context, manifest model.BatchManifest) error
	GetManifest(ctx context.Context, batchID string) (model.BatchManifest, error)
	ListManifests(ctx context.Context) ([]model.BatchManifest, error)
	ListManifestsAfter(ctx context.Context, afterBatchID string, limit int) ([]model.BatchManifest, error)
	PutCheckpoint(ctx context.Context, cp model.WALCheckpoint) error
	GetCheckpoint(ctx context.Context) (model.WALCheckpoint, bool, error)

	PutGlobalLeaf(ctx context.Context, leaf model.GlobalLogLeaf) error
	GetGlobalLeaf(ctx context.Context, index uint64) (model.GlobalLogLeaf, bool, error)
	GetGlobalLeafByBatchID(ctx context.Context, batchID string) (model.GlobalLogLeaf, bool, error)
	ListGlobalLeaves(ctx context.Context) ([]model.GlobalLogLeaf, error)
	ListGlobalLeavesRange(ctx context.Context, startIndex uint64, limit int) ([]model.GlobalLogLeaf, error)
	ListGlobalLeavesPage(ctx context.Context, opts model.GlobalLeafListOptions) ([]model.GlobalLogLeaf, error)
	PutGlobalLogNode(ctx context.Context, node model.GlobalLogNode) error
	GetGlobalLogNode(ctx context.Context, level, startIndex uint64) (model.GlobalLogNode, bool, error)
	// ListGlobalLogNodesAfter returns nodes in (level,start_index) order.
	// Pass ^uint64(0), ^uint64(0) as the initial cursor to include the
	// first possible node at (0,0).
	ListGlobalLogNodesAfter(ctx context.Context, afterLevel, afterStartIndex uint64, limit int) ([]model.GlobalLogNode, error)
	PutGlobalLogState(ctx context.Context, state model.GlobalLogState) error
	GetGlobalLogState(ctx context.Context) (model.GlobalLogState, bool, error)
	PutSignedTreeHead(ctx context.Context, sth model.SignedTreeHead) error
	GetSignedTreeHead(ctx context.Context, treeSize uint64) (model.SignedTreeHead, bool, error)
	ListSignedTreeHeadsAfter(ctx context.Context, afterTreeSize uint64, limit int) ([]model.SignedTreeHead, error)
	ListSignedTreeHeadsPage(ctx context.Context, opts model.TreeHeadListOptions) ([]model.SignedTreeHead, error)
	LatestSignedTreeHead(ctx context.Context) (model.SignedTreeHead, bool, error)
	PutGlobalLogTile(ctx context.Context, tile model.GlobalLogTile) error
	ListGlobalLogTiles(ctx context.Context) ([]model.GlobalLogTile, error)
	// ListGlobalLogTilesAfter follows the same cursor convention as
	// ListGlobalLogNodesAfter.
	ListGlobalLogTilesAfter(ctx context.Context, afterLevel, afterStartIndex uint64, limit int) ([]model.GlobalLogTile, error)
	// CommitGlobalLogAppend persists one complete Global Log append as a
	// single semantic unit. Backends with transaction support should commit
	// leaf indexes, subtree nodes, latest state, and STH atomically.
	CommitGlobalLogAppend(ctx context.Context, entry model.GlobalLogAppend) error

	// Global-log append outbox. Batch commit writes these items durably; a
	// separate worker appends them to the global transparency log and merges
	// the newest STH into the constant-space anchor scheduler.
	EnqueueGlobalLog(ctx context.Context, item model.GlobalLogOutboxItem) error
	ListPendingGlobalLog(ctx context.Context, nowUnixN int64, limit int) ([]model.GlobalLogOutboxItem, error)
	// ListPendingGlobalLogForStream returns only work owned by one Global Log
	// identity. Anchored workers use this scoped form so a shared proofstore
	// cannot hand one log's durable outbox item to another log's signer.
	ListPendingGlobalLogForStream(ctx context.Context, nodeID, logID string, nowUnixN int64, limit int) ([]model.GlobalLogOutboxItem, error)
	ListGlobalLogOutboxItemsAfter(ctx context.Context, afterBatchID string, limit int) ([]model.GlobalLogOutboxItem, error)
	GetGlobalLogOutboxItem(ctx context.Context, batchID string) (model.GlobalLogOutboxItem, bool, error)
	MarkGlobalLogPublished(ctx context.Context, batchID string, sth model.SignedTreeHead) error
	RescheduleGlobalLog(ctx context.Context, batchID string, attempts int, nextAttemptUnixN int64, lastErrorMessage string) error

	// Successful anchor evidence is immutable by cryptographic binding. The
	// legacy per-STH mutable queue is deliberately not part of Store.
	GetSTHAnchorResult(ctx context.Context, treeSize uint64) (model.STHAnchorResult, bool, error)

	io.Closer
}

// Compile-time assertions that the known backends satisfy Store. Both
// value and pointer receivers on LocalStore resolve through the method
// set of the pointer, so we pin the pointer form here.
var _ Store = (*LocalStore)(nil)
var _ GlobalLogPublishedBatchWithAnchorCandidateMarker = (*LocalStore)(nil)

// CryptoSuiteBindingReader exposes the immutable suite selected when the
// namespace marker was validated at open time. Backup and migration paths use
// this capability to reject cross-suite copies before writing any data.
type CryptoSuiteBindingReader interface {
	CryptoSuite() cryptosuite.ID
}

func BoundCryptoSuite(store any) (cryptosuite.ID, error) {
	reader, ok := store.(CryptoSuiteBindingReader)
	if !ok {
		return "", trusterr.New(trusterr.CodeFailedPrecondition, "proofstore does not expose a cryptographic suite binding")
	}
	suiteID := reader.CryptoSuite()
	if _, err := cryptosuite.RequireKnown(suiteID); err != nil {
		return "", trusterr.Wrap(trusterr.CodeDataLoss, "proofstore exposes an invalid cryptographic suite binding", err)
	}
	return suiteID, nil
}

// WALCheckpointPruneSafety is an optional capability for stores that can make
// a local WAL checkpoint safe to trust after a crash. Returning true certifies
// all committed batch artifacts and restart-idempotency decisions become
// durable before the checkpoint, and that the checkpoint is scoped to the
// same node-local WAL. Stores that do not implement this interface fail closed:
// replay scans retained WAL and batch commits never invoke automatic pruning.
type WALCheckpointPruneSafety interface {
	WALCheckpointPruneSafe() bool
}

// WALCheckpointPruneGuard keeps a verified local checkpoint current while its
// caller removes WAL segments. Invalidating manifest writes must wait until
// the callback returns, so they cannot race a previously queued prune.
type WALCheckpointPruneGuard interface {
	WithWALCheckpointPruneGuard(context.Context, model.WALCheckpoint, func() error) (bool, error)
}

// WALCheckpointPruneSafe deliberately defaults to false for wrappers and new
// backends. Opting in without satisfying the durability and scoping contract
// can turn a recovery optimization into permanent data loss.
func WALCheckpointPruneSafe(store any) bool {
	capability, ok := store.(WALCheckpointPruneSafety)
	return ok && capability.WALCheckpointPruneSafe()
}

// IdempotencyDecisionReader resolves one committed ingest decision without a
// scan. Backends that do not implement it must retain and replay their WAL.
type IdempotencyDecisionReader interface {
	GetIdempotencyDecision(context.Context, model.IdempotencyIdentity) (model.IdempotencyDecision, bool, error)
}

// CommittedBatchIdempotencyPublisher atomically publishes a committed
// manifest and the keyed decisions owned by that batch. A checkpoint must not
// advance between those two visibility changes.
type CommittedBatchIdempotencyPublisher interface {
	PublishCommittedBatch(context.Context, model.BatchManifest, []model.ProofBundle) ([]model.IdempotencyDecision, error)
}

// IdempotencyProjectionManager makes the durable point-read projection ready
// before a backend advertises checkpoint/prune safety.
type IdempotencyProjectionManager interface {
	EnsureIdempotencyProjection(context.Context) error
}

// BatchArtifactWriter is an optional fast path for stores that can persist all
// proof bundles, record indexes, and the batch root in chunked transactional
// writes. Callers must still write the prepared/committed manifest around this
// operation; the method only replaces the per-record PutBundle loop.
type BatchArtifactWriter interface {
	PutBatchArtifacts(ctx context.Context, bundles []model.ProofBundle, root model.BatchRoot) error
}

// MaterializedBatchArtifactWriter promotes an already persisted L2 batch to
// L3. Implementations may update only the bundle, primary record index, and
// proof-level secondary index because the prepared batch already owns the
// remaining secondary indexes and root.
type MaterializedBatchArtifactWriter interface {
	PutMaterializedBatchArtifacts(ctx context.Context, bundles []model.ProofBundle) error
}

// BatchIndexRootWriter is an optional fast path for proof modes that expose
// record visibility before full proof bundles are materialized. It persists
// the record index projection and batch root without writing ProofBundle
// payloads.
type BatchIndexRootWriter interface {
	PutBatchIndexesAndRoot(ctx context.Context, indexes []model.RecordIndex, root model.BatchRoot) error
}

// PreparedBatchIndexRootWriter writes a newly planned L2 batch. Unlike the
// generic replacement API, it does not enumerate and delete secondary keys
// that cannot exist yet; recovery may safely replay the same keys.
type PreparedBatchIndexRootWriter interface {
	PutPreparedBatchIndexesAndRoot(ctx context.Context, indexes []model.RecordIndex, root model.BatchRoot) error
}

// BatchTreeSnapshotWriter persists the compact in-memory tree directly,
// avoiding thousands of transient leaf/node projection objects.
type BatchTreeSnapshotWriter interface {
	PutBatchTreeSnapshot(ctx context.Context, snapshot model.BatchTreeSnapshot) error
}

type PreparedManifestLister interface {
	ListPreparedManifests(ctx context.Context, nodeID string, nowUnixN int64, limit int) ([]model.BatchManifest, error)
}

type GlobalLogPublishedBatchMarker interface {
	MarkGlobalLogPublishedBatch(ctx context.Context, batchIDs []string, sths []model.SignedTreeHead) error
}

type GlobalLogPublishedBatchWithAnchorCandidateMarker interface {
	MarkGlobalLogPublishedBatchWithAnchorCandidate(ctx context.Context, batchIDs []string, sths []model.SignedTreeHead, candidate model.STHAnchorCandidate) error
}

// LatestSTHAnchorResultReader provides a bounded lookup for the newest
// successfully published STH anchor. It is optional so wrappers and focused
// test stores do not need to implement the entire anchor read path.
type LatestSTHAnchorResultReader interface {
	LatestSTHAnchorResult(context.Context) (model.STHAnchorResult, bool, error)
}

type STHAnchorResultWriter interface {
	PutSTHAnchorResult(context.Context, model.STHAnchorResult) error
}

// STHAnchorResultUpdater conditionally persists sink-specific proof enrichment
// for an existing immutable result binding. The write succeeds only when the
// stored result still exactly matches expected, preventing concurrent
// OpenTimestamps calendar upgrades from overwriting one another.
type STHAnchorResultUpdater interface {
	UpdateSTHAnchorResult(context.Context, model.STHAnchorResult, model.STHAnchorResult) error
}

type STHAnchorResultKeyedReader interface {
	GetSTHAnchorResultForKey(context.Context, model.STHAnchorResultKey) (model.STHAnchorResult, bool, error)
	LatestSTHAnchorResultForKeyReader
}

type LatestSTHAnchorResultForKeyReader interface {
	LatestSTHAnchorResultForKey(context.Context, model.STHAnchorScheduleKey) (model.STHAnchorResult, bool, error)
}

type STHAnchorResultLister interface {
	ListSTHAnchorResultsAfter(context.Context, model.STHAnchorResultKey, int) ([]model.STHAnchorResult, error)
}

// STHAnchorResultPager performs bounded, direction-aware immutable result
// pagination. Ordered backends must seek directly from the composite cursor;
// transport list requests must not scan the complete anchor history.
type STHAnchorResultPager interface {
	ListSTHAnchorResultsPage(context.Context, model.AnchorListOptions) ([]model.STHAnchorResult, error)
}

// STHAnchorScheduleStore owns the durable constant-space Pending/InFlight
// scheduler state used directly by the runtime anchor worker.
type STHAnchorScheduleStore interface {
	UpsertSTHAnchorCandidate(context.Context, model.STHAnchorCandidate) (model.STHAnchorSchedule, error)
	GetSTHAnchorSchedule(context.Context, model.STHAnchorScheduleKey) (model.STHAnchorSchedule, bool, error)
	ListSTHAnchorSchedules(context.Context) ([]model.STHAnchorSchedule, error)
	ClaimSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, nowUnixN, leaseUntilUnixN int64, leaseOwner, leaseToken string) (model.STHAnchorAttempt, bool, error)
	RescheduleSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, generation uint64, leaseToken string, attempts int, nextAttemptUnixN int64, lastError string) error
	FailSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, generation uint64, leaseToken string, attempts int, lastError string) error
	CompleteSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, generation uint64, leaseToken string, result model.STHAnchorResult) error
}

// STHAnchorScheduleRestorer imports one validated scheduler snapshot from a
// logical backup. Restore callers must clear process-local lease ownership
// before invoking it; normal runtime mutations use STHAnchorScheduleStore.
type STHAnchorScheduleRestorer interface {
	PutSTHAnchorSchedule(context.Context, model.STHAnchorSchedule) error
}

// STHAnchorScheduleReplacer is reserved for explicit offline migration with
// overwrite enabled. Runtime and logical-backup restore use the conflict-
// detecting restorer above.
type STHAnchorScheduleReplacer interface {
	ReplaceSTHAnchorSchedule(context.Context, model.STHAnchorSchedule) error
}

// L5CoverageCheckpointStore persists only the continuous projected prefix.
// The checkpoint is derived from immutable anchor results and Global Log
// leaves, so logical backup deliberately omits it and restore starts at zero.
type L5CoverageCheckpointStore interface {
	GetL5CoverageCheckpoint(context.Context, model.STHAnchorScheduleKey) (model.L5CoverageCheckpoint, bool, error)
	AdvanceL5CoverageCheckpoint(context.Context, model.STHAnchorScheduleKey, uint64, int64) (model.L5CoverageCheckpoint, error)
}

// BatchProofLevelPromoter idempotently raises every record index in a batch
// to the requested level. Implementations must never lower an existing level.
type BatchProofLevelPromoter interface {
	PromoteBatchProofLevel(context.Context, string, string) error
}
