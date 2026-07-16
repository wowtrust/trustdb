package proofstore

import (
	"context"
	"io"

	"github.com/ryan-wong-coder/trustdb/internal/model"
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
	// separate worker appends them to the global transparency log and then
	// enqueues STH anchors.
	EnqueueGlobalLog(ctx context.Context, item model.GlobalLogOutboxItem) error
	ListPendingGlobalLog(ctx context.Context, nowUnixN int64, limit int) ([]model.GlobalLogOutboxItem, error)
	ListGlobalLogOutboxItemsAfter(ctx context.Context, afterBatchID string, limit int) ([]model.GlobalLogOutboxItem, error)
	GetGlobalLogOutboxItem(ctx context.Context, batchID string) (model.GlobalLogOutboxItem, bool, error)
	MarkGlobalLogPublished(ctx context.Context, batchID string, sth model.SignedTreeHead) error
	RescheduleGlobalLog(ctx context.Context, batchID string, attempts int, nextAttemptUnixN int64, lastErrorMessage string) error

	// STH anchor outbox. L5 only publishes SignedTreeHead/global roots;
	// batch roots are never direct anchor targets.
	EnqueueSTHAnchor(ctx context.Context, item model.STHAnchorOutboxItem) error
	ListPendingSTHAnchors(ctx context.Context, nowUnixN int64, limit int) ([]model.STHAnchorOutboxItem, error)
	ListPublishedSTHAnchors(ctx context.Context, limit int) ([]model.STHAnchorOutboxItem, error)
	ListSTHAnchorOutboxItemsAfter(ctx context.Context, afterTreeSize uint64, limit int) ([]model.STHAnchorOutboxItem, error)
	ListSTHAnchorsPage(ctx context.Context, opts model.AnchorListOptions) ([]model.STHAnchorOutboxItem, error)
	GetSTHAnchorOutboxItem(ctx context.Context, treeSize uint64) (model.STHAnchorOutboxItem, bool, error)
	RescheduleSTHAnchor(ctx context.Context, treeSize uint64, attempts int, nextAttemptUnixN int64, lastErrorMessage string) error
	MarkSTHAnchorPublished(ctx context.Context, result model.STHAnchorResult) error
	MarkSTHAnchorFailed(ctx context.Context, treeSize uint64, lastErrorMessage string) error
	GetSTHAnchorResult(ctx context.Context, treeSize uint64) (model.STHAnchorResult, bool, error)

	io.Closer
}

// Compile-time assertions that the known backends satisfy Store. Both
// value and pointer receivers on LocalStore resolve through the method
// set of the pointer, so we pin the pointer form here.
var _ Store = (*LocalStore)(nil)

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
