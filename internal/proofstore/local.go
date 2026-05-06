package proofstore

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

const maxStoredObjectBytes = 64 << 20

type LocalStore struct {
	Root string
}

func (s LocalStore) PutBundle(ctx context.Context, bundle model.ProofBundle) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put bundle canceled", err)
	}
	if bundle.RecordID == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "proof bundle record_id is required")
	}
	path := filepath.Join(s.bundleDir(), safeFileName(bundle.RecordID)+".tdproof")
	if err := writeCBORAtomic(path, bundle); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write proof bundle", err)
	}
	if err := s.PutRecordIndex(ctx, model.RecordIndexFromBundle(bundle)); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write record index", err)
	}
	return nil
}

func (s LocalStore) PutRecordIndex(ctx context.Context, idx model.RecordIndex) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put record index canceled", err)
	}
	if idx.RecordID == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "record index record_id is required")
	}
	var old model.RecordIndex
	oldFound := false
	if existing, ok, err := s.GetRecordIndex(ctx, idx.RecordID); err != nil {
		return err
	} else if ok {
		old = existing
		oldFound = true
	}
	idx.ProofLevel = model.RecordIndexProofLevel(idx)
	if err := s.writeRecordIndex(idx); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write record index", err)
	}
	if oldFound {
		s.removeRecordIndexSecondary(old, idx)
	}
	return nil
}

func (s LocalStore) GetBundle(ctx context.Context, recordID string) (model.ProofBundle, error) {
	if err := ctx.Err(); err != nil {
		return model.ProofBundle{}, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get bundle canceled", err)
	}
	if recordID == "" {
		return model.ProofBundle{}, trusterr.New(trusterr.CodeInvalidArgument, "record_id is required")
	}
	path := filepath.Join(s.bundleDir(), safeFileName(recordID)+".tdproof")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return model.ProofBundle{}, trusterr.Wrap(trusterr.CodeNotFound, "proof bundle not found", err)
		}
		return model.ProofBundle{}, trusterr.Wrap(trusterr.CodeDataLoss, "read proof bundle", err)
	}
	var bundle model.ProofBundle
	if err := cborx.UnmarshalLimit(data, &bundle, maxStoredObjectBytes); err != nil {
		return model.ProofBundle{}, trusterr.Wrap(trusterr.CodeDataLoss, "decode proof bundle", err)
	}
	return bundle, nil
}

func (s LocalStore) GetRecordIndex(ctx context.Context, recordID string) (model.RecordIndex, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.RecordIndex{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get record index canceled", err)
	}
	if recordID == "" {
		return model.RecordIndex{}, false, trusterr.New(trusterr.CodeInvalidArgument, "record_id is required")
	}
	data, err := os.ReadFile(s.recordByIDPath(recordID))
	if err != nil {
		if os.IsNotExist(err) {
			return model.RecordIndex{}, false, nil
		}
		return model.RecordIndex{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read record index", err)
	}
	var idx model.RecordIndex
	if err := cborx.UnmarshalLimit(data, &idx, maxStoredObjectBytes); err != nil {
		return model.RecordIndex{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode record index", err)
	}
	return idx, true, nil
}

func (s LocalStore) ListRecordIndexes(ctx context.Context, opts model.RecordListOptions) ([]model.RecordIndex, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list record indexes canceled", err)
	}
	limit := normaliseRecordLimit(opts.Limit)
	dir := s.recordByTimeDir()
	switch {
	case len(opts.ContentHash) > 0:
		dir = s.recordByContentDir(opts.ContentHash)
	case model.RecordStorageQueryToken(opts.Query) != "":
		dir = s.recordByStorageTokenDir(model.RecordStorageQueryToken(opts.Query))
	case opts.BatchID != "":
		dir = s.recordByBatchDir(opts.BatchID)
	case opts.ProofLevel != "":
		dir = s.recordByProofLevelDir(opts.ProofLevel)
	case opts.TenantID != "":
		dir = s.recordByTenantDir(opts.TenantID)
	case opts.ClientID != "":
		dir = s.recordByClientDir(opts.ClientID)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read record index directory", err)
	}
	indexes := make([]model.RecordIndex, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdrecord") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list record indexes canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read record index", err)
		}
		var idx model.RecordIndex
		if err := cborx.UnmarshalLimit(data, &idx, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode record index", err)
		}
		if !model.RecordIndexMatchesListOptions(idx, opts) || !model.RecordIndexAfterCursor(idx, opts) {
			continue
		}
		indexes = append(indexes, idx)
	}
	sortRecordIndexes(indexes, opts.Direction)
	if len(indexes) > limit {
		indexes = indexes[:limit]
	}
	return indexes, nil
}

func (s LocalStore) PutRoot(ctx context.Context, root model.BatchRoot) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put root canceled", err)
	}
	if root.BatchID == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "batch root batch_id is required")
	}
	if root.SchemaVersion == "" {
		root.SchemaVersion = model.SchemaBatchRoot
	}
	if root.ClosedAtUnixN == 0 {
		root.ClosedAtUnixN = time.Now().UTC().UnixNano()
	}
	name := fmt.Sprintf("%020d_%s.tdroot", root.ClosedAtUnixN, safeFileName(root.BatchID))
	path := filepath.Join(s.rootDir(), name)
	if err := writeCBORAtomic(path, root); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write batch root", err)
	}
	return nil
}

func (s LocalStore) ListRoots(ctx context.Context, limit int) ([]model.BatchRoot, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list roots canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	entries, err := os.ReadDir(s.rootDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read root directory", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdroot") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if len(names) > limit {
		names = names[:limit]
	}
	roots := make([]model.BatchRoot, 0, len(names))
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list roots canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(s.rootDir(), name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read batch root", err)
		}
		var root model.BatchRoot
		if err := cborx.UnmarshalLimit(data, &root, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch root", err)
		}
		roots = append(roots, root)
	}
	return roots, nil
}

func (s LocalStore) ListRootsAfter(ctx context.Context, afterClosedAtUnixN int64, limit int) ([]model.BatchRoot, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list roots after canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	entries, err := os.ReadDir(s.rootDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read root directory", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdroot") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	roots := make([]model.BatchRoot, 0, limit)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list roots after canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(s.rootDir(), name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read batch root", err)
		}
		var root model.BatchRoot
		if err := cborx.UnmarshalLimit(data, &root, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch root", err)
		}
		if root.ClosedAtUnixN <= afterClosedAtUnixN {
			continue
		}
		roots = append(roots, root)
		if len(roots) >= limit {
			break
		}
	}
	return roots, nil
}

func (s LocalStore) ListRootsPage(ctx context.Context, opts model.RootListOptions) ([]model.BatchRoot, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list roots page canceled", err)
	}
	limit := normaliseRecordLimit(opts.Limit)
	entries, err := os.ReadDir(s.rootDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read root directory", err)
	}
	roots := make([]model.BatchRoot, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdroot") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list roots page canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(s.rootDir(), entry.Name()))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read batch root", err)
		}
		var root model.BatchRoot
		if err := cborx.UnmarshalLimit(data, &root, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch root", err)
		}
		if !model.BatchRootAfterCursor(root, opts) {
			continue
		}
		roots = append(roots, root)
	}
	sortBatchRoots(roots, opts.Direction)
	if len(roots) > limit {
		roots = roots[:limit]
	}
	return roots, nil
}

func (s LocalStore) LatestRoot(ctx context.Context) (model.BatchRoot, error) {
	roots, err := s.ListRoots(ctx, 1)
	if err != nil {
		return model.BatchRoot{}, err
	}
	if len(roots) == 0 {
		return model.BatchRoot{}, trusterr.New(trusterr.CodeNotFound, "batch root not found")
	}
	return roots[0], nil
}

func (s LocalStore) PutBatchTreeArtifacts(ctx context.Context, leaves []model.BatchTreeLeaf, nodes []model.BatchTreeNode) error {
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
	normalizedLeaves := make([]model.BatchTreeLeaf, len(leaves))
	for i := range leaves {
		if err := ctx.Err(); err != nil {
			return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put batch tree artifacts canceled", err)
		}
		leaf := leaves[i]
		if leaf.BatchID != batchID {
			return trusterr.New(trusterr.CodeInvalidArgument, "batch tree leaves must share batch_id")
		}
		if leaf.SchemaVersion == "" {
			leaf.SchemaVersion = model.SchemaBatchTreeLeaf
		}
		if leaf.CreatedAtUnixN == 0 {
			leaf.CreatedAtUnixN = now
		}
		normalizedLeaves[i] = leaf
	}
	normalizedNodes := make([]model.BatchTreeNode, len(nodes))
	for i := range nodes {
		if err := ctx.Err(); err != nil {
			return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put batch tree artifacts canceled", err)
		}
		node := nodes[i]
		if node.BatchID != batchID {
			return trusterr.New(trusterr.CodeInvalidArgument, "batch tree nodes must share batch_id")
		}
		if node.Width == 0 {
			return trusterr.New(trusterr.CodeInvalidArgument, "batch tree node width is required")
		}
		if node.SchemaVersion == "" {
			node.SchemaVersion = model.SchemaBatchTreeNode
		}
		if node.CreatedAtUnixN == 0 {
			node.CreatedAtUnixN = now
		}
		normalizedNodes[i] = node
	}
	// LocalStore cannot make this multi-file artifact fully atomic. Write
	// internal nodes first and leaves last so a visible leaf is a better
	// signal that the tree projection is ready for readers.
	for i := range normalizedNodes {
		node := normalizedNodes[i]
		if err := writeCBORAtomic(s.batchTreeNodePath(node.BatchID, node.Level, node.StartIndex), node); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "write batch tree node", err)
		}
	}
	for i := range normalizedLeaves {
		leaf := normalizedLeaves[i]
		if err := writeCBORAtomic(s.batchTreeLeafPath(leaf.BatchID, leaf.LeafIndex), leaf); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "write batch tree leaf", err)
		}
	}
	return nil
}

func (s LocalStore) ListBatchTreeLeaves(ctx context.Context, opts model.BatchTreeLeafListOptions) ([]model.BatchTreeLeaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list batch tree leaves canceled", err)
	}
	if opts.BatchID == "" {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "batch_id is required")
	}
	limit := normaliseRecordLimit(opts.Limit)
	entries, err := os.ReadDir(s.batchTreeLeafDir(opts.BatchID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read batch tree leaf directory", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdbtleaf") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	leaves := make([]model.BatchTreeLeaf, 0, limit)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list batch tree leaves canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(s.batchTreeLeafDir(opts.BatchID), name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read batch tree leaf", err)
		}
		var leaf model.BatchTreeLeaf
		if err := cborx.UnmarshalLimit(data, &leaf, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch tree leaf", err)
		}
		if opts.HasAfter && leaf.LeafIndex <= opts.AfterLeafIndex {
			continue
		}
		leaves = append(leaves, leaf)
		if len(leaves) >= limit {
			break
		}
	}
	return leaves, nil
}

func (s LocalStore) ListBatchTreeNodes(ctx context.Context, opts model.BatchTreeNodeListOptions) ([]model.BatchTreeNode, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list batch tree nodes canceled", err)
	}
	if opts.BatchID == "" {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "batch_id is required")
	}
	limit := normaliseRecordLimit(opts.Limit)
	entries, err := os.ReadDir(s.batchTreeNodeLevelDir(opts.BatchID, opts.Level))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read batch tree node directory", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdbtnode") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	nodes := make([]model.BatchTreeNode, 0, limit)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list batch tree nodes canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(s.batchTreeNodeLevelDir(opts.BatchID, opts.Level), name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read batch tree node", err)
		}
		var node model.BatchTreeNode
		if err := cborx.UnmarshalLimit(data, &node, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch tree node", err)
		}
		if node.StartIndex < opts.StartIndex {
			continue
		}
		if opts.HasAfter && node.StartIndex <= opts.AfterStartIndex {
			continue
		}
		nodes = append(nodes, node)
		if len(nodes) >= limit {
			break
		}
	}
	return nodes, nil
}

func (s LocalStore) PutManifest(ctx context.Context, manifest model.BatchManifest) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put manifest canceled", err)
	}
	if manifest.BatchID == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "batch manifest batch_id is required")
	}
	if manifest.State != model.BatchStatePrepared && manifest.State != model.BatchStateCommitted {
		return trusterr.New(trusterr.CodeInvalidArgument, "batch manifest state must be prepared or committed")
	}
	if manifest.SchemaVersion == "" {
		manifest.SchemaVersion = model.SchemaBatchManifest
	}
	path := filepath.Join(s.manifestDir(), safeFileName(manifest.BatchID)+".tdmanifest")
	if err := writeCBORAtomic(path, manifest); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write batch manifest", err)
	}
	return nil
}

func (s LocalStore) GetManifest(ctx context.Context, batchID string) (model.BatchManifest, error) {
	if err := ctx.Err(); err != nil {
		return model.BatchManifest{}, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get manifest canceled", err)
	}
	if batchID == "" {
		return model.BatchManifest{}, trusterr.New(trusterr.CodeInvalidArgument, "batch_id is required")
	}
	path := filepath.Join(s.manifestDir(), safeFileName(batchID)+".tdmanifest")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return model.BatchManifest{}, trusterr.Wrap(trusterr.CodeNotFound, "batch manifest not found", err)
		}
		return model.BatchManifest{}, trusterr.Wrap(trusterr.CodeDataLoss, "read batch manifest", err)
	}
	var manifest model.BatchManifest
	if err := cborx.UnmarshalLimit(data, &manifest, maxStoredObjectBytes); err != nil {
		return model.BatchManifest{}, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch manifest", err)
	}
	return manifest, nil
}

func (s LocalStore) ListManifests(ctx context.Context) ([]model.BatchManifest, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list manifests canceled", err)
	}
	entries, err := os.ReadDir(s.manifestDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read manifest directory", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdmanifest") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	manifests := make([]model.BatchManifest, 0, len(names))
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list manifests canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(s.manifestDir(), name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read batch manifest", err)
		}
		var manifest model.BatchManifest
		if err := cborx.UnmarshalLimit(data, &manifest, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch manifest", err)
		}
		manifests = append(manifests, manifest)
	}
	return manifests, nil
}

func (s LocalStore) ListManifestsAfter(ctx context.Context, afterBatchID string, limit int) ([]model.BatchManifest, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list manifests after canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	entries, err := os.ReadDir(s.manifestDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read manifest directory", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdmanifest") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	manifests := make([]model.BatchManifest, 0, limit)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list manifests after canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(s.manifestDir(), name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read batch manifest", err)
		}
		var manifest model.BatchManifest
		if err := cborx.UnmarshalLimit(data, &manifest, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch manifest", err)
		}
		if manifest.BatchID <= afterBatchID {
			continue
		}
		manifests = append(manifests, manifest)
		if len(manifests) >= limit {
			break
		}
	}
	return manifests, nil
}

// PutCheckpoint atomically persists the WAL checkpoint. The checkpoint is a
// single-file pointer living alongside manifests in the proof store; replays
// read it on startup to skip records that are already covered by a committed
// batch. Callers should only ever advance the checkpoint monotonically (see
// batch.Service.advanceCheckpoint) but the store itself does not enforce
// ordering, which keeps this method a simple idempotent write.
func (s LocalStore) PutCheckpoint(ctx context.Context, cp model.WALCheckpoint) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put checkpoint canceled", err)
	}
	if cp.SchemaVersion == "" {
		cp.SchemaVersion = model.SchemaWALCheckpoint
	}
	if cp.RecordedAtUnixN == 0 {
		cp.RecordedAtUnixN = time.Now().UTC().UnixNano()
	}
	if err := writeCBORAtomic(s.checkpointPath(), cp); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write wal checkpoint", err)
	}
	return nil
}

// GetCheckpoint loads the persisted WAL checkpoint. The found return value
// is false when no checkpoint has ever been written; callers must fall back
// to scanning the full WAL in that case. A missing checkpoint is never an
// error because replay correctness does not depend on it.
func (s LocalStore) GetCheckpoint(ctx context.Context) (model.WALCheckpoint, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.WALCheckpoint{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get checkpoint canceled", err)
	}
	data, err := os.ReadFile(s.checkpointPath())
	if err != nil {
		if os.IsNotExist(err) {
			return model.WALCheckpoint{}, false, nil
		}
		return model.WALCheckpoint{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read wal checkpoint", err)
	}
	var cp model.WALCheckpoint
	if err := cborx.UnmarshalLimit(data, &cp, maxStoredObjectBytes); err != nil {
		return model.WALCheckpoint{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode wal checkpoint", err)
	}
	return cp, true, nil
}

// Close is a no-op for the file-backed store because it owns only a
// directory handle via stdlib os calls, but the method exists so
// LocalStore can satisfy the Store interface alongside backends (e.g.
// Pebble) that require explicit teardown.
func (s LocalStore) Close() error {
	return nil
}

func (s LocalStore) PutGlobalLeaf(ctx context.Context, leaf model.GlobalLogLeaf) error {
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
	if err := writeCBORAtomic(s.globalLeafPath(leaf.LeafIndex), leaf); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write global log leaf", err)
	}
	if err := writeCBORAtomic(s.globalLeafByBatchPath(leaf.BatchID), leaf); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write global log batch index", err)
	}
	return nil
}

func (s LocalStore) GetGlobalLeaf(ctx context.Context, index uint64) (model.GlobalLogLeaf, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.GlobalLogLeaf{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get global leaf canceled", err)
	}
	data, err := os.ReadFile(s.globalLeafPath(index))
	if err != nil {
		if os.IsNotExist(err) {
			return model.GlobalLogLeaf{}, false, nil
		}
		return model.GlobalLogLeaf{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read global log leaf", err)
	}
	var leaf model.GlobalLogLeaf
	if err := cborx.UnmarshalLimit(data, &leaf, maxStoredObjectBytes); err != nil {
		return model.GlobalLogLeaf{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log leaf", err)
	}
	return leaf, true, nil
}

func (s LocalStore) GetGlobalLeafByBatchID(ctx context.Context, batchID string) (model.GlobalLogLeaf, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.GlobalLogLeaf{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get global leaf by batch canceled", err)
	}
	if batchID == "" {
		return model.GlobalLogLeaf{}, false, trusterr.New(trusterr.CodeInvalidArgument, "batch_id is required")
	}
	data, err := os.ReadFile(s.globalLeafByBatchPath(batchID))
	if err != nil {
		if os.IsNotExist(err) {
			return model.GlobalLogLeaf{}, false, nil
		}
		return model.GlobalLogLeaf{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read global log batch index", err)
	}
	var leaf model.GlobalLogLeaf
	if err := cborx.UnmarshalLimit(data, &leaf, maxStoredObjectBytes); err != nil {
		return model.GlobalLogLeaf{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log batch index", err)
	}
	return leaf, true, nil
}

func (s LocalStore) PutGlobalLogNode(ctx context.Context, node model.GlobalLogNode) error {
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
	if err := writeCBORAtomic(s.globalNodePath(node.Level, node.StartIndex), node); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write global log node", err)
	}
	return nil
}

func (s LocalStore) GetGlobalLogNode(ctx context.Context, level, startIndex uint64) (model.GlobalLogNode, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.GlobalLogNode{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get global node canceled", err)
	}
	data, err := os.ReadFile(s.globalNodePath(level, startIndex))
	if err != nil {
		if os.IsNotExist(err) {
			return model.GlobalLogNode{}, false, nil
		}
		return model.GlobalLogNode{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read global log node", err)
	}
	var node model.GlobalLogNode
	if err := cborx.UnmarshalLimit(data, &node, maxStoredObjectBytes); err != nil {
		return model.GlobalLogNode{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log node", err)
	}
	return node, true, nil
}

func (s LocalStore) ListGlobalLogNodesAfter(ctx context.Context, afterLevel, afterStartIndex uint64, limit int) ([]model.GlobalLogNode, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global nodes after canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	entries, err := os.ReadDir(s.globalNodeDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global node directory", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdgnode") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	nodes := make([]model.GlobalLogNode, 0, limit)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global nodes after canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(s.globalNodeDir(), name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global log node", err)
		}
		var node model.GlobalLogNode
		if err := cborx.UnmarshalLimit(data, &node, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log node", err)
		}
		hasCursor := afterLevel != ^uint64(0) || afterStartIndex != ^uint64(0)
		if hasCursor && (node.Level < afterLevel || node.Level == afterLevel && node.StartIndex <= afterStartIndex) {
			continue
		}
		nodes = append(nodes, node)
		if len(nodes) >= limit {
			break
		}
	}
	return nodes, nil
}

func (s LocalStore) PutGlobalLogState(ctx context.Context, state model.GlobalLogState) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put global state canceled", err)
	}
	if state.SchemaVersion == "" {
		state.SchemaVersion = model.SchemaGlobalLogState
	}
	if state.UpdatedAtUnixN == 0 {
		state.UpdatedAtUnixN = time.Now().UTC().UnixNano()
	}
	if err := writeCBORAtomic(s.globalStatePath(), state); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write global log state", err)
	}
	return nil
}

func (s LocalStore) GetGlobalLogState(ctx context.Context) (model.GlobalLogState, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.GlobalLogState{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get global state canceled", err)
	}
	data, err := os.ReadFile(s.globalStatePath())
	if err != nil {
		if os.IsNotExist(err) {
			return model.GlobalLogState{}, false, nil
		}
		return model.GlobalLogState{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read global log state", err)
	}
	var state model.GlobalLogState
	if err := cborx.UnmarshalLimit(data, &state, maxStoredObjectBytes); err != nil {
		return model.GlobalLogState{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log state", err)
	}
	return state, true, nil
}

func (s LocalStore) ListGlobalLeaves(ctx context.Context) ([]model.GlobalLogLeaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global leaves canceled", err)
	}
	entries, err := os.ReadDir(s.globalLeafDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global leaf directory", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdgleaf") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	leaves := make([]model.GlobalLogLeaf, 0, len(names))
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(s.globalLeafDir(), name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global log leaf", err)
		}
		var leaf model.GlobalLogLeaf
		if err := cborx.UnmarshalLimit(data, &leaf, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log leaf", err)
		}
		leaves = append(leaves, leaf)
	}
	return leaves, nil
}

func (s LocalStore) ListGlobalLeavesRange(ctx context.Context, startIndex uint64, limit int) ([]model.GlobalLogLeaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global leaves range canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	leaves := make([]model.GlobalLogLeaf, 0, limit)
	for i := startIndex; len(leaves) < limit; i++ {
		leaf, ok, err := s.GetGlobalLeaf(ctx, i)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		leaves = append(leaves, leaf)
	}
	return leaves, nil
}

func (s LocalStore) ListGlobalLeavesPage(ctx context.Context, opts model.GlobalLeafListOptions) ([]model.GlobalLogLeaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global leaves page canceled", err)
	}
	limit := normaliseRecordLimit(opts.Limit)
	entries, err := os.ReadDir(s.globalLeafDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global leaf directory", err)
	}
	leaves := make([]model.GlobalLogLeaf, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdgleaf") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global leaves page canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(s.globalLeafDir(), entry.Name()))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global log leaf", err)
		}
		var leaf model.GlobalLogLeaf
		if err := cborx.UnmarshalLimit(data, &leaf, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log leaf", err)
		}
		if !model.Uint64AfterCursor(leaf.LeafIndex, opts.AfterLeafIndex, opts.Direction) {
			continue
		}
		leaves = append(leaves, leaf)
	}
	sortGlobalLeaves(leaves, opts.Direction)
	if len(leaves) > limit {
		leaves = leaves[:limit]
	}
	return leaves, nil
}

func (s LocalStore) PutSignedTreeHead(ctx context.Context, sth model.SignedTreeHead) error {
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
	if err := writeCBORAtomic(s.sthPath(sth.TreeSize), sth); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write signed tree head", err)
	}
	return nil
}

func (s LocalStore) CommitGlobalLogAppend(ctx context.Context, entry model.GlobalLogAppend) error {
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
	if err := s.PutGlobalLeaf(ctx, entry.Leaf); err != nil {
		return err
	}
	for _, node := range entry.Nodes {
		if err := s.PutGlobalLogNode(ctx, node); err != nil {
			return err
		}
	}
	if err := s.PutGlobalLogState(ctx, entry.State); err != nil {
		return err
	}
	return s.PutSignedTreeHead(ctx, entry.STH)
}

func (s LocalStore) GetSignedTreeHead(ctx context.Context, treeSize uint64) (model.SignedTreeHead, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get sth canceled", err)
	}
	if treeSize == 0 {
		return model.SignedTreeHead{}, false, trusterr.New(trusterr.CodeInvalidArgument, "sth tree_size is required")
	}
	data, err := os.ReadFile(s.sthPath(treeSize))
	if err != nil {
		if os.IsNotExist(err) {
			return model.SignedTreeHead{}, false, nil
		}
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read signed tree head", err)
	}
	var sth model.SignedTreeHead
	if err := cborx.UnmarshalLimit(data, &sth, maxStoredObjectBytes); err != nil {
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode signed tree head", err)
	}
	return sth, true, nil
}

func (s LocalStore) ListSignedTreeHeadsAfter(ctx context.Context, afterTreeSize uint64, limit int) ([]model.SignedTreeHead, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth after canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	out := make([]model.SignedTreeHead, 0, limit)
	for size := afterTreeSize + 1; len(out) < limit; size++ {
		sth, ok, err := s.GetSignedTreeHead(ctx, size)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		out = append(out, sth)
	}
	return out, nil
}

func (s LocalStore) ListSignedTreeHeadsPage(ctx context.Context, opts model.TreeHeadListOptions) ([]model.SignedTreeHead, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list signed tree heads page canceled", err)
	}
	limit := normaliseRecordLimit(opts.Limit)
	entries, err := os.ReadDir(s.sthDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read signed tree head directory", err)
	}
	sths := make([]model.SignedTreeHead, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdsth") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list signed tree heads page canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(s.sthDir(), entry.Name()))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read signed tree head", err)
		}
		var sth model.SignedTreeHead
		if err := cborx.UnmarshalLimit(data, &sth, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode signed tree head", err)
		}
		if !model.Uint64AfterCursor(sth.TreeSize, opts.AfterTreeSize, opts.Direction) {
			continue
		}
		sths = append(sths, sth)
	}
	sortSignedTreeHeads(sths, opts.Direction)
	if len(sths) > limit {
		sths = sths[:limit]
	}
	return sths, nil
}

func (s LocalStore) LatestSignedTreeHead(ctx context.Context) (model.SignedTreeHead, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore latest sth canceled", err)
	}
	entries, err := os.ReadDir(s.sthDir())
	if err != nil {
		if os.IsNotExist(err) {
			return model.SignedTreeHead{}, false, nil
		}
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read sth directory", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdsth") {
			continue
		}
		names = append(names, entry.Name())
	}
	if len(names) == 0 {
		return model.SignedTreeHead{}, false, nil
	}
	sort.Strings(names)
	data, err := os.ReadFile(filepath.Join(s.sthDir(), names[len(names)-1]))
	if err != nil {
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read latest signed tree head", err)
	}
	var sth model.SignedTreeHead
	if err := cborx.UnmarshalLimit(data, &sth, maxStoredObjectBytes); err != nil {
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode latest signed tree head", err)
	}
	return sth, true, nil
}

func (s LocalStore) PutGlobalLogTile(ctx context.Context, tile model.GlobalLogTile) error {
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
	if err := writeCBORAtomic(s.globalTilePath(tile.Level, tile.StartIndex, tile.Width), tile); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write global log tile", err)
	}
	return nil
}

func (s LocalStore) ListGlobalLogTiles(ctx context.Context) ([]model.GlobalLogTile, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global tiles canceled", err)
	}
	entries, err := os.ReadDir(s.globalTileDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global tile directory", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdgtile") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	tiles := make([]model.GlobalLogTile, 0, len(names))
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(s.globalTileDir(), name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global log tile", err)
		}
		var tile model.GlobalLogTile
		if err := cborx.UnmarshalLimit(data, &tile, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log tile", err)
		}
		tiles = append(tiles, tile)
	}
	return tiles, nil
}

func (s LocalStore) ListGlobalLogTilesAfter(ctx context.Context, afterLevel, afterStartIndex uint64, limit int) ([]model.GlobalLogTile, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global tiles after canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	entries, err := os.ReadDir(s.globalTileDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global tile directory", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdgtile") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	tiles := make([]model.GlobalLogTile, 0, limit)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global tiles after canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(s.globalTileDir(), name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global log tile", err)
		}
		var tile model.GlobalLogTile
		if err := cborx.UnmarshalLimit(data, &tile, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log tile", err)
		}
		hasCursor := afterLevel != ^uint64(0) || afterStartIndex != ^uint64(0)
		if hasCursor && (tile.Level < afterLevel || tile.Level == afterLevel && tile.StartIndex <= afterStartIndex) {
			continue
		}
		tiles = append(tiles, tile)
		if len(tiles) >= limit {
			break
		}
	}
	return tiles, nil
}

func (s LocalStore) EnqueueGlobalLog(ctx context.Context, item model.GlobalLogOutboxItem) error {
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
	path := s.globalOutboxPath(item.BatchID)
	if _, err := os.Stat(path); err == nil {
		return trusterr.New(trusterr.CodeAlreadyExists, "global log outbox item already exists")
	} else if !os.IsNotExist(err) {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stat global log outbox item", err)
	}
	if err := writeCBORAtomic(path, item); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write global log outbox item", err)
	}
	return nil
}

func (s LocalStore) ListPendingGlobalLog(ctx context.Context, nowUnixN int64, limit int) ([]model.GlobalLogOutboxItem, error) {
	return s.listGlobalLogOutbox(ctx, limit, func(item model.GlobalLogOutboxItem) bool {
		return item.Status == model.AnchorStatePending && item.NextAttemptUnixN <= nowUnixN
	})
}

func (s LocalStore) ListGlobalLogOutboxItemsAfter(ctx context.Context, afterBatchID string, limit int) ([]model.GlobalLogOutboxItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global log outbox after canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	entries, err := os.ReadDir(s.globalOutboxDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global log outbox directory", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdgoutbox") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	items := make([]model.GlobalLogOutboxItem, 0, limit)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global log outbox after canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(s.globalOutboxDir(), name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global log outbox item", err)
		}
		var item model.GlobalLogOutboxItem
		if err := cborx.UnmarshalLimit(data, &item, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log outbox item", err)
		}
		if item.BatchID <= afterBatchID {
			continue
		}
		items = append(items, item)
		if len(items) >= limit {
			break
		}
	}
	return items, nil
}

func (s LocalStore) GetGlobalLogOutboxItem(ctx context.Context, batchID string) (model.GlobalLogOutboxItem, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.GlobalLogOutboxItem{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get global log outbox canceled", err)
	}
	if batchID == "" {
		return model.GlobalLogOutboxItem{}, false, trusterr.New(trusterr.CodeInvalidArgument, "batch_id is required")
	}
	data, err := os.ReadFile(s.globalOutboxPath(batchID))
	if err != nil {
		if os.IsNotExist(err) {
			return model.GlobalLogOutboxItem{}, false, nil
		}
		return model.GlobalLogOutboxItem{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read global log outbox item", err)
	}
	var item model.GlobalLogOutboxItem
	if err := cborx.UnmarshalLimit(data, &item, maxStoredObjectBytes); err != nil {
		return model.GlobalLogOutboxItem{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log outbox item", err)
	}
	return item, true, nil
}

func (s LocalStore) MarkGlobalLogPublished(ctx context.Context, batchID string, sth model.SignedTreeHead) error {
	item, ok, err := s.GetGlobalLogOutboxItem(ctx, batchID)
	if err != nil {
		return err
	}
	if !ok {
		return trusterr.New(trusterr.CodeNotFound, "global log outbox item not found")
	}
	now := time.Now().UTC().UnixNano()
	item.Status = model.AnchorStatePublished
	item.STH = sth
	item.LastErrorMessage = ""
	item.LastAttemptUnixN = now
	item.NextAttemptUnixN = 0
	item.CompletedAtUnixN = now
	if err := writeCBORAtomic(s.globalOutboxPath(batchID), item); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "update global log outbox item", err)
	}
	if err := s.promoteBatchRecords(ctx, batchID, "L4"); err != nil {
		return err
	}
	return nil
}

func (s LocalStore) RescheduleGlobalLog(ctx context.Context, batchID string, attempts int, nextAttemptUnixN int64, lastErrorMessage string) error {
	item, ok, err := s.GetGlobalLogOutboxItem(ctx, batchID)
	if err != nil {
		return err
	}
	if !ok {
		return trusterr.New(trusterr.CodeNotFound, "global log outbox item not found")
	}
	item.Status = model.AnchorStatePending
	item.Attempts = attempts
	item.NextAttemptUnixN = nextAttemptUnixN
	item.LastErrorMessage = lastErrorMessage
	item.LastAttemptUnixN = time.Now().UTC().UnixNano()
	if err := writeCBORAtomic(s.globalOutboxPath(batchID), item); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "update global log outbox item", err)
	}
	return nil
}

func (s LocalStore) listGlobalLogOutbox(ctx context.Context, limit int, include func(model.GlobalLogOutboxItem) bool) ([]model.GlobalLogOutboxItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global log outbox canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	entries, err := os.ReadDir(s.globalOutboxDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global log outbox directory", err)
	}
	items := make([]model.GlobalLogOutboxItem, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdgoutbox") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.globalOutboxDir(), entry.Name()))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global log outbox item", err)
		}
		var item model.GlobalLogOutboxItem
		if err := cborx.UnmarshalLimit(data, &item, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log outbox item", err)
		}
		if include(item) {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].EnqueuedAtUnixN < items[j].EnqueuedAtUnixN
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (s LocalStore) EnqueueSTHAnchor(ctx context.Context, item model.STHAnchorOutboxItem) error {
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
	path := s.sthAnchorOutboxPath(item.TreeSize)
	if _, err := os.Stat(path); err == nil {
		return trusterr.New(trusterr.CodeAlreadyExists, "sth anchor outbox item already exists")
	} else if !os.IsNotExist(err) {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stat sth anchor outbox item", err)
	}
	if err := writeCBORAtomic(path, item); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write sth anchor outbox item", err)
	}
	return nil
}

func (s LocalStore) ListPendingSTHAnchors(ctx context.Context, nowUnixN int64, limit int) ([]model.STHAnchorOutboxItem, error) {
	items, err := s.listSTHAnchors(ctx, limit, func(item model.STHAnchorOutboxItem) bool {
		return item.Status == model.AnchorStatePending && item.NextAttemptUnixN <= nowUnixN
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s LocalStore) ListPublishedSTHAnchors(ctx context.Context, limit int) ([]model.STHAnchorOutboxItem, error) {
	return s.listSTHAnchors(ctx, limit, func(item model.STHAnchorOutboxItem) bool {
		return item.Status == model.AnchorStatePublished
	})
}

func (s LocalStore) GetSTHAnchorOutboxItem(ctx context.Context, treeSize uint64) (model.STHAnchorOutboxItem, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorOutboxItem{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get sth anchor canceled", err)
	}
	if treeSize == 0 {
		return model.STHAnchorOutboxItem{}, false, trusterr.New(trusterr.CodeInvalidArgument, "tree_size is required")
	}
	data, err := os.ReadFile(s.sthAnchorOutboxPath(treeSize))
	if err != nil {
		if os.IsNotExist(err) {
			return model.STHAnchorOutboxItem{}, false, nil
		}
		return model.STHAnchorOutboxItem{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor outbox item", err)
	}
	var item model.STHAnchorOutboxItem
	if err := cborx.UnmarshalLimit(data, &item, maxStoredObjectBytes); err != nil {
		return model.STHAnchorOutboxItem{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode sth anchor outbox item", err)
	}
	return item, true, nil
}

func (s LocalStore) ListSTHAnchorOutboxItemsAfter(ctx context.Context, afterTreeSize uint64, limit int) ([]model.STHAnchorOutboxItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor outbox after canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	entries, err := os.ReadDir(s.sthAnchorOutboxDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor outbox directory", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdsth-anchor") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	items := make([]model.STHAnchorOutboxItem, 0, limit)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor outbox after canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(s.sthAnchorOutboxDir(), name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor outbox item", err)
		}
		var item model.STHAnchorOutboxItem
		if err := cborx.UnmarshalLimit(data, &item, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode sth anchor outbox item", err)
		}
		if item.TreeSize <= afterTreeSize {
			continue
		}
		items = append(items, item)
		if len(items) >= limit {
			break
		}
	}
	return items, nil
}

func (s LocalStore) ListSTHAnchorsPage(ctx context.Context, opts model.AnchorListOptions) ([]model.STHAnchorOutboxItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchors page canceled", err)
	}
	limit := normaliseRecordLimit(opts.Limit)
	entries, err := os.ReadDir(s.sthAnchorOutboxDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor outbox directory", err)
	}
	items := make([]model.STHAnchorOutboxItem, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdsth-anchor") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchors page canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(s.sthAnchorOutboxDir(), entry.Name()))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor outbox item", err)
		}
		var item model.STHAnchorOutboxItem
		if err := cborx.UnmarshalLimit(data, &item, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode sth anchor outbox item", err)
		}
		if !model.Uint64AfterCursor(item.TreeSize, opts.AfterTreeSize, opts.Direction) {
			continue
		}
		items = append(items, item)
	}
	sortSTHAnchorsByTreeSize(items, opts.Direction)
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (s LocalStore) RescheduleSTHAnchor(ctx context.Context, treeSize uint64, attempts int, nextAttemptUnixN int64, lastErrorMessage string) error {
	item, ok, err := s.GetSTHAnchorOutboxItem(ctx, treeSize)
	if err != nil {
		return err
	}
	if !ok {
		return trusterr.New(trusterr.CodeNotFound, "sth anchor outbox item not found")
	}
	item.Status = model.AnchorStatePending
	item.Attempts = attempts
	item.NextAttemptUnixN = nextAttemptUnixN
	item.LastErrorMessage = lastErrorMessage
	item.LastAttemptUnixN = time.Now().UTC().UnixNano()
	if err := writeCBORAtomic(s.sthAnchorOutboxPath(treeSize), item); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "update sth anchor outbox item", err)
	}
	return nil
}

func (s LocalStore) MarkSTHAnchorPublished(ctx context.Context, result model.STHAnchorResult) error {
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
	if err := writeCBORAtomic(s.sthAnchorResultPath(result.TreeSize), result); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write sth anchor result", err)
	}
	item.Status = model.AnchorStatePublished
	item.LastErrorMessage = ""
	item.LastAttemptUnixN = result.PublishedAtUnixN
	item.NextAttemptUnixN = 0
	if err := writeCBORAtomic(s.sthAnchorOutboxPath(result.TreeSize), item); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "update sth anchor outbox item", err)
	}
	leaf, ok, err := s.GetGlobalLeaf(ctx, result.TreeSize-1)
	if err != nil {
		return err
	}
	if ok {
		if err := s.promoteBatchRecords(ctx, leaf.BatchID, "L5"); err != nil {
			return err
		}
	}
	return nil
}

func (s LocalStore) MarkSTHAnchorFailed(ctx context.Context, treeSize uint64, lastErrorMessage string) error {
	item, ok, err := s.GetSTHAnchorOutboxItem(ctx, treeSize)
	if err != nil {
		return err
	}
	if !ok {
		return trusterr.New(trusterr.CodeNotFound, "sth anchor outbox item not found")
	}
	item.Status = model.AnchorStateFailed
	item.LastErrorMessage = lastErrorMessage
	item.LastAttemptUnixN = time.Now().UTC().UnixNano()
	item.NextAttemptUnixN = 0
	if err := writeCBORAtomic(s.sthAnchorOutboxPath(treeSize), item); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "update sth anchor outbox item", err)
	}
	return nil
}

func (s LocalStore) GetSTHAnchorResult(ctx context.Context, treeSize uint64) (model.STHAnchorResult, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get sth anchor result canceled", err)
	}
	if treeSize == 0 {
		return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeInvalidArgument, "tree_size is required")
	}
	data, err := os.ReadFile(s.sthAnchorResultPath(treeSize))
	if err != nil {
		if os.IsNotExist(err) {
			return model.STHAnchorResult{}, false, nil
		}
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor result", err)
	}
	var result model.STHAnchorResult
	if err := cborx.UnmarshalLimit(data, &result, maxStoredObjectBytes); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode sth anchor result", err)
	}
	return result, true, nil
}

func (s LocalStore) listSTHAnchors(ctx context.Context, limit int, include func(model.STHAnchorOutboxItem) bool) ([]model.STHAnchorOutboxItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchors canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	entries, err := os.ReadDir(s.sthAnchorOutboxDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor outbox directory", err)
	}
	items := make([]model.STHAnchorOutboxItem, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdsth-anchor") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.sthAnchorOutboxDir(), entry.Name()))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor outbox item", err)
		}
		var item model.STHAnchorOutboxItem
		if err := cborx.UnmarshalLimit(data, &item, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode sth anchor outbox item", err)
		}
		if include(item) {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].EnqueuedAtUnixN < items[j].EnqueuedAtUnixN
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (s LocalStore) globalLeafDir() string {
	return filepath.Join(s.root(), "global", "leaves")
}

func (s LocalStore) globalLeafByBatchDir() string {
	return filepath.Join(s.root(), "global", "leaf-by-batch")
}

func (s LocalStore) globalNodeDir() string {
	return filepath.Join(s.root(), "global", "nodes")
}

func (s LocalStore) globalStatePath() string {
	return filepath.Join(s.root(), "global", "state.tdgstate")
}

func (s LocalStore) sthDir() string {
	return filepath.Join(s.root(), "global", "sth")
}

func (s LocalStore) globalTileDir() string {
	return filepath.Join(s.root(), "global", "tiles")
}

func (s LocalStore) globalOutboxDir() string {
	return filepath.Join(s.root(), "global", "outbox")
}

func (s LocalStore) sthAnchorOutboxDir() string {
	return filepath.Join(s.root(), "anchor", "sth-outbox")
}

func (s LocalStore) sthAnchorResultDir() string {
	return filepath.Join(s.root(), "anchor", "sth-result")
}

func (s LocalStore) globalLeafPath(index uint64) string {
	return filepath.Join(s.globalLeafDir(), fmt.Sprintf("%020d.tdgleaf", index))
}

func (s LocalStore) globalLeafByBatchPath(batchID string) string {
	return filepath.Join(s.globalLeafByBatchDir(), safeFileName(batchID)+".tdgleaf")
}

func (s LocalStore) globalNodePath(level, start uint64) string {
	return filepath.Join(s.globalNodeDir(), fmt.Sprintf("%020d_%020d.tdgnode", level, start))
}

func (s LocalStore) batchTreeLeafDir(batchID string) string {
	return filepath.Join(s.root(), "batch-trees", safeFileName(batchID), "leaves")
}

func (s LocalStore) batchTreeLeafPath(batchID string, index uint64) string {
	return filepath.Join(s.batchTreeLeafDir(batchID), fmt.Sprintf("%020d.tdbtleaf", index))
}

func (s LocalStore) batchTreeNodeLevelDir(batchID string, level uint64) string {
	return filepath.Join(s.root(), "batch-trees", safeFileName(batchID), "nodes", fmt.Sprintf("%020d", level))
}

func (s LocalStore) batchTreeNodePath(batchID string, level, start uint64) string {
	return filepath.Join(s.batchTreeNodeLevelDir(batchID, level), fmt.Sprintf("%020d.tdbtnode", start))
}

func (s LocalStore) sthPath(treeSize uint64) string {
	return filepath.Join(s.sthDir(), fmt.Sprintf("%020d.tdsth", treeSize))
}

func (s LocalStore) globalTilePath(level, start, width uint64) string {
	return filepath.Join(s.globalTileDir(), fmt.Sprintf("%020d_%020d_%020d.tdgtile", level, start, width))
}

func (s LocalStore) globalOutboxPath(batchID string) string {
	return filepath.Join(s.globalOutboxDir(), safeFileName(batchID)+".tdgoutbox")
}

func (s LocalStore) sthAnchorOutboxPath(treeSize uint64) string {
	return filepath.Join(s.sthAnchorOutboxDir(), fmt.Sprintf("%020d.tdsth-anchor", treeSize))
}

func (s LocalStore) sthAnchorResultPath(treeSize uint64) string {
	return filepath.Join(s.sthAnchorResultDir(), fmt.Sprintf("%020d.tdsth-anchor-result", treeSize))
}

func (s LocalStore) checkpointPath() string {
	return filepath.Join(s.root(), "wal-checkpoint.tdckpt")
}

func (s LocalStore) bundleDir() string {
	return filepath.Join(s.root(), "bundles")
}

func (s LocalStore) recordByIDDir() string {
	return filepath.Join(s.root(), "records", "by-id")
}

func (s LocalStore) recordByTimeDir() string {
	return filepath.Join(s.root(), "records", "by-time")
}

func (s LocalStore) recordByBatchDir(batchID string) string {
	return filepath.Join(s.root(), "records", "by-batch", safeFileName(batchID))
}

func (s LocalStore) recordByProofLevelDir(level string) string {
	return filepath.Join(s.root(), "records", "by-proof-level", safeFileName(level))
}

func (s LocalStore) recordByTenantDir(tenantID string) string {
	return filepath.Join(s.root(), "records", "by-tenant", safeFileName(tenantID))
}

func (s LocalStore) recordByClientDir(clientID string) string {
	return filepath.Join(s.root(), "records", "by-client", safeFileName(clientID))
}

func (s LocalStore) recordByContentDir(contentHash []byte) string {
	return filepath.Join(s.root(), "records", "by-content", hex.EncodeToString(contentHash))
}

func (s LocalStore) recordByStorageTokenDir(token string) string {
	return filepath.Join(s.root(), "records", "by-storage-token", recordTokenPart(token))
}

func (s LocalStore) recordByIDPath(recordID string) string {
	return filepath.Join(s.recordByIDDir(), safeFileName(recordID)+".tdrecord")
}

func (s LocalStore) recordIndexName(idx model.RecordIndex) string {
	return fmt.Sprintf("%020d_%s.tdrecord", idx.ReceivedAtUnixN, safeFileName(idx.RecordID))
}

func (s LocalStore) rootDir() string {
	return filepath.Join(s.root(), "roots")
}

func (s LocalStore) manifestDir() string {
	return filepath.Join(s.root(), "manifests")
}

func (s LocalStore) root() string {
	if s.Root == "" {
		return ".trustdb/proofs"
	}
	return s.Root
}

func writeCBORAtomic(path string, value any) error {
	data, err := cborx.Marshal(value)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.%d.tmp", filepath.Base(path), time.Now().UTC().UnixNano()))
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		if os.IsExist(err) {
			if removeErr := os.Remove(path); removeErr == nil {
				if retryErr := os.Rename(tmp, path); retryErr == nil {
					return nil
				}
			}
		}
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (s LocalStore) writeRecordIndex(idx model.RecordIndex) error {
	if idx.RecordID == "" {
		return nil
	}
	if idx.SchemaVersion == "" {
		idx.SchemaVersion = model.SchemaRecordIndex
	}
	// Keep record-by-id continuously readable while secondary indexes are
	// being promoted (for example L3 -> L4 -> L5). List queries may briefly
	// observe stale secondary entries, but direct GetRecord lookups should
	// never see a missing record during index replacement.
	if err := writeCBORAtomic(s.recordByIDPath(idx.RecordID), idx); err != nil {
		return err
	}
	for _, path := range s.recordIndexSecondaryPaths(idx) {
		if err := writeCBORAtomic(path, idx); err != nil {
			return err
		}
	}
	return nil
}

func (s LocalStore) removeRecordIndex(idx model.RecordIndex) {
	paths := append([]string{s.recordByIDPath(idx.RecordID)}, s.recordIndexSecondaryPaths(idx)...)
	for _, path := range paths {
		_ = os.Remove(path)
	}
}

func (s LocalStore) removeRecordIndexSecondary(old, next model.RecordIndex) {
	if old.RecordID == "" {
		return
	}
	keep := make(map[string]struct{}, 8)
	for _, path := range s.recordIndexSecondaryPaths(next) {
		keep[path] = struct{}{}
	}
	for _, path := range s.recordIndexSecondaryPaths(old) {
		if _, ok := keep[path]; ok {
			continue
		}
		_ = os.Remove(path)
	}
}

func (s LocalStore) recordIndexSecondaryPaths(idx model.RecordIndex) []string {
	paths := []string{
		filepath.Join(s.recordByTimeDir(), s.recordIndexName(idx)),
	}
	if idx.BatchID != "" {
		paths = append(paths, filepath.Join(s.recordByBatchDir(idx.BatchID), s.recordIndexName(idx)))
	}
	if idx.ProofLevel != "" {
		paths = append(paths, filepath.Join(s.recordByProofLevelDir(idx.ProofLevel), s.recordIndexName(idx)))
	}
	if idx.TenantID != "" {
		paths = append(paths, filepath.Join(s.recordByTenantDir(idx.TenantID), s.recordIndexName(idx)))
	}
	if idx.ClientID != "" {
		paths = append(paths, filepath.Join(s.recordByClientDir(idx.ClientID), s.recordIndexName(idx)))
	}
	if len(idx.ContentHash) > 0 {
		paths = append(paths, filepath.Join(s.recordByContentDir(idx.ContentHash), s.recordIndexName(idx)))
	}
	for _, token := range model.RecordIndexStorageTokens(idx) {
		paths = append(paths, filepath.Join(s.recordByStorageTokenDir(token), s.recordIndexName(idx)))
	}
	return paths
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

func sortBatchRoots(roots []model.BatchRoot, direction string) {
	desc := !strings.EqualFold(direction, model.RecordListDirectionAsc)
	sort.Slice(roots, func(i, j int) bool {
		cmp := model.CompareBatchRootPosition(roots[i].ClosedAtUnixN, roots[i].BatchID, roots[j].ClosedAtUnixN, roots[j].BatchID)
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortRecordIndexes(indexes []model.RecordIndex, direction string) {
	desc := !strings.EqualFold(direction, model.RecordListDirectionAsc)
	sort.Slice(indexes, func(i, j int) bool {
		cmp := model.CompareRecordPosition(indexes[i].ReceivedAtUnixN, indexes[i].RecordID, indexes[j].ReceivedAtUnixN, indexes[j].RecordID)
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortSignedTreeHeads(sths []model.SignedTreeHead, direction string) {
	desc := !strings.EqualFold(direction, model.RecordListDirectionAsc)
	sort.Slice(sths, func(i, j int) bool {
		cmp := model.CompareUint64Position(sths[i].TreeSize, sths[j].TreeSize)
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortGlobalLeaves(leaves []model.GlobalLogLeaf, direction string) {
	desc := !strings.EqualFold(direction, model.RecordListDirectionAsc)
	sort.Slice(leaves, func(i, j int) bool {
		cmp := model.CompareUint64Position(leaves[i].LeafIndex, leaves[j].LeafIndex)
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortSTHAnchorsByTreeSize(items []model.STHAnchorOutboxItem, direction string) {
	desc := !strings.EqualFold(direction, model.RecordListDirectionAsc)
	sort.Slice(items, func(i, j int) bool {
		cmp := model.CompareUint64Position(items[i].TreeSize, items[j].TreeSize)
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func (s LocalStore) promoteBatchRecords(ctx context.Context, batchID, proofLevel string) error {
	if batchID == "" {
		return nil
	}
	entries, err := os.ReadDir(s.recordByBatchDir(batchID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return trusterr.Wrap(trusterr.CodeDataLoss, "read batch record index directory", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdrecord") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "promote batch record indexes canceled", err)
		}
		data, err := os.ReadFile(filepath.Join(s.recordByBatchDir(batchID), entry.Name()))
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "read batch record index", err)
		}
		var idx model.RecordIndex
		if err := cborx.UnmarshalLimit(data, &idx, maxStoredObjectBytes); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "decode batch record index", err)
		}
		if model.ProofLevelRank(model.RecordIndexProofLevel(idx)) >= model.ProofLevelRank(proofLevel) {
			continue
		}
		idx.ProofLevel = proofLevel
		if err := s.PutRecordIndex(ctx, idx); err != nil {
			return err
		}
	}
	return nil
}

func safeFileName(value string) string {
	if value == "" {
		return "_"
	}
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	return b.String()
}

func recordTokenPart(value string) string {
	if value == "" {
		return "_"
	}
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}
