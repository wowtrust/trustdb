package proofstore

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

const (
	maxStoredObjectBytes  = 64 << 20
	encodedFileNamePrefix = "~"
	localPositionWidth    = 20
)

type LocalStore struct {
	Root string
}

type localFileOps struct {
	stat       func(string) (os.FileInfo, error)
	mkdir      func(string, os.FileMode) error
	createTemp func(string, string) (*os.File, error)
	syncFile   func(*os.File) error
	closeFile  func(*os.File) error
	replace    func(string, string) error
	remove     func(string) error
	syncDir    func(string) error
	cacheDirs  bool
}

var localDurableDirectories sync.Map

var localLatestSTHLocks [64]sync.Mutex
var localLatestRootLocks [64]sync.Mutex

func defaultLocalFileOps() localFileOps {
	return localFileOps{
		stat:       os.Stat,
		mkdir:      os.Mkdir,
		createTemp: os.CreateTemp,
		syncFile:   func(file *os.File) error { return file.Sync() },
		closeFile:  func(file *os.File) error { return file.Close() },
		replace:    replaceLocalFile,
		remove:     os.Remove,
		syncDir:    syncLocalDirectory,
		cacheDirs:  true,
	}
}

func (s LocalStore) PutBundle(ctx context.Context, bundle model.ProofBundle) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put bundle canceled", err)
	}
	if bundle.RecordID == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "proof bundle record_id is required")
	}
	if err := writeCBORAtomic(s.bundlePath(bundle.RecordID), bundle); err != nil {
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
	data, err := readStoredFile(s.bundlePath(recordID))
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
	data, err := readStoredFile(s.recordByIDPath(recordID))
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
	dir := filepath.Join("records", "by-time")
	switch {
	case len(opts.ContentHash) > 0:
		dir = filepath.Join("records", "by-content", hex.EncodeToString(opts.ContentHash))
	case model.RecordStorageQueryToken(opts.Query) != "":
		dir = filepath.Join("records", "by-storage-token", recordTokenPart(model.RecordStorageQueryToken(opts.Query)))
	case opts.BatchID != "":
		dir = filepath.Join("records", "by-batch", safeFileName(opts.BatchID))
	case opts.ProofLevel != "":
		dir = filepath.Join("records", "by-proof-level", safeFileName(opts.ProofLevel))
	case opts.TenantID != "":
		dir = filepath.Join("records", "by-tenant", safeFileName(opts.TenantID))
	case opts.ClientID != "":
		dir = filepath.Join("records", "by-client", safeFileName(opts.ClientID))
	}
	root, err := os.OpenRoot(s.root())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "open proofstore root", err)
	}
	defer root.Close()
	dirFile, err := root.Open(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read record index directory", err)
	}
	entries, err := dirFile.ReadDir(-1)
	closeErr := dirFile.Close()
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read record index directory", err)
	}
	if closeErr != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "close record index directory", closeErr)
	}
	ordered, err := orderedRecordIndexEntries(entries)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "parse record index filename", err)
	}
	indexes := make([]model.RecordIndex, 0, min(limit, len(ordered)))
	start, end, step := recordIndexPageRange(ordered, opts)
	for i := start; i != end && len(indexes) < limit; i += step {
		entry := ordered[i]
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list record indexes canceled", err)
		}
		data, err := root.ReadFile(filepath.Join(dir, entry.name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read record index", err)
		}
		var idx model.RecordIndex
		if err := cborx.UnmarshalLimit(data, &idx, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode record index", err)
		}
		if idx.ReceivedAtUnixN != entry.receivedAtUnixN || idx.RecordID != entry.recordID {
			return nil, trusterr.New(trusterr.CodeDataLoss, "record index position does not match filename")
		}
		if !model.RecordIndexMatchesListOptions(idx, opts) || !model.RecordIndexAfterCursor(idx, opts) {
			continue
		}
		indexes = append(indexes, idx)
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
	lock := s.latestRootLock()
	lock.Lock()
	defer lock.Unlock()
	if err := s.prepareLatestRootReferenceLocked(ctx, root); err != nil {
		return err
	}
	if err := writeCBORAtomic(s.rootPath(root.ClosedAtUnixN, root.BatchID), root); err != nil {
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
	ordered, err := orderedRootEntries(entries)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "parse batch root filename", err)
	}
	roots := make([]model.BatchRoot, 0, min(limit, len(ordered)))
	for i := len(ordered) - 1; i >= 0 && len(roots) < limit; i-- {
		entry := ordered[i]
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list roots canceled", err)
		}
		data, err := readStoredFile(filepath.Join(s.rootDir(), entry.name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read batch root", err)
		}
		var root model.BatchRoot
		if err := cborx.UnmarshalLimit(data, &root, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch root", err)
		}
		if root.ClosedAtUnixN != entry.closedAtUnixN || root.BatchID != entry.batchID {
			return nil, trusterr.New(trusterr.CodeDataLoss, "batch root position does not match filename")
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
	ordered, err := orderedRootEntries(entries)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "parse batch root filename", err)
	}
	start := sort.Search(len(ordered), func(i int) bool {
		return ordered[i].closedAtUnixN > afterClosedAtUnixN
	})
	roots := make([]model.BatchRoot, 0, min(limit, len(ordered)-start))
	for i := start; i < len(ordered) && len(roots) < limit; i++ {
		entry := ordered[i]
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list roots after canceled", err)
		}
		data, err := readStoredFile(filepath.Join(s.rootDir(), entry.name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read batch root", err)
		}
		var root model.BatchRoot
		if err := cborx.UnmarshalLimit(data, &root, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch root", err)
		}
		if root.ClosedAtUnixN != entry.closedAtUnixN || root.BatchID != entry.batchID {
			return nil, trusterr.New(trusterr.CodeDataLoss, "batch root position does not match filename")
		}
		roots = append(roots, root)
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
	ordered, err := orderedRootEntries(entries)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "parse batch root filename", err)
	}
	roots := make([]model.BatchRoot, 0, min(limit, len(ordered)))
	start, end, step := rootPageRange(ordered, opts)
	for i := start; i != end && len(roots) < limit; i += step {
		entry := ordered[i]
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list roots page canceled", err)
		}
		data, err := readStoredFile(filepath.Join(s.rootDir(), entry.name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read batch root", err)
		}
		var root model.BatchRoot
		if err := cborx.UnmarshalLimit(data, &root, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch root", err)
		}
		if root.ClosedAtUnixN != entry.closedAtUnixN || root.BatchID != entry.batchID {
			return nil, trusterr.New(trusterr.CodeDataLoss, "batch root position does not match filename")
		}
		if !model.BatchRootAfterCursor(root, opts) {
			continue
		}
		roots = append(roots, root)
	}
	return roots, nil
}

func (s LocalStore) LatestRoot(ctx context.Context) (model.BatchRoot, error) {
	if err := ctx.Err(); err != nil {
		return model.BatchRoot{}, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore latest root canceled", err)
	}
	ref, ok, refErr := s.readLatestRootReference()
	if refErr == nil && ok {
		root, found, complete, err := s.rootFromLatestReference(ctx, ref)
		if err != nil {
			return model.BatchRoot{}, err
		}
		if found && complete {
			return root, nil
		}
	}
	return s.rebuildLatestRootReference(ctx)
}

type localRootReferencePosition struct {
	ClosedAtUnixN int64  `cbor:"closed_at_unix_n"`
	BatchID       string `cbor:"batch_id"`
}

type localLatestRootReference struct {
	Candidate localRootReferencePosition  `cbor:"candidate"`
	Previous  *localRootReferencePosition `cbor:"previous,omitempty"`
}

func (s LocalStore) prepareLatestRootReferenceLocked(ctx context.Context, root model.BatchRoot) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore update latest root reference canceled", err)
	}
	candidate := localRootReferencePosition{ClosedAtUnixN: root.ClosedAtUnixN, BatchID: root.BatchID}
	var current *localRootReferencePosition
	if ref, ok, err := s.readLatestRootReference(); err == nil && ok {
		currentRoot, found, _, resolveErr := s.rootFromLatestReference(ctx, ref)
		if resolveErr != nil {
			return resolveErr
		}
		if found {
			position := localRootReferencePosition{ClosedAtUnixN: currentRoot.ClosedAtUnixN, BatchID: currentRoot.BatchID}
			current = &position
		}
	} else {
		currentRoot, found, historyErr := s.latestRootFromHistory(ctx)
		if historyErr != nil {
			return historyErr
		}
		if found {
			position := localRootReferencePosition{ClosedAtUnixN: currentRoot.ClosedAtUnixN, BatchID: currentRoot.BatchID}
			current = &position
		}
	}
	if current != nil && compareLocalRootReferencePosition(candidate, *current) <= 0 {
		return nil
	}
	ref := localLatestRootReference{Candidate: candidate, Previous: current}
	if err := writeCBORAtomic(s.latestRootReferencePath(), ref); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write latest root reference", err)
	}
	return nil
}

func (s LocalStore) rootFromLatestReference(ctx context.Context, ref localLatestRootReference) (model.BatchRoot, bool, bool, error) {
	root, found, err := s.rootAtReferencePosition(ctx, ref.Candidate)
	if err != nil {
		return model.BatchRoot{}, false, false, err
	}
	if found {
		return root, true, true, nil
	}
	if ref.Previous == nil {
		return model.BatchRoot{}, false, false, nil
	}
	root, found, err = s.rootAtReferencePosition(ctx, *ref.Previous)
	if err != nil {
		return model.BatchRoot{}, false, false, err
	}
	return root, found, false, nil
}

func (s LocalStore) rootAtReferencePosition(ctx context.Context, position localRootReferencePosition) (model.BatchRoot, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.BatchRoot{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore read referenced root canceled", err)
	}
	if position.ClosedAtUnixN <= 0 || position.BatchID == "" {
		return model.BatchRoot{}, false, trusterr.New(trusterr.CodeDataLoss, "latest root reference position is invalid")
	}
	data, err := readStoredFile(s.rootPath(position.ClosedAtUnixN, position.BatchID))
	if err != nil {
		if os.IsNotExist(err) {
			return model.BatchRoot{}, false, nil
		}
		return model.BatchRoot{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read referenced batch root", err)
	}
	var root model.BatchRoot
	if err := cborx.UnmarshalLimit(data, &root, maxStoredObjectBytes); err != nil {
		return model.BatchRoot{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode referenced batch root", err)
	}
	if root.ClosedAtUnixN != position.ClosedAtUnixN || root.BatchID != position.BatchID {
		return model.BatchRoot{}, false, trusterr.New(trusterr.CodeDataLoss, "latest root reference does not match item")
	}
	return root, true, nil
}

func (s LocalStore) rebuildLatestRootReference(ctx context.Context) (model.BatchRoot, error) {
	lock := s.latestRootLock()
	lock.Lock()
	defer lock.Unlock()

	if ref, ok, err := s.readLatestRootReference(); err == nil && ok {
		root, found, complete, resolveErr := s.rootFromLatestReference(ctx, ref)
		if resolveErr != nil {
			return model.BatchRoot{}, resolveErr
		}
		if found && complete {
			return root, nil
		}
	}
	root, found, err := s.latestRootFromHistory(ctx)
	if err != nil {
		return model.BatchRoot{}, err
	}
	if !found {
		return model.BatchRoot{}, trusterr.New(trusterr.CodeNotFound, "batch root not found")
	}
	ref := localLatestRootReference{Candidate: localRootReferencePosition{ClosedAtUnixN: root.ClosedAtUnixN, BatchID: root.BatchID}}
	if err := writeCBORAtomic(s.latestRootReferencePath(), ref); err != nil {
		return model.BatchRoot{}, trusterr.Wrap(trusterr.CodeDataLoss, "rebuild latest root reference", err)
	}
	return root, nil
}

func (s LocalStore) latestRootFromHistory(ctx context.Context) (model.BatchRoot, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.BatchRoot{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore scan latest root canceled", err)
	}
	entries, err := os.ReadDir(s.rootDir())
	if err != nil {
		if os.IsNotExist(err) {
			return model.BatchRoot{}, false, nil
		}
		return model.BatchRoot{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read root directory", err)
	}
	ordered, err := orderedRootEntries(entries)
	if err != nil {
		return model.BatchRoot{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "parse batch root filename", err)
	}
	if len(ordered) == 0 {
		return model.BatchRoot{}, false, nil
	}
	entry := ordered[len(ordered)-1]
	root, found, err := s.rootAtReferencePosition(ctx, localRootReferencePosition{ClosedAtUnixN: entry.closedAtUnixN, BatchID: entry.batchID})
	return root, found, err
}

func (s LocalStore) readLatestRootReference() (localLatestRootReference, bool, error) {
	data, err := readStoredFile(s.latestRootReferencePath())
	if err != nil {
		if os.IsNotExist(err) {
			return localLatestRootReference{}, false, nil
		}
		return localLatestRootReference{}, false, err
	}
	var ref localLatestRootReference
	if err := cborx.UnmarshalLimit(data, &ref, maxStoredObjectBytes); err != nil {
		return localLatestRootReference{}, false, err
	}
	if ref.Candidate.ClosedAtUnixN <= 0 || ref.Candidate.BatchID == "" {
		return localLatestRootReference{}, false, trusterr.New(trusterr.CodeDataLoss, "latest root reference is invalid")
	}
	return ref, true, nil
}

func compareLocalRootReferencePosition(left, right localRootReferencePosition) int {
	return model.CompareBatchRootPosition(left.ClosedAtUnixN, left.BatchID, right.ClosedAtUnixN, right.BatchID)
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
	leaves := make([]model.BatchTreeLeaf, 0, limit)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdbtleaf") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list batch tree leaves canceled", err)
		}
		data, err := readStoredFile(filepath.Join(s.batchTreeLeafDir(opts.BatchID), entry.Name()))
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
	entries, err := os.ReadDir(s.batchTreeNodeLevelDir(opts.BatchID, opts.Level))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read batch tree node directory", err)
	}
	nodes := make([]model.BatchTreeNode, 0, limit)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdbtnode") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list batch tree nodes canceled", err)
		}
		data, err := readStoredFile(filepath.Join(s.batchTreeNodeLevelDir(opts.BatchID, opts.Level), entry.Name()))
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
	if !model.ValidBatchManifestState(manifest.State) {
		return trusterr.New(trusterr.CodeInvalidArgument, "invalid batch manifest state")
	}
	if manifest.SchemaVersion == "" {
		manifest.SchemaVersion = model.SchemaBatchManifest
	}
	if err := writeCBORAtomic(s.manifestPath(manifest.BatchID), manifest); err != nil {
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
	data, err := readStoredFile(s.manifestPath(batchID))
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
	ordered, err := orderedManifestEntries(entries)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "parse batch manifest filename", err)
	}
	manifests := make([]model.BatchManifest, 0, len(ordered))
	for _, entry := range ordered {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list manifests canceled", err)
		}
		data, err := readStoredFile(filepath.Join(s.manifestDir(), entry.name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read batch manifest", err)
		}
		var manifest model.BatchManifest
		if err := cborx.UnmarshalLimit(data, &manifest, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch manifest", err)
		}
		if manifest.BatchID != entry.batchID {
			return nil, trusterr.New(trusterr.CodeDataLoss, "batch manifest id does not match filename")
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
	ordered, err := orderedManifestEntries(entries)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "parse batch manifest filename", err)
	}
	start := sort.Search(len(ordered), func(i int) bool {
		return ordered[i].batchID > afterBatchID
	})
	manifests := make([]model.BatchManifest, 0, min(limit, len(ordered)-start))
	for i := start; i < len(ordered) && len(manifests) < limit; i++ {
		entry := ordered[i]
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list manifests after canceled", err)
		}
		data, err := readStoredFile(filepath.Join(s.manifestDir(), entry.name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read batch manifest", err)
		}
		var manifest model.BatchManifest
		if err := cborx.UnmarshalLimit(data, &manifest, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode batch manifest", err)
		}
		if manifest.BatchID != entry.batchID {
			return nil, trusterr.New(trusterr.CodeDataLoss, "batch manifest id does not match filename")
		}
		manifests = append(manifests, manifest)
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
	data, err := readStoredFile(s.checkpointPath())
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

// WALCheckpointPruneSafe remains false because durable file publication alone
// cannot rebuild committed idempotency decisions after older WAL records are
// deleted. The development backend fails closed until it provides that second
// half of the checkpoint contract.
func (LocalStore) WALCheckpointPruneSafe() bool { return false }

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
	data, err := readStoredFile(s.globalLeafPath(index))
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
	data, err := readStoredFile(s.globalLeafByBatchPath(batchID))
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
	data, err := readStoredFile(s.globalNodePath(level, startIndex))
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
	ordered, err := orderedGlobalNodeEntries(entries)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "parse global node filename", err)
	}
	hasCursor := afterLevel != ^uint64(0) || afterStartIndex != ^uint64(0)
	start := 0
	if hasCursor {
		start = sort.Search(len(ordered), func(i int) bool {
			return ordered[i].level > afterLevel || ordered[i].level == afterLevel && ordered[i].startIndex > afterStartIndex
		})
	}
	nodes := make([]model.GlobalLogNode, 0, min(limit, len(ordered)-start))
	for i := start; i < len(ordered) && len(nodes) < limit; i++ {
		entry := ordered[i]
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global nodes after canceled", err)
		}
		data, err := readStoredFile(filepath.Join(s.globalNodeDir(), entry.name))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global log node", err)
		}
		var node model.GlobalLogNode
		if err := cborx.UnmarshalLimit(data, &node, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log node", err)
		}
		if node.Level != entry.level || node.StartIndex != entry.startIndex {
			return nil, trusterr.New(trusterr.CodeDataLoss, "global log node position does not match filename")
		}
		nodes = append(nodes, node)
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
	data, err := readStoredFile(s.globalStatePath())
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
	leaves := make([]model.GlobalLogLeaf, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdgleaf") {
			continue
		}
		data, err := readStoredFile(filepath.Join(s.globalLeafDir(), entry.Name()))
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
	leaves := make([]model.GlobalLogLeaf, 0, min(limit, len(entries)))
	start, end, step := sortedDirectoryPageRange(len(entries), opts.Direction)
	for i := start; i != end && len(leaves) < limit; i += step {
		entry := entries[i]
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdgleaf") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global leaves page canceled", err)
		}
		data, err := readStoredFile(filepath.Join(s.globalLeafDir(), entry.Name()))
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
	lock := s.latestSignedTreeHeadLock()
	lock.Lock()
	defer lock.Unlock()
	if err := writeCBORAtomic(s.sthPath(sth.TreeSize), sth); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write signed tree head", err)
	}
	if err := s.promoteLatestSignedTreeHeadReferenceLocked(ctx, sth.TreeSize); err != nil {
		return err
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
	data, err := readStoredFile(s.sthPath(treeSize))
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
	sths := make([]model.SignedTreeHead, 0, min(limit, len(entries)))
	start, end, step := sortedDirectoryPageRange(len(entries), opts.Direction)
	for i := start; i != end && len(sths) < limit; i += step {
		entry := entries[i]
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdsth") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list signed tree heads page canceled", err)
		}
		data, err := readStoredFile(filepath.Join(s.sthDir(), entry.Name()))
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
	return sths, nil
}

func (s LocalStore) LatestSignedTreeHead(ctx context.Context) (model.SignedTreeHead, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore latest sth canceled", err)
	}
	treeSize, ok, refErr := s.readLatestSignedTreeHeadReference()
	if refErr == nil && ok {
		sth, found, err := s.GetSignedTreeHead(ctx, treeSize)
		if err != nil {
			return model.SignedTreeHead{}, false, err
		}
		if found {
			if sth.TreeSize != treeSize {
				return model.SignedTreeHead{}, false, trusterr.New(trusterr.CodeDataLoss, "latest signed tree head reference does not match item")
			}
			state, stateFound, err := s.GetGlobalLogState(ctx)
			if err != nil {
				return model.SignedTreeHead{}, false, err
			}
			if !stateFound || state.TreeSize <= treeSize {
				return sth, true, nil
			}
			newer, newerFound, err := s.GetSignedTreeHead(ctx, state.TreeSize)
			if err != nil {
				return model.SignedTreeHead{}, false, err
			}
			if !newerFound {
				return sth, true, nil
			}
			if newer.TreeSize != state.TreeSize {
				return model.SignedTreeHead{}, false, trusterr.New(trusterr.CodeDataLoss, "global state tree size does not match signed tree head")
			}
			if err := s.promoteLatestSignedTreeHeadReference(ctx, newer.TreeSize); err != nil {
				return model.SignedTreeHead{}, false, err
			}
			return newer, true, nil
		}
	}
	return s.rebuildLatestSignedTreeHeadReference(ctx)
}

func (s LocalStore) promoteLatestSignedTreeHeadReference(ctx context.Context, treeSize uint64) error {
	lock := s.latestSignedTreeHeadLock()
	lock.Lock()
	defer lock.Unlock()
	return s.promoteLatestSignedTreeHeadReferenceLocked(ctx, treeSize)
}

func (s LocalStore) promoteLatestSignedTreeHeadReferenceLocked(ctx context.Context, treeSize uint64) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore update latest sth reference canceled", err)
	}
	current, ok, err := s.readLatestSignedTreeHeadReference()
	if err == nil && ok {
		if current >= treeSize {
			return nil
		}
		if err := writeCBORAtomic(s.latestSignedTreeHeadReferencePath(), treeSize); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "write latest signed tree head reference", err)
		}
		return nil
	}
	_, latest, found, rebuildErr := s.latestSignedTreeHeadFromHistory(ctx)
	if rebuildErr != nil {
		return rebuildErr
	}
	if found {
		treeSize = latest.TreeSize
	}
	if err := writeCBORAtomic(s.latestSignedTreeHeadReferencePath(), treeSize); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write latest signed tree head reference", err)
	}
	return nil
}

func (s LocalStore) rebuildLatestSignedTreeHeadReference(ctx context.Context) (model.SignedTreeHead, bool, error) {
	lock := s.latestSignedTreeHeadLock()
	lock.Lock()
	defer lock.Unlock()

	if treeSize, ok, err := s.readLatestSignedTreeHeadReference(); err == nil && ok {
		sth, found, getErr := s.GetSignedTreeHead(ctx, treeSize)
		if getErr != nil {
			return model.SignedTreeHead{}, false, getErr
		}
		if found {
			if sth.TreeSize != treeSize {
				return model.SignedTreeHead{}, false, trusterr.New(trusterr.CodeDataLoss, "latest signed tree head reference does not match item")
			}
			return sth, true, nil
		}
	}
	treeSize, sth, found, err := s.latestSignedTreeHeadFromHistory(ctx)
	if err != nil || !found {
		return sth, found, err
	}
	if err := writeCBORAtomic(s.latestSignedTreeHeadReferencePath(), treeSize); err != nil {
		return model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "rebuild latest signed tree head reference", err)
	}
	return sth, true, nil
}

func (s LocalStore) latestSignedTreeHeadFromHistory(ctx context.Context) (uint64, model.SignedTreeHead, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore scan latest sth canceled", err)
	}
	entries, err := os.ReadDir(s.sthDir())
	if err != nil {
		if os.IsNotExist(err) {
			return 0, model.SignedTreeHead{}, false, nil
		}
		return 0, model.SignedTreeHead{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read sth directory", err)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdsth") {
			continue
		}
		treeSize, err := decodeLocalUint64Filename(entry.Name(), ".tdsth")
		if err != nil || treeSize == 0 {
			return 0, model.SignedTreeHead{}, false, trusterr.New(trusterr.CodeDataLoss, "invalid signed tree head filename")
		}
		sth, found, err := s.GetSignedTreeHead(ctx, treeSize)
		if err != nil {
			return 0, model.SignedTreeHead{}, false, err
		}
		if !found || sth.TreeSize != treeSize {
			return 0, model.SignedTreeHead{}, false, trusterr.New(trusterr.CodeDataLoss, "signed tree head path does not match item")
		}
		return treeSize, sth, true, nil
	}
	return 0, model.SignedTreeHead{}, false, nil
}

func (s LocalStore) readLatestSignedTreeHeadReference() (uint64, bool, error) {
	data, err := readStoredFile(s.latestSignedTreeHeadReferencePath())
	if err != nil {
		if os.IsNotExist(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	var treeSize uint64
	if err := cborx.UnmarshalLimit(data, &treeSize, maxStoredObjectBytes); err != nil {
		return 0, false, err
	}
	if treeSize == 0 {
		return 0, false, trusterr.New(trusterr.CodeDataLoss, "latest signed tree head reference is zero")
	}
	return treeSize, true, nil
}

func (s LocalStore) latestSignedTreeHeadLock() *sync.Mutex {
	return localStoreStripedLock(s.root(), &localLatestSTHLocks)
}

func (s LocalStore) latestRootLock() *sync.Mutex {
	return localStoreStripedLock(s.root(), &localLatestRootLocks)
}

func localStoreStripedLock(value string, locks *[64]sync.Mutex) *sync.Mutex {
	hash := uint64(14695981039346656037)
	for i := 0; i < len(value); i++ {
		hash ^= uint64(value[i])
		hash *= 1099511628211
	}
	return &locks[hash%uint64(len(locks))]
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
	tiles := make([]model.GlobalLogTile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdgtile") {
			continue
		}
		data, err := readStoredFile(filepath.Join(s.globalTileDir(), entry.Name()))
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
	tiles := make([]model.GlobalLogTile, 0, limit)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdgtile") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global tiles after canceled", err)
		}
		data, err := readStoredFile(filepath.Join(s.globalTileDir(), entry.Name()))
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
	if !isLocalGlobalOutboxStatus(item.Status) {
		return trusterr.New(trusterr.CodeInvalidArgument, "global log outbox status is invalid")
	}
	for _, status := range localGlobalOutboxStatusOrder {
		if _, err := os.Stat(s.globalOutboxPath(status, item.BatchID)); err == nil {
			return trusterr.New(trusterr.CodeAlreadyExists, "global log outbox item already exists")
		} else if !os.IsNotExist(err) {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stat global log outbox item", err)
		}
	}
	path := s.globalOutboxPath(item.Status, item.BatchID)
	if err := writeCBORAtomic(path, item); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write global log outbox item", err)
	}
	return nil
}

func (s LocalStore) ListPendingGlobalLog(ctx context.Context, nowUnixN int64, limit int) ([]model.GlobalLogOutboxItem, error) {
	return s.listGlobalLogOutbox(ctx, model.AnchorStatePending, limit, func(item model.GlobalLogOutboxItem) bool {
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
	entries, err := s.globalOutboxEntries(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]model.GlobalLogOutboxItem, 0, limit)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global log outbox after canceled", err)
		}
		if entry.batchID <= afterBatchID {
			continue
		}
		data, err := readStoredFile(entry.path)
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global log outbox item", err)
		}
		var item model.GlobalLogOutboxItem
		if err := cborx.UnmarshalLimit(data, &item, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log outbox item", err)
		}
		if item.BatchID != entry.batchID || item.Status != entry.status {
			return nil, trusterr.New(trusterr.CodeDataLoss, "global log outbox path does not match item")
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
	for _, status := range []string{model.AnchorStatePublished, model.AnchorStatePending} {
		item, ok, err := s.getGlobalLogOutboxItemAtStatus(batchID, status)
		if err != nil {
			return model.GlobalLogOutboxItem{}, false, err
		}
		if ok {
			return item, true, nil
		}
	}
	return model.GlobalLogOutboxItem{}, false, nil
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
	if err := writeCBORAtomic(s.globalOutboxPath(model.AnchorStatePublished, batchID), item); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "update global log outbox item", err)
	}
	if err := removeLocalFileDurable(s.globalOutboxPath(model.AnchorStatePending, batchID)); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "remove pending global log outbox item", err)
	}
	if err := s.promoteBatchRecords(ctx, batchID, "L4"); err != nil {
		return err
	}
	return nil
}

func (s LocalStore) RescheduleGlobalLog(ctx context.Context, batchID string, attempts int, nextAttemptUnixN int64, lastErrorMessage string) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore reschedule global log canceled", err)
	}
	if batchID == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "batch_id is required")
	}
	item, ok, err := s.getGlobalLogOutboxItemAtStatus(batchID, model.AnchorStatePending)
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
	if err := writeCBORAtomic(s.globalOutboxPath(model.AnchorStatePending, batchID), item); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "update global log outbox item", err)
	}
	return nil
}

func (s LocalStore) listGlobalLogOutbox(ctx context.Context, status string, limit int, include func(model.GlobalLogOutboxItem) bool) ([]model.GlobalLogOutboxItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global log outbox canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	entries, err := os.ReadDir(s.globalOutboxStatusDir(status))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global log outbox directory", err)
	}
	items := make([]model.GlobalLogOutboxItem, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdgoutbox") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global log outbox canceled", err)
		}
		data, err := readStoredFile(filepath.Join(s.globalOutboxStatusDir(status), entry.Name()))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global log outbox item", err)
		}
		var item model.GlobalLogOutboxItem
		if err := cborx.UnmarshalLimit(data, &item, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log outbox item", err)
		}
		if item.Status != status {
			return nil, trusterr.New(trusterr.CodeDataLoss, "global log outbox status directory does not match item")
		}
		if include(item) {
			if len(items) == 0 {
				items = make([]model.GlobalLogOutboxItem, 0, len(entries))
			}
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

type localGlobalOutboxEntry struct {
	batchID string
	status  string
	path    string
}

var localGlobalOutboxStatusOrder = [...]string{model.AnchorStatePending, model.AnchorStatePublished}

func isLocalGlobalOutboxStatus(status string) bool {
	return status == model.AnchorStatePending || status == model.AnchorStatePublished
}

func (s LocalStore) getGlobalLogOutboxItemAtStatus(batchID, status string) (model.GlobalLogOutboxItem, bool, error) {
	data, err := readStoredFile(s.globalOutboxPath(status, batchID))
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
	if item.BatchID != batchID || item.Status != status {
		return model.GlobalLogOutboxItem{}, false, trusterr.New(trusterr.CodeDataLoss, "global log outbox path does not match item")
	}
	return item, true, nil
}

func (s LocalStore) globalOutboxEntries(ctx context.Context) ([]localGlobalOutboxEntry, error) {
	byBatchID := make(map[string]localGlobalOutboxEntry)
	for _, status := range localGlobalOutboxStatusOrder {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global log outbox canceled", err)
		}
		dir := s.globalOutboxStatusDir(status)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read global log outbox directory", err)
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list global log outbox canceled", err)
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdgoutbox") {
				continue
			}
			batchID, err := decodeLocalIDFilename(entry.Name(), ".tdgoutbox")
			if err != nil {
				return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode global log outbox filename", err)
			}
			byBatchID[batchID] = localGlobalOutboxEntry{
				batchID: batchID,
				status:  status,
				path:    filepath.Join(dir, entry.Name()),
			}
		}
	}
	entries := make([]localGlobalOutboxEntry, 0, len(byBatchID))
	for _, entry := range byBatchID {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].batchID < entries[j].batchID })
	return entries, nil
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
	if !isLocalSTHAnchorStatus(item.Status) {
		return trusterr.New(trusterr.CodeInvalidArgument, "sth anchor outbox status is invalid")
	}
	for _, status := range localSTHAnchorStatusOrder {
		if _, err := os.Stat(s.sthAnchorOutboxPath(status, item.TreeSize)); err == nil {
			return trusterr.New(trusterr.CodeAlreadyExists, "sth anchor outbox item already exists")
		} else if !os.IsNotExist(err) {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stat sth anchor outbox item", err)
		}
	}
	path := s.sthAnchorOutboxPath(item.Status, item.TreeSize)
	if err := writeCBORAtomic(path, item); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write sth anchor outbox item", err)
	}
	return nil
}

func (s LocalStore) ListPendingSTHAnchors(ctx context.Context, nowUnixN int64, limit int) ([]model.STHAnchorOutboxItem, error) {
	items, err := s.listSTHAnchors(ctx, model.AnchorStatePending, limit, func(item model.STHAnchorOutboxItem) bool {
		return item.Status == model.AnchorStatePending && item.NextAttemptUnixN <= nowUnixN
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s LocalStore) ListPublishedSTHAnchors(ctx context.Context, limit int) ([]model.STHAnchorOutboxItem, error) {
	return s.listSTHAnchors(ctx, model.AnchorStatePublished, limit, func(item model.STHAnchorOutboxItem) bool {
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
	for _, status := range []string{model.AnchorStatePublished, model.AnchorStateFailed, model.AnchorStatePending} {
		item, ok, err := s.getSTHAnchorOutboxItemAtStatus(treeSize, status)
		if err != nil {
			return model.STHAnchorOutboxItem{}, false, err
		}
		if ok {
			return item, true, nil
		}
	}
	return model.STHAnchorOutboxItem{}, false, nil
}

func (s LocalStore) ListSTHAnchorOutboxItemsAfter(ctx context.Context, afterTreeSize uint64, limit int) ([]model.STHAnchorOutboxItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor outbox after canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	entries, err := s.sthAnchorOutboxEntries(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]model.STHAnchorOutboxItem, 0, limit)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor outbox after canceled", err)
		}
		if entry.treeSize <= afterTreeSize {
			continue
		}
		data, err := readStoredFile(entry.path)
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor outbox item", err)
		}
		var item model.STHAnchorOutboxItem
		if err := cborx.UnmarshalLimit(data, &item, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode sth anchor outbox item", err)
		}
		if item.TreeSize != entry.treeSize || item.Status != entry.status {
			return nil, trusterr.New(trusterr.CodeDataLoss, "sth anchor outbox path does not match item")
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
	entries, err := s.sthAnchorOutboxEntries(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]model.STHAnchorOutboxItem, 0, min(limit, len(entries)))
	start, end, step := sthAnchorPageRange(entries, opts)
	for i := start; i != end && len(items) < limit; i += step {
		entry := entries[i]
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchors page canceled", err)
		}
		data, err := readStoredFile(entry.path)
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor outbox item", err)
		}
		var item model.STHAnchorOutboxItem
		if err := cborx.UnmarshalLimit(data, &item, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode sth anchor outbox item", err)
		}
		if item.TreeSize != entry.treeSize || item.Status != entry.status {
			return nil, trusterr.New(trusterr.CodeDataLoss, "sth anchor outbox path does not match item")
		}
		items = append(items, item)
	}
	return items, nil
}

func (s LocalStore) RescheduleSTHAnchor(ctx context.Context, treeSize uint64, attempts int, nextAttemptUnixN int64, lastErrorMessage string) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore reschedule sth anchor canceled", err)
	}
	if treeSize == 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "tree_size is required")
	}
	item, ok, err := s.getSTHAnchorOutboxItemAtStatus(treeSize, model.AnchorStatePending)
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
	if err := writeCBORAtomic(s.sthAnchorOutboxPath(model.AnchorStatePending, treeSize), item); err != nil {
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
	if err := writeCBORAtomic(s.sthAnchorOutboxPath(model.AnchorStatePublished, result.TreeSize), item); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "update sth anchor outbox item", err)
	}
	for _, status := range []string{model.AnchorStatePending, model.AnchorStateFailed} {
		if err := removeLocalFileDurable(s.sthAnchorOutboxPath(status, result.TreeSize)); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "remove previous sth anchor outbox item", err)
		}
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
	if err := writeCBORAtomic(s.sthAnchorOutboxPath(model.AnchorStateFailed, treeSize), item); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "update sth anchor outbox item", err)
	}
	for _, status := range []string{model.AnchorStatePending, model.AnchorStatePublished} {
		if err := removeLocalFileDurable(s.sthAnchorOutboxPath(status, treeSize)); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "remove previous sth anchor outbox item", err)
		}
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
	data, err := readStoredFile(s.sthAnchorResultPath(treeSize))
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

func (s LocalStore) listSTHAnchors(ctx context.Context, status string, limit int, include func(model.STHAnchorOutboxItem) bool) ([]model.STHAnchorOutboxItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchors canceled", err)
	}
	if limit <= 0 {
		limit = 100
	}
	entries, err := os.ReadDir(s.sthAnchorOutboxStatusDir(status))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor outbox directory", err)
	}
	items := make([]model.STHAnchorOutboxItem, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdsth-anchor") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchors canceled", err)
		}
		data, err := readStoredFile(filepath.Join(s.sthAnchorOutboxStatusDir(status), entry.Name()))
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor outbox item", err)
		}
		var item model.STHAnchorOutboxItem
		if err := cborx.UnmarshalLimit(data, &item, maxStoredObjectBytes); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode sth anchor outbox item", err)
		}
		if item.Status != status {
			return nil, trusterr.New(trusterr.CodeDataLoss, "sth anchor status directory does not match item")
		}
		if include(item) {
			if len(items) == 0 {
				items = make([]model.STHAnchorOutboxItem, 0, len(entries))
			}
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

type localSTHAnchorOutboxEntry struct {
	treeSize uint64
	status   string
	path     string
}

var localSTHAnchorStatusOrder = [...]string{model.AnchorStatePending, model.AnchorStateFailed, model.AnchorStatePublished}

func isLocalSTHAnchorStatus(status string) bool {
	return status == model.AnchorStatePending || status == model.AnchorStatePublished || status == model.AnchorStateFailed
}

func (s LocalStore) getSTHAnchorOutboxItemAtStatus(treeSize uint64, status string) (model.STHAnchorOutboxItem, bool, error) {
	data, err := readStoredFile(s.sthAnchorOutboxPath(status, treeSize))
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
	if item.TreeSize != treeSize || item.Status != status {
		return model.STHAnchorOutboxItem{}, false, trusterr.New(trusterr.CodeDataLoss, "sth anchor outbox path does not match item")
	}
	return item, true, nil
}

func (s LocalStore) sthAnchorOutboxEntries(ctx context.Context) ([]localSTHAnchorOutboxEntry, error) {
	byTreeSize := make(map[uint64]localSTHAnchorOutboxEntry)
	for _, status := range localSTHAnchorStatusOrder {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor outbox canceled", err)
		}
		dir := s.sthAnchorOutboxStatusDir(status)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor outbox directory", err)
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor outbox canceled", err)
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tdsth-anchor") {
				continue
			}
			treeSize, err := decodeLocalUint64Filename(entry.Name(), ".tdsth-anchor")
			if err != nil {
				return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode sth anchor outbox filename", err)
			}
			if treeSize == 0 {
				return nil, trusterr.New(trusterr.CodeDataLoss, "sth anchor outbox filename has zero tree size")
			}
			byTreeSize[treeSize] = localSTHAnchorOutboxEntry{treeSize: treeSize, status: status, path: filepath.Join(dir, entry.Name())}
		}
	}
	entries := make([]localSTHAnchorOutboxEntry, 0, len(byTreeSize))
	for _, entry := range byTreeSize {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].treeSize < entries[j].treeSize })
	return entries, nil
}

func sthAnchorPageRange(entries []localSTHAnchorOutboxEntry, opts model.AnchorListOptions) (start, end, step int) {
	ascending := strings.EqualFold(opts.Direction, model.RecordListDirectionAsc)
	if ascending {
		if opts.AfterTreeSize > 0 {
			start = sort.Search(len(entries), func(i int) bool { return entries[i].treeSize > opts.AfterTreeSize })
		}
		return start, len(entries), 1
	}
	upper := len(entries)
	if opts.AfterTreeSize > 0 {
		upper = sort.Search(len(entries), func(i int) bool { return entries[i].treeSize >= opts.AfterTreeSize })
	}
	return upper - 1, -1, -1
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

func (s LocalStore) latestSignedTreeHeadReferencePath() string {
	return filepath.Join(s.root(), "global", "latest-sth.tdref")
}

func (s LocalStore) globalTileDir() string {
	return filepath.Join(s.root(), "global", "tiles")
}

func (s LocalStore) globalOutboxDir() string {
	return filepath.Join(s.root(), "global", "outbox")
}

func (s LocalStore) globalOutboxStatusDir(status string) string {
	return filepath.Join(s.globalOutboxDir(), status)
}

func (s LocalStore) sthAnchorOutboxDir() string {
	return filepath.Join(s.root(), "anchor", "sth-outbox")
}

func (s LocalStore) sthAnchorOutboxStatusDir(status string) string {
	return filepath.Join(s.sthAnchorOutboxDir(), status)
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

func (s LocalStore) globalOutboxPath(status, batchID string) string {
	return filepath.Join(s.globalOutboxStatusDir(status), safeFileName(batchID)+".tdgoutbox")
}

func (s LocalStore) sthAnchorOutboxPath(status string, treeSize uint64) string {
	return filepath.Join(s.sthAnchorOutboxStatusDir(status), fmt.Sprintf("%020d.tdsth-anchor", treeSize))
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

func (s LocalStore) bundlePath(recordID string) string {
	return filepath.Join(s.bundleDir(), safeFileName(recordID)+".tdproof")
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
	return fmt.Sprintf("%0*d_%s.tdrecord", localPositionWidth, idx.ReceivedAtUnixN, safeFileName(idx.RecordID))
}

func (s LocalStore) rootDir() string {
	return filepath.Join(s.root(), "roots")
}

func (s LocalStore) rootPath(closedAtUnixN int64, batchID string) string {
	name := fmt.Sprintf("%0*d_%s.tdroot", localPositionWidth, closedAtUnixN, safeFileName(batchID))
	return filepath.Join(s.rootDir(), name)
}

func (s LocalStore) latestRootReferencePath() string {
	return filepath.Join(s.rootDir(), "latest.tdroot-ref")
}

func (s LocalStore) manifestDir() string {
	return filepath.Join(s.root(), "manifests")
}

func (s LocalStore) manifestPath(batchID string) string {
	return filepath.Join(s.manifestDir(), safeFileName(batchID)+".tdmanifest")
}

func (s LocalStore) root() string {
	if s.Root == "" {
		return ".trustdb/proofs"
	}
	return s.Root
}

func writeCBORAtomic(path string, value any) error {
	return writeCBORAtomicWithOps(path, value, defaultLocalFileOps())
}

func removeLocalFileDurable(path string) error {
	return removeLocalFileDurableWithOps(path, defaultLocalFileOps())
}

func removeLocalFileDurableWithOps(path string, ops localFileOps) error {
	if err := ops.remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := ops.syncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync proofstore directory after removing %q: %w", path, err)
	}
	return nil
}

func writeCBORAtomicWithOps(path string, value any, ops localFileOps) error {
	data, err := cborx.Marshal(value)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := ensureLocalDurableDirectory(dir, 0o755, ops); err != nil {
		return err
	}

	tmp, err := ops.createTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = ops.remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return errors.Join(err, ops.closeFile(tmp))
	}
	if err := ops.syncFile(tmp); err != nil {
		return errors.Join(err, ops.closeFile(tmp))
	}
	if err := ops.closeFile(tmp); err != nil {
		return err
	}
	if err := rejectDirectoryTarget(path); err != nil {
		return err
	}
	if err := ops.replace(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	if err := ops.syncDir(dir); err != nil {
		return fmt.Errorf("sync proofstore directory %q after publishing %q: %w", dir, path, err)
	}
	return nil
}

func ensureLocalDurableDirectory(path string, perm os.FileMode, ops localFileOps) error {
	clean := filepath.Clean(path)
	if ops.cacheDirs {
		if _, ok := localDurableDirectories.Load(clean); ok {
			return nil
		}
	}
	missing := make([]string, 0, 4)
	var boundary string
	for current := clean; ; current = filepath.Dir(current) {
		info, err := ops.stat(current)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("proofstore path component %q is not a directory", current)
			}
			boundary = current
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat proofstore directory %q: %w", current, err)
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("no existing parent for proofstore directory %q", clean)
		}
	}
	if parent := filepath.Dir(boundary); parent != boundary {
		if err := ops.syncDir(parent); err != nil {
			return fmt.Errorf("sync parent directory %q for proofstore boundary %q: %w", parent, boundary, err)
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		component := missing[i]
		if err := ops.mkdir(component, perm); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("create proofstore directory %q: %w", component, err)
			}
			info, statErr := ops.stat(component)
			if statErr != nil {
				return fmt.Errorf("stat concurrently created proofstore directory %q: %w", component, statErr)
			}
			if !info.IsDir() {
				return fmt.Errorf("concurrently created proofstore path %q is not a directory", component)
			}
		}
		parent := filepath.Dir(component)
		if err := ops.syncDir(parent); err != nil {
			return fmt.Errorf("sync parent directory %q after creating %q: %w", parent, component, err)
		}
	}
	if ops.cacheDirs {
		localDurableDirectories.Store(clean, struct{}{})
	}
	return nil
}

func rejectDirectoryTarget(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return fmt.Errorf("%s is a directory", path)
		}
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func readStoredFile(path string) ([]byte, error) {
	return readStoredFileLimit(path, maxStoredObjectBytes)
}

func readStoredFileLimit(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("max stored object bytes must be positive")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("stored object too large: %d > %d", len(data), maxBytes)
	}
	return data, nil
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

func sortedDirectoryPageRange(length int, direction string) (start, end, step int) {
	if strings.EqualFold(direction, model.RecordListDirectionAsc) {
		return 0, length, 1
	}
	return length - 1, -1, -1
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
		data, err := readStoredFile(filepath.Join(s.recordByBatchDir(batchID), entry.Name()))
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
	if isPlainSafeFileName(value) {
		return value
	}
	return encodedFileNamePrefix + base64.RawURLEncoding.EncodeToString([]byte(value))
}

type localRecordIndexEntry struct {
	name            string
	receivedAtUnixN int64
	recordID        string
}

func orderedRecordIndexEntries(entries []os.DirEntry) ([]localRecordIndexEntry, error) {
	const suffix = ".tdrecord"
	ordered := make([]localRecordIndexEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), suffix) {
			continue
		}
		receivedAtUnixN, recordID, err := decodeLocalPositionFilename(entry.Name(), suffix)
		if err != nil {
			return nil, err
		}
		ordered = append(ordered, localRecordIndexEntry{
			name:            entry.Name(),
			receivedAtUnixN: receivedAtUnixN,
			recordID:        recordID,
		})
	}
	sort.Slice(ordered, func(i, j int) bool {
		return model.CompareRecordPosition(
			ordered[i].receivedAtUnixN,
			ordered[i].recordID,
			ordered[j].receivedAtUnixN,
			ordered[j].recordID,
		) < 0
	})
	return ordered, nil
}

type localRootEntry struct {
	name          string
	closedAtUnixN int64
	batchID       string
}

type localManifestEntry struct {
	name    string
	batchID string
}

type localGlobalNodeEntry struct {
	name       string
	level      uint64
	startIndex uint64
}

func orderedGlobalNodeEntries(entries []os.DirEntry) ([]localGlobalNodeEntry, error) {
	const suffix = ".tdgnode"
	ordered := make([]localGlobalNodeEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), suffix) {
			continue
		}
		level, startIndex, err := decodeLocalUint64PositionFilename(entry.Name(), suffix)
		if err != nil {
			return nil, err
		}
		ordered = append(ordered, localGlobalNodeEntry{name: entry.Name(), level: level, startIndex: startIndex})
	}
	return ordered, nil
}

func orderedManifestEntries(entries []os.DirEntry) ([]localManifestEntry, error) {
	const suffix = ".tdmanifest"
	ordered := make([]localManifestEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), suffix) {
			continue
		}
		batchID, err := decodeLocalIDFilename(entry.Name(), suffix)
		if err != nil {
			return nil, err
		}
		ordered = append(ordered, localManifestEntry{name: entry.Name(), batchID: batchID})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].batchID < ordered[j].batchID })
	return ordered, nil
}

func orderedRootEntries(entries []os.DirEntry) ([]localRootEntry, error) {
	const suffix = ".tdroot"
	ordered := make([]localRootEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), suffix) {
			continue
		}
		closedAtUnixN, batchID, err := decodeLocalPositionFilename(entry.Name(), suffix)
		if err != nil {
			return nil, err
		}
		ordered = append(ordered, localRootEntry{name: entry.Name(), closedAtUnixN: closedAtUnixN, batchID: batchID})
	}
	sort.Slice(ordered, func(i, j int) bool {
		return model.CompareBatchRootPosition(ordered[i].closedAtUnixN, ordered[i].batchID, ordered[j].closedAtUnixN, ordered[j].batchID) < 0
	})
	return ordered, nil
}

func decodeLocalPositionFilename(name, suffix string) (int64, string, error) {
	base := strings.TrimSuffix(name, suffix)
	if len(base) <= localPositionWidth+1 || base[localPositionWidth] != '_' {
		return 0, "", fmt.Errorf("invalid position filename %q", name)
	}
	timestamp, err := strconv.ParseInt(base[:localPositionWidth], 10, 64)
	if err != nil || timestamp < 0 {
		return 0, "", fmt.Errorf("invalid timestamp in position filename %q", name)
	}
	encodedID := base[localPositionWidth+1:]
	id, err := decodeSafeFileName(encodedID)
	if err != nil || id == "" || safeFileName(id) != encodedID {
		return 0, "", fmt.Errorf("invalid id in position filename %q", name)
	}
	return timestamp, id, nil
}

func decodeLocalIDFilename(name, suffix string) (string, error) {
	encodedID := strings.TrimSuffix(name, suffix)
	id, err := decodeSafeFileName(encodedID)
	if err != nil || id == "" || safeFileName(id) != encodedID {
		return "", fmt.Errorf("invalid id filename %q", name)
	}
	return id, nil
}

func decodeLocalUint64PositionFilename(name, suffix string) (uint64, uint64, error) {
	base := strings.TrimSuffix(name, suffix)
	if len(base) != 2*localPositionWidth+1 || base[localPositionWidth] != '_' {
		return 0, 0, fmt.Errorf("invalid uint64 position filename %q", name)
	}
	first, err := strconv.ParseUint(base[:localPositionWidth], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid first position in filename %q", name)
	}
	second, err := strconv.ParseUint(base[localPositionWidth+1:], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid second position in filename %q", name)
	}
	return first, second, nil
}

func decodeLocalUint64Filename(name, suffix string) (uint64, error) {
	base := strings.TrimSuffix(name, suffix)
	value, err := strconv.ParseUint(base, 10, 64)
	if err != nil || fmt.Sprintf("%0*d%s", localPositionWidth, value, suffix) != name {
		return 0, fmt.Errorf("invalid uint64 filename %q", name)
	}
	return value, nil
}

func decodeSafeFileName(value string) (string, error) {
	if !strings.HasPrefix(value, encodedFileNamePrefix) {
		return value, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, encodedFileNamePrefix))
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func recordIndexPageRange(entries []localRecordIndexEntry, opts model.RecordListOptions) (start, end, step int) {
	lower, upper := 0, len(entries)
	if opts.ReceivedFromUnixN > 0 {
		lower = sort.Search(len(entries), func(i int) bool {
			return entries[i].receivedAtUnixN >= opts.ReceivedFromUnixN
		})
	}
	if opts.ReceivedToUnixN > 0 {
		upper = sort.Search(len(entries), func(i int) bool {
			return entries[i].receivedAtUnixN > opts.ReceivedToUnixN
		})
	}
	hasCursor := opts.AfterReceivedAtUnixN != 0 || opts.AfterRecordID != ""
	asc := strings.EqualFold(opts.Direction, model.RecordListDirectionAsc)
	if hasCursor && asc {
		cursor := sort.Search(len(entries), func(i int) bool {
			return model.CompareRecordPosition(entries[i].receivedAtUnixN, entries[i].recordID, opts.AfterReceivedAtUnixN, opts.AfterRecordID) > 0
		})
		lower = max(lower, cursor)
	}
	if hasCursor && !asc {
		cursor := sort.Search(len(entries), func(i int) bool {
			return model.CompareRecordPosition(entries[i].receivedAtUnixN, entries[i].recordID, opts.AfterReceivedAtUnixN, opts.AfterRecordID) >= 0
		})
		upper = min(upper, cursor)
	}
	if lower > upper {
		lower = upper
	}
	if asc {
		return lower, upper, 1
	}
	return upper - 1, lower - 1, -1
}

func rootPageRange(entries []localRootEntry, opts model.RootListOptions) (start, end, step int) {
	upper := len(entries)
	hasCursor := opts.AfterClosedAtUnixN != 0 || opts.AfterBatchID != ""
	asc := strings.EqualFold(opts.Direction, model.RecordListDirectionAsc)
	if asc {
		if hasCursor {
			start = sort.Search(len(entries), func(i int) bool {
				return model.CompareBatchRootPosition(entries[i].closedAtUnixN, entries[i].batchID, opts.AfterClosedAtUnixN, opts.AfterBatchID) > 0
			})
		}
		return start, upper, 1
	}
	if hasCursor {
		upper = sort.Search(len(entries), func(i int) bool {
			return model.CompareBatchRootPosition(entries[i].closedAtUnixN, entries[i].batchID, opts.AfterClosedAtUnixN, opts.AfterBatchID) >= 0
		})
	}
	return upper - 1, -1, -1
}

func isPlainSafeFileName(value string) bool {
	if value == "" || value == "." || value == ".." || strings.HasPrefix(value, ".") {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func recordTokenPart(value string) string {
	if value == "" {
		return "_"
	}
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}
