package proofstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/l5coverage"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const (
	maxStoredObjectBytes      = 64 << 20
	encodedFileNamePrefix     = "~"
	localPositionWidth        = 20
	localAnchorScheduleSuffix = ".tdsth-anchor-schedule"
	localAnchorSchedulePrefix = "v1_"
	localAnchorResultSuffix   = ".tdsth-anchor-result"
	localAnchorResultPrefix   = "v2_"
	localAnchorTreeRefSuffix  = ".tdsth-anchor-tree-ref"
	localAnchorLatestSuffix   = ".tdsth-anchor-latest"
	localAnchorTreeRootSuffix = ".tdsth-anchor-tree-root"
	localL5CoverageSuffix     = ".tdl5-coverage"
	localAnchorPublishSuffix  = ".tdanchor-publish-journal"
	localAnchorPublishSchema  = "trustdb.local-anchor-publish-journal.v1"
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
var localLatestAnchorLocks [64]sync.Mutex
var localSTHAnchorScheduleLocks [64]sync.Mutex
var localSTHAnchorTreeRootLocks [64]sync.Mutex
var localL5CoverageLocks [64]sync.Mutex

type localLatestAnchorReference struct {
	Candidate model.STHAnchorLatestReference  `cbor:"candidate"`
	Previous  *model.STHAnchorLatestReference `cbor:"previous,omitempty"`
}

type localSTHAnchorResultEntry struct {
	name string
	key  model.STHAnchorResultKey
}

type localAnchorPublicationJournal struct {
	SchemaVersion string                     `cbor:"schema_version"`
	Key           model.STHAnchorScheduleKey `cbor:"key"`
	BatchIDs      []string                   `cbor:"batch_ids"`
	STHs          []model.SignedTreeHead     `cbor:"sths"`
	Schedule      model.STHAnchorSchedule    `cbor:"schedule"`
}

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
	state, ok, err := s.GetGlobalLogState(ctx)
	if err != nil {
		return nil, err
	}
	if ok {
		return s.listCommittedGlobalLeavesPage(ctx, state.TreeSize, opts, limit)
	}
	return s.listGlobalLeavesPageFromDirectory(ctx, opts, limit)
}

func (s LocalStore) listCommittedGlobalLeavesPage(ctx context.Context, treeSize uint64, opts model.GlobalLeafListOptions, limit int) ([]model.GlobalLogLeaf, error) {
	capacity := limit
	if treeSize < uint64(capacity) {
		capacity = int(treeSize)
	}
	leaves := make([]model.GlobalLogLeaf, 0, capacity)
	if strings.EqualFold(opts.Direction, model.RecordListDirectionAsc) {
		start := uint64(0)
		if opts.AfterLeafIndex > 0 {
			if opts.AfterLeafIndex == ^uint64(0) {
				return leaves, nil
			}
			start = opts.AfterLeafIndex + 1
		}
		for index := start; index < treeSize && len(leaves) < limit; index++ {
			leaf, err := s.readCommittedGlobalLeaf(ctx, index)
			if err != nil {
				return nil, err
			}
			leaves = append(leaves, leaf)
		}
		return leaves, nil
	}

	upper := treeSize
	if opts.AfterLeafIndex > 0 && opts.AfterLeafIndex < upper {
		upper = opts.AfterLeafIndex
	}
	for upper > 0 && len(leaves) < limit {
		index := upper - 1
		leaf, err := s.readCommittedGlobalLeaf(ctx, index)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, leaf)
		upper = index
	}
	return leaves, nil
}

func (s LocalStore) readCommittedGlobalLeaf(ctx context.Context, index uint64) (model.GlobalLogLeaf, error) {
	leaf, ok, err := s.GetGlobalLeaf(ctx, index)
	if err != nil {
		return model.GlobalLogLeaf{}, err
	}
	if !ok {
		return model.GlobalLogLeaf{}, trusterr.New(trusterr.CodeDataLoss, "committed global log leaf is missing")
	}
	if leaf.LeafIndex != index {
		return model.GlobalLogLeaf{}, trusterr.New(trusterr.CodeDataLoss, "global log leaf index does not match path")
	}
	return leaf, nil
}

func (s LocalStore) listGlobalLeavesPageFromDirectory(ctx context.Context, opts model.GlobalLeafListOptions, limit int) ([]model.GlobalLogLeaf, error) {
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

func (s LocalStore) latestSTHAnchorLock() *sync.Mutex {
	return localStoreStripedLock(s.root(), &localLatestAnchorLocks)
}

func (s LocalStore) sthAnchorScheduleLock(key model.STHAnchorScheduleKey) *sync.Mutex {
	return localStoreStripedLock(s.root()+"\x00"+encodeLocalSTHAnchorScheduleFilename(key), &localSTHAnchorScheduleLocks)
}

func (s LocalStore) sthAnchorTreeRootLock(nodeID, logID string, treeSize uint64) *sync.Mutex {
	return localStoreStripedLock(s.root()+"\x00"+encodeLocalSTHAnchorTreeRootFilename(nodeID, logID, treeSize), &localSTHAnchorTreeRootLocks)
}

func (s LocalStore) l5CoverageLock(key model.STHAnchorScheduleKey) *sync.Mutex {
	return localStoreStripedLock(s.root()+"\x00"+encodeLocalL5CoverageFilename(key), &localL5CoverageLocks)
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

func (s LocalStore) ListPendingGlobalLogForStream(ctx context.Context, nodeID, logID string, nowUnixN int64, limit int) ([]model.GlobalLogOutboxItem, error) {
	return s.listGlobalLogOutbox(ctx, model.AnchorStatePending, limit, func(item model.GlobalLogOutboxItem) bool {
		return item.Status == model.AnchorStatePending &&
			item.NextAttemptUnixN <= nowUnixN &&
			item.BatchRoot.NodeID == nodeID &&
			item.BatchRoot.LogID == logID
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

func (s LocalStore) MarkGlobalLogPublishedBatchWithAnchorCandidate(ctx context.Context, batchIDs []string, sths []model.SignedTreeHead, candidate model.STHAnchorCandidate) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore mark global log batch published with anchor candidate canceled", err)
	}
	if len(batchIDs) == 0 || len(batchIDs) != len(sths) {
		return trusterr.New(trusterr.CodeInvalidArgument, "global log published batch inputs are inconsistent")
	}
	if err := anchorschedule.ValidateCandidate(candidate); err != nil {
		return err
	}
	_, highest, err := anchorschedule.SelectPublicationTargets(sths, 0)
	if err != nil {
		return err
	}
	if !anchorschedule.SameTarget(candidate.STH, highest) {
		return trusterr.New(trusterr.CodeInvalidArgument, "anchor candidate must be the highest published STH")
	}

	lock := s.sthAnchorScheduleLock(candidate.Key)
	lock.Lock()
	defer lock.Unlock()
	if err := s.replayLocalAnchorPublicationLocked(candidate.Key); err != nil {
		return err
	}

	for i := range batchIDs {
		if batchIDs[i] == "" || sths[i].TreeSize == 0 {
			return trusterr.New(trusterr.CodeInvalidArgument, "global log published batch item is invalid")
		}
		globalItem, ok, err := s.GetGlobalLogOutboxItem(ctx, batchIDs[i])
		if err != nil {
			return err
		}
		if !ok {
			return trusterr.New(trusterr.CodeNotFound, "global log outbox item not found")
		}
		if globalItem.Status == model.AnchorStatePublished && !sameLocalSignedTreeHead(globalItem.STH, sths[i]) {
			return trusterr.New(trusterr.CodeDataLoss, "published global log outbox STH does not match retry")
		}
	}

	schedule, _, err := s.mergeSTHAnchorCandidateLocked(ctx, candidate)
	if err != nil {
		return err
	}
	journal := localAnchorPublicationJournal{
		SchemaVersion: localAnchorPublishSchema,
		Key:           candidate.Key,
		BatchIDs:      append([]string(nil), batchIDs...),
		STHs:          append([]model.SignedTreeHead(nil), sths...),
		Schedule:      schedule,
	}
	for i := range journal.STHs {
		journal.STHs[i] = cloneLocalSignedTreeHead(journal.STHs[i])
	}
	if err := writeCBORAtomic(s.sthAnchorPublicationJournalPath(candidate.Key), journal); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write global publication anchor journal", err)
	}
	return s.applyLocalAnchorPublicationLocked(candidate.Key, journal)
}

func (s LocalStore) replayLocalAnchorPublicationLocked(key model.STHAnchorScheduleKey) error {
	data, err := readStoredFile(s.sthAnchorPublicationJournalPath(key))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return trusterr.Wrap(trusterr.CodeDataLoss, "read global publication anchor journal", err)
	}
	var journal localAnchorPublicationJournal
	if err := cborx.UnmarshalLimit(data, &journal, maxStoredObjectBytes); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "decode global publication anchor journal", err)
	}
	return s.applyLocalAnchorPublicationLocked(key, journal)
}

func (s LocalStore) applyLocalAnchorPublicationLocked(expectedKey model.STHAnchorScheduleKey, journal localAnchorPublicationJournal) error {
	if journal.SchemaVersion != localAnchorPublishSchema || !anchorschedule.SameKey(expectedKey, journal.Key) || !anchorschedule.SameKey(journal.Key, journal.Schedule.Key) || len(journal.BatchIDs) == 0 || len(journal.BatchIDs) != len(journal.STHs) {
		return trusterr.New(trusterr.CodeDataLoss, "global publication anchor journal is invalid")
	}
	if err := anchorschedule.ValidateSchedule(journal.Schedule); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "global publication anchor journal schedule is invalid", err)
	}
	current, found, err := s.getSTHAnchorSchedule(journal.Key)
	if err != nil {
		return err
	}
	if found && current.Revision > journal.Schedule.Revision {
		return trusterr.New(trusterr.CodeDataLoss, "global publication anchor journal would regress schedule")
	}
	if !found || current.Revision < journal.Schedule.Revision {
		if err := s.writeSTHAnchorSchedule(journal.Schedule); err != nil {
			return err
		}
	} else if !reflect.DeepEqual(current, journal.Schedule) {
		return trusterr.New(trusterr.CodeDataLoss, "global publication anchor journal conflicts with schedule")
	}
	ctx := context.Background()
	for i := range journal.BatchIDs {
		item, ok, err := s.GetGlobalLogOutboxItem(ctx, journal.BatchIDs[i])
		if err != nil {
			return err
		}
		if !ok {
			return trusterr.New(trusterr.CodeNotFound, "global log outbox item not found during journal replay")
		}
		if item.Status == model.AnchorStatePublished {
			if !sameLocalSignedTreeHead(item.STH, journal.STHs[i]) {
				return trusterr.New(trusterr.CodeDataLoss, "published global log outbox STH conflicts with journal")
			}
		} else {
			now := time.Now().UTC().UnixNano()
			item.Status = model.AnchorStatePublished
			item.STH = journal.STHs[i]
			item.LastErrorMessage = ""
			item.LastAttemptUnixN = now
			item.NextAttemptUnixN = 0
			item.CompletedAtUnixN = now
			if err := writeCBORAtomic(s.globalOutboxPath(model.AnchorStatePublished, item.BatchID), item); err != nil {
				return trusterr.Wrap(trusterr.CodeDataLoss, "publish global log outbox journal item", err)
			}
		}
		if err := removeLocalFileDurable(s.globalOutboxPath(model.AnchorStatePending, item.BatchID)); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "remove pending global log journal item", err)
		}
		if err := s.promoteBatchRecords(ctx, journal.BatchIDs[i], "L4"); err != nil {
			return err
		}
	}
	if err := removeLocalFileDurable(s.sthAnchorPublicationJournalPath(journal.Key)); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "clear global publication anchor journal", err)
	}
	return nil
}

func cloneLocalSignedTreeHead(sth model.SignedTreeHead) model.SignedTreeHead {
	sth.RootHash = append([]byte(nil), sth.RootHash...)
	sth.Signature.Signature = append([]byte(nil), sth.Signature.Signature...)
	return sth
}

func sameLocalSignedTreeHead(left, right model.SignedTreeHead) bool {
	return left.SchemaVersion == right.SchemaVersion &&
		left.TreeAlg == right.TreeAlg &&
		left.TreeSize == right.TreeSize &&
		bytes.Equal(left.RootHash, right.RootHash) &&
		left.TimestampUnixN == right.TimestampUnixN &&
		left.NodeID == right.NodeID &&
		left.LogID == right.LogID &&
		left.Signature.Alg == right.Signature.Alg &&
		left.Signature.KeyID == right.Signature.KeyID &&
		bytes.Equal(left.Signature.Signature, right.Signature.Signature)
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

func (s LocalStore) GetSTHAnchorResult(ctx context.Context, treeSize uint64) (model.STHAnchorResult, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get sth anchor result canceled", err)
	}
	if treeSize == 0 {
		return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeInvalidArgument, "tree_size is required")
	}
	lock := s.latestSTHAnchorLock()
	lock.Lock()
	defer lock.Unlock()
	return s.sthAnchorResultForTreeLocked(treeSize)
}

// PutSTHAnchorResult persists a successful anchor independently of mutable
// scheduler state. Successful results are immutable by cryptographic binding:
// an idempotent retry may carry older proof metadata, but it must never replace
// proof bytes that may already have been enriched by a sink-specific upgrader.
func (s LocalStore) PutSTHAnchorResult(ctx context.Context, result model.STHAnchorResult) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put sth anchor result canceled", err)
	}
	key := model.STHAnchorScheduleKey{NodeID: result.NodeID, LogID: result.LogID, SinkName: result.SinkName}
	if err := anchorschedule.ValidateResult(key, result); err != nil {
		return err
	}
	lock := s.sthAnchorScheduleLock(key)
	lock.Lock()
	defer lock.Unlock()
	if err := s.replayLocalAnchorPublicationLocked(key); err != nil {
		return err
	}
	return s.putSTHAnchorResultLocked(ctx, result)
}

func (s LocalStore) UpdateSTHAnchorResult(ctx context.Context, expected, result model.STHAnchorResult) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore update sth anchor result canceled", err)
	}
	key := model.STHAnchorScheduleKey{NodeID: result.NodeID, LogID: result.LogID, SinkName: result.SinkName}
	if err := anchorschedule.ValidateResult(key, result); err != nil {
		return err
	}
	expectedKey := model.STHAnchorScheduleKey{NodeID: expected.NodeID, LogID: expected.LogID, SinkName: expected.SinkName}
	if err := anchorschedule.ValidateResult(expectedKey, expected); err != nil {
		return err
	}
	if !anchorschedule.SameResultBinding(expected, result) {
		return trusterr.New(trusterr.CodeDataLoss, "sth anchor result update changes immutable binding")
	}
	expectedUpdate := expected
	expectedUpdate.Proof = append([]byte(nil), result.Proof...)
	if !reflect.DeepEqual(expectedUpdate, result) {
		return trusterr.New(trusterr.CodeDataLoss, "sth anchor result update changes immutable metadata")
	}
	lock := s.sthAnchorScheduleLock(key)
	lock.Lock()
	defer lock.Unlock()
	if err := s.replayLocalAnchorPublicationLocked(key); err != nil {
		return err
	}
	latestLock := s.latestSTHAnchorLock()
	latestLock.Lock()
	defer latestLock.Unlock()
	existing, found, err := s.readSTHAnchorResult(anchorschedule.ResultKey(result))
	if err != nil {
		return err
	}
	if !found {
		return trusterr.New(trusterr.CodeNotFound, "sth anchor result not found")
	}
	if !reflect.DeepEqual(existing, expected) {
		return trusterr.New(trusterr.CodeFailedPrecondition, "sth anchor result changed concurrently")
	}
	if err := s.prepareLatestSTHAnchorReferencesLocked(ctx, result); err != nil {
		return err
	}
	if err := writeCBORAtomic(s.sthAnchorResultPath(anchorschedule.ResultKey(result)), result); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "update sth anchor result", err)
	}
	return s.ensureSTHAnchorTreeReferenceLocked(result)
}

// putSTHAnchorResultLocked requires the schedule stripe for result's key. It
// updates the crash-safe latest reference before publishing a new result, so a
// crash can always fall back to the previous complete reference.
func (s LocalStore) putSTHAnchorResultLocked(ctx context.Context, result model.STHAnchorResult) error {
	latestLock := s.latestSTHAnchorLock()
	latestLock.Lock()
	defer latestLock.Unlock()

	resultKey := anchorschedule.ResultKey(result)
	existing, found, err := s.readSTHAnchorResult(resultKey)
	if err != nil {
		return err
	}
	if found {
		existingKey := model.STHAnchorScheduleKey{NodeID: existing.NodeID, LogID: existing.LogID, SinkName: existing.SinkName}
		if err := anchorschedule.ValidateResult(existingKey, existing); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stored STH anchor result is invalid", err)
		}
		if !anchorschedule.SameResultBinding(existing, result) {
			return trusterr.New(trusterr.CodeDataLoss, "STH anchor result conflicts with immutable stored binding")
		}
		if err := s.prepareLatestSTHAnchorReferencesLocked(ctx, existing); err != nil {
			return err
		}
		return s.ensureSTHAnchorTreeReferenceLocked(existing)
	}
	if err := s.validateSTHAnchorResultTreeLocked(result); err != nil {
		return err
	}
	if err := s.prepareLatestSTHAnchorReferencesLocked(ctx, result); err != nil {
		return err
	}
	if err := writeCBORAtomic(s.sthAnchorResultPath(resultKey), result); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write sth anchor result", err)
	}
	return s.ensureSTHAnchorTreeReferenceLocked(result)
}

func (s LocalStore) sthAnchorResultForTreeLocked(treeSize uint64) (model.STHAnchorResult, bool, error) {
	data, err := readStoredFile(s.sthAnchorResultTreeReferencePath(treeSize))
	if err == nil {
		var ref model.STHAnchorLatestReference
		if decodeErr := cborx.UnmarshalLimit(data, &ref, maxStoredObjectBytes); decodeErr == nil &&
			anchorschedule.ValidateLatestReference(ref) == nil && ref.Key.TreeSize == treeSize {
			result, found, readErr := s.readSTHAnchorResult(ref.Key)
			if readErr != nil {
				return model.STHAnchorResult{}, false, readErr
			}
			if found && anchorschedule.ReferenceMatchesResult(ref, result) {
				return result, true, nil
			}
		}
	} else if !os.IsNotExist(err) {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor tree reference", err)
	}
	return s.rebuildSTHAnchorTreeReferenceLocked(treeSize)
}

func (s LocalStore) ensureSTHAnchorTreeReferenceLocked(result model.STHAnchorResult) error {
	path := s.sthAnchorResultTreeReferencePath(result.TreeSize)
	data, err := readStoredFile(path)
	if err == nil {
		var ref model.STHAnchorLatestReference
		if cborx.UnmarshalLimit(data, &ref, maxStoredObjectBytes) == nil &&
			anchorschedule.ValidateLatestReference(ref) == nil && ref.Key.TreeSize == result.TreeSize &&
			anchorschedule.CompareResultKeys(ref.Key, anchorschedule.ResultKey(result)) <= 0 {
			stored, found, readErr := s.readSTHAnchorResult(ref.Key)
			if readErr != nil {
				return readErr
			}
			if found && anchorschedule.ReferenceMatchesResult(ref, stored) {
				return nil
			}
		}
	} else if !os.IsNotExist(err) {
		return trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor tree reference", err)
	}
	_, _, err = s.rebuildSTHAnchorTreeReferenceLocked(result.TreeSize)
	return err
}

func (s LocalStore) rebuildSTHAnchorTreeReferenceLocked(treeSize uint64) (model.STHAnchorResult, bool, error) {
	entries, err := s.listLocalSTHAnchorResultEntries()
	if err != nil {
		return model.STHAnchorResult{}, false, err
	}
	start := sort.Search(len(entries), func(i int) bool { return entries[i].key.TreeSize >= treeSize })
	path := s.sthAnchorResultTreeReferencePath(treeSize)
	if start == len(entries) || entries[start].key.TreeSize != treeSize {
		if err := removeLocalFileDurable(path); err != nil {
			return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "clear stale sth anchor tree reference", err)
		}
		return model.STHAnchorResult{}, false, nil
	}
	result, found, err := s.readSTHAnchorResult(entries[start].key)
	if err != nil {
		return model.STHAnchorResult{}, false, err
	}
	if !found {
		return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeDataLoss, "sth anchor result disappeared while rebuilding tree reference")
	}
	if err := writeCBORAtomic(path, anchorschedule.LatestReference(result)); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "write sth anchor tree reference", err)
	}
	return result, true, nil
}

func (s LocalStore) GetSTHAnchorResultForKey(ctx context.Context, key model.STHAnchorResultKey) (model.STHAnchorResult, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get keyed sth anchor result canceled", err)
	}
	if err := anchorschedule.ValidateResultKey(key); err != nil {
		return model.STHAnchorResult{}, false, err
	}
	return s.readSTHAnchorResult(key)
}

func (s LocalStore) readSTHAnchorResult(key model.STHAnchorResultKey) (model.STHAnchorResult, bool, error) {
	data, err := readStoredFile(s.sthAnchorResultPath(key))
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
	resultKey := anchorschedule.ResultKey(result)
	resultScheduleKey := anchorschedule.ScheduleKey(resultKey)
	if err := anchorschedule.ValidateResult(resultScheduleKey, result); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "stored STH anchor result is invalid", err)
	}
	if !anchorschedule.SameResultKey(resultKey, key) {
		return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeDataLoss, "sth anchor result path does not match item")
	}
	return result, true, nil
}

func (s LocalStore) listLocalSTHAnchorResultEntries() ([]localSTHAnchorResultEntry, error) {
	entries, err := os.ReadDir(s.sthAnchorResultDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor result directory", err)
	}
	ordered := make([]localSTHAnchorResultEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), localAnchorResultSuffix) {
			continue
		}
		key, err := decodeLocalSTHAnchorResultFilename(entry.Name())
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "invalid sth anchor result filename", err)
		}
		ordered = append(ordered, localSTHAnchorResultEntry{name: entry.Name(), key: key})
	}
	sort.Slice(ordered, func(i, j int) bool { return anchorschedule.CompareResultKeys(ordered[i].key, ordered[j].key) < 0 })
	return ordered, nil
}

func (s LocalStore) validateSTHAnchorResultTreeLocked(result model.STHAnchorResult) error {
	return s.validateOrStoreSTHAnchorTreeRootLocked(result.NodeID, result.LogID, result.TreeSize, result.RootHash)
}

func (s LocalStore) validateSTHAnchorCandidateTreeLocked(candidate model.STHAnchorCandidate) error {
	return s.validateOrStoreSTHAnchorTreeRootLocked(candidate.Key.NodeID, candidate.Key.LogID, candidate.STH.TreeSize, candidate.STH.RootHash)
}

func (s LocalStore) validateOrStoreSTHAnchorTreeRootLocked(nodeID, logID string, treeSize uint64, rootHash []byte) error {
	lock := s.sthAnchorTreeRootLock(nodeID, logID, treeSize)
	lock.Lock()
	defer lock.Unlock()

	path := s.sthAnchorTreeRootPath(nodeID, logID, treeSize)
	data, err := readStoredFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := writeCBORAtomic(path, append([]byte(nil), rootHash...)); err != nil {
				return trusterr.Wrap(trusterr.CodeDataLoss, "write canonical sth anchor tree root", err)
			}
			return nil
		}
		return trusterr.Wrap(trusterr.CodeDataLoss, "read canonical sth anchor tree root", err)
	}
	var stored []byte
	if err := cborx.UnmarshalLimit(data, &stored, maxStoredObjectBytes); err != nil || len(stored) != sha256.Size {
		return trusterr.New(trusterr.CodeDataLoss, "canonical sth anchor tree root is invalid")
	}
	if !bytes.Equal(stored, rootHash) {
		return trusterr.New(trusterr.CodeDataLoss, "anchor tree size has conflicting root hash")
	}
	return nil
}

func (s LocalStore) ListSTHAnchorResultsAfter(ctx context.Context, after model.STHAnchorResultKey, limit int) ([]model.STHAnchorResult, error) {
	return s.ListSTHAnchorResultsPage(ctx, model.AnchorListOptions{
		Limit: limit, Direction: model.RecordListDirectionAsc,
		AfterResultKey: after, HasAfter: after.TreeSize != 0,
	})
}

func (s LocalStore) ListSTHAnchorResultsPage(ctx context.Context, opts model.AnchorListOptions) ([]model.STHAnchorResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor result page canceled", err)
	}
	limit := normaliseRecordLimit(opts.Limit)
	if opts.HasAfter {
		if err := anchorschedule.ValidateResultKey(opts.AfterResultKey); err != nil {
			return nil, err
		}
	}
	ordered, err := s.listLocalSTHAnchorResultEntries()
	if err != nil {
		return nil, err
	}
	asc := strings.EqualFold(opts.Direction, model.RecordListDirectionAsc)
	start, end, step := 0, len(ordered), 1
	if asc {
		if opts.HasAfter {
			start = sort.Search(len(ordered), func(i int) bool {
				return anchorschedule.CompareResultKeys(ordered[i].key, opts.AfterResultKey) > 0
			})
		}
	} else {
		start, end, step = len(ordered)-1, -1, -1
		if opts.HasAfter {
			start = sort.Search(len(ordered), func(i int) bool {
				return anchorschedule.CompareResultKeys(ordered[i].key, opts.AfterResultKey) >= 0
			}) - 1
		}
	}
	results := make([]model.STHAnchorResult, 0, limit)
	for i := start; i != end && len(results) < limit; i += step {
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor result page canceled", err)
		}
		result, found, err := s.readSTHAnchorResult(ordered[i].key)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, trusterr.New(trusterr.CodeDataLoss, "sth anchor result disappeared during listing")
		}
		results = append(results, result)
	}
	return results, nil
}

func (s LocalStore) UpsertSTHAnchorCandidate(ctx context.Context, candidate model.STHAnchorCandidate) (model.STHAnchorSchedule, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorSchedule{}, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore upsert sth anchor candidate canceled", err)
	}
	if err := anchorschedule.ValidateCandidate(candidate); err != nil {
		return model.STHAnchorSchedule{}, err
	}
	lock := s.sthAnchorScheduleLock(candidate.Key)
	lock.Lock()
	defer lock.Unlock()
	if err := s.replayLocalAnchorPublicationLocked(candidate.Key); err != nil {
		return model.STHAnchorSchedule{}, err
	}
	next, changed, err := s.mergeSTHAnchorCandidateLocked(ctx, candidate)
	if err != nil {
		return model.STHAnchorSchedule{}, err
	}
	if changed {
		if err := s.writeSTHAnchorSchedule(next); err != nil {
			return model.STHAnchorSchedule{}, err
		}
	}
	return next, nil
}

func (s LocalStore) mergeSTHAnchorCandidateLocked(ctx context.Context, candidate model.STHAnchorCandidate) (model.STHAnchorSchedule, bool, error) {
	current, found, err := s.getSTHAnchorSchedule(candidate.Key)
	if err != nil {
		return model.STHAnchorSchedule{}, false, err
	}
	latestLock := s.latestSTHAnchorLock()
	latestLock.Lock()
	defer latestLock.Unlock()
	if err := s.validateSTHAnchorCandidateTreeLocked(candidate); err != nil {
		return model.STHAnchorSchedule{}, false, err
	}
	latest, latestFound, err := s.latestSTHAnchorResultLocked(ctx, &candidate.Key)
	if err != nil {
		return model.STHAnchorSchedule{}, false, err
	}
	exactResultKey := model.STHAnchorResultKey{
		NodeID: candidate.Key.NodeID, LogID: candidate.Key.LogID, SinkName: candidate.Key.SinkName, TreeSize: candidate.STH.TreeSize,
	}
	exact, exactFound, err := s.readSTHAnchorResult(exactResultKey)
	if err != nil {
		return model.STHAnchorSchedule{}, false, err
	}
	if exactFound {
		if err := anchorschedule.ValidateCandidateAgainstExactResult(candidate, exact); err != nil {
			return model.STHAnchorSchedule{}, false, err
		}
		if !latestFound || exact.TreeSize > latest.TreeSize {
			latest, latestFound = exact, true
		}
	}
	var latestPtr *model.STHAnchorResult
	if latestFound {
		latestPtr = &latest
	}
	next, changed, err := anchorschedule.MergeCandidate(current, found, candidate, latestPtr)
	if err != nil {
		return model.STHAnchorSchedule{}, false, err
	}
	return next, changed, nil
}

func (s LocalStore) GetSTHAnchorSchedule(ctx context.Context, key model.STHAnchorScheduleKey) (model.STHAnchorSchedule, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorSchedule{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get sth anchor schedule canceled", err)
	}
	if err := anchorschedule.ValidateKey(key); err != nil {
		return model.STHAnchorSchedule{}, false, err
	}
	lock := s.sthAnchorScheduleLock(key)
	lock.Lock()
	defer lock.Unlock()
	if err := s.replayLocalAnchorPublicationLocked(key); err != nil {
		return model.STHAnchorSchedule{}, false, err
	}
	return s.getSTHAnchorSchedule(key)
}

func (s LocalStore) getSTHAnchorSchedule(key model.STHAnchorScheduleKey) (model.STHAnchorSchedule, bool, error) {
	data, err := readStoredFile(s.sthAnchorSchedulePath(key))
	if err != nil {
		if os.IsNotExist(err) {
			return model.STHAnchorSchedule{}, false, nil
		}
		return model.STHAnchorSchedule{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor schedule", err)
	}
	var schedule model.STHAnchorSchedule
	if err := cborx.UnmarshalLimit(data, &schedule, maxStoredObjectBytes); err != nil {
		return model.STHAnchorSchedule{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode sth anchor schedule", err)
	}
	if err := anchorschedule.ValidateSchedule(schedule); err != nil {
		return model.STHAnchorSchedule{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "stored STH anchor schedule is invalid", err)
	}
	if !anchorschedule.SameKey(schedule.Key, key) {
		return model.STHAnchorSchedule{}, false, trusterr.New(trusterr.CodeDataLoss, "sth anchor schedule path does not match item")
	}
	return schedule, true, nil
}

func (s LocalStore) ListSTHAnchorSchedules(ctx context.Context) ([]model.STHAnchorSchedule, error) {
	if err := ctx.Err(); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor schedules canceled", err)
	}
	entries, err := os.ReadDir(s.sthAnchorScheduleDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, "read sth anchor schedule directory", err)
	}
	schedules := make([]model.STHAnchorSchedule, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), localAnchorScheduleSuffix) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore list sth anchor schedules canceled", err)
		}
		key, err := decodeLocalSTHAnchorScheduleFilename(entry.Name())
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "decode sth anchor schedule filename", err)
		}
		schedule, found, err := s.GetSTHAnchorSchedule(ctx, key)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, trusterr.New(trusterr.CodeDataLoss, "sth anchor schedule disappeared during listing")
		}
		schedules = append(schedules, schedule)
	}
	anchorschedule.Sort(schedules)
	return schedules, nil
}

func (s LocalStore) ClaimSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, nowUnixN, leaseUntilUnixN int64, leaseOwner, leaseToken string) (model.STHAnchorAttempt, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorAttempt{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore claim sth anchor attempt canceled", err)
	}
	if err := anchorschedule.ValidateKey(key); err != nil {
		return model.STHAnchorAttempt{}, false, err
	}
	lock := s.sthAnchorScheduleLock(key)
	lock.Lock()
	defer lock.Unlock()
	if err := s.replayLocalAnchorPublicationLocked(key); err != nil {
		return model.STHAnchorAttempt{}, false, err
	}
	current, found, err := s.getSTHAnchorSchedule(key)
	if err != nil {
		return model.STHAnchorAttempt{}, false, err
	}
	if !found {
		return model.STHAnchorAttempt{}, false, nil
	}
	current, reconciled, err := s.reconcileStoredSTHAnchorResultsLocked(ctx, current)
	if err != nil {
		return model.STHAnchorAttempt{}, false, err
	}
	next, attempt, claimed, err := anchorschedule.Claim(current, nowUnixN, leaseUntilUnixN, leaseOwner, leaseToken)
	if err != nil {
		return model.STHAnchorAttempt{}, false, err
	}
	if !claimed {
		if reconciled {
			if err := s.writeSTHAnchorSchedule(current); err != nil {
				return model.STHAnchorAttempt{}, false, err
			}
		}
		return model.STHAnchorAttempt{}, false, nil
	}
	if err := s.writeSTHAnchorSchedule(next); err != nil {
		return model.STHAnchorAttempt{}, false, err
	}
	return attempt, true, nil
}

func (s LocalStore) RescheduleSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, generation uint64, leaseToken string, attempts int, nextAttemptUnixN int64, lastError string) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore reschedule sth anchor attempt canceled", err)
	}
	if err := anchorschedule.ValidateKey(key); err != nil {
		return err
	}
	lock := s.sthAnchorScheduleLock(key)
	lock.Lock()
	defer lock.Unlock()
	if err := s.replayLocalAnchorPublicationLocked(key); err != nil {
		return err
	}
	current, found, err := s.getSTHAnchorSchedule(key)
	if err != nil {
		return err
	}
	if !found {
		return trusterr.New(trusterr.CodeNotFound, "sth anchor schedule not found")
	}
	next, err := anchorschedule.Reschedule(current, generation, leaseToken, attempts, nextAttemptUnixN, lastError)
	if err != nil {
		return err
	}
	return s.writeSTHAnchorSchedule(next)
}

func (s LocalStore) FailSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, generation uint64, leaseToken string, attempts int, lastError string) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore fail sth anchor attempt canceled", err)
	}
	if err := anchorschedule.ValidateKey(key); err != nil {
		return err
	}
	lock := s.sthAnchorScheduleLock(key)
	lock.Lock()
	defer lock.Unlock()
	if err := s.replayLocalAnchorPublicationLocked(key); err != nil {
		return err
	}
	current, found, err := s.getSTHAnchorSchedule(key)
	if err != nil {
		return err
	}
	if !found {
		return trusterr.New(trusterr.CodeNotFound, "sth anchor schedule not found")
	}
	next, err := anchorschedule.Fail(current, generation, leaseToken, attempts, lastError)
	if err != nil {
		return err
	}
	return s.writeSTHAnchorSchedule(next)
}

func (s LocalStore) CompleteSTHAnchorAttempt(ctx context.Context, key model.STHAnchorScheduleKey, generation uint64, leaseToken string, result model.STHAnchorResult) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore complete sth anchor attempt canceled", err)
	}
	if err := anchorschedule.ValidateResult(key, result); err != nil {
		return err
	}
	lock := s.sthAnchorScheduleLock(key)
	lock.Lock()
	defer lock.Unlock()
	if err := s.replayLocalAnchorPublicationLocked(key); err != nil {
		return err
	}

	existing, resultFound, err := s.readSTHAnchorResult(anchorschedule.ResultKey(result))
	if err != nil {
		return err
	}
	if resultFound {
		existingKey := model.STHAnchorScheduleKey{NodeID: existing.NodeID, LogID: existing.LogID, SinkName: existing.SinkName}
		if err := anchorschedule.ValidateResult(existingKey, existing); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "stored STH anchor result is invalid", err)
		}
		if !anchorschedule.SameResultBinding(existing, result) {
			return trusterr.New(trusterr.CodeDataLoss, "STH anchor result conflicts with immutable stored binding")
		}
		result = existing
	}

	current, scheduleFound, err := s.getSTHAnchorSchedule(key)
	if err != nil {
		return err
	}
	if resultFound {
		if err := s.putSTHAnchorResultLocked(ctx, result); err != nil {
			return err
		}
		if !scheduleFound {
			return nil
		}
		next, changed, err := anchorschedule.ReconcileCompleted(current, result)
		if err != nil {
			return err
		}
		if !changed {
			return nil
		}
		return s.writeSTHAnchorSchedule(next)
	}
	if !scheduleFound || current.InFlight == nil {
		return trusterr.New(trusterr.CodeNotFound, "in-flight anchor attempt not found")
	}
	next, err := anchorschedule.Complete(current, generation, leaseToken, result)
	if err != nil {
		return err
	}
	// The result must be durable before the in-flight target is cleared. If the
	// process stops between these writes, an idempotent retry observes the same
	// immutable result and safely completes the remaining schedule transition.
	if err := s.putSTHAnchorResultLocked(ctx, result); err != nil {
		return err
	}
	return s.writeSTHAnchorSchedule(next)
}

func (s LocalStore) PutSTHAnchorSchedule(ctx context.Context, schedule model.STHAnchorSchedule) error {
	return s.restoreSTHAnchorSchedule(ctx, schedule, false)
}

func (s LocalStore) ReplaceSTHAnchorSchedule(ctx context.Context, schedule model.STHAnchorSchedule) error {
	return s.restoreSTHAnchorSchedule(ctx, schedule, true)
}

func (s LocalStore) restoreSTHAnchorSchedule(ctx context.Context, schedule model.STHAnchorSchedule, replace bool) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore put sth anchor schedule canceled", err)
	}
	if err := anchorschedule.ValidateSchedule(schedule); err != nil {
		return err
	}
	if schedule.InFlight != nil && (schedule.InFlight.LeaseOwner != "" || schedule.InFlight.LeaseToken != "" || schedule.InFlight.LeaseUntilUnixN != 0) {
		return trusterr.New(trusterr.CodeFailedPrecondition, "restored STH anchor schedule must not retain a process lease")
	}
	lock := s.sthAnchorScheduleLock(schedule.Key)
	lock.Lock()
	defer lock.Unlock()
	if err := s.replayLocalAnchorPublicationLocked(schedule.Key); err != nil {
		return err
	}
	schedule, _, err := s.reconcileStoredSTHAnchorResultsLocked(ctx, schedule)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "reconcile restored STH anchor schedule", err)
	}
	for _, target := range localSTHAnchorScheduleTargets(schedule) {
		if err := s.validateOrStoreSTHAnchorTreeRootLocked(schedule.Key.NodeID, schedule.Key.LogID, target.TreeSize, target.RootHash); err != nil {
			return err
		}
	}
	existing, found, err := s.getSTHAnchorSchedule(schedule.Key)
	if err != nil {
		return err
	}
	if found {
		if reflect.DeepEqual(existing, schedule) {
			return nil
		}
		if !replace {
			return trusterr.New(trusterr.CodeAlreadyExists, "sth anchor schedule already exists with different state")
		}
	}
	return s.writeSTHAnchorSchedule(schedule)
}

func (s LocalStore) reconcileStoredSTHAnchorResultsLocked(ctx context.Context, schedule model.STHAnchorSchedule) (model.STHAnchorSchedule, bool, error) {
	changed := false
	if schedule.InFlight != nil {
		resultKey := model.STHAnchorResultKey{
			NodeID: schedule.Key.NodeID, LogID: schedule.Key.LogID, SinkName: schedule.Key.SinkName, TreeSize: schedule.InFlight.Target.TreeSize,
		}
		result, found, err := s.readSTHAnchorResult(resultKey)
		if err != nil {
			return model.STHAnchorSchedule{}, false, err
		}
		if found {
			next, reconciled, err := anchorschedule.ReconcileCompleted(schedule, result)
			if err != nil {
				return model.STHAnchorSchedule{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "reconcile completed STH anchor in-flight target", err)
			}
			schedule, changed = next, changed || reconciled
		}
	}
	if schedule.Pending == nil {
		return schedule, changed, nil
	}
	latestLock := s.latestSTHAnchorLock()
	latestLock.Lock()
	latest, found, err := s.latestSTHAnchorResultLocked(ctx, &schedule.Key)
	latestLock.Unlock()
	if err != nil || !found {
		return schedule, changed, err
	}
	next, reconciled, err := anchorschedule.ReconcileCompleted(schedule, latest)
	if err != nil {
		return model.STHAnchorSchedule{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "reconcile completed STH anchor pending target", err)
	}
	return next, changed || reconciled, nil
}

func localSTHAnchorScheduleTargets(schedule model.STHAnchorSchedule) []model.SignedTreeHead {
	targets := make([]model.SignedTreeHead, 0, 2)
	if schedule.InFlight != nil {
		targets = append(targets, schedule.InFlight.Target)
	}
	if schedule.Pending != nil {
		targets = append(targets, schedule.Pending.Target)
	}
	return targets
}

func (s LocalStore) writeSTHAnchorSchedule(schedule model.STHAnchorSchedule) error {
	if err := anchorschedule.ValidateSchedule(schedule); err != nil {
		return err
	}
	if err := writeCBORAtomic(s.sthAnchorSchedulePath(schedule.Key), schedule); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "write sth anchor schedule", err)
	}
	return nil
}

func (s LocalStore) GetL5CoverageCheckpoint(ctx context.Context, key model.STHAnchorScheduleKey) (model.L5CoverageCheckpoint, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.L5CoverageCheckpoint{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore get L5 coverage checkpoint canceled", err)
	}
	if err := anchorschedule.ValidateKey(key); err != nil {
		return model.L5CoverageCheckpoint{}, false, err
	}
	lock := s.l5CoverageLock(key)
	lock.Lock()
	defer lock.Unlock()
	return s.readL5CoverageCheckpoint(key)
}

func (s LocalStore) AdvanceL5CoverageCheckpoint(ctx context.Context, key model.STHAnchorScheduleKey, coveredTreeSize uint64, updatedAtUnixN int64) (model.L5CoverageCheckpoint, error) {
	if err := ctx.Err(); err != nil {
		return model.L5CoverageCheckpoint{}, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore advance L5 coverage checkpoint canceled", err)
	}
	lock := s.l5CoverageLock(key)
	lock.Lock()
	defer lock.Unlock()
	current, found, err := s.readL5CoverageCheckpoint(key)
	if err != nil {
		return model.L5CoverageCheckpoint{}, err
	}
	next, changed, err := l5coverage.Advance(current, found, key, coveredTreeSize, updatedAtUnixN)
	if err != nil {
		return model.L5CoverageCheckpoint{}, err
	}
	if !changed {
		return next, nil
	}
	if err := writeCBORAtomic(s.l5CoverageCheckpointPath(key), next); err != nil {
		return model.L5CoverageCheckpoint{}, trusterr.Wrap(trusterr.CodeDataLoss, "write L5 coverage checkpoint", err)
	}
	return next, nil
}

func (s LocalStore) readL5CoverageCheckpoint(key model.STHAnchorScheduleKey) (model.L5CoverageCheckpoint, bool, error) {
	data, err := readStoredFile(s.l5CoverageCheckpointPath(key))
	if err != nil {
		if os.IsNotExist(err) {
			return model.L5CoverageCheckpoint{}, false, nil
		}
		return model.L5CoverageCheckpoint{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "read L5 coverage checkpoint", err)
	}
	var checkpoint model.L5CoverageCheckpoint
	if err := cborx.UnmarshalLimit(data, &checkpoint, maxStoredObjectBytes); err != nil {
		return model.L5CoverageCheckpoint{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "decode L5 coverage checkpoint", err)
	}
	if err := l5coverage.ValidateCheckpoint(checkpoint); err != nil {
		return model.L5CoverageCheckpoint{}, false, err
	}
	if !anchorschedule.SameKey(checkpoint.Key, key) {
		return model.L5CoverageCheckpoint{}, false, trusterr.New(trusterr.CodeDataLoss, "L5 coverage checkpoint path does not match item")
	}
	return checkpoint, true, nil
}

func (s LocalStore) latestSTHAnchorResultForKey(ctx context.Context, key model.STHAnchorScheduleKey) (model.STHAnchorResult, bool, error) {
	if err := anchorschedule.ValidateKey(key); err != nil {
		return model.STHAnchorResult{}, false, err
	}
	lock := s.latestSTHAnchorLock()
	lock.Lock()
	defer lock.Unlock()
	return s.latestSTHAnchorResultLocked(ctx, &key)
}

func (s LocalStore) LatestSTHAnchorResultForKey(ctx context.Context, key model.STHAnchorScheduleKey) (model.STHAnchorResult, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore latest keyed sth anchor result canceled", err)
	}
	return s.latestSTHAnchorResultForKey(ctx, key)
}

func (s LocalStore) LatestSTHAnchorResult(ctx context.Context) (model.STHAnchorResult, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore latest sth anchor result canceled", err)
	}
	lock := s.latestSTHAnchorLock()
	lock.Lock()
	defer lock.Unlock()
	return s.latestSTHAnchorResultLocked(ctx, nil)
}

func (s LocalStore) prepareLatestSTHAnchorReferencesLocked(ctx context.Context, result model.STHAnchorResult) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore update latest sth anchor reference canceled", err)
	}
	stream := model.STHAnchorScheduleKey{NodeID: result.NodeID, LogID: result.LogID, SinkName: result.SinkName}
	for _, target := range []struct {
		path   string
		stream *model.STHAnchorScheduleKey
	}{{path: s.latestSTHAnchorReferencePath()}, {path: s.latestSTHAnchorReferencePathForKey(stream), stream: &stream}} {
		current, found, err := s.latestSTHAnchorResultLocked(ctx, target.stream)
		if err != nil {
			return err
		}
		if found && anchorschedule.CompareResultKeys(anchorschedule.ResultKey(result), anchorschedule.ResultKey(current)) <= 0 {
			continue
		}
		candidate := anchorschedule.LatestReference(result)
		ref := localLatestAnchorReference{Candidate: candidate}
		if found {
			previous := anchorschedule.LatestReference(current)
			ref.Previous = &previous
		}
		if err := writeCBORAtomic(target.path, ref); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "write latest sth anchor reference", err)
		}
	}
	return nil
}

func (s LocalStore) latestSTHAnchorResultLocked(ctx context.Context, stream *model.STHAnchorScheduleKey) (model.STHAnchorResult, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "proofstore scan latest sth anchor result canceled", err)
	}
	path := s.latestSTHAnchorReferencePath()
	if stream != nil {
		path = s.latestSTHAnchorReferencePathForKey(*stream)
	}
	if ref, ok, err := s.readLatestSTHAnchorReference(path); err == nil && ok {
		if anchorschedule.EmptyLatestReferenceMatches(ref.Candidate, stream) {
			return model.STHAnchorResult{}, false, nil
		}
		if ref.Candidate.SchemaVersion != model.SchemaSTHAnchorLatestEmpty {
			result, found, complete, resolveErr := s.sthAnchorResultFromLatestReference(ref)
			if resolveErr == nil && found && complete && (stream == nil || anchorschedule.SameKey(*stream, anchorschedule.ScheduleKey(anchorschedule.ResultKey(result)))) {
				return result, true, nil
			}
		}
	}
	entries, err := s.listLocalSTHAnchorResultEntries()
	if err != nil {
		return model.STHAnchorResult{}, false, err
	}
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if stream != nil && !anchorschedule.SameKey(*stream, anchorschedule.ScheduleKey(entry.key)) {
			continue
		}
		result, found, err := s.readSTHAnchorResult(entry.key)
		if err != nil {
			return model.STHAnchorResult{}, false, err
		}
		if !found {
			return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeDataLoss, "sth anchor result disappeared while rebuilding latest reference")
		}
		if err := writeCBORAtomic(path, localLatestAnchorReference{Candidate: anchorschedule.LatestReference(result)}); err != nil {
			return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "rebuild latest sth anchor reference", err)
		}
		return result, true, nil
	}
	empty := localLatestAnchorReference{Candidate: anchorschedule.EmptyLatestReference(stream)}
	if err := writeCBORAtomic(path, empty); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "write empty latest sth anchor reference", err)
	}
	return model.STHAnchorResult{}, false, nil
}

func (s LocalStore) readLatestSTHAnchorReference(path string) (localLatestAnchorReference, bool, error) {
	data, err := readStoredFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return localLatestAnchorReference{}, false, nil
		}
		return localLatestAnchorReference{}, false, err
	}
	var ref localLatestAnchorReference
	if err := cborx.UnmarshalLimit(data, &ref, maxStoredObjectBytes); err != nil {
		return localLatestAnchorReference{}, false, err
	}
	if ref.Candidate.SchemaVersion == model.SchemaSTHAnchorLatestEmpty {
		if !anchorschedule.ValidEmptyLatestReference(ref.Candidate) || ref.Previous != nil {
			return localLatestAnchorReference{}, false, trusterr.New(trusterr.CodeDataLoss, "empty latest sth anchor reference is invalid")
		}
		return ref, true, nil
	}
	if err := anchorschedule.ValidateLatestReference(ref.Candidate); err != nil {
		return localLatestAnchorReference{}, false, trusterr.New(trusterr.CodeDataLoss, "latest sth anchor reference is invalid")
	}
	if ref.Previous != nil {
		if err := anchorschedule.ValidateLatestReference(*ref.Previous); err != nil {
			return localLatestAnchorReference{}, false, trusterr.New(trusterr.CodeDataLoss, "previous sth anchor reference is invalid")
		}
	}
	return ref, true, nil
}

func (s LocalStore) sthAnchorResultFromLatestReference(ref localLatestAnchorReference) (model.STHAnchorResult, bool, bool, error) {
	result, found, err := s.readSTHAnchorResult(ref.Candidate.Key)
	if err != nil {
		return model.STHAnchorResult{}, false, false, err
	}
	if found {
		if !anchorschedule.ReferenceMatchesResult(ref.Candidate, result) {
			return model.STHAnchorResult{}, false, false, trusterr.New(trusterr.CodeDataLoss, "latest sth anchor reference does not match item")
		}
		return result, true, true, nil
	}
	if ref.Previous == nil {
		return model.STHAnchorResult{}, false, false, nil
	}
	result, found, err = s.readSTHAnchorResult(ref.Previous.Key)
	if err != nil {
		return model.STHAnchorResult{}, false, false, err
	}
	if found && !anchorschedule.ReferenceMatchesResult(*ref.Previous, result) {
		return model.STHAnchorResult{}, false, false, trusterr.New(trusterr.CodeDataLoss, "previous sth anchor reference does not match item")
	}
	return result, found, false, nil
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

func (s LocalStore) sthAnchorResultDir() string {
	return filepath.Join(s.root(), "anchor", "sth-result")
}

func (s LocalStore) sthAnchorResultTreeReferenceDir() string {
	return filepath.Join(s.root(), "anchor", "sth-result-by-tree")
}

func (s LocalStore) sthAnchorScheduleDir() string {
	return filepath.Join(s.root(), "anchor", "sth-schedule")
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

func (s LocalStore) sthAnchorResultPath(key model.STHAnchorResultKey) string {
	return filepath.Join(s.sthAnchorResultDir(), encodeLocalSTHAnchorResultFilename(key))
}

func (s LocalStore) sthAnchorResultTreeReferencePath(treeSize uint64) string {
	return filepath.Join(s.sthAnchorResultTreeReferenceDir(), fmt.Sprintf("%020d%s", treeSize, localAnchorTreeRefSuffix))
}

func (s LocalStore) sthAnchorSchedulePath(key model.STHAnchorScheduleKey) string {
	return filepath.Join(s.sthAnchorScheduleDir(), encodeLocalSTHAnchorScheduleFilename(key))
}

func (s LocalStore) sthAnchorPublicationJournalPath(key model.STHAnchorScheduleKey) string {
	name := strings.TrimSuffix(encodeLocalSTHAnchorScheduleFilename(key), localAnchorScheduleSuffix) + localAnchorPublishSuffix
	return filepath.Join(s.sthAnchorScheduleDir(), name)
}

func (s LocalStore) sthAnchorTreeRootPath(nodeID, logID string, treeSize uint64) string {
	return filepath.Join(s.root(), "anchor", "sth-tree-root", encodeLocalSTHAnchorTreeRootFilename(nodeID, logID, treeSize))
}

func (s LocalStore) l5CoverageCheckpointPath(key model.STHAnchorScheduleKey) string {
	return filepath.Join(s.root(), "anchor", "l5-coverage", encodeLocalL5CoverageFilename(key))
}

func (s LocalStore) latestSTHAnchorReferencePath() string {
	return filepath.Join(s.root(), "anchor", "latest-sth-anchor.tdref")
}

func (s LocalStore) latestSTHAnchorReferencePathForKey(key model.STHAnchorScheduleKey) string {
	name := strings.TrimSuffix(encodeLocalSTHAnchorScheduleFilename(key), localAnchorScheduleSuffix) + localAnchorLatestSuffix
	return filepath.Join(s.root(), "anchor", "latest-sth-anchor", name)
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

func (s LocalStore) PromoteBatchProofLevel(ctx context.Context, batchID, proofLevel string) error {
	proofLevel = model.NormalizedProofLevel(proofLevel)
	if batchID == "" || proofLevel == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "batch_id and valid proof level are required")
	}
	return s.promoteBatchRecords(ctx, batchID, proofLevel)
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

func encodeLocalSTHAnchorResultFilename(key model.STHAnchorResultKey) string {
	parts := []string{
		fmt.Sprintf("%0*d", localPositionWidth, key.TreeSize),
		base64.RawURLEncoding.EncodeToString([]byte(key.NodeID)),
		base64.RawURLEncoding.EncodeToString([]byte(key.LogID)),
		base64.RawURLEncoding.EncodeToString([]byte(key.SinkName)),
	}
	return localAnchorResultPrefix + strings.Join(parts, ".") + localAnchorResultSuffix
}

func decodeLocalSTHAnchorResultFilename(name string) (model.STHAnchorResultKey, error) {
	if !strings.HasPrefix(name, localAnchorResultPrefix) || !strings.HasSuffix(name, localAnchorResultSuffix) {
		return model.STHAnchorResultKey{}, fmt.Errorf("invalid STH anchor result filename %q", name)
	}
	body := strings.TrimSuffix(strings.TrimPrefix(name, localAnchorResultPrefix), localAnchorResultSuffix)
	parts := strings.Split(body, ".")
	if len(parts) != 4 {
		return model.STHAnchorResultKey{}, fmt.Errorf("invalid STH anchor result filename %q", name)
	}
	treeSize, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil || fmt.Sprintf("%0*d", localPositionWidth, treeSize) != parts[0] {
		return model.STHAnchorResultKey{}, fmt.Errorf("invalid tree size in STH anchor result filename %q", name)
	}
	values := make([]string, 3)
	for i, part := range parts[1:] {
		decoded, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return model.STHAnchorResultKey{}, fmt.Errorf("decode STH anchor result filename %q: %w", name, err)
		}
		values[i] = string(decoded)
	}
	key := model.STHAnchorResultKey{TreeSize: treeSize, NodeID: values[0], LogID: values[1], SinkName: values[2]}
	if err := anchorschedule.ValidateResultKey(key); err != nil {
		return model.STHAnchorResultKey{}, fmt.Errorf("invalid STH anchor result filename %q: %w", name, err)
	}
	if encodeLocalSTHAnchorResultFilename(key) != name {
		return model.STHAnchorResultKey{}, fmt.Errorf("non-canonical STH anchor result filename %q", name)
	}
	return key, nil
}

func encodeLocalSTHAnchorScheduleFilename(key model.STHAnchorScheduleKey) string {
	parts := []string{
		base64.RawURLEncoding.EncodeToString([]byte(key.NodeID)),
		base64.RawURLEncoding.EncodeToString([]byte(key.LogID)),
		base64.RawURLEncoding.EncodeToString([]byte(key.SinkName)),
	}
	return localAnchorSchedulePrefix + strings.Join(parts, ".") + localAnchorScheduleSuffix
}

func encodeLocalSTHAnchorTreeRootFilename(nodeID, logID string, treeSize uint64) string {
	parts := []string{
		fmt.Sprintf("%0*d", localPositionWidth, treeSize),
		base64.RawURLEncoding.EncodeToString([]byte(nodeID)),
		base64.RawURLEncoding.EncodeToString([]byte(logID)),
	}
	return localAnchorSchedulePrefix + strings.Join(parts, ".") + localAnchorTreeRootSuffix
}

func encodeLocalL5CoverageFilename(key model.STHAnchorScheduleKey) string {
	return strings.TrimSuffix(encodeLocalSTHAnchorScheduleFilename(key), localAnchorScheduleSuffix) + localL5CoverageSuffix
}

func decodeLocalSTHAnchorScheduleFilename(name string) (model.STHAnchorScheduleKey, error) {
	if !strings.HasPrefix(name, localAnchorSchedulePrefix) || !strings.HasSuffix(name, localAnchorScheduleSuffix) {
		return model.STHAnchorScheduleKey{}, fmt.Errorf("invalid STH anchor schedule filename %q", name)
	}
	body := strings.TrimSuffix(strings.TrimPrefix(name, localAnchorSchedulePrefix), localAnchorScheduleSuffix)
	parts := strings.Split(body, ".")
	if len(parts) != 3 {
		return model.STHAnchorScheduleKey{}, fmt.Errorf("invalid STH anchor schedule filename %q", name)
	}
	values := make([]string, len(parts))
	for i, part := range parts {
		decoded, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return model.STHAnchorScheduleKey{}, fmt.Errorf("decode STH anchor schedule filename %q: %w", name, err)
		}
		values[i] = string(decoded)
	}
	key := model.STHAnchorScheduleKey{NodeID: values[0], LogID: values[1], SinkName: values[2]}
	if err := anchorschedule.ValidateKey(key); err != nil {
		return model.STHAnchorScheduleKey{}, fmt.Errorf("invalid STH anchor schedule filename %q: %w", name, err)
	}
	if encodeLocalSTHAnchorScheduleFilename(key) != name {
		return model.STHAnchorScheduleKey{}, fmt.Errorf("non-canonical STH anchor schedule filename %q", name)
	}
	return key, nil
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
