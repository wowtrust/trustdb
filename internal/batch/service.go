package batch

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/ryan-wong-coder/trustdb/internal/merkle"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/observability"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

type Engine interface {
	CommitBatch(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) ([]model.ProofBundle, error)
}

type IndexEngine interface {
	CommitBatchIndexes(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) (model.BatchRoot, []model.RecordIndex, error)
}

type ComputeEngine interface {
	ComputeBatch(ctx context.Context, batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt, opts model.BatchComputeOptions) (model.BatchCommit, error)
}

const (
	ProofModeInline   = "inline"
	ProofModeAsync    = "async"
	ProofModeOnDemand = "on_demand"
)

type Store interface {
	PutBundle(context.Context, model.ProofBundle) error
	GetBundle(context.Context, string) (model.ProofBundle, error)
	PutRecordIndex(context.Context, model.RecordIndex) error
	GetRecordIndex(context.Context, string) (model.RecordIndex, bool, error)
	ListRecordIndexes(context.Context, model.RecordListOptions) ([]model.RecordIndex, error)
	PutRoot(context.Context, model.BatchRoot) error
	ListRoots(context.Context, int) ([]model.BatchRoot, error)
	ListRootsAfter(context.Context, int64, int) ([]model.BatchRoot, error)
	ListRootsPage(context.Context, model.RootListOptions) ([]model.BatchRoot, error)
	LatestRoot(context.Context) (model.BatchRoot, error)
	PutBatchTreeArtifacts(context.Context, []model.BatchTreeLeaf, []model.BatchTreeNode) error
	ListBatchTreeLeaves(context.Context, model.BatchTreeLeafListOptions) ([]model.BatchTreeLeaf, error)
	ListBatchTreeNodes(context.Context, model.BatchTreeNodeListOptions) ([]model.BatchTreeNode, error)
	PutManifest(context.Context, model.BatchManifest) error
	GetManifest(context.Context, string) (model.BatchManifest, error)
	ListManifests(context.Context) ([]model.BatchManifest, error)
	PutCheckpoint(context.Context, model.WALCheckpoint) error
	GetCheckpoint(context.Context) (model.WALCheckpoint, bool, error)
}

type Accepted struct {
	Signed   model.SignedClaim
	Record   model.ServerRecord
	Accepted model.AcceptedReceipt
}

type Options struct {
	QueueSize                int
	MaxRecords               int
	MaxDelay                 time.Duration
	ProofMode                string
	MaterializerWorkers      int
	MaterializerQueueSize    int
	MaterializerPollInterval time.Duration
	MaterializerNodeID       string
	DeferMaterializerScan    bool
	// InitialSeq seeds the in-memory batch sequence counter so that
	// batch_id suffixes keep increasing across restarts. Callers
	// typically derive it from the latest persisted BatchRoot via
	// ParseBatchSeq; leaving it at 0 means "first batch starts at
	// -000001", which is the legacy behaviour from before we
	// persisted the counter.
	//
	// The counter is still process-local — it disambiguates batches
	// inside the same nanosecond, which the single-goroutine worker
	// can't actually produce, so the field is mainly cosmetic. But
	// without restoring it, every server restart resets the suffix
	// to -000001 and the human reading the proof bundle thinks two
	// unrelated batches share an ID.
	InitialSeq uint64
	// OnCheckpointAdvanced is called after a successful advanceCheckpoint
	// step with the newly persisted checkpoint. It runs on the batch
	// worker goroutine so it must not block on IO that could stall
	// subsequent batches — wire async prune or metric updates here, not
	// synchronous network calls. Errors from the hook are not returned
	// because checkpoint advancement is a best-effort optimization.
	OnCheckpointAdvanced func(context.Context, model.WALCheckpoint)
	// OnBatchCommitted fires after a batch is fully persisted (manifest
	// committed, bundles + root written, checkpoint advanced) with the
	// BatchRoot that was just stored. The serve command uses this hook only
	// to persist a durable global-log outbox event and trigger the separate
	// outbox worker; global append and L5 anchoring must remain outside the
	// batch goroutine. The hook must not block on slow IO for the same
	// reason as OnCheckpointAdvanced.
	OnBatchCommitted func(context.Context, model.BatchRoot)
	LoadBatchItems   func(context.Context, model.BatchManifest) ([]Accepted, error)
}

type Service struct {
	engine  Engine
	store   Store
	metrics *observability.Metrics
	queue   chan Accepted
	opts    Options

	mu      sync.RWMutex
	closed  bool
	lastErr error
	wg      sync.WaitGroup
	seq     uint64

	ingestDone           chan struct{}
	shutdownDone         chan struct{}
	materializeQueue     chan materializeJob
	materializeStop      chan struct{}
	materializeScanStart chan struct{}
	scannerDone          chan struct{}
	scannerStartOnce     sync.Once

	materializeStateMu  sync.Mutex
	materializeInFlight map[string]struct{}
	materializeGroup    singleflight.Group
	artifactWriteMu     sync.Mutex
	pendingMu           sync.Mutex
	pending             map[string][]Accepted
	pendingOrder        []string
}

type materializeJob struct {
	manifest model.BatchManifest
	items    []Accepted
}

func New(engine Engine, store Store, opts Options, metrics *observability.Metrics) *Service {
	if opts.QueueSize <= 0 {
		opts.QueueSize = 1024
	}
	if opts.MaxRecords <= 0 {
		opts.MaxRecords = 1024
	}
	if opts.MaxDelay <= 0 {
		opts.MaxDelay = 500 * time.Millisecond
	}
	if opts.MaterializerWorkers <= 0 {
		opts.MaterializerWorkers = 2
	}
	if opts.MaterializerQueueSize <= 0 {
		opts.MaterializerQueueSize = 4
	}
	if opts.MaterializerPollInterval <= 0 {
		opts.MaterializerPollInterval = 250 * time.Millisecond
	}
	opts.ProofMode = normalizeProofMode(opts.ProofMode)
	s := &Service{
		engine:               engine,
		store:                store,
		metrics:              metrics,
		queue:                make(chan Accepted, opts.QueueSize),
		opts:                 opts,
		seq:                  opts.InitialSeq,
		ingestDone:           make(chan struct{}),
		shutdownDone:         make(chan struct{}),
		materializeQueue:     make(chan materializeJob, opts.MaterializerQueueSize),
		materializeStop:      make(chan struct{}),
		materializeScanStart: make(chan struct{}),
		scannerDone:          make(chan struct{}),
		materializeInFlight:  make(map[string]struct{}),
		pending:              make(map[string][]Accepted),
	}
	s.wg.Add(1)
	go s.worker()
	if opts.ProofMode == ProofModeAsync {
		if !opts.DeferMaterializerScan {
			close(s.materializeScanStart)
		}
		for i := 0; i < opts.MaterializerWorkers; i++ {
			s.wg.Add(1)
			go s.materializerWorker()
		}
		s.wg.Add(1)
		go s.materializerScanner()
	}
	return s
}

func (s *Service) StartMaterializerScan() {
	if s.opts.ProofMode != ProofModeAsync {
		return
	}
	s.scannerStartOnce.Do(func() {
		select {
		case <-s.materializeScanStart:
		default:
			close(s.materializeScanStart)
		}
	})
}

func normalizeProofMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case ProofModeAsync, ProofModeOnDemand:
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return ProofModeInline
	}
}

func (s *Service) Enqueue(ctx context.Context, signed model.SignedClaim, record model.ServerRecord, accepted model.AcceptedReceipt) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "batch enqueue canceled", err)
	}
	item := Accepted{Signed: signed, Record: record, Accepted: accepted}
	return s.enqueue(ctx, item, false)
}

func (s *Service) EnqueueRecovered(ctx context.Context, item Accepted) error {
	if err := ctx.Err(); err != nil {
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "batch enqueue canceled", err)
	}
	return s.enqueue(ctx, item, true)
}

func (s *Service) enqueue(ctx context.Context, item Accepted, wait bool) error {
	for {
		s.mu.RLock()
		if s.closed {
			s.mu.RUnlock()
			return trusterr.New(trusterr.CodeFailedPrecondition, "batch service is shutting down")
		}
		select {
		case s.queue <- item:
			s.setQueueDepth()
			s.mu.RUnlock()
			return nil
		default:
			s.mu.RUnlock()
		}

		if !wait {
			return trusterr.New(trusterr.CodeResourceExhausted, "batch queue is full")
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "batch enqueue canceled", ctx.Err())
		}
	}
}

func (s *Service) Proof(ctx context.Context, recordID string) (model.ProofBundle, error) {
	if s.store == nil {
		return model.ProofBundle{}, trusterr.New(trusterr.CodeFailedPrecondition, "proof store is not configured")
	}
	bundle, err := s.store.GetBundle(ctx, recordID)
	if err == nil {
		if s.opts.ProofMode != ProofModeInline {
			if err := s.requireCommittedManifest(ctx, bundle); err != nil {
				return model.ProofBundle{}, err
			}
		}
		return bundle, nil
	}
	if s.opts.ProofMode != ProofModeOnDemand {
		return bundle, err
	}
	if trusterr.CodeOf(err) != trusterr.CodeNotFound {
		return model.ProofBundle{}, err
	}
	if err := s.materializeRecord(ctx, recordID); err != nil {
		return model.ProofBundle{}, err
	}
	bundle, err = s.store.GetBundle(ctx, recordID)
	if err != nil {
		return model.ProofBundle{}, err
	}
	if err := s.requireCommittedManifest(ctx, bundle); err != nil {
		return model.ProofBundle{}, err
	}
	return bundle, nil
}

func (s *Service) requireCommittedManifest(ctx context.Context, bundle model.ProofBundle) error {
	batchID := bundle.CommittedReceipt.BatchID
	if batchID == "" {
		return nil
	}
	manifest, err := s.store.GetManifest(ctx, batchID)
	if err != nil {
		if trusterr.CodeOf(err) == trusterr.CodeNotFound {
			return nil
		}
		return err
	}
	if manifest.State != model.BatchStateCommitted {
		return trusterr.New(trusterr.CodeNotFound, "proof bundle is not committed yet")
	}
	return nil
}

func (s *Service) RecordIndex(ctx context.Context, recordID string) (model.RecordIndex, bool, error) {
	if s.store == nil {
		return model.RecordIndex{}, false, trusterr.New(trusterr.CodeFailedPrecondition, "proof store is not configured")
	}
	return s.store.GetRecordIndex(ctx, recordID)
}

func (s *Service) Records(ctx context.Context, opts model.RecordListOptions) ([]model.RecordIndex, error) {
	if s.store == nil {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "proof store is not configured")
	}
	return s.store.ListRecordIndexes(ctx, opts)
}

func (s *Service) Roots(ctx context.Context, limit int) ([]model.BatchRoot, error) {
	if s.store == nil {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "proof store is not configured")
	}
	return s.store.ListRoots(ctx, limit)
}

func (s *Service) RootsAfter(ctx context.Context, afterClosedAtUnixN int64, limit int) ([]model.BatchRoot, error) {
	if s.store == nil {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "proof store is not configured")
	}
	return s.store.ListRootsAfter(ctx, afterClosedAtUnixN, limit)
}

func (s *Service) RootsPage(ctx context.Context, opts model.RootListOptions) ([]model.BatchRoot, error) {
	if s.store == nil {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "proof store is not configured")
	}
	return s.store.ListRootsPage(ctx, opts)
}

func (s *Service) LatestRoot(ctx context.Context) (model.BatchRoot, error) {
	if s.store == nil {
		return model.BatchRoot{}, trusterr.New(trusterr.CodeFailedPrecondition, "proof store is not configured")
	}
	return s.store.LatestRoot(ctx)
}

func (s *Service) Manifest(ctx context.Context, batchID string) (model.BatchManifest, error) {
	if s.store == nil {
		return model.BatchManifest{}, trusterr.New(trusterr.CodeFailedPrecondition, "proof store is not configured")
	}
	return s.store.GetManifest(ctx, batchID)
}

func (s *Service) BatchTreeLeaves(ctx context.Context, opts model.BatchTreeLeafListOptions) ([]model.BatchTreeLeaf, error) {
	if s.store == nil {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "proof store is not configured")
	}
	return s.store.ListBatchTreeLeaves(ctx, opts)
}

func (s *Service) BatchTreeNodes(ctx context.Context, opts model.BatchTreeNodeListOptions) ([]model.BatchTreeNode, error) {
	if s.store == nil {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "proof store is not configured")
	}
	return s.store.ListBatchTreeNodes(ctx, opts)
}

func (s *Service) Manifests(ctx context.Context) ([]model.BatchManifest, error) {
	if s.store == nil {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "proof store is not configured")
	}
	return s.store.ListManifests(ctx)
}

func (s *Service) LastError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastErr
}

func (s *Service) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	startedShutdown := false
	if !s.closed {
		s.closed = true
		close(s.queue)
		startedShutdown = true
	}
	s.mu.Unlock()
	if startedShutdown {
		go s.finishShutdown()
	}
	select {
	case <-s.shutdownDone:
		s.setQueueDepth()
		return nil
	case <-ctx.Done():
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "batch shutdown timed out", ctx.Err())
	}
}

func (s *Service) finishShutdown() {
	<-s.ingestDone
	if s.opts.ProofMode == ProofModeAsync {
		close(s.materializeStop)
		<-s.scannerDone
		close(s.materializeQueue)
	}
	s.wg.Wait()
	close(s.shutdownDone)
}

func (s *Service) worker() {
	defer s.wg.Done()
	defer close(s.ingestDone)

	batch := make([]Accepted, 0, s.opts.MaxRecords)
	timer := time.NewTimer(s.opts.MaxDelay)
	if !timer.Stop() {
		<-timer.C
	}
	var timerC <-chan time.Time
	startTimer := func() {
		timer.Reset(s.opts.MaxDelay)
		timerC = timer.C
	}
	stopTimer := func() {
		if timerC == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerC = nil
	}

	for {
		select {
		case item, ok := <-s.queue:
			if !ok {
				stopTimer()
				s.commit(batch)
				return
			}
			s.setQueueDepth()
			batch = append(batch, item)
			if len(batch) == 1 {
				startTimer()
			}
			if len(batch) >= s.opts.MaxRecords {
				stopTimer()
				s.commit(batch)
				batch = batch[:0]
			}
		case <-timerC:
			timerC = nil
			s.commit(batch)
			batch = batch[:0]
		}
	}
}

func (s *Service) commit(items []Accepted) {
	if len(items) == 0 {
		return
	}
	if s.engine == nil || s.store == nil {
		s.setLastError(trusterr.New(trusterr.CodeFailedPrecondition, "batch engine and store are required"))
		return
	}
	start := time.Now().UTC()
	batchID := s.nextBatchID(start)
	if err := s.persistBatch(context.Background(), batchID, start, items); err != nil {
		s.setLastError(err)
		return
	}
	if s.metrics != nil {
		s.metrics.BatchSizeRecords.Observe(float64(len(items)))
		s.metrics.BatchCommitLatency.Observe(time.Since(start).Seconds())
	}
	s.setLastError(nil)
}

// persistBatch writes a batch using the prepared -> bundles/root -> committed
// manifest protocol so that a crash between steps is recoverable from the WAL
// by rebuilding the deterministic outputs and replaying the remaining writes.
func (s *Service) persistBatch(ctx context.Context, batchID string, closedAt time.Time, items []Accepted) error {
	stageStart := time.Now()
	signed := make([]model.SignedClaim, len(items))
	records := make([]model.ServerRecord, len(items))
	accepted := make([]model.AcceptedReceipt, len(items))
	recordIDs := make([]string, len(items))
	for i := range items {
		signed[i] = items[i].Signed
		records[i] = items[i].Record
		accepted[i] = items[i].Accepted
		recordIDs[i] = items[i].Record.RecordID
	}
	s.observeBatchStage("collect", stageStart)

	var (
		commit model.BatchCommit
		err    error
	)
	stageStart = time.Now()
	if s.opts.ProofMode == ProofModeInline {
		commit, err = s.computeBatch(ctx, batchID, closedAt, signed, records, accepted, model.BatchComputeOptions{
			Mode:        model.BatchComputeMaterialized,
			IncludeTree: true,
		})
		if err == nil && len(commit.Bundles) != len(items) {
			err = trusterr.New(trusterr.CodeInternal, "commit batch returned inconsistent proof count")
		}
	} else {
		commit, err = s.computeBatch(ctx, batchID, closedAt, signed, records, accepted, model.BatchComputeOptions{
			Mode:        model.BatchComputePlanOnly,
			IncludeTree: true,
		})
		if err == nil && len(commit.Indexes) != len(items) {
			err = trusterr.New(trusterr.CodeInternal, "batch index plan returned inconsistent index count")
		}
	}
	s.observeBatchStage("commit_batch", stageStart)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeInternal, "commit batch", err)
	}
	manifest := model.BatchManifest{
		SchemaVersion:    model.SchemaBatchManifest,
		BatchID:          batchID,
		NodeID:           commit.Root.NodeID,
		LogID:            commit.Root.LogID,
		State:            model.BatchStatePreparing,
		TreeAlg:          model.DefaultMerkleTreeAlg,
		TreeSize:         commit.Root.TreeSize,
		BatchRoot:        append([]byte(nil), commit.Root.BatchRoot...),
		RecordIDs:        recordIDs,
		WALRange:         walRangeFor(items),
		ClosedAtUnixN:    commit.Root.ClosedAtUnixN,
		PreparingAtUnixN: time.Now().UTC().UnixNano(),
	}
	stageStart = time.Now()
	err = s.store.PutManifest(ctx, manifest)
	s.observeBatchStage("manifest_prepare", stageStart)
	if err != nil {
		return err
	}
	stageStart = time.Now()
	if s.opts.ProofMode != ProofModeInline {
		if err := s.writeIndexesAndRoot(ctx, commit.Indexes, commit.Root); err != nil {
			s.observeBatchStage("artifacts", stageStart)
			return err
		}
		if err := s.writeBatchTree(ctx, commit.Tree); err != nil {
			s.observeBatchStage("artifacts", stageStart)
			return err
		}
		manifest.State = model.BatchStatePrepared
		manifest.PreparedAtUnixN = time.Now().UTC().UnixNano()
		if err := s.store.PutManifest(ctx, manifest); err != nil {
			s.observeBatchStage("artifacts", stageStart)
			return err
		}
		s.observeBatchStage("artifacts", stageStart)
		itemsCopy := cloneAcceptedItems(items)
		if s.opts.ProofMode == ProofModeAsync {
			s.startAsyncMaterialize(manifest, itemsCopy)
		} else {
			s.rememberPending(manifest.BatchID, itemsCopy)
		}
		return nil
	}
	root, err := s.writeBundlesAndRoot(ctx, batchID, commit.Bundles)
	s.observeBatchStage("artifacts", stageStart)
	if err != nil {
		return err
	}
	if err := s.writeBatchTree(ctx, commit.Tree); err != nil {
		return err
	}
	manifest.State = model.BatchStateCommitted
	manifest.CommittedAtUnixN = time.Now().UTC().UnixNano()
	stageStart = time.Now()
	err = s.store.PutManifest(ctx, manifest)
	s.observeBatchStage("manifest_commit", stageStart)
	if err != nil {
		return err
	}
	// Advance the WAL checkpoint as a best-effort optimization for the next
	// restart. A failed write here never breaks correctness: replay can
	// always fall back to scanning the whole WAL and consulting manifests.
	stageStart = time.Now()
	err = s.advanceCheckpoint(ctx, manifest)
	s.observeBatchStage("checkpoint", stageStart)
	if err != nil {
		s.setLastError(err)
	}
	stageStart = time.Now()
	s.fireOnBatchCommitted(ctx, root)
	s.observeBatchStage("outbox_hook", stageStart)
	return nil
}

func (s *Service) writeBundlesAndRoot(ctx context.Context, batchID string, bundles []model.ProofBundle) (model.BatchRoot, error) {
	if len(bundles) == 0 {
		return model.BatchRoot{}, trusterr.New(trusterr.CodeInternal, "commit batch returned no proof bundles")
	}
	root := rootFromBundles(batchID, bundles)
	if writer, ok := s.store.(proofstore.BatchArtifactWriter); ok {
		if err := writer.PutBatchArtifacts(ctx, bundles, root); err != nil {
			return model.BatchRoot{}, err
		}
		return root, nil
	}
	for i := range bundles {
		if err := s.store.PutBundle(ctx, bundles[i]); err != nil {
			return model.BatchRoot{}, err
		}
	}
	if err := s.store.PutRoot(ctx, root); err != nil {
		return model.BatchRoot{}, err
	}
	return root, nil
}

func buildBatchTreeArtifacts(batchID string, root model.BatchRoot, records []model.ServerRecord) ([]model.BatchTreeLeaf, []model.BatchTreeNode, error) {
	snapshot, err := buildBatchTreeSnapshot(batchID, root, records)
	if err != nil {
		return nil, nil, err
	}
	return batchTreeArtifactsFromSnapshot(snapshot)
}

func buildBatchTreeSnapshot(batchID string, root model.BatchRoot, records []model.ServerRecord) (model.BatchTreeSnapshot, error) {
	tree, err := merkle.Build(records)
	if err != nil {
		return model.BatchTreeSnapshot{}, err
	}
	if len(root.BatchRoot) > 0 && !bytes.Equal(root.BatchRoot, tree.Root()) {
		return model.BatchTreeSnapshot{}, trusterr.New(trusterr.CodeDataLoss, "batch tree root does not match committed batch root")
	}
	now := time.Now().UTC().UnixNano()
	recordIDs := make([]string, len(records))
	for i := range records {
		recordIDs[i] = records[i].RecordID
	}
	rawNodes := tree.CompactNodes()
	sort.Slice(rawNodes, func(i, j int) bool {
		if rawNodes[i].Level != rawNodes[j].Level {
			return rawNodes[i].Level < rawNodes[j].Level
		}
		return rawNodes[i].StartIndex < rawNodes[j].StartIndex
	})
	nodes := make([]model.BatchTreeSnapshotNode, len(rawNodes))
	for i := range rawNodes {
		nodes[i] = model.BatchTreeSnapshotNode{
			Level:      rawNodes[i].Level,
			StartIndex: rawNodes[i].StartIndex,
			Width:      rawNodes[i].Width,
			Hash:       rawNodes[i].Hash,
		}
	}
	return model.BatchTreeSnapshot{
		BatchID:        batchID,
		CreatedAtUnixN: now,
		RecordIDs:      recordIDs,
		LeafHashes:     append([][32]byte(nil), tree.CompactLeaves()...),
		Nodes:          nodes,
	}, nil
}

func batchTreeArtifactsFromSnapshot(snapshot model.BatchTreeSnapshot) ([]model.BatchTreeLeaf, []model.BatchTreeNode, error) {
	if snapshot.BatchID == "" || len(snapshot.LeafHashes) == 0 || len(snapshot.RecordIDs) != len(snapshot.LeafHashes) {
		return nil, nil, trusterr.New(trusterr.CodeDataLoss, "invalid batch tree snapshot")
	}
	leaves := make([]model.BatchTreeLeaf, len(snapshot.LeafHashes))
	for i := range snapshot.LeafHashes {
		leaves[i] = model.BatchTreeLeaf{
			SchemaVersion:  model.SchemaBatchTreeLeaf,
			BatchID:        snapshot.BatchID,
			RecordID:       snapshot.RecordIDs[i],
			LeafIndex:      uint64(i),
			LeafHash:       append([]byte(nil), snapshot.LeafHashes[i][:]...),
			CreatedAtUnixN: snapshot.CreatedAtUnixN,
		}
	}
	nodes := make([]model.BatchTreeNode, len(snapshot.Nodes))
	for i := range snapshot.Nodes {
		nodes[i] = model.BatchTreeNode{
			SchemaVersion:  model.SchemaBatchTreeNode,
			BatchID:        snapshot.BatchID,
			Level:          snapshot.Nodes[i].Level,
			StartIndex:     snapshot.Nodes[i].StartIndex,
			Width:          snapshot.Nodes[i].Width,
			Hash:           append([]byte(nil), snapshot.Nodes[i].Hash[:]...),
			CreatedAtUnixN: snapshot.CreatedAtUnixN,
		}
	}
	return leaves, nodes, nil
}

func rootFromBundles(batchID string, bundles []model.ProofBundle) model.BatchRoot {
	r := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       batchID,
		TreeSize:      uint64(len(bundles)),
	}
	if len(bundles) > 0 {
		r.BatchRoot = append([]byte(nil), bundles[0].CommittedReceipt.BatchRoot...)
		r.ClosedAtUnixN = bundles[0].CommittedReceipt.ClosedAtUnixN
		r.NodeID = bundles[0].NodeID
		r.LogID = bundles[0].LogID
	}
	return r
}

func (s *Service) planBatchIndexes(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) (model.BatchRoot, []model.RecordIndex, error) {
	if planner, ok := s.engine.(IndexEngine); ok {
		return planner.CommitBatchIndexes(batchID, closedAt, signed, records, accepted)
	}
	bundles, err := s.engine.CommitBatch(batchID, closedAt, signed, records, accepted)
	if err != nil {
		return model.BatchRoot{}, nil, err
	}
	if len(bundles) != len(records) {
		return model.BatchRoot{}, nil, trusterr.New(trusterr.CodeInternal, "commit batch returned inconsistent proof count")
	}
	indexes := make([]model.RecordIndex, len(bundles))
	for i := range bundles {
		indexes[i] = model.RecordIndexFromBundle(bundles[i])
	}
	return rootFromBundles(batchID, bundles), indexes, nil
}

func (s *Service) computeBatch(ctx context.Context, batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt, opts model.BatchComputeOptions) (model.BatchCommit, error) {
	if engine, ok := s.engine.(ComputeEngine); ok {
		return engine.ComputeBatch(ctx, batchID, closedAt, signed, records, accepted, opts)
	}
	if opts.Mode == model.BatchComputeMaterialized {
		bundles, err := s.engine.CommitBatch(batchID, closedAt, signed, records, accepted)
		if err != nil {
			return model.BatchCommit{}, err
		}
		result := model.BatchCommit{Root: rootFromBundles(batchID, bundles), Bundles: bundles}
		result.Indexes = make([]model.RecordIndex, len(bundles))
		for i := range bundles {
			result.Indexes[i] = model.RecordIndexFromBundle(bundles[i])
		}
		if opts.IncludeTree {
			result.Tree, err = buildBatchTreeSnapshot(batchID, result.Root, records)
		}
		return result, err
	}
	root, indexes, err := s.planBatchIndexes(batchID, closedAt, signed, records, accepted)
	if err != nil {
		return model.BatchCommit{}, err
	}
	result := model.BatchCommit{Root: root, Indexes: indexes}
	if opts.IncludeTree {
		result.Tree, err = buildBatchTreeSnapshot(batchID, root, records)
	}
	return result, err
}

func (s *Service) writeIndexesAndRoot(ctx context.Context, indexes []model.RecordIndex, root model.BatchRoot) error {
	if writer, ok := s.store.(proofstore.PreparedBatchIndexRootWriter); ok {
		return writer.PutPreparedBatchIndexesAndRoot(ctx, indexes, root)
	}
	if writer, ok := s.store.(proofstore.BatchIndexRootWriter); ok {
		return writer.PutBatchIndexesAndRoot(ctx, indexes, root)
	}
	for i := range indexes {
		if err := s.store.PutRecordIndex(ctx, indexes[i]); err != nil {
			return err
		}
	}
	return s.store.PutRoot(ctx, root)
}

func cloneAcceptedItems(items []Accepted) []Accepted {
	out := make([]Accepted, len(items))
	copy(out, items)
	return out
}

// RecoverManifest replays a prepared manifest from items looked up from the
// WAL by the caller. Inline/async modes finish materializing bundles and mark
// the manifest committed. On-demand mode only repairs deterministic
// root/index artifacts and leaves bundles lazy so the first Proof call remains
// the materialization boundary.
func (s *Service) RecoverManifest(ctx context.Context, manifest model.BatchManifest, items []Accepted) error {
	if manifest.State == model.BatchStateCommitted {
		return nil
	}
	if manifest.State == model.BatchStateFailed {
		return trusterr.New(trusterr.CodeFailedPrecondition, "batch materialization is permanently failed")
	}
	if manifest.State != model.BatchStatePreparing && manifest.State != model.BatchStatePrepared {
		return trusterr.New(trusterr.CodeFailedPrecondition, fmt.Sprintf("unknown batch manifest state: %s", manifest.State))
	}
	if len(items) != len(manifest.RecordIDs) {
		return trusterr.New(trusterr.CodeFailedPrecondition, fmt.Sprintf("recovered items (%d) do not match manifest record count (%d)", len(items), len(manifest.RecordIDs)))
	}
	for i, rid := range manifest.RecordIDs {
		if items[i].Record.RecordID != rid {
			return trusterr.New(trusterr.CodeFailedPrecondition, fmt.Sprintf("recovered item %d record_id mismatch: got %s, want %s", i, items[i].Record.RecordID, rid))
		}
	}
	if s.opts.ProofMode != ProofModeInline {
		signed, records, accepted := splitAcceptedItems(items)
		planned, err := s.computeBatch(ctx, manifest.BatchID, time.Unix(0, manifest.ClosedAtUnixN).UTC(), signed, records, accepted, model.BatchComputeOptions{
			Mode:        model.BatchComputePlanOnly,
			IncludeTree: true,
		})
		if err != nil {
			return trusterr.Wrap(trusterr.CodeInternal, "rebuild batch indexes during recovery", err)
		}
		if len(manifest.BatchRoot) > 0 && !bytes.Equal(manifest.BatchRoot, planned.Root.BatchRoot) {
			return trusterr.New(trusterr.CodeDataLoss, "recovered batch root does not match prepared manifest")
		}
		if err := s.writeIndexesAndRoot(ctx, planned.Indexes, planned.Root); err != nil {
			return err
		}
		if err := s.writeBatchTree(ctx, planned.Tree); err != nil {
			return err
		}
		manifest.State = model.BatchStatePrepared
		if manifest.PreparedAtUnixN == 0 {
			manifest.PreparedAtUnixN = time.Now().UTC().UnixNano()
		}
		if err := s.store.PutManifest(ctx, manifest); err != nil {
			return err
		}
		if s.opts.ProofMode == ProofModeOnDemand {
			return nil
		}
	}

	_, err := s.materializeManifest(ctx, manifest, items)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeInternal, "rebuild batch during recovery", err)
	}
	return nil
}

func (s *Service) startAsyncMaterialize(manifest model.BatchManifest, items []Accepted) {
	s.enqueueMaterialization(materializeJob{manifest: manifest, items: items})
}

func (s *Service) enqueueMaterialization(job materializeJob) bool {
	if job.manifest.BatchID == "" {
		return false
	}
	s.materializeStateMu.Lock()
	if _, exists := s.materializeInFlight[job.manifest.BatchID]; exists {
		s.materializeStateMu.Unlock()
		return true
	}
	s.materializeInFlight[job.manifest.BatchID] = struct{}{}
	s.materializeStateMu.Unlock()

	select {
	case s.materializeQueue <- job:
		s.setMaterializerQueueDepth()
		return true
	default:
		s.releaseMaterialization(job.manifest.BatchID)
		s.setMaterializerQueueDepth()
		return false
	}
}

func (s *Service) releaseMaterialization(batchID string) {
	s.materializeStateMu.Lock()
	delete(s.materializeInFlight, batchID)
	s.materializeStateMu.Unlock()
}

func (s *Service) materializerWorker() {
	defer s.wg.Done()
	for job := range s.materializeQueue {
		s.setMaterializerQueueDepth()
		if s.metrics != nil {
			s.metrics.MaterializerInFlight.Inc()
		}
		s.runMaterializationJob(job)
		if s.metrics != nil {
			s.metrics.MaterializerInFlight.Dec()
		}
		s.releaseMaterialization(job.manifest.BatchID)
	}
}

func (s *Service) runMaterializationJob(job materializeJob) {
	ctx := context.Background()
	manifest, err := s.store.GetManifest(ctx, job.manifest.BatchID)
	if err != nil {
		s.setLastError(err)
		return
	}
	if manifest.State == model.BatchStateCommitted || manifest.State == model.BatchStateFailed {
		return
	}
	if manifest.State != model.BatchStatePrepared || manifest.MaterializeNextUnixN > time.Now().UTC().UnixNano() {
		return
	}
	items := job.items
	if len(items) == 0 {
		items, err = s.materializationItems(ctx, manifest)
		if err != nil {
			s.recordMaterializationFailure(ctx, manifest, err)
			s.setLastError(err)
			return
		}
	}
	if _, err := s.materializeManifest(ctx, manifest, items); err != nil {
		s.recordMaterializationFailure(ctx, manifest, err)
		s.setLastError(err)
		return
	}
	if s.metrics != nil {
		s.metrics.MaterializedRecords.Add(float64(len(items)))
	}
	s.setLastError(nil)
}

func (s *Service) materializerScanner() {
	defer s.wg.Done()
	defer close(s.scannerDone)
	select {
	case <-s.materializeScanStart:
	case <-s.materializeStop:
		return
	}
	ticker := time.NewTicker(s.opts.MaterializerPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.schedulePreparedManifests(context.Background())
		case <-s.materializeStop:
			return
		}
	}
}

func (s *Service) schedulePreparedManifests(ctx context.Context) {
	var (
		manifests []model.BatchManifest
		err       error
	)
	now := time.Now().UTC().UnixNano()
	if lister, ok := s.store.(proofstore.PreparedManifestLister); ok {
		manifests, err = lister.ListPreparedManifests(ctx, s.opts.MaterializerNodeID, now, cap(s.materializeQueue)+s.opts.MaterializerWorkers)
	} else {
		manifests, err = s.store.ListManifests(ctx)
	}
	if err != nil {
		s.setLastError(err)
		return
	}
	if s.metrics != nil {
		s.metrics.MaterializerPrepared.Set(float64(len(manifests)))
		oldest := int64(0)
		for i := range manifests {
			if manifests[i].PreparedAtUnixN > 0 && (oldest == 0 || manifests[i].PreparedAtUnixN < oldest) {
				oldest = manifests[i].PreparedAtUnixN
			}
		}
		age := float64(0)
		if oldest > 0 && now > oldest {
			age = time.Duration(now - oldest).Seconds()
		}
		s.metrics.MaterializerOldestAge.Set(age)
	}
	for i := range manifests {
		manifest := manifests[i]
		if manifest.State != model.BatchStatePrepared || manifest.MaterializeNextUnixN > now {
			continue
		}
		if s.opts.MaterializerNodeID != "" && manifest.NodeID != "" && manifest.NodeID != s.opts.MaterializerNodeID {
			continue
		}
		if !s.enqueueMaterialization(materializeJob{manifest: manifest}) {
			return
		}
	}
}

func (s *Service) recordMaterializationFailure(ctx context.Context, manifest model.BatchManifest, cause error) {
	latest, err := s.store.GetManifest(ctx, manifest.BatchID)
	if err == nil {
		manifest = latest
	}
	if manifest.State == model.BatchStateCommitted {
		return
	}
	manifest.MaterializeAttempts++
	manifest.MaterializeLastError = cause.Error()
	manifest.MaterializeFailureCode = string(trusterr.CodeOf(cause))
	if permanentMaterializationError(cause) {
		manifest.State = model.BatchStateFailed
		manifest.MaterializeNextUnixN = 0
	} else {
		manifest.State = model.BatchStatePrepared
		manifest.MaterializeNextUnixN = time.Now().UTC().Add(materializationBackoff(manifest.MaterializeAttempts)).UnixNano()
		if s.metrics != nil {
			s.metrics.MaterializerRetries.Inc()
		}
	}
	if err := s.store.PutManifest(ctx, manifest); err != nil {
		s.setLastError(err)
	}
}

func permanentMaterializationError(err error) bool {
	switch trusterr.CodeOf(err) {
	case trusterr.CodeInvalidArgument, trusterr.CodeDataLoss:
		return true
	default:
		return false
	}
}

func materializationBackoff(attempts int) time.Duration {
	delay := 100 * time.Millisecond
	for i := 1; i < attempts && delay < time.Minute; i++ {
		if delay >= 30*time.Second {
			return time.Minute
		}
		delay *= 2
	}
	if delay > time.Minute {
		return time.Minute
	}
	return delay
}

func (s *Service) materializeRecord(ctx context.Context, recordID string) error {
	if _, err := s.store.GetBundle(ctx, recordID); err == nil {
		return nil
	} else if trusterr.CodeOf(err) != trusterr.CodeNotFound {
		return err
	}
	idx, ok, err := s.store.GetRecordIndex(ctx, recordID)
	if err != nil {
		return err
	}
	if !ok || idx.BatchID == "" {
		return trusterr.New(trusterr.CodeNotFound, "proof bundle not found")
	}
	_, err, _ = s.materializeGroup.Do(idx.BatchID, func() (any, error) {
		manifest, err := s.store.GetManifest(ctx, idx.BatchID)
		if err != nil {
			return nil, err
		}
		if manifest.State == model.BatchStateCommitted {
			return nil, nil
		}
		if manifest.State == model.BatchStateFailed {
			return nil, trusterr.New(trusterr.CodeFailedPrecondition, "batch materialization failed")
		}
		items, err := s.materializationItems(ctx, manifest)
		if err != nil {
			return nil, err
		}
		_, err = s.materializeManifest(ctx, manifest, items)
		return nil, err
	})
	return err
}

func (s *Service) materializationItems(ctx context.Context, manifest model.BatchManifest) ([]Accepted, error) {
	s.pendingMu.Lock()
	items := cloneAcceptedItems(s.pending[manifest.BatchID])
	s.pendingMu.Unlock()
	if len(items) > 0 {
		return items, nil
	}
	if s.opts.LoadBatchItems == nil {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "proof bundle is not materialized")
	}
	return s.opts.LoadBatchItems(ctx, manifest)
}

func (s *Service) materializeManifest(ctx context.Context, manifest model.BatchManifest, items []Accepted) (model.BatchRoot, error) {
	signed, records, accepted := splitAcceptedItems(items)
	closedAt := time.Unix(0, manifest.ClosedAtUnixN).UTC()
	commit, err := s.computeBatch(ctx, manifest.BatchID, closedAt, signed, records, accepted, model.BatchComputeOptions{
		Mode:        model.BatchComputeMaterialized,
		IncludeTree: s.opts.ProofMode == ProofModeInline,
	})
	if err != nil {
		return model.BatchRoot{}, err
	}
	if len(commit.Bundles) != len(manifest.RecordIDs) {
		return model.BatchRoot{}, trusterr.New(trusterr.CodeInternal, "materialized bundle count mismatch")
	}
	if len(manifest.BatchRoot) > 0 && !bytes.Equal(manifest.BatchRoot, commit.Root.BatchRoot) {
		return model.BatchRoot{}, trusterr.New(trusterr.CodeDataLoss, "materialized batch root does not match prepared manifest")
	}
	s.artifactWriteMu.Lock()
	root, err := s.writeMaterializedBundles(ctx, manifest.BatchID, commit.Bundles)
	if err != nil {
		s.artifactWriteMu.Unlock()
		return model.BatchRoot{}, err
	}
	if s.opts.ProofMode == ProofModeInline {
		if err := s.writeBatchTree(ctx, commit.Tree); err != nil {
			s.artifactWriteMu.Unlock()
			return model.BatchRoot{}, err
		}
	}
	s.artifactWriteMu.Unlock()
	manifest.State = model.BatchStateCommitted
	if manifest.CommittedAtUnixN == 0 {
		manifest.CommittedAtUnixN = time.Now().UTC().UnixNano()
	}
	manifest.MaterializeNextUnixN = 0
	manifest.MaterializeLastError = ""
	manifest.MaterializeFailureCode = ""
	if err := s.store.PutManifest(ctx, manifest); err != nil {
		return model.BatchRoot{}, err
	}
	if err := s.advanceCheckpoint(ctx, manifest); err != nil {
		s.setLastError(err)
	}
	s.forgetPending(manifest.BatchID)
	s.fireOnBatchCommitted(ctx, root)
	return root, nil
}

func (s *Service) writeMaterializedBundles(ctx context.Context, batchID string, bundles []model.ProofBundle) (model.BatchRoot, error) {
	if len(bundles) == 0 {
		return model.BatchRoot{}, trusterr.New(trusterr.CodeInternal, "commit batch returned no proof bundles")
	}
	root := rootFromBundles(batchID, bundles)
	if s.opts.ProofMode != ProofModeInline {
		if writer, ok := s.store.(proofstore.MaterializedBatchArtifactWriter); ok {
			if err := writer.PutMaterializedBatchArtifacts(ctx, bundles); err != nil {
				return model.BatchRoot{}, err
			}
			return root, nil
		}
	}
	return s.writeBundlesAndRoot(ctx, batchID, bundles)
}

func (s *Service) writeBatchTree(ctx context.Context, snapshot model.BatchTreeSnapshot) error {
	if s.metrics != nil {
		s.metrics.BatchTreeTiles.Observe(float64(batchTreeTileCount(snapshot)))
	}
	if writer, ok := s.store.(proofstore.BatchTreeSnapshotWriter); ok {
		return writer.PutBatchTreeSnapshot(ctx, snapshot)
	}
	leaves, nodes, err := batchTreeArtifactsFromSnapshot(snapshot)
	if err != nil {
		return err
	}
	return s.store.PutBatchTreeArtifacts(ctx, leaves, nodes)
}

func batchTreeTileCount(snapshot model.BatchTreeSnapshot) int {
	tiles := (len(snapshot.LeafHashes) + 511) / 512
	for start := 0; start < len(snapshot.Nodes); {
		level := snapshot.Nodes[start].Level
		end := start
		for end < len(snapshot.Nodes) && snapshot.Nodes[end].Level == level {
			end++
		}
		if level != 0 {
			tiles += (end - start + 511) / 512
		}
		start = end
	}
	return tiles
}

func (s *Service) setMaterializerQueueDepth() {
	if s.metrics != nil {
		s.metrics.QueueDepth.WithLabelValues("materializer").Set(float64(len(s.materializeQueue)))
	}
}

func (s *Service) planBatchIndexesFromItems(batchID string, closedAt time.Time, items []Accepted) (model.BatchRoot, []model.RecordIndex, []model.ServerRecord, error) {
	signed, records, accepted := splitAcceptedItems(items)
	root, indexes, err := s.planBatchIndexes(batchID, closedAt, signed, records, accepted)
	return root, indexes, records, err
}

func splitAcceptedItems(items []Accepted) ([]model.SignedClaim, []model.ServerRecord, []model.AcceptedReceipt) {
	signed := make([]model.SignedClaim, len(items))
	records := make([]model.ServerRecord, len(items))
	accepted := make([]model.AcceptedReceipt, len(items))
	for i := range items {
		signed[i] = items[i].Signed
		records[i] = items[i].Record
		accepted[i] = items[i].Accepted
	}
	return signed, records, accepted
}

func (s *Service) rememberPending(batchID string, items []Accepted) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if _, exists := s.pending[batchID]; !exists {
		s.pendingOrder = append(s.pendingOrder, batchID)
	}
	s.pending[batchID] = cloneAcceptedItems(items)
	const maxPendingBatches = 64
	for len(s.pendingOrder) > maxPendingBatches {
		oldest := s.pendingOrder[0]
		s.pendingOrder = s.pendingOrder[1:]
		delete(s.pending, oldest)
	}
}

func (s *Service) forgetPending(batchID string) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	delete(s.pending, batchID)
	for i := range s.pendingOrder {
		if s.pendingOrder[i] == batchID {
			s.pendingOrder = append(s.pendingOrder[:i], s.pendingOrder[i+1:]...)
			break
		}
	}
}

// fireOnBatchCommitted runs the commit hook in a panic-safe wrapper so a buggy
// observer cannot crash the batch worker. It is intentionally synchronous only
// for bounded local side effects such as durable outbox enqueue; slow global
// append, external notary calls, or network IO belong in a separate worker.
func (s *Service) fireOnBatchCommitted(ctx context.Context, root model.BatchRoot) {
	if s.opts.OnBatchCommitted == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			s.setLastError(trusterr.New(trusterr.CodeInternal,
				fmt.Sprintf("OnBatchCommitted panic: %v", r)))
		}
	}()
	s.opts.OnBatchCommitted(ctx, root)
}

// advanceCheckpoint moves the WAL checkpoint forward to cover every record
// inside manifest. The checkpoint is always advanced monotonically, so a
// stale read (concurrent commits, retries, recovery passes) never regresses
// it. Persisting the checkpoint is a best-effort optimization and a failure
// is surfaced as LastError so operators can investigate without rolling back
// the commit.
func (s *Service) advanceCheckpoint(ctx context.Context, manifest model.BatchManifest) error {
	to := manifest.WALRange.To
	if to.Sequence == 0 {
		return nil
	}
	existing, found, err := s.store.GetCheckpoint(ctx)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "load wal checkpoint", err)
	}
	if found && existing.LastSequence >= to.Sequence {
		return nil
	}
	cp := model.WALCheckpoint{
		SchemaVersion:   model.SchemaWALCheckpoint,
		SegmentID:       to.SegmentID,
		LastSequence:    to.Sequence,
		LastOffset:      to.Offset,
		BatchID:         manifest.BatchID,
		RecordedAtUnixN: time.Now().UTC().UnixNano(),
	}
	if err := s.store.PutCheckpoint(ctx, cp); err != nil {
		return err
	}
	if s.metrics != nil {
		s.metrics.WALCheckpointLastSequence.Set(float64(cp.LastSequence))
	}
	if s.opts.OnCheckpointAdvanced != nil {
		// Hook runs synchronously on the batch worker; see Options doc
		// for the tradeoff. Panics are recovered so a buggy prune hook
		// cannot take down the batcher.
		defer func() {
			if r := recover(); r != nil {
				s.setLastError(trusterr.New(trusterr.CodeInternal,
					fmt.Sprintf("OnCheckpointAdvanced panic: %v", r)))
			}
		}()
		s.opts.OnCheckpointAdvanced(ctx, cp)
	}
	return nil
}

func walRangeFor(items []Accepted) model.WALRange {
	if len(items) == 0 {
		return model.WALRange{}
	}
	from := items[0].Record.WAL
	to := items[0].Record.WAL
	for i := 1; i < len(items); i++ {
		pos := items[i].Record.WAL
		if pos.Sequence < from.Sequence {
			from = pos
		}
		if pos.Sequence > to.Sequence {
			to = pos
		}
	}
	return model.WALRange{From: from, To: to}
}

func (s *Service) nextBatchID(now time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return fmt.Sprintf("batch-%d-%06d", now.UTC().UnixNano(), s.seq)
}

func (s *Service) setLastError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = err
}

func (s *Service) setQueueDepth() {
	if s.metrics != nil {
		s.metrics.QueueDepth.WithLabelValues("batch").Set(float64(len(s.queue)))
	}
}

func (s *Service) observeBatchStage(stage string, start time.Time) {
	if s.metrics != nil {
		s.metrics.BatchStageLatency.WithLabelValues(stage).Observe(time.Since(start).Seconds())
	}
}
