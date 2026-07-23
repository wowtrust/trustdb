// Package globallog implements TrustDB's global transparency log. The log
// appends one leaf per committed batch root and emits a SignedTreeHead after
// every append; L5 anchors publish those STHs, not individual batch roots.
package globallog

import (
	"bytes"
	"context"
	"fmt"
	"math/bits"
	"strings"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/merkle"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const (
	appendConflictAttempts   = 16
	appendConflictBackoff    = time.Millisecond
	appendConflictMaxBackoff = 16 * time.Millisecond
)

type Store interface {
	PutGlobalLeaf(context.Context, model.GlobalLogLeaf) error
	GetGlobalLeaf(context.Context, uint64) (model.GlobalLogLeaf, bool, error)
	GetGlobalLeafByBatchID(context.Context, string) (model.GlobalLogLeaf, bool, error)
	ListGlobalLeaves(context.Context) ([]model.GlobalLogLeaf, error)
	ListGlobalLeavesRange(context.Context, uint64, int) ([]model.GlobalLogLeaf, error)
	ListGlobalLeavesPage(context.Context, model.GlobalLeafListOptions) ([]model.GlobalLogLeaf, error)
	PutGlobalLogNode(context.Context, model.GlobalLogNode) error
	GetGlobalLogNode(context.Context, uint64, uint64) (model.GlobalLogNode, bool, error)
	ListGlobalLogNodesAfter(context.Context, uint64, uint64, int) ([]model.GlobalLogNode, error)
	PutGlobalLogState(context.Context, model.GlobalLogState) error
	GetGlobalLogState(context.Context) (model.GlobalLogState, bool, error)
	PutSignedTreeHead(context.Context, model.SignedTreeHead) error
	GetSignedTreeHead(context.Context, uint64) (model.SignedTreeHead, bool, error)
	ListSignedTreeHeadsPage(context.Context, model.TreeHeadListOptions) ([]model.SignedTreeHead, error)
	LatestSignedTreeHead(context.Context) (model.SignedTreeHead, bool, error)
	PutGlobalLogTile(context.Context, model.GlobalLogTile) error
	ListGlobalLogTiles(context.Context) ([]model.GlobalLogTile, error)
	CommitGlobalLogAppend(context.Context, model.GlobalLogAppend) error
}

type latestSTHAnchorResultReader interface {
	LatestSTHAnchorResult(context.Context) (model.STHAnchorResult, bool, error)
}

type latestSTHAnchorResultKeyedReader interface {
	LatestSTHAnchorResultForKey(context.Context, model.STHAnchorScheduleKey) (model.STHAnchorResult, bool, error)
}

type BatchAppendStore interface {
	CommitGlobalLogAppends(context.Context, []model.GlobalLogAppend) error
}

type Service struct {
	mu        sync.Mutex
	store     Store
	nodeID    string
	logID     string
	signer    trustcrypto.Signer
	provider  trustcrypto.Provider
	profile   merkle.Profile
	clock     func() time.Time
	anchorKey *model.STHAnchorScheduleKey
}

type Options struct {
	Store          Store
	NodeID         string
	LogID          string
	Signer         trustcrypto.Signer
	CryptoProvider trustcrypto.Provider
	Clock          func() time.Time
	// AnchorSinkName binds GlobalEvidence to the configured provider stream.
	// Empty preserves the generic aggregate lookup used by standalone tools.
	AnchorSinkName string
}

func New(opts Options) (*Service, error) {
	if opts.Store == nil {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "global log store is required")
	}
	provider := opts.CryptoProvider
	if provider == nil {
		provider = trustcrypto.DefaultProvider()
	}
	if err := trustcrypto.ValidateSignerWithProvider(context.Background(), provider, opts.Signer); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeInvalidArgument, "global log signer is invalid", err)
	}
	profile, err := merkle.ProfileForSuite(provider.Suite())
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeInvalidArgument, "global log merkle profile is invalid", err)
	}
	clock := opts.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	logID := strings.TrimSpace(opts.LogID)
	if logID == "" {
		logID = "trustdb-global-log"
	}
	nodeID := strings.TrimSpace(opts.NodeID)
	service := &Service{
		store:    opts.Store,
		nodeID:   nodeID,
		logID:    logID,
		signer:   opts.Signer,
		provider: provider,
		profile:  profile,
		clock:    clock,
	}
	if sinkName := strings.TrimSpace(opts.AnchorSinkName); sinkName != "" {
		service.anchorKey = &model.STHAnchorScheduleKey{NodeID: nodeID, LogID: logID, SinkName: sinkName}
	}
	return service, nil
}

// NewReader returns a read-only global log service. It can build inclusion,
// consistency, and compaction artefacts from an existing store, but cannot
// append because no STH signing key is configured.
func NewReader(store Store) (*Service, error) {
	return NewReaderWithProvider(store, trustcrypto.DefaultProvider())
}

func NewReaderWithProvider(store Store, provider trustcrypto.Provider) (*Service, error) {
	if store == nil {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "global log store is required")
	}
	if provider == nil {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "global log crypto provider is required")
	}
	profile, err := merkle.ProfileForSuite(provider.Suite())
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeInvalidArgument, "global log merkle profile is invalid", err)
	}
	return &Service{
		store:    store,
		provider: provider,
		profile:  profile,
		clock:    func() time.Time { return time.Now().UTC() },
	}, nil
}

// StreamIdentity returns the signer identity for newly created Signed Tree
// Heads. Durable outbox workers use it to reject a mismatched anchor schedule
// before an append can create an STH for the wrong stream.
func (s *Service) StreamIdentity() (string, string) {
	if s == nil {
		return "", ""
	}
	return s.nodeID, s.logID
}

func (s *Service) AppendBatchRoot(ctx context.Context, root model.BatchRoot) (model.SignedTreeHead, error) {
	sths, err := s.AppendBatchRoots(ctx, []model.BatchRoot{root})
	if err != nil {
		return model.SignedTreeHead{}, err
	}
	return sths[0], nil
}

func (s *Service) AppendBatchRoots(ctx context.Context, roots []model.BatchRoot) ([]model.SignedTreeHead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.signer == nil {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "global log signer is not configured")
	}
	if len(roots) == 0 {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "global log append requires at least one batch root")
	}
	for i := range roots {
		if roots[i].BatchID == "" {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "global log batch_id is required")
		}
		if len(roots[i].BatchRoot) != s.profile.Size() {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "global log batch_root has the wrong digest size")
		}
	}
	for attempt := 0; ; attempt++ {
		sths, retryable, err := s.appendBatchRootsOnce(ctx, roots)
		if err == nil {
			return sths, nil
		}
		if !retryable || attempt+1 >= appendConflictAttempts {
			return nil, err
		}
		backoff := appendConflictBackoff << min(attempt, 4)
		if backoff > appendConflictMaxBackoff {
			backoff = appendConflictMaxBackoff
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *Service) appendBatchRootsOnce(ctx context.Context, roots []model.BatchRoot) ([]model.SignedTreeHead, bool, error) {
	state, err := s.loadState(ctx)
	if err != nil {
		return nil, false, err
	}
	sths := make([]model.SignedTreeHead, len(roots))
	appends := make([]model.GlobalLogAppend, 0, len(roots))
	planned := make(map[string]model.SignedTreeHead, len(roots))
	plannedRoots := make(map[string]model.BatchRoot, len(roots))
	for i := range roots {
		root := roots[i]
		root.NodeID = strings.TrimSpace(root.NodeID)
		if root.NodeID == "" {
			root.NodeID = s.nodeID
		}
		root.LogID = strings.TrimSpace(root.LogID)
		if root.LogID == "" {
			root.LogID = s.logID
		}
		if root.NodeID != s.nodeID || root.LogID != s.logID {
			return nil, false, trusterr.New(trusterr.CodeInvalidArgument, "global log batch root identity does not match signer stream")
		}
		if sth, ok := planned[root.BatchID]; ok {
			if err := validateGlobalLogReplayRoot(plannedRoots[root.BatchID], root); err != nil {
				return nil, false, err
			}
			sths[i] = sth
			continue
		}
		if existing, ok, err := s.store.GetGlobalLeafByBatchID(ctx, root.BatchID); err != nil {
			return nil, false, err
		} else if ok {
			if err := validateGlobalLogReplayLeaf(existing, root); err != nil {
				return nil, false, err
			}
			sth, found, err := s.store.GetSignedTreeHead(ctx, existing.LeafIndex+1)
			if err != nil {
				return nil, false, err
			}
			if !found {
				return nil, false, trusterr.New(trusterr.CodeDataLoss, "global log leaf exists without matching signed tree head")
			}
			if sth.NodeID != s.nodeID || sth.LogID != s.logID {
				return nil, false, trusterr.New(trusterr.CodeDataLoss, "global log replay signed tree head identity does not match signer stream")
			}
			sths[i] = sth
			planned[root.BatchID] = sth
			plannedRoots[root.BatchID] = root
			continue
		}
		leaf := model.GlobalLogLeaf{
			SchemaVersion:      model.SchemaGlobalLogLeaf,
			NodeID:             root.NodeID,
			LogID:              root.LogID,
			BatchID:            root.BatchID,
			BatchRoot:          append([]byte(nil), root.BatchRoot...),
			BatchTreeSize:      root.TreeSize,
			BatchClosedAtUnixN: root.ClosedAtUnixN,
			LeafIndex:          state.TreeSize,
			AppendedAtUnixN:    s.clock().UTC().UnixNano(),
		}
		hash, err := HashLeafWithProvider(s.provider, leaf)
		if err != nil {
			return nil, false, trusterr.Wrap(trusterr.CodeInternal, "hash global log leaf", err)
		}
		leaf.LeafHash = hash
		nextState, nodes, err := s.appendState(state, leaf)
		if err != nil {
			return nil, false, err
		}
		sth, err := s.signSTHFromState(ctx, nextState)
		if err != nil {
			return nil, false, err
		}
		appends = append(appends, model.GlobalLogAppend{Leaf: leaf, Nodes: nodes, State: nextState, STH: sth})
		state = nextState
		sths[i] = sth
		planned[root.BatchID] = sth
		plannedRoots[root.BatchID] = root
	}
	if len(appends) > 0 {
		if store, ok := s.store.(BatchAppendStore); ok {
			if err := store.CommitGlobalLogAppends(ctx, appends); err != nil {
				return nil, trusterr.CodeOf(err) == trusterr.CodeFailedPrecondition, err
			}
		} else {
			for i := range appends {
				if err := s.store.CommitGlobalLogAppend(ctx, appends[i]); err != nil {
					return nil, trusterr.CodeOf(err) == trusterr.CodeFailedPrecondition, err
				}
			}
		}
	}
	return sths, false, nil
}

func validateGlobalLogReplayRoot(existing, incoming model.BatchRoot) error {
	if existing.BatchID != incoming.BatchID ||
		existing.NodeID != incoming.NodeID ||
		existing.LogID != incoming.LogID ||
		existing.TreeSize != incoming.TreeSize ||
		existing.ClosedAtUnixN != incoming.ClosedAtUnixN ||
		!bytes.Equal(existing.BatchRoot, incoming.BatchRoot) {
		return trusterr.New(trusterr.CodeDataLoss, "global log batch_id replay does not match the original batch root")
	}
	return nil
}

func validateGlobalLogReplayLeaf(existing model.GlobalLogLeaf, incoming model.BatchRoot) error {
	if existing.BatchID != incoming.BatchID ||
		existing.NodeID != incoming.NodeID ||
		existing.LogID != incoming.LogID ||
		existing.BatchTreeSize != incoming.TreeSize ||
		existing.BatchClosedAtUnixN != incoming.ClosedAtUnixN ||
		!bytes.Equal(existing.BatchRoot, incoming.BatchRoot) {
		return trusterr.New(trusterr.CodeDataLoss, "global log batch_id conflicts with the durable leaf")
	}
	return nil
}

func (s *Service) LatestSTH(ctx context.Context) (model.SignedTreeHead, bool, error) {
	return s.store.LatestSignedTreeHead(ctx)
}

func (s *Service) STH(ctx context.Context, treeSize uint64) (model.SignedTreeHead, bool, error) {
	return s.store.GetSignedTreeHead(ctx, treeSize)
}

func (s *Service) ListSTHs(ctx context.Context, opts model.TreeHeadListOptions) ([]model.SignedTreeHead, error) {
	return s.store.ListSignedTreeHeadsPage(ctx, opts)
}

func (s *Service) ListLeaves(ctx context.Context, opts model.GlobalLeafListOptions) ([]model.GlobalLogLeaf, error) {
	return s.store.ListGlobalLeavesPage(ctx, opts)
}

func (s *Service) State(ctx context.Context) (model.GlobalLogState, bool, error) {
	return s.store.GetGlobalLogState(ctx)
}

func (s *Service) Node(ctx context.Context, level, startIndex uint64) (model.GlobalLogNode, bool, error) {
	return s.store.GetGlobalLogNode(ctx, level, startIndex)
}

func (s *Service) ListNodesAfter(ctx context.Context, afterLevel, afterStartIndex uint64, limit int) ([]model.GlobalLogNode, error) {
	return s.store.ListGlobalLogNodesAfter(ctx, afterLevel, afterStartIndex, limit)
}

func (s *Service) InclusionProof(ctx context.Context, batchID string, treeSize uint64) (model.GlobalLogProof, error) {
	leaf, ok, err := s.store.GetGlobalLeafByBatchID(ctx, batchID)
	if err != nil {
		return model.GlobalLogProof{}, err
	}
	if !ok {
		return model.GlobalLogProof{}, trusterr.New(trusterr.CodeNotFound, "global log leaf not found")
	}
	if treeSize == 0 {
		latest, found, err := s.store.LatestSignedTreeHead(ctx)
		if err != nil {
			return model.GlobalLogProof{}, err
		}
		if !found {
			return model.GlobalLogProof{}, trusterr.New(trusterr.CodeNotFound, "signed tree head not found")
		}
		treeSize = latest.TreeSize
	}
	if leaf.LeafIndex >= treeSize {
		return model.GlobalLogProof{}, trusterr.New(trusterr.CodeFailedPrecondition, "batch is not included in requested STH")
	}
	sth, found, err := s.store.GetSignedTreeHead(ctx, treeSize)
	if err != nil {
		return model.GlobalLogProof{}, err
	}
	if !found {
		return model.GlobalLogProof{}, trusterr.New(trusterr.CodeNotFound, "signed tree head not found")
	}
	path, err := s.auditPath(ctx, leaf.LeafIndex, 0, treeSize)
	if err != nil {
		return model.GlobalLogProof{}, trusterr.Wrap(trusterr.CodeInternal, "build global inclusion proof", err)
	}
	return model.GlobalLogProof{
		SchemaVersion: model.SchemaGlobalLogProof,
		NodeID:        leaf.NodeID,
		LogID:         leaf.LogID,
		BatchID:       batchID,
		LeafIndex:     leaf.LeafIndex,
		LeafHash:      append([]byte(nil), leaf.LeafHash...),
		TreeSize:      treeSize,
		InclusionPath: path,
		STH:           sth,
	}, nil
}

// Evidence returns the strongest currently available Global Log evidence for
// a batch. A later STH can cover every earlier leaf, so when the newest
// published anchor contains the requested batch we build the inclusion proof
// directly against that exact STH. This keeps L5's exact STH/anchor binding
// unchanged while avoiding any need for a consistency-proof envelope.
func (s *Service) Evidence(ctx context.Context, batchID string) (model.GlobalLogEvidence, error) {
	leaf, ok, err := s.store.GetGlobalLeafByBatchID(ctx, batchID)
	if err != nil {
		return model.GlobalLogEvidence{}, err
	}
	if !ok {
		return model.GlobalLogEvidence{}, trusterr.New(trusterr.CodeNotFound, "global log leaf not found")
	}
	if result, found, available, err := s.latestAnchorResult(ctx); available {
		if err != nil {
			return model.GlobalLogEvidence{}, err
		}
		if found {
			if result.TreeSize == 0 {
				return model.GlobalLogEvidence{}, trusterr.New(trusterr.CodeDataLoss, "latest STH anchor result has an empty tree size")
			}
			if leaf.LeafIndex < result.TreeSize {
				proof, err := s.InclusionProof(ctx, batchID, result.TreeSize)
				if err != nil {
					return model.GlobalLogEvidence{}, err
				}
				if !bytes.Equal(result.RootHash, proof.STH.RootHash) {
					return model.GlobalLogEvidence{}, trusterr.New(trusterr.CodeDataLoss, "latest STH anchor root does not match signed tree head")
				}
				if result.NodeID != "" && proof.STH.NodeID != "" && result.NodeID != proof.STH.NodeID {
					return model.GlobalLogEvidence{}, trusterr.New(trusterr.CodeDataLoss, "latest STH anchor node does not match signed tree head")
				}
				if result.LogID != "" && proof.STH.LogID != "" && result.LogID != proof.STH.LogID {
					return model.GlobalLogEvidence{}, trusterr.New(trusterr.CodeDataLoss, "latest STH anchor log does not match signed tree head")
				}
				return model.GlobalLogEvidence{GlobalProof: proof, AnchorResult: &result}, nil
			}
		}
	}
	proof, err := s.InclusionProof(ctx, batchID, 0)
	if err != nil {
		return model.GlobalLogEvidence{}, err
	}
	return model.GlobalLogEvidence{GlobalProof: proof}, nil
}

func (s *Service) latestAnchorResult(ctx context.Context) (model.STHAnchorResult, bool, bool, error) {
	if s.anchorKey != nil {
		reader, ok := s.store.(latestSTHAnchorResultKeyedReader)
		if !ok {
			return model.STHAnchorResult{}, false, true, trusterr.New(trusterr.CodeFailedPrecondition, "global evidence store does not support keyed anchor lookup")
		}
		result, found, err := reader.LatestSTHAnchorResultForKey(ctx, *s.anchorKey)
		return result, found, true, err
	}
	reader, ok := s.store.(latestSTHAnchorResultReader)
	if !ok {
		return model.STHAnchorResult{}, false, false, nil
	}
	result, found, err := reader.LatestSTHAnchorResult(ctx)
	return result, found, true, err
}

func (s *Service) ConsistencyProof(ctx context.Context, from, to uint64) (model.GlobalConsistencyProof, error) {
	if from == 0 || to == 0 || from > to {
		return model.GlobalConsistencyProof{}, trusterr.New(trusterr.CodeInvalidArgument, "consistency proof requires 0 < from <= to")
	}
	path, err := s.consistencyProofRange(ctx, 0, to, from, true)
	if err != nil {
		return model.GlobalConsistencyProof{}, err
	}
	return model.GlobalConsistencyProof{
		FromTreeSize: from,
		ToTreeSize:   to,
		AuditPath:    path,
	}, nil
}

func (s *Service) CompactHistory(ctx context.Context, tileSize uint64) (int, error) {
	if tileSize == 0 {
		tileSize = 256
	}
	limit := int(tileSize)
	written := 0
	for start := uint64(0); ; {
		leaves, err := s.store.ListGlobalLeavesRange(ctx, start, limit)
		if err != nil {
			return written, err
		}
		if len(leaves) == 0 {
			break
		}
		tileStart := leaves[0].LeafIndex
		hashes := make([][]byte, 0, len(leaves))
		for _, leaf := range leaves {
			hashes = append(hashes, append([]byte(nil), leaf.LeafHash...))
			start = leaf.LeafIndex + 1
		}
		tile := model.GlobalLogTile{
			SchemaVersion:  model.SchemaGlobalLogTile,
			Level:          0,
			StartIndex:     tileStart,
			Width:          uint64(len(hashes)),
			Hashes:         hashes,
			Compressed:     true,
			CreatedAtUnixN: s.clock().UTC().UnixNano(),
		}
		if err := s.store.PutGlobalLogTile(ctx, tile); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

func HashLeaf(leaf model.GlobalLogLeaf) ([]byte, error) {
	return HashLeafWithProvider(trustcrypto.DefaultProvider(), leaf)
}

func HashLeafWithProvider(provider trustcrypto.Provider, leaf model.GlobalLogLeaf) ([]byte, error) {
	if provider == nil {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "global log crypto provider is required")
	}
	leaf.LeafHash = nil
	leaf.AppendedAtUnixN = 0
	payload, err := cborx.Marshal(leaf)
	if err != nil {
		return nil, err
	}
	suite, err := cryptosuite.RequireAvailable(provider.Suite())
	if err != nil {
		return nil, err
	}
	profile, err := merkle.ProfileForAlgorithm(suite.ID, suite.Merkle.Algorithm)
	if err != nil {
		return nil, err
	}
	factory, err := provider.HashFactory(suite.Merkle.Hash.Algorithm)
	if err != nil {
		return nil, err
	}
	if factory.Algorithm() != profile.HashAlgorithm() || factory.Size() != profile.Size() {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "global log provider hash does not match the suite merkle profile")
	}
	h := factory.New()
	h.Write([]byte{suite.Merkle.LeafPrefix})
	h.Write([]byte(model.SchemaGlobalLogLeaf))
	h.Write([]byte{0})
	h.Write(payload)
	return h.Sum(nil), nil
}

func VerifySTH(sth model.SignedTreeHead, publicKey []byte) error {
	descriptor, err := trustcrypto.NewEd25519PublicKey("", publicKey)
	if err != nil {
		return err
	}
	return VerifySTHWithProvider(context.Background(), sth, descriptor, trustcrypto.DefaultProvider())
}

func VerifySTHWithProvider(ctx context.Context, sth model.SignedTreeHead, publicKey trustcrypto.PublicKeyDescriptor, provider trustcrypto.Provider) error {
	if provider == nil {
		return trusterr.New(trusterr.CodeInvalidArgument, "global log crypto provider is required")
	}
	suite, err := cryptosuite.RequireAvailable(provider.Suite())
	if err != nil {
		return err
	}
	if sth.TreeAlg != suite.Merkle.Algorithm {
		return fmt.Errorf("verify signed tree head: tree algorithm %q does not match suite %s", sth.TreeAlg, suite.ID)
	}
	sig := sth.Signature
	sth.Signature = model.Signature{}
	payload, err := cborx.Marshal(sth)
	if err != nil {
		return err
	}
	input, err := trustcrypto.SignatureInputForSuite(provider.Suite(), trustcrypto.SignaturePurposeSignedTreeHead, payload)
	if err != nil {
		return err
	}
	if err := trustcrypto.Verify(ctx, provider, publicKey, input, sig); err != nil {
		return fmt.Errorf("verify signed tree head: %w", err)
	}
	return nil
}

func VerifyInclusion(proof model.GlobalLogProof) bool {
	ok, err := VerifyInclusionForSuite(cryptosuite.INTLV1, proof)
	return err == nil && ok
}

func VerifyInclusionWithProvider(provider trustcrypto.Provider, proof model.GlobalLogProof) bool {
	if provider == nil {
		return false
	}
	ok, err := VerifyInclusionForSuite(provider.Suite(), proof)
	return err == nil && ok
}

func VerifyInclusionForSuite(suiteID cryptosuite.ID, proof model.GlobalLogProof) (bool, error) {
	if proof.SchemaVersion != model.SchemaGlobalLogProof {
		return false, nil
	}
	if proof.STH.SchemaVersion != model.SchemaSignedTreeHead || proof.TreeSize != proof.STH.TreeSize {
		return false, nil
	}
	if proof.TreeSize == 0 || proof.LeafIndex >= proof.TreeSize {
		return false, nil
	}
	return merkle.VerifyForSuite(
		suiteID,
		proof.STH.TreeAlg,
		proof.LeafHash,
		proof.LeafIndex,
		proof.TreeSize,
		proof.InclusionPath,
		proof.STH.RootHash,
	)
}

func (s *Service) signSTH(ctx context.Context, leaves []model.GlobalLogLeaf) (model.SignedTreeHead, error) {
	hashes := make([][]byte, len(leaves))
	for i := range leaves {
		hashes[i] = append([]byte(nil), leaves[i].LeafHash...)
	}
	root, err := merkle.RootFromLeavesForSuite(s.profile.Suite(), s.profile.Algorithm(), hashes)
	if err != nil {
		return model.SignedTreeHead{}, err
	}
	sth := model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        s.profile.Algorithm(),
		TreeSize:       uint64(len(leaves)),
		RootHash:       root,
		TimestampUnixN: s.clock().UTC().UnixNano(),
		NodeID:         s.nodeID,
		LogID:          s.logID,
	}
	payloadSTH := sth
	payloadSTH.Signature = model.Signature{}
	payload, err := cborx.Marshal(payloadSTH)
	if err != nil {
		return model.SignedTreeHead{}, err
	}
	input, err := trustcrypto.SignatureInputForSuite(s.provider.Suite(), trustcrypto.SignaturePurposeSignedTreeHead, payload)
	if err != nil {
		return model.SignedTreeHead{}, err
	}
	sig, err := trustcrypto.Sign(ctx, s.provider.Suite(), s.signer, input)
	if err != nil {
		return model.SignedTreeHead{}, err
	}
	sth.Signature = sig
	return sth, nil
}

func (s *Service) signSTHFromState(ctx context.Context, state model.GlobalLogState) (model.SignedTreeHead, error) {
	if state.TreeSize == 0 {
		return model.SignedTreeHead{}, trusterr.New(trusterr.CodeInvalidArgument, "cannot sign empty global log")
	}
	if len(state.RootHash) != s.profile.Size() {
		return model.SignedTreeHead{}, trusterr.New(trusterr.CodeInternal, "global log state root is invalid")
	}
	sth := model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        s.profile.Algorithm(),
		TreeSize:       state.TreeSize,
		RootHash:       append([]byte(nil), state.RootHash...),
		TimestampUnixN: s.clock().UTC().UnixNano(),
		NodeID:         s.nodeID,
		LogID:          s.logID,
	}
	payloadSTH := sth
	payloadSTH.Signature = model.Signature{}
	payload, err := cborx.Marshal(payloadSTH)
	if err != nil {
		return model.SignedTreeHead{}, err
	}
	input, err := trustcrypto.SignatureInputForSuite(s.provider.Suite(), trustcrypto.SignaturePurposeSignedTreeHead, payload)
	if err != nil {
		return model.SignedTreeHead{}, err
	}
	sig, err := trustcrypto.Sign(ctx, s.provider.Suite(), s.signer, input)
	if err != nil {
		return model.SignedTreeHead{}, err
	}
	sth.Signature = sig
	return sth, nil
}

func (s *Service) loadState(ctx context.Context) (model.GlobalLogState, error) {
	state, ok, err := s.store.GetGlobalLogState(ctx)
	if err != nil {
		return model.GlobalLogState{}, err
	}
	if ok {
		return state, nil
	}
	// One-time rebuild path for pre-state stores and tests. New production
	// appends stay on the incremental path after this state is persisted.
	state = model.GlobalLogState{
		SchemaVersion: model.SchemaGlobalLogState,
		Frontier:      nil,
	}
	for nextLeafIndex := uint64(0); ; {
		leaves, err := s.store.ListGlobalLeavesRange(ctx, nextLeafIndex, 1024)
		if err != nil {
			return model.GlobalLogState{}, err
		}
		if len(leaves) == 0 {
			break
		}
		for _, leaf := range leaves {
			next, nodes, err := s.appendState(state, leaf)
			if err != nil {
				return model.GlobalLogState{}, err
			}
			for _, node := range nodes {
				if err := s.store.PutGlobalLogNode(ctx, node); err != nil {
					return model.GlobalLogState{}, err
				}
			}
			state = next
			nextLeafIndex = leaf.LeafIndex + 1
		}
	}
	if state.TreeSize > 0 {
		if err := s.store.PutGlobalLogState(ctx, state); err != nil {
			return model.GlobalLogState{}, err
		}
	}
	return state, nil
}

func (s *Service) appendState(state model.GlobalLogState, leaf model.GlobalLogLeaf) (model.GlobalLogState, []model.GlobalLogNode, error) {
	if len(leaf.LeafHash) != s.profile.Size() {
		return model.GlobalLogState{}, nil, trusterr.New(trusterr.CodeInvalidArgument, "global leaf hash has the wrong digest size")
	}
	if leaf.LeafIndex != state.TreeSize {
		return model.GlobalLogState{}, nil, trusterr.New(trusterr.CodeFailedPrecondition, "global leaf index does not match tree frontier")
	}
	now := s.clock().UTC().UnixNano()
	frontier := cloneFrontier(state.Frontier)
	current := append([]byte(nil), leaf.LeafHash...)
	start := leaf.LeafIndex
	level := uint64(0)
	nodes := []model.GlobalLogNode{{
		SchemaVersion:  model.SchemaGlobalLogNode,
		Level:          0,
		StartIndex:     start,
		Width:          1,
		Hash:           append([]byte(nil), current...),
		CreatedAtUnixN: now,
	}}
	for int(level) < len(frontier) && len(frontier[level]) > 0 {
		width := uint64(1) << level
		if start < width {
			return model.GlobalLogState{}, nil, trusterr.New(trusterr.CodeInternal, "global frontier start underflow")
		}
		parentStart := start - width
		parent, err := merkle.HashNodeForSuite(s.profile.Suite(), s.profile.Algorithm(), frontier[level], current)
		if err != nil {
			return model.GlobalLogState{}, nil, err
		}
		frontier[level] = nil
		level++
		current = parent
		start = parentStart
		nodes = append(nodes, model.GlobalLogNode{
			SchemaVersion:  model.SchemaGlobalLogNode,
			Level:          level,
			StartIndex:     start,
			Width:          uint64(1) << level,
			Hash:           append([]byte(nil), current...),
			CreatedAtUnixN: now,
		})
	}
	for int(level) >= len(frontier) {
		frontier = append(frontier, nil)
	}
	frontier[level] = append([]byte(nil), current...)
	root, err := rootFromFrontier(s.profile, frontier)
	if err != nil {
		return model.GlobalLogState{}, nil, err
	}
	return model.GlobalLogState{
		SchemaVersion:  model.SchemaGlobalLogState,
		TreeSize:       state.TreeSize + 1,
		RootHash:       root,
		Frontier:       trimFrontier(frontier),
		UpdatedAtUnixN: now,
	}, nodes, nil
}

func (s *Service) auditPath(ctx context.Context, leafIndex, start, width uint64) ([][]byte, error) {
	if width == 0 || leafIndex < start || leafIndex >= start+width {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "global audit path range is invalid")
	}
	if width == 1 {
		return nil, nil
	}
	k := largestPowerOfTwoLessThan64(width)
	if leafIndex < start+k {
		path, err := s.auditPath(ctx, leafIndex, start, k)
		if err != nil {
			return nil, err
		}
		right, err := s.subtreeRoot(ctx, start+k, width-k)
		if err != nil {
			return nil, err
		}
		return append(path, right), nil
	}
	path, err := s.auditPath(ctx, leafIndex, start+k, width-k)
	if err != nil {
		return nil, err
	}
	left, err := s.subtreeRoot(ctx, start, k)
	if err != nil {
		return nil, err
	}
	return append(path, left), nil
}

func (s *Service) consistencyProofRange(ctx context.Context, start, width, from uint64, complete bool) ([][]byte, error) {
	if from == 0 || from > width {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "invalid consistency proof range")
	}
	if from == width {
		if complete {
			return nil, nil
		}
		root, err := s.subtreeRoot(ctx, start, width)
		if err != nil {
			return nil, err
		}
		return [][]byte{root}, nil
	}
	k := largestPowerOfTwoLessThan64(width)
	if from <= k {
		left, err := s.consistencyProofRange(ctx, start, k, from, complete)
		if err != nil {
			return nil, err
		}
		right, err := s.subtreeRoot(ctx, start+k, width-k)
		if err != nil {
			return nil, err
		}
		return append(left, right), nil
	}
	right, err := s.consistencyProofRange(ctx, start+k, width-k, from-k, false)
	if err != nil {
		return nil, err
	}
	left, err := s.subtreeRoot(ctx, start, k)
	if err != nil {
		return nil, err
	}
	return append(right, left), nil
}

func (s *Service) subtreeRoot(ctx context.Context, start, width uint64) ([]byte, error) {
	if width == 0 {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "global subtree width is zero")
	}
	if width == 1 {
		leaf, ok, err := s.store.GetGlobalLeaf(ctx, start)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, trusterr.New(trusterr.CodeNotFound, "global log leaf not found")
		}
		return append([]byte(nil), leaf.LeafHash...), nil
	}
	if isPowerOfTwo(width) {
		level := uint64(bits.TrailingZeros64(width))
		if node, ok, err := s.store.GetGlobalLogNode(ctx, level, start); err != nil {
			return nil, err
		} else if ok {
			return append([]byte(nil), node.Hash...), nil
		}
	}
	k := largestPowerOfTwoLessThan64(width)
	if isPowerOfTwo(width) {
		k = width / 2
	}
	left, err := s.subtreeRoot(ctx, start, k)
	if err != nil {
		return nil, err
	}
	right, err := s.subtreeRoot(ctx, start+k, width-k)
	if err != nil {
		return nil, err
	}
	return merkle.HashNodeForSuite(s.profile.Suite(), s.profile.Algorithm(), left, right)
}

func rootFromFrontier(profile merkle.Profile, frontier [][]byte) ([]byte, error) {
	if profile.Size() == 0 {
		return nil, trusterr.New(trusterr.CodeInternal, "global merkle profile is invalid")
	}
	var root []byte
	for level := 0; level < len(frontier); level++ {
		h := frontier[level]
		if len(h) == 0 {
			continue
		}
		if len(h) != profile.Size() {
			return nil, trusterr.New(trusterr.CodeInternal, "global frontier hash is invalid")
		}
		if root == nil {
			root = append([]byte(nil), h...)
			continue
		}
		combined, err := merkle.HashNodeForSuite(profile.Suite(), profile.Algorithm(), h, root)
		if err != nil {
			return nil, err
		}
		root = combined
	}
	if root == nil {
		return nil, nil
	}
	return root, nil
}

func cloneFrontier(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		if len(in[i]) > 0 {
			out[i] = append([]byte(nil), in[i]...)
		}
	}
	return out
}

func trimFrontier(in [][]byte) [][]byte {
	last := len(in) - 1
	for last >= 0 && len(in[last]) == 0 {
		last--
	}
	if last < 0 {
		return nil
	}
	return in[:last+1]
}

func isPowerOfTwo(n uint64) bool {
	return n > 0 && n&(n-1) == 0
}

func largestPowerOfTwoLessThan64(n uint64) uint64 {
	if n < 2 {
		return 0
	}
	return uint64(1) << (bits.Len64(n-1) - 1)
}

func consistencyProof(leaves [][]byte, from uint64) ([][]byte, error) {
	if from == 0 || from > uint64(len(leaves)) {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "invalid consistency proof range")
	}
	if from == uint64(len(leaves)) {
		return [][]byte{}, nil
	}
	path, err := subproof(leaves, int(from), true)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(path))
	for i := range path {
		out[i] = append([]byte(nil), path[i]...)
	}
	return out, nil
}

func subproof(leaves [][]byte, from int, complete bool) ([][]byte, error) {
	n := len(leaves)
	if from == n {
		if complete {
			return [][]byte{}, nil
		}
		root, err := merkle.RootFromLeaves(leaves)
		if err != nil {
			return nil, err
		}
		return [][]byte{root}, nil
	}
	k := largestPowerOfTwoLessThan(n)
	if from <= k {
		left, err := subproof(leaves[:k], from, complete)
		if err != nil {
			return nil, err
		}
		right, err := merkle.RootFromLeaves(leaves[k:])
		if err != nil {
			return nil, err
		}
		return append(left, right), nil
	}
	right, err := subproof(leaves[k:], from-k, false)
	if err != nil {
		return nil, err
	}
	left, err := merkle.RootFromLeaves(leaves[:k])
	if err != nil {
		return nil, err
	}
	return append(right, left), nil
}

func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}
