// Package globallog implements TrustDB's global transparency log. The log
// appends one leaf per committed batch root and emits a SignedTreeHead after
// every append; L5 anchors publish those STHs, not individual batch roots.
package globallog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"math/bits"
	"strings"
	"sync"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/merkle"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trustcrypto"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

const (
	sthDomain                = "trustdb.signed-tree-head.v1"
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

type BatchAppendStore interface {
	CommitGlobalLogAppends(context.Context, []model.GlobalLogAppend) error
}

type Service struct {
	mu         sync.Mutex
	store      Store
	nodeID     string
	logID      string
	keyID      string
	privateKey ed25519.PrivateKey
	clock      func() time.Time
}

type Options struct {
	Store      Store
	NodeID     string
	LogID      string
	KeyID      string
	PrivateKey ed25519.PrivateKey
	Clock      func() time.Time
}

func New(opts Options) (*Service, error) {
	if opts.Store == nil {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "global log store is required")
	}
	if len(opts.PrivateKey) != ed25519.PrivateKeySize {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "global log signer private key is required")
	}
	if opts.KeyID == "" {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "global log signer key_id is required")
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
	return &Service{
		store:      opts.Store,
		nodeID:     nodeID,
		logID:      logID,
		keyID:      opts.KeyID,
		privateKey: opts.PrivateKey,
		clock:      clock,
	}, nil
}

// NewReader returns a read-only global log service. It can build inclusion,
// consistency, and compaction artefacts from an existing store, but cannot
// append because no STH signing key is configured.
func NewReader(store Store) (*Service, error) {
	if store == nil {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "global log store is required")
	}
	return &Service{
		store: store,
		clock: func() time.Time { return time.Now().UTC() },
	}, nil
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

	if len(s.privateKey) != ed25519.PrivateKeySize || s.keyID == "" {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "global log signer is not configured")
	}
	if len(roots) == 0 {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "global log append requires at least one batch root")
	}
	for i := range roots {
		if roots[i].BatchID == "" {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "global log batch_id is required")
		}
		if len(roots[i].BatchRoot) != sha256.Size {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "global log batch_root must be sha256")
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
	for i := range roots {
		root := roots[i]
		if sth, ok := planned[root.BatchID]; ok {
			sths[i] = sth
			continue
		}
		if existing, ok, err := s.store.GetGlobalLeafByBatchID(ctx, root.BatchID); err != nil {
			return nil, false, err
		} else if ok {
			sth, found, err := s.store.GetSignedTreeHead(ctx, existing.LeafIndex+1)
			if err != nil {
				return nil, false, err
			}
			if !found {
				return nil, false, trusterr.New(trusterr.CodeDataLoss, "global log leaf exists without matching signed tree head")
			}
			sths[i] = sth
			planned[root.BatchID] = sth
			continue
		}
		nodeID := strings.TrimSpace(root.NodeID)
		if nodeID == "" {
			nodeID = s.nodeID
		}
		logID := strings.TrimSpace(root.LogID)
		if logID == "" {
			logID = s.logID
		}
		leaf := model.GlobalLogLeaf{
			SchemaVersion:      model.SchemaGlobalLogLeaf,
			NodeID:             nodeID,
			LogID:              logID,
			BatchID:            root.BatchID,
			BatchRoot:          append([]byte(nil), root.BatchRoot...),
			BatchTreeSize:      root.TreeSize,
			BatchClosedAtUnixN: root.ClosedAtUnixN,
			LeafIndex:          state.TreeSize,
			AppendedAtUnixN:    s.clock().UTC().UnixNano(),
		}
		hash, err := HashLeaf(leaf)
		if err != nil {
			return nil, false, trusterr.Wrap(trusterr.CodeInternal, "hash global log leaf", err)
		}
		leaf.LeafHash = hash
		nextState, nodes, err := s.appendState(state, leaf)
		if err != nil {
			return nil, false, err
		}
		sth, err := s.signSTHFromState(nextState)
		if err != nil {
			return nil, false, err
		}
		appends = append(appends, model.GlobalLogAppend{Leaf: leaf, Nodes: nodes, State: nextState, STH: sth})
		state = nextState
		sths[i] = sth
		planned[root.BatchID] = sth
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
	leaf.LeafHash = nil
	leaf.AppendedAtUnixN = 0
	payload, err := cborx.Marshal(leaf)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte{0})
	h.Write([]byte(model.SchemaGlobalLogLeaf))
	h.Write([]byte{0})
	h.Write(payload)
	return h.Sum(nil), nil
}

func VerifySTH(sth model.SignedTreeHead, publicKey ed25519.PublicKey) error {
	sig := sth.Signature
	sth.Signature = model.Signature{}
	payload, err := cborx.Marshal(sth)
	if err != nil {
		return err
	}
	if err := trustcrypto.VerifyEd25519(publicKey, domainInput(sthDomain, payload), sig); err != nil {
		return fmt.Errorf("verify signed tree head: %w", err)
	}
	return nil
}

func VerifyInclusion(proof model.GlobalLogProof) bool {
	if proof.SchemaVersion != model.SchemaGlobalLogProof {
		return false
	}
	if proof.TreeSize == 0 || proof.LeafIndex >= proof.TreeSize {
		return false
	}
	return merkle.Verify(
		proof.LeafHash,
		proof.LeafIndex,
		proof.TreeSize,
		proof.InclusionPath,
		proof.STH.RootHash,
	)
}

func (s *Service) signSTH(leaves []model.GlobalLogLeaf) (model.SignedTreeHead, error) {
	hashes := make([][]byte, len(leaves))
	for i := range leaves {
		hashes[i] = append([]byte(nil), leaves[i].LeafHash...)
	}
	root, err := merkle.RootFromLeaves(hashes)
	if err != nil {
		return model.SignedTreeHead{}, err
	}
	sth := model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
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
	sig, err := trustcrypto.SignEd25519(s.keyID, s.privateKey, domainInput(sthDomain, payload))
	if err != nil {
		return model.SignedTreeHead{}, err
	}
	sth.Signature = sig
	return sth, nil
}

func (s *Service) signSTHFromState(state model.GlobalLogState) (model.SignedTreeHead, error) {
	if state.TreeSize == 0 {
		return model.SignedTreeHead{}, trusterr.New(trusterr.CodeInvalidArgument, "cannot sign empty global log")
	}
	if len(state.RootHash) != sha256.Size {
		return model.SignedTreeHead{}, trusterr.New(trusterr.CodeInternal, "global log state root is invalid")
	}
	sth := model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
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
	sig, err := trustcrypto.SignEd25519(s.keyID, s.privateKey, domainInput(sthDomain, payload))
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
	if len(leaf.LeafHash) != sha256.Size {
		return model.GlobalLogState{}, nil, trusterr.New(trusterr.CodeInvalidArgument, "global leaf hash must be sha256")
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
		parent, err := merkle.HashNode(frontier[level], current)
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
	root, err := rootFromFrontier(frontier)
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
	return merkle.HashNode(left, right)
}

func rootFromFrontier(frontier [][]byte) ([]byte, error) {
	var root []byte
	for level := 0; level < len(frontier); level++ {
		h := frontier[level]
		if len(h) == 0 {
			continue
		}
		if len(h) != sha256.Size {
			return nil, trusterr.New(trusterr.CodeInternal, "global frontier hash is invalid")
		}
		if root == nil {
			root = append([]byte(nil), h...)
			continue
		}
		combined, err := merkle.HashNode(h, root)
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

func domainInput(domain string, payload []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(domain)
	buf.WriteByte(0)
	buf.Write(payload)
	return buf.Bytes()
}
