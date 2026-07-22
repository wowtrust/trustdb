package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"github.com/wowtrust/trustdb/internal/anchor"
	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/globallog"
	"github.com/wowtrust/trustdb/internal/merkle"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/prooflevel"
	"github.com/wowtrust/trustdb/internal/receipt"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

type TrustedKeys struct {
	ClientPublicKey ed25519.PublicKey
	ServerPublicKey ed25519.PublicKey
}

// Result is the outcome of ProofBundle. ProofLevel follows the centralized
// prooflevel ladder so CLI, desktop and future SDK code do not drift.
type Result struct {
	Valid      bool   `json:"valid"`
	RecordID   string `json:"record_id"`
	ProofLevel string `json:"proof_level"`
	// AnchorSink is populated only when an anchor was verified; it
	// identifies the sink ("file", "noop", ...) that produced the
	// AnchorResult so downstream tooling knows how to interpret
	// the Proof bytes.
	AnchorSink string `json:"anchor_sink,omitempty"`
	AnchorID   string `json:"anchor_id,omitempty"`
}

// Option tunes ProofBundle without growing its positional signature
// every time a new trust layer is added. Every option is optional;
// the zero-option call verifies up to L3.
type Option func(*options)

type options struct {
	global *model.GlobalLogProof
	anchor *model.STHAnchorResult
}

func WithGlobalProof(p model.GlobalLogProof) Option {
	return func(o *options) { o.global = &p }
}

// WithAnchor asks ProofBundle to additionally verify an L5 external STH
// anchor. L5 requires a matching WithGlobalProof because batch roots are no
// longer directly anchored.
func WithAnchor(a model.STHAnchorResult) Option {
	return func(o *options) { o.anchor = &a }
}

func ProofBundle(raw io.Reader, bundle model.ProofBundle, keys TrustedKeys, opts ...Option) (Result, error) {
	var o options
	for _, apply := range opts {
		apply(&o)
	}
	if bundle.SchemaVersion != model.SchemaProofBundle {
		return Result{}, fmt.Errorf("verify: unexpected proof bundle schema: %s", bundle.SchemaVersion)
	}
	sum, n, err := trustcrypto.HashReader(bundle.SignedClaim.Claim.Content.HashAlg, raw)
	if err != nil {
		return Result{}, err
	}
	if n != bundle.SignedClaim.Claim.Content.ContentLength {
		return Result{}, fmt.Errorf("verify: content length mismatch: got %d want %d", n, bundle.SignedClaim.Claim.Content.ContentLength)
	}
	if !bytes.Equal(sum, bundle.SignedClaim.Claim.Content.ContentHash) {
		return Result{}, fmt.Errorf("verify: content hash mismatch")
	}
	verified, err := claim.Verify(bundle.SignedClaim, keys.ClientPublicKey)
	if err != nil {
		return Result{}, err
	}
	if verified.RecordID != bundle.RecordID || verified.RecordID != bundle.ServerRecord.RecordID {
		return Result{}, fmt.Errorf("verify: record id mismatch")
	}
	if err := validateBundleBindings(bundle, verified); err != nil {
		return Result{}, err
	}
	if err := receipt.VerifyAccepted(bundle.AcceptedReceipt, keys.ServerPublicKey); err != nil {
		return Result{}, err
	}
	if err := receipt.VerifyCommitted(bundle.CommittedReceipt, keys.ServerPublicKey); err != nil {
		return Result{}, err
	}
	leaf, err := merkle.HashLeaf(bundle.ServerRecord)
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(leaf, bundle.CommittedReceipt.LeafHash) {
		return Result{}, fmt.Errorf("verify: leaf hash mismatch")
	}
	if !merkle.Verify(
		leaf,
		bundle.BatchProof.LeafIndex,
		bundle.BatchProof.TreeSize,
		bundle.BatchProof.AuditPath,
		bundle.CommittedReceipt.BatchRoot,
	) {
		return Result{}, fmt.Errorf("verify: merkle proof failed")
	}
	evidence := prooflevel.EvidenceFor(prooflevel.L3)
	result := Result{
		Valid:      true,
		RecordID:   verified.RecordID,
		ProofLevel: prooflevel.Evaluate(evidence).String(),
	}
	if o.global != nil {
		if err := VerifyGlobalLogProof(bundle, *o.global, keys.ServerPublicKey); err != nil {
			return Result{}, err
		}
		evidence.GlobalLogProof = true
		result.ProofLevel = prooflevel.Evaluate(evidence).String()
	}
	if o.anchor != nil {
		if o.global == nil {
			return Result{}, fmt.Errorf("verify: L5 anchor requires a global log proof")
		}
		if err := AnchorConsistency(*o.global, *o.anchor); err != nil {
			return Result{}, err
		}
		evidence.STHAnchorResult = true
		result.ProofLevel = prooflevel.Evaluate(evidence).String()
		result.AnchorSink = o.anchor.SinkName
		result.AnchorID = o.anchor.AnchorID
	}
	return result, nil
}

func validateBundleBindings(bundle model.ProofBundle, verified claim.Verified) error {
	if bundle.ServerRecord.TenantID != bundle.SignedClaim.Claim.TenantID {
		return fmt.Errorf("verify: server record tenant_id mismatch")
	}
	if bundle.ServerRecord.ClientID != bundle.SignedClaim.Claim.ClientID {
		return fmt.Errorf("verify: server record client_id mismatch")
	}
	if bundle.ServerRecord.KeyID != bundle.SignedClaim.Claim.KeyID {
		return fmt.Errorf("verify: server record key_id mismatch")
	}
	claimHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, verified.ClaimCBOR)
	if err != nil {
		return err
	}
	if !bytes.Equal(bundle.ServerRecord.ClaimHash, claimHash) {
		return fmt.Errorf("verify: server record claim_hash mismatch")
	}
	sigHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, bundle.SignedClaim.Signature.Signature)
	if err != nil {
		return err
	}
	if !bytes.Equal(bundle.ServerRecord.ClientSignatureHash, sigHash) {
		return fmt.Errorf("verify: server record client_signature_hash mismatch")
	}
	if bundle.AcceptedReceipt.RecordID != verified.RecordID {
		return fmt.Errorf("verify: accepted receipt record_id mismatch")
	}
	if bundle.AcceptedReceipt.ReceivedAtUnixN != bundle.ServerRecord.ReceivedAtUnixN {
		return fmt.Errorf("verify: accepted receipt received_at mismatch")
	}
	if bundle.AcceptedReceipt.WAL != bundle.ServerRecord.WAL {
		return fmt.Errorf("verify: accepted receipt WAL mismatch")
	}
	if bundle.NodeID != "" && bundle.AcceptedReceipt.ServerID != "" && bundle.NodeID != bundle.AcceptedReceipt.ServerID {
		return fmt.Errorf("verify: bundle node_id mismatch")
	}
	if bundle.CommittedReceipt.RecordID != verified.RecordID {
		return fmt.Errorf("verify: committed receipt record_id mismatch")
	}
	if bundle.CommittedReceipt.LeafIndex != bundle.BatchProof.LeafIndex {
		return fmt.Errorf("verify: committed receipt leaf_index mismatch")
	}
	if bundle.CommittedReceipt.NodeID != "" && bundle.NodeID != "" && bundle.CommittedReceipt.NodeID != bundle.NodeID {
		return fmt.Errorf("verify: committed receipt node_id mismatch")
	}
	if bundle.CommittedReceipt.LogID != "" && bundle.LogID != "" && bundle.CommittedReceipt.LogID != bundle.LogID {
		return fmt.Errorf("verify: committed receipt log_id mismatch")
	}
	if bundle.BatchProof.TreeAlg != model.DefaultMerkleTreeAlg {
		return fmt.Errorf("verify: unsupported batch proof tree_alg: %s", bundle.BatchProof.TreeAlg)
	}
	if bundle.BatchProof.TreeSize == 0 || bundle.BatchProof.LeafIndex >= bundle.BatchProof.TreeSize {
		return fmt.Errorf("verify: invalid batch proof leaf index")
	}
	return nil
}

func VerifyGlobalLogProof(bundle model.ProofBundle, proof model.GlobalLogProof, publicKey ed25519.PublicKey) error {
	if err := GlobalLogConsistency(bundle, proof); err != nil {
		return err
	}
	if err := globallog.VerifySTH(proof.STH, publicKey); err != nil {
		return err
	}
	return nil
}

func GlobalLogConsistency(bundle model.ProofBundle, proof model.GlobalLogProof) error {
	if proof.SchemaVersion != model.SchemaGlobalLogProof {
		return fmt.Errorf("verify: unexpected global log proof schema: %s", proof.SchemaVersion)
	}
	if proof.STH.SchemaVersion != model.SchemaSignedTreeHead {
		return fmt.Errorf("verify: unexpected STH schema: %s", proof.STH.SchemaVersion)
	}
	if proof.STH.TreeAlg != model.DefaultMerkleTreeAlg {
		return fmt.Errorf("verify: unsupported STH tree_alg: %s", proof.STH.TreeAlg)
	}
	if proof.TreeSize != proof.STH.TreeSize {
		return fmt.Errorf("verify: global proof tree_size mismatch: proof=%d sth=%d", proof.TreeSize, proof.STH.TreeSize)
	}
	if len(proof.STH.RootHash) != sha256.Size {
		return fmt.Errorf("verify: STH root_hash must be sha256")
	}
	if proof.BatchID != bundle.CommittedReceipt.BatchID {
		return fmt.Errorf("verify: global proof batch_id mismatch: proof=%s bundle=%s", proof.BatchID, bundle.CommittedReceipt.BatchID)
	}
	if proof.NodeID != "" && bundle.NodeID != "" && proof.NodeID != bundle.NodeID {
		return fmt.Errorf("verify: global proof node_id mismatch: proof=%s bundle=%s", proof.NodeID, bundle.NodeID)
	}
	if proof.LogID != "" && bundle.LogID != "" && proof.LogID != bundle.LogID {
		return fmt.Errorf("verify: global proof log_id mismatch: proof=%s bundle=%s", proof.LogID, bundle.LogID)
	}
	if proof.STH.NodeID != "" && proof.NodeID != "" && proof.STH.NodeID != proof.NodeID {
		return fmt.Errorf("verify: global proof STH node_id mismatch: proof=%s sth=%s", proof.NodeID, proof.STH.NodeID)
	}
	if proof.STH.LogID != "" && proof.LogID != "" && proof.STH.LogID != proof.LogID {
		return fmt.Errorf("verify: global proof STH log_id mismatch: proof=%s sth=%s", proof.LogID, proof.STH.LogID)
	}
	if !globallog.VerifyInclusion(proof) {
		return fmt.Errorf("verify: global log inclusion proof failed")
	}
	leaf := model.GlobalLogLeaf{
		SchemaVersion:      model.SchemaGlobalLogLeaf,
		NodeID:             proof.NodeID,
		LogID:              proof.LogID,
		BatchID:            bundle.CommittedReceipt.BatchID,
		BatchRoot:          bundle.CommittedReceipt.BatchRoot,
		BatchTreeSize:      bundle.BatchProof.TreeSize,
		BatchClosedAtUnixN: bundle.CommittedReceipt.ClosedAtUnixN,
		LeafIndex:          proof.LeafIndex,
	}
	hash, err := globallog.HashLeaf(leaf)
	if err != nil {
		return err
	}
	if !bytes.Equal(hash, proof.LeafHash) {
		return fmt.Errorf("verify: global log leaf hash mismatch")
	}
	return nil
}

// AnchorConsistency checks that an STHAnchorResult is bound to the same STH
// proven by the supplied global log proof. It does not talk to external
// services; built-in sinks are checked locally for deterministic IDs and
// proof envelope consistency.
func AnchorConsistency(proof model.GlobalLogProof, ar model.STHAnchorResult) error {
	if ar.SchemaVersion != model.SchemaSTHAnchorResult {
		return fmt.Errorf("verify: unexpected anchor result schema: %s", ar.SchemaVersion)
	}
	if ar.TreeSize != proof.STH.TreeSize {
		return fmt.Errorf("verify: anchor tree_size mismatch: anchor=%d sth=%d", ar.TreeSize, proof.STH.TreeSize)
	}
	if ar.NodeID != "" && proof.STH.NodeID != "" && ar.NodeID != proof.STH.NodeID {
		return fmt.Errorf("verify: anchor node_id mismatch: anchor=%s sth=%s", ar.NodeID, proof.STH.NodeID)
	}
	if ar.LogID != "" && proof.STH.LogID != "" && ar.LogID != proof.STH.LogID {
		return fmt.Errorf("verify: anchor log_id mismatch: anchor=%s sth=%s", ar.LogID, proof.STH.LogID)
	}
	if !bytes.Equal(ar.RootHash, proof.STH.RootHash) {
		return fmt.Errorf("verify: anchor root_hash does not match STH root")
	}
	if ar.AnchorID == "" {
		return fmt.Errorf("verify: anchor result is missing anchor_id")
	}
	switch ar.SinkName {
	case anchor.FileSinkName:
		if got, want := ar.AnchorID, anchor.DeterministicFileAnchorID(proof.STH); got != want {
			return fmt.Errorf("verify: file sink anchor_id mismatch: got %s want %s", got, want)
		}
	case anchor.NoopSinkName:
		if got, want := ar.AnchorID, anchor.DeterministicNoopAnchorID(proof.STH); got != want {
			return fmt.Errorf("verify: noop sink anchor_id mismatch: got %s want %s", got, want)
		}
	case anchor.OtsSinkName:
		if got, want := ar.AnchorID, anchor.DeterministicOtsAnchorID(proof.STH); got != want {
			return fmt.Errorf("verify: ots sink anchor_id mismatch: got %s want %s", got, want)
		}
		if err := validateOtsAnchorProof(proof.STH, ar); err != nil {
			return err
		}
	default:
		return fmt.Errorf("verify: unsupported anchor sink: %s", ar.SinkName)
	}
	return nil
}

func validateOtsAnchorProof(sth model.SignedTreeHead, ar model.STHAnchorResult) error {
	if len(ar.Proof) == 0 {
		return fmt.Errorf("verify: ots anchor proof is empty")
	}
	var proof anchor.OtsAnchorProof
	if err := json.Unmarshal(ar.Proof, &proof); err != nil {
		return fmt.Errorf("verify: decode ots anchor proof: %w", err)
	}
	if proof.SchemaVersion != anchor.SchemaOtsAnchorProof {
		return fmt.Errorf("verify: unexpected ots anchor proof schema: %s", proof.SchemaVersion)
	}
	if proof.TreeSize != sth.TreeSize {
		return fmt.Errorf("verify: ots anchor proof tree_size mismatch")
	}
	if proof.HashAlg != model.DefaultHashAlg {
		return fmt.Errorf("verify: unsupported ots anchor proof hash_alg: %s", proof.HashAlg)
	}
	if !bytes.Equal(proof.Digest, sth.RootHash) {
		return fmt.Errorf("verify: ots anchor proof digest mismatch")
	}
	accepted := 0
	for _, calendar := range proof.Calendars {
		if !calendar.Accepted {
			continue
		}
		accepted++
		if len(calendar.RawTimestamp) == 0 {
			return fmt.Errorf("verify: ots accepted calendar has empty timestamp")
		}
		if _, err := anchor.ParseOtsTimestamp(proof.Digest, calendar.RawTimestamp); err != nil {
			return fmt.Errorf("verify: parse ots timestamp: %w", err)
		}
	}
	if accepted == 0 {
		return fmt.Errorf("verify: ots anchor proof has no accepted calendars")
	}
	return nil
}
