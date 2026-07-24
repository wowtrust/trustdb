package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/wowtrust/trustdb/internal/anchor"
	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/globallog"
	"github.com/wowtrust/trustdb/internal/merkle"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/modelsuite"
	"github.com/wowtrust/trustdb/internal/prooflevel"
	"github.com/wowtrust/trustdb/internal/receipt"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

type TrustedKeys struct {
	ClientPublicKey           trustcrypto.PublicKeyDescriptor
	ServerPublicKey           trustcrypto.PublicKeyDescriptor
	AcceptedReceiptPublicKey  trustcrypto.PublicKeyDescriptor
	CommittedReceiptPublicKey trustcrypto.PublicKeyDescriptor
	SignedTreeHeadPublicKey   trustcrypto.PublicKeyDescriptor
	CryptoProvider            trustcrypto.Provider
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
	global         *model.GlobalLogProof
	anchor         *model.STHAnchorResult
	anchorVerifier AnchorVerifier
	namespace      *namespaceBinding
}

type namespaceBinding struct {
	nodeID string
	logID  string
}

// AnchorVerifier validates proof bytes for a dynamically configured sink.
// Generic binding to the immutable STH is always checked by TrustDB first.
type AnchorVerifier interface {
	VerifyAnchor(model.SignedTreeHead, model.STHAnchorResult) error
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

func WithAnchorVerifier(verifier AnchorVerifier) Option {
	return func(o *options) { o.anchorVerifier = verifier }
}

// WithExactNamespaceBinding makes the portable evidence envelope's NodeID and
// LogID mandatory at the Global Log and anchor stages. It is intended for
// formats such as .sproof v2 that carry an explicit outer namespace.
func WithExactNamespaceBinding(nodeID, logID string) Option {
	return func(o *options) {
		o.namespace = &namespaceBinding{nodeID: nodeID, logID: logID}
	}
}

func ProofBundle(raw io.Reader, bundle model.ProofBundle, keys TrustedKeys, opts ...Option) (Result, error) {
	provider := keys.CryptoProvider
	if provider == nil {
		provider = trustcrypto.DefaultProvider()
	}
	var o options
	for _, apply := range opts {
		apply(&o)
	}
	if bundle.SchemaVersion != model.SchemaProofBundle {
		return Result{}, failStage(StageProofBundle, fmt.Errorf("verify: unexpected proof bundle schema: %s", bundle.SchemaVersion))
	}
	suite, err := cryptosuite.RequireAvailable(provider.Suite())
	if err != nil {
		return Result{}, failStage(StageProofBundle, err)
	}
	if err := modelsuite.Require(suite.ID, bundle); err != nil {
		return Result{}, fmt.Errorf("verify: proof bundle crypto_suite: %w", err)
	}
	sum, n, err := trustcrypto.HashReaderWithProvider(provider, bundle.SignedClaim.Claim.Content.HashAlg, raw)
	if err != nil {
		return Result{}, failStage(StageContent, err)
	}
	if n != bundle.SignedClaim.Claim.Content.ContentLength {
		return Result{}, failStage(StageContent, fmt.Errorf("verify: content length mismatch: got %d want %d", n, bundle.SignedClaim.Claim.Content.ContentLength))
	}
	if !bytes.Equal(sum, bundle.SignedClaim.Claim.Content.ContentHash) {
		return Result{}, failStage(StageContent, fmt.Errorf("verify: content hash mismatch"))
	}
	verified, err := claim.VerifyWithProvider(context.Background(), bundle.SignedClaim, keys.ClientPublicKey, provider)
	if err != nil {
		return Result{}, failStage(StageClientClaim, err)
	}
	if verified.RecordID != bundle.RecordID || verified.RecordID != bundle.ServerRecord.RecordID {
		return Result{}, failStage(StageBundleBindings, fmt.Errorf("verify: record id mismatch"))
	}
	if err := validateBundleBindings(bundle, verified, provider); err != nil {
		return Result{}, failStage(StageBundleBindings, err)
	}
	if err := receipt.VerifyAcceptedWithProvider(
		context.Background(),
		bundle.AcceptedReceipt,
		publicKeyOrFallback(keys.AcceptedReceiptPublicKey, keys.ServerPublicKey),
		provider,
	); err != nil {
		return Result{}, failStage(StageAcceptedReceipt, err)
	}
	if err := receipt.VerifyCommittedWithProvider(
		context.Background(),
		bundle.CommittedReceipt,
		publicKeyOrFallback(keys.CommittedReceiptPublicKey, keys.ServerPublicKey),
		provider,
	); err != nil {
		return Result{}, failStage(StageCommittedReceipt, err)
	}
	leaf, err := merkle.HashLeafForSuite(suite.ID, suite.Merkle.Algorithm, bundle.ServerRecord)
	if err != nil {
		return Result{}, failStage(StageBatchMerkle, err)
	}
	if !bytes.Equal(leaf, bundle.CommittedReceipt.LeafHash) {
		return Result{}, failStage(StageBatchMerkle, fmt.Errorf("verify: leaf hash mismatch"))
	}
	ok, err := merkle.VerifyForSuite(
		suite.ID,
		bundle.BatchProof.TreeAlg,
		leaf,
		bundle.BatchProof.LeafIndex,
		bundle.BatchProof.TreeSize,
		bundle.BatchProof.AuditPath,
		bundle.CommittedReceipt.BatchRoot,
	)
	if err != nil {
		return Result{}, failStage(StageBatchMerkle, err)
	}
	if !ok {
		return Result{}, failStage(StageBatchMerkle, fmt.Errorf("verify: merkle proof failed"))
	}
	evidence := prooflevel.EvidenceFor(prooflevel.L3)
	result := Result{
		Valid:      true,
		RecordID:   verified.RecordID,
		ProofLevel: prooflevel.Evaluate(evidence).String(),
	}
	if o.global != nil {
		if o.namespace != nil {
			if err := exactGlobalNamespace(*o.global, *o.namespace); err != nil {
				return Result{}, failStage(StageGlobalLog, err)
			}
		}
		if err := VerifyGlobalLogProof(
			bundle,
			*o.global,
			publicKeyOrFallback(keys.SignedTreeHeadPublicKey, keys.ServerPublicKey),
			provider,
		); err != nil {
			return Result{}, failStage(StageGlobalLog, err)
		}
		evidence.GlobalLogProof = true
		result.ProofLevel = prooflevel.Evaluate(evidence).String()
	}
	if o.anchor != nil {
		if o.global == nil {
			return Result{}, failStage(StageAnchor, fmt.Errorf("verify: L5 anchor requires a global log proof"))
		}
		if o.namespace != nil {
			if err := exactAnchorNamespace(*o.anchor, *o.namespace); err != nil {
				return Result{}, failStage(StageAnchor, err)
			}
		}
		if err := AnchorConsistencyWithVerifier(*o.global, *o.anchor, o.anchorVerifier); err != nil {
			return Result{}, failStage(StageAnchor, err)
		}
		evidence.STHAnchorResult = true
		result.ProofLevel = prooflevel.Evaluate(evidence).String()
		result.AnchorSink = o.anchor.SinkName
		result.AnchorID = o.anchor.AnchorID
	}
	return result, nil
}

func exactGlobalNamespace(proof model.GlobalLogProof, binding namespaceBinding) error {
	if binding.nodeID == "" || proof.NodeID != binding.nodeID || proof.STH.NodeID != binding.nodeID {
		return fmt.Errorf("verify: global proof node_id does not exactly match the evidence namespace")
	}
	if binding.logID == "" || proof.LogID != binding.logID || proof.STH.LogID != binding.logID {
		return fmt.Errorf("verify: global proof log_id does not exactly match the evidence namespace")
	}
	return nil
}

func exactAnchorNamespace(result model.STHAnchorResult, binding namespaceBinding) error {
	if binding.nodeID == "" || result.NodeID != binding.nodeID || result.STH.NodeID != binding.nodeID {
		return fmt.Errorf("verify: anchor result node_id does not exactly match the evidence namespace")
	}
	if binding.logID == "" || result.LogID != binding.logID || result.STH.LogID != binding.logID {
		return fmt.Errorf("verify: anchor result log_id does not exactly match the evidence namespace")
	}
	return nil
}

func publicKeyOrFallback(
	specific trustcrypto.PublicKeyDescriptor,
	fallback trustcrypto.PublicKeyDescriptor,
) trustcrypto.PublicKeyDescriptor {
	if len(specific.Bytes) == 0 {
		return fallback
	}
	return specific
}

func validateBundleBindings(bundle model.ProofBundle, verified claim.Verified, provider trustcrypto.Provider) error {
	suite, err := cryptosuite.RequireAvailable(provider.Suite())
	if err != nil {
		return err
	}
	if err := modelsuite.Require(suite.ID, bundle); err != nil {
		return fmt.Errorf("verify: proof bundle crypto_suite: %w", err)
	}
	if bundle.ServerRecord.TenantID != bundle.SignedClaim.Claim.TenantID {
		return fmt.Errorf("verify: server record tenant_id mismatch")
	}
	if bundle.ServerRecord.ClientID != bundle.SignedClaim.Claim.ClientID {
		return fmt.Errorf("verify: server record client_id mismatch")
	}
	if bundle.ServerRecord.KeyID != bundle.SignedClaim.Claim.KeyID {
		return fmt.Errorf("verify: server record key_id mismatch")
	}
	claimHash, err := trustcrypto.HashBytesWithProvider(provider, suite.ClaimHash.Algorithm, verified.ClaimCBOR)
	if err != nil {
		return err
	}
	if !bytes.Equal(bundle.ServerRecord.ClaimHash, claimHash) {
		return fmt.Errorf("verify: server record claim_hash mismatch")
	}
	sigHash, err := trustcrypto.HashBytesWithProvider(provider, suite.SignatureHash.Algorithm, bundle.SignedClaim.Signature.Signature)
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
	if bundle.BatchProof.TreeAlg != suite.Merkle.Algorithm {
		return fmt.Errorf("verify: unsupported batch proof tree_alg: %s", bundle.BatchProof.TreeAlg)
	}
	if bundle.BatchProof.TreeSize == 0 || bundle.BatchProof.LeafIndex >= bundle.BatchProof.TreeSize {
		return fmt.Errorf("verify: invalid batch proof leaf index")
	}
	return nil
}

func VerifyGlobalLogProof(bundle model.ProofBundle, proof model.GlobalLogProof, publicKey trustcrypto.PublicKeyDescriptor, provider trustcrypto.Provider) error {
	if err := globalLogConsistencyWithProvider(bundle, proof, provider); err != nil {
		return err
	}
	if err := globallog.VerifySTHWithProvider(context.Background(), proof.STH, publicKey, provider); err != nil {
		return err
	}
	return nil
}

func GlobalLogConsistency(bundle model.ProofBundle, proof model.GlobalLogProof) error {
	return globalLogConsistencyWithProvider(bundle, proof, trustcrypto.DefaultProvider())
}

// GlobalLogConsistencyForSuite recomputes the complete proof container with
// the suite explicitly carried by V2 evidence. It performs no signature or
// trust-root verification; callers must still verify the STH with a
// verifier-local public key before granting L4.
func GlobalLogConsistencyForSuite(bundle model.ProofBundle, proof model.GlobalLogProof) error {
	if err := cryptosuite.RequireSame(bundle.CryptoSuite, proof.CryptoSuite, proof.STH.CryptoSuite); err != nil {
		return fmt.Errorf("verify: global log crypto_suite mismatch: %w", err)
	}
	provider, err := trustcrypto.ProviderForSuite(bundle.CryptoSuite)
	if err != nil {
		return err
	}
	return globalLogConsistencyWithProvider(bundle, proof, provider)
}

func globalLogConsistencyWithProvider(bundle model.ProofBundle, proof model.GlobalLogProof, provider trustcrypto.Provider) error {
	if provider == nil {
		return fmt.Errorf("verify: crypto provider is required")
	}
	if proof.SchemaVersion != model.SchemaGlobalLogProof {
		return fmt.Errorf("verify: unexpected global log proof schema: %s", proof.SchemaVersion)
	}
	if proof.STH.SchemaVersion != model.SchemaSignedTreeHead {
		return fmt.Errorf("verify: unexpected STH schema: %s", proof.STH.SchemaVersion)
	}
	suite, err := cryptosuite.RequireAvailable(provider.Suite())
	if err != nil {
		return err
	}
	if err := modelsuite.Require(suite.ID, bundle); err != nil {
		return fmt.Errorf("verify: proof bundle crypto_suite: %w", err)
	}
	if err := modelsuite.Require(suite.ID, proof); err != nil {
		return fmt.Errorf("verify: global proof crypto_suite: %w", err)
	}
	if proof.STH.TreeAlg != suite.Merkle.Algorithm {
		return fmt.Errorf("verify: unsupported STH tree_alg: %s", proof.STH.TreeAlg)
	}
	if proof.TreeSize != proof.STH.TreeSize {
		return fmt.Errorf("verify: global proof tree_size mismatch: proof=%d sth=%d", proof.TreeSize, proof.STH.TreeSize)
	}
	if len(proof.STH.RootHash) != suite.Merkle.Hash.DigestBytes {
		return fmt.Errorf("verify: STH root_hash has length %d, want %d", len(proof.STH.RootHash), suite.Merkle.Hash.DigestBytes)
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
	if !globallog.VerifyInclusionWithProvider(provider, proof) {
		return fmt.Errorf("verify: global log inclusion proof failed")
	}
	leaf := model.GlobalLogLeaf{
		SchemaVersion:      model.SchemaGlobalLogLeaf,
		CryptoSuite:        suite.ID,
		NodeID:             proof.NodeID,
		LogID:              proof.LogID,
		BatchID:            bundle.CommittedReceipt.BatchID,
		BatchRoot:          bundle.CommittedReceipt.BatchRoot,
		BatchTreeSize:      bundle.BatchProof.TreeSize,
		BatchClosedAtUnixN: bundle.CommittedReceipt.ClosedAtUnixN,
		LeafIndex:          proof.LeafIndex,
	}
	hash, err := globallog.HashLeafWithProvider(provider, leaf)
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
	return AnchorConsistencyWithVerifier(proof, ar, nil)
}

func AnchorConsistencyWithVerifier(proof model.GlobalLogProof, ar model.STHAnchorResult, verifier AnchorVerifier) error {
	if err := AnchorBindingConsistency(proof, ar); err != nil {
		return err
	}
	supported, err := verifyBuiltInAnchor(proof, ar)
	if supported {
		return err
	}
	if verifier == nil {
		return fmt.Errorf("verify: unsupported anchor sink: %s", ar.SinkName)
	}
	if err := verifier.VerifyAnchor(proof.STH, ar); err != nil {
		return err
	}
	return nil
}

// AnchorContainerConsistency validates built-in proofs completely while
// allowing a structurally valid custom proof to be transported in .sproof.
// A custom proof still requires AnchorConsistencyWithVerifier before L5 is
// granted.
func AnchorContainerConsistency(proof model.GlobalLogProof, ar model.STHAnchorResult) error {
	if err := AnchorBindingConsistency(proof, ar); err != nil {
		return err
	}
	_, err := verifyBuiltInAnchor(proof, ar)
	return err
}

func verifyBuiltInAnchor(proof model.GlobalLogProof, ar model.STHAnchorResult) (bool, error) {
	switch ar.SinkName {
	case anchor.FileSinkName:
		return true, fmt.Errorf("verify: file sink is local-only and cannot provide offline-verifiable anchor evidence")
	case anchor.NoopSinkName:
		return true, fmt.Errorf("verify: noop sink is local-only and cannot provide offline-verifiable anchor evidence")
	case anchor.OtsSinkName:
		if got, want := ar.AnchorID, anchor.DeterministicOtsAnchorID(proof.STH); got != want {
			return true, fmt.Errorf("verify: ots sink anchor_id mismatch: got %s want %s", got, want)
		}
		if err := validateOtsAnchorProof(proof.STH, ar); err != nil {
			return true, err
		}
	default:
		return false, nil
	}
	return true, nil
}

// AnchorBindingConsistency validates the sink-independent immutable fields.
// It intentionally does not interpret provider proof bytes.
func AnchorBindingConsistency(proof model.GlobalLogProof, ar model.STHAnchorResult) error {
	if ar.SchemaVersion != model.SchemaSTHAnchorResult {
		return fmt.Errorf("verify: unexpected anchor result schema: %s", ar.SchemaVersion)
	}
	suite, err := cryptosuite.RequireAvailable(ar.CryptoSuite)
	if err != nil {
		return fmt.Errorf("verify: anchor result crypto_suite: %w", err)
	}
	if err := modelsuite.Require(suite.ID, proof); err != nil {
		return fmt.Errorf("verify: global proof crypto_suite: %w", err)
	}
	if err := modelsuite.Require(suite.ID, ar); err != nil {
		return fmt.Errorf("verify: anchor result crypto_suite: %w", err)
	}
	if ar.EvidenceStage != model.AnchorEvidenceStageOfflineVerified {
		return fmt.Errorf("verify: anchor evidence stage is not offline_verified: %s", ar.EvidenceStage)
	}
	if ar.TreeSize != proof.STH.TreeSize {
		return fmt.Errorf("verify: anchor tree_size mismatch: anchor=%d sth=%d", ar.TreeSize, proof.STH.TreeSize)
	}
	if ar.NodeID == "" || proof.STH.NodeID == "" || ar.NodeID != proof.STH.NodeID {
		return fmt.Errorf("verify: anchor node_id mismatch: anchor=%s sth=%s", ar.NodeID, proof.STH.NodeID)
	}
	if ar.LogID == "" || proof.STH.LogID == "" || ar.LogID != proof.STH.LogID {
		return fmt.Errorf("verify: anchor log_id mismatch: anchor=%s sth=%s", ar.LogID, proof.STH.LogID)
	}
	if !bytes.Equal(ar.RootHash, proof.STH.RootHash) {
		return fmt.Errorf("verify: anchor root_hash does not match STH root")
	}
	if ar.SinkName == "" {
		return fmt.Errorf("verify: anchor result is missing sink_name")
	}
	if ar.AnchorID == "" {
		return fmt.Errorf("verify: anchor result is missing anchor_id")
	}
	if !sameSignedTreeHead(ar.STH, proof.STH) {
		return fmt.Errorf("verify: anchor signed tree head does not exactly match global proof STH")
	}
	return nil
}

func sameSignedTreeHead(left, right model.SignedTreeHead) bool {
	return left.SchemaVersion == right.SchemaVersion &&
		left.CryptoSuite == right.CryptoSuite &&
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
