package fiscobcos

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
)

const (
	MaxProofBytes          = 16 << 20
	maxTransactionAttempts = 32
	maxMerklePathNodes     = 512
	maxCommitSignatures    = 1024
	maxRawTransactionBytes = 4 << 20
	maxRawReceiptBytes     = 4 << 20
	maxRawHeaderBytes      = 2 << 20
	maxDecodedEventBytes   = 1 << 20
	maxProofNodeBytes      = 128 << 10
	maxSignatureBytes      = 1024
)

type TransactionAttempt struct {
	RawCanonicalTransaction []byte `cbor:"raw_canonical_transaction" json:"raw_canonical_transaction"`
	Signature               []byte `cbor:"signature" json:"signature"`
	Sender                  []byte `cbor:"sender" json:"sender"`
	TransactionHash         []byte `cbor:"transaction_hash" json:"transaction_hash"`
	BlockLimit              uint64 `cbor:"block_limit" json:"block_limit"`
	SubmittedAtUnixN        int64  `cbor:"submitted_at_unix_nano" json:"submitted_at_unix_nano"`
}

type ReceiptEvidence struct {
	RawCanonicalReceipt []byte   `cbor:"raw_canonical_receipt" json:"raw_canonical_receipt"`
	ReceiptHash         []byte   `cbor:"receipt_hash" json:"receipt_hash"`
	TransactionHash     []byte   `cbor:"transaction_hash" json:"transaction_hash"`
	TransactionIndex    uint64   `cbor:"transaction_index" json:"transaction_index"`
	TransactionProof    [][]byte `cbor:"transaction_proof" json:"transaction_proof"`
	ReceiptIndex        uint64   `cbor:"receipt_index" json:"receipt_index"`
	ReceiptProof        [][]byte `cbor:"receipt_proof" json:"receipt_proof"`
	AnchorLogIndex      uint64   `cbor:"anchor_log_index" json:"anchor_log_index"`
	DecodedAnchorEvent  []byte   `cbor:"decoded_anchor_event" json:"decoded_anchor_event"`
}

type BlockEvidence struct {
	RawCanonicalHeader []byte `cbor:"raw_canonical_header" json:"raw_canonical_header"`
	BlockHash          []byte `cbor:"block_hash" json:"block_hash"`
	BlockNumber        uint64 `cbor:"block_number" json:"block_number"`
}

type CommitSignature struct {
	ValidatorNodeID string `cbor:"validator_node_id" json:"validator_node_id"`
	Signature       []byte `cbor:"signature" json:"signature"`
}

type FinalityEvidence struct {
	View       uint64            `cbor:"view" json:"view"`
	Round      uint64            `cbor:"round" json:"round"`
	Signatures []CommitSignature `cbor:"signatures" json:"signatures"`
}

// AnchorProof is an immutable evidence envelope. It carries untrusted chain
// claims and raw evidence but intentionally carries no validator public keys,
// certificate roots, endpoint configuration, account provider, or quorum
// threshold. Those are supplied only through a local TrustConfig.
type AnchorProof struct {
	SchemaVersion             string               `cbor:"schema_version" json:"schema_version"`
	FormatVersion             uint64               `cbor:"format_version" json:"format_version"`
	CryptoMode                CryptoMode           `cbor:"crypto_mode" json:"crypto_mode"`
	ProtocolHashAlgorithm     string               `cbor:"protocol_hash_algorithm" json:"protocol_hash_algorithm"`
	ChainHashAlgorithm        string               `cbor:"chain_hash_algorithm" json:"chain_hash_algorithm"`
	ChainSignatureAlgorithm   string               `cbor:"chain_signature_algorithm" json:"chain_signature_algorithm"`
	ChainID                   string               `cbor:"chain_id" json:"chain_id"`
	GroupID                   string               `cbor:"group_id" json:"group_id"`
	GenesisHash               []byte               `cbor:"genesis_hash" json:"genesis_hash"`
	TrustedCheckpoint         BlockCheckpoint      `cbor:"trusted_checkpoint" json:"trusted_checkpoint"`
	Contract                  ContractBinding      `cbor:"contract" json:"contract"`
	ChainContextID            []byte               `cbor:"chain_context_id" json:"chain_context_id"`
	CanonicalPayload          []byte               `cbor:"canonical_payload" json:"canonical_payload"`
	TransactionAttempts       []TransactionAttempt `cbor:"transaction_attempts" json:"transaction_attempts"`
	SuccessfulTransactionHash []byte               `cbor:"successful_transaction_hash" json:"successful_transaction_hash"`
	Receipt                   ReceiptEvidence      `cbor:"receipt" json:"receipt"`
	Block                     BlockEvidence        `cbor:"block" json:"block"`
	Finality                  FinalityEvidence     `cbor:"finality" json:"finality"`
}

func MarshalProof(proof AnchorProof) ([]byte, error) {
	if err := ValidateProofStructure(proof); err != nil {
		return nil, err
	}
	data, err := cborx.Marshal(proof)
	if err != nil {
		return nil, fmt.Errorf("%w: encode proof: %v", ErrInvalidProof, err)
	}
	if len(data) > MaxProofBytes {
		return nil, fmt.Errorf("%w: encoded proof is %d bytes, limit %d", ErrInvalidProof, len(data), MaxProofBytes)
	}
	return data, nil
}

func UnmarshalProof(data []byte) (AnchorProof, error) {
	var proof AnchorProof
	if err := cborx.UnmarshalLimit(data, &proof, MaxProofBytes); err != nil {
		return AnchorProof{}, fmt.Errorf("%w: decode proof: %v", ErrInvalidProof, err)
	}
	if err := ValidateProofStructure(proof); err != nil {
		return AnchorProof{}, err
	}
	return proof, nil
}

func ValidateProofStructure(proof AnchorProof) error {
	if proof.SchemaVersion != SchemaAnchorProof || proof.FormatVersion != ProofVersion {
		return fmt.Errorf("%w: unsupported schema/version %q/%d", ErrInvalidProof, proof.SchemaVersion, proof.FormatVersion)
	}
	if err := validateExplicitModeParameters(proof.CryptoMode, proof.ProtocolHashAlgorithm, proof.ChainHashAlgorithm, proof.ChainSignatureAlgorithm); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}
	for name, value := range map[string]string{
		"chain_id": proof.ChainID, "group_id": proof.GroupID,
		"contract.protocol_version": proof.Contract.ProtocolVersion,
		"contract.event_signature":  proof.Contract.EventSignature,
	} {
		if err := validateConfigString(name, value); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidProof, err)
		}
	}
	if len(proof.GenesisHash) != identifierBytes || len(proof.TrustedCheckpoint.BlockHash) != identifierBytes || len(proof.ChainContextID) != identifierBytes {
		return fmt.Errorf("%w: genesis, checkpoint, and chain_context identifiers must be %d bytes", ErrInvalidProof, identifierBytes)
	}
	if len(proof.Contract.Address) != 20 || len(proof.Contract.CodeHash) != identifierBytes {
		return fmt.Errorf("%w: contract address/code hash length is invalid", ErrInvalidProof)
	}
	if _, err := UnmarshalPayload(proof.CanonicalPayload); err != nil {
		return fmt.Errorf("%w: canonical payload: %v", ErrInvalidProof, err)
	}
	if len(proof.TransactionAttempts) == 0 || len(proof.TransactionAttempts) > maxTransactionAttempts {
		return fmt.Errorf("%w: transaction attempt count=%d", ErrInvalidProof, len(proof.TransactionAttempts))
	}
	seenAttempts := make(map[string]struct{}, len(proof.TransactionAttempts))
	foundSuccessful := false
	for i, attempt := range proof.TransactionAttempts {
		if len(attempt.RawCanonicalTransaction) == 0 || len(attempt.RawCanonicalTransaction) > maxRawTransactionBytes || len(attempt.Signature) == 0 || len(attempt.Signature) > maxSignatureBytes || len(attempt.Sender) == 0 || len(attempt.Sender) > 256 || len(attempt.TransactionHash) != identifierBytes || attempt.BlockLimit == 0 {
			return fmt.Errorf("%w: transaction attempt %d is incomplete or oversized", ErrInvalidProof, i)
		}
		key := string(attempt.TransactionHash)
		if _, exists := seenAttempts[key]; exists {
			return fmt.Errorf("%w: duplicate transaction attempt hash", ErrInvalidProof)
		}
		seenAttempts[key] = struct{}{}
		if bytes.Equal(attempt.TransactionHash, proof.SuccessfulTransactionHash) {
			foundSuccessful = true
		}
	}
	if len(proof.SuccessfulTransactionHash) != identifierBytes || !foundSuccessful {
		return fmt.Errorf("%w: successful transaction hash does not identify one immutable attempt", ErrInvalidProof)
	}
	if len(proof.Receipt.RawCanonicalReceipt) == 0 || len(proof.Receipt.RawCanonicalReceipt) > maxRawReceiptBytes || len(proof.Receipt.ReceiptHash) != identifierBytes || !bytes.Equal(proof.Receipt.TransactionHash, proof.SuccessfulTransactionHash) || len(proof.Receipt.DecodedAnchorEvent) == 0 || len(proof.Receipt.DecodedAnchorEvent) > maxDecodedEventBytes {
		return fmt.Errorf("%w: receipt evidence is incomplete or oversized", ErrInvalidProof)
	}
	if err := validateMerklePath("transaction", proof.Receipt.TransactionProof); err != nil {
		return err
	}
	if err := validateMerklePath("receipt", proof.Receipt.ReceiptProof); err != nil {
		return err
	}
	if len(proof.Block.RawCanonicalHeader) == 0 || len(proof.Block.RawCanonicalHeader) > maxRawHeaderBytes || len(proof.Block.BlockHash) != identifierBytes || proof.Block.BlockNumber == 0 {
		return fmt.Errorf("%w: block evidence is incomplete or oversized", ErrInvalidProof)
	}
	if len(proof.Finality.Signatures) == 0 || len(proof.Finality.Signatures) > maxCommitSignatures {
		return fmt.Errorf("%w: finality signature count=%d", ErrInvalidProof, len(proof.Finality.Signatures))
	}
	seenSigners := make(map[string]struct{}, len(proof.Finality.Signatures))
	for i, signature := range proof.Finality.Signatures {
		if strings.TrimSpace(signature.ValidatorNodeID) == "" || len(signature.ValidatorNodeID) > maxConfigString || len(signature.Signature) == 0 || len(signature.Signature) > maxSignatureBytes {
			return fmt.Errorf("%w: finality signature %d is incomplete or oversized", ErrInvalidProof, i)
		}
		if _, exists := seenSigners[signature.ValidatorNodeID]; exists {
			return fmt.Errorf("%w: duplicate finality signer %q", ErrInvalidProof, signature.ValidatorNodeID)
		}
		seenSigners[signature.ValidatorNodeID] = struct{}{}
	}
	return nil
}

// ValidateProofContainer checks the immutable TrustDB binding and the strict
// proof encoding only. It intentionally does not claim receipt inclusion or
// PBFT finality; those stages require a local TrustConfig and native BCOS
// verification implemented by the dedicated offline verifier.
func ValidateProofContainer(sth model.SignedTreeHead, result model.STHAnchorResult) error {
	if result.SinkName != SinkName {
		return fmt.Errorf("%w: sink_name=%q", ErrInvalidProof, result.SinkName)
	}
	if result.SchemaVersion != model.SchemaSTHAnchorResult || !sameSignedTreeHead(result.STH, sth) {
		return fmt.Errorf("%w: result does not carry the exact supplied signed STH", ErrInvalidProof)
	}
	proof, err := UnmarshalProof(result.Proof)
	if err != nil {
		return err
	}
	payload, err := UnmarshalPayload(proof.CanonicalPayload)
	if err != nil {
		return fmt.Errorf("%w: decode canonical payload: %v", ErrInvalidProof, err)
	}
	if err := ValidatePayloadAgainstSTH(payload, sth); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}
	if result.AnchorID != AnchorIDString(payload) {
		return fmt.Errorf("%w: result anchor_id=%q, want %s", ErrInvalidProof, result.AnchorID, AnchorIDString(payload))
	}
	if result.NodeID != sth.NodeID || result.LogID != sth.LogID || result.TreeSize != sth.TreeSize || !bytes.Equal(result.RootHash, sth.RootHash) {
		return fmt.Errorf("%w: result does not exactly bind node/log/tree/root", ErrInvalidProof)
	}
	return nil
}

// ValidateProofAgainstTrustConfig rejects wrong-chain, wrong-contract, and
// cross-mode evidence using only locally supplied trust material. Evidence
// fields are claims to compare, never configuration to adopt.
func ValidateProofAgainstTrustConfig(sth model.SignedTreeHead, result model.STHAnchorResult, config TrustConfig) error {
	if err := ValidateProofContainer(sth, result); err != nil {
		return err
	}
	canonical, err := canonicalTrustConfig(config)
	if err != nil {
		return err
	}
	proof, _ := UnmarshalProof(result.Proof)
	if proof.CryptoMode != canonical.CryptoMode || proof.ProtocolHashAlgorithm != canonical.ProtocolHashAlgorithm || proof.ChainHashAlgorithm != canonical.ChainHashAlgorithm || proof.ChainSignatureAlgorithm != canonical.ChainSignatureAlgorithm {
		return fmt.Errorf("%w: evidence crypto mode or algorithms do not match local trust config", ErrInvalidProof)
	}
	if proof.ChainID != canonical.ChainID || proof.GroupID != canonical.GroupID || !bytes.Equal(proof.GenesisHash, canonical.GenesisHash) || proof.TrustedCheckpoint.BlockNumber != canonical.TrustedCheckpoint.BlockNumber || !bytes.Equal(proof.TrustedCheckpoint.BlockHash, canonical.TrustedCheckpoint.BlockHash) {
		return fmt.Errorf("%w: evidence chain/group/checkpoint does not match local trust config", ErrInvalidProof)
	}
	if !sameContractBinding(proof.Contract, canonical.Contract) {
		return fmt.Errorf("%w: evidence contract does not match local trust config", ErrInvalidProof)
	}
	wantContext, err := ChainContextID(canonical)
	if err != nil {
		return err
	}
	if !bytes.Equal(proof.ChainContextID, wantContext) {
		return fmt.Errorf("%w: chain_context_id=%s does not match local trust config", ErrInvalidProof, hex.EncodeToString(proof.ChainContextID))
	}
	return nil
}

func validateMerklePath(name string, path [][]byte) error {
	if len(path) > maxMerklePathNodes {
		return fmt.Errorf("%w: %s proof node count=%d", ErrInvalidProof, name, len(path))
	}
	for i, node := range path {
		if len(node) == 0 || len(node) > maxProofNodeBytes {
			return fmt.Errorf("%w: %s proof node %d is empty or oversized", ErrInvalidProof, name, i)
		}
	}
	return nil
}

func sameContractBinding(left, right ContractBinding) bool {
	return bytes.Equal(left.Address, right.Address) && bytes.Equal(left.CodeHash, right.CodeHash) && left.ProtocolVersion == right.ProtocolVersion && left.EventSignature == right.EventSignature
}

func sameSignedTreeHead(left, right model.SignedTreeHead) bool {
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
