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
	MaxProofBytes             = 16 << 20
	MaxMerklePathNodes        = 512
	MaxCanonicalLogs          = 512
	MaxProofNodeBytes         = 128 << 10
	MaxCommitSignatures       = 1024
	MaxSignatureBytes         = 1024
	maxTransactionAttempts    = 32
	maxMerklePathNodes        = MaxMerklePathNodes
	maxCommitSignatures       = MaxCommitSignatures
	maxRawTransactionBytes    = 4 << 20
	maxRawReceiptBytes        = 4 << 20
	maxRawHeaderBytes         = 2 << 20
	MaxValidatorHistoryBlocks = 4096
	maxDecodedEventBytes      = 1 << 20
	maxProofNodeBytes         = MaxProofNodeBytes
	maxSignatureBytes         = MaxSignatureBytes
)

type TransactionAttempt struct {
	Ordinal                 uint32                 `cbor:"ordinal" json:"ordinal"`
	RawCanonicalTransaction []byte                 `cbor:"raw_canonical_transaction" json:"raw_canonical_transaction"`
	ChainID                 string                 `cbor:"chain_id" json:"chain_id"`
	GroupID                 string                 `cbor:"group_id" json:"group_id"`
	To                      []byte                 `cbor:"to" json:"to"`
	Input                   []byte                 `cbor:"input" json:"input"`
	Signature               []byte                 `cbor:"signature" json:"signature"`
	Sender                  []byte                 `cbor:"sender" json:"sender"`
	TransactionHash         []byte                 `cbor:"transaction_hash" json:"transaction_hash"`
	BlockLimit              uint64                 `cbor:"block_limit" json:"block_limit"`
	SubmittedAtUnixN        int64                  `cbor:"submitted_at_unix_nano" json:"submitted_at_unix_nano"`
	Outcome                 AttemptOutcome         `cbor:"outcome" json:"outcome"`
	Submission              *SubmissionObservation `cbor:"submission,omitempty" json:"submission,omitempty"`
}

type ReceiptEvidence struct {
	Fields              NativeReceiptFields `cbor:"fields" json:"fields"`
	RawCanonicalReceipt []byte              `cbor:"raw_canonical_receipt" json:"raw_canonical_receipt"`
	Status              int64               `cbor:"status" json:"status"`
	StatusMessage       string              `cbor:"status_message" json:"status_message"`
	CanonicalLogs       [][]byte            `cbor:"canonical_logs" json:"canonical_logs"`
	ReceiptHash         []byte              `cbor:"receipt_hash" json:"receipt_hash"`
	TransactionHash     []byte              `cbor:"transaction_hash" json:"transaction_hash"`
	TransactionIndex    uint64              `cbor:"transaction_index" json:"transaction_index"`
	TransactionProof    [][]byte            `cbor:"transaction_proof" json:"transaction_proof"`
	ReceiptIndex        uint64              `cbor:"receipt_index" json:"receipt_index"`
	ReceiptProof        [][]byte            `cbor:"receipt_proof" json:"receipt_proof"`
	AnchorLogIndex      uint64              `cbor:"anchor_log_index" json:"anchor_log_index"`
	DecodedAnchorEvent  []byte              `cbor:"decoded_anchor_event" json:"decoded_anchor_event"`
}

type BlockEvidence struct {
	Fields             NativeBlockHeaderFields `cbor:"fields" json:"fields"`
	RawCanonicalHeader []byte                  `cbor:"raw_canonical_header" json:"raw_canonical_header"`
	BlockHash          []byte                  `cbor:"block_hash" json:"block_hash"`
	BlockNumber        uint64                  `cbor:"block_number" json:"block_number"`
}

type CommitSignature struct {
	ValidatorNodeID string `cbor:"validator_node_id" json:"validator_node_id"`
	Signature       []byte `cbor:"signature" json:"signature"`
}

type FinalityEvidence struct {
	Signatures []CommitSignature `cbor:"signatures" json:"signatures"`
}

type TransitionTransactionEvidence struct {
	Fields          NativeTransactionFields `cbor:"fields" json:"fields"`
	RawHashPreimage []byte                  `cbor:"raw_hash_preimage" json:"raw_hash_preimage"`
	TransactionHash []byte                  `cbor:"transaction_hash" json:"transaction_hash"`
}

type TransitionReceiptEvidence struct {
	Fields              NativeReceiptFields `cbor:"fields" json:"fields"`
	RawCanonicalReceipt []byte              `cbor:"raw_canonical_receipt" json:"raw_canonical_receipt"`
	ReceiptHash         []byte              `cbor:"receipt_hash" json:"receipt_hash"`
}

// ValidatorHistoryBlock carries one contiguous predecessor block. The first
// item is the verifier-local trusted checkpoint; the last item immediately
// precedes AnchorProof.Block. Full transaction/receipt lists are present only
// when this block activates a different validator set in the next block.
type ValidatorHistoryBlock struct {
	Block        BlockEvidence                   `cbor:"block" json:"block"`
	Finality     FinalityEvidence                `cbor:"finality" json:"finality"`
	Transactions []TransitionTransactionEvidence `cbor:"transactions,omitempty" json:"transactions,omitempty"`
	Receipts     []TransitionReceiptEvidence     `cbor:"receipts,omitempty" json:"receipts,omitempty"`
}

// AnchorProof is an immutable evidence envelope. It carries untrusted chain
// claims and raw evidence but intentionally carries no validator public keys,
// certificate roots, endpoint configuration, account provider, or quorum
// threshold. Those are supplied only through a local TrustConfig.
type AnchorProof struct {
	SchemaVersion             string                  `cbor:"schema_version" json:"schema_version"`
	FormatVersion             uint64                  `cbor:"format_version" json:"format_version"`
	CryptoMode                CryptoMode              `cbor:"crypto_mode" json:"crypto_mode"`
	ProtocolHashAlgorithm     string                  `cbor:"protocol_hash_algorithm" json:"protocol_hash_algorithm"`
	ChainHashAlgorithm        string                  `cbor:"chain_hash_algorithm" json:"chain_hash_algorithm"`
	ChainSignatureAlgorithm   string                  `cbor:"chain_signature_algorithm" json:"chain_signature_algorithm"`
	ChainID                   string                  `cbor:"chain_id" json:"chain_id"`
	GroupID                   string                  `cbor:"group_id" json:"group_id"`
	GenesisHash               []byte                  `cbor:"genesis_hash" json:"genesis_hash"`
	TrustedCheckpoint         BlockCheckpoint         `cbor:"trusted_checkpoint" json:"trusted_checkpoint"`
	Contract                  ContractBinding         `cbor:"contract" json:"contract"`
	ChainContextID            []byte                  `cbor:"chain_context_id" json:"chain_context_id"`
	CanonicalPayload          []byte                  `cbor:"canonical_payload" json:"canonical_payload"`
	TransactionAttempts       []TransactionAttempt    `cbor:"transaction_attempts" json:"transaction_attempts"`
	SuccessfulAttemptOrdinal  uint32                  `cbor:"successful_attempt_ordinal" json:"successful_attempt_ordinal"`
	SuccessfulTransactionHash []byte                  `cbor:"successful_transaction_hash" json:"successful_transaction_hash"`
	Receipt                   ReceiptEvidence         `cbor:"receipt" json:"receipt"`
	Block                     BlockEvidence           `cbor:"block" json:"block"`
	Finality                  FinalityEvidence        `cbor:"finality" json:"finality"`
	ValidatorHistory          []ValidatorHistoryBlock `cbor:"validator_history,omitempty" json:"validator_history,omitempty"`
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
	if err := cborx.UnmarshalLimits(data, &proof, MaxProofBytes, 4096, 128); err != nil {
		return AnchorProof{}, fmt.Errorf("%w: decode proof: %v", ErrInvalidProof, err)
	}
	if err := ValidateProofStructure(proof); err != nil {
		return AnchorProof{}, err
	}
	canonical, err := MarshalProof(proof)
	if err != nil {
		return AnchorProof{}, err
	}
	if !bytes.Equal(data, canonical) {
		return AnchorProof{}, fmt.Errorf("%w: non-canonical deterministic CBOR", ErrInvalidProof)
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
	var previousBlockLimit uint64
	for i, attempt := range proof.TransactionAttempts {
		if attempt.Ordinal != uint32(i+1) ||
			len(attempt.RawCanonicalTransaction) == 0 ||
			len(attempt.RawCanonicalTransaction) > maxRawTransactionBytes ||
			attempt.ChainID != proof.ChainID ||
			attempt.GroupID != proof.GroupID ||
			!bytes.Equal(attempt.To, proof.Contract.Address) ||
			len(attempt.Input) == 0 || len(attempt.Input) > MaxPayloadBytes+4 ||
			len(attempt.Signature) == 0 || len(attempt.Signature) > maxSignatureBytes ||
			len(attempt.Sender) == 0 || len(attempt.Sender) > 256 ||
			len(attempt.TransactionHash) != identifierBytes ||
			attempt.BlockLimit == 0 || attempt.SubmittedAtUnixN <= 0 ||
			!validCompletedAttemptOutcome(attempt.Outcome) {
			return fmt.Errorf("%w: transaction attempt %d is incomplete or oversized", ErrInvalidProof, i)
		}
		if i > 0 && attempt.BlockLimit <= previousBlockLimit {
			return fmt.Errorf("%w: transaction block limits do not strictly increase", ErrInvalidProof)
		}
		if i < len(proof.TransactionAttempts)-1 &&
			attempt.Outcome != AttemptOutcomeBlockLimitExpired &&
			attempt.Outcome != AttemptOutcomeReceiptBlockLimitRejected {
			return fmt.Errorf("%w: non-final transaction attempt %d was not closed by block limit", ErrInvalidProof, i+1)
		}
		switch attempt.Outcome {
		case AttemptOutcomeBlockLimitExpired:
			if attempt.Submission != nil {
				return fmt.Errorf("%w: transaction attempt %d has unexpected submission response", ErrInvalidProof, i+1)
			}
		case AttemptOutcomeReceiptSuccess:
			if attempt.Submission != nil {
				if err := validateSubmissionObservation(attempt.Submission, -1); err != nil {
					return err
				}
				if attempt.Submission.Status != ReceiptStatusOK &&
					!isRecoverableSubmissionStatus(attempt.Submission.Status) {
					return fmt.Errorf("%w: successful attempt %d has incompatible submission status", ErrInvalidProof, i+1)
				}
			}
		case AttemptOutcomeReceiptBlockLimitRejected:
			if err := validateSubmissionObservation(attempt.Submission, ReceiptStatusCodeBlockLimit); err != nil {
				return err
			}
		case AttemptOutcomeReceiptTerminalRejected:
			if err := validateSubmissionObservation(attempt.Submission, -1); err != nil {
				return err
			}
			if attempt.Submission.Status == ReceiptStatusOK ||
				attempt.Submission.Status == ReceiptStatusCodeBlockLimit {
				return fmt.Errorf("%w: transaction attempt %d has non-terminal status", ErrInvalidProof, i+1)
			}
		}
		previousBlockLimit = attempt.BlockLimit
		key := string(attempt.TransactionHash)
		if _, exists := seenAttempts[key]; exists {
			return fmt.Errorf("%w: duplicate transaction attempt hash", ErrInvalidProof)
		}
		seenAttempts[key] = struct{}{}
		if attempt.Ordinal == proof.SuccessfulAttemptOrdinal &&
			bytes.Equal(attempt.TransactionHash, proof.SuccessfulTransactionHash) &&
			attempt.Outcome == AttemptOutcomeReceiptSuccess {
			foundSuccessful = true
		}
	}
	if proof.SuccessfulAttemptOrdinal == 0 ||
		proof.SuccessfulAttemptOrdinal > uint32(len(proof.TransactionAttempts)) ||
		len(proof.SuccessfulTransactionHash) != identifierBytes ||
		!foundSuccessful {
		return fmt.Errorf("%w: successful transaction hash does not identify one immutable attempt", ErrInvalidProof)
	}
	if len(proof.Receipt.RawCanonicalReceipt) == 0 ||
		len(proof.Receipt.RawCanonicalReceipt) > maxRawReceiptBytes ||
		proof.Receipt.Status != ReceiptStatusOK ||
		len(proof.Receipt.StatusMessage) == 0 ||
		len(proof.Receipt.StatusMessage) > maxConfigString ||
		len(proof.Receipt.CanonicalLogs) == 0 ||
		len(proof.Receipt.CanonicalLogs) > maxCanonicalLogs ||
		len(proof.Receipt.ReceiptHash) != identifierBytes ||
		!bytes.Equal(proof.Receipt.TransactionHash, proof.SuccessfulTransactionHash) ||
		len(proof.Receipt.DecodedAnchorEvent) == 0 ||
		len(proof.Receipt.DecodedAnchorEvent) > maxDecodedEventBytes {
		return fmt.Errorf("%w: receipt evidence is incomplete or oversized", ErrInvalidProof)
	}
	canonicalReceipt, canonicalLogs, err := MarshalNativeReceiptPreimage(proof.Receipt.Fields)
	if err != nil ||
		!bytes.Equal(canonicalReceipt, proof.Receipt.RawCanonicalReceipt) ||
		!sameEvidenceByteSlices(canonicalLogs, proof.Receipt.CanonicalLogs) ||
		int64(proof.Receipt.Fields.Status) != proof.Receipt.Status {
		return fmt.Errorf("%w: receipt fields do not reconstruct exact consensus preimage", ErrInvalidProof)
	}
	receiptHash, err := HashNativeEvidence(proof.ChainHashAlgorithm, canonicalReceipt)
	if err != nil || !bytes.Equal(receiptHash, proof.Receipt.ReceiptHash) {
		return fmt.Errorf("%w: receipt consensus hash mismatch", ErrInvalidProof)
	}
	if err := validateMerklePath("transaction", proof.Receipt.TransactionProof); err != nil {
		return err
	}
	if err := validateMerklePath("receipt", proof.Receipt.ReceiptProof); err != nil {
		return err
	}
	receiptAggregate := len(proof.Receipt.RawCanonicalReceipt) + len(proof.Receipt.DecodedAnchorEvent)
	for index, log := range proof.Receipt.CanonicalLogs {
		if len(log) == 0 || len(log) > maxProofNodeBytes {
			return fmt.Errorf("%w: canonical log %d is empty or oversized", ErrInvalidProof, index)
		}
		receiptAggregate += len(log)
	}
	for _, path := range [][][]byte{proof.Receipt.TransactionProof, proof.Receipt.ReceiptProof} {
		for _, node := range path {
			receiptAggregate += len(node)
		}
	}
	if receiptAggregate > maxReceiptAggregate {
		return fmt.Errorf("%w: receipt/log/proof aggregate exceeds %d", ErrInvalidProof, maxReceiptAggregate)
	}
	if len(proof.Block.RawCanonicalHeader) == 0 || len(proof.Block.RawCanonicalHeader) > maxRawHeaderBytes || len(proof.Block.BlockHash) != identifierBytes || proof.Block.BlockNumber == 0 {
		return fmt.Errorf("%w: block evidence is incomplete or oversized", ErrInvalidProof)
	}
	canonicalHeader, err := MarshalNativeBlockHeaderPreimage(proof.Block.Fields)
	if err != nil ||
		!bytes.Equal(canonicalHeader, proof.Block.RawCanonicalHeader) ||
		proof.Block.Fields.BlockNumber < 0 ||
		uint64(proof.Block.Fields.BlockNumber) != proof.Block.BlockNumber ||
		proof.Receipt.Fields.BlockNumber != proof.Block.Fields.BlockNumber {
		return fmt.Errorf("%w: block fields do not reconstruct exact consensus preimage", ErrInvalidProof)
	}
	blockHash, err := HashNativeEvidence(proof.ChainHashAlgorithm, canonicalHeader)
	if err != nil || !bytes.Equal(blockHash, proof.Block.BlockHash) {
		return fmt.Errorf("%w: block consensus hash mismatch", ErrInvalidProof)
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
	if len(proof.ValidatorHistory) > MaxValidatorHistoryBlocks {
		return fmt.Errorf("%w: validator history block count=%d", ErrInvalidProof, len(proof.ValidatorHistory))
	}
	for index, item := range proof.ValidatorHistory {
		if err := validateHistoryBlockStructure(proof, index, item); err != nil {
			return err
		}
	}
	return nil
}

func validateHistoryBlockStructure(proof AnchorProof, index int, item ValidatorHistoryBlock) error {
	if len(item.Block.RawCanonicalHeader) == 0 ||
		len(item.Block.RawCanonicalHeader) > maxRawHeaderBytes ||
		len(item.Block.BlockHash) != identifierBytes {
		return fmt.Errorf("%w: validator history block %d is incomplete or oversized", ErrInvalidProof, index)
	}
	canonicalHeader, err := MarshalNativeBlockHeaderPreimage(item.Block.Fields)
	if err != nil || !bytes.Equal(canonicalHeader, item.Block.RawCanonicalHeader) ||
		item.Block.Fields.BlockNumber < 0 ||
		uint64(item.Block.Fields.BlockNumber) != item.Block.BlockNumber {
		return fmt.Errorf("%w: validator history block %d has a non-canonical header", ErrInvalidProof, index)
	}
	blockHash, err := HashNativeEvidence(proof.ChainHashAlgorithm, canonicalHeader)
	if err != nil || !bytes.Equal(blockHash, item.Block.BlockHash) {
		return fmt.Errorf("%w: validator history block %d hash mismatch", ErrInvalidProof, index)
	}
	if len(item.Finality.Signatures) > maxCommitSignatures {
		return fmt.Errorf("%w: validator history block %d signature count=%d", ErrInvalidProof, index, len(item.Finality.Signatures))
	}
	seenSigners := make(map[string]struct{}, len(item.Finality.Signatures))
	for signatureIndex, signature := range item.Finality.Signatures {
		if strings.TrimSpace(signature.ValidatorNodeID) == "" ||
			len(signature.ValidatorNodeID) > maxConfigString ||
			len(signature.Signature) == 0 || len(signature.Signature) > maxSignatureBytes {
			return fmt.Errorf("%w: validator history block %d signature %d is incomplete or oversized", ErrInvalidProof, index, signatureIndex)
		}
		if _, duplicate := seenSigners[signature.ValidatorNodeID]; duplicate {
			return fmt.Errorf("%w: validator history block %d duplicates signer %q", ErrInvalidProof, index, signature.ValidatorNodeID)
		}
		seenSigners[signature.ValidatorNodeID] = struct{}{}
	}
	if len(item.Transactions) != len(item.Receipts) || len(item.Transactions) > maxNativeEvidenceItems {
		return fmt.Errorf("%w: validator history block %d transaction/receipt count mismatch", ErrInvalidProof, index)
	}
	for transactionIndex := range item.Transactions {
		transaction := item.Transactions[transactionIndex]
		preimage, err := MarshalNativeTransactionHashPreimage(transaction.Fields)
		if err != nil || len(transaction.RawHashPreimage) == 0 ||
			len(transaction.RawHashPreimage) > maxRawTransactionBytes ||
			!bytes.Equal(preimage, transaction.RawHashPreimage) ||
			transaction.Fields.ChainID != proof.ChainID ||
			transaction.Fields.GroupID != proof.GroupID ||
			len(transaction.TransactionHash) != identifierBytes {
			return fmt.Errorf("%w: validator history block %d transaction %d is incomplete", ErrInvalidProof, index, transactionIndex)
		}
		transactionHash, err := HashNativeEvidence(proof.ChainHashAlgorithm, preimage)
		if err != nil || !bytes.Equal(transactionHash, transaction.TransactionHash) {
			return fmt.Errorf("%w: validator history block %d transaction %d hash mismatch", ErrInvalidProof, index, transactionIndex)
		}
		receipt := item.Receipts[transactionIndex]
		canonicalReceipt, _, err := MarshalNativeReceiptPreimage(receipt.Fields)
		if err != nil || len(receipt.RawCanonicalReceipt) == 0 ||
			len(receipt.RawCanonicalReceipt) > maxRawReceiptBytes ||
			!bytes.Equal(canonicalReceipt, receipt.RawCanonicalReceipt) ||
			receipt.Fields.BlockNumber < 0 ||
			uint64(receipt.Fields.BlockNumber) != item.Block.BlockNumber ||
			len(receipt.ReceiptHash) != identifierBytes {
			return fmt.Errorf("%w: validator history block %d receipt %d is incomplete", ErrInvalidProof, index, transactionIndex)
		}
		receiptHash, err := HashNativeEvidence(proof.ChainHashAlgorithm, canonicalReceipt)
		if err != nil || !bytes.Equal(receiptHash, receipt.ReceiptHash) {
			return fmt.Errorf("%w: validator history block %d receipt %d hash mismatch", ErrInvalidProof, index, transactionIndex)
		}
	}
	return nil
}

func validCompletedAttemptOutcome(outcome AttemptOutcome) bool {
	switch outcome {
	case AttemptOutcomeBlockLimitExpired,
		AttemptOutcomeReceiptBlockLimitRejected,
		AttemptOutcomeReceiptTerminalRejected,
		AttemptOutcomeReceiptSuccess:
		return true
	default:
		return false
	}
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

func sameEvidenceByteSlices(left, right [][]byte) bool {
	if len(left) != len(right) || (left == nil) != (right == nil) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

func sameContractBinding(left, right ContractBinding) bool {
	return bytes.Equal(left.Address, right.Address) && bytes.Equal(left.CodeHash, right.CodeHash) && left.ProtocolVersion == right.ProtocolVersion && left.EventSignature == right.EventSignature
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
