package fiscobcos

import (
	"bytes"
	"fmt"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
)

const (
	SchemaPublicationObservation   = "trustdb.fisco-bcos-publication-observation.v1"
	MaxPublicationObservationBytes = 16 << 20
)

// PublicationObservation is durable raw RPC material for an externally
// observed publication. It intentionally does not use AnchorProof's
// RawCanonical* fields and makes no receipt-inclusion or PBFT-finality claim.
// #465 may transform qualified native encodings into the offline proof format.
type PublicationObservation struct {
	SchemaVersion     string                `cbor:"schema_version" json:"schema_version"`
	EvidenceStage     string                `cbor:"evidence_stage" json:"evidence_stage"`
	CryptoMode        CryptoMode            `cbor:"crypto_mode" json:"crypto_mode"`
	ChainID           string                `cbor:"chain_id" json:"chain_id"`
	GroupID           string                `cbor:"group_id" json:"group_id"`
	GenesisHash       []byte                `cbor:"genesis_hash" json:"genesis_hash"`
	TrustedCheckpoint BlockCheckpoint       `cbor:"trusted_checkpoint" json:"trusted_checkpoint"`
	Contract          ContractBinding       `cbor:"contract" json:"contract"`
	ChainContextID    []byte                `cbor:"chain_context_id" json:"chain_context_id"`
	CanonicalPayload  []byte                `cbor:"canonical_payload" json:"canonical_payload"`
	Transaction       TransactionSubmission `cbor:"transaction" json:"transaction"`
	Receipt           ReceiptRPCObservation `cbor:"receipt" json:"receipt"`
	Event             AnchorPublishedEvent  `cbor:"event" json:"event"`
	Readback          AnchorRecord          `cbor:"readback" json:"readback"`
	Block             BlockRPCObservation   `cbor:"block" json:"block"`
	Consensus         ConsensusSnapshot     `cbor:"consensus" json:"consensus"`
}

func MarshalPublicationObservation(observation PublicationObservation) ([]byte, error) {
	if err := ValidatePublicationObservation(observation); err != nil {
		return nil, err
	}
	data, err := cborx.Marshal(observation)
	if err != nil {
		return nil, fmt.Errorf("%w: encode publication observation: %v", ErrDriverInvalid, err)
	}
	if len(data) > MaxPublicationObservationBytes {
		return nil, fmt.Errorf("%w: publication observation exceeds %d bytes", ErrDriverInvalid, MaxPublicationObservationBytes)
	}
	return data, nil
}

func UnmarshalPublicationObservation(data []byte) (PublicationObservation, error) {
	var observation PublicationObservation
	if err := cborx.UnmarshalLimit(data, &observation, MaxPublicationObservationBytes); err != nil {
		return PublicationObservation{}, fmt.Errorf("%w: decode publication observation: %v", ErrDriverInvalid, err)
	}
	if err := ValidatePublicationObservation(observation); err != nil {
		return PublicationObservation{}, err
	}
	canonical, err := cborx.Marshal(observation)
	if err != nil {
		return PublicationObservation{}, fmt.Errorf("%w: canonicalize publication observation: %v", ErrDriverInvalid, err)
	}
	if !bytes.Equal(canonical, data) {
		return PublicationObservation{}, fmt.Errorf("%w: publication observation is not canonical CBOR", ErrDriverInvalid)
	}
	return observation, nil
}

func ValidatePublicationObservation(observation PublicationObservation) error {
	if observation.SchemaVersion != SchemaPublicationObservation ||
		observation.EvidenceStage != model.AnchorEvidenceStageRaw ||
		observation.CryptoMode != CryptoModeStandard ||
		observation.ChainID == "" || observation.GroupID == "" ||
		len(observation.GenesisHash) != 32 ||
		len(observation.TrustedCheckpoint.BlockHash) != 32 ||
		len(observation.Contract.Address) != 20 ||
		len(observation.Contract.CodeHash) != 32 ||
		len(observation.ChainContextID) != 32 {
		return fmt.Errorf("%w: invalid publication observation identity", ErrDriverInvalid)
	}
	if err := validateConfigString("publication chain_id", observation.ChainID); err != nil {
		return fmt.Errorf("%w: invalid publication chain_id", ErrDriverInvalid)
	}
	if err := validateConfigString("publication group_id", observation.GroupID); err != nil {
		return fmt.Errorf("%w: invalid publication group_id", ErrDriverInvalid)
	}
	if len(observation.CanonicalPayload) == 0 || len(observation.CanonicalPayload) > MaxPayloadBytes ||
		len(observation.Transaction.EncodedTransaction) == 0 ||
		len(observation.Transaction.EncodedTransaction) > maxRawTransactionBytes ||
		len(observation.Transaction.Signature) != 65 ||
		len(observation.Receipt.NormalizedRPCReceipt) == 0 ||
		len(observation.Receipt.NormalizedRPCReceipt) > maxRawReceiptBytes ||
		len(observation.Event.NormalizedRPCLog) == 0 ||
		len(observation.Event.NormalizedRPCLog) > maxDecodedEventBytes ||
		len(observation.Block.NormalizedRPCHeader) == 0 ||
		len(observation.Block.NormalizedRPCHeader) > maxRawHeaderBytes ||
		len(observation.Receipt.StatusMessage) > maxConfigString {
		return fmt.Errorf("%w: publication observation contains an empty or oversized field", ErrDriverInvalid)
	}
	if err := validateMerklePath("transaction RPC", observation.Receipt.TransactionProofRPC); err != nil {
		return err
	}
	if err := validateMerklePath("receipt RPC", observation.Receipt.ReceiptProofRPC); err != nil {
		return err
	}
	if len(observation.Consensus.Finality.Signatures) == 0 ||
		len(observation.Consensus.Finality.Signatures) > maxCommitSignatures ||
		observation.Consensus.Finality.View != nil ||
		observation.Consensus.Finality.Round != nil {
		return fmt.Errorf("%w: invalid or non-historical consensus observation", ErrDriverInvalid)
	}
	for _, signature := range observation.Consensus.Finality.Signatures {
		if len(signature.ValidatorNodeID) == 0 || len(signature.ValidatorNodeID) > maxConfigString ||
			len(signature.Signature) == 0 || len(signature.Signature) > maxSignatureBytes {
			return fmt.Errorf("%w: invalid consensus signature observation", ErrDriverInvalid)
		}
	}
	payload, err := UnmarshalPayload(observation.CanonicalPayload)
	if err != nil {
		return err
	}
	if len(observation.Transaction.Sender) != 20 ||
		observation.Transaction.ChainID != observation.ChainID ||
		observation.Transaction.GroupID != observation.GroupID ||
		!bytes.Equal(observation.Transaction.To, observation.Contract.Address) ||
		len(observation.Transaction.Input) == 0 ||
		len(observation.Transaction.Input) > MaxPayloadBytes+4 ||
		len(observation.Transaction.TransactionHash) != 32 ||
		observation.Transaction.BlockLimit == 0 ||
		observation.Transaction.SubmittedAtUnixN <= 0 {
		return fmt.Errorf("%w: incomplete transaction observation", ErrIncompleteChainEvidence)
	}
	expectedCallData, err := PublishCallData(payload)
	if err != nil {
		return err
	}
	if !bytes.Equal(observation.Transaction.Input, expectedCallData) {
		return fmt.Errorf("%w: transaction input does not match canonical payload", ErrContractMismatch)
	}
	if observation.Receipt.Status != ReceiptStatusOK ||
		observation.Receipt.BlockNumber == 0 ||
		len(observation.Receipt.BlockHashClaim) != 32 ||
		len(observation.Receipt.ReceiptHashClaim) != 32 ||
		!bytes.Equal(observation.Receipt.TransactionHash, observation.Transaction.TransactionHash) ||
		observation.Receipt.TransactionProofRPC == nil ||
		observation.Receipt.ReceiptProofRPC == nil {
		return fmt.Errorf("%w: incomplete receipt RPC observation", ErrIncompleteChainEvidence)
	}
	event := observation.Event
	if !bytes.Equal(event.ContractAddress, observation.Contract.Address) ||
		!bytes.Equal(event.AnchorID, payload.AnchorID) ||
		!bytes.Equal(event.StreamID, payload.StreamID) ||
		event.TreeSize != payload.TreeSize ||
		!bytes.Equal(event.RootHash, payload.RootHash) ||
		!bytes.Equal(event.SignedSTHDigest, payload.SignedSTHDigest) ||
		!bytes.Equal(event.Publisher, observation.Transaction.Sender) ||
		event.PayloadVersion != payload.Version ||
		event.LogIndex != observation.Receipt.AnchorLogIndex ||
		len(event.NormalizedRPCLog) == 0 {
		return fmt.Errorf("%w: event observation does not match payload", ErrContractMismatch)
	}
	if err := ValidateAnchorRecord(payload, observation.Readback); err != nil {
		return err
	}
	if !bytes.Equal(observation.Readback.Publisher, event.Publisher) {
		return fmt.Errorf("%w: event publisher does not match contract readback", ErrContractMismatch)
	}
	if len(observation.Block.BlockHashClaim) != 32 ||
		observation.Block.BlockNumber == 0 ||
		observation.Receipt.BlockNumber != observation.Block.BlockNumber ||
		!bytes.Equal(observation.Receipt.BlockHashClaim, observation.Block.BlockHashClaim) ||
		observation.Consensus.BlockNumber != observation.Block.BlockNumber ||
		!bytes.Equal(observation.Consensus.BlockHash, observation.Block.BlockHashClaim) {
		return fmt.Errorf("%w: incomplete block/consensus observation", ErrIncompleteChainEvidence)
	}
	return nil
}
