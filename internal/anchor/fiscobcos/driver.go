package fiscobcos

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

const (
	StandardSDKVersion = "fisco-bcos-go-sdk-v3.0.2+c-sdk-v3.6.0@53240138c396c10cb0e1a2b7b4d5c0cdaa0ac539"
	ReceiptStatusOK    = 0
)

var (
	ErrDriverInvalid                     = errors.New("invalid FISCO BCOS driver response")
	ErrWrongNetwork                      = errors.New("FISCO BCOS wrong network")
	ErrStaleEndpoint                     = errors.New("FISCO BCOS stale endpoint")
	ErrEndpointDisagreement              = errors.New("FISCO BCOS endpoint disagreement")
	ErrContractMismatch                  = errors.New("FISCO BCOS contract mismatch")
	ErrUnsupportedSDK                    = errors.New("FISCO BCOS SDK is unsupported")
	ErrInvalidReceiptStatus              = errors.New("FISCO BCOS receipt status is invalid")
	ErrIncompleteChainEvidence           = errors.New("FISCO BCOS chain evidence is incomplete")
	ErrExistingAnchorEvidenceUnavailable = errors.New("existing FISCO BCOS anchor requires immutable transaction evidence recovery")
)

// ReceiptStatusDisposition is the pinned FISCO BCOS v3.16.3 interpretation of
// a non-success transaction receipt. It is deliberately more precise than the
// scheduler's three failure classes so block-limit refresh and deterministic
// duplicate lookup can be implemented by #470 without changing this boundary.
type ReceiptStatusDisposition string

const (
	ReceiptStatusSucceeded  ReceiptStatusDisposition = "succeeded"
	ReceiptStatusPermanent  ReceiptStatusDisposition = "permanent"
	ReceiptStatusRetryable  ReceiptStatusDisposition = "retryable"
	ReceiptStatusBlockLimit ReceiptStatusDisposition = "block_limit"
	ReceiptStatusDuplicate  ReceiptStatusDisposition = "duplicate"
	ReceiptStatusAmbiguous  ReceiptStatusDisposition = "ambiguous"
)

type ReceiptStatusError struct {
	Status      int
	Disposition ReceiptStatusDisposition
}

func (e *ReceiptStatusError) Error() string {
	if e == nil {
		return ErrInvalidReceiptStatus.Error()
	}
	return fmt.Sprintf("%s: status=%d disposition=%s", ErrInvalidReceiptStatus, e.Status, e.Disposition)
}

func (*ReceiptStatusError) Unwrap() error { return ErrInvalidReceiptStatus }

func NewReceiptStatusError(status int) *ReceiptStatusError {
	return &ReceiptStatusError{Status: status, Disposition: ClassifyReceiptStatus(status)}
}

func (e *ReceiptStatusError) FailureClass() FailureClass {
	if e != nil && e.Disposition == ReceiptStatusPermanent {
		return FailurePermanent
	}
	if e != nil && (e.Disposition == ReceiptStatusRetryable || e.Disposition == ReceiptStatusBlockLimit) {
		return FailureTransient
	}
	return FailureAmbiguous
}

// ClassifyReceiptStatus uses the receipt codes pinned by Go SDK v3.0.2 and the
// FISCO BCOS v3.16.3 node baseline. Unknown/reserved codes remain ambiguous.
func ClassifyReceiptStatus(status int) ReceiptStatusDisposition {
	switch status {
	case 0:
		return ReceiptStatusSucceeded
	case 1, 10010:
		// "unknown" and transaction-pool timeout do not prove whether the
		// transaction was accepted or propagated.
		return ReceiptStatusAmbiguous
	case 10001:
		return ReceiptStatusBlockLimit
	case 10002:
		return ReceiptStatusRetryable
	case 10000, 10004, 10005, 10011:
		// Nonce/duplicate responses require deterministic lookup of the exact
		// immutable attempt before any replacement is permitted (#470).
		return ReceiptStatusDuplicate
	case 2, 7,
		10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
		32, 33, 34, 35,
		10003, 10006, 10007, 10008, 10009:
		return ReceiptStatusPermanent
	default:
		return ReceiptStatusAmbiguous
	}
}

// FailureClass is intentionally small and stable. The anchor worker maps
// permanent failures to anchor.ErrPermanent and retries transient failures
// without replacing its immutable InFlight STH.
type FailureClass string

const (
	FailurePermanent FailureClass = "permanent"
	FailureTransient FailureClass = "transient"
	FailureAmbiguous FailureClass = "ambiguous"
)

// DriverError carries a bounded classification without exposing certificate
// paths, account references, private material, or provider error payloads.
type DriverError struct {
	Operation string
	Endpoint  string
	Class     FailureClass
	Kind      error
}

func (e *DriverError) Error() string {
	if e == nil {
		return "FISCO BCOS driver error"
	}
	if e.Endpoint == "" {
		return fmt.Sprintf("FISCO BCOS %s failed: %v", e.Operation, e.Kind)
	}
	return fmt.Sprintf("FISCO BCOS %s failed for endpoint %q: %v", e.Operation, e.Endpoint, e.Kind)
}

func (e *DriverError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Kind
}

func IsPermanentDriverError(err error) bool {
	var driverErr *DriverError
	return errors.As(err, &driverErr) && driverErr.Class == FailurePermanent
}

// ChainProbe is the minimum startup/readiness identity returned by one
// independently configured endpoint. All byte fields are fixed 32-byte
// identities. Height is compared across the quorum before any side effect.
type ChainProbe struct {
	Endpoint         string
	SDKVersion       string
	CryptoMode       CryptoMode
	ChainID          string
	GroupID          string
	GenesisHash      []byte
	CheckpointHash   []byte
	Height           uint64
	ContractCodeHash []byte
}

// AnchorRecord mirrors TrustDBAnchorV1.AnchorRecord. It is a read-only chain
// observation and is not itself an offline proof.
type AnchorRecord struct {
	StreamID        []byte `cbor:"stream_id" json:"stream_id"`
	TreeSize        uint64 `cbor:"tree_size" json:"tree_size"`
	RootHash        []byte `cbor:"root_hash" json:"root_hash"`
	SignedSTHDigest []byte `cbor:"signed_sth_digest" json:"signed_sth_digest"`
	Publisher       []byte `cbor:"publisher" json:"publisher"`
	PayloadVersion  uint16 `cbor:"payload_version" json:"payload_version"`
	Exists          bool   `cbor:"exists" json:"exists"`
}

// SubmitRequest is immutable for one scheduler attempt. CanonicalPayload is
// retained so fake, native, or sidecar drivers cannot infer TrustDB fields.
type SubmitRequest struct {
	Payload          AnchorPayload
	CanonicalPayload []byte
}

type TransactionSubmission struct {
	EncodedTransaction []byte `cbor:"encoded_transaction" json:"encoded_transaction"`
	ChainID            string `cbor:"chain_id" json:"chain_id"`
	GroupID            string `cbor:"group_id" json:"group_id"`
	To                 []byte `cbor:"to" json:"to"`
	Input              []byte `cbor:"input" json:"input"`
	Signature          []byte `cbor:"signature" json:"signature"`
	Sender             []byte `cbor:"sender" json:"sender"`
	TransactionHash    []byte `cbor:"transaction_hash" json:"transaction_hash"`
	BlockLimit         uint64 `cbor:"block_limit" json:"block_limit"`
	SubmittedAtUnixN   int64  `cbor:"submitted_at_unix_nano" json:"submitted_at_unix_nano"`
}

type Submission struct {
	Attempt TransactionSubmission
}

type AnchorPublishedEvent struct {
	ContractAddress  []byte `cbor:"contract_address" json:"contract_address"`
	AnchorID         []byte `cbor:"anchor_id" json:"anchor_id"`
	StreamID         []byte `cbor:"stream_id" json:"stream_id"`
	TreeSize         uint64 `cbor:"tree_size" json:"tree_size"`
	RootHash         []byte `cbor:"root_hash" json:"root_hash"`
	SignedSTHDigest  []byte `cbor:"signed_sth_digest" json:"signed_sth_digest"`
	Publisher        []byte `cbor:"publisher" json:"publisher"`
	PayloadVersion   uint16 `cbor:"payload_version" json:"payload_version"`
	LogIndex         uint64 `cbor:"log_index" json:"log_index"`
	NormalizedRPCLog []byte `cbor:"normalized_rpc_log" json:"normalized_rpc_log"`
}

type ReceiptRPCObservation struct {
	NormalizedRPCReceipt []byte   `cbor:"normalized_rpc_receipt" json:"normalized_rpc_receipt"`
	Status               int      `cbor:"status" json:"status"`
	StatusMessage        string   `cbor:"status_message" json:"status_message"`
	BlockNumber          uint64   `cbor:"block_number" json:"block_number"`
	BlockHashClaim       []byte   `cbor:"block_hash_claim" json:"block_hash_claim"`
	ReceiptHashClaim     []byte   `cbor:"receipt_hash_claim" json:"receipt_hash_claim"`
	TransactionHash      []byte   `cbor:"transaction_hash" json:"transaction_hash"`
	TransactionIndex     uint64   `cbor:"transaction_index" json:"transaction_index"`
	TransactionProofRPC  [][]byte `cbor:"transaction_proof_rpc" json:"transaction_proof_rpc"`
	ReceiptIndex         uint64   `cbor:"receipt_index" json:"receipt_index"`
	ReceiptProofRPC      [][]byte `cbor:"receipt_proof_rpc" json:"receipt_proof_rpc"`
	AnchorLogIndex       uint64   `cbor:"anchor_log_index" json:"anchor_log_index"`
}

// ReceiptWithProof is deliberately named to exclude receipt-only APIs. A
// driver must return both transaction and receipt proof fields, the decoded
// exact contract record, and the containing block identity.
type ReceiptWithProof struct {
	Status        int
	StatusMessage string
	BlockNumber   uint64
	BlockHash     []byte
	Record        AnchorRecord
	Event         AnchorPublishedEvent
	Observation   ReceiptRPCObservation
}

type BlockRPCObservation struct {
	NormalizedRPCHeader []byte `cbor:"normalized_rpc_header" json:"normalized_rpc_header"`
	BlockHashClaim      []byte `cbor:"block_hash_claim" json:"block_hash_claim"`
	BlockNumber         uint64 `cbor:"block_number" json:"block_number"`
}

type BlockHeader struct {
	Observation BlockRPCObservation
}

// ConsensusFinalityObservation contains only values bound to the requested
// historical block. FISCO BCOS exposes the current PBFT view through a
// separate latest-state RPC; it is not a historical block-header field.
// Nil View and Round values explicitly record that the pinned standard SDK
// cannot recover those historical values without inventing a binding.
type ConsensusFinalityObservation struct {
	View       *uint64           `cbor:"view" json:"view"`
	Round      *uint64           `cbor:"round" json:"round"`
	Signatures []CommitSignature `cbor:"signatures" json:"signatures"`
}

type ConsensusSnapshot struct {
	BlockNumber uint64                       `cbor:"block_number" json:"block_number"`
	BlockHash   []byte                       `cbor:"block_hash" json:"block_hash"`
	Finality    ConsensusFinalityObservation `cbor:"finality" json:"finality"`
}

// Driver is the complete network boundary used by the standard-crypto sink.
// Implementations may wrap the pinned Go SDK, but no SDK types cross this
// interface and no method claims that returned evidence is offline-valid.
type Driver interface {
	Endpoint() string
	ProbeChain(context.Context) (ChainProbe, error)
	SubmitAnchor(context.Context, SubmitRequest) (Submission, error)
	ReadAnchor(context.Context, []byte) (AnchorRecord, error)
	GetReceiptWithProof(context.Context, TransactionSubmission) (ReceiptWithProof, error)
	GetBlockHeader(context.Context, uint64) (BlockHeader, error)
	GetConsensusSnapshot(context.Context, uint64) (ConsensusSnapshot, error)
	Close() error
}

func ValidateAnchorRecord(payload AnchorPayload, record AnchorRecord) error {
	if !record.Exists {
		return fmt.Errorf("%w: anchor record is absent", ErrDriverInvalid)
	}
	if !bytes.Equal(record.StreamID, payload.StreamID) ||
		record.TreeSize != payload.TreeSize ||
		!bytes.Equal(record.RootHash, payload.RootHash) ||
		!bytes.Equal(record.SignedSTHDigest, payload.SignedSTHDigest) ||
		record.PayloadVersion != payload.Version ||
		len(record.Publisher) != 20 {
		return fmt.Errorf("%w: on-chain record does not exactly match canonical payload", ErrContractMismatch)
	}
	return nil
}

func validateProbeAgainstTrust(probe ChainProbe, config TrustConfig) error {
	if probe.SDKVersion != StandardSDKVersion {
		return &DriverError{Operation: "probe", Endpoint: probe.Endpoint, Class: FailurePermanent, Kind: ErrUnsupportedSDK}
	}
	if probe.CryptoMode != CryptoModeStandard {
		return &DriverError{Operation: "probe", Endpoint: probe.Endpoint, Class: FailurePermanent, Kind: ErrWrongNetwork}
	}
	if probe.ChainID != config.ChainID || probe.GroupID != config.GroupID ||
		!bytes.Equal(probe.GenesisHash, config.GenesisHash) ||
		!bytes.Equal(probe.CheckpointHash, config.TrustedCheckpoint.BlockHash) {
		return &DriverError{Operation: "probe", Endpoint: probe.Endpoint, Class: FailurePermanent, Kind: ErrWrongNetwork}
	}
	if probe.Height < config.TrustedCheckpoint.BlockNumber {
		return &DriverError{Operation: "probe", Endpoint: probe.Endpoint, Class: FailureTransient, Kind: ErrStaleEndpoint}
	}
	if !bytes.Equal(probe.ContractCodeHash, config.Contract.CodeHash) {
		return &DriverError{Operation: "probe", Endpoint: probe.Endpoint, Class: FailurePermanent, Kind: ErrContractMismatch}
	}
	return nil
}

func probesAgree(left, right ChainProbe) bool {
	return left.SDKVersion == right.SDKVersion &&
		left.CryptoMode == right.CryptoMode &&
		left.ChainID == right.ChainID &&
		left.GroupID == right.GroupID &&
		bytes.Equal(left.GenesisHash, right.GenesisHash) &&
		bytes.Equal(left.CheckpointHash, right.CheckpointHash) &&
		left.Height == right.Height &&
		bytes.Equal(left.ContractCodeHash, right.ContractCodeHash)
}
