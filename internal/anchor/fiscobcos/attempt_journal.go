package fiscobcos

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
)

const (
	SchemaAttemptJournal   = "trustdb.fisco-bcos-attempt-journal.v1"
	AttemptJournalVersion  = uint64(1)
	MaxAttemptJournalBytes = 16 << 20

	maxJournalArrayElements = 1024
	maxJournalMapPairs      = 64
	maxReceiptAggregate     = 4 << 20
	maxCanonicalLogs        = 512
	ReceiptStatusBlockLimit = int64(10001)
)

var ErrInvalidAttemptJournal = errors.New("invalid FISCO BCOS attempt journal")

type AttemptOutcome string

const (
	AttemptOutcomePrepared                  AttemptOutcome = "prepared"
	AttemptOutcomeSubmitUnknown             AttemptOutcome = "submit_unknown"
	AttemptOutcomeBlockLimitExpired         AttemptOutcome = "block_limit_expired"
	AttemptOutcomeReceiptSuccess            AttemptOutcome = "receipt_success"
	AttemptOutcomeReceiptBlockLimitRejected AttemptOutcome = "receipt_block_limit_rejected"
	AttemptOutcomeReceiptTerminalRejected   AttemptOutcome = "receipt_terminal_rejected"
)

// SignedTransactionAttempt contains the exact transaction bytes prepared
// before a possible external side effect. PreparedAtUnixN is local audit
// metadata and is not used as a chain timestamp.
type SignedTransactionAttempt struct {
	Ordinal                 uint32 `cbor:"ordinal" json:"ordinal"`
	RawCanonicalTransaction []byte `cbor:"raw_canonical_transaction" json:"raw_canonical_transaction"`
	ChainID                 string `cbor:"chain_id" json:"chain_id"`
	GroupID                 string `cbor:"group_id" json:"group_id"`
	To                      []byte `cbor:"to" json:"to"`
	Input                   []byte `cbor:"input" json:"input"`
	Signature               []byte `cbor:"signature" json:"signature"`
	Sender                  []byte `cbor:"sender" json:"sender"`
	TransactionHash         []byte `cbor:"transaction_hash" json:"transaction_hash"`
	BlockLimit              uint64 `cbor:"block_limit" json:"block_limit"`
	PreparedAtUnixN         int64  `cbor:"prepared_at_unix_nano" json:"prepared_at_unix_nano"`
}

// AttemptReceiptObservation preserves the canonical receipt material known
// for one attempt. It is still an untrusted chain observation until the
// dedicated offline verifier recomputes inclusion and finality.
type AttemptReceiptObservation struct {
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
	BlockNumber         uint64              `cbor:"block_number" json:"block_number"`
	BlockHash           []byte              `cbor:"block_hash" json:"block_hash"`
	AnchorLogIndex      uint64              `cbor:"anchor_log_index,omitempty" json:"anchor_log_index,omitempty"`
	DecodedAnchorEvent  []byte              `cbor:"decoded_anchor_event,omitempty" json:"decoded_anchor_event,omitempty"`
	ObservedAtUnixN     int64               `cbor:"observed_at_unix_nano" json:"observed_at_unix_nano"`
}

type SubmissionObservation struct {
	Status          int64  `cbor:"status" json:"status"`
	StatusMessage   string `cbor:"status_message" json:"status_message"`
	ObservedAtUnixN int64  `cbor:"observed_at_unix_nano" json:"observed_at_unix_nano"`
}

type JournalAttempt struct {
	Transaction SignedTransactionAttempt   `cbor:"transaction" json:"transaction"`
	Outcome     AttemptOutcome             `cbor:"outcome" json:"outcome"`
	Submission  *SubmissionObservation     `cbor:"submission,omitempty" json:"submission,omitempty"`
	Receipt     *AttemptReceiptObservation `cbor:"receipt,omitempty" json:"receipt,omitempty"`
}

// AttemptJournal is opaque provider state attached to one scheduler InFlight
// generation. Existing attempts are immutable; a CAS update may only enrich
// the last outcome or append the next prepared transaction.
type AttemptJournal struct {
	SchemaVersion    string           `cbor:"schema_version" json:"schema_version"`
	FormatVersion    uint64           `cbor:"format_version" json:"format_version"`
	Generation       uint64           `cbor:"generation" json:"generation"`
	Revision         uint64           `cbor:"revision" json:"revision"`
	NodeID           string           `cbor:"node_id" json:"node_id"`
	LogID            string           `cbor:"log_id" json:"log_id"`
	SinkName         string           `cbor:"sink_name" json:"sink_name"`
	TreeSize         uint64           `cbor:"tree_size" json:"tree_size"`
	RootHash         []byte           `cbor:"root_hash" json:"root_hash"`
	SignedSTHDigest  []byte           `cbor:"signed_sth_digest" json:"signed_sth_digest"`
	CryptoMode       CryptoMode       `cbor:"crypto_mode" json:"crypto_mode"`
	ChainID          string           `cbor:"chain_id" json:"chain_id"`
	GroupID          string           `cbor:"group_id" json:"group_id"`
	Contract         ContractBinding  `cbor:"contract" json:"contract"`
	ChainContextID   []byte           `cbor:"chain_context_id" json:"chain_context_id"`
	CanonicalPayload []byte           `cbor:"canonical_payload" json:"canonical_payload"`
	Attempts         []JournalAttempt `cbor:"attempts" json:"attempts"`
}

func MarshalAttemptJournal(journal AttemptJournal) ([]byte, error) {
	if err := ValidateAttemptJournal(journal); err != nil {
		return nil, err
	}
	data, err := cborx.Marshal(journal)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidAttemptJournal, err)
	}
	if len(data) > MaxAttemptJournalBytes {
		return nil, fmt.Errorf("%w: encoded size %d exceeds %d", ErrInvalidAttemptJournal, len(data), MaxAttemptJournalBytes)
	}
	return data, nil
}

func UnmarshalAttemptJournal(data []byte) (AttemptJournal, error) {
	var journal AttemptJournal
	if err := cborx.UnmarshalLimits(
		data,
		&journal,
		MaxAttemptJournalBytes,
		maxJournalArrayElements,
		maxJournalMapPairs,
	); err != nil {
		return AttemptJournal{}, fmt.Errorf("%w: decode: %v", ErrInvalidAttemptJournal, err)
	}
	if err := ValidateAttemptJournal(journal); err != nil {
		return AttemptJournal{}, err
	}
	canonical, err := cborx.Marshal(journal)
	if err != nil {
		return AttemptJournal{}, fmt.Errorf("%w: canonicalize: %v", ErrInvalidAttemptJournal, err)
	}
	if !bytes.Equal(canonical, data) {
		return AttemptJournal{}, fmt.Errorf("%w: encoding is not canonical CBOR", ErrInvalidAttemptJournal)
	}
	return journal, nil
}

func ValidateAttemptJournal(journal AttemptJournal) error {
	if journal.SchemaVersion != SchemaAttemptJournal ||
		journal.FormatVersion != AttemptJournalVersion ||
		journal.Generation == 0 || journal.Revision == 0 ||
		journal.NodeID == "" || journal.LogID == "" ||
		journal.SinkName != SinkName || journal.TreeSize == 0 ||
		len(journal.RootHash) != identifierBytes ||
		len(journal.SignedSTHDigest) != identifierBytes ||
		journal.CryptoMode != CryptoModeStandard ||
		len(journal.ChainContextID) != identifierBytes {
		return fmt.Errorf("%w: invalid identity or version", ErrInvalidAttemptJournal)
	}
	if err := validateConfigString("journal node_id", journal.NodeID); err != nil {
		return fmt.Errorf("%w: invalid node_id", ErrInvalidAttemptJournal)
	}
	if err := validateConfigString("journal log_id", journal.LogID); err != nil {
		return fmt.Errorf("%w: invalid log_id", ErrInvalidAttemptJournal)
	}
	if err := validateConfigString("journal chain_id", journal.ChainID); err != nil {
		return fmt.Errorf("%w: invalid chain_id", ErrInvalidAttemptJournal)
	}
	if err := validateConfigString("journal group_id", journal.GroupID); err != nil {
		return fmt.Errorf("%w: invalid group_id", ErrInvalidAttemptJournal)
	}
	if len(journal.Contract.Address) != 20 ||
		len(journal.Contract.CodeHash) != identifierBytes ||
		journal.Contract.ProtocolVersion == "" ||
		journal.Contract.EventSignature == "" {
		return fmt.Errorf("%w: invalid contract binding", ErrInvalidAttemptJournal)
	}
	payload, err := UnmarshalPayload(journal.CanonicalPayload)
	if err != nil {
		return fmt.Errorf("%w: canonical payload: %v", ErrInvalidAttemptJournal, err)
	}
	if payload.NodeID != journal.NodeID || payload.LogID != journal.LogID ||
		payload.SinkName != journal.SinkName || payload.TreeSize != journal.TreeSize ||
		!bytes.Equal(payload.RootHash, journal.RootHash) ||
		!bytes.Equal(payload.SignedSTHDigest, journal.SignedSTHDigest) {
		return fmt.Errorf("%w: payload does not match journal target", ErrInvalidAttemptJournal)
	}
	if len(journal.Attempts) == 0 || len(journal.Attempts) > maxTransactionAttempts {
		return fmt.Errorf("%w: attempt count=%d", ErrInvalidAttemptJournal, len(journal.Attempts))
	}
	seenHashes := make(map[string]struct{}, len(journal.Attempts))
	var previousBlockLimit uint64
	for index := range journal.Attempts {
		attempt := journal.Attempts[index]
		if err := validateJournalAttempt(attempt, uint32(index+1), journal); err != nil {
			return err
		}
		if index < len(journal.Attempts)-1 &&
			attempt.Outcome != AttemptOutcomeReceiptBlockLimitRejected &&
			attempt.Outcome != AttemptOutcomeBlockLimitExpired {
			return fmt.Errorf("%w: non-final attempt %d is not closed by block limit", ErrInvalidAttemptJournal, index+1)
		}
		hashKey := string(attempt.Transaction.TransactionHash)
		if _, exists := seenHashes[hashKey]; exists {
			return fmt.Errorf("%w: duplicate transaction hash", ErrInvalidAttemptJournal)
		}
		seenHashes[hashKey] = struct{}{}
		if index > 0 && attempt.Transaction.BlockLimit <= previousBlockLimit {
			return fmt.Errorf("%w: block limits do not strictly increase", ErrInvalidAttemptJournal)
		}
		previousBlockLimit = attempt.Transaction.BlockLimit
	}
	return nil
}

func ValidateAttemptJournalBinding(journal AttemptJournal, generation uint64, sth model.SignedTreeHead, config TrustConfig) error {
	if err := ValidateAttemptJournal(journal); err != nil {
		return err
	}
	if generation == 0 || journal.Generation != generation ||
		journal.NodeID != sth.NodeID || journal.LogID != sth.LogID ||
		journal.TreeSize != sth.TreeSize || !bytes.Equal(journal.RootHash, sth.RootHash) {
		return fmt.Errorf("%w: journal does not match immutable InFlight target", ErrInvalidAttemptJournal)
	}
	payload, err := UnmarshalPayload(journal.CanonicalPayload)
	if err != nil {
		return err
	}
	if err := ValidatePayloadAgainstSTH(payload, sth); err != nil {
		return fmt.Errorf("%w: payload does not match Signed STH: %v", ErrInvalidAttemptJournal, err)
	}
	canonicalConfig, err := canonicalTrustConfig(config)
	if err != nil {
		return err
	}
	contextID, err := ChainContextID(canonicalConfig)
	if err != nil {
		return err
	}
	if journal.CryptoMode != canonicalConfig.CryptoMode ||
		journal.ChainID != canonicalConfig.ChainID ||
		journal.GroupID != canonicalConfig.GroupID ||
		!sameContractBinding(journal.Contract, canonicalConfig.Contract) ||
		!bytes.Equal(journal.ChainContextID, contextID) {
		return fmt.Errorf("%w: journal does not match local chain trust", ErrInvalidAttemptJournal)
	}
	return nil
}

// ValidateAttemptJournalTransition enforces append-only evidence and a
// revision increment of exactly one. It is used before every provider-state
// compare-and-swap and again by backend contract tests.
func ValidateAttemptJournalTransition(previous, next AttemptJournal) error {
	if err := ValidateAttemptJournal(previous); err != nil {
		return err
	}
	if err := ValidateAttemptJournal(next); err != nil {
		return err
	}
	if next.Revision != previous.Revision+1 || !sameJournalIdentity(previous, next) {
		return fmt.Errorf("%w: revision or immutable identity changed", ErrInvalidAttemptJournal)
	}
	if len(next.Attempts) < len(previous.Attempts) || len(next.Attempts) > len(previous.Attempts)+1 {
		return fmt.Errorf("%w: attempts were removed or appended in bulk", ErrInvalidAttemptJournal)
	}
	unchanged := len(previous.Attempts)
	if len(next.Attempts) == len(previous.Attempts) {
		unchanged--
	}
	for index := 0; index < unchanged; index++ {
		if !sameJournalAttempt(previous.Attempts[index], next.Attempts[index]) {
			return fmt.Errorf("%w: immutable attempt %d changed", ErrInvalidAttemptJournal, index+1)
		}
	}
	if len(next.Attempts) == len(previous.Attempts)+1 {
		last := previous.Attempts[len(previous.Attempts)-1]
		if last.Outcome != AttemptOutcomeReceiptBlockLimitRejected &&
			last.Outcome != AttemptOutcomeBlockLimitExpired {
			return fmt.Errorf("%w: next attempt is not authorized by block limit outcome", ErrInvalidAttemptJournal)
		}
		if next.Attempts[len(next.Attempts)-1].Outcome != AttemptOutcomePrepared {
			return fmt.Errorf("%w: appended attempt is not prepared", ErrInvalidAttemptJournal)
		}
		return nil
	}
	before := previous.Attempts[len(previous.Attempts)-1]
	after := next.Attempts[len(next.Attempts)-1]
	if !sameSignedTransaction(before.Transaction, after.Transaction) ||
		!validOutcomeTransition(before.Outcome, after.Outcome) {
		return fmt.Errorf("%w: invalid attempt outcome transition", ErrInvalidAttemptJournal)
	}
	return nil
}

func validateJournalAttempt(attempt JournalAttempt, ordinal uint32, journal AttemptJournal) error {
	transaction := attempt.Transaction
	if transaction.Ordinal != ordinal ||
		len(transaction.RawCanonicalTransaction) == 0 ||
		len(transaction.RawCanonicalTransaction) > maxRawTransactionBytes ||
		transaction.ChainID != journal.ChainID ||
		transaction.GroupID != journal.GroupID ||
		!bytes.Equal(transaction.To, journal.Contract.Address) ||
		len(transaction.Input) == 0 || len(transaction.Input) > MaxPayloadBytes+4 ||
		len(transaction.Signature) != 65 ||
		len(transaction.Sender) != 20 ||
		len(transaction.TransactionHash) != identifierBytes ||
		transaction.BlockLimit == 0 || transaction.PreparedAtUnixN <= 0 {
		return fmt.Errorf("%w: transaction attempt %d is incomplete or oversized", ErrInvalidAttemptJournal, ordinal)
	}
	payload, _ := UnmarshalPayload(journal.CanonicalPayload)
	callData, err := PublishCallData(payload)
	if err != nil || !bytes.Equal(transaction.Input, callData) {
		return fmt.Errorf("%w: transaction attempt %d input does not match payload", ErrInvalidAttemptJournal, ordinal)
	}
	switch attempt.Outcome {
	case AttemptOutcomePrepared, AttemptOutcomeSubmitUnknown, AttemptOutcomeBlockLimitExpired:
		if attempt.Submission != nil || attempt.Receipt != nil {
			return fmt.Errorf("%w: outcome %q must not contain submission or receipt evidence", ErrInvalidAttemptJournal, attempt.Outcome)
		}
	case AttemptOutcomeReceiptSuccess:
		if attempt.Submission != nil {
			if err := validateSubmissionObservation(attempt.Submission, ReceiptStatusOK); err != nil {
				return err
			}
		}
		if err := validateAttemptReceipt(attempt.Outcome, attempt.Receipt, transaction.TransactionHash); err != nil {
			return err
		}
	case AttemptOutcomeReceiptBlockLimitRejected:
		if attempt.Receipt != nil {
			return fmt.Errorf("%w: block-limit rejection must not claim an included receipt", ErrInvalidAttemptJournal)
		}
		if err := validateSubmissionObservation(attempt.Submission, ReceiptStatusBlockLimit); err != nil {
			return err
		}
	case AttemptOutcomeReceiptTerminalRejected:
		if attempt.Receipt != nil {
			return fmt.Errorf("%w: terminal rejection must not claim an included receipt", ErrInvalidAttemptJournal)
		}
		if err := validateSubmissionObservation(attempt.Submission, -1); err != nil {
			return err
		}
		if attempt.Submission.Status == ReceiptStatusOK ||
			attempt.Submission.Status == ReceiptStatusBlockLimit {
			return fmt.Errorf("%w: terminal submission status=%d is not terminal", ErrInvalidAttemptJournal, attempt.Submission.Status)
		}
	default:
		return fmt.Errorf("%w: unknown attempt outcome %q", ErrInvalidAttemptJournal, attempt.Outcome)
	}
	return nil
}

func validateSubmissionObservation(observation *SubmissionObservation, expectedStatus int64) error {
	if observation == nil ||
		len(observation.StatusMessage) == 0 ||
		len(observation.StatusMessage) > maxConfigString ||
		observation.ObservedAtUnixN <= 0 {
		return fmt.Errorf("%w: submission observation is incomplete or oversized", ErrInvalidAttemptJournal)
	}
	if expectedStatus >= 0 && observation.Status != expectedStatus {
		return fmt.Errorf("%w: submission observation status=%d, want %d", ErrInvalidAttemptJournal, observation.Status, expectedStatus)
	}
	return nil
}

func validateAttemptReceipt(outcome AttemptOutcome, receipt *AttemptReceiptObservation, transactionHash []byte) error {
	if receipt == nil ||
		len(receipt.RawCanonicalReceipt) == 0 ||
		len(receipt.RawCanonicalReceipt) > maxRawReceiptBytes ||
		len(receipt.StatusMessage) == 0 || len(receipt.StatusMessage) > maxConfigString ||
		len(receipt.ReceiptHash) != identifierBytes ||
		!bytes.Equal(receipt.TransactionHash, transactionHash) ||
		len(receipt.BlockHash) != identifierBytes ||
		receipt.BlockNumber == 0 || receipt.ObservedAtUnixN <= 0 ||
		receipt.TransactionProof == nil || receipt.ReceiptProof == nil ||
		len(receipt.CanonicalLogs) > maxCanonicalLogs {
		return fmt.Errorf("%w: receipt observation is incomplete or oversized", ErrInvalidAttemptJournal)
	}
	canonicalReceipt, canonicalLogs, err := MarshalNativeReceiptPreimage(receipt.Fields)
	if err != nil ||
		!bytes.Equal(canonicalReceipt, receipt.RawCanonicalReceipt) ||
		!sameEvidenceByteSlices(canonicalLogs, receipt.CanonicalLogs) ||
		int64(receipt.Fields.Status) != receipt.Status ||
		receipt.Fields.BlockNumber < 0 ||
		uint64(receipt.Fields.BlockNumber) != receipt.BlockNumber {
		return fmt.Errorf("%w: receipt fields do not reconstruct exact consensus preimage", ErrInvalidAttemptJournal)
	}
	receiptHash, err := HashNativeEvidence(HashKeccak256, canonicalReceipt)
	if err != nil || !bytes.Equal(receiptHash, receipt.ReceiptHash) {
		return fmt.Errorf("%w: receipt consensus hash mismatch", ErrInvalidAttemptJournal)
	}
	switch outcome {
	case AttemptOutcomeReceiptSuccess:
		if receipt.Status != ReceiptStatusOK ||
			len(receipt.CanonicalLogs) == 0 ||
			receipt.AnchorLogIndex >= uint64(len(receipt.CanonicalLogs)) ||
			len(receipt.DecodedAnchorEvent) == 0 ||
			len(receipt.DecodedAnchorEvent) > maxDecodedEventBytes {
			return fmt.Errorf("%w: successful receipt lacks exact event", ErrInvalidAttemptJournal)
		}
	}
	if err := validateMerklePath("journal transaction", receipt.TransactionProof); err != nil {
		return err
	}
	if err := validateMerklePath("journal receipt", receipt.ReceiptProof); err != nil {
		return err
	}
	total := len(receipt.RawCanonicalReceipt) + len(receipt.DecodedAnchorEvent)
	for _, log := range receipt.CanonicalLogs {
		if len(log) == 0 || len(log) > maxProofNodeBytes {
			return fmt.Errorf("%w: canonical receipt log is empty or oversized", ErrInvalidAttemptJournal)
		}
		total += len(log)
	}
	for _, path := range [][][]byte{receipt.TransactionProof, receipt.ReceiptProof} {
		for _, node := range path {
			total += len(node)
		}
	}
	if total > maxReceiptAggregate {
		return fmt.Errorf("%w: receipt/log/proof aggregate exceeds %d", ErrInvalidAttemptJournal, maxReceiptAggregate)
	}
	return nil
}

func sameJournalIdentity(left, right AttemptJournal) bool {
	return left.SchemaVersion == right.SchemaVersion &&
		left.FormatVersion == right.FormatVersion &&
		left.Generation == right.Generation &&
		left.NodeID == right.NodeID &&
		left.LogID == right.LogID &&
		left.SinkName == right.SinkName &&
		left.TreeSize == right.TreeSize &&
		bytes.Equal(left.RootHash, right.RootHash) &&
		bytes.Equal(left.SignedSTHDigest, right.SignedSTHDigest) &&
		left.CryptoMode == right.CryptoMode &&
		left.ChainID == right.ChainID &&
		left.GroupID == right.GroupID &&
		sameContractBinding(left.Contract, right.Contract) &&
		bytes.Equal(left.ChainContextID, right.ChainContextID) &&
		bytes.Equal(left.CanonicalPayload, right.CanonicalPayload)
}

func sameJournalAttempt(left, right JournalAttempt) bool {
	leftBytes, leftErr := cborx.Marshal(left)
	rightBytes, rightErr := cborx.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func sameSignedTransaction(left, right SignedTransactionAttempt) bool {
	leftBytes, leftErr := cborx.Marshal(left)
	rightBytes, rightErr := cborx.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func validOutcomeTransition(previous, next AttemptOutcome) bool {
	switch previous {
	case AttemptOutcomePrepared:
		return next == AttemptOutcomeSubmitUnknown ||
			next == AttemptOutcomeBlockLimitExpired ||
			next == AttemptOutcomeReceiptSuccess ||
			next == AttemptOutcomeReceiptBlockLimitRejected ||
			next == AttemptOutcomeReceiptTerminalRejected
	case AttemptOutcomeSubmitUnknown:
		return next == AttemptOutcomeBlockLimitExpired ||
			next == AttemptOutcomeReceiptSuccess ||
			next == AttemptOutcomeReceiptBlockLimitRejected ||
			next == AttemptOutcomeReceiptTerminalRejected
	default:
		return false
	}
}
