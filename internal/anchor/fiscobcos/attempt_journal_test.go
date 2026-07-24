package fiscobcos

import (
	"bytes"
	"testing"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
)

func TestAttemptJournalCanonicalRoundTripAndBinding(t *testing.T) {
	t.Parallel()

	sth, config, journal := testAttemptJournal(t)
	data, err := MarshalAttemptJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalAttemptJournal(data)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := MarshalAttemptJournal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, roundTrip) {
		t.Fatal("attempt journal did not round-trip byte-identically")
	}
	if err := ValidateAttemptJournalBinding(decoded, journal.Generation, sth, config); err != nil {
		t.Fatalf("ValidateAttemptJournalBinding() = %v", err)
	}

	changed := sth
	changed.TimestampUnixN++
	if err := ValidateAttemptJournalBinding(decoded, journal.Generation, changed, config); err == nil {
		t.Fatal("journal accepted a different immutable Signed STH")
	}
	wrongTrust := config
	wrongTrust.GroupID = "group-other"
	if err := ValidateAttemptJournalBinding(decoded, journal.Generation, sth, wrongTrust); err == nil {
		t.Fatal("journal accepted a different local chain context")
	}
}

func TestAttemptJournalTransitionsAreAppendOnly(t *testing.T) {
	t.Parallel()

	_, _, prepared := testAttemptJournal(t)
	unknown := cloneAttemptJournal(t, prepared)
	unknown.Revision++
	unknown.Attempts[0].Outcome = AttemptOutcomeSubmitUnknown
	if err := ValidateAttemptJournalTransition(prepared, unknown); err != nil {
		t.Fatalf("prepared -> unknown: %v", err)
	}

	expired := cloneAttemptJournal(t, unknown)
	expired.Revision++
	expired.Attempts[0].Outcome = AttemptOutcomeBlockLimitExpired
	if err := ValidateAttemptJournalTransition(unknown, expired); err != nil {
		t.Fatalf("unknown -> block limit expired: %v", err)
	}

	next := cloneAttemptJournal(t, expired)
	next.Revision++
	next.Attempts = append(next.Attempts, JournalAttempt{
		Transaction: testSignedTransaction(t, next, 2, 9000, 0x80),
		Outcome:     AttemptOutcomePrepared,
	})
	if err := ValidateAttemptJournalTransition(expired, next); err != nil {
		t.Fatalf("append after block limit expiry: %v", err)
	}

	tampered := cloneAttemptJournal(t, unknown)
	tampered.Revision++
	tampered.Attempts[0].Transaction.Signature[0] ^= 0xff
	tampered.Attempts[0].Outcome = AttemptOutcomeBlockLimitExpired
	if err := ValidateAttemptJournalTransition(unknown, tampered); err == nil {
		t.Fatal("transition changed immutable signed transaction")
	}

	unauthorized := cloneAttemptJournal(t, unknown)
	unauthorized.Revision++
	unauthorized.Attempts = append(unauthorized.Attempts, JournalAttempt{
		Transaction: testSignedTransaction(t, unauthorized, 2, 9000, 0x90),
		Outcome:     AttemptOutcomePrepared,
	})
	if err := ValidateAttemptJournalTransition(unknown, unauthorized); err == nil {
		t.Fatal("unknown outcome authorized a replacement transaction")
	}
}

func TestAttemptJournalPreservesSuccessfulReceiptMaterial(t *testing.T) {
	t.Parallel()

	_, _, journal := testAttemptJournal(t)
	success := cloneAttemptJournal(t, journal)
	success.Revision++
	success.Attempts[0].Outcome = AttemptOutcomeReceiptSuccess
	success.Attempts[0].Receipt = testAttemptReceipt(success.Attempts[0].Transaction.TransactionHash, ReceiptStatusOK)
	if err := ValidateAttemptJournalTransition(journal, success); err != nil {
		t.Fatalf("prepared -> successful receipt: %v", err)
	}
	data, err := MarshalAttemptJournal(success)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalAttemptJournal(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Attempts[0].Receipt.RawCanonicalReceipt, success.Attempts[0].Receipt.RawCanonicalReceipt) ||
		!bytes.Equal(decoded.Attempts[0].Receipt.CanonicalLogs[0], success.Attempts[0].Receipt.CanonicalLogs[0]) ||
		!bytes.Equal(decoded.Attempts[0].Receipt.DecodedAnchorEvent, []byte("canonical-decoded-event")) {
		t.Fatal("successful receipt material changed during round trip")
	}
}

func TestAttemptJournalPreservesIncludedTerminalReceipt(t *testing.T) {
	t.Parallel()
	_, _, journal := testAttemptJournal(t)
	terminal := cloneAttemptJournal(t, journal)
	terminal.Revision++
	terminal.Attempts[0].Outcome = AttemptOutcomeReceiptTerminalRejected
	terminal.Attempts[0].Submission = &SubmissionObservation{
		Status: 1, StatusMessage: "reverted", ObservedAtUnixN: 3,
	}
	terminal.Attempts[0].Receipt = testAttemptReceipt(terminal.Attempts[0].Transaction.TransactionHash, 1)
	terminal.Attempts[0].Receipt.StatusMessage = "reverted"
	terminal.Attempts[0].Receipt.DecodedAnchorEvent = nil
	if err := ValidateAttemptJournalTransition(journal, terminal); err != nil {
		t.Fatalf("prepared -> included terminal receipt: %v", err)
	}
	data, err := MarshalAttemptJournal(terminal)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalAttemptJournal(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Attempts[0].Receipt == nil ||
		decoded.Attempts[0].Receipt.Status != 1 ||
		len(decoded.Attempts[0].Receipt.RawCanonicalReceipt) == 0 {
		t.Fatalf("terminal receipt was not retained: %+v", decoded.Attempts[0])
	}
}

func TestAttemptJournalRejectsConflictAndAggregateOverflow(t *testing.T) {
	t.Parallel()

	_, _, journal := testAttemptJournal(t)
	journal.Attempts[0].Outcome = AttemptOutcomeBlockLimitExpired
	duplicate := testSignedTransaction(t, journal, 2, 9000, 0x70)
	duplicate.TransactionHash = append([]byte(nil), journal.Attempts[0].Transaction.TransactionHash...)
	journal.Attempts = append(journal.Attempts, JournalAttempt{
		Transaction: duplicate,
		Outcome:     AttemptOutcomePrepared,
	})
	if err := ValidateAttemptJournal(journal); err == nil {
		t.Fatal("journal accepted duplicate transaction hash")
	}

	_, _, oversized := testAttemptJournal(t)
	oversized.Attempts[0].Outcome = AttemptOutcomeReceiptSuccess
	receipt := testAttemptReceipt(oversized.Attempts[0].Transaction.TransactionHash, ReceiptStatusOK)
	receipt.RawCanonicalReceipt = make([]byte, maxReceiptAggregate)
	oversized.Attempts[0].Receipt = receipt
	if err := ValidateAttemptJournal(oversized); err == nil {
		t.Fatal("journal accepted receipt/log/proof aggregate overflow")
	}
}

func TestAttemptJournalDecoderRejectsNonCanonicalAndHugeDeclaredCount(t *testing.T) {
	t.Parallel()

	_, _, journal := testAttemptJournal(t)
	data, err := MarshalAttemptJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalAttemptJournal(append(data, 0xf6)); err == nil {
		t.Fatal("decoder accepted trailing CBOR data")
	}

	// {"attempts": <array with declared length 1,048,576>}. The
	// format-specific decoder rejects the count before allocating the slice.
	declaredHugeAttempts := []byte{
		0xa1,
		0x68, 'a', 't', 't', 'e', 'm', 'p', 't', 's',
		0x9a, 0x00, 0x10, 0x00, 0x00,
	}
	if _, err := UnmarshalAttemptJournal(declaredHugeAttempts); err == nil {
		t.Fatal("decoder accepted a huge declared attempts array")
	}
}

func testAttemptJournal(t *testing.T) (sth model.SignedTreeHead, config TrustConfig, journal AttemptJournal) {
	t.Helper()
	sth = testSTH(cryptosuite.INTLV1)
	config = testTrustConfig(t, CryptoModeStandard)
	payload, err := NewAnchorPayload(cryptosuite.INTLV1, sth)
	if err != nil {
		t.Fatal(err)
	}
	canonicalPayload, err := MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	contextID, err := ChainContextID(config)
	if err != nil {
		t.Fatal(err)
	}
	journal = AttemptJournal{
		SchemaVersion:    SchemaAttemptJournal,
		FormatVersion:    AttemptJournalVersion,
		Generation:       7,
		Revision:         1,
		NodeID:           sth.NodeID,
		LogID:            sth.LogID,
		SinkName:         SinkName,
		TreeSize:         sth.TreeSize,
		RootHash:         append([]byte(nil), sth.RootHash...),
		SignedSTHDigest:  append([]byte(nil), payload.SignedSTHDigest...),
		CryptoMode:       config.CryptoMode,
		ChainID:          config.ChainID,
		GroupID:          config.GroupID,
		Contract:         config.Contract,
		ChainContextID:   contextID,
		CanonicalPayload: canonicalPayload,
	}
	journal.Attempts = []JournalAttempt{{
		Transaction: testSignedTransaction(t, journal, 1, 8000, 0x70),
		Outcome:     AttemptOutcomePrepared,
	}}
	return sth, config, journal
}

func testSignedTransaction(t *testing.T, journal AttemptJournal, ordinal uint32, blockLimit uint64, seed byte) SignedTransactionAttempt {
	t.Helper()
	payload, err := UnmarshalPayload(journal.CanonicalPayload)
	if err != nil {
		t.Fatal(err)
	}
	input, err := PublishCallData(payload)
	if err != nil {
		t.Fatal(err)
	}
	return SignedTransactionAttempt{
		Ordinal:                 ordinal,
		RawCanonicalTransaction: append([]byte("canonical-signed-transaction-"), byte(ordinal)),
		ChainID:                 journal.ChainID,
		GroupID:                 journal.GroupID,
		To:                      append([]byte(nil), journal.Contract.Address...),
		Input:                   input,
		Signature:               sequenceBytes(seed, 65),
		Sender:                  sequenceBytes(seed+1, 20),
		TransactionHash:         sequenceBytes(seed+2, 32),
		BlockLimit:              blockLimit,
		PreparedAtUnixN:         int64(ordinal),
	}
}

func testAttemptReceipt(transactionHash []byte, status int64) *AttemptReceiptObservation {
	fields := NativeReceiptFields{
		Version:     0,
		GasUsed:     "1",
		Status:      int32(status),
		Logs:        []NativeLogFields{{Address: "0x01", Topics: [][]byte{sequenceBytes(0x90, 32)}, Data: []byte{0x01}}},
		BlockNumber: 7000,
	}
	raw, logs, err := MarshalNativeReceiptPreimage(fields)
	if err != nil {
		panic(err)
	}
	hash, err := HashNativeEvidence(HashKeccak256, raw)
	if err != nil {
		panic(err)
	}
	return &AttemptReceiptObservation{
		Fields:              fields,
		RawCanonicalReceipt: raw,
		Status:              status,
		StatusMessage:       "success",
		CanonicalLogs:       logs,
		ReceiptHash:         hash,
		TransactionHash:     append([]byte(nil), transactionHash...),
		TransactionProof:    [][]byte{sequenceBytes(0xb0, 32)},
		ReceiptProof:        [][]byte{sequenceBytes(0xc0, 32)},
		BlockNumber:         7000,
		BlockHash:           sequenceBytes(0xd0, 32),
		DecodedAnchorEvent:  []byte("canonical-decoded-event"),
		ObservedAtUnixN:     3,
	}
}

func cloneAttemptJournal(t *testing.T, journal AttemptJournal) AttemptJournal {
	t.Helper()
	data, err := MarshalAttemptJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	cloned, err := UnmarshalAttemptJournal(data)
	if err != nil {
		t.Fatal(err)
	}
	return cloned
}
