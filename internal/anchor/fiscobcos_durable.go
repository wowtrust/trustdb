package anchor

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
)

// PublishDurable resumes one append-only BCOS attempt journal bound to the
// scheduler's immutable InFlight Signed STH. Every newly signed transaction is
// checkpointed before SubmitPreparedAnchor can produce a network side effect.
func (s *FISCOBCOSStandardSink) PublishDurable(
	ctx context.Context,
	inFlight model.STHAnchorAttempt,
	checkpoint ProviderStateCheckpoint,
) (model.STHAnchorResult, error) {
	if s == nil || checkpoint == nil {
		return model.STHAnchorResult{}, fmt.Errorf("%w: durable BCOS publication requires a sink and checkpoint", ErrPermanent)
	}
	if inFlight.Generation == 0 || inFlight.Target.TreeSize == 0 {
		return model.STHAnchorResult{}, fmt.Errorf("%w: invalid BCOS in-flight target", ErrPermanent)
	}
	route, err := s.probeQuorum(ctx)
	if err != nil {
		return model.STHAnchorResult{}, mapSinkError(err)
	}
	payload, err := payloadForSTH(inFlight.Target)
	if err != nil {
		return model.STHAnchorResult{}, fmt.Errorf("%w: %w", ErrPermanent, err)
	}
	canonicalPayload, err := fiscobcos.MarshalPayload(payload)
	if err != nil {
		return model.STHAnchorResult{}, fmt.Errorf("%w: %w", ErrPermanent, err)
	}
	request := fiscobcos.SubmitRequest{Payload: payload, CanonicalPayload: canonicalPayload}

	rawJournal := append([]byte(nil), inFlight.ProviderState...)
	var journal fiscobcos.AttemptJournal
	if len(rawJournal) == 0 {
		existing, err := s.readAnchorStateQuorum(ctx, payload)
		if err != nil {
			return model.STHAnchorResult{}, mapSinkError(err)
		}
		if existing {
			return model.STHAnchorResult{}, mapSinkError(ambiguousDriverFailure(
				"recover_existing_anchor",
				s.drivers[0].Endpoint(),
				fiscobcos.ErrExistingAnchorEvidenceUnavailable,
			))
		}
		prepared, err := route.driver.PrepareAnchor(ctx, request)
		if err != nil {
			return model.STHAnchorResult{}, mapSinkError(classifyDriverFailure("prepare_anchor", route.driver.Endpoint(), err))
		}
		if err := validateTransactionAttempt(prepared, s.trust, payload); err != nil {
			return model.STHAnchorResult{}, mapSinkError(permanentDriverFailure("validate_prepared_anchor", route.driver.Endpoint(), err))
		}
		journal, err = s.newAttemptJournal(inFlight, canonicalPayload, prepared)
		if err != nil {
			return model.STHAnchorResult{}, fmt.Errorf("%w: %w", ErrPermanent, err)
		}
		rawJournal, err = fiscobcos.MarshalAttemptJournal(journal)
		if err != nil {
			return model.STHAnchorResult{}, fmt.Errorf("%w: %w", ErrPermanent, err)
		}
		if err := checkpoint(ctx, nil, rawJournal); err != nil {
			return model.STHAnchorResult{}, fmt.Errorf("checkpoint prepared BCOS transaction: %w", err)
		}
	} else {
		journal, err = fiscobcos.UnmarshalAttemptJournal(rawJournal)
		if err != nil {
			return model.STHAnchorResult{}, fmt.Errorf("%w: decode durable BCOS provider state: %w", ErrPermanent, err)
		}
		if err := fiscobcos.ValidateAttemptJournalBinding(journal, inFlight.Generation, inFlight.Target, s.trust); err != nil {
			return model.STHAnchorResult{}, fmt.Errorf("%w: bind durable BCOS provider state: %w", ErrPermanent, err)
		}
	}
	return s.resumeAttemptJournal(ctx, inFlight.Target, request, route, journal, rawJournal, checkpoint)
}

func (s *FISCOBCOSStandardSink) newAttemptJournal(
	inFlight model.STHAnchorAttempt,
	canonicalPayload []byte,
	prepared fiscobcos.TransactionSubmission,
) (fiscobcos.AttemptJournal, error) {
	contextID, err := fiscobcos.ChainContextID(s.trust)
	if err != nil {
		return fiscobcos.AttemptJournal{}, err
	}
	payload, err := fiscobcos.UnmarshalPayload(canonicalPayload)
	if err != nil {
		return fiscobcos.AttemptJournal{}, err
	}
	journal := fiscobcos.AttemptJournal{
		SchemaVersion:    fiscobcos.SchemaAttemptJournal,
		FormatVersion:    fiscobcos.AttemptJournalVersion,
		Generation:       inFlight.Generation,
		Revision:         1,
		NodeID:           inFlight.Target.NodeID,
		LogID:            inFlight.Target.LogID,
		SinkName:         fiscobcos.SinkName,
		TreeSize:         inFlight.Target.TreeSize,
		RootHash:         append([]byte(nil), inFlight.Target.RootHash...),
		SignedSTHDigest:  append([]byte(nil), payload.SignedSTHDigest...),
		CryptoMode:       s.trust.CryptoMode,
		ChainID:          s.trust.ChainID,
		GroupID:          s.trust.GroupID,
		Contract:         s.trust.Contract,
		ChainContextID:   contextID,
		CanonicalPayload: append([]byte(nil), canonicalPayload...),
		Attempts: []fiscobcos.JournalAttempt{{
			Transaction: journalTransaction(prepared, 1),
			Outcome:     fiscobcos.AttemptOutcomePrepared,
		}},
	}
	if err := fiscobcos.ValidateAttemptJournalBinding(journal, inFlight.Generation, inFlight.Target, s.trust); err != nil {
		return fiscobcos.AttemptJournal{}, err
	}
	return journal, nil
}

func (s *FISCOBCOSStandardSink) resumeAttemptJournal(
	ctx context.Context,
	sth model.SignedTreeHead,
	request fiscobcos.SubmitRequest,
	route bcosQuorumRoute,
	journal fiscobcos.AttemptJournal,
	rawJournal []byte,
	checkpoint ProviderStateCheckpoint,
) (model.STHAnchorResult, error) {
	for {
		lastIndex := len(journal.Attempts) - 1
		last := journal.Attempts[lastIndex]
		switch last.Outcome {
		case fiscobcos.AttemptOutcomeReceiptSuccess:
			return s.resultFromSuccessfulJournal(ctx, sth, journal, lastIndex)
		case fiscobcos.AttemptOutcomeReceiptTerminalRejected:
			return model.STHAnchorResult{}, fmt.Errorf(
				"%w: BCOS transaction received terminal status %d",
				ErrPermanent,
				last.Submission.Status,
			)
		case fiscobcos.AttemptOutcomeReceiptBlockLimitRejected, fiscobcos.AttemptOutcomeBlockLimitExpired:
			if index, receipt, found, err := s.recoverRecordedReceipts(ctx, journal); err != nil {
				return model.STHAnchorResult{}, mapSinkError(err)
			} else if found {
				if receipt.Status == fiscobcos.ReceiptStatusOK {
					return s.completeObservedReceipt(ctx, sth, journal, rawJournal, index, receipt, checkpoint)
				}
				return model.STHAnchorResult{}, ambiguousDriverFailure(
					"recover_closed_attempt_receipt",
					s.drivers[0].Endpoint(),
					fiscobcos.ErrEndpointDisagreement,
				)
			}
			if len(journal.Attempts) >= 32 {
				return model.STHAnchorResult{}, fmt.Errorf("%w: BCOS transaction attempt limit reached", ErrPermanent)
			}
			prepared, err := route.driver.PrepareAnchor(ctx, request)
			if err != nil {
				return model.STHAnchorResult{}, mapSinkError(classifyDriverFailure("prepare_anchor_retry", route.driver.Endpoint(), err))
			}
			if err := validateTransactionAttempt(prepared, s.trust, request.Payload); err != nil {
				return model.STHAnchorResult{}, mapSinkError(permanentDriverFailure("validate_prepared_anchor_retry", route.driver.Endpoint(), err))
			}
			next, err := cloneAttemptJournal(rawJournal)
			if err != nil {
				return model.STHAnchorResult{}, err
			}
			next.Revision++
			next.Attempts = append(next.Attempts, fiscobcos.JournalAttempt{
				Transaction: journalTransaction(prepared, uint32(len(next.Attempts)+1)),
				Outcome:     fiscobcos.AttemptOutcomePrepared,
			})
			var nextRaw []byte
			nextRaw, err = s.checkpointAttemptJournal(ctx, journal, rawJournal, next, checkpoint)
			if err != nil {
				return model.STHAnchorResult{}, err
			}
			s.recordRetry(bcosRetryReasonBlockLimitRefresh)
			journal, rawJournal = next, nextRaw
			continue
		}

		attempt := submissionFromJournal(last.Transaction)
		recoveredIndex, receipt, found, err := s.recoverRecordedReceipts(ctx, journal)
		if err != nil {
			return model.STHAnchorResult{}, mapSinkError(err)
		}
		if found {
			if receipt.Status == fiscobcos.ReceiptStatusOK {
				return s.completeObservedReceipt(ctx, sth, journal, rawJournal, recoveredIndex, receipt, checkpoint)
			}
			if recoveredIndex != lastIndex {
				return model.STHAnchorResult{}, ambiguousDriverFailure(
					"recover_nonfinal_terminal_receipt",
					s.drivers[0].Endpoint(),
					fiscobcos.ErrEndpointDisagreement,
				)
			}
			next, cloneErr := cloneAttemptJournal(rawJournal)
			if cloneErr != nil {
				return model.STHAnchorResult{}, cloneErr
			}
			next.Revision++
			next.Attempts[lastIndex].Outcome = fiscobcos.AttemptOutcomeReceiptTerminalRejected
			next.Attempts[lastIndex].Submission = &fiscobcos.SubmissionObservation{
				Status: int64(receipt.Status), StatusMessage: receipt.StatusMessage,
				ObservedAtUnixN: s.clock().UTC().UnixNano(),
			}
			next.Attempts[lastIndex].Receipt = receiptObservation(receipt, next.Attempts[lastIndex].Submission.ObservedAtUnixN)
			if _, checkpointErr := s.checkpointAttemptJournal(ctx, journal, rawJournal, next, checkpoint); checkpointErr != nil {
				return model.STHAnchorResult{}, checkpointErr
			}
			return model.STHAnchorResult{}, fmt.Errorf("%w: BCOS transaction status %d", ErrPermanent, receipt.Status)
		}

		existing, err := s.readAnchorStateQuorum(ctx, request.Payload)
		if err != nil {
			return model.STHAnchorResult{}, mapSinkError(err)
		}
		if existing {
			return model.STHAnchorResult{}, mapSinkError(ambiguousDriverFailure(
				"recover_existing_anchor",
				s.drivers[0].Endpoint(),
				fiscobcos.ErrExistingAnchorEvidenceUnavailable,
			))
		}
		if route.height > attempt.BlockLimit {
			next, err := cloneAttemptJournal(rawJournal)
			if err != nil {
				return model.STHAnchorResult{}, err
			}
			next.Revision++
			next.Attempts[lastIndex].Outcome = fiscobcos.AttemptOutcomeBlockLimitExpired
			nextRaw, err := s.checkpointAttemptJournal(ctx, journal, rawJournal, next, checkpoint)
			if err != nil {
				return model.STHAnchorResult{}, err
			}
			journal, rawJournal = next, nextRaw
			continue
		}

		outcome, err := route.driver.SubmitPreparedAnchor(ctx, attempt)
		if err != nil {
			if last.Outcome == fiscobcos.AttemptOutcomePrepared {
				next, cloneErr := cloneAttemptJournal(rawJournal)
				if cloneErr != nil {
					return model.STHAnchorResult{}, cloneErr
				}
				next.Revision++
				next.Attempts[lastIndex].Outcome = fiscobcos.AttemptOutcomeSubmitUnknown
				nextRaw, checkpointErr := s.checkpointAttemptJournal(ctx, journal, rawJournal, next, checkpoint)
				if checkpointErr != nil {
					return model.STHAnchorResult{}, checkpointErr
				}
				journal, rawJournal = next, nextRaw
			}
			s.recordRetry(bcosRetryReasonExactTransaction)
			return model.STHAnchorResult{}, mapSinkError(classifyDriverFailure("submit_prepared_anchor", route.driver.Endpoint(), err))
		}
		switch outcome.Status {
		case fiscobcos.ReceiptStatusOK:
			receipt, err := route.driver.GetReceiptWithProof(ctx, attempt)
			if err == nil {
				return s.completeObservedReceipt(ctx, sth, journal, rawJournal, lastIndex, receipt, checkpoint)
			}
			if !errors.Is(err, fiscobcos.ErrTransactionNotFound) {
				return model.STHAnchorResult{}, mapSinkError(ambiguousDriverFailure("get_submitted_receipt", route.driver.Endpoint(), err))
			}
			if last.Outcome == fiscobcos.AttemptOutcomePrepared {
				next, cloneErr := cloneAttemptJournal(rawJournal)
				if cloneErr != nil {
					return model.STHAnchorResult{}, cloneErr
				}
				next.Revision++
				next.Attempts[lastIndex].Outcome = fiscobcos.AttemptOutcomeSubmitUnknown
				if _, checkpointErr := s.checkpointAttemptJournal(ctx, journal, rawJournal, next, checkpoint); checkpointErr != nil {
					return model.STHAnchorResult{}, checkpointErr
				}
			}
			s.recordRetry(bcosRetryReasonDuplicateLookup)
			return model.STHAnchorResult{}, ambiguousDriverFailure("await_submitted_receipt", route.driver.Endpoint(), fiscobcos.ErrTransactionNotFound)
		case int(fiscobcos.ReceiptStatusCodeBlockLimit):
			next, cloneErr := cloneAttemptJournal(rawJournal)
			if cloneErr != nil {
				return model.STHAnchorResult{}, cloneErr
			}
			next.Revision++
			next.Attempts[lastIndex].Outcome = fiscobcos.AttemptOutcomeReceiptBlockLimitRejected
			next.Attempts[lastIndex].Submission = submissionObservation(outcome)
			if _, checkpointErr := s.checkpointAttemptJournal(ctx, journal, rawJournal, next, checkpoint); checkpointErr != nil {
				return model.STHAnchorResult{}, checkpointErr
			}
			return model.STHAnchorResult{}, fmt.Errorf("FISCO BCOS block limit rejected prepared transaction")
		case fiscobcos.ReceiptStatusNonceCheckFailed,
			fiscobcos.ReceiptStatusAlreadyInPool,
			fiscobcos.ReceiptStatusAlreadyInChain,
			fiscobcos.ReceiptStatusAlreadyInPoolAccept:
			if last.Outcome == fiscobcos.AttemptOutcomePrepared ||
				(last.Outcome == fiscobcos.AttemptOutcomeSubmitUnknown && last.Submission == nil) {
				next, cloneErr := cloneAttemptJournal(rawJournal)
				if cloneErr != nil {
					return model.STHAnchorResult{}, cloneErr
				}
				next.Revision++
				next.Attempts[lastIndex].Outcome = fiscobcos.AttemptOutcomeSubmitUnknown
				next.Attempts[lastIndex].Submission = submissionObservation(outcome)
				nextRaw, checkpointErr := s.checkpointAttemptJournal(ctx, journal, rawJournal, next, checkpoint)
				if checkpointErr != nil {
					return model.STHAnchorResult{}, checkpointErr
				}
				journal, rawJournal = next, nextRaw
			}
			s.recordRetry(bcosRetryReasonDuplicateLookup)
			return model.STHAnchorResult{}, ambiguousDriverFailure(
				"await_duplicate_transaction_receipt",
				route.driver.Endpoint(),
				fiscobcos.ErrTransactionNotFound,
			)
		case fiscobcos.ReceiptStatusTransactionPoolFull:
			s.recordRetry(bcosRetryReasonExactTransaction)
			return model.STHAnchorResult{}, fmt.Errorf(
				"FISCO BCOS transient submission status %d",
				outcome.Status,
			)
		default:
			var terminalReceipt *fiscobcos.AttemptReceiptObservation
			if outcome.Status < 10000 {
				receipt, receiptErr := s.readReceiptQuorum(ctx, attempt)
				if receiptErr != nil {
					if !errors.Is(receiptErr, fiscobcos.ErrTransactionNotFound) {
						return model.STHAnchorResult{}, mapSinkError(receiptErr)
					}
				} else {
					terminalReceipt = receiptObservation(receipt, outcome.ObservedAtUnixN)
				}
			}
			if outcome.Status < 10000 && terminalReceipt == nil {
				s.recordRetry(bcosRetryReasonDuplicateLookup)
				return model.STHAnchorResult{}, ambiguousDriverFailure(
					"await_included_transaction_receipt",
					route.driver.Endpoint(),
					fiscobcos.ErrTransactionNotFound,
				)
			}
			disposition := fiscobcos.ClassifyReceiptStatus(outcome.Status)
			if terminalReceipt == nil && disposition == fiscobcos.ReceiptStatusAmbiguous {
				if last.Outcome == fiscobcos.AttemptOutcomePrepared ||
					(last.Outcome == fiscobcos.AttemptOutcomeSubmitUnknown && last.Submission == nil) {
					next, cloneErr := cloneAttemptJournal(rawJournal)
					if cloneErr != nil {
						return model.STHAnchorResult{}, cloneErr
					}
					next.Revision++
					next.Attempts[lastIndex].Outcome = fiscobcos.AttemptOutcomeSubmitUnknown
					next.Attempts[lastIndex].Submission = submissionObservation(outcome)
					nextRaw, checkpointErr := s.checkpointAttemptJournal(ctx, journal, rawJournal, next, checkpoint)
					if checkpointErr != nil {
						return model.STHAnchorResult{}, checkpointErr
					}
					journal, rawJournal = next, nextRaw
				}
				s.recordRetry(bcosRetryReasonExactTransaction)
				return model.STHAnchorResult{}, ambiguousDriverFailure(
					"submit_prepared_anchor_status",
					route.driver.Endpoint(),
					fiscobcos.NewReceiptStatusError(outcome.Status),
				)
			}
			if terminalReceipt == nil && disposition != fiscobcos.ReceiptStatusPermanent {
				s.recordRetry(bcosRetryReasonExactTransaction)
				return model.STHAnchorResult{}, ambiguousDriverFailure(
					"submit_prepared_anchor_status",
					route.driver.Endpoint(),
					fiscobcos.NewReceiptStatusError(outcome.Status),
				)
			}
			next, cloneErr := cloneAttemptJournal(rawJournal)
			if cloneErr != nil {
				return model.STHAnchorResult{}, cloneErr
			}
			next.Revision++
			next.Attempts[lastIndex].Outcome = fiscobcos.AttemptOutcomeReceiptTerminalRejected
			next.Attempts[lastIndex].Submission = submissionObservation(outcome)
			next.Attempts[lastIndex].Receipt = terminalReceipt
			if _, checkpointErr := s.checkpointAttemptJournal(ctx, journal, rawJournal, next, checkpoint); checkpointErr != nil {
				return model.STHAnchorResult{}, checkpointErr
			}
			return model.STHAnchorResult{}, fmt.Errorf("%w: BCOS transaction status %d", ErrPermanent, outcome.Status)
		}
	}
}

func (s *FISCOBCOSStandardSink) completeObservedReceipt(
	ctx context.Context,
	sth model.SignedTreeHead,
	journal fiscobcos.AttemptJournal,
	rawJournal []byte,
	attemptIndex int,
	receipt fiscobcos.ReceiptWithProof,
	checkpoint ProviderStateCheckpoint,
) (model.STHAnchorResult, error) {
	payload, err := fiscobcos.UnmarshalPayload(journal.CanonicalPayload)
	if err != nil {
		return model.STHAnchorResult{}, fmt.Errorf("%w: %w", ErrPermanent, err)
	}
	attempt := submissionFromJournal(journal.Attempts[attemptIndex].Transaction)
	if receipt.Status != fiscobcos.ReceiptStatusOK {
		return model.STHAnchorResult{}, ambiguousDriverFailure("validate_receipt_status", s.drivers[0].Endpoint(), fiscobcos.ErrInvalidReceiptStatus)
	}
	records, err := s.readAnchorQuorum(ctx, payload)
	if err != nil {
		return model.STHAnchorResult{}, mapSinkError(err)
	}
	if err := validateReceipt(s.trust, payload, attempt, receipt, records[0]); err != nil {
		return model.STHAnchorResult{}, mapSinkError(ambiguousDriverFailure("validate_receipt", s.drivers[0].Endpoint(), err))
	}
	if journal.Attempts[attemptIndex].Outcome != fiscobcos.AttemptOutcomeReceiptSuccess {
		next, err := cloneAttemptJournal(rawJournal)
		if err != nil {
			return model.STHAnchorResult{}, err
		}
		next.Revision++
		next.Attempts[attemptIndex].Outcome = fiscobcos.AttemptOutcomeReceiptSuccess
		next.Attempts[attemptIndex].Receipt = receiptObservation(receipt, s.clock().UTC().UnixNano())
		nextRaw, err := s.checkpointAttemptJournal(ctx, journal, rawJournal, next, checkpoint)
		if err != nil {
			return model.STHAnchorResult{}, err
		}
		journal, rawJournal = next, nextRaw
		_ = rawJournal
	}
	return s.resultFromSuccessfulJournal(ctx, sth, journal, attemptIndex)
}

func (s *FISCOBCOSStandardSink) resultFromSuccessfulJournal(
	ctx context.Context,
	sth model.SignedTreeHead,
	journal fiscobcos.AttemptJournal,
	attemptIndex int,
) (model.STHAnchorResult, error) {
	success := journal.Attempts[attemptIndex]
	if success.Receipt == nil {
		return model.STHAnchorResult{}, fmt.Errorf("%w: successful BCOS journal attempt lacks receipt", ErrPermanent)
	}
	header, consensus, err := s.readBlockQuorum(ctx, success.Receipt.BlockNumber, success.Receipt.BlockHash)
	if err != nil {
		return model.STHAnchorResult{}, mapSinkError(err)
	}
	attempts := make([]fiscobcos.TransactionAttempt, len(journal.Attempts))
	for index, item := range journal.Attempts {
		attempts[index] = proofTransactionAttempt(item)
	}
	proof := fiscobcos.AnchorProof{
		SchemaVersion:             fiscobcos.SchemaAnchorProof,
		FormatVersion:             fiscobcos.ProofVersion,
		CryptoMode:                s.trust.CryptoMode,
		ProtocolHashAlgorithm:     s.trust.ProtocolHashAlgorithm,
		ChainHashAlgorithm:        s.trust.ChainHashAlgorithm,
		ChainSignatureAlgorithm:   s.trust.ChainSignatureAlgorithm,
		ChainID:                   s.trust.ChainID,
		GroupID:                   s.trust.GroupID,
		GenesisHash:               append([]byte(nil), s.trust.GenesisHash...),
		TrustedCheckpoint:         s.trust.TrustedCheckpoint,
		Contract:                  s.trust.Contract,
		ChainContextID:            append([]byte(nil), journal.ChainContextID...),
		CanonicalPayload:          append([]byte(nil), journal.CanonicalPayload...),
		TransactionAttempts:       attempts,
		SuccessfulAttemptOrdinal:  success.Transaction.Ordinal,
		SuccessfulTransactionHash: append([]byte(nil), success.Transaction.TransactionHash...),
		Receipt: fiscobcos.ReceiptEvidence{
			Fields:              success.Receipt.Fields,
			RawCanonicalReceipt: append([]byte(nil), success.Receipt.RawCanonicalReceipt...),
			Status:              success.Receipt.Status,
			StatusMessage:       success.Receipt.StatusMessage,
			CanonicalLogs:       cloneByteSlices(success.Receipt.CanonicalLogs),
			ReceiptHash:         append([]byte(nil), success.Receipt.ReceiptHash...),
			TransactionHash:     append([]byte(nil), success.Receipt.TransactionHash...),
			TransactionIndex:    success.Receipt.TransactionIndex,
			TransactionProof:    cloneByteSlices(success.Receipt.TransactionProof),
			ReceiptIndex:        success.Receipt.ReceiptIndex,
			ReceiptProof:        cloneByteSlices(success.Receipt.ReceiptProof),
			AnchorLogIndex:      success.Receipt.AnchorLogIndex,
			DecodedAnchorEvent:  append([]byte(nil), success.Receipt.DecodedAnchorEvent...),
		},
		Block:    header.Evidence,
		Finality: consensus.Finality,
	}
	proofBytes, err := fiscobcos.MarshalProof(proof)
	if err != nil {
		return model.STHAnchorResult{}, mapSinkError(ambiguousDriverFailure("marshal_anchor_proof", s.drivers[0].Endpoint(), err))
	}
	payload, err := fiscobcos.UnmarshalPayload(journal.CanonicalPayload)
	if err != nil {
		return model.STHAnchorResult{}, fmt.Errorf("%w: %w", ErrPermanent, err)
	}
	result := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		NodeID:        sth.NodeID,
		LogID:         sth.LogID,
		TreeSize:      sth.TreeSize,
		SinkName:      fiscobcos.SinkName,
		AnchorID:      fiscobcos.AnchorIDString(payload),
		RootHash:      append([]byte(nil), sth.RootHash...),
		STH:           sth,
		Proof:         proofBytes,
		EvidenceStage: model.AnchorEvidenceStageRaw,
		// The first durable observation time remains stable across a crash
		// after external success but before local result completion.
		PublishedAtUnixN: success.Receipt.ObservedAtUnixN,
	}
	if err := fiscobcos.ValidateProofAgainstTrustConfig(sth, result, s.trust); err != nil {
		return model.STHAnchorResult{}, mapSinkError(ambiguousDriverFailure("validate_anchor_proof", s.drivers[0].Endpoint(), err))
	}
	return result, nil
}

func (s *FISCOBCOSStandardSink) checkpointAttemptJournal(
	ctx context.Context,
	previous fiscobcos.AttemptJournal,
	previousRaw []byte,
	next fiscobcos.AttemptJournal,
	checkpoint ProviderStateCheckpoint,
) ([]byte, error) {
	if err := fiscobcos.ValidateAttemptJournalTransition(previous, next); err != nil {
		return nil, fmt.Errorf("%w: invalid BCOS attempt transition: %w", ErrPermanent, err)
	}
	nextRaw, err := fiscobcos.MarshalAttemptJournal(next)
	if err != nil {
		return nil, fmt.Errorf("%w: encode BCOS attempt transition: %w", ErrPermanent, err)
	}
	if err := checkpoint(ctx, previousRaw, nextRaw); err != nil {
		return nil, fmt.Errorf("checkpoint BCOS attempt transition: %w", err)
	}
	return nextRaw, nil
}

func cloneAttemptJournal(raw []byte) (fiscobcos.AttemptJournal, error) {
	journal, err := fiscobcos.UnmarshalAttemptJournal(raw)
	if err != nil {
		return fiscobcos.AttemptJournal{}, fmt.Errorf("%w: clone BCOS attempt journal: %w", ErrPermanent, err)
	}
	return journal, nil
}

func journalTransaction(attempt fiscobcos.TransactionSubmission, ordinal uint32) fiscobcos.SignedTransactionAttempt {
	return fiscobcos.SignedTransactionAttempt{
		Ordinal:                 ordinal,
		RawCanonicalTransaction: append([]byte(nil), attempt.EncodedTransaction...),
		ChainID:                 attempt.ChainID,
		GroupID:                 attempt.GroupID,
		To:                      append([]byte(nil), attempt.To...),
		Input:                   append([]byte(nil), attempt.Input...),
		Signature:               append([]byte(nil), attempt.Signature...),
		Sender:                  append([]byte(nil), attempt.Sender...),
		TransactionHash:         append([]byte(nil), attempt.TransactionHash...),
		BlockLimit:              attempt.BlockLimit,
		PreparedAtUnixN:         attempt.SubmittedAtUnixN,
	}
}

func submissionFromJournal(attempt fiscobcos.SignedTransactionAttempt) fiscobcos.TransactionSubmission {
	return fiscobcos.TransactionSubmission{
		EncodedTransaction: append([]byte(nil), attempt.RawCanonicalTransaction...),
		ChainID:            attempt.ChainID,
		GroupID:            attempt.GroupID,
		To:                 append([]byte(nil), attempt.To...),
		Input:              append([]byte(nil), attempt.Input...),
		Signature:          append([]byte(nil), attempt.Signature...),
		Sender:             append([]byte(nil), attempt.Sender...),
		TransactionHash:    append([]byte(nil), attempt.TransactionHash...),
		BlockLimit:         attempt.BlockLimit,
		SubmittedAtUnixN:   attempt.PreparedAtUnixN,
	}
}

func proofTransactionAttempt(attempt fiscobcos.JournalAttempt) fiscobcos.TransactionAttempt {
	transaction := attempt.Transaction
	return fiscobcos.TransactionAttempt{
		Ordinal:                 transaction.Ordinal,
		RawCanonicalTransaction: append([]byte(nil), transaction.RawCanonicalTransaction...),
		ChainID:                 transaction.ChainID,
		GroupID:                 transaction.GroupID,
		To:                      append([]byte(nil), transaction.To...),
		Input:                   append([]byte(nil), transaction.Input...),
		Signature:               append([]byte(nil), transaction.Signature...),
		Sender:                  append([]byte(nil), transaction.Sender...),
		TransactionHash:         append([]byte(nil), transaction.TransactionHash...),
		BlockLimit:              transaction.BlockLimit,
		SubmittedAtUnixN:        transaction.PreparedAtUnixN,
		Outcome:                 attempt.Outcome,
		Submission:              cloneSubmissionObservation(attempt.Submission),
	}
}

func cloneSubmissionObservation(observation *fiscobcos.SubmissionObservation) *fiscobcos.SubmissionObservation {
	if observation == nil {
		return nil
	}
	cloned := *observation
	return &cloned
}

func submissionObservation(outcome fiscobcos.SubmissionOutcome) *fiscobcos.SubmissionObservation {
	return &fiscobcos.SubmissionObservation{
		Status:          int64(outcome.Status),
		StatusMessage:   outcome.StatusMessage,
		ObservedAtUnixN: outcome.ObservedAtUnixN,
	}
}

func receiptObservation(receipt fiscobcos.ReceiptWithProof, observedAt int64) *fiscobcos.AttemptReceiptObservation {
	return &fiscobcos.AttemptReceiptObservation{
		Fields:              receipt.Evidence.Fields,
		RawCanonicalReceipt: append([]byte(nil), receipt.Evidence.RawCanonicalReceipt...),
		Status:              int64(receipt.Status),
		StatusMessage:       receipt.StatusMessage,
		CanonicalLogs:       cloneByteSlices(receipt.Evidence.CanonicalLogs),
		ReceiptHash:         append([]byte(nil), receipt.Evidence.ReceiptHash...),
		TransactionHash:     append([]byte(nil), receipt.Evidence.TransactionHash...),
		TransactionIndex:    receipt.Evidence.TransactionIndex,
		TransactionProof:    cloneByteSlices(receipt.Evidence.TransactionProof),
		ReceiptIndex:        receipt.Evidence.ReceiptIndex,
		ReceiptProof:        cloneByteSlices(receipt.Evidence.ReceiptProof),
		BlockNumber:         receipt.BlockNumber,
		BlockHash:           append([]byte(nil), receipt.BlockHash...),
		AnchorLogIndex:      receipt.Evidence.AnchorLogIndex,
		DecodedAnchorEvent:  append([]byte(nil), receipt.Evidence.DecodedAnchorEvent...),
		ObservedAtUnixN:     observedAt,
	}
}

// recoverRecordedReceipts examines every immutable transaction hash. A
// restart must not let the journal's last element hide an earlier inclusion.
func (s *FISCOBCOSStandardSink) recoverRecordedReceipts(
	ctx context.Context,
	journal fiscobcos.AttemptJournal,
) (int, fiscobcos.ReceiptWithProof, bool, error) {
	foundIndex := -1
	var foundReceipt fiscobcos.ReceiptWithProof
	for index := range journal.Attempts {
		receipt, err := s.readReceiptQuorum(ctx, submissionFromJournal(journal.Attempts[index].Transaction))
		if errors.Is(err, fiscobcos.ErrTransactionNotFound) {
			continue
		}
		if err != nil {
			return 0, fiscobcos.ReceiptWithProof{}, false, err
		}
		if foundIndex >= 0 {
			return 0, fiscobcos.ReceiptWithProof{}, false, ambiguousDriverFailure(
				"recover_receipts",
				s.drivers[0].Endpoint(),
				fiscobcos.ErrEndpointDisagreement,
			)
		}
		foundIndex, foundReceipt = index, receipt
	}
	return foundIndex, foundReceipt, foundIndex >= 0, nil
}

func (s *FISCOBCOSStandardSink) readReceiptQuorum(
	ctx context.Context,
	attempt fiscobcos.TransactionSubmission,
) (fiscobcos.ReceiptWithProof, error) {
	quorum := int(s.trust.ReadQuorum)
	notFound := 0
	var selected fiscobcos.ReceiptWithProof
	var selectedKey []byte
	matches := 0
	for _, driver := range s.drivers {
		receipt, err := driver.GetReceiptWithProof(ctx, attempt)
		if errors.Is(err, fiscobcos.ErrTransactionNotFound) {
			notFound++
			continue
		}
		if err != nil {
			continue
		}
		key, err := receiptQuorumKey(receipt)
		if err != nil {
			s.recordQuorumFailure(bcosQuorumOperationReceipt, bcosQuorumFailureDisagreement)
			return fiscobcos.ReceiptWithProof{}, ambiguousDriverFailure("recover_receipt", driver.Endpoint(), err)
		}
		if selectedKey == nil {
			selected, selectedKey, matches = receipt, key, 1
			continue
		}
		if !bytes.Equal(selectedKey, key) {
			s.recordQuorumFailure(bcosQuorumOperationReceipt, bcosQuorumFailureDisagreement)
			return fiscobcos.ReceiptWithProof{}, ambiguousDriverFailure(
				"recover_receipt",
				driver.Endpoint(),
				fiscobcos.ErrEndpointDisagreement,
			)
		}
		matches++
	}
	if matches >= quorum {
		return selected, nil
	}
	if matches == 0 && notFound >= quorum {
		return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrTransactionNotFound
	}
	s.recordQuorumFailure(bcosQuorumOperationReceipt, bcosQuorumFailureInsufficient)
	return fiscobcos.ReceiptWithProof{}, ambiguousDriverFailure(
		"recover_receipt_quorum",
		s.drivers[0].Endpoint(),
		fiscobcos.ErrIncompleteChainEvidence,
	)
}

func receiptQuorumKey(receipt fiscobcos.ReceiptWithProof) ([]byte, error) {
	return cborx.Marshal(struct {
		Status        int64                           `cbor:"status"`
		StatusMessage string                          `cbor:"status_message"`
		BlockNumber   uint64                          `cbor:"block_number"`
		BlockHash     []byte                          `cbor:"block_hash"`
		Record        fiscobcos.AnchorRecord          `cbor:"record"`
		Event         fiscobcos.AnchorPublishedEvent  `cbor:"event"`
		Observation   fiscobcos.ReceiptRPCObservation `cbor:"observation"`
		Evidence      fiscobcos.ReceiptEvidence       `cbor:"evidence"`
	}{
		Status: int64(receipt.Status), StatusMessage: receipt.StatusMessage,
		BlockNumber: receipt.BlockNumber, BlockHash: receipt.BlockHash,
		Record: receipt.Record, Event: receipt.Event,
		Observation: receipt.Observation, Evidence: receipt.Evidence,
	})
}

func cloneByteSlices(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	cloned := make([][]byte, len(values))
	for index := range values {
		cloned[index] = append([]byte(nil), values[index]...)
	}
	return cloned
}

var _ DurableSink = (*FISCOBCOSStandardSink)(nil)
