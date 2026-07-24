package anchor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const minimumFISCOBCOSEndpoints = 2

type FISCOBCOSStandardSinkConfig struct {
	TrustConfig fiscobcos.TrustConfig
	Drivers     []fiscobcos.Driver
	Metrics     *observability.Metrics
	Logger      zerolog.Logger
	Clock       func() time.Time
}

// FISCOBCOSStandardSink owns quorum reads and exact payload/result binding.
// Drivers own network and SDK details. A successful Publish always includes
// transaction and receipt proof fields, an exact contract readback, the
// containing header, and a consensus snapshot; submission alone is never
// reported as an L5 result.
type FISCOBCOSStandardSink struct {
	trust   fiscobcos.TrustConfig
	drivers []fiscobcos.Driver
	metrics *observability.Metrics
	logger  zerolog.Logger
	clock   func() time.Time

	closeOnce sync.Once
	closeErr  error
}

func NewFISCOBCOSStandardSink(config FISCOBCOSStandardSinkConfig) (*FISCOBCOSStandardSink, error) {
	canonicalBytes, err := fiscobcos.MarshalTrustConfig(config.TrustConfig)
	if err != nil {
		return nil, err
	}
	trust, err := fiscobcos.UnmarshalTrustConfig(canonicalBytes)
	if err != nil {
		return nil, err
	}
	if trust.CryptoMode != fiscobcos.CryptoModeStandard {
		return nil, fmt.Errorf("%w: standard sink requires crypto_mode=standard", fiscobcos.ErrWrongNetwork)
	}
	if len(config.Drivers) < minimumFISCOBCOSEndpoints || trust.ReadQuorum < minimumFISCOBCOSEndpoints {
		return nil, fmt.Errorf("%w: standard sink requires at least two endpoints and read_quorum >= 2", fiscobcos.ErrDriverInvalid)
	}
	if int(trust.ReadQuorum) > len(config.Drivers) {
		return nil, fmt.Errorf("%w: read_quorum exceeds driver count", fiscobcos.ErrDriverInvalid)
	}
	drivers := append([]fiscobcos.Driver(nil), config.Drivers...)
	expected := make(map[string]struct{}, len(trust.Endpoints))
	for _, endpoint := range trust.Endpoints {
		expected[endpoint] = struct{}{}
	}
	seen := make(map[string]struct{}, len(drivers))
	for _, driver := range drivers {
		if driver == nil || strings.TrimSpace(driver.Endpoint()) == "" {
			return nil, fmt.Errorf("%w: nil driver or empty endpoint", fiscobcos.ErrDriverInvalid)
		}
		endpoint := driver.Endpoint()
		if _, ok := expected[endpoint]; !ok {
			return nil, fmt.Errorf("%w: driver endpoint %q is not in TrustConfig", fiscobcos.ErrWrongNetwork, endpoint)
		}
		if _, duplicate := seen[endpoint]; duplicate {
			return nil, fmt.Errorf("%w: duplicate driver endpoint %q", fiscobcos.ErrDriverInvalid, endpoint)
		}
		seen[endpoint] = struct{}{}
	}
	if len(seen) != len(expected) {
		return nil, fmt.Errorf("%w: every TrustConfig endpoint requires exactly one driver", fiscobcos.ErrDriverInvalid)
	}
	sort.Slice(drivers, func(i, j int) bool { return drivers[i].Endpoint() < drivers[j].Endpoint() })
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &FISCOBCOSStandardSink{
		trust: trust, drivers: drivers, metrics: config.Metrics, logger: config.Logger, clock: config.Clock,
	}, nil
}

func (*FISCOBCOSStandardSink) Name() string { return fiscobcos.SinkName }

// Probe validates every configured endpoint before a side effect. Requiring
// exact height equality is conservative by design for #464; bounded stale
// reads and quorum-height policy belong to the retry hardening in #470.
func (s *FISCOBCOSStandardSink) Probe(ctx context.Context) ([]fiscobcos.ChainProbe, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: nil standard sink", fiscobcos.ErrDriverInvalid)
	}
	type result struct {
		probe fiscobcos.ChainProbe
		err   error
	}
	s.setEndpointProbeMetrics(nil, false)
	results := make(chan result, len(s.drivers))
	for _, driver := range s.drivers {
		driver := driver
		go func() {
			probe, err := driver.ProbeChain(ctx)
			results <- result{probe: probe, err: err}
		}()
	}
	probes := make([]fiscobcos.ChainProbe, 0, len(s.drivers))
	for range s.drivers {
		item := <-results
		if item.err != nil {
			return nil, classifyDriverFailure("probe", item.probe.Endpoint, item.err)
		}
		if item.probe.Endpoint == "" {
			return nil, permanentDriverFailure("probe", "", fiscobcos.ErrDriverInvalid)
		}
		if err := validateProbeForSink(item.probe, s.trust); err != nil {
			return nil, err
		}
		probes = append(probes, cloneChainProbe(item.probe))
	}
	sort.Slice(probes, func(i, j int) bool { return probes[i].Endpoint < probes[j].Endpoint })
	for i := 1; i < len(probes); i++ {
		if !sameChainIdentity(probes[0], probes[i]) {
			return nil, permanentDriverFailure("probe", probes[i].Endpoint, fiscobcos.ErrEndpointDisagreement)
		}
		if probes[0].Height != probes[i].Height {
			return nil, transientDriverFailure("probe", probes[i].Endpoint, fiscobcos.ErrEndpointDisagreement)
		}
	}
	s.setEndpointProbeMetrics(probes, true)
	return probes, nil
}

func (s *FISCOBCOSStandardSink) setEndpointProbeMetrics(probes []fiscobcos.ChainProbe, healthy bool) {
	if s == nil || s.metrics == nil ||
		s.metrics.AnchorProviderEndpointHealthy == nil ||
		s.metrics.AnchorProviderEndpointHeight == nil {
		return
	}
	for index := range s.drivers {
		label := strconv.Itoa(index)
		value := 0.0
		if healthy {
			value = 1
		}
		s.metrics.AnchorProviderEndpointHealthy.WithLabelValues(fiscobcos.SinkName, label).Set(value)
		if index < len(probes) {
			s.metrics.AnchorProviderEndpointHeight.WithLabelValues(fiscobcos.SinkName, label).Set(float64(probes[index].Height))
		}
	}
}

func (s *FISCOBCOSStandardSink) Publish(ctx context.Context, sth model.SignedTreeHead) (model.STHAnchorResult, error) {
	if _, err := s.Probe(ctx); err != nil {
		return model.STHAnchorResult{}, mapSinkError(err)
	}
	payload, err := payloadForSTH(sth)
	if err != nil {
		return model.STHAnchorResult{}, fmt.Errorf("%w: %w", ErrPermanent, err)
	}
	canonicalPayload, err := fiscobcos.MarshalPayload(payload)
	if err != nil {
		return model.STHAnchorResult{}, fmt.Errorf("%w: %w", ErrPermanent, err)
	}
	request := fiscobcos.SubmitRequest{Payload: payload, CanonicalPayload: canonicalPayload}
	existing, err := s.readAnchorStateQuorum(ctx, payload)
	if err != nil {
		return model.STHAnchorResult{}, mapSinkError(err)
	}
	if existing {
		// An exact visible record prevents another side effect, but #464 does
		// not reconstruct the missing immutable transaction evidence. That
		// recovery belongs to #465/#470.
		return model.STHAnchorResult{}, &fiscobcos.DriverError{
			Operation: "recover_existing_anchor",
			Class:     fiscobcos.FailureAmbiguous,
			Kind:      fiscobcos.ErrExistingAnchorEvidenceUnavailable,
		}
	}
	submission, err := s.drivers[0].SubmitAnchor(ctx, request)
	if err != nil {
		return model.STHAnchorResult{}, mapSinkError(classifyDriverFailure("submit_anchor", s.drivers[0].Endpoint(), err))
	}
	if err := validateTransactionAttempt(submission.Attempt, s.trust, payload); err != nil {
		return model.STHAnchorResult{}, ambiguousDriverFailure("validate_submission", s.drivers[0].Endpoint(), err)
	}
	records, err := s.readAnchorQuorum(ctx, payload)
	if err != nil {
		return model.STHAnchorResult{}, mapSinkError(err)
	}
	receipt, err := s.drivers[0].GetReceiptWithProof(ctx, submission.Attempt)
	if err != nil {
		return model.STHAnchorResult{}, ambiguousDriverFailure("get_receipt_with_proof", s.drivers[0].Endpoint(), err)
	}
	if receipt.Status != fiscobcos.ReceiptStatusOK {
		statusErr := fiscobcos.NewReceiptStatusError(receipt.Status)
		classified := &fiscobcos.DriverError{
			Operation: "validate_receipt_status",
			Endpoint:  s.drivers[0].Endpoint(),
			Class:     statusErr.FailureClass(),
			Kind:      statusErr,
		}
		return model.STHAnchorResult{}, mapSinkError(classified)
	}
	if err := validateReceipt(s.trust, payload, submission.Attempt, receipt, records[0]); err != nil {
		return model.STHAnchorResult{}, ambiguousDriverFailure("validate_receipt", s.drivers[0].Endpoint(), err)
	}
	header, consensus, err := s.readBlockQuorum(ctx, receipt.BlockNumber, receipt.BlockHash)
	if err != nil {
		return model.STHAnchorResult{}, mapSinkError(err)
	}
	observation, err := s.buildObservation(canonicalPayload, submission.Attempt, receipt, header, consensus)
	if err != nil {
		return model.STHAnchorResult{}, ambiguousDriverFailure("build_publication_observation", s.drivers[0].Endpoint(), err)
	}
	proofBytes, err := fiscobcos.MarshalPublicationObservation(observation)
	if err != nil {
		return model.STHAnchorResult{}, ambiguousDriverFailure("marshal_publication_observation", s.drivers[0].Endpoint(), err)
	}
	return model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		NodeID:        sth.NodeID, LogID: sth.LogID, TreeSize: sth.TreeSize,
		SinkName: fiscobcos.SinkName, AnchorID: fiscobcos.AnchorIDString(payload),
		RootHash: append([]byte(nil), sth.RootHash...), STH: sth, Proof: proofBytes,
		EvidenceStage:    model.AnchorEvidenceStageRaw,
		PublishedAtUnixN: s.clock().UTC().UnixNano(),
	}, nil
}

func (s *FISCOBCOSStandardSink) readAnchorStateQuorum(ctx context.Context, payload fiscobcos.AnchorPayload) (bool, error) {
	var first fiscobcos.AnchorRecord
	for index, driver := range s.drivers {
		record, err := driver.ReadAnchor(ctx, payload.AnchorID)
		if err != nil {
			return false, classifyDriverFailure("read_anchor_before_submit", driver.Endpoint(), err)
		}
		if index == 0 {
			first = cloneAnchorRecord(record)
		} else if !sameAnchorRecord(first, record) {
			return false, transientDriverFailure("read_anchor_before_submit", driver.Endpoint(), fiscobcos.ErrEndpointDisagreement)
		}
		if record.Exists {
			if err := fiscobcos.ValidateAnchorRecord(payload, record); err != nil {
				return false, permanentDriverFailure("read_anchor_before_submit", driver.Endpoint(), err)
			}
		} else if len(record.StreamID) != 0 || record.TreeSize != 0 || len(record.RootHash) != 0 ||
			len(record.SignedSTHDigest) != 0 || len(record.Publisher) != 0 || record.PayloadVersion != 0 {
			return false, permanentDriverFailure("read_anchor_before_submit", driver.Endpoint(), fiscobcos.ErrDriverInvalid)
		}
	}
	return first.Exists, nil
}

func (s *FISCOBCOSStandardSink) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		var errs []error
		for _, driver := range s.drivers {
			if err := driver.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close FISCO BCOS endpoint driver: %w", err))
			}
		}
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

func (s *FISCOBCOSStandardSink) System(context.Context) (model.AnchorSystem, error) {
	if s == nil {
		return model.AnchorSystem{}, trusterr.New(trusterr.CodeFailedPrecondition, "FISCO BCOS anchor sink is not configured")
	}
	return model.AnchorSystem{
		SchemaVersion: model.SchemaAnchorSystem,
		SystemID:      "fisco-bcos-standard",
		SinkName:      fiscobcos.SinkName,
		DisplayName:   "FISCO BCOS standard-crypto anchor",
		Kind:          model.AnchorSystemKindEvidenceBlockchain,
		Network:       s.trust.ChainID,
		Provider:      "FISCO BCOS",
		Capabilities: []string{
			model.AnchorCapabilityPublish,
			model.AnchorCapabilityEvidenceRead,
			model.AnchorCapabilitySystemStatusRead,
		},
		Assurance: model.AnchorAssurance{
			Decentralized: true,
			Finality:      "PBFT observation; offline proof verification pending",
			Custody:       s.trust.AccountProvider.Provider,
		},
		Metadata: map[string]string{
			"chain_id":       s.trust.ChainID,
			"group_id":       s.trust.GroupID,
			"crypto_mode":    string(s.trust.CryptoMode),
			"sdk_version":    fiscobcos.StandardSDKVersion,
			"endpoint_count": strconv.Itoa(len(s.drivers)),
		},
	}, nil
}

func (s *FISCOBCOSStandardSink) Status(ctx context.Context) (model.AnchorSystemStatus, error) {
	status := model.AnchorSystemStatus{
		SchemaVersion:   model.SchemaAnchorSystemStatus,
		SystemID:        "fisco-bcos-standard",
		State:           model.AnchorSystemStateUnavailable,
		ObservedAtUnixN: s.clock().UTC().UnixNano(),
		Message:         "provider identity probe failed",
	}
	probes, err := s.Probe(ctx)
	if err != nil {
		switch {
		case errors.Is(err, fiscobcos.ErrStaleEndpoint), errors.Is(err, fiscobcos.ErrEndpointDisagreement):
			status.State = model.AnchorSystemStateDegraded
			status.Message = "provider endpoints have not converged"
		case errors.Is(err, fiscobcos.ErrWrongNetwork), errors.Is(err, fiscobcos.ErrContractMismatch):
			status.Message = "provider trust identity mismatch"
		}
		return status, nil
	}
	status.State = model.AnchorSystemStateHealthy
	status.Message = "all configured endpoints agree"
	status.Details = map[string]string{
		"chain_id":       s.trust.ChainID,
		"group_id":       s.trust.GroupID,
		"height":         strconv.FormatUint(probes[0].Height, 10),
		"endpoint_count": strconv.Itoa(len(probes)),
	}
	return status, nil
}

func (*FISCOBCOSStandardSink) ListResources(context.Context, model.AnchorResourceListOptions) (model.AnchorSystemResourcePage, error) {
	return model.AnchorSystemResourcePage{}, trusterr.New(trusterr.CodeFailedPrecondition, "FISCO BCOS explorer resources are not exposed by the anchor driver")
}

func (*FISCOBCOSStandardSink) Resource(context.Context, string, string) (model.AnchorSystemResource, bool, error) {
	return model.AnchorSystemResource{}, false, trusterr.New(trusterr.CodeFailedPrecondition, "FISCO BCOS explorer resources are not exposed by the anchor driver")
}

func (s *FISCOBCOSStandardSink) readAnchorQuorum(ctx context.Context, payload fiscobcos.AnchorPayload) ([]fiscobcos.AnchorRecord, error) {
	records := make([]fiscobcos.AnchorRecord, 0, len(s.drivers))
	for _, driver := range s.drivers {
		record, err := driver.ReadAnchor(ctx, payload.AnchorID)
		if err != nil {
			return nil, ambiguousDriverFailure("read_anchor", driver.Endpoint(), err)
		}
		if len(records) > 0 && !sameAnchorRecord(records[0], record) {
			return nil, ambiguousDriverFailure("read_anchor", driver.Endpoint(), fiscobcos.ErrEndpointDisagreement)
		}
		if !record.Exists {
			return nil, ambiguousDriverFailure("read_anchor", driver.Endpoint(), fiscobcos.ErrIncompleteChainEvidence)
		}
		if err := fiscobcos.ValidateAnchorRecord(payload, record); err != nil {
			return nil, ambiguousDriverFailure("read_anchor", driver.Endpoint(), err)
		}
		records = append(records, cloneAnchorRecord(record))
	}
	return records, nil
}

func (s *FISCOBCOSStandardSink) readBlockQuorum(ctx context.Context, blockNumber uint64, blockHash []byte) (fiscobcos.BlockHeader, fiscobcos.ConsensusSnapshot, error) {
	var selectedHeader fiscobcos.BlockHeader
	var selectedConsensus fiscobcos.ConsensusSnapshot
	for index, driver := range s.drivers {
		header, err := driver.GetBlockHeader(ctx, blockNumber)
		if err != nil {
			return fiscobcos.BlockHeader{}, fiscobcos.ConsensusSnapshot{}, ambiguousDriverFailure("get_block_header", driver.Endpoint(), err)
		}
		consensus, err := driver.GetConsensusSnapshot(ctx, blockNumber)
		if err != nil {
			return fiscobcos.BlockHeader{}, fiscobcos.ConsensusSnapshot{}, ambiguousDriverFailure("get_consensus_snapshot", driver.Endpoint(), err)
		}
		if err := validateBlockObservation(blockNumber, blockHash, header, consensus); err != nil {
			return fiscobcos.BlockHeader{}, fiscobcos.ConsensusSnapshot{}, ambiguousDriverFailure("read_block", driver.Endpoint(), err)
		}
		if index == 0 {
			selectedHeader = cloneBlockHeader(header)
			selectedConsensus = cloneConsensus(consensus)
			continue
		}
		if !sameBlockHeader(selectedHeader, header) || !sameConsensusSnapshot(selectedConsensus, consensus) {
			return fiscobcos.BlockHeader{}, fiscobcos.ConsensusSnapshot{}, ambiguousDriverFailure("read_block", driver.Endpoint(), fiscobcos.ErrEndpointDisagreement)
		}
	}
	return selectedHeader, selectedConsensus, nil
}

func (s *FISCOBCOSStandardSink) buildObservation(payload []byte, attempt fiscobcos.TransactionSubmission, receipt fiscobcos.ReceiptWithProof, header fiscobcos.BlockHeader, consensus fiscobcos.ConsensusSnapshot) (fiscobcos.PublicationObservation, error) {
	contextID, err := fiscobcos.ChainContextID(s.trust)
	if err != nil {
		return fiscobcos.PublicationObservation{}, err
	}
	return fiscobcos.PublicationObservation{
		SchemaVersion:     fiscobcos.SchemaPublicationObservation,
		EvidenceStage:     model.AnchorEvidenceStageRaw,
		CryptoMode:        s.trust.CryptoMode,
		ChainID:           s.trust.ChainID,
		GroupID:           s.trust.GroupID,
		GenesisHash:       append([]byte(nil), s.trust.GenesisHash...),
		TrustedCheckpoint: s.trust.TrustedCheckpoint,
		Contract:          s.trust.Contract,
		ChainContextID:    contextID,
		CanonicalPayload:  append([]byte(nil), payload...),
		Transaction:       attempt,
		Receipt:           receipt.Observation,
		Event:             receipt.Event,
		Readback:          receipt.Record,
		Block:             header.Observation,
		Consensus:         consensus,
	}, nil
}

func payloadForSTH(sth model.SignedTreeHead) (fiscobcos.AnchorPayload, error) {
	var matched []fiscobcos.AnchorPayload
	for _, suite := range []cryptosuite.ID{cryptosuite.INTLV1, cryptosuite.CNSMV1} {
		payload, err := fiscobcos.NewAnchorPayload(suite, sth)
		if err == nil {
			matched = append(matched, payload)
		}
	}
	if len(matched) != 1 {
		return fiscobcos.AnchorPayload{}, fmt.Errorf("%w: signed STH matches %d suites", fiscobcos.ErrInvalidPayload, len(matched))
	}
	return matched[0], nil
}

func validateTransactionAttempt(attempt fiscobcos.TransactionSubmission, trust fiscobcos.TrustConfig, payload fiscobcos.AnchorPayload) error {
	callData, err := fiscobcos.PublishCallData(payload)
	if err != nil {
		return err
	}
	if len(attempt.EncodedTransaction) == 0 || len(attempt.Signature) != 65 ||
		attempt.ChainID != trust.ChainID ||
		attempt.GroupID != trust.GroupID ||
		!bytes.Equal(attempt.To, trust.Contract.Address) ||
		!bytes.Equal(attempt.Input, callData) ||
		len(attempt.Sender) != 20 || len(attempt.TransactionHash) != 32 ||
		attempt.BlockLimit == 0 || attempt.SubmittedAtUnixN <= 0 {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	return nil
}

func validateReceipt(trust fiscobcos.TrustConfig, payload fiscobcos.AnchorPayload, attempt fiscobcos.TransactionSubmission, receipt fiscobcos.ReceiptWithProof, quorumRecord fiscobcos.AnchorRecord) error {
	if receipt.BlockNumber == 0 || len(receipt.BlockHash) != 32 ||
		!bytes.Equal(receipt.Observation.TransactionHash, attempt.TransactionHash) ||
		len(receipt.Observation.NormalizedRPCReceipt) == 0 ||
		len(receipt.Observation.ReceiptHashClaim) != 32 ||
		receipt.Observation.TransactionProofRPC == nil ||
		receipt.Observation.ReceiptProofRPC == nil {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	if err := fiscobcos.ValidateAnchorRecord(payload, receipt.Record); err != nil {
		return err
	}
	if !sameAnchorRecord(receipt.Record, quorumRecord) {
		return fiscobcos.ErrEndpointDisagreement
	}
	event := receipt.Event
	if !bytes.Equal(event.ContractAddress, trust.Contract.Address) ||
		!bytes.Equal(event.AnchorID, payload.AnchorID) ||
		!bytes.Equal(event.StreamID, payload.StreamID) ||
		event.TreeSize != payload.TreeSize ||
		!bytes.Equal(event.RootHash, payload.RootHash) ||
		!bytes.Equal(event.SignedSTHDigest, payload.SignedSTHDigest) ||
		event.PayloadVersion != payload.Version ||
		!bytes.Equal(event.Publisher, receipt.Record.Publisher) ||
		!bytes.Equal(event.Publisher, attempt.Sender) ||
		event.LogIndex != receipt.Observation.AnchorLogIndex ||
		len(event.NormalizedRPCLog) == 0 {
		return fiscobcos.ErrContractMismatch
	}
	return nil
}

func validateBlockObservation(blockNumber uint64, blockHash []byte, header fiscobcos.BlockHeader, consensus fiscobcos.ConsensusSnapshot) error {
	if blockNumber == 0 || header.Observation.BlockNumber != blockNumber ||
		len(header.Observation.NormalizedRPCHeader) == 0 ||
		!bytes.Equal(header.Observation.BlockHashClaim, blockHash) ||
		consensus.BlockNumber != blockNumber ||
		!bytes.Equal(consensus.BlockHash, blockHash) ||
		len(consensus.Finality.Signatures) == 0 {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	return nil
}

func validateProbeForSink(probe fiscobcos.ChainProbe, trust fiscobcos.TrustConfig) error {
	if probe.SDKVersion != fiscobcos.StandardSDKVersion {
		return permanentDriverFailure("probe", probe.Endpoint, fiscobcos.ErrUnsupportedSDK)
	}
	if probe.CryptoMode != fiscobcos.CryptoModeStandard ||
		probe.ChainID != trust.ChainID || probe.GroupID != trust.GroupID ||
		!bytes.Equal(probe.GenesisHash, trust.GenesisHash) ||
		!bytes.Equal(probe.CheckpointHash, trust.TrustedCheckpoint.BlockHash) {
		return permanentDriverFailure("probe", probe.Endpoint, fiscobcos.ErrWrongNetwork)
	}
	if probe.Height < trust.TrustedCheckpoint.BlockNumber {
		return &fiscobcos.DriverError{Operation: "probe", Endpoint: probe.Endpoint, Class: fiscobcos.FailureTransient, Kind: fiscobcos.ErrStaleEndpoint}
	}
	if !bytes.Equal(probe.ContractCodeHash, trust.Contract.CodeHash) {
		return permanentDriverFailure("probe", probe.Endpoint, fiscobcos.ErrContractMismatch)
	}
	return nil
}

func sameChainIdentity(left, right fiscobcos.ChainProbe) bool {
	return left.SDKVersion == right.SDKVersion && left.CryptoMode == right.CryptoMode &&
		left.ChainID == right.ChainID && left.GroupID == right.GroupID &&
		bytes.Equal(left.GenesisHash, right.GenesisHash) &&
		bytes.Equal(left.CheckpointHash, right.CheckpointHash) &&
		bytes.Equal(left.ContractCodeHash, right.ContractCodeHash)
}

func sameAnchorRecord(left, right fiscobcos.AnchorRecord) bool {
	return bytes.Equal(left.StreamID, right.StreamID) && left.TreeSize == right.TreeSize &&
		bytes.Equal(left.RootHash, right.RootHash) &&
		bytes.Equal(left.SignedSTHDigest, right.SignedSTHDigest) &&
		bytes.Equal(left.Publisher, right.Publisher) &&
		left.PayloadVersion == right.PayloadVersion && left.Exists == right.Exists
}

func sameBlockHeader(left, right fiscobcos.BlockHeader) bool {
	return left.Observation.BlockNumber == right.Observation.BlockNumber &&
		bytes.Equal(left.Observation.BlockHashClaim, right.Observation.BlockHashClaim) &&
		bytes.Equal(left.Observation.NormalizedRPCHeader, right.Observation.NormalizedRPCHeader)
}

func sameConsensusSnapshot(left, right fiscobcos.ConsensusSnapshot) bool {
	if left.BlockNumber != right.BlockNumber || !bytes.Equal(left.BlockHash, right.BlockHash) ||
		!sameOptionalUint64(left.Finality.View, right.Finality.View) ||
		!sameOptionalUint64(left.Finality.Round, right.Finality.Round) ||
		len(left.Finality.Signatures) != len(right.Finality.Signatures) {
		return false
	}
	for i := range left.Finality.Signatures {
		if left.Finality.Signatures[i].ValidatorNodeID != right.Finality.Signatures[i].ValidatorNodeID ||
			!bytes.Equal(left.Finality.Signatures[i].Signature, right.Finality.Signatures[i].Signature) {
			return false
		}
	}
	return true
}

func sameOptionalUint64(left, right *uint64) bool {
	return left == nil && right == nil ||
		left != nil && right != nil && *left == *right
}

func permanentDriverFailure(operation, endpoint string, kind error) error {
	return &fiscobcos.DriverError{Operation: operation, Endpoint: endpoint, Class: fiscobcos.FailurePermanent, Kind: kind}
}

func transientDriverFailure(operation, endpoint string, kind error) error {
	return &fiscobcos.DriverError{Operation: operation, Endpoint: endpoint, Class: fiscobcos.FailureTransient, Kind: kind}
}

func ambiguousDriverFailure(operation, endpoint string, kind error) error {
	return &fiscobcos.DriverError{Operation: operation, Endpoint: endpoint, Class: fiscobcos.FailureAmbiguous, Kind: kind}
}

func classifyDriverFailure(operation, endpoint string, err error) error {
	if err == nil {
		return nil
	}
	var classified *fiscobcos.DriverError
	if errors.As(err, &classified) {
		return err
	}
	return &fiscobcos.DriverError{Operation: operation, Endpoint: endpoint, Class: fiscobcos.FailureTransient, Kind: err}
}

func mapSinkError(err error) error {
	if fiscobcos.IsPermanentDriverError(err) {
		return fmt.Errorf("%w: %w", ErrPermanent, err)
	}
	return err
}

func cloneChainProbe(in fiscobcos.ChainProbe) fiscobcos.ChainProbe {
	in.GenesisHash = append([]byte(nil), in.GenesisHash...)
	in.CheckpointHash = append([]byte(nil), in.CheckpointHash...)
	in.ContractCodeHash = append([]byte(nil), in.ContractCodeHash...)
	return in
}

func cloneAnchorRecord(in fiscobcos.AnchorRecord) fiscobcos.AnchorRecord {
	in.StreamID = append([]byte(nil), in.StreamID...)
	in.RootHash = append([]byte(nil), in.RootHash...)
	in.SignedSTHDigest = append([]byte(nil), in.SignedSTHDigest...)
	in.Publisher = append([]byte(nil), in.Publisher...)
	return in
}

func cloneBlockHeader(in fiscobcos.BlockHeader) fiscobcos.BlockHeader {
	in.Observation.NormalizedRPCHeader = append([]byte(nil), in.Observation.NormalizedRPCHeader...)
	in.Observation.BlockHashClaim = append([]byte(nil), in.Observation.BlockHashClaim...)
	return in
}

func cloneConsensus(in fiscobcos.ConsensusSnapshot) fiscobcos.ConsensusSnapshot {
	in.BlockHash = append([]byte(nil), in.BlockHash...)
	in.Finality.Signatures = append([]fiscobcos.CommitSignature(nil), in.Finality.Signatures...)
	for i := range in.Finality.Signatures {
		in.Finality.Signatures[i].Signature = append([]byte(nil), in.Finality.Signatures[i].Signature...)
	}
	return in
}
