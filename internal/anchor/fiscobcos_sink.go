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
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const (
	minimumFISCOBCOSEndpoints        = 2
	maxFISCOBCOSEndpointHeightLag    = uint64(2)
	bcosQuorumOperationProbe         = "probe"
	bcosQuorumOperationAnchor        = "anchor"
	bcosQuorumOperationReceipt       = "receipt"
	bcosQuorumOperationBlock         = "block"
	bcosQuorumOperationHistory       = "validator_history"
	bcosQuorumFailureInsufficient    = "insufficient"
	bcosQuorumFailureDisagreement    = "disagreement"
	bcosRetryReasonExactTransaction  = "exact_transaction"
	bcosRetryReasonBlockLimitRefresh = "block_limit_refresh"
	bcosRetryReasonDuplicateLookup   = "duplicate_lookup"
)

type bcosProbeObservation struct {
	probe   fiscobcos.ChainProbe
	err     error
	healthy bool
	stale   bool
}

type bcosQuorumRoute struct {
	probes           []fiscobcos.ChainProbe
	driver           fiscobcos.Driver
	height           uint64
	healthyEndpoints map[string]struct{}
	healthyCount     int
	degraded         bool
}

func (route bcosQuorumRoute) isHealthy(endpoint string) bool {
	_, ok := route.healthyEndpoints[endpoint]
	return ok
}

type FISCOBCOSStandardSinkConfig struct {
	TrustConfig fiscobcos.TrustConfig
	Drivers     []fiscobcos.Driver
	Metrics     *observability.Metrics
	Logger      zerolog.Logger
	Clock       func() time.Time
}

// FISCOBCOSStandardSink owns quorum reads and exact payload/result binding for
// both explicitly configured FISCO BCOS cryptographic modes.
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
	if len(config.Drivers) < minimumFISCOBCOSEndpoints || trust.ReadQuorum < minimumFISCOBCOSEndpoints {
		return nil, fmt.Errorf("%w: FISCO BCOS sink requires at least two endpoints and read_quorum >= 2", fiscobcos.ErrDriverInvalid)
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

// Probe validates configured endpoints and returns the identity-matched,
// non-stale observations. A failed or lagging minority does not stop a read
// quorum, while any responding trust-identity mismatch remains fail-closed.
func (s *FISCOBCOSStandardSink) Probe(ctx context.Context) ([]fiscobcos.ChainProbe, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: nil FISCO BCOS sink", fiscobcos.ErrDriverInvalid)
	}
	route, err := s.probeQuorum(ctx)
	if err != nil {
		return nil, err
	}
	return route.probes, nil
}

func (s *FISCOBCOSStandardSink) probeQuorum(ctx context.Context) (bcosQuorumRoute, error) {
	type result struct {
		index int
		probe fiscobcos.ChainProbe
		err   error
	}
	results := make(chan result, len(s.drivers))
	for index, driver := range s.drivers {
		index := index
		driver := driver
		go func() {
			probe, err := driver.ProbeChain(ctx)
			results <- result{index: index, probe: probe, err: err}
		}()
	}
	observations := make([]bcosProbeObservation, len(s.drivers))
	for range s.drivers {
		item := <-results
		endpoint := s.drivers[item.index].Endpoint()
		if item.err != nil {
			classified := classifyDriverFailure("probe", endpoint, item.err)
			if fiscobcos.IsPermanentDriverError(classified) {
				s.setEndpointProbeMetrics(observations, false)
				return bcosQuorumRoute{}, classified
			}
			observations[item.index].err = classified
			continue
		}
		if item.probe.Endpoint != endpoint {
			s.setEndpointProbeMetrics(observations, false)
			return bcosQuorumRoute{}, permanentDriverFailure("probe", endpoint, fiscobcos.ErrDriverInvalid)
		}
		if err := validateProbeForSink(item.probe, s.trust); err != nil {
			if fiscobcos.IsPermanentDriverError(err) {
				s.setEndpointProbeMetrics(observations, false)
				return bcosQuorumRoute{}, err
			}
			observations[item.index] = bcosProbeObservation{probe: cloneChainProbe(item.probe), err: err, stale: true}
			continue
		}
		observations[item.index].probe = cloneChainProbe(item.probe)
	}

	type heightObservation struct {
		index  int
		height uint64
	}
	heights := make([]heightObservation, 0, len(observations))
	var identity *fiscobcos.ChainProbe
	for index := range observations {
		if observations[index].err != nil || observations[index].probe.Endpoint == "" {
			continue
		}
		if identity == nil {
			candidate := cloneChainProbe(observations[index].probe)
			identity = &candidate
		} else if !sameChainIdentity(*identity, observations[index].probe) {
			s.setEndpointProbeMetrics(observations, false)
			return bcosQuorumRoute{}, permanentDriverFailure(
				"probe",
				observations[index].probe.Endpoint,
				fiscobcos.ErrEndpointDisagreement,
			)
		}
		heights = append(heights, heightObservation{index: index, height: observations[index].probe.Height})
	}
	quorum := int(s.trust.ReadQuorum)
	if len(heights) < quorum {
		s.setEndpointProbeMetrics(observations, false)
		s.recordQuorumFailure(bcosQuorumOperationProbe, bcosQuorumFailureInsufficient)
		return bcosQuorumRoute{}, transientDriverFailure(
			"probe_quorum",
			s.drivers[0].Endpoint(),
			fiscobcos.ErrIncompleteChainEvidence,
		)
	}
	sort.Slice(heights, func(i, j int) bool {
		if heights[i].height != heights[j].height {
			return heights[i].height > heights[j].height
		}
		return s.drivers[heights[i].index].Endpoint() < s.drivers[heights[j].index].Endpoint()
	})
	quorumHeight := heights[quorum-1].height
	healthyCount := 0
	healthyEndpoints := make(map[string]struct{}, len(heights))
	probes := make([]fiscobcos.ChainProbe, 0, len(heights))
	var selected fiscobcos.Driver
	for index := range observations {
		observation := &observations[index]
		if observation.err != nil || observation.probe.Endpoint == "" {
			continue
		}
		if quorumHeight > observation.probe.Height &&
			quorumHeight-observation.probe.Height > maxFISCOBCOSEndpointHeightLag {
			observation.stale = true
			continue
		}
		observation.healthy = true
		healthyCount++
		healthyEndpoints[observation.probe.Endpoint] = struct{}{}
		probes = append(probes, cloneChainProbe(observation.probe))
		if selected == nil {
			selected = s.drivers[index]
		}
	}
	if healthyCount < quorum || selected == nil {
		s.setEndpointProbeMetrics(observations, false)
		s.recordQuorumFailure(bcosQuorumOperationProbe, bcosQuorumFailureInsufficient)
		return bcosQuorumRoute{}, transientDriverFailure(
			"probe_quorum",
			s.drivers[0].Endpoint(),
			fiscobcos.ErrStaleEndpoint,
		)
	}
	s.setEndpointProbeMetrics(observations, true)
	return bcosQuorumRoute{
		probes: probes, driver: selected, height: quorumHeight,
		healthyEndpoints: healthyEndpoints,
		healthyCount:     healthyCount, degraded: healthyCount != len(s.drivers),
	}, nil
}

func (s *FISCOBCOSStandardSink) setEndpointProbeMetrics(observations []bcosProbeObservation, quorumHealthy bool) {
	if s == nil || s.metrics == nil {
		return
	}
	if s.metrics.AnchorProviderQuorumHealthy != nil {
		value := 0.0
		if quorumHealthy {
			value = 1
		}
		s.metrics.AnchorProviderQuorumHealthy.WithLabelValues(fiscobcos.SinkName).Set(value)
	}
	for index := range s.drivers {
		label := strconv.Itoa(index)
		var observation bcosProbeObservation
		if index < len(observations) {
			observation = observations[index]
		}
		if s.metrics.AnchorProviderEndpointHealthy != nil {
			value := 0.0
			if observation.healthy {
				value = 1
			}
			s.metrics.AnchorProviderEndpointHealthy.WithLabelValues(fiscobcos.SinkName, label).Set(value)
		}
		if s.metrics.AnchorProviderEndpointStale != nil {
			value := 0.0
			if observation.stale {
				value = 1
			}
			s.metrics.AnchorProviderEndpointStale.WithLabelValues(fiscobcos.SinkName, label).Set(value)
		}
		if s.metrics.AnchorProviderEndpointHeight != nil && observation.probe.Endpoint != "" {
			s.metrics.AnchorProviderEndpointHeight.WithLabelValues(fiscobcos.SinkName, label).Set(float64(observation.probe.Height))
		}
	}
}

func (s *FISCOBCOSStandardSink) Publish(ctx context.Context, sth model.SignedTreeHead) (model.STHAnchorResult, error) {
	_ = ctx
	_ = sth
	return model.STHAnchorResult{}, fmt.Errorf(
		"%w: FISCO BCOS publication requires the durable scheduler checkpoint path",
		ErrPermanent,
	)
}

func (s *FISCOBCOSStandardSink) readAnchorStateQuorum(
	ctx context.Context,
	payload fiscobcos.AnchorPayload,
	route bcosQuorumRoute,
) (bool, error) {
	quorum := int(s.trust.ReadQuorum)
	exact := 0
	absent := 0
	positiveSeen := false
	var selected fiscobcos.AnchorRecord
	for _, driver := range s.drivers {
		record, err := driver.ReadAnchor(ctx, payload.AnchorID)
		if err != nil {
			continue
		}
		if record.Exists {
			positiveSeen = true
			if err := fiscobcos.ValidateAnchorRecord(payload, record); err != nil {
				s.recordQuorumFailure(bcosQuorumOperationAnchor, bcosQuorumFailureDisagreement)
				return false, permanentDriverFailure("read_anchor_before_submit", driver.Endpoint(), err)
			}
			if exact == 0 {
				selected = cloneAnchorRecord(record)
			} else if !sameAnchorRecord(selected, record) {
				s.recordQuorumFailure(bcosQuorumOperationAnchor, bcosQuorumFailureDisagreement)
				return false, permanentDriverFailure("read_anchor_before_submit", driver.Endpoint(), fiscobcos.ErrEndpointDisagreement)
			}
			if route.isHealthy(driver.Endpoint()) {
				exact++
			}
		} else if len(record.StreamID) != 0 || record.TreeSize != 0 || len(record.RootHash) != 0 ||
			len(record.SignedSTHDigest) != 0 || len(record.Publisher) != 0 || record.PayloadVersion != 0 {
			return false, permanentDriverFailure("read_anchor_before_submit", driver.Endpoint(), fiscobcos.ErrDriverInvalid)
		} else if route.isHealthy(driver.Endpoint()) {
			absent++
		}
	}
	if exact >= quorum {
		return true, nil
	}
	// Any exact positive observation means a side effect may already exist.
	// An absent quorum cannot authorize a duplicate submission until the
	// positive observation is either corroborated or proven conflicting.
	if positiveSeen {
		s.recordQuorumFailure(bcosQuorumOperationAnchor, bcosQuorumFailureInsufficient)
		return false, ambiguousDriverFailure("read_anchor_before_submit", s.drivers[0].Endpoint(), fiscobcos.ErrIncompleteChainEvidence)
	}
	if absent < quorum {
		s.recordQuorumFailure(bcosQuorumOperationAnchor, bcosQuorumFailureInsufficient)
		return false, ambiguousDriverFailure("read_anchor_before_submit", s.drivers[0].Endpoint(), fiscobcos.ErrIncompleteChainEvidence)
	}
	return false, nil
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
		SystemID:      s.systemID(),
		SinkName:      fiscobcos.SinkName,
		DisplayName:   "FISCO BCOS " + string(s.trust.CryptoMode) + "-crypto anchor",
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
			Finality:      "PBFT commit evidence; offline verification uses the local checkpoint and validator-transition policy",
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
		SystemID:        s.systemID(),
		State:           model.AnchorSystemStateUnavailable,
		ObservedAtUnixN: s.clock().UTC().UnixNano(),
		Message:         "provider identity probe failed",
	}
	route, err := s.probeQuorum(ctx)
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
	status.Message = "provider read quorum is healthy"
	if route.degraded {
		status.State = model.AnchorSystemStateDegraded
		status.Message = "provider read quorum is healthy with unavailable or stale endpoints"
	}
	status.Details = map[string]string{
		"chain_id":       s.trust.ChainID,
		"group_id":       s.trust.GroupID,
		"height":         strconv.FormatUint(route.height, 10),
		"endpoint_count": strconv.Itoa(len(s.drivers)),
		"healthy_count":  strconv.Itoa(route.healthyCount),
	}
	return status, nil
}

func (s *FISCOBCOSStandardSink) systemID() string {
	return "fisco-bcos-" + string(s.trust.CryptoMode)
}

func (*FISCOBCOSStandardSink) ListResources(context.Context, model.AnchorResourceListOptions) (model.AnchorSystemResourcePage, error) {
	return model.AnchorSystemResourcePage{}, trusterr.New(trusterr.CodeFailedPrecondition, "FISCO BCOS explorer resources are not exposed by the anchor driver")
}

func (*FISCOBCOSStandardSink) Resource(context.Context, string, string) (model.AnchorSystemResource, bool, error) {
	return model.AnchorSystemResource{}, false, trusterr.New(trusterr.CodeFailedPrecondition, "FISCO BCOS explorer resources are not exposed by the anchor driver")
}

func (s *FISCOBCOSStandardSink) readAnchorQuorum(
	ctx context.Context,
	payload fiscobcos.AnchorPayload,
	route bcosQuorumRoute,
) ([]fiscobcos.AnchorRecord, error) {
	records := make([]fiscobcos.AnchorRecord, 0, len(s.drivers))
	var selected *fiscobcos.AnchorRecord
	for _, driver := range s.drivers {
		record, err := driver.ReadAnchor(ctx, payload.AnchorID)
		if err != nil {
			continue
		}
		if !record.Exists {
			if len(record.StreamID) != 0 || record.TreeSize != 0 || len(record.RootHash) != 0 ||
				len(record.SignedSTHDigest) != 0 || len(record.Publisher) != 0 || record.PayloadVersion != 0 {
				return nil, permanentDriverFailure("read_anchor", driver.Endpoint(), fiscobcos.ErrDriverInvalid)
			}
			continue
		}
		if err := fiscobcos.ValidateAnchorRecord(payload, record); err != nil {
			s.recordQuorumFailure(bcosQuorumOperationAnchor, bcosQuorumFailureDisagreement)
			return nil, permanentDriverFailure("read_anchor", driver.Endpoint(), err)
		}
		if selected != nil && !sameAnchorRecord(*selected, record) {
			s.recordQuorumFailure(bcosQuorumOperationAnchor, bcosQuorumFailureDisagreement)
			return nil, permanentDriverFailure("read_anchor", driver.Endpoint(), fiscobcos.ErrEndpointDisagreement)
		}
		if selected == nil {
			cloned := cloneAnchorRecord(record)
			selected = &cloned
		}
		if route.isHealthy(driver.Endpoint()) {
			records = append(records, cloneAnchorRecord(record))
		}
	}
	if len(records) < int(s.trust.ReadQuorum) {
		s.recordQuorumFailure(bcosQuorumOperationAnchor, bcosQuorumFailureInsufficient)
		return nil, ambiguousDriverFailure("read_anchor", s.drivers[0].Endpoint(), fiscobcos.ErrIncompleteChainEvidence)
	}
	return records, nil
}

func (s *FISCOBCOSStandardSink) readBlockQuorum(
	ctx context.Context,
	blockNumber uint64,
	blockHash []byte,
	route bcosQuorumRoute,
) (fiscobcos.BlockHeader, fiscobcos.ConsensusSnapshot, error) {
	var selectedHeader fiscobcos.BlockHeader
	var selectedConsensus fiscobcos.ConsensusSnapshot
	successes := 0
	for _, driver := range s.drivers {
		header, err := driver.GetBlockHeader(ctx, blockNumber)
		if err != nil {
			continue
		}
		consensus, err := driver.GetConsensusSnapshot(ctx, blockNumber)
		if err != nil {
			continue
		}
		if err := validateBlockObservation(blockNumber, blockHash, s.trust.ChainHashAlgorithm, header, consensus); err != nil {
			s.recordQuorumFailure(bcosQuorumOperationBlock, bcosQuorumFailureDisagreement)
			return fiscobcos.BlockHeader{}, fiscobcos.ConsensusSnapshot{}, ambiguousDriverFailure("read_block", driver.Endpoint(), err)
		}
		if selectedHeader.Evidence.BlockNumber == 0 {
			selectedHeader = cloneBlockHeader(header)
			selectedConsensus = cloneConsensus(consensus)
		} else if !sameBlockHeader(selectedHeader, header) || !sameConsensusSnapshot(selectedConsensus, consensus) {
			s.recordQuorumFailure(bcosQuorumOperationBlock, bcosQuorumFailureDisagreement)
			return fiscobcos.BlockHeader{}, fiscobcos.ConsensusSnapshot{}, ambiguousDriverFailure("read_block", driver.Endpoint(), fiscobcos.ErrEndpointDisagreement)
		}
		if route.isHealthy(driver.Endpoint()) {
			successes++
		}
	}
	if successes < int(s.trust.ReadQuorum) {
		s.recordQuorumFailure(bcosQuorumOperationBlock, bcosQuorumFailureInsufficient)
		return fiscobcos.BlockHeader{}, fiscobcos.ConsensusSnapshot{}, ambiguousDriverFailure("read_block", s.drivers[0].Endpoint(), fiscobcos.ErrIncompleteChainEvidence)
	}
	return selectedHeader, selectedConsensus, nil
}

func (s *FISCOBCOSStandardSink) collectValidatorHistory(
	ctx context.Context,
	target fiscobcos.BlockEvidence,
	route bcosQuorumRoute,
) ([]fiscobcos.ValidatorHistoryBlock, error) {
	if s.trust.ValidatorTransitionPolicy == fiscobcos.ValidatorPolicyStatic {
		return nil, nil
	}
	if s.trust.ValidatorTransitionPolicy != fiscobcos.ValidatorPolicyTransitions {
		return nil, permanentDriverFailure("validator_history", s.drivers[0].Endpoint(), fiscobcos.ErrInvalidTrustConfig)
	}
	if target.BlockNumber <= s.trust.TrustedCheckpoint.BlockNumber {
		return nil, nil
	}
	delta := target.BlockNumber - s.trust.TrustedCheckpoint.BlockNumber
	if delta > fiscobcos.MaxValidatorHistoryBlocks {
		return nil, permanentDriverFailure("validator_history", s.drivers[0].Endpoint(), fiscobcos.ErrIncompleteChainEvidence)
	}
	history := make([]fiscobcos.ValidatorHistoryBlock, delta)
	totalTransitionItems := 0
	totalTransitionBytes := 0
	for index := uint64(0); index < delta; index++ {
		blockNumber := s.trust.TrustedCheckpoint.BlockNumber + index
		item, err := s.readValidatorHistoryBlockQuorum(ctx, blockNumber, false, route)
		if err != nil {
			return nil, err
		}
		history[index] = item
	}
	for index := range history {
		var nextHeader fiscobcos.NativeBlockHeaderFields
		if index+1 == len(history) {
			nextHeader = target.Fields
		} else {
			nextHeader = history[index+1].Block.Fields
		}
		if fiscobcos.ValidatorHeadersHaveSameSet(history[index].Block.Fields, nextHeader) {
			continue
		}
		full, err := s.readValidatorHistoryBlockQuorum(ctx, history[index].Block.BlockNumber, true, route)
		if err != nil {
			return nil, err
		}
		if !sameHistoryHeaderAndFinality(history[index], full) {
			s.recordQuorumFailure(bcosQuorumOperationHistory, bcosQuorumFailureDisagreement)
			return nil, ambiguousDriverFailure("validator_history", s.drivers[0].Endpoint(), fiscobcos.ErrEndpointDisagreement)
		}
		if len(full.Transactions) > fiscobcos.MaxNativeEvidenceItems-totalTransitionItems {
			return nil, permanentDriverFailure("validator_history", s.drivers[0].Endpoint(), fiscobcos.ErrIncompleteChainEvidence)
		}
		fullRaw, err := cborx.Marshal(full)
		if err != nil || len(fullRaw) > fiscobcos.MaxProofBytes-totalTransitionBytes {
			return nil, permanentDriverFailure("validator_history", s.drivers[0].Endpoint(), fiscobcos.ErrIncompleteChainEvidence)
		}
		totalTransitionItems += len(full.Transactions)
		totalTransitionBytes += len(fullRaw)
		history[index] = full
	}
	// The first block hash and validator state are verifier-local trust. Its
	// commit proof is redundant and intentionally omitted from the file.
	history[0].Finality.Signatures = nil
	return history, nil
}

func (s *FISCOBCOSStandardSink) readValidatorHistoryBlockQuorum(
	ctx context.Context,
	blockNumber uint64,
	includeContents bool,
	route bcosQuorumRoute,
) (fiscobcos.ValidatorHistoryBlock, error) {
	var selected fiscobcos.ValidatorHistoryBlock
	var selectedRaw []byte
	successes := 0
	for _, driver := range s.drivers {
		historyDriver, ok := driver.(fiscobcos.ValidatorHistoryDriver)
		if !ok {
			return fiscobcos.ValidatorHistoryBlock{}, permanentDriverFailure("validator_history", driver.Endpoint(), fiscobcos.ErrUnsupportedSDK)
		}
		item, err := historyDriver.GetValidatorHistoryBlock(ctx, blockNumber, includeContents)
		if err != nil {
			continue
		}
		if err := validateValidatorHistoryObservation(s.trust.ChainHashAlgorithm, blockNumber, includeContents, item); err != nil {
			s.recordQuorumFailure(bcosQuorumOperationHistory, bcosQuorumFailureDisagreement)
			return fiscobcos.ValidatorHistoryBlock{}, ambiguousDriverFailure("validator_history", driver.Endpoint(), err)
		}
		raw, err := cborx.Marshal(item)
		if err != nil {
			return fiscobcos.ValidatorHistoryBlock{}, permanentDriverFailure("validator_history", driver.Endpoint(), fiscobcos.ErrDriverInvalid)
		}
		if selectedRaw == nil {
			selected = item
			selectedRaw = raw
		} else if !bytes.Equal(selectedRaw, raw) {
			s.recordQuorumFailure(bcosQuorumOperationHistory, bcosQuorumFailureDisagreement)
			return fiscobcos.ValidatorHistoryBlock{}, ambiguousDriverFailure("validator_history", driver.Endpoint(), fiscobcos.ErrEndpointDisagreement)
		}
		if route.isHealthy(driver.Endpoint()) {
			successes++
		}
	}
	if successes < int(s.trust.ReadQuorum) {
		s.recordQuorumFailure(bcosQuorumOperationHistory, bcosQuorumFailureInsufficient)
		return fiscobcos.ValidatorHistoryBlock{}, ambiguousDriverFailure("validator_history", s.drivers[0].Endpoint(), fiscobcos.ErrIncompleteChainEvidence)
	}
	return selected, nil
}

func validateValidatorHistoryObservation(
	hashAlgorithm string,
	blockNumber uint64,
	includeContents bool,
	item fiscobcos.ValidatorHistoryBlock,
) error {
	if item.Block.BlockNumber != blockNumber || item.Block.Fields.BlockNumber < 0 ||
		uint64(item.Block.Fields.BlockNumber) != blockNumber ||
		len(item.Block.BlockHash) != 32 || len(item.Finality.Signatures) == 0 ||
		len(item.Finality.Signatures) > fiscobcos.MaxCommitSignatures {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	canonical, err := fiscobcos.MarshalNativeBlockHeaderPreimage(item.Block.Fields)
	if err != nil || !bytes.Equal(canonical, item.Block.RawCanonicalHeader) {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	computedHash, err := fiscobcos.HashNativeEvidence(hashAlgorithm, canonical)
	if err != nil || !bytes.Equal(computedHash, item.Block.BlockHash) {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	if includeContents {
		if len(item.Transactions) == 0 || len(item.Transactions) != len(item.Receipts) ||
			len(item.Transactions) > fiscobcos.MaxNativeEvidenceItems {
			return fiscobcos.ErrIncompleteChainEvidence
		}
	} else if len(item.Transactions) != 0 || len(item.Receipts) != 0 {
		return fiscobcos.ErrDriverInvalid
	}
	return nil
}

func sameHistoryHeaderAndFinality(left, right fiscobcos.ValidatorHistoryBlock) bool {
	left.Transactions = nil
	left.Receipts = nil
	right.Transactions = nil
	right.Receipts = nil
	leftRaw, leftErr := cborx.Marshal(left)
	rightRaw, rightErr := cborx.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
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
	callData, err := fiscobcos.PublishCallDataForMode(trust.CryptoMode, payload)
	if err != nil {
		return err
	}
	signatureBytes, err := fiscobcos.NativeTransactionSignatureBytes(trust.CryptoMode)
	if err != nil {
		return err
	}
	if len(attempt.EncodedTransaction) == 0 || len(attempt.Signature) != signatureBytes ||
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
		receipt.Observation.ReceiptProofRPC == nil ||
		len(receipt.Evidence.RawCanonicalReceipt) == 0 ||
		receipt.Evidence.Status != int64(receipt.Status) ||
		receipt.Evidence.StatusMessage != receipt.StatusMessage ||
		!bytes.Equal(receipt.Evidence.ReceiptHash, receipt.Observation.ReceiptHashClaim) ||
		!bytes.Equal(receipt.Evidence.TransactionHash, attempt.TransactionHash) ||
		receipt.Evidence.TransactionIndex != receipt.Observation.TransactionIndex ||
		receipt.Evidence.ReceiptIndex != receipt.Observation.ReceiptIndex ||
		receipt.Evidence.AnchorLogIndex != receipt.Event.LogIndex ||
		!sameByteSlices(receipt.Evidence.TransactionProof, receipt.Observation.TransactionProofRPC) ||
		!sameByteSlices(receipt.Evidence.ReceiptProof, receipt.Observation.ReceiptProofRPC) ||
		len(receipt.Evidence.CanonicalLogs) == 0 ||
		receipt.Evidence.AnchorLogIndex >= uint64(len(receipt.Evidence.CanonicalLogs)) ||
		len(receipt.Evidence.DecodedAnchorEvent) == 0 {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	canonicalReceipt, canonicalLogs, err := fiscobcos.MarshalNativeReceiptPreimage(receipt.Evidence.Fields)
	if err != nil ||
		!bytes.Equal(canonicalReceipt, receipt.Evidence.RawCanonicalReceipt) ||
		!sameByteSlices(canonicalLogs, receipt.Evidence.CanonicalLogs) {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	receiptHash, err := fiscobcos.HashNativeEvidence(trust.ChainHashAlgorithm, canonicalReceipt)
	if err != nil || !bytes.Equal(receiptHash, receipt.Evidence.ReceiptHash) {
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

func validateBlockObservation(blockNumber uint64, blockHash []byte, hashAlgorithm string, header fiscobcos.BlockHeader, consensus fiscobcos.ConsensusSnapshot) error {
	if blockNumber == 0 || header.Observation.BlockNumber != blockNumber ||
		len(header.Observation.NormalizedRPCHeader) == 0 ||
		!bytes.Equal(header.Observation.BlockHashClaim, blockHash) ||
		header.Evidence.BlockNumber != blockNumber ||
		len(header.Evidence.RawCanonicalHeader) == 0 ||
		!bytes.Equal(header.Evidence.BlockHash, blockHash) ||
		consensus.BlockNumber != blockNumber ||
		!bytes.Equal(consensus.BlockHash, blockHash) ||
		len(consensus.Finality.Signatures) == 0 {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	canonical, err := fiscobcos.MarshalNativeBlockHeaderPreimage(header.Evidence.Fields)
	if err != nil ||
		!bytes.Equal(canonical, header.Evidence.RawCanonicalHeader) ||
		header.Evidence.Fields.BlockNumber < 0 ||
		uint64(header.Evidence.Fields.BlockNumber) != blockNumber {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	computedHash, err := fiscobcos.HashNativeEvidence(hashAlgorithm, canonical)
	if err != nil || !bytes.Equal(computedHash, blockHash) {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	return nil
}

func validateProbeForSink(probe fiscobcos.ChainProbe, trust fiscobcos.TrustConfig) error {
	if probe.SDKVersion != fiscobcos.StandardSDKVersion {
		return permanentDriverFailure("probe", probe.Endpoint, fiscobcos.ErrUnsupportedSDK)
	}
	if probe.CryptoMode != trust.CryptoMode ||
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
	return left.Evidence.BlockNumber == right.Evidence.BlockNumber &&
		bytes.Equal(left.Evidence.BlockHash, right.Evidence.BlockHash) &&
		bytes.Equal(left.Evidence.RawCanonicalHeader, right.Evidence.RawCanonicalHeader) &&
		left.Observation.BlockNumber == right.Observation.BlockNumber &&
		bytes.Equal(left.Observation.BlockHashClaim, right.Observation.BlockHashClaim) &&
		bytes.Equal(left.Observation.NormalizedRPCHeader, right.Observation.NormalizedRPCHeader)
}

func sameByteSlices(left, right [][]byte) bool {
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

func sameConsensusSnapshot(left, right fiscobcos.ConsensusSnapshot) bool {
	if left.BlockNumber != right.BlockNumber || !bytes.Equal(left.BlockHash, right.BlockHash) ||
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

func (s *FISCOBCOSStandardSink) recordRetry(reason string) {
	if s != nil && s.metrics != nil && s.metrics.AnchorProviderRetryEvents != nil {
		s.metrics.AnchorProviderRetryEvents.WithLabelValues(fiscobcos.SinkName, reason).Inc()
	}
}

func (s *FISCOBCOSStandardSink) recordQuorumFailure(operation, reason string) {
	if s != nil && s.metrics != nil && s.metrics.AnchorProviderQuorumFailures != nil {
		s.metrics.AnchorProviderQuorumFailures.WithLabelValues(fiscobcos.SinkName, operation, reason).Inc()
	}
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
	in.Evidence.Fields.ParentInfo = append([]fiscobcos.NativeParentInfo(nil), in.Evidence.Fields.ParentInfo...)
	for index := range in.Evidence.Fields.ParentInfo {
		in.Evidence.Fields.ParentInfo[index].BlockHash = append([]byte(nil), in.Evidence.Fields.ParentInfo[index].BlockHash...)
	}
	in.Evidence.Fields.TransactionsRoot = append([]byte(nil), in.Evidence.Fields.TransactionsRoot...)
	in.Evidence.Fields.ReceiptsRoot = append([]byte(nil), in.Evidence.Fields.ReceiptsRoot...)
	in.Evidence.Fields.StateRoot = append([]byte(nil), in.Evidence.Fields.StateRoot...)
	in.Evidence.Fields.SealerList = cloneByteSlices(in.Evidence.Fields.SealerList)
	in.Evidence.Fields.ExtraData = append([]byte(nil), in.Evidence.Fields.ExtraData...)
	in.Evidence.Fields.ConsensusWeights = append([]int64(nil), in.Evidence.Fields.ConsensusWeights...)
	in.Evidence.RawCanonicalHeader = append([]byte(nil), in.Evidence.RawCanonicalHeader...)
	in.Evidence.BlockHash = append([]byte(nil), in.Evidence.BlockHash...)
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
