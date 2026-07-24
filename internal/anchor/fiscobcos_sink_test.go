package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
)

type fakeBCOSState struct {
	mu                  sync.Mutex
	record              fiscobcos.AnchorRecord
	attempt             fiscobcos.TransactionSubmission
	receipt             fiscobcos.ReceiptWithProof
	submitCalls         int
	failAfterEffectOnce bool
	hideRecordReads     int
}

type fakeBCOSDriver struct {
	endpoint string
	probe    fiscobcos.ChainProbe
	state    *fakeBCOSState
	closed   bool
}

func (d *fakeBCOSDriver) Endpoint() string { return d.endpoint }
func (d *fakeBCOSDriver) ProbeChain(context.Context) (fiscobcos.ChainProbe, error) {
	return cloneChainProbe(d.probe), nil
}
func (d *fakeBCOSDriver) SubmitAnchor(_ context.Context, request fiscobcos.SubmitRequest) (fiscobcos.Submission, error) {
	d.state.mu.Lock()
	defer d.state.mu.Unlock()
	d.state.submitCalls++
	txHash := sha256.Sum256(append(append([]byte(nil), request.Payload.AnchorID...), byte(d.state.submitCalls)))
	callData, err := fiscobcos.PublishCallData(request.Payload)
	if err != nil {
		return fiscobcos.Submission{}, err
	}
	d.state.attempt = fiscobcos.TransactionSubmission{
		EncodedTransaction: append([]byte("encoded-transaction-"), txHash[:]...),
		ChainID:            d.probe.ChainID,
		GroupID:            d.probe.GroupID,
		To:                 bytes.Repeat([]byte{0x41}, 20),
		Input:              callData,
		Signature:          bytes.Repeat([]byte{0x51}, 65),
		Sender:             bytes.Repeat([]byte{0x61}, 20),
		TransactionHash:    txHash[:],
		BlockLimit:         700,
		SubmittedAtUnixN:   int64(d.state.submitCalls),
	}
	d.state.record = fiscobcos.AnchorRecord{
		StreamID: append([]byte(nil), request.Payload.StreamID...), TreeSize: request.Payload.TreeSize,
		RootHash:        append([]byte(nil), request.Payload.RootHash...),
		SignedSTHDigest: append([]byte(nil), request.Payload.SignedSTHDigest...),
		Publisher:       bytes.Repeat([]byte{0x61}, 20), PayloadVersion: request.Payload.Version, Exists: true,
	}
	blockHash := bytes.Repeat([]byte{0x71}, 32)
	d.state.receipt = fiscobcos.ReceiptWithProof{
		Status: fiscobcos.ReceiptStatusOK, BlockNumber: 500, BlockHash: blockHash, Record: cloneAnchorRecord(d.state.record),
		Event: fiscobcos.AnchorPublishedEvent{
			ContractAddress:  bytes.Repeat([]byte{0x41}, 20),
			AnchorID:         append([]byte(nil), request.Payload.AnchorID...),
			StreamID:         append([]byte(nil), request.Payload.StreamID...),
			TreeSize:         request.Payload.TreeSize,
			RootHash:         append([]byte(nil), request.Payload.RootHash...),
			SignedSTHDigest:  append([]byte(nil), request.Payload.SignedSTHDigest...),
			Publisher:        bytes.Repeat([]byte{0x61}, 20),
			PayloadVersion:   request.Payload.Version,
			LogIndex:         0,
			NormalizedRPCLog: []byte("normalized-rpc-log"),
		},
		Observation: fiscobcos.ReceiptRPCObservation{
			NormalizedRPCReceipt: []byte("normalized-rpc-receipt"),
			Status:               fiscobcos.ReceiptStatusOK,
			StatusMessage:        "success",
			BlockNumber:          500,
			BlockHashClaim:       append([]byte(nil), blockHash...),
			ReceiptHashClaim:     bytes.Repeat([]byte{0x72}, 32),
			TransactionHash:      txHash[:],
			TransactionProofRPC:  [][]byte{},
			ReceiptProofRPC:      [][]byte{},
			AnchorLogIndex:       0,
		},
	}
	if d.state.failAfterEffectOnce {
		d.state.failAfterEffectOnce = false
		return fiscobcos.Submission{}, errors.New("connection lost after submission")
	}
	return fiscobcos.Submission{Attempt: cloneAttempt(d.state.attempt)}, nil
}
func (d *fakeBCOSDriver) ReadAnchor(context.Context, []byte) (fiscobcos.AnchorRecord, error) {
	d.state.mu.Lock()
	defer d.state.mu.Unlock()
	if d.state.hideRecordReads > 0 {
		d.state.hideRecordReads--
		return fiscobcos.AnchorRecord{}, nil
	}
	return cloneAnchorRecord(d.state.record), nil
}
func (d *fakeBCOSDriver) GetReceiptWithProof(context.Context, fiscobcos.TransactionSubmission) (fiscobcos.ReceiptWithProof, error) {
	d.state.mu.Lock()
	defer d.state.mu.Unlock()
	return cloneReceipt(d.state.receipt), nil
}
func (d *fakeBCOSDriver) GetBlockHeader(context.Context, uint64) (fiscobcos.BlockHeader, error) {
	return fiscobcos.BlockHeader{Observation: fiscobcos.BlockRPCObservation{
		NormalizedRPCHeader: []byte("normalized-rpc-header"), BlockHashClaim: bytes.Repeat([]byte{0x71}, 32), BlockNumber: 500,
	}}, nil
}
func (d *fakeBCOSDriver) GetConsensusSnapshot(context.Context, uint64) (fiscobcos.ConsensusSnapshot, error) {
	return fiscobcos.ConsensusSnapshot{
		BlockNumber: 500, BlockHash: bytes.Repeat([]byte{0x71}, 32),
		Finality: fiscobcos.ConsensusFinalityObservation{Signatures: []fiscobcos.CommitSignature{
			{ValidatorNodeID: "validator-a", Signature: bytes.Repeat([]byte{0x81}, 64)},
			{ValidatorNodeID: "validator-b", Signature: bytes.Repeat([]byte{0x82}, 64)},
			{ValidatorNodeID: "validator-c", Signature: bytes.Repeat([]byte{0x83}, 64)},
		}},
	}, nil
}
func (d *fakeBCOSDriver) Close() error { d.closed = true; return nil }

func TestFISCOBCOSStandardSinkPublishesCompleteRawEvidence(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{
		TrustConfig: trust, Drivers: drivers, Clock: func() time.Time { return time.Unix(10, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	sth := testSTH(testScheduleKey(fiscobcos.SinkName), 8, 0x18)
	result, err := sink.Publish(context.Background(), sth)
	if err != nil {
		t.Fatal(err)
	}
	if result.SinkName != fiscobcos.SinkName || result.TreeSize != sth.TreeSize || result.PublishedAtUnixN == 0 {
		t.Fatalf("result=%+v", result)
	}
	if result.EvidenceStage != model.AnchorEvidenceStageRaw || model.AnchorResultProvidesOfflineL5(result) {
		t.Fatalf("raw result must not satisfy L5: %+v", result)
	}
	observation, err := fiscobcos.UnmarshalPublicationObservation(result.Proof)
	if err != nil {
		t.Fatal(err)
	}
	if observation.EvidenceStage != model.AnchorEvidenceStageRaw ||
		len(observation.Receipt.TransactionProofRPC) != 0 ||
		len(observation.Consensus.Finality.Signatures) != 3 {
		t.Fatalf("observation=%+v", observation)
	}
	if err := fiscobcos.ValidateProofAgainstTrustConfig(sth, result, trust); err == nil {
		t.Fatal("raw RPC observation must not decode as an offline anchor proof")
	}
}

func TestFISCOBCOSStandardSinkSystemHealthAndEndpointMetrics(t *testing.T) {
	t.Parallel()

	trust, drivers := fakeBCOSFixture(t)
	metrics := observability.NewMetrics()
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{
		TrustConfig: trust, Drivers: drivers, Metrics: metrics,
		Clock: func() time.Time { return time.Unix(20, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	system, err := sink.System(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, capability := range system.Capabilities {
		if capability == model.AnchorCapabilityVerify {
			t.Fatal("raw FISCO BCOS observation advertised offline verification")
		}
	}
	status, err := sink.Status(context.Background())
	if err != nil || status.State != model.AnchorSystemStateHealthy ||
		status.Details["height"] != "500" {
		t.Fatalf("healthy status=%+v err=%v", status, err)
	}
	for index := range drivers {
		label := fmt.Sprintf("%d", index)
		if got := testutil.ToFloat64(metrics.AnchorProviderEndpointHealthy.WithLabelValues(fiscobcos.SinkName, label)); got != 1 {
			t.Fatalf("endpoint %d healthy metric=%v, want 1", index, got)
		}
		if got := testutil.ToFloat64(metrics.AnchorProviderEndpointHeight.WithLabelValues(fiscobcos.SinkName, label)); got != 500 {
			t.Fatalf("endpoint %d height metric=%v, want 500", index, got)
		}
	}
	drivers[1].(*fakeBCOSDriver).probe.Height = 499
	status, err = sink.Status(context.Background())
	if err != nil || status.State != model.AnchorSystemStateDegraded {
		t.Fatalf("degraded status=%+v err=%v", status, err)
	}
	for index := range drivers {
		label := fmt.Sprintf("%d", index)
		if got := testutil.ToFloat64(metrics.AnchorProviderEndpointHealthy.WithLabelValues(fiscobcos.SinkName, label)); got != 0 {
			t.Fatalf("endpoint %d healthy metric=%v after disagreement, want 0", index, got)
		}
	}
}

func TestFISCOBCOSPublicationObservationStrictWireFormat(t *testing.T) {
	t.Parallel()
	trust, drivers := fakeBCOSFixture(t)
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{
		TrustConfig: trust, Drivers: drivers, Clock: func() time.Time { return time.Unix(10, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sink.Publish(context.Background(), testSTH(testScheduleKey(fiscobcos.SinkName), 8, 0x18))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := fiscobcos.UnmarshalPublicationObservation(result.Proof)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := fiscobcos.UnmarshalPublicationObservation(append(append([]byte(nil), result.Proof...), 0)); err == nil {
		t.Fatal("accepted trailing CBOR data")
	}
	var object map[string]any
	if err := cbor.Unmarshal(result.Proof, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown_field"] = true
	unknown, err := cborx.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fiscobcos.UnmarshalPublicationObservation(unknown); err == nil {
		t.Fatal("accepted an unknown publication observation field")
	}
	mode, err := cbor.EncOptions{Sort: cbor.SortNone, IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden}.EncMode()
	if err != nil {
		t.Fatal(err)
	}
	nonCanonical, err := mode.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(nonCanonical, result.Proof) {
		t.Fatal("test encoder unexpectedly emitted canonical field order")
	}
	if _, err := fiscobcos.UnmarshalPublicationObservation(nonCanonical); err == nil {
		t.Fatal("accepted non-canonical CBOR")
	}
	tampered := observation
	tampered.Event.RootHash = bytes.Repeat([]byte{0xff}, 32)
	tamperedBytes, err := cborx.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fiscobcos.UnmarshalPublicationObservation(tamperedBytes); err == nil {
		t.Fatal("accepted event/payload binding tamper")
	}
	if _, err := fiscobcos.UnmarshalPublicationObservation(make([]byte, fiscobcos.MaxPublicationObservationBytes+1)); err == nil {
		t.Fatal("accepted oversized publication observation")
	}
	observation.Transaction.EncodedTransaction = make([]byte, fiscobcos.MaxPublicationObservationBytes)
	if _, err := fiscobcos.MarshalPublicationObservation(observation); err == nil {
		t.Fatal("accepted oversized transaction observation before encoding")
	}
}

func TestFISCOBCOSStandardSinkFailsClosedOnEndpointDisagreement(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	drivers[1].(*fakeBCOSDriver).probe.Height++
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sink.Publish(context.Background(), testSTH(testScheduleKey(fiscobcos.SinkName), 8, 0x18))
	if errors.Is(err, ErrPermanent) || !errors.Is(err, fiscobcos.ErrEndpointDisagreement) {
		t.Fatalf("height disagreement error=%v", err)
	}
	state := drivers[0].(*fakeBCOSDriver).state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.submitCalls != 0 {
		t.Fatalf("side effect occurred before quorum probe: calls=%d", state.submitCalls)
	}
}

func TestFISCOBCOSStandardSinkRejectsNonCanonicalV1BindingBeforeSideEffect(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fiscobcos.TrustConfig)
	}{
		{name: "protocol version", mutate: func(trust *fiscobcos.TrustConfig) {
			trust.Contract.ProtocolVersion = "trustdb-anchor-v2"
		}},
		{name: "event signature", mutate: func(trust *fiscobcos.TrustConfig) {
			trust.Contract.EventSignature = "AnchorPublished(bytes32)"
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			trust, drivers := fakeBCOSFixture(t)
			state := drivers[0].(*fakeBCOSDriver).state
			test.mutate(&trust)
			if _, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{
				TrustConfig: trust,
				Drivers:     drivers,
			}); !errors.Is(err, fiscobcos.ErrInvalidTrustConfig) {
				t.Fatalf("constructor error=%v, want ErrInvalidTrustConfig", err)
			}
			state.mu.Lock()
			defer state.mu.Unlock()
			if state.submitCalls != 0 {
				t.Fatalf("invalid V1 binding produced %d side effects", state.submitCalls)
			}
		})
	}
}

func TestFISCOBCOSStandardSinkDoesNotMaskConfiguredEndpointReadDisagreement(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	trust.Endpoints = append(trust.Endpoints, "127.0.0.1:20202")
	base := drivers[0].(*fakeBCOSDriver)
	probe := cloneChainProbe(base.probe)
	probe.Endpoint = trust.Endpoints[2]
	drivers = append(drivers, &fakeBCOSDriver{
		endpoint: probe.Endpoint,
		probe:    probe,
		state:    &fakeBCOSState{},
	})
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sink.Publish(context.Background(), testSTH(testScheduleKey(fiscobcos.SinkName), 8, 0x18))
	if errors.Is(err, ErrPermanent) || !errors.Is(err, fiscobcos.ErrEndpointDisagreement) {
		t.Fatalf("minority endpoint disagreement error=%v", err)
	}
	base.state.mu.Lock()
	defer base.state.mu.Unlock()
	if base.state.submitCalls != 1 {
		t.Fatalf("submit calls=%d, want one side effect before readback disagreement", base.state.submitCalls)
	}
}

type currentViewDriver struct {
	*fakeBCOSDriver
	currentView uint64
	exposeView  bool
}

func (d *currentViewDriver) GetConsensusSnapshot(ctx context.Context, blockNumber uint64) (fiscobcos.ConsensusSnapshot, error) {
	snapshot, err := d.fakeBCOSDriver.GetConsensusSnapshot(ctx, blockNumber)
	if err == nil && d.exposeView {
		view := d.currentView
		snapshot.Finality.View = &view
	}
	return snapshot, err
}

func TestFISCOBCOSStandardSinkDoesNotBindAdvancingLiveViewToHistoricalBlock(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	for index, driver := range drivers {
		drivers[index] = &currentViewDriver{
			fakeBCOSDriver: driver.(*fakeBCOSDriver),
			currentView:    uint64(100 + index),
		}
	}
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Publish(context.Background(), testSTH(testScheduleKey(fiscobcos.SinkName), 12, 0x1c)); err != nil {
		t.Fatalf("different current endpoint views affected historical block evidence: %v", err)
	}
}

func TestFISCOBCOSStandardSinkRejectsUnboundLiveViewObservation(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	for index, driver := range drivers {
		drivers[index] = &currentViewDriver{
			fakeBCOSDriver: driver.(*fakeBCOSDriver),
			currentView:    uint64(100 + index),
			exposeView:     true,
		}
	}
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Publish(context.Background(), testSTH(testScheduleKey(fiscobcos.SinkName), 13, 0x1d)); err == nil {
		t.Fatal("accepted a latest PBFT view as historical block evidence")
	}
}

func TestFISCOBCOSReadbackDisagreementRemainsRecoverOnlyAfterConvergence(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	trust.Endpoints = append(trust.Endpoints, "127.0.0.1:20202")
	base := drivers[0].(*fakeBCOSDriver)
	probe := cloneChainProbe(base.probe)
	probe.Endpoint = trust.Endpoints[2]
	laggingState := &fakeBCOSState{}
	drivers = append(drivers, &fakeBCOSDriver{endpoint: probe.Endpoint, probe: probe, state: laggingState})
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}

	store := newBoundTestLocalStore(t, t.TempDir())
	key := testScheduleKey(fiscobcos.SinkName)
	sth := testSTH(key, 10, 0x1a)
	offer(t, store, key, sth, 100, 100)
	now := time.Unix(0, 100)
	first := newTestService(t, store, sink, key, &now, func(config *Config) {
		config.InitialBackoff = time.Nanosecond
		config.MaxBackoff = time.Nanosecond
	})
	first.tick(context.Background())

	base.state.mu.Lock()
	converged := cloneAnchorRecord(base.state.record)
	base.state.mu.Unlock()
	laggingState.mu.Lock()
	laggingState.record = converged
	laggingState.mu.Unlock()

	now = now.Add(time.Second)
	second := newTestService(t, store, sink, key, &now, nil)
	second.tick(context.Background())
	schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.InFlight == nil || schedule.InFlight.TerminalFailure ||
		schedule.InFlight.Target.TreeSize != sth.TreeSize {
		t.Fatalf("recover-only schedule after convergence=%+v found=%v err=%v", schedule, found, err)
	}
	base.state.mu.Lock()
	defer base.state.mu.Unlock()
	if base.state.submitCalls != 1 {
		t.Fatalf("submit calls=%d, converged readback must not resubmit", base.state.submitCalls)
	}
}

func TestFISCOBCOSStandardSinkRejectsReceiptOnlyResponse(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	driver := drivers[0].(*fakeBCOSDriver)
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}
	drivers[0] = &receiptOnlyDriver{fakeBCOSDriver: driver}
	sink, err = NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sink.Publish(context.Background(), testSTH(testScheduleKey(fiscobcos.SinkName), 8, 0x18))
	if errors.Is(err, ErrPermanent) || !errors.Is(err, fiscobcos.ErrIncompleteChainEvidence) {
		t.Fatalf("receipt-only error=%v", err)
	}
}

func TestFISCOBCOSStandardSinkDoesNotResubmitExistingAnchorWithoutEvidence(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	driver := drivers[0].(*fakeBCOSDriver)
	sth := testSTH(testScheduleKey(fiscobcos.SinkName), 8, 0x18)
	request := fakeSubmitRequest(t, sth)
	if _, err := driver.SubmitAnchor(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sink.Publish(context.Background(), sth)
	if errors.Is(err, ErrPermanent) || !errors.Is(err, fiscobcos.ErrExistingAnchorEvidenceUnavailable) {
		t.Fatalf("pre-existing anchor error=%v", err)
	}
	driver.state.mu.Lock()
	defer driver.state.mu.Unlock()
	if driver.state.submitCalls != 1 {
		t.Fatalf("pre-existing anchor was resubmitted: calls=%d", driver.state.submitCalls)
	}
}

type receiptOnlyDriver struct{ *fakeBCOSDriver }

func (d *receiptOnlyDriver) GetReceiptWithProof(ctx context.Context, attempt fiscobcos.TransactionSubmission) (fiscobcos.ReceiptWithProof, error) {
	receipt, err := d.fakeBCOSDriver.GetReceiptWithProof(ctx, attempt)
	receipt.Observation.TransactionProofRPC = nil
	receipt.Observation.ReceiptProofRPC = nil
	return receipt, err
}

type statusMismatchDriver struct{ *fakeBCOSDriver }

func (d *statusMismatchDriver) GetReceiptWithProof(ctx context.Context, attempt fiscobcos.TransactionSubmission) (fiscobcos.ReceiptWithProof, error) {
	receipt, err := d.fakeBCOSDriver.GetReceiptWithProof(ctx, attempt)
	receipt.Status = 10008
	receipt.Observation.Status = 10008
	receipt.Observation.StatusMessage = "invalid_signature"
	return receipt, err
}

type attemptMismatchDriver struct{ *fakeBCOSDriver }

func (d *attemptMismatchDriver) SubmitAnchor(ctx context.Context, request fiscobcos.SubmitRequest) (fiscobcos.Submission, error) {
	submission, err := d.fakeBCOSDriver.SubmitAnchor(ctx, request)
	submission.Attempt.ChainID = "wrong-chain"
	return submission, err
}

type classifiedReceiptSubmitDriver struct {
	*fakeBCOSDriver
	status int
}

func (d *classifiedReceiptSubmitDriver) SubmitAnchor(context.Context, fiscobcos.SubmitRequest) (fiscobcos.Submission, error) {
	statusErr := fiscobcos.NewReceiptStatusError(d.status)
	return fiscobcos.Submission{}, &fiscobcos.DriverError{
		Operation: "submit_anchor_receipt",
		Endpoint:  d.endpoint,
		Class:     statusErr.FailureClass(),
		Kind:      statusErr,
	}
}

func TestFISCOBCOSReceiptStatusDispositionControlsServiceRetry(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		terminal bool
	}{
		{name: "contract revert", status: 16, terminal: true},
		{name: "permission denied", status: 18, terminal: true},
		{name: "invalid chain", status: 10006, terminal: true},
		{name: "invalid group", status: 10007, terminal: true},
		{name: "invalid signature", status: 10008, terminal: true},
		{name: "block limit", status: 10001},
		{name: "transaction pool full", status: 10002},
		{name: "duplicate in pool", status: 10004},
		{name: "duplicate in chain", status: 10005},
		{name: "pool timeout", status: 10010},
		{name: "unknown status", status: 99999},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			trust, drivers := fakeBCOSFixture(t)
			base := drivers[0].(*fakeBCOSDriver)
			drivers[0] = &classifiedReceiptSubmitDriver{fakeBCOSDriver: base, status: test.status}
			sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
			if err != nil {
				t.Fatal(err)
			}
			store := newBoundTestLocalStore(t, t.TempDir())
			key := testScheduleKey(fiscobcos.SinkName)
			sth := testSTH(key, 14, 0x1e)
			offer(t, store, key, sth, 100, 100)
			now := time.Unix(0, 100)
			service := newTestService(t, store, sink, key, &now, func(config *Config) {
				config.InitialBackoff = time.Nanosecond
				config.MaxBackoff = time.Nanosecond
			})
			service.tick(context.Background())

			schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
			if err != nil || !found || schedule.InFlight == nil {
				t.Fatalf("schedule=%+v found=%v err=%v", schedule, found, err)
			}
			if schedule.InFlight.TerminalFailure != test.terminal || schedule.InFlight.Attempts != 1 {
				t.Fatalf("status=%d terminal=%v attempts=%d, want terminal=%v attempts=1",
					test.status, schedule.InFlight.TerminalFailure, schedule.InFlight.Attempts, test.terminal)
			}
			if !test.terminal && schedule.InFlight.NextAttemptUnixN == 0 {
				t.Fatalf("status=%d was not durably scheduled for retry/recovery", test.status)
			}
			base.state.mu.Lock()
			defer base.state.mu.Unlock()
			if base.state.submitCalls != 0 {
				t.Fatalf("status-classification fixture produced a side effect: calls=%d", base.state.submitCalls)
			}
		})
	}
}

func TestFISCOBCOSPostSubmitValidationFailuresAreClassified(t *testing.T) {
	for _, test := range []struct {
		name     string
		wrap     func(*fakeBCOSDriver) fiscobcos.Driver
		terminal bool
	}{
		{name: "missing receipt proofs", wrap: func(driver *fakeBCOSDriver) fiscobcos.Driver {
			return &receiptOnlyDriver{fakeBCOSDriver: driver}
		}},
		{name: "invalid receipt status", wrap: func(driver *fakeBCOSDriver) fiscobcos.Driver {
			return &statusMismatchDriver{fakeBCOSDriver: driver}
		}, terminal: true},
		{name: "submission identity mismatch", wrap: func(driver *fakeBCOSDriver) fiscobcos.Driver {
			return &attemptMismatchDriver{fakeBCOSDriver: driver}
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			trust, drivers := fakeBCOSFixture(t)
			base := drivers[0].(*fakeBCOSDriver)
			drivers[0] = test.wrap(base)
			sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
			if err != nil {
				t.Fatal(err)
			}
			store := newBoundTestLocalStore(t, t.TempDir())
			key := testScheduleKey(fiscobcos.SinkName)
			sth := testSTH(key, 11, 0x1b)
			offer(t, store, key, sth, 100, 100)
			now := time.Unix(0, 100)
			service := newTestService(t, store, sink, key, &now, func(config *Config) {
				config.InitialBackoff = time.Nanosecond
				config.MaxBackoff = time.Nanosecond
			})
			service.tick(context.Background())
			now = now.Add(time.Second)
			service = newTestService(t, store, sink, key, &now, nil)
			service.tick(context.Background())
			schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
			if err != nil || !found || schedule.InFlight == nil ||
				schedule.InFlight.TerminalFailure != test.terminal {
				t.Fatalf("schedule=%+v found=%v error=%v, want terminal=%v", schedule, found, err, test.terminal)
			}
			base.state.mu.Lock()
			defer base.state.mu.Unlock()
			if base.state.submitCalls != 1 {
				t.Fatalf("submit calls=%d, want exactly one after post-submit failure", base.state.submitCalls)
			}
		})
	}
}

func TestFISCOBCOSServiceRestartDoesNotRepeatImmediatelyVisibleUnknownSideEffect(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	state := drivers[0].(*fakeBCOSDriver).state
	state.failAfterEffectOnce = true
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}
	store := newBoundTestLocalStore(t, t.TempDir())
	key := testScheduleKey(fiscobcos.SinkName)
	sth := testSTH(key, 9, 0x19)
	offer(t, store, key, sth, 100, 100)
	now := time.Unix(0, 100)
	first := newTestService(t, store, sink, key, &now, func(config *Config) {
		config.InitialBackoff = time.Nanosecond
		config.MaxBackoff = time.Nanosecond
	})
	first.tick(context.Background())
	schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.InFlight == nil || schedule.InFlight.Target.TreeSize != sth.TreeSize {
		t.Fatalf("schedule after ambiguous submission=%+v found=%v err=%v", schedule, found, err)
	}

	now = now.Add(time.Second)
	second := newTestService(t, store, sink, key, &now, nil)
	second.tick(context.Background())
	if result, found, err := store.GetSTHAnchorResult(context.Background(), sth.TreeSize); err != nil || found {
		t.Fatalf("unknown-outcome result must remain unclaimed until #465 recovery: result=%+v found=%v err=%v", result, found, err)
	}
	schedule, found, err = store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.InFlight == nil || schedule.InFlight.TerminalFailure ||
		schedule.InFlight.Target.TreeSize != sth.TreeSize {
		t.Fatalf("recover-only schedule=%+v found=%v err=%v", schedule, found, err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.submitCalls != 1 {
		t.Fatalf("submit calls=%d, visible exact record must not be resubmitted", state.submitCalls)
	}
}

func TestFISCOBCOSDelayedUnknownOutcomeRecoveryRemainsDeferred(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	state := drivers[0].(*fakeBCOSDriver).state
	state.failAfterEffectOnce = true
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}
	sth := testSTH(testScheduleKey(fiscobcos.SinkName), 15, 0x1f)
	if _, err := sink.Publish(context.Background(), sth); err == nil {
		t.Fatal("lost submission response was reported as success")
	}

	// Hide the committed record for one complete two-endpoint preflight. This
	// captures the deliberate #464 boundary: without the persisted immutable
	// attempt and deterministic lookup added by #465/#470, delayed visibility
	// can still cause a replacement submission.
	state.mu.Lock()
	state.hideRecordReads = len(drivers)
	state.mu.Unlock()
	if _, err := sink.Publish(context.Background(), sth); err != nil {
		t.Fatalf("replacement publication failed: %v", err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.submitCalls != 2 {
		t.Fatalf("submit calls=%d, want the documented pre-#465 delayed-visibility boundary", state.submitCalls)
	}
}

func fakeBCOSFixture(t *testing.T) (fiscobcos.TrustConfig, []fiscobcos.Driver) {
	t.Helper()
	trust, err := fiscobcos.NewTrustConfig(fiscobcos.CryptoModeStandard)
	if err != nil {
		t.Fatal(err)
	}
	trust.ChainID = "chain0"
	trust.GroupID = "group0"
	trust.GenesisHash = bytes.Repeat([]byte{0x01}, 32)
	trust.TrustedCheckpoint = fiscobcos.BlockCheckpoint{BlockNumber: 400, BlockHash: bytes.Repeat([]byte{0x21}, 32)}
	trust.Contract = fiscobcos.ContractBinding{
		Address: bytes.Repeat([]byte{0x41}, 20), CodeHash: bytes.Repeat([]byte{0x61}, 32),
		ProtocolVersion: fiscobcos.TrustDBAnchorV1ProtocolVersion,
		EventSignature:  fiscobcos.TrustDBAnchorV1EventSignature,
	}
	trust.Endpoints = []string{"127.0.0.1:20200", "127.0.0.1:20201"}
	trust.ReadQuorum = 2
	trust.AccountProvider = fiscobcos.AccountProviderConfig{
		Provider: "software", KeyID: "publisher", KeyReference: "publisher.keyref",
		Algorithm: fiscobcos.StandardAccountAlg,
	}
	trust.Certificates = fiscobcos.CertificateConfig{
		TransportMode:               fiscobcos.StandardTransport,
		TrustedCAReferences:         []string{"ca.crt"},
		TrustedCACertificateHashes:  [][]byte{bytes.Repeat([]byte{0xa1}, 32)},
		ClientSigningCertificateRef: "sdk.crt", ClientSigningKeyRef: "sdk.key",
	}
	for _, id := range []string{"validator-a", "validator-b", "validator-c", "validator-d"} {
		publicKey := append([]byte{0x04}, bytes.Repeat([]byte{byte(len(id))}, 64)...)
		trust.Validators = append(trust.Validators, fiscobcos.ValidatorDescriptor{
			NodeID: id, Algorithm: fiscobcos.StandardAccountAlg,
			PublicKeyEncoding: fiscobcos.StandardKeyEncoding, PublicKey: publicKey,
		})
	}
	probe := fiscobcos.ChainProbe{
		SDKVersion: fiscobcos.StandardSDKVersion, CryptoMode: fiscobcos.CryptoModeStandard,
		ChainID: trust.ChainID, GroupID: trust.GroupID,
		GenesisHash:    append([]byte(nil), trust.GenesisHash...),
		CheckpointHash: append([]byte(nil), trust.TrustedCheckpoint.BlockHash...),
		Height:         500, ContractCodeHash: append([]byte(nil), trust.Contract.CodeHash...),
	}
	state := &fakeBCOSState{}
	drivers := make([]fiscobcos.Driver, 0, len(trust.Endpoints))
	for _, endpoint := range trust.Endpoints {
		candidate := cloneChainProbe(probe)
		candidate.Endpoint = endpoint
		drivers = append(drivers, &fakeBCOSDriver{endpoint: endpoint, probe: candidate, state: state})
	}
	return trust, drivers
}

func fakeSubmitRequest(t *testing.T, sth model.SignedTreeHead) fiscobcos.SubmitRequest {
	t.Helper()
	payload, err := fiscobcos.NewAnchorPayload(cryptosuite.INTLV1, sth)
	if err != nil {
		t.Fatal(err)
	}
	data, err := fiscobcos.MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	return fiscobcos.SubmitRequest{Payload: payload, CanonicalPayload: data}
}

func cloneAttempt(in fiscobcos.TransactionSubmission) fiscobcos.TransactionSubmission {
	in.EncodedTransaction = append([]byte(nil), in.EncodedTransaction...)
	in.To = append([]byte(nil), in.To...)
	in.Input = append([]byte(nil), in.Input...)
	in.Signature = append([]byte(nil), in.Signature...)
	in.Sender = append([]byte(nil), in.Sender...)
	in.TransactionHash = append([]byte(nil), in.TransactionHash...)
	return in
}

func cloneReceipt(in fiscobcos.ReceiptWithProof) fiscobcos.ReceiptWithProof {
	in.BlockHash = append([]byte(nil), in.BlockHash...)
	in.Record = cloneAnchorRecord(in.Record)
	in.Event.ContractAddress = append([]byte(nil), in.Event.ContractAddress...)
	in.Event.AnchorID = append([]byte(nil), in.Event.AnchorID...)
	in.Event.StreamID = append([]byte(nil), in.Event.StreamID...)
	in.Event.RootHash = append([]byte(nil), in.Event.RootHash...)
	in.Event.SignedSTHDigest = append([]byte(nil), in.Event.SignedSTHDigest...)
	in.Event.Publisher = append([]byte(nil), in.Event.Publisher...)
	in.Event.NormalizedRPCLog = append([]byte(nil), in.Event.NormalizedRPCLog...)
	in.Observation.NormalizedRPCReceipt = append([]byte(nil), in.Observation.NormalizedRPCReceipt...)
	in.Observation.BlockHashClaim = append([]byte(nil), in.Observation.BlockHashClaim...)
	in.Observation.ReceiptHashClaim = append([]byte(nil), in.Observation.ReceiptHashClaim...)
	in.Observation.TransactionHash = append([]byte(nil), in.Observation.TransactionHash...)
	in.Observation.TransactionProofRPC = cloneByteSlicesForTest(in.Observation.TransactionProofRPC)
	in.Observation.ReceiptProofRPC = cloneByteSlicesForTest(in.Observation.ReceiptProofRPC)
	return in
}

func cloneByteSlicesForTest(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = append([]byte(nil), in[i]...)
	}
	return out
}

func (s *fakeBCOSState) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf("submits=%d", s.submitCalls)
}
