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
	request             fiscobcos.SubmitRequest
	receipt             fiscobcos.ReceiptWithProof
	prepareCalls        int
	submitCalls         int
	submitStatuses      []int
	effectStatuses      map[int]bool
	failAfterEffectOnce bool
	hideRecordReads     int
}

type fakeBCOSDriver struct {
	endpoint      string
	probe         fiscobcos.ChainProbe
	probeErr      error
	readErr       error
	submitErrOnce error
	state         *fakeBCOSState
	closed        bool
}

func (d *fakeBCOSDriver) Endpoint() string { return d.endpoint }
func (d *fakeBCOSDriver) ProbeChain(context.Context) (fiscobcos.ChainProbe, error) {
	return cloneChainProbe(d.probe), d.probeErr
}
func (d *fakeBCOSDriver) PrepareAnchor(_ context.Context, request fiscobcos.SubmitRequest) (fiscobcos.TransactionSubmission, error) {
	d.state.mu.Lock()
	defer d.state.mu.Unlock()
	d.state.prepareCalls++
	txHash := sha256.Sum256(append(append([]byte(nil), request.Payload.AnchorID...), byte(d.state.prepareCalls)))
	callData, err := fiscobcos.PublishCallData(request.Payload)
	if err != nil {
		return fiscobcos.TransactionSubmission{}, err
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
		BlockLimit:         uint64(699 + d.state.prepareCalls),
		SubmittedAtUnixN:   int64(d.state.prepareCalls),
	}
	d.state.request = request
	return cloneAttempt(d.state.attempt), nil
}

func (d *fakeBCOSDriver) SubmitPreparedAnchor(_ context.Context, attempt fiscobcos.TransactionSubmission) (fiscobcos.SubmissionOutcome, error) {
	d.state.mu.Lock()
	defer d.state.mu.Unlock()
	if !bytes.Equal(attempt.EncodedTransaction, d.state.attempt.EncodedTransaction) ||
		!bytes.Equal(attempt.TransactionHash, d.state.attempt.TransactionHash) {
		return fiscobcos.SubmissionOutcome{}, fiscobcos.ErrContractMismatch
	}
	d.state.submitCalls++
	if d.submitErrOnce != nil {
		err := d.submitErrOnce
		d.submitErrOnce = nil
		return fiscobcos.SubmissionOutcome{}, err
	}
	status := fiscobcos.ReceiptStatusOK
	if d.state.submitCalls <= len(d.state.submitStatuses) {
		status = d.state.submitStatuses[d.state.submitCalls-1]
	}
	statusMessage := fmt.Sprintf("status_%d", status)
	if status == fiscobcos.ReceiptStatusOK {
		statusMessage = "success"
	}
	if status != fiscobcos.ReceiptStatusOK && !d.state.effectStatuses[status] {
		return fiscobcos.SubmissionOutcome{
			Status: status, StatusMessage: statusMessage,
			ObservedAtUnixN: int64(d.state.submitCalls),
		}, nil
	}
	request := d.state.request
	d.state.record = fiscobcos.AnchorRecord{
		StreamID: append([]byte(nil), request.Payload.StreamID...), TreeSize: request.Payload.TreeSize,
		RootHash:        append([]byte(nil), request.Payload.RootHash...),
		SignedSTHDigest: append([]byte(nil), request.Payload.SignedSTHDigest...),
		Publisher:       bytes.Repeat([]byte{0x61}, 20), PayloadVersion: request.Payload.Version, Exists: true,
	}
	header := fakeBCOSBlockHeader()
	blockHash := header.Evidence.BlockHash
	receiptFields := fiscobcos.NativeReceiptFields{
		Version:         0,
		GasUsed:         "1",
		ContractAddress: "",
		Status:          0,
		Logs: []fiscobcos.NativeLogFields{{
			Address: "0x" + fmt.Sprintf("%x", bytes.Repeat([]byte{0x41}, 20)),
			Topics:  [][]byte{bytes.Repeat([]byte{0x11}, 32)},
			Data:    []byte{0x01},
		}},
		BlockNumber: 500,
	}
	rawReceipt, canonicalLogs, err := fiscobcos.MarshalNativeReceiptPreimage(receiptFields)
	if err != nil {
		return fiscobcos.SubmissionOutcome{}, err
	}
	receiptHash, err := fiscobcos.HashNativeEvidence(fiscobcos.HashKeccak256, rawReceipt)
	if err != nil {
		return fiscobcos.SubmissionOutcome{}, err
	}
	d.state.receipt = fiscobcos.ReceiptWithProof{
		Status: fiscobcos.ReceiptStatusOK, StatusMessage: "success",
		BlockNumber: 500, BlockHash: blockHash, Record: cloneAnchorRecord(d.state.record),
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
			ReceiptHashClaim:     append([]byte(nil), receiptHash...),
			TransactionHash:      append([]byte(nil), attempt.TransactionHash...),
			TransactionProofRPC:  [][]byte{},
			ReceiptProofRPC:      [][]byte{},
			AnchorLogIndex:       0,
		},
		Evidence: fiscobcos.ReceiptEvidence{
			Fields:              receiptFields,
			RawCanonicalReceipt: rawReceipt,
			Status:              fiscobcos.ReceiptStatusOK,
			StatusMessage:       "success",
			CanonicalLogs:       canonicalLogs,
			ReceiptHash:         append([]byte(nil), receiptHash...),
			TransactionHash:     append([]byte(nil), attempt.TransactionHash...),
			TransactionProof:    [][]byte{},
			ReceiptProof:        [][]byte{},
			DecodedAnchorEvent:  []byte("canonical-anchor-event"),
		},
	}
	if d.state.failAfterEffectOnce {
		d.state.failAfterEffectOnce = false
		return fiscobcos.SubmissionOutcome{}, errors.New("connection lost after submission")
	}
	return fiscobcos.SubmissionOutcome{
		Status: status, StatusMessage: statusMessage,
		ObservedAtUnixN: int64(d.state.submitCalls),
	}, nil
}
func (d *fakeBCOSDriver) ReadAnchor(context.Context, []byte) (fiscobcos.AnchorRecord, error) {
	if d.readErr != nil {
		return fiscobcos.AnchorRecord{}, d.readErr
	}
	d.state.mu.Lock()
	defer d.state.mu.Unlock()
	if d.state.hideRecordReads > 0 {
		d.state.hideRecordReads--
		return fiscobcos.AnchorRecord{}, nil
	}
	return cloneAnchorRecord(d.state.record), nil
}
func (d *fakeBCOSDriver) GetReceiptWithProof(_ context.Context, attempt fiscobcos.TransactionSubmission) (fiscobcos.ReceiptWithProof, error) {
	if d.readErr != nil {
		return fiscobcos.ReceiptWithProof{}, d.readErr
	}
	d.state.mu.Lock()
	defer d.state.mu.Unlock()
	if !d.state.record.Exists ||
		!bytes.Equal(d.state.receipt.Evidence.TransactionHash, attempt.TransactionHash) {
		return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrTransactionNotFound
	}
	return cloneReceipt(d.state.receipt), nil
}
func (d *fakeBCOSDriver) GetBlockHeader(context.Context, uint64) (fiscobcos.BlockHeader, error) {
	if d.readErr != nil {
		return fiscobcos.BlockHeader{}, d.readErr
	}
	return fakeBCOSBlockHeader(), nil
}
func (d *fakeBCOSDriver) GetConsensusSnapshot(context.Context, uint64) (fiscobcos.ConsensusSnapshot, error) {
	if d.readErr != nil {
		return fiscobcos.ConsensusSnapshot{}, d.readErr
	}
	return fiscobcos.ConsensusSnapshot{
		BlockNumber: 500, BlockHash: append([]byte(nil), fakeBCOSBlockHeader().Evidence.BlockHash...),
		Finality: fiscobcos.FinalityEvidence{Signatures: []fiscobcos.CommitSignature{
			{ValidatorNodeID: "validator-a", Signature: bytes.Repeat([]byte{0x81}, 64)},
			{ValidatorNodeID: "validator-b", Signature: bytes.Repeat([]byte{0x82}, 64)},
			{ValidatorNodeID: "validator-c", Signature: bytes.Repeat([]byte{0x83}, 64)},
		}},
	}, nil
}
func (d *fakeBCOSDriver) Close() error { d.closed = true; return nil }

func fakeBCOSBlockHeader() fiscobcos.BlockHeader {
	fields := fiscobcos.NativeBlockHeaderFields{
		Version:          0,
		ParentInfo:       []fiscobcos.NativeParentInfo{{BlockNumber: 499, BlockHash: bytes.Repeat([]byte{0x70}, 32)}},
		TransactionsRoot: bytes.Repeat([]byte{0x73}, 32),
		ReceiptsRoot:     bytes.Repeat([]byte{0x74}, 32),
		StateRoot:        bytes.Repeat([]byte{0x75}, 32),
		BlockNumber:      500,
		GasUsed:          "1",
		Timestamp:        100,
		Sealer:           0,
		SealerList:       [][]byte{[]byte("validator-a")},
		ConsensusWeights: []int64{1},
	}
	raw, err := fiscobcos.MarshalNativeBlockHeaderPreimage(fields)
	if err != nil {
		panic(err)
	}
	hash, err := fiscobcos.HashNativeEvidence(fiscobcos.HashKeccak256, raw)
	if err != nil {
		panic(err)
	}
	return fiscobcos.BlockHeader{
		Evidence: fiscobcos.BlockEvidence{
			Fields: fields, RawCanonicalHeader: raw, BlockHash: hash, BlockNumber: 500,
		},
		Observation: fiscobcos.BlockRPCObservation{
			NormalizedRPCHeader: []byte("normalized-rpc-header"),
			BlockHashClaim:      append([]byte(nil), hash...),
			BlockNumber:         500,
		},
	}
}

func publishBCOSForTest(t *testing.T, sink *FISCOBCOSStandardSink, sth model.SignedTreeHead) (model.STHAnchorResult, error) {
	t.Helper()
	var providerState []byte
	return sink.PublishDurable(context.Background(), model.STHAnchorAttempt{
		Generation: 1,
		Target:     sth,
	}, func(_ context.Context, expected, next []byte) error {
		if !bytes.Equal(expected, providerState) {
			return errors.New("stale test provider state")
		}
		providerState = append([]byte(nil), next...)
		return nil
	})
}

func TestFISCOBCOSStandardSinkPublishesCompleteRawEvidence(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{
		TrustConfig: trust, Drivers: drivers, Clock: func() time.Time { return time.Unix(10, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	sth := testSTH(testScheduleKey(fiscobcos.SinkName), 8, 0x18)
	result, err := publishBCOSForTest(t, sink, sth)
	if err != nil {
		t.Fatal(err)
	}
	if result.SinkName != fiscobcos.SinkName || result.TreeSize != sth.TreeSize || result.PublishedAtUnixN == 0 {
		t.Fatalf("result=%+v", result)
	}
	if result.EvidenceStage != model.AnchorEvidenceStageRaw || model.AnchorResultProvidesOfflineL5(result) {
		t.Fatalf("raw result must not satisfy L5: %+v", result)
	}
	proof, err := fiscobcos.UnmarshalProof(result.Proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.TransactionAttempts) != 1 ||
		len(proof.Receipt.TransactionProof) != 0 ||
		len(proof.Finality.Signatures) != 3 {
		t.Fatalf("proof=%+v", proof)
	}
	if err := fiscobcos.ValidateProofAgainstTrustConfig(sth, result, trust); err != nil {
		t.Fatalf("proof trust binding failed: %v", err)
	}
}

func TestFISCOBCOSStandardSinkSystemHealthAndEndpointMetrics(t *testing.T) {
	t.Parallel()

	trust, drivers := fakeBCOSFixture(t)
	trust.Endpoints = append(trust.Endpoints, "127.0.0.1:20202")
	base := drivers[0].(*fakeBCOSDriver)
	probe := cloneChainProbe(base.probe)
	probe.Endpoint = trust.Endpoints[2]
	drivers = append(drivers, &fakeBCOSDriver{endpoint: probe.Endpoint, probe: probe, state: base.state})
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
	drivers[2].(*fakeBCOSDriver).probe.Height = 490
	status, err = sink.Status(context.Background())
	if err != nil || status.State != model.AnchorSystemStateDegraded {
		t.Fatalf("degraded status=%+v err=%v", status, err)
	}
	for index := range drivers {
		label := fmt.Sprintf("%d", index)
		wantHealthy := float64(1)
		wantStale := float64(0)
		if index == 2 {
			wantHealthy = 0
			wantStale = 1
		}
		if got := testutil.ToFloat64(metrics.AnchorProviderEndpointHealthy.WithLabelValues(fiscobcos.SinkName, label)); got != wantHealthy {
			t.Fatalf("endpoint %d healthy metric=%v, want %v", index, got, wantHealthy)
		}
		if got := testutil.ToFloat64(metrics.AnchorProviderEndpointStale.WithLabelValues(fiscobcos.SinkName, label)); got != wantStale {
			t.Fatalf("endpoint %d stale metric=%v, want %v", index, got, wantStale)
		}
	}
	if got := testutil.ToFloat64(metrics.AnchorProviderQuorumHealthy.WithLabelValues(fiscobcos.SinkName)); got != 1 {
		t.Fatalf("quorum healthy metric=%v, want 1", got)
	}
}

func TestFISCOBCOSAnchorProofStrictWireFormat(t *testing.T) {
	t.Parallel()
	trust, drivers := fakeBCOSFixture(t)
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{
		TrustConfig: trust, Drivers: drivers, Clock: func() time.Time { return time.Unix(10, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := publishBCOSForTest(t, sink, testSTH(testScheduleKey(fiscobcos.SinkName), 8, 0x18))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := fiscobcos.UnmarshalProof(result.Proof)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := fiscobcos.UnmarshalProof(append(append([]byte(nil), result.Proof...), 0)); err == nil {
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
	if _, err := fiscobcos.UnmarshalProof(unknown); err == nil {
		t.Fatal("accepted an unknown anchor proof field")
	}
	mode, err := cbor.EncOptions{Sort: cbor.SortNone, IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden}.EncMode()
	if err != nil {
		t.Fatal(err)
	}
	nonCanonical, err := mode.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(nonCanonical, result.Proof) {
		t.Fatal("test encoder unexpectedly emitted canonical field order")
	}
	if _, err := fiscobcos.UnmarshalProof(nonCanonical); err == nil {
		t.Fatal("accepted non-canonical CBOR")
	}
	tampered := proof
	tampered.SuccessfulTransactionHash = bytes.Repeat([]byte{0xff}, 32)
	tamperedBytes, err := cborx.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fiscobcos.UnmarshalProof(tamperedBytes); err == nil {
		t.Fatal("accepted successful transaction binding tamper")
	}
	if _, err := fiscobcos.UnmarshalProof(make([]byte, fiscobcos.MaxProofBytes+1)); err == nil {
		t.Fatal("accepted oversized anchor proof")
	}
	proof.TransactionAttempts[0].RawCanonicalTransaction = make([]byte, fiscobcos.MaxProofBytes)
	if _, err := fiscobcos.MarshalProof(proof); err == nil {
		t.Fatal("accepted oversized transaction observation before encoding")
	}
}

func TestFISCOBCOSStandardSinkUsesConservativeQuorumHeightAcrossNormalDrift(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	drivers[1].(*fakeBCOSDriver).probe.Height++
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = publishBCOSForTest(t, sink, testSTH(testScheduleKey(fiscobcos.SinkName), 8, 0x18)); err != nil {
		t.Fatalf("normal height drift blocked quorum publication: %v", err)
	}
	state := drivers[0].(*fakeBCOSDriver).state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.submitCalls != 1 {
		t.Fatalf("submit calls=%d, want 1", state.submitCalls)
	}
}

func TestFISCOBCOSStandardSinkPublishesWithUnavailableMinority(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	trust.Endpoints = append(trust.Endpoints, "127.0.0.1:20202")
	base := drivers[0].(*fakeBCOSDriver)
	probe := cloneChainProbe(base.probe)
	probe.Endpoint = trust.Endpoints[2]
	drivers = append(drivers, &fakeBCOSDriver{endpoint: probe.Endpoint, probe: probe, state: base.state})
	base.probeErr = errors.New("endpoint unavailable")
	base.readErr = errors.New("endpoint unavailable")
	metrics := observability.NewMetrics()
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{
		TrustConfig: trust, Drivers: drivers, Metrics: metrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publishBCOSForTest(t, sink, testSTH(testScheduleKey(fiscobcos.SinkName), 8, 0x18)); err != nil {
		t.Fatalf("unavailable minority blocked publication: %v", err)
	}
	base.state.mu.Lock()
	defer base.state.mu.Unlock()
	if base.state.prepareCalls != 1 || base.state.submitCalls != 1 {
		t.Fatalf("prepare calls=%d submit calls=%d, want 1/1", base.state.prepareCalls, base.state.submitCalls)
	}
	if got := testutil.ToFloat64(metrics.AnchorProviderEndpointHealthy.WithLabelValues(fiscobcos.SinkName, "0")); got != 0 {
		t.Fatalf("unavailable endpoint healthy metric=%v, want 0", got)
	}
	if got := testutil.ToFloat64(metrics.AnchorProviderQuorumHealthy.WithLabelValues(fiscobcos.SinkName)); got != 1 {
		t.Fatalf("quorum healthy metric=%v, want 1", got)
	}
}

func TestFISCOBCOSStandardSinkRebroadcastsExactPreparedBytesAfterEndpointFailover(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	trust.Endpoints = append(trust.Endpoints, "127.0.0.1:20202")
	base := drivers[0].(*fakeBCOSDriver)
	probe := cloneChainProbe(base.probe)
	probe.Endpoint = trust.Endpoints[2]
	drivers = append(drivers, &fakeBCOSDriver{endpoint: probe.Endpoint, probe: probe, state: base.state})
	base.submitErrOnce = errors.New("connection lost before response")
	metrics := observability.NewMetrics()
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{
		TrustConfig: trust, Drivers: drivers, Metrics: metrics,
	})
	if err != nil {
		t.Fatal(err)
	}

	sth := testSTH(testScheduleKey(fiscobcos.SinkName), 9, 0x19)
	inFlight := model.STHAnchorAttempt{Generation: 9, Target: sth}
	var providerState []byte
	checkpoint := func(_ context.Context, expected, next []byte) error {
		if !bytes.Equal(expected, providerState) {
			return errors.New("stale provider state")
		}
		providerState = append([]byte(nil), next...)
		return nil
	}
	if _, err := sink.PublishDurable(context.Background(), inFlight, checkpoint); err == nil {
		t.Fatal("ambiguous first endpoint response unexpectedly completed")
	}
	journal, err := fiscobcos.UnmarshalAttemptJournal(providerState)
	if err != nil {
		t.Fatal(err)
	}
	if len(journal.Attempts) != 1 || journal.Attempts[0].Outcome != fiscobcos.AttemptOutcomeSubmitUnknown {
		t.Fatalf("journal after ambiguous submit=%+v", journal)
	}
	preparedBytes := append([]byte(nil), journal.Attempts[0].Transaction.RawCanonicalTransaction...)

	base.probeErr = errors.New("endpoint unavailable")
	base.readErr = errors.New("endpoint unavailable")
	inFlight.ProviderState = append([]byte(nil), providerState...)
	result, err := sink.PublishDurable(context.Background(), inFlight, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := fiscobcos.UnmarshalProof(result.Proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.TransactionAttempts) != 1 ||
		!bytes.Equal(proof.TransactionAttempts[0].RawCanonicalTransaction, preparedBytes) {
		t.Fatal("endpoint failover replaced the immutable prepared transaction")
	}
	base.state.mu.Lock()
	defer base.state.mu.Unlock()
	if base.state.prepareCalls != 1 || base.state.submitCalls != 2 {
		t.Fatalf("prepare calls=%d submit calls=%d, want 1/2", base.state.prepareCalls, base.state.submitCalls)
	}
	if got := testutil.ToFloat64(metrics.AnchorProviderRetryEvents.WithLabelValues(
		fiscobcos.SinkName,
		bcosRetryReasonExactTransaction,
	)); got != 1 {
		t.Fatalf("exact-transaction retry metric=%v, want 1", got)
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

func TestFISCOBCOSStandardSinkRejectsConflictingAnchorFromAnyEndpoint(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	trust.Endpoints = append(trust.Endpoints, "127.0.0.1:20202")
	base := drivers[0].(*fakeBCOSDriver)
	probe := cloneChainProbe(base.probe)
	probe.Endpoint = trust.Endpoints[2]
	conflicting := &fakeBCOSState{record: fiscobcos.AnchorRecord{
		StreamID: bytes.Repeat([]byte{0x31}, 32), TreeSize: 8,
		RootHash: bytes.Repeat([]byte{0xff}, 32), SignedSTHDigest: bytes.Repeat([]byte{0x41}, 32),
		Publisher: bytes.Repeat([]byte{0x61}, 20), PayloadVersion: 1, Exists: true,
	}}
	drivers = append(drivers, &fakeBCOSDriver{
		endpoint: probe.Endpoint,
		probe:    probe,
		state:    conflicting,
	})
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}
	_, err = publishBCOSForTest(t, sink, testSTH(testScheduleKey(fiscobcos.SinkName), 8, 0x18))
	if !errors.Is(err, ErrPermanent) || !errors.Is(err, fiscobcos.ErrContractMismatch) {
		t.Fatalf("conflicting endpoint error=%v", err)
	}
	base.state.mu.Lock()
	defer base.state.mu.Unlock()
	if base.state.submitCalls != 0 {
		t.Fatalf("conflicting existing anchor allowed %d side effects", base.state.submitCalls)
	}
}

func TestFISCOBCOSPostSubmitConflictDoesNotAdvanceAnchorResult(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	trust.Endpoints = append(trust.Endpoints, "127.0.0.1:20202")
	base := drivers[0].(*fakeBCOSDriver)
	probe := cloneChainProbe(base.probe)
	probe.Endpoint = trust.Endpoints[2]
	conflicting := &fakeBCOSState{
		record: fiscobcos.AnchorRecord{
			StreamID: bytes.Repeat([]byte{0x31}, 32), TreeSize: 8,
			RootHash: bytes.Repeat([]byte{0xff}, 32), SignedSTHDigest: bytes.Repeat([]byte{0x41}, 32),
			Publisher: bytes.Repeat([]byte{0x61}, 20), PayloadVersion: 1, Exists: true,
		},
		hideRecordReads: 2,
	}
	drivers = append(drivers, &fakeBCOSDriver{endpoint: probe.Endpoint, probe: probe, state: conflicting})
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}
	store := newBoundTestLocalStore(t, t.TempDir())
	key := testScheduleKey(fiscobcos.SinkName)
	sth := testSTH(key, 8, 0x18)
	offer(t, store, key, sth, 100, 100)
	now := time.Unix(0, 100)
	service := newTestService(t, store, sink, key, &now, nil)
	service.tick(context.Background())

	if _, found, err := store.GetSTHAnchorResult(context.Background(), sth.TreeSize); err != nil || found {
		t.Fatalf("conflicting readback result found=%v err=%v", found, err)
	}
	if latest, found, err := store.LatestSTHAnchorResultForKey(context.Background(), key); err != nil || found {
		t.Fatalf("conflicting readback latest result=%+v found=%v err=%v", latest, found, err)
	}
	schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.InFlight == nil || !schedule.InFlight.TerminalFailure {
		t.Fatalf("conflicting readback schedule=%+v found=%v err=%v", schedule, found, err)
	}
	base.state.mu.Lock()
	defer base.state.mu.Unlock()
	if base.state.submitCalls != 1 {
		t.Fatalf(
			"submit calls=%d, want exactly one before fail-closed readback; last error=%q",
			base.state.submitCalls,
			schedule.InFlight.LastErrorMessage,
		)
	}
}

func TestFISCOBCOSReadbackDisagreementRemainsRecoverOnlyAfterConvergence(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	trust.Endpoints = append(trust.Endpoints, "127.0.0.1:20202")
	trust.ReadQuorum = 3
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
	convergedReceipt := cloneReceipt(base.state.receipt)
	base.state.mu.Unlock()
	laggingState.mu.Lock()
	laggingState.record = converged
	laggingState.receipt = convergedReceipt
	laggingState.mu.Unlock()

	now = now.Add(time.Second)
	second := newTestService(t, store, sink, key, &now, nil)
	second.tick(context.Background())
	schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.InFlight != nil {
		t.Fatalf("recovered schedule after convergence=%+v in_flight=%+v found=%v err=%v", schedule, schedule.InFlight, found, err)
	}
	if _, found, err := store.GetSTHAnchorResult(context.Background(), sth.TreeSize); err != nil || !found {
		t.Fatalf("recovered result found=%v err=%v", found, err)
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
	_, err = publishBCOSForTest(t, sink, testSTH(testScheduleKey(fiscobcos.SinkName), 8, 0x18))
	if errors.Is(err, ErrPermanent) || !errors.Is(err, fiscobcos.ErrIncompleteChainEvidence) {
		t.Fatalf("receipt-only error=%v", err)
	}
}

func TestFISCOBCOSStandardSinkDoesNotResubmitExistingAnchorWithoutEvidence(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	driver := drivers[0].(*fakeBCOSDriver)
	sth := testSTH(testScheduleKey(fiscobcos.SinkName), 8, 0x18)
	request := fakeSubmitRequest(t, sth)
	attempt, err := driver.PrepareAnchor(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := driver.SubmitPreparedAnchor(context.Background(), attempt); err != nil {
		t.Fatal(err)
	}
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}
	_, err = publishBCOSForTest(t, sink, sth)
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

func (d *attemptMismatchDriver) PrepareAnchor(ctx context.Context, request fiscobcos.SubmitRequest) (fiscobcos.TransactionSubmission, error) {
	attempt, err := d.fakeBCOSDriver.PrepareAnchor(ctx, request)
	attempt.ChainID = "wrong-chain"
	return attempt, err
}

func TestFISCOBCOSPostSubmitValidationFailuresAreClassified(t *testing.T) {
	for _, test := range []struct {
		name         string
		wrap         func(*fakeBCOSDriver) fiscobcos.Driver
		wantTerminal bool
		wantSubmits  int
	}{
		{name: "missing receipt proofs", wrap: func(driver *fakeBCOSDriver) fiscobcos.Driver {
			return &receiptOnlyDriver{fakeBCOSDriver: driver}
		}, wantSubmits: 1},
		{name: "invalid receipt status", wrap: func(driver *fakeBCOSDriver) fiscobcos.Driver {
			return &statusMismatchDriver{fakeBCOSDriver: driver}
		}, wantSubmits: 1},
		{name: "submission identity mismatch", wrap: func(driver *fakeBCOSDriver) fiscobcos.Driver {
			return &attemptMismatchDriver{fakeBCOSDriver: driver}
		}, wantTerminal: true, wantSubmits: 0},
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
				schedule.InFlight.TerminalFailure != test.wantTerminal {
				t.Fatalf("schedule=%+v found=%v error=%v, want terminal=%v", schedule, found, err, test.wantTerminal)
			}
			base.state.mu.Lock()
			defer base.state.mu.Unlock()
			if base.state.submitCalls != test.wantSubmits {
				t.Fatalf("submit calls=%d, want %d", base.state.submitCalls, test.wantSubmits)
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
	if result, found, err := store.GetSTHAnchorResult(context.Background(), sth.TreeSize); err != nil || !found {
		t.Fatalf("unknown-outcome result was not recovered: result=%+v found=%v err=%v", result, found, err)
	}
	schedule, found, err = store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.InFlight != nil {
		t.Fatalf("recovered schedule=%+v found=%v err=%v", schedule, found, err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.submitCalls != 1 {
		t.Fatalf("submit calls=%d, visible exact record must not be resubmitted", state.submitCalls)
	}
}

func TestFISCOBCOSBlockLimitRetryPreservesEverySignedAttempt(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	state := drivers[0].(*fakeBCOSDriver).state
	state.submitStatuses = []int{int(fiscobcos.ReceiptStatusCodeBlockLimit), fiscobcos.ReceiptStatusOK}
	metrics := observability.NewMetrics()
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{
		TrustConfig: trust, Drivers: drivers, Metrics: metrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := newBoundTestLocalStore(t, t.TempDir())
	key := testScheduleKey(fiscobcos.SinkName)
	sth := testSTH(key, 12, 0x1c)
	offer(t, store, key, sth, 100, 100)
	now := time.Unix(0, 100)
	service := newTestService(t, store, sink, key, &now, func(config *Config) {
		config.InitialBackoff = time.Nanosecond
		config.MaxBackoff = time.Nanosecond
	})
	service.tick(context.Background())

	schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
	if err != nil || !found || schedule.InFlight == nil {
		t.Fatalf("schedule after block-limit rejection=%+v found=%v err=%v", schedule, found, err)
	}
	firstJournal, err := fiscobcos.UnmarshalAttemptJournal(schedule.InFlight.ProviderState)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstJournal.Attempts) != 1 ||
		firstJournal.Attempts[0].Outcome != fiscobcos.AttemptOutcomeReceiptBlockLimitRejected ||
		firstJournal.Attempts[0].Submission == nil ||
		firstJournal.Attempts[0].Submission.Status != fiscobcos.ReceiptStatusCodeBlockLimit {
		t.Fatalf("first journal=%+v", firstJournal)
	}
	firstTransaction := append([]byte(nil), firstJournal.Attempts[0].Transaction.RawCanonicalTransaction...)

	now = now.Add(time.Second)
	service = newTestService(t, store, sink, key, &now, nil)
	service.tick(context.Background())
	result, found, err := store.GetSTHAnchorResult(context.Background(), sth.TreeSize)
	if err != nil || !found {
		current, _, _ := store.GetSTHAnchorSchedule(context.Background(), key)
		t.Fatalf("result found=%v err=%v schedule=%+v", found, err, current)
	}
	proof, err := fiscobcos.UnmarshalProof(result.Proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.TransactionAttempts) != 2 ||
		proof.TransactionAttempts[0].Outcome != fiscobcos.AttemptOutcomeReceiptBlockLimitRejected ||
		proof.TransactionAttempts[0].Submission == nil ||
		proof.TransactionAttempts[0].Submission.Status != fiscobcos.ReceiptStatusCodeBlockLimit ||
		!bytes.Equal(proof.TransactionAttempts[0].RawCanonicalTransaction, firstTransaction) ||
		proof.TransactionAttempts[1].Outcome != fiscobcos.AttemptOutcomeReceiptSuccess ||
		!bytes.Equal(proof.TransactionAttempts[0].Input, proof.TransactionAttempts[1].Input) ||
		bytes.Equal(proof.TransactionAttempts[0].RawCanonicalTransaction, proof.TransactionAttempts[1].RawCanonicalTransaction) ||
		proof.SuccessfulAttemptOrdinal != 2 {
		t.Fatalf("proof attempts=%+v", proof.TransactionAttempts)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.prepareCalls != 2 || state.submitCalls != 2 {
		t.Fatalf("prepare calls=%d submit calls=%d, want 2/2", state.prepareCalls, state.submitCalls)
	}
	if got := testutil.ToFloat64(metrics.AnchorProviderRetryEvents.WithLabelValues(
		fiscobcos.SinkName,
		bcosRetryReasonBlockLimitRefresh,
	)); got != 1 {
		t.Fatalf("block-limit refresh metric=%v, want 1", got)
	}
}

func TestFISCOBCOSPreparedCheckpointFailurePreventsSideEffectAndResumesExactBytes(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	state := drivers[0].(*fakeBCOSDriver).state
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}
	sth := testSTH(testScheduleKey(fiscobcos.SinkName), 13, 0x1d)
	inFlight := model.STHAnchorAttempt{Generation: 7, Target: sth}
	var providerState []byte
	checkpointFailed := false
	_, err = sink.PublishDurable(context.Background(), inFlight, func(_ context.Context, expected, next []byte) error {
		if !bytes.Equal(expected, providerState) {
			return errors.New("stale provider state")
		}
		providerState = append([]byte(nil), next...)
		if !checkpointFailed {
			checkpointFailed = true
			return errors.New("simulated crash after durable checkpoint")
		}
		return nil
	})
	if err == nil {
		t.Fatal("checkpoint failure was ignored")
	}
	state.mu.Lock()
	if state.submitCalls != 0 {
		state.mu.Unlock()
		t.Fatalf("side effect occurred before successful checkpoint: %d", state.submitCalls)
	}
	state.mu.Unlock()
	prepared, err := fiscobcos.UnmarshalAttemptJournal(providerState)
	if err != nil {
		t.Fatal(err)
	}
	preparedBytes := append([]byte(nil), prepared.Attempts[0].Transaction.RawCanonicalTransaction...)

	inFlight.ProviderState = append([]byte(nil), providerState...)
	result, err := sink.PublishDurable(context.Background(), inFlight, func(_ context.Context, expected, next []byte) error {
		if !bytes.Equal(expected, providerState) {
			return errors.New("stale provider state")
		}
		providerState = append([]byte(nil), next...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := fiscobcos.UnmarshalProof(result.Proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.TransactionAttempts) != 1 ||
		!bytes.Equal(proof.TransactionAttempts[0].RawCanonicalTransaction, preparedBytes) {
		t.Fatal("resumed publication replaced prepared transaction bytes")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.prepareCalls != 1 || state.submitCalls != 1 {
		t.Fatalf("prepare calls=%d submit calls=%d, want 1/1", state.prepareCalls, state.submitCalls)
	}
}

func TestFISCOBCOSCheckpointCASConflictCannotSubmit(t *testing.T) {
	trust, drivers := fakeBCOSFixture(t)
	state := drivers[0].(*fakeBCOSDriver).state
	sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sink.PublishDurable(context.Background(), model.STHAnchorAttempt{
		Generation: 8,
		Target:     testSTH(testScheduleKey(fiscobcos.SinkName), 14, 0x1e),
	}, func(context.Context, []byte, []byte) error {
		return errors.New("provider-state compare-and-swap conflict")
	})
	if err == nil {
		t.Fatal("checkpoint CAS conflict was ignored")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.submitCalls != 0 {
		t.Fatalf("CAS loser produced %d side effects", state.submitCalls)
	}
}

func TestFISCOBCOSSubmissionStatusRecoveryMatrix(t *testing.T) {
	tests := []struct {
		name            string
		statuses        []int
		effectStatuses  map[int]bool
		wantResult      bool
		wantTerminal    bool
		wantPrepare     int
		wantSubmit      int
		wantJournalLast fiscobcos.AttemptOutcome
		wantSubmission  int64
	}{
		{
			name: "pool full retries exact transaction",
			statuses: []int{
				fiscobcos.ReceiptStatusTransactionPoolFull,
				fiscobcos.ReceiptStatusOK,
			},
			wantResult: true, wantPrepare: 1, wantSubmit: 2,
		},
		{
			name: "pool timeout retries exact transaction after lookup",
			statuses: []int{
				fiscobcos.ReceiptStatusPoolTimeout,
				fiscobcos.ReceiptStatusOK,
			},
			wantResult: true, wantPrepare: 1, wantSubmit: 2,
		},
		{
			name: "unknown pool status remains ambiguous and retries exact transaction",
			statuses: []int{
				10099,
				fiscobcos.ReceiptStatusOK,
			},
			wantResult: true, wantPrepare: 1, wantSubmit: 2,
		},
		{
			name: "nonce duplicate recovers receipt without resubmit",
			statuses: []int{
				fiscobcos.ReceiptStatusNonceCheckFailed,
			},
			effectStatuses: map[int]bool{fiscobcos.ReceiptStatusNonceCheckFailed: true},
			wantResult:     true, wantPrepare: 1, wantSubmit: 1,
			wantSubmission: fiscobcos.ReceiptStatusNonceCheckFailed,
		},
		{
			name: "already in chain recovers receipt without resubmit",
			statuses: []int{
				fiscobcos.ReceiptStatusAlreadyInChain,
			},
			effectStatuses: map[int]bool{fiscobcos.ReceiptStatusAlreadyInChain: true},
			wantResult:     true, wantPrepare: 1, wantSubmit: 1,
			wantSubmission: fiscobcos.ReceiptStatusAlreadyInChain,
		},
		{
			name: "invalid signature is terminal",
			statuses: []int{
				10008,
			},
			wantTerminal: true, wantPrepare: 1, wantSubmit: 1,
			wantJournalLast: fiscobcos.AttemptOutcomeReceiptTerminalRejected,
		},
		{
			name: "sender no EOA is terminal",
			statuses: []int{
				10014,
			},
			wantTerminal: true, wantPrepare: 1, wantSubmit: 1,
			wantJournalLast: fiscobcos.AttemptOutcomeReceiptTerminalRejected,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			trust, drivers := fakeBCOSFixture(t)
			state := drivers[0].(*fakeBCOSDriver).state
			state.submitStatuses = test.statuses
			state.effectStatuses = test.effectStatuses
			sink, err := NewFISCOBCOSStandardSink(FISCOBCOSStandardSinkConfig{TrustConfig: trust, Drivers: drivers})
			if err != nil {
				t.Fatal(err)
			}
			store := newBoundTestLocalStore(t, t.TempDir())
			key := testScheduleKey(fiscobcos.SinkName)
			sth := testSTH(key, 15, 0x1f)
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

			result, resultFound, err := store.GetSTHAnchorResult(context.Background(), sth.TreeSize)
			if err != nil || resultFound != test.wantResult {
				current, _, _ := store.GetSTHAnchorSchedule(context.Background(), key)
				t.Fatalf("result found=%v want=%v err=%v in_flight=%#v", resultFound, test.wantResult, err, current.InFlight)
			}
			if resultFound && test.wantSubmission != 0 {
				proof, err := fiscobcos.UnmarshalProof(result.Proof)
				if err != nil {
					t.Fatal(err)
				}
				if len(proof.TransactionAttempts) != 1 ||
					proof.TransactionAttempts[0].Submission == nil ||
					proof.TransactionAttempts[0].Submission.Status != test.wantSubmission {
					t.Fatalf("submission response not retained: %+v", proof.TransactionAttempts)
				}
			}
			schedule, found, err := store.GetSTHAnchorSchedule(context.Background(), key)
			if err != nil || !found {
				t.Fatalf("schedule found=%v err=%v", found, err)
			}
			if test.wantResult {
				if schedule.InFlight != nil {
					t.Fatalf("completed status retained InFlight: %+v", schedule.InFlight)
				}
			} else {
				if schedule.InFlight == nil || schedule.InFlight.TerminalFailure != test.wantTerminal {
					t.Fatalf("terminal schedule=%+v", schedule)
				}
				journal, err := fiscobcos.UnmarshalAttemptJournal(schedule.InFlight.ProviderState)
				if err != nil {
					t.Fatal(err)
				}
				if journal.Attempts[len(journal.Attempts)-1].Outcome != test.wantJournalLast {
					t.Fatalf("last journal outcome=%q", journal.Attempts[len(journal.Attempts)-1].Outcome)
				}
			}
			state.mu.Lock()
			defer state.mu.Unlock()
			if state.prepareCalls != test.wantPrepare || state.submitCalls != test.wantSubmit {
				t.Fatalf("prepare calls=%d submit calls=%d, want %d/%d", state.prepareCalls, state.submitCalls, test.wantPrepare, test.wantSubmit)
			}
		})
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
	in.Evidence.RawCanonicalReceipt = append([]byte(nil), in.Evidence.RawCanonicalReceipt...)
	in.Evidence.CanonicalLogs = cloneByteSlicesForTest(in.Evidence.CanonicalLogs)
	in.Evidence.ReceiptHash = append([]byte(nil), in.Evidence.ReceiptHash...)
	in.Evidence.TransactionHash = append([]byte(nil), in.Evidence.TransactionHash...)
	in.Evidence.TransactionProof = cloneByteSlicesForTest(in.Evidence.TransactionProof)
	in.Evidence.ReceiptProof = cloneByteSlicesForTest(in.Evidence.ReceiptProof)
	in.Evidence.DecodedAnchorEvent = append([]byte(nil), in.Evidence.DecodedAnchorEvent...)
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
