package sdk

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

func TestNativeLogBatchUsesConfiguredSigningConcurrency(t *testing.T) {
	t.Parallel()

	identity := testLogIdentity(t)
	probe := newSigningConcurrencyProbe(4)
	entries := make([]LogEntry, 5)
	for index := range entries {
		entries[index] = LogEntry{
			Reader: &blockingProbeReader{probe: probe, payload: []byte(`{"level":"info"}`)},
			Options: LogClaimOptions{
				ProducedAt:     time.Unix(20, int64(index)),
				Nonce:          bytes.Repeat([]byte{byte(index)}, 16),
				IdempotencyKey: "concurrency-" + strconv.Itoa(index),
			},
		}
	}
	client, err := NewClientWithTransport(echoSignedClaimBatchTransport{})
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	type outcome struct {
		result LogBatchResult
		err    error
	}
	completed := make(chan outcome, 1)
	go func() {
		result, err := client.SubmitLogBatch(context.Background(), entries, identity, LogSubmitOptions{Concurrency: 4})
		completed <- outcome{result: result, err: err}
	}()
	select {
	case <-probe.reached:
		close(probe.release)
	case <-time.After(time.Second):
		close(probe.release)
		t.Fatalf("maximum signing concurrency = %d, want 4", probe.maximum.Load())
	}
	select {
	case outcome := <-completed:
		if outcome.err != nil {
			t.Fatalf("SubmitLogBatch: %v", outcome.err)
		}
		if outcome.result.Submitted != len(entries) {
			t.Fatalf("submitted = %d, want %d", outcome.result.Submitted, len(entries))
		}
		if maximum := probe.maximum.Load(); maximum != 4 {
			t.Fatalf("maximum signing concurrency = %d, want 4", maximum)
		}
	case <-time.After(time.Second):
		t.Fatal("SubmitLogBatch did not complete")
	}
}

func TestNativeLogBatchPreservesOrderAroundBuildFailures(t *testing.T) {
	t.Parallel()

	transport := &capturingSignedClaimBatchTransport{
		results: []signedClaimBatchItemResult{
			{Index: 1, Result: SubmitResult{RecordID: "record-third"}},
			{Index: 0, Result: SubmitResult{RecordID: "record-first"}},
		},
	}
	client, err := NewClientWithTransport(transport)
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	result, err := client.SubmitLogBatch(context.Background(), []LogEntry{
		{Body: []byte(`{"index":0}`), Options: fixedLogClaimOptions("first", 1)},
		{},
		{Body: []byte(`{"index":2}`), Options: fixedLogClaimOptions("third", 3)},
	}, testLogIdentity(t), LogSubmitOptions{Concurrency: 3})
	var batchErr *LogBatchError
	if !errors.As(err, &batchErr) {
		t.Fatalf("SubmitLogBatch error = %v, want LogBatchError", err)
	}
	if result.Submitted != 2 || result.Failed != 1 {
		t.Fatalf("result counts = submitted:%d failed:%d, want 2/1", result.Submitted, result.Failed)
	}
	if result.Results[0].Result.RecordID == "" ||
		result.Results[0].Result.SignedClaim.Claim.IdempotencyKey != "first" {
		t.Fatalf("result[0] = %+v", result.Results[0])
	}
	if result.Results[1].Err == nil {
		t.Fatalf("result[1] = %+v, want build error", result.Results[1])
	}
	if result.Results[2].Result.RecordID == "" ||
		result.Results[2].Result.SignedClaim.Claim.IdempotencyKey != "third" {
		t.Fatalf("result[2] = %+v", result.Results[2])
	}
	if got := transport.idempotencyKeys(); len(got) != 2 || got[0] != "first" || got[1] != "third" {
		t.Fatalf("submitted idempotency keys = %v, want [first third]", got)
	}
}

func TestCNSMV1NativeLogBatchPreservesSuiteAndOrder(t *testing.T) {
	t.Parallel()

	_, privateKey, err := GenerateCNSMV1SoftwareKey()
	if err != nil {
		t.Fatalf("GenerateCNSMV1SoftwareKey: %v", err)
	}
	transport := &capturingSignedClaimBatchTransport{
		results: []signedClaimBatchItemResult{
			{Index: 0, Result: SubmitResult{RecordID: "record-0"}},
			{Index: 1, Result: SubmitResult{RecordID: "record-1"}},
		},
	}
	client, err := NewClientWithTransportForSuite(transport, CryptoSuiteCNSMV1)
	if err != nil {
		t.Fatalf("NewClientWithTransportForSuite: %v", err)
	}
	result, err := client.SubmitLogBatch(
		context.Background(),
		[]LogEntry{
			{Body: []byte(`{"index":0}`), Options: fixedLogClaimOptions("cn-first", 1)},
			{Body: []byte(`{"index":1}`), Options: fixedLogClaimOptions("cn-second", 2)},
		},
		mustCNSMV1Identity(t, "tenant-cn", "client-cn", "client-sm2", privateKey),
		LogSubmitOptions{Concurrency: 2},
	)
	if err != nil {
		t.Fatalf("SubmitLogBatch: %v", err)
	}
	if result.Submitted != 2 ||
		result.Results[0].Result.SignedClaim.Claim.IdempotencyKey != "cn-first" ||
		result.Results[1].Result.SignedClaim.Claim.IdempotencyKey != "cn-second" {
		t.Fatalf("result = %+v", result)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	for index, signed := range transport.signed {
		if signed.CryptoSuite != cryptosuite.CNSMV1 ||
			signed.Claim.CryptoSuite != cryptosuite.CNSMV1 ||
			signed.Claim.Content.HashAlg != cryptosuite.HashSM3 ||
			signed.Signature.Alg != cryptosuite.SignatureSM2SM3 {
			t.Fatalf("signed[%d] = %+v", index, signed)
		}
	}
}

func testLogIdentity(t *testing.T) Identity {
	t.Helper()
	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	return mustINTLV1Identity(t, "tenant-test", "client-test", "key-test", privateKey)
}

func fixedLogClaimOptions(idempotencyKey string, nonce byte) LogClaimOptions {
	return LogClaimOptions{
		ProducedAt:     time.Unix(20, int64(nonce)),
		Nonce:          bytes.Repeat([]byte{nonce}, 16),
		IdempotencyKey: idempotencyKey,
	}
}

type capturingSignedClaimBatchTransport struct {
	stubTransport
	mu      sync.Mutex
	signed  []SignedClaim
	results []signedClaimBatchItemResult
}

func (t *capturingSignedClaimBatchTransport) SubmitSignedClaims(_ context.Context, signed []SignedClaim) ([]signedClaimBatchItemResult, error) {
	t.mu.Lock()
	t.signed = append([]SignedClaim(nil), signed...)
	t.mu.Unlock()
	results := append([]signedClaimBatchItemResult(nil), t.results...)
	for index := range results {
		if results[index].Err != nil || results[index].Index < 0 || results[index].Index >= len(signed) {
			continue
		}
		recordID := results[index].Result.RecordID
		if recordID == "" {
			recordID = "tr1-native-batch"
		}
		results[index].Result = validSDKSubmitResult(signed[results[index].Index], recordID)
	}
	return results, nil
}

func (t *capturingSignedClaimBatchTransport) idempotencyKeys() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, len(t.signed))
	for index := range t.signed {
		out[index] = t.signed[index].Claim.IdempotencyKey
	}
	return out
}
