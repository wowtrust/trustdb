package sdk

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/trustcrypto"
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
	if result.Results[0].Result.RecordID != "record-first" {
		t.Fatalf("result[0] = %+v", result.Results[0])
	}
	if result.Results[1].Err == nil {
		t.Fatalf("result[1] = %+v, want build error", result.Results[1])
	}
	if result.Results[2].Result.RecordID != "record-third" {
		t.Fatalf("result[2] = %+v", result.Results[2])
	}
	if got := transport.idempotencyKeys(); len(got) != 2 || got[0] != "first" || got[1] != "third" {
		t.Fatalf("submitted idempotency keys = %v, want [first third]", got)
	}
}

func testLogIdentity(t *testing.T) Identity {
	t.Helper()
	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	return Identity{
		TenantID:   "tenant-test",
		ClientID:   "client-test",
		KeyID:      "key-test",
		PrivateKey: privateKey,
	}
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
	return t.results, nil
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
