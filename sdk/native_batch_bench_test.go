package sdk

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func BenchmarkNativeLogBatch256(b *testing.B) {
	for _, concurrency := range []int{1, 4} {
		b.Run("concurrency="+strconv.Itoa(concurrency), func(b *testing.B) {
			benchmarkNativeLogBatch256(b, concurrency)
		})
	}
}

func benchmarkNativeLogBatch256(b *testing.B, concurrency int) {
	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		b.Fatal(err)
	}
	identity := Identity{
		TenantID:   "tenant-benchmark",
		ClientID:   "client-benchmark",
		KeyID:      "key-benchmark",
		PrivateKey: privateKey,
	}
	entries := make([]LogEntry, 256)
	for index := range entries {
		entries[index] = LogEntry{
			Body: []byte(`{"level":"info","message":"native batch benchmark"}`),
			Options: LogClaimOptions{
				ProducedAt:     time.Unix(20, int64(index)),
				Nonce:          bytes.Repeat([]byte{byte(index)}, 16),
				IdempotencyKey: "benchmark-" + strconv.Itoa(index),
			},
		}
	}
	client, err := NewClientWithTransport(echoSignedClaimBatchTransport{})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		result, err := client.SubmitLogBatch(context.Background(), entries, identity, LogSubmitOptions{Concurrency: concurrency})
		if err != nil {
			b.Fatal(err)
		}
		if result.Submitted != len(entries) {
			b.Fatalf("submitted = %d, want %d", result.Submitted, len(entries))
		}
	}
}

type echoSignedClaimBatchTransport struct {
	stubTransport
}

func (echoSignedClaimBatchTransport) SubmitSignedClaims(_ context.Context, signed []SignedClaim) ([]signedClaimBatchItemResult, error) {
	results := make([]signedClaimBatchItemResult, len(signed))
	for index := range results {
		results[index].Index = index
	}
	return results, nil
}
