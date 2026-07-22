package sdk

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func TestNativeLogStreamUsesConfiguredSigningConcurrency(t *testing.T) {
	t.Parallel()

	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	probe := newSigningConcurrencyProbe(4)
	entries := make(chan LogEntry, 4)
	for index := range 4 {
		entries <- LogEntry{
			Reader: &blockingProbeReader{probe: probe, payload: []byte(`{"level":"info"}`)},
			Options: LogClaimOptions{
				ProducedAt:     time.Unix(20, int64(index)),
				Nonce:          bytes.Repeat([]byte{byte(index)}, 16),
				IdempotencyKey: "concurrency-" + strconv.Itoa(index),
			},
		}
	}
	close(entries)
	client, err := NewClientWithTransport(echoSignedClaimStreamTransport{})
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	out, err := client.SubmitLogStream(context.Background(), entries, Identity{
		TenantID:   "tenant-test",
		ClientID:   "client-test",
		KeyID:      "key-test",
		PrivateKey: privateKey,
	}, LogStreamOptions{Concurrency: 4, QueueSize: 4})
	if err != nil {
		t.Fatalf("SubmitLogStream: %v", err)
	}
	select {
	case <-probe.reached:
		close(probe.release)
	case <-time.After(time.Second):
		close(probe.release)
		t.Fatalf("maximum signing concurrency = %d, want 4", probe.maximum.Load())
	}
	count := 0
	for item := range out {
		if item.Err != nil {
			t.Fatalf("stream item error: %v", item.Err)
		}
		count++
	}
	if count != 4 {
		t.Fatalf("results = %d, want 4", count)
	}
}

func BenchmarkNativeLogStreamSigning256(b *testing.B) {
	for _, concurrency := range []int{1, 4} {
		b.Run("concurrency="+strconv.Itoa(concurrency), func(b *testing.B) {
			benchmarkNativeLogStreamSigning(b, concurrency)
		})
	}
}

func benchmarkNativeLogStreamSigning(b *testing.B, concurrency int) {
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
			Body: []byte(`{"level":"info","message":"native stream benchmark"}`),
			Options: LogClaimOptions{
				ProducedAt:     time.Unix(20, int64(index)),
				Nonce:          bytes.Repeat([]byte{byte(index)}, 16),
				IdempotencyKey: "benchmark-" + strconv.Itoa(index),
			},
		}
	}
	client, err := NewClientWithTransport(echoSignedClaimStreamTransport{})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		in := make(chan LogEntry, len(entries))
		for _, entry := range entries {
			in <- entry
		}
		close(in)
		out, err := client.SubmitLogStream(context.Background(), in, identity, LogStreamOptions{
			Concurrency: concurrency,
			QueueSize:   len(entries),
		})
		if err != nil {
			b.Fatal(err)
		}
		count := 0
		for item := range out {
			if item.Err != nil {
				b.Fatal(item.Err)
			}
			count++
		}
		if count != len(entries) {
			b.Fatalf("results = %d, want %d", count, len(entries))
		}
	}
}

type echoSignedClaimStreamTransport struct {
	stubTransport
}

type signingConcurrencyProbe struct {
	target  int64
	active  atomic.Int64
	maximum atomic.Int64
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func newSigningConcurrencyProbe(target int64) *signingConcurrencyProbe {
	return &signingConcurrencyProbe{
		target:  target,
		reached: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (p *signingConcurrencyProbe) enter() {
	active := p.active.Add(1)
	for {
		maximum := p.maximum.Load()
		if active <= maximum || p.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	if active >= p.target {
		p.once.Do(func() { close(p.reached) })
	}
	<-p.release
	p.active.Add(-1)
}

type blockingProbeReader struct {
	probe   *signingConcurrencyProbe
	payload []byte
	read    bool
}

func (r *blockingProbeReader) Read(dst []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	r.probe.enter()
	return copy(dst, r.payload), nil
}

func (echoSignedClaimStreamTransport) SubmitSignedClaimStream(_ context.Context, in <-chan signedClaimStreamItem) (<-chan signedClaimStreamItemResult, error) {
	out := make(chan signedClaimStreamItemResult)
	go func() {
		defer close(out)
		for item := range in {
			out <- signedClaimStreamItemResult{Index: item.Index}
		}
	}()
	return out, nil
}
