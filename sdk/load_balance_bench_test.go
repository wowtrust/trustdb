package sdk

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestLoadBalancedDispatchRoundRobinOrder(t *testing.T) {
	t.Parallel()

	var hits [3]atomic.Int64
	transport := &loadBalancedTransport{
		transports: []Transport{
			dispatchTransport{endpoint: "one", hits: &hits[0]},
			dispatchTransport{endpoint: "two", hits: &hits[1]},
			dispatchTransport{endpoint: "three", hits: &hits[2]},
		},
		mode: LoadBalanceRoundRobin,
	}
	for range 6 {
		if _, err := transport.SubmitSignedClaim(context.Background(), SignedClaim{}); err != nil {
			t.Fatalf("SubmitSignedClaim: %v", err)
		}
	}
	for index := range hits {
		if got := hits[index].Load(); got != 2 {
			t.Fatalf("hits[%d] = %d, want 2", index, got)
		}
	}
}

func TestLoadBalancedDispatchFailoverStartsFirst(t *testing.T) {
	t.Parallel()

	var primaryHits atomic.Int64
	var secondaryHits atomic.Int64
	transport := &loadBalancedTransport{
		transports: []Transport{
			dispatchTransport{endpoint: "primary", hits: &primaryHits},
			dispatchTransport{endpoint: "secondary", hits: &secondaryHits},
		},
		mode: LoadBalanceFailover,
	}
	for range 3 {
		if _, err := transport.SubmitSignedClaim(context.Background(), SignedClaim{}); err != nil {
			t.Fatalf("SubmitSignedClaim: %v", err)
		}
	}
	if got := primaryHits.Load(); got != 3 {
		t.Fatalf("primary hits = %d, want 3", got)
	}
	if got := secondaryHits.Load(); got != 0 {
		t.Fatalf("secondary hits = %d, want 0", got)
	}
}

func TestLoadBalancedDispatchPreservesCancellationAndJoinedErrors(t *testing.T) {
	t.Parallel()

	firstErr := errors.New("first unavailable")
	secondErr := errors.New("second unavailable")
	transport := &loadBalancedTransport{
		transports: []Transport{
			dispatchTransport{endpoint: "one", err: firstErr},
			dispatchTransport{endpoint: "two", err: secondErr},
		},
		mode: LoadBalanceFailover,
	}
	_, err := transport.SubmitSignedClaim(context.Background(), SignedClaim{})
	if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("SubmitSignedClaim() error = %v, want both endpoint errors", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = transport.SubmitSignedClaim(ctx, SignedClaim{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("SubmitSignedClaim(canceled) error = %v, want context canceled", err)
	}
}

func BenchmarkLoadBalancedDispatchFailover(b *testing.B) {
	benchmarkLoadBalancedDispatch(b, LoadBalanceFailover)
}

func BenchmarkLoadBalancedDispatchRoundRobin(b *testing.B) {
	benchmarkLoadBalancedDispatch(b, LoadBalanceRoundRobin)
}

func benchmarkLoadBalancedDispatch(b *testing.B, mode LoadBalanceMode) {
	transport := &loadBalancedTransport{
		transports: []Transport{stubTransport{}, stubTransport{}, stubTransport{}},
		mode:       mode,
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := transport.SubmitSignedClaim(ctx, SignedClaim{}); err != nil {
			b.Fatal(err)
		}
	}
}

type dispatchTransport struct {
	stubTransport
	endpoint string
	hits     *atomic.Int64
	err      error
}

func (t dispatchTransport) Endpoint() string {
	return t.endpoint
}

func (t dispatchTransport) SubmitSignedClaim(context.Context, SignedClaim) (SubmitResult, error) {
	if t.hits != nil {
		t.hits.Add(1)
	}
	return SubmitResult{}, t.err
}
