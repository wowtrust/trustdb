package sdk

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

// LoadBalanceMode controls how a multi-endpoint client chooses the first
// endpoint. Failover is always attempted on transport errors.
type LoadBalanceMode string

const (
	LoadBalanceRoundRobin LoadBalanceMode = "round_robin"
	LoadBalanceFailover   LoadBalanceMode = "failover"
)

// LoadBalanceOptions configures client-side endpoint selection. TrustDB keeps
// service nodes independent, so SDKs own discovery, retry, and failover.
type LoadBalanceOptions struct {
	Mode LoadBalanceMode
}

func NewLoadBalancedClient(endpoints []string, lb LoadBalanceOptions, opts ...Option) (*Client, error) {
	transports := make([]Transport, 0, len(endpoints))
	for _, endpoint := range endpoints {
		trimmed := strings.TrimSpace(endpoint)
		if trimmed == "" {
			continue
		}
		client, err := NewClient(trimmed, opts...)
		if err != nil {
			return nil, err
		}
		transports = append(transports, client.transport)
	}
	if len(transports) == 0 {
		return nil, errors.New("sdk: at least one endpoint is required")
	}
	return NewClientWithTransport(&loadBalancedTransport{
		transports: transports,
		mode:       lb.Mode,
	})
}

type loadBalancedTransport struct {
	transports []Transport
	next       atomic.Uint64
	mode       LoadBalanceMode
}

func (t *loadBalancedTransport) Endpoint() string {
	parts := make([]string, len(t.transports))
	for i, transport := range t.transports {
		parts[i] = transport.Endpoint()
	}
	return strings.Join(parts, ",")
}

func (t *loadBalancedTransport) Close() error {
	var joined error
	for _, transport := range t.transports {
		if closer, ok := transport.(interface{ Close() error }); ok {
			joined = errors.Join(joined, closer.Close())
		}
	}
	return joined
}

func (t *loadBalancedTransport) startIndex() int {
	if len(t.transports) == 0 || t.mode == LoadBalanceFailover {
		return 0
	}
	return int((t.next.Add(1) - 1) % uint64(len(t.transports)))
}

func tryEndpoints[T any](ctx context.Context, t *loadBalancedTransport, op string, fn func(context.Context, Transport) (T, error)) (T, error) {
	var zero T
	var errs error
	if ctx == nil {
		ctx = context.Background()
	}
	start := t.startIndex()
	for offset := range len(t.transports) {
		index := start + offset
		if index >= len(t.transports) {
			index -= len(t.transports)
		}
		transport := t.transports[index]
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		got, err := fn(ctx, transport)
		if err == nil {
			return got, nil
		}
		errs = errors.Join(errs, fmt.Errorf("%s %s: %w", op, transport.Endpoint(), err))
	}
	return zero, errs
}

func (t *loadBalancedTransport) CheckHealth(ctx context.Context) HealthStatus {
	var last HealthStatus
	start := t.startIndex()
	for offset := range len(t.transports) {
		index := start + offset
		if index >= len(t.transports) {
			index -= len(t.transports)
		}
		transport := t.transports[index]
		last = transport.CheckHealth(ctx)
		if last.OK {
			return last
		}
	}
	return last
}

func (t *loadBalancedTransport) SubmitSignedClaim(ctx context.Context, claim SignedClaim) (SubmitResult, error) {
	return tryEndpoints(ctx, t, "submit claim", func(ctx context.Context, transport Transport) (SubmitResult, error) {
		return transport.SubmitSignedClaim(ctx, claim)
	})
}

func (t *loadBalancedTransport) GetRecord(ctx context.Context, recordID string) (RecordIndex, error) {
	return tryEndpoints(ctx, t, "get record", func(ctx context.Context, transport Transport) (RecordIndex, error) {
		return transport.GetRecord(ctx, recordID)
	})
}

func (t *loadBalancedTransport) ListRecords(ctx context.Context, opts ListRecordsOptions) (RecordPage, error) {
	return tryEndpoints(ctx, t, "list records", func(ctx context.Context, transport Transport) (RecordPage, error) {
		return transport.ListRecords(ctx, opts)
	})
}

func (t *loadBalancedTransport) ListRootsPage(ctx context.Context, opts ListPageOptions) (RootPage, error) {
	return tryEndpoints(ctx, t, "list roots", func(ctx context.Context, transport Transport) (RootPage, error) {
		return transport.ListRootsPage(ctx, opts)
	})
}

func (t *loadBalancedTransport) GetProofBundle(ctx context.Context, recordID string) (ProofBundle, error) {
	return tryEndpoints(ctx, t, "get proof bundle", func(ctx context.Context, transport Transport) (ProofBundle, error) {
		return transport.GetProofBundle(ctx, recordID)
	})
}

func (t *loadBalancedTransport) ListRoots(ctx context.Context, limit int) ([]BatchRoot, error) {
	return tryEndpoints(ctx, t, "list roots", func(ctx context.Context, transport Transport) ([]BatchRoot, error) {
		return transport.ListRoots(ctx, limit)
	})
}

func (t *loadBalancedTransport) LatestRoot(ctx context.Context) (BatchRoot, error) {
	return tryEndpoints(ctx, t, "latest root", func(ctx context.Context, transport Transport) (BatchRoot, error) {
		return transport.LatestRoot(ctx)
	})
}

func (t *loadBalancedTransport) ListSTHs(ctx context.Context, opts ListPageOptions) (TreeHeadPage, error) {
	return tryEndpoints(ctx, t, "list sths", func(ctx context.Context, transport Transport) (TreeHeadPage, error) {
		return transport.ListSTHs(ctx, opts)
	})
}

func (t *loadBalancedTransport) GetGlobalProof(ctx context.Context, batchID string) (GlobalLogProof, error) {
	return tryEndpoints(ctx, t, "get global proof", func(ctx context.Context, transport Transport) (GlobalLogProof, error) {
		return transport.GetGlobalProof(ctx, batchID)
	})
}

func (t *loadBalancedTransport) ListGlobalLeaves(ctx context.Context, opts ListPageOptions) (GlobalLeafPage, error) {
	return tryEndpoints(ctx, t, "list global leaves", func(ctx context.Context, transport Transport) (GlobalLeafPage, error) {
		return transport.ListGlobalLeaves(ctx, opts)
	})
}

func (t *loadBalancedTransport) ListAnchors(ctx context.Context, opts ListPageOptions) (AnchorPage, error) {
	return tryEndpoints(ctx, t, "list anchors", func(ctx context.Context, transport Transport) (AnchorPage, error) {
		return transport.ListAnchors(ctx, opts)
	})
}

func (t *loadBalancedTransport) GetAnchor(ctx context.Context, treeSize uint64) (AnchorStatus, error) {
	return tryEndpoints(ctx, t, "get anchor", func(ctx context.Context, transport Transport) (AnchorStatus, error) {
		return transport.GetAnchor(ctx, treeSize)
	})
}

func (t *loadBalancedTransport) LatestSTH(ctx context.Context) (SignedTreeHead, error) {
	return tryEndpoints(ctx, t, "latest sth", func(ctx context.Context, transport Transport) (SignedTreeHead, error) {
		return transport.LatestSTH(ctx)
	})
}

func (t *loadBalancedTransport) GetSTH(ctx context.Context, treeSize uint64) (SignedTreeHead, error) {
	return tryEndpoints(ctx, t, "get sth", func(ctx context.Context, transport Transport) (SignedTreeHead, error) {
		return transport.GetSTH(ctx, treeSize)
	})
}

func (t *loadBalancedTransport) MetricsRaw(ctx context.Context) (string, error) {
	return tryEndpoints(ctx, t, "metrics", func(ctx context.Context, transport Transport) (string, error) {
		return transport.MetricsRaw(ctx)
	})
}
