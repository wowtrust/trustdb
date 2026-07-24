package sdk

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/wowtrust/trustdb/internal/trusterr"
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
	transports         []Transport
	next               atomic.Uint64
	mode               LoadBalanceMode
	subscriptionOwners sync.Map // subscription_id -> Transport
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
		if !retryableEndpointError(err) {
			return zero, errs
		}
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

func (t *loadBalancedTransport) SubmitSignedClaims(ctx context.Context, claims []SignedClaim) ([]signedClaimBatchItemResult, error) {
	return tryEndpoints(ctx, t, "submit claim batch", func(ctx context.Context, transport Transport) ([]signedClaimBatchItemResult, error) {
		batch, ok := transport.(signedClaimBatchTransport)
		if !ok {
			return nil, &Error{
				Op:      "submit claim batch",
				URL:     transport.Endpoint(),
				Code:    string(trusterr.CodeFailedPrecondition),
				Message: "endpoint transport does not support native batch submission",
			}
		}
		return batch.SubmitSignedClaims(ctx, claims)
	})
}

func (t *loadBalancedTransport) GetRecord(ctx context.Context, recordID string) (RecordIndex, error) {
	return tryEndpoints(ctx, t, "get record", func(ctx context.Context, transport Transport) (RecordIndex, error) {
		return transport.GetRecord(ctx, recordID)
	})
}

func (t *loadBalancedTransport) GetRecordStatus(ctx context.Context, recordID string) (RecordStatus, error) {
	return tryEndpoints(ctx, t, "get record status", func(ctx context.Context, transport Transport) (RecordStatus, error) {
		statusTransport, ok := transport.(recordStatusTransport)
		if !ok {
			return RecordStatus{}, &Error{Op: "get record status", Message: "endpoint transport does not support record status queries"}
		}
		return statusTransport.GetRecordStatus(ctx, recordID)
	})
}

func (t *loadBalancedTransport) GetRecordStatuses(ctx context.Context, recordIDs []string) (RecordStatusBatch, error) {
	return tryEndpoints(ctx, t, "get record statuses", func(ctx context.Context, transport Transport) (RecordStatusBatch, error) {
		statusTransport, ok := transport.(recordStatusTransport)
		if !ok {
			return RecordStatusBatch{}, &Error{Op: "get record statuses", Message: "endpoint transport does not support record status queries"}
		}
		return statusTransport.GetRecordStatuses(ctx, recordIDs)
	})
}

func (t *loadBalancedTransport) CreateStatusSubscription(ctx context.Context, opts CreateStatusSubscriptionOptions) (StatusSubscription, error) {
	var errs error
	start := t.startIndex()
	for offset := range len(t.transports) {
		index := (start + offset) % len(t.transports)
		transport := t.transports[index]
		subscriptionTransport, ok := transport.(statusSubscriptionTransport)
		if !ok {
			continue
		}
		subscription, err := subscriptionTransport.CreateStatusSubscription(ctx, opts)
		if err == nil {
			t.subscriptionOwners.Store(subscription.ID, transport)
			return subscription, nil
		}
		errs = errors.Join(errs, err)
		if !retryableEndpointError(err) {
			break
		}
	}
	if errs == nil {
		errs = &Error{Op: "create status subscription", Message: "no endpoint transport supports status subscriptions"}
	}
	return StatusSubscription{}, errs
}

func (t *loadBalancedTransport) DeleteStatusSubscription(ctx context.Context, subscriptionID string) error {
	_, err := withStatusSubscriptionTransport(ctx, t, subscriptionID, "delete status subscription", func(transport statusSubscriptionTransport) (struct{}, error) {
		return struct{}{}, transport.DeleteStatusSubscription(ctx, subscriptionID)
	})
	if err == nil {
		t.subscriptionOwners.Delete(subscriptionID)
	}
	return err
}

func (t *loadBalancedTransport) GetStatusSubscriptionStatuses(ctx context.Context, subscriptionID string) (RecordStatusBatch, error) {
	return withStatusSubscriptionTransport(ctx, t, subscriptionID, "get subscription statuses", func(transport statusSubscriptionTransport) (RecordStatusBatch, error) {
		return transport.GetStatusSubscriptionStatuses(ctx, subscriptionID)
	})
}

func (t *loadBalancedTransport) SubscribeStatusRefresh(ctx context.Context, subscriptionID string) (<-chan StatusRefresh, <-chan error, error) {
	owner, ok := t.subscriptionOwners.Load(subscriptionID)
	if ok {
		if transport, supported := owner.(statusSubscriptionTransport); supported {
			return transport.SubscribeStatusRefresh(ctx, subscriptionID)
		}
	}
	for _, endpoint := range t.transports {
		transport, supported := endpoint.(statusSubscriptionTransport)
		if !supported {
			continue
		}
		events, errorsCh, err := transport.SubscribeStatusRefresh(ctx, subscriptionID)
		if err == nil {
			t.subscriptionOwners.Store(subscriptionID, endpoint)
			return events, errorsCh, nil
		}
		if !IsNotFound(err) {
			return nil, nil, err
		}
	}
	return nil, nil, &Error{Op: "subscribe status refresh", Message: "status subscription not found on any endpoint"}
}

func withStatusSubscriptionTransport[T any](ctx context.Context, t *loadBalancedTransport, subscriptionID, op string, fn func(statusSubscriptionTransport) (T, error)) (T, error) {
	var zero T
	if owner, ok := t.subscriptionOwners.Load(subscriptionID); ok {
		if transport, supported := owner.(statusSubscriptionTransport); supported {
			result, err := fn(transport)
			if err == nil || !IsNotFound(err) {
				return result, err
			}
			t.subscriptionOwners.Delete(subscriptionID)
		}
	}
	var errs error
	for _, endpoint := range t.transports {
		transport, supported := endpoint.(statusSubscriptionTransport)
		if !supported {
			continue
		}
		result, err := fn(transport)
		if err == nil {
			t.subscriptionOwners.Store(subscriptionID, endpoint)
			return result, nil
		}
		errs = errors.Join(errs, fmt.Errorf("%s %s: %w", op, endpoint.Endpoint(), err))
		if !IsNotFound(err) {
			return zero, errs
		}
	}
	if errs == nil {
		errs = &Error{Op: op, Message: "no endpoint transport supports status subscriptions"}
	}
	return zero, errs
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

func (t *loadBalancedTransport) GetGlobalEvidence(ctx context.Context, batchID string) (GlobalLogEvidence, error) {
	return tryEndpoints(ctx, t, "get global evidence", func(ctx context.Context, transport Transport) (GlobalLogEvidence, error) {
		evidenceTransport, ok := transport.(globalEvidenceTransport)
		if !ok {
			return GlobalLogEvidence{}, &Error{Op: "get global evidence", Message: "transport does not support global evidence"}
		}
		return evidenceTransport.GetGlobalEvidence(ctx, batchID)
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

func (t *loadBalancedTransport) ListAnchorSystems(ctx context.Context) ([]AnchorSystem, error) {
	return tryEndpoints(ctx, t, "list anchor systems", func(ctx context.Context, transport Transport) ([]AnchorSystem, error) {
		provider, ok := transport.(anchorSystemTransport)
		if !ok {
			return nil, &Error{Op: "list anchor systems", Message: "transport does not support anchor systems"}
		}
		return provider.ListAnchorSystems(ctx)
	})
}

func (t *loadBalancedTransport) GetAnchorSystem(ctx context.Context, systemID string) (AnchorSystem, error) {
	return tryEndpoints(ctx, t, "get anchor system", func(ctx context.Context, transport Transport) (AnchorSystem, error) {
		provider, ok := transport.(anchorSystemTransport)
		if !ok {
			return AnchorSystem{}, &Error{Op: "get anchor system", Message: "transport does not support anchor systems"}
		}
		return provider.GetAnchorSystem(ctx, systemID)
	})
}

func (t *loadBalancedTransport) GetAnchorSystemStatus(ctx context.Context, systemID string) (AnchorSystemStatus, error) {
	return tryEndpoints(ctx, t, "get anchor system status", func(ctx context.Context, transport Transport) (AnchorSystemStatus, error) {
		provider, ok := transport.(anchorSystemTransport)
		if !ok {
			return AnchorSystemStatus{}, &Error{Op: "get anchor system status", Message: "transport does not support anchor systems"}
		}
		return provider.GetAnchorSystemStatus(ctx, systemID)
	})
}

func (t *loadBalancedTransport) ListAnchorSystemResources(ctx context.Context, systemID string, opts AnchorResourceListOptions) (AnchorSystemResourcePage, error) {
	return tryEndpoints(ctx, t, "list anchor system resources", func(ctx context.Context, transport Transport) (AnchorSystemResourcePage, error) {
		provider, ok := transport.(anchorSystemTransport)
		if !ok {
			return AnchorSystemResourcePage{}, &Error{Op: "list anchor system resources", Message: "transport does not support anchor systems"}
		}
		return provider.ListAnchorSystemResources(ctx, systemID, opts)
	})
}

func (t *loadBalancedTransport) GetAnchorSystemResource(ctx context.Context, systemID, kind, resourceID string) (AnchorSystemResource, error) {
	return tryEndpoints(ctx, t, "get anchor system resource", func(ctx context.Context, transport Transport) (AnchorSystemResource, error) {
		provider, ok := transport.(anchorSystemTransport)
		if !ok {
			return AnchorSystemResource{}, &Error{Op: "get anchor system resource", Message: "transport does not support anchor systems"}
		}
		return provider.GetAnchorSystemResource(ctx, systemID, kind, resourceID)
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
