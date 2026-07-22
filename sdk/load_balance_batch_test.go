package sdk

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestLoadBalancedNativeBatchUsesOneBatchRequest(t *testing.T) {
	t.Parallel()

	var batchHits atomic.Int64
	var singleHits atomic.Int64
	itemErr := errors.New("item rejected")
	transport := &loadBalancedTransport{
		transports: []Transport{batchDispatchTransport{
			dispatchTransport: dispatchTransport{endpoint: "primary", hits: &singleHits},
			batchHits:         &batchHits,
			results: []signedClaimBatchItemResult{
				{Index: 0, Result: SubmitResult{RecordID: "record-0"}},
				{Index: 1, Err: itemErr},
			},
		}},
		mode: LoadBalanceFailover,
	}
	client, err := NewClientWithTransport(transport)
	if err != nil {
		t.Fatalf("NewClientWithTransport() error = %v", err)
	}
	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	result, err := client.SubmitLogBatch(context.Background(), []LogEntry{
		{Body: []byte(`{"index":0}`)},
		{Body: []byte(`{"index":1}`)},
	}, Identity{TenantID: "tenant", ClientID: "client", KeyID: "key", PrivateKey: privateKey}, LogSubmitOptions{})
	var batchErr *LogBatchError
	if !errors.As(err, &batchErr) {
		t.Fatalf("SubmitLogBatch() error = %v, want LogBatchError", err)
	}
	if got := batchHits.Load(); got != 1 {
		t.Fatalf("batch calls = %d, want 1", got)
	}
	if got := singleHits.Load(); got != 0 {
		t.Fatalf("single calls = %d, want 0", got)
	}
	if len(result.Results) != 2 || result.Results[0].Result.RecordID != "record-0" || !errors.Is(result.Results[1].Err, itemErr) {
		t.Fatalf("results = %+v", result.Results)
	}
}

func TestLoadBalancedNativeBatchRetriesTransientRequestError(t *testing.T) {
	t.Parallel()

	var primaryHits atomic.Int64
	var secondaryHits atomic.Int64
	transient := &Error{Op: "submit claim batch", StatusCode: http.StatusServiceUnavailable, Message: "overloaded"}
	transport := &loadBalancedTransport{
		transports: []Transport{
			batchDispatchTransport{dispatchTransport: dispatchTransport{endpoint: "primary"}, batchHits: &primaryHits, err: transient},
			batchDispatchTransport{dispatchTransport: dispatchTransport{endpoint: "secondary"}, batchHits: &secondaryHits},
		},
		mode: LoadBalanceFailover,
	}
	if _, err := transport.SubmitSignedClaims(context.Background(), []SignedClaim{{}}); err != nil {
		t.Fatalf("SubmitSignedClaims() error = %v", err)
	}
	if primaryHits.Load() != 1 || secondaryHits.Load() != 1 {
		t.Fatalf("batch calls = primary:%d secondary:%d, want 1/1", primaryHits.Load(), secondaryHits.Load())
	}
}

func TestLoadBalancedNativeBatchStopsOnTerminalRequestError(t *testing.T) {
	t.Parallel()

	var primaryHits atomic.Int64
	var secondaryHits atomic.Int64
	terminal := &Error{
		Op:         "submit claim batch",
		StatusCode: http.StatusBadRequest,
		Code:       string(trusterr.CodeInvalidArgument),
		Message:    "invalid batch",
	}
	transport := &loadBalancedTransport{
		transports: []Transport{
			batchDispatchTransport{dispatchTransport: dispatchTransport{endpoint: "primary"}, batchHits: &primaryHits, err: terminal},
			batchDispatchTransport{dispatchTransport: dispatchTransport{endpoint: "secondary"}, batchHits: &secondaryHits},
		},
		mode: LoadBalanceFailover,
	}
	_, err := transport.SubmitSignedClaims(context.Background(), []SignedClaim{{}})
	if !errors.Is(err, terminal) {
		t.Fatalf("SubmitSignedClaims() error = %v, want terminal error", err)
	}
	if primaryHits.Load() != 1 || secondaryHits.Load() != 0 {
		t.Fatalf("batch calls = primary:%d secondary:%d, want 1/0", primaryHits.Load(), secondaryHits.Load())
	}
}

type batchDispatchTransport struct {
	dispatchTransport
	batchHits *atomic.Int64
	results   []signedClaimBatchItemResult
	err       error
}

func (t batchDispatchTransport) SubmitSignedClaims(context.Context, []SignedClaim) ([]signedClaimBatchItemResult, error) {
	if t.batchHits != nil {
		t.batchHits.Add(1)
	}
	return t.results, t.err
}
