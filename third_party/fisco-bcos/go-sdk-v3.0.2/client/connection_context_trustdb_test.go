package client

import (
	"context"
	"errors"
	"testing"

	"github.com/FISCO-BCOS/bcos-c-sdk/bindings/go/csdk"
)

func TestTrustDBRequestWaitHonorsContextAndLateCallback(t *testing.T) {
	t.Parallel()
	callback := &csdk.CallbackChan{Data: make(chan csdk.Response, 1)}
	op := &requestOp{respChanData: callback}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, err := op.waitRpcMessage(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitRpcMessage() error = %v", err)
	}
	select {
	case callback.Data <- csdk.Response{Result: []byte(`{"jsonrpc":"2.0","result":"late"}`)}:
	default:
		t.Fatal("late callback blocked after CallContext cancellation")
	}
}
