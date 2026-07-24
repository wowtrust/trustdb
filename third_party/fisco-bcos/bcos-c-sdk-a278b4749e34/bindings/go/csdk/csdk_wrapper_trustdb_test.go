package csdk

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"
)

func TestTrustDBResponseSizeIsCheckedBeforeAllocation(t *testing.T) {
	t.Parallel()
	if err := ValidateResponseSize(DefaultMaxResponseBytes, DefaultMaxResponseBytes); err != nil {
		t.Fatalf("maximum response rejected: %v", err)
	}
	for _, size := range []uint64{
		DefaultMaxResponseBytes + 1,
		math.MaxUint32,
		math.MaxUint64,
	} {
		if err := ValidateResponseSize(size, DefaultMaxResponseBytes); err == nil {
			t.Fatalf("oversized native response %d accepted", size)
		}
	}
}

func TestTrustDBCanceledWaitAllowsBoundedLateDelivery(t *testing.T) {
	t.Parallel()
	callback := &CallbackChan{Data: make(chan Response, 1)}
	index := setContext(callback)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if _, err := callback.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled wait took %s", elapsed)
	}
	if got := getContext(index, false); got != nil {
		t.Fatal("canceled wait retained its native callback context")
	}

	late := Response{Result: []byte(`{"jsonrpc":"2.0","result":"late"}`)}
	select {
	case callback.Data <- late:
	default:
		t.Fatal("late native callback would block after cancellation")
	}
	response, err := callback.Wait(context.Background())
	if err != nil || string(response.Result.([]byte)) != string(late.Result.([]byte)) {
		t.Fatalf("late response = %#v, %v", response, err)
	}
}
