package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestServiceSubmit(t *testing.T) {
	t.Parallel()

	p := processorFunc(func(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
		return model.ServerRecord{RecordID: "tr1test"}, model.AcceptedReceipt{RecordID: "tr1test"}, false, nil
	})
	svc := New(p, Options{QueueSize: 1, Workers: 1}, nil)
	defer svc.Shutdown(context.Background())

	record, accepted, idempotent, err := svc.Submit(context.Background(), model.SignedClaim{})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if idempotent {
		t.Fatalf("Submit() idempotent = true, want false on first call")
	}
	if record.RecordID != "tr1test" || accepted.RecordID != "tr1test" {
		t.Fatalf("Submit() = %+v %+v", record, accepted)
	}
}

func TestServiceSubmitPropagatesIdempotent(t *testing.T) {
	t.Parallel()

	p := processorFunc(func(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
		return model.ServerRecord{RecordID: "tr1repeat"}, model.AcceptedReceipt{RecordID: "tr1repeat"}, true, nil
	})
	svc := New(p, Options{QueueSize: 1, Workers: 1}, nil)
	defer svc.Shutdown(context.Background())

	_, _, idempotent, err := svc.Submit(context.Background(), model.SignedClaim{})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if !idempotent {
		t.Fatalf("Submit() idempotent = false, want true when processor reports replay")
	}
}

func TestServiceRejectsFullQueue(t *testing.T) {
	t.Parallel()

	block := make(chan struct{})
	entered := make(chan struct{})
	p := processorFunc(func(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-block
		return model.ServerRecord{}, model.AcceptedReceipt{}, false, nil
	})
	svc := New(p, Options{QueueSize: 1, Workers: 1}, nil)
	defer func() {
		_ = svc.Shutdown(context.Background())
	}()

	go func() {
		_, _, _, _ = svc.Submit(context.Background(), model.SignedClaim{})
	}()
	<-entered

	svc.queue <- job{
		ctx:    context.Background(),
		result: make(chan result, 1),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, _, err := svc.Submit(ctx, model.SignedClaim{})
	gotCode := trusterr.CodeOf(err)
	close(block)
	if gotCode != trusterr.CodeResourceExhausted {
		t.Fatalf("Submit() error code = %s, want %s err=%v", gotCode, trusterr.CodeResourceExhausted, err)
	}
}

func TestServiceShutdownRespectsContext(t *testing.T) {
	t.Parallel()

	block := make(chan struct{})
	entered := make(chan struct{})
	p := processorFunc(func(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
		close(entered)
		<-block
		return model.ServerRecord{}, model.AcceptedReceipt{}, false, nil
	})
	svc := New(p, Options{QueueSize: 1, Workers: 1}, nil)
	submitDone := make(chan struct{})
	go func() {
		defer close(submitDone)
		_, _, _, _ = svc.Submit(context.Background(), model.SignedClaim{})
	}()
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := svc.Shutdown(ctx)
	gotCode := trusterr.CodeOf(err)
	close(block)
	<-submitDone
	if gotCode != trusterr.CodeDeadlineExceeded {
		t.Fatalf("Shutdown() error code = %s, want %s err=%v", gotCode, trusterr.CodeDeadlineExceeded, err)
	}
	if err := svc.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown() error = %v", err)
	}
}

type processorFunc func(context.Context, model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error)

func (f processorFunc) Submit(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
	return f(ctx, signed)
}
