package submission

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestSubmitEnqueuesNewAcceptance(t *testing.T) {
	t.Parallel()

	signed, record, accepted := submissionFixtures()
	ingest := &fakeIngest{record: record, accepted: accepted}
	batch := &fakeBatch{}
	outcome, err := New(ingest, batch).Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if ingest.calls != 1 || batch.callCount() != 1 {
		t.Fatalf("calls ingest=%d batch=%d, want 1/1", ingest.calls, batch.callCount())
	}
	if outcome.RecordID != record.RecordID || outcome.Status != accepted.Status || outcome.ProofLevel != "L2" {
		t.Fatalf("Submit() outcome = %+v", outcome)
	}
	if outcome.Idempotent || !outcome.BatchEnqueued || outcome.BatchError != "" {
		t.Fatalf("Submit() state = %+v", outcome)
	}
	if outcome.ServerRecord.RecordID != record.RecordID || outcome.AcceptedReceipt.RecordID != accepted.RecordID {
		t.Fatalf("Submit() evidence fields = %+v", outcome)
	}
}

func TestSubmitIdempotentReplaySkipsBatch(t *testing.T) {
	t.Parallel()

	signed, record, accepted := submissionFixtures()
	ingest := &fakeIngest{record: record, accepted: accepted, idempotent: true}
	batch := &fakeBatch{}
	outcome, err := New(ingest, batch).Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if !outcome.Idempotent || outcome.BatchEnqueued || outcome.BatchError != "" {
		t.Fatalf("Submit() state = %+v", outcome)
	}
	if batch.callCount() != 0 {
		t.Fatalf("batch calls = %d, want 0", batch.callCount())
	}
}

func TestSubmitIngestErrorSkipsBatch(t *testing.T) {
	t.Parallel()

	want := trusterr.New(trusterr.CodeInvalidArgument, "invalid signed claim")
	ingest := &fakeIngest{err: want}
	batch := &fakeBatch{}
	_, err := New(ingest, batch).Submit(context.Background(), model.SignedClaim{})
	if !errors.Is(err, want) {
		t.Fatalf("Submit() error = %v, want %v", err, want)
	}
	if batch.callCount() != 0 {
		t.Fatalf("batch calls = %d, want 0", batch.callCount())
	}
}

func TestSubmitPreservesBatchErrorInOutcome(t *testing.T) {
	t.Parallel()

	signed, record, accepted := submissionFixtures()
	batch := &fakeBatch{err: errors.New("batch unavailable")}
	outcome, err := New(&fakeIngest{record: record, accepted: accepted}, batch).Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if outcome.BatchEnqueued || outcome.BatchError != "batch unavailable" {
		t.Fatalf("Submit() outcome = %+v", outcome)
	}
}

func TestSubmitKeepsAcceptedBatchEnqueueAliveAfterCancellation(t *testing.T) {
	t.Parallel()

	signed, record, accepted := submissionFixtures()
	batch := &blockingBatch{entered: make(chan struct{}), release: make(chan struct{})}
	svc := New(&fakeIngest{record: record, accepted: accepted}, batch)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	type result struct {
		outcome Outcome
		err     error
	}
	done := make(chan result, 1)
	go func() {
		outcome, err := svc.Submit(ctx, signed)
		done <- result{outcome: outcome, err: err}
	}()

	select {
	case <-batch.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("batch enqueue was not reached")
	}
	cancel()
	select {
	case got := <-done:
		t.Fatalf("Submit() returned while batch enqueue was blocked: %+v", got)
	case <-time.After(100 * time.Millisecond):
	}

	close(batch.release)
	select {
	case got := <-done:
		if got.err != nil || !got.outcome.BatchEnqueued || got.outcome.BatchError != "" {
			t.Fatalf("Submit() result after release = %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Submit() did not finish after batch capacity became available")
	}
}

func TestNilIngestIsNotConfigured(t *testing.T) {
	t.Parallel()

	var ingest *fakeIngest
	if svc := New(ingest, &fakeBatch{}); svc != nil {
		t.Fatalf("New() = %T, want nil", svc)
	}
	var svc *Service
	_, err := svc.Submit(context.Background(), model.SignedClaim{})
	if trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition || err.Error() != "ingest service is not configured" {
		t.Fatalf("Submit() error = %v", err)
	}
}

func submissionFixtures() (model.SignedClaim, model.ServerRecord, model.AcceptedReceipt) {
	signed := model.SignedClaim{SchemaVersion: model.SchemaSignedClaim}
	record := model.ServerRecord{SchemaVersion: model.SchemaServerRecord, RecordID: "tr1submission"}
	accepted := model.AcceptedReceipt{SchemaVersion: model.SchemaAcceptedReceipt, RecordID: record.RecordID, Status: "accepted"}
	return signed, record, accepted
}

type fakeIngest struct {
	record     model.ServerRecord
	accepted   model.AcceptedReceipt
	idempotent bool
	err        error
	calls      int
}

func (f *fakeIngest) Submit(context.Context, model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
	f.calls++
	return f.record, f.accepted, f.idempotent, f.err
}

type fakeBatch struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *fakeBatch) Enqueue(context.Context, model.SignedClaim, model.ServerRecord, model.AcceptedReceipt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.err
}

func (f *fakeBatch) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type blockingBatch struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockingBatch) Enqueue(ctx context.Context, _ model.SignedClaim, _ model.ServerRecord, _ model.AcceptedReceipt) error {
	close(b.entered)
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
