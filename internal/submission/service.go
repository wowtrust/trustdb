// Package submission owns the transport-independent ordering between durable
// ingest acceptance and downstream batch enqueueing.
package submission

import (
	"context"
	"reflect"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/prooflevel"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

// Ingest accepts one signed claim into the durable TrustDB ingest boundary.
type Ingest interface {
	Submit(context.Context, model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error)
}

// Batch accepts one newly-created L2 record into the proof pipeline.
type Batch interface {
	Enqueue(context.Context, model.SignedClaim, model.ServerRecord, model.AcceptedReceipt) error
}

// Submitter is the shared entry point used by HTTP, gRPC, and future ingress
// transports.
type Submitter interface {
	Submit(context.Context, model.SignedClaim) (Outcome, error)
}

// Outcome contains the existing transport-neutral submit response fields.
type Outcome struct {
	RecordID        string
	Status          string
	ProofLevel      string
	Idempotent      bool
	BatchEnqueued   bool
	BatchError      string
	ServerRecord    model.ServerRecord
	AcceptedReceipt model.AcceptedReceipt
}

// Service coordinates durable ingest acceptance with downstream batch
// enqueueing. It is stateless; durability and idempotency remain owned by the
// underlying ingest and batch services.
type Service struct {
	ingest Ingest
	batch  Batch
}

// New returns nil when ingest is absent so transports preserve their existing
// fail-fast "ingest service is not configured" behavior.
func New(ingest Ingest, batch Batch) *Service {
	if isNil(ingest) {
		return nil
	}
	if isNil(batch) {
		batch = nil
	}
	return &Service{ingest: ingest, batch: batch}
}

// Submit accepts a signed claim and, for a new record, waits until it enters
// the bounded batch pipeline. Once L2 acceptance succeeds, transport request
// cancellation must not strand the accepted WAL record before batch enqueue;
// batch shutdown remains independently able to stop the wait.
func (s *Service) Submit(ctx context.Context, signed model.SignedClaim) (Outcome, error) {
	if s == nil || isNil(s.ingest) {
		return Outcome{}, trusterr.New(trusterr.CodeFailedPrecondition, "ingest service is not configured")
	}
	record, accepted, idempotent, err := s.ingest.Submit(ctx, signed)
	if err != nil {
		return Outcome{}, err
	}

	outcome := Outcome{
		RecordID:        record.RecordID,
		Status:          accepted.Status,
		ProofLevel:      prooflevel.L2.String(),
		Idempotent:      idempotent,
		ServerRecord:    record,
		AcceptedReceipt: accepted,
	}
	if s.batch == nil || idempotent {
		return outcome, nil
	}
	if err := s.batch.Enqueue(context.WithoutCancel(ctx), signed, record, accepted); err != nil {
		outcome.BatchError = err.Error()
		return outcome, nil
	}
	outcome.BatchEnqueued = true
	return outcome, nil
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}
