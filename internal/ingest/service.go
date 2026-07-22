package ingest

import (
	"context"
	"sync"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

type Processor interface {
	Submit(context.Context, model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error)
}

type Options struct {
	QueueSize int
	Workers   int
}

type Service struct {
	processor Processor
	metrics   *observability.Metrics
	queue     chan job

	mu     sync.RWMutex
	closed bool
	wg     sync.WaitGroup
}

type job struct {
	ctx    context.Context
	signed model.SignedClaim
	result chan result
}

type result struct {
	record     model.ServerRecord
	accepted   model.AcceptedReceipt
	idempotent bool
	err        error
}

func New(processor Processor, opts Options, metrics *observability.Metrics) *Service {
	queueSize := opts.QueueSize
	if queueSize <= 0 {
		queueSize = 1024
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = 1
	}
	s := &Service{
		processor: processor,
		metrics:   metrics,
		queue:     make(chan job, queueSize),
	}
	for i := 0; i < workers; i++ {
		s.wg.Add(1)
		go s.worker()
	}
	return s
}

func (s *Service) Submit(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.ServerRecord{}, model.AcceptedReceipt{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "request context canceled", err)
	}

	j := job{
		ctx:    ctx,
		signed: signed,
		result: make(chan result, 1),
	}

	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return model.ServerRecord{}, model.AcceptedReceipt{}, false, trusterr.New(trusterr.CodeFailedPrecondition, "ingest service is shutting down")
	}
	select {
	case s.queue <- j:
		s.setQueueDepth()
	default:
		s.mu.RUnlock()
		s.reject("queue_full")
		return model.ServerRecord{}, model.AcceptedReceipt{}, false, trusterr.New(trusterr.CodeResourceExhausted, "ingest queue is full")
	}
	s.mu.RUnlock()

	select {
	case res := <-j.result:
		if res.err != nil {
			s.ingestResult("error")
		} else if res.idempotent {
			s.ingestResult("idempotent")
		} else {
			s.ingestResult("accepted")
		}
		return res.record, res.accepted, res.idempotent, res.err
	case <-ctx.Done():
		s.reject("request_canceled")
		return model.ServerRecord{}, model.AcceptedReceipt{}, false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "request context canceled", ctx.Err())
	}
}

func (s *Service) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		s.setQueueDepth()
		return nil
	case <-ctx.Done():
		return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "ingest shutdown timed out", ctx.Err())
	}
}

func (s *Service) worker() {
	defer s.wg.Done()
	for j := range s.queue {
		s.setQueueDepth()
		record, accepted, idempotent, err := s.processor.Submit(j.ctx, j.signed)
		j.result <- result{record: record, accepted: accepted, idempotent: idempotent, err: err}
	}
}

func (s *Service) setQueueDepth() {
	if s.metrics != nil {
		s.metrics.QueueDepth.WithLabelValues("ingest").Set(float64(len(s.queue)))
	}
}

func (s *Service) reject(reason string) {
	if s.metrics != nil {
		s.metrics.IngestRejected.WithLabelValues(reason).Inc()
	}
}

func (s *Service) ingestResult(result string) {
	if s.metrics != nil {
		s.metrics.IngestRequests.WithLabelValues(result).Inc()
	}
}
