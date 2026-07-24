package natsingress

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	goruntime "runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/wowtrust/trustdb/internal/config"
	"github.com/wowtrust/trustdb/internal/submission"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

// OutcomeSink durably stores accepted results and terminal rejections. Store
// must be idempotent for the same outcome and must honor context cancellation.
// A worker never ACKs or terminates a message before Store returns nil.
type OutcomeSink interface {
	Store(context.Context, DeliveryOutcome) error
}

// DeliveryOutcome contains exactly one valid request/result pair or one raw
// rejection. Result remains the exact public NATS ingress result envelope.
type DeliveryOutcome struct {
	Request   *Request
	Result    *Result
	Rejection *Rejection
}

// Rejection captures a malformed broker delivery without treating any
// caller-provided header as a trusted identity.
type Rejection struct {
	ID               string
	Subject          string
	Reply            string
	Headers          nats.Header
	Data             []byte
	Stream           string
	Consumer         string
	StreamSequence   uint64
	ConsumerSequence uint64
	NumDelivered     uint64
	Code             trusterr.Code
	Message          string
}

func (o DeliveryOutcome) Validate() error {
	validResult := o.Request != nil && o.Result != nil && o.Rejection == nil
	validRejection := o.Request == nil && o.Result == nil && o.Rejection != nil
	if !validResult && !validRejection {
		return errors.New("NATS delivery outcome must contain exactly one request/result pair or rejection")
	}
	if validResult {
		return o.Result.ValidateFor(*o.Request)
	}
	if strings.TrimSpace(o.Rejection.ID) == "" || strings.TrimSpace(o.Rejection.Message) == "" || o.Rejection.Code == "" {
		return errors.New("NATS delivery rejection requires id, code, and message")
	}
	return nil
}

// Worker consumes the existing durable pull consumer without introducing an
// additional in-process queue. One pull context is created per resolved
// worker, and their combined client buffers never exceed MaxAckPending.
type Worker struct {
	consumer  jetstream.Consumer
	submitter submission.Submitter
	sink      OutcomeSink
	observer  WorkerObserver

	workers          int
	perWorkerBatch   int
	fetchWait        time.Duration
	ackWait          time.Duration
	nakDelay         time.Duration
	outcomeRetryWait time.Duration
	maxDeliver       uint64
	subject          string
	onError          func(error)
}

type WorkerOption func(*Worker)

const (
	DeliveryActionAck           = "ack"
	DeliveryActionNak           = "nak"
	DeliveryActionTermResult    = "term_result"
	DeliveryActionTermRejection = "term_rejection"

	OutcomeKindResult    = "result"
	OutcomeKindRejection = "rejection"

	WorkerErrorStageConsume     = "consume"
	WorkerErrorStageProcess     = "process"
	WorkerErrorStageAckProgress = "ack_progress"
)

// WorkerObserver receives constant-cardinality runtime events. Implementations
// must return promptly and must not retain request, result, or message data.
type WorkerObserver interface {
	DeliveryStarted()
	DeliveryFinished()
	DeliveryAction(action string)
	OutcomeStoreRetry(kind string)
	WorkerError(stage string)
}

type noopWorkerObserver struct{}

func (noopWorkerObserver) DeliveryStarted()         {}
func (noopWorkerObserver) DeliveryFinished()        {}
func (noopWorkerObserver) DeliveryAction(string)    {}
func (noopWorkerObserver) OutcomeStoreRetry(string) {}
func (noopWorkerObserver) WorkerError(string)       {}

// WithWorkerErrorHandler observes recoverable processing and pull-loop errors.
// The handler may run concurrently and should return promptly.
func WithWorkerErrorHandler(handler func(error)) WorkerOption {
	return func(worker *Worker) {
		worker.onError = handler
	}
}

// WithWorkerObserver attaches aggregate runtime instrumentation. A nil or
// typed-nil observer is treated as a no-op.
func WithWorkerObserver(observer WorkerObserver) WorkerOption {
	return func(worker *Worker) {
		worker.observer = observer
	}
}

func NewWorker(consumer jetstream.Consumer, submitter submission.Submitter, sink OutcomeSink, cfg config.NATS, options ...WorkerOption) (*Worker, error) {
	if !cfg.Enabled {
		return nil, errors.New("NATS ingress worker requires nats.enabled=true")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if nilInterface(consumer) {
		return nil, errors.New("NATS ingress worker requires a consumer")
	}
	if nilInterface(submitter) {
		return nil, errors.New("NATS ingress worker requires a submission service")
	}
	if nilInterface(sink) {
		return nil, errors.New("NATS ingress worker requires an outcome sink")
	}

	parse := func(name, value string) (time.Duration, error) {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return 0, fmt.Errorf("parse %s: %w", name, err)
		}
		return duration, nil
	}
	fetchWait, err := parse("nats.fetch_wait", cfg.FetchWait)
	if err != nil {
		return nil, err
	}
	ackWait, err := parse("nats.ack_wait", cfg.AckWait)
	if err != nil {
		return nil, err
	}
	nakDelay, err := parse("nats.nak_delay", cfg.NakDelay)
	if err != nil {
		return nil, err
	}
	outcomeRetryWait, err := parse("nats.outcome_retry_wait", cfg.ResultRetryWait)
	if err != nil {
		return nil, err
	}

	workers := ResolveWorkerCount(cfg.Workers, cfg.FetchBatch, cfg.MaxAckPending)
	worker := &Worker{
		consumer:         consumer,
		submitter:        submitter,
		sink:             sink,
		observer:         noopWorkerObserver{},
		workers:          workers,
		perWorkerBatch:   min(cfg.FetchBatch, max(1, cfg.MaxAckPending/workers)),
		fetchWait:        fetchWait,
		ackWait:          ackWait,
		nakDelay:         nakDelay,
		outcomeRetryWait: outcomeRetryWait,
		maxDeliver:       uint64(cfg.MaxDeliver),
		subject:          cfg.Subject,
		onError:          func(error) {},
	}
	for _, option := range options {
		if option != nil {
			option(worker)
		}
	}
	if worker.onError == nil {
		worker.onError = func(error) {}
	}
	if nilInterface(worker.observer) {
		worker.observer = noopWorkerObserver{}
	}
	return worker, nil
}

// ResolveWorkerCount applies explicit sizing or derives it from GOMAXPROCS.
// Automatic sizing is bounded by the pull request and acknowledgement limits;
// explicit validated sizing is bounded by MaxAckPending.
func ResolveWorkerCount(configured, fetchBatch, maxAckPending int) int {
	limit := max(1, min(fetchBatch, maxAckPending))
	if configured > 0 {
		return min(configured, maxAckPending)
	}
	return max(1, min(goruntime.GOMAXPROCS(0), limit))
}

func (w *Worker) Workers() int {
	if w == nil {
		return 0
	}
	return w.workers
}

func (w *Worker) PerWorkerBatch() int {
	if w == nil {
		return 0
	}
	return w.perWorkerBatch
}

// Run starts the bounded pull loops and blocks until cancellation or an
// unexpected loop shutdown. Cancellation drains already-buffered callbacks;
// canceled callbacks leave their messages unacknowledged for later delivery.
func (w *Worker) Run(ctx context.Context) error {
	if w == nil {
		return errors.New("NATS ingress worker is nil")
	}
	if w.workers <= 0 || w.perWorkerBatch <= 0 {
		return errors.New("NATS ingress worker has invalid concurrency settings")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	consumeContexts := make([]jetstream.ConsumeContext, 0, w.workers)
	closed := make(chan int, w.workers)
	started := make(chan struct{})
	startupCanceled := make(chan struct{})
	var consumeErrMu sync.Mutex
	var lastConsumeErr error

	stopAll := func(drain bool) {
		for _, consumeContext := range consumeContexts {
			if drain {
				consumeContext.Drain()
			} else {
				consumeContext.Stop()
			}
		}
	}
	waitAll := func() {
		for _, consumeContext := range consumeContexts {
			<-consumeContext.Closed()
		}
	}

	for index := 0; index < w.workers; index++ {
		consumeContext, err := w.consumer.Consume(
			func(message jetstream.Msg) {
				select {
				case <-started:
				case <-startupCanceled:
					return
				case <-ctx.Done():
					return
				}
				if err := w.Process(ctx, message); err != nil && ctx.Err() == nil {
					w.report(fmt.Errorf("process NATS ingress delivery: %w", err))
				}
			},
			jetstream.PullMaxMessages(w.perWorkerBatch),
			jetstream.PullExpiry(w.fetchWait),
			jetstream.ConsumeErrHandler(func(_ jetstream.ConsumeContext, err error) {
				consumeErrMu.Lock()
				lastConsumeErr = err
				consumeErrMu.Unlock()
				w.observer.WorkerError(WorkerErrorStageConsume)
				w.report(fmt.Errorf("NATS ingress consume loop: %w", err))
			}),
		)
		if err != nil {
			close(startupCanceled)
			stopAll(false)
			waitAll()
			w.observer.WorkerError(WorkerErrorStageConsume)
			return fmt.Errorf("start NATS ingress consume loop %d: %w", index, err)
		}
		consumeContexts = append(consumeContexts, consumeContext)
		go func(index int, consumeContext jetstream.ConsumeContext) {
			<-consumeContext.Closed()
			closed <- index
		}(index, consumeContext)
	}
	close(started)

	select {
	case <-ctx.Done():
		stopAll(true)
		waitAll()
		return ctx.Err()
	case index := <-closed:
		stopAll(false)
		waitAll()
		consumeErrMu.Lock()
		err := lastConsumeErr
		consumeErrMu.Unlock()
		if err != nil {
			return fmt.Errorf("NATS ingress consume loop %d stopped: %w", index, err)
		}
		w.observer.WorkerError(WorkerErrorStageConsume)
		return fmt.Errorf("NATS ingress consume loop %d stopped unexpectedly", index)
	}
}

// Process handles one delivery according to the durable outcome-before-ack
// state machine. It is exported for transport integration tests and custom
// supervisors; callers should normally use Run.
func (w *Worker) Process(ctx context.Context, message jetstream.Msg) (err error) {
	if w == nil {
		return errors.New("NATS ingress worker is nil")
	}
	if nilInterface(message) {
		return errors.New("NATS ingress message is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	w.observer.DeliveryStarted()
	defer w.observer.DeliveryFinished()
	defer func() {
		if err != nil && ctx.Err() == nil {
			w.observer.WorkerError(WorkerErrorStageProcess)
		}
	}()

	stopHeartbeat := w.keepAlive(ctx, message)
	stop := func() {
		stopHeartbeat()
	}
	defer stop()

	metadata, metadataErr := message.Metadata()
	if metadataErr != nil {
		rejection := newRejection(message, nil, trusterr.CodeDataLoss, fmt.Errorf("read JetStream message metadata: %w", metadataErr))
		return w.storeAndTerminate(ctx, message, DeliveryOutcome{Rejection: &rejection}, stop)
	}

	request, err := w.decodeMessage(message)
	if err != nil {
		rejection := newRejection(message, metadata, trusterr.CodeInvalidArgument, err)
		return w.storeAndTerminate(ctx, message, DeliveryOutcome{Rejection: &rejection}, stop)
	}

	outcome, err := w.submitter.Submit(ctx, request.SignedClaim)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err == nil {
		result, resultErr := NewAcceptedResult(request, outcome)
		if resultErr == nil {
			delivery := DeliveryOutcome{Request: &request, Result: &result}
			if err := w.storeUntilConfirmed(ctx, delivery); err != nil {
				return err
			}
			stop()
			if err := message.DoubleAck(ctx); err != nil {
				return fmt.Errorf("confirm NATS ingress acknowledgement: %w", err)
			}
			w.observer.DeliveryAction(DeliveryActionAck)
			return nil
		}
		err = trusterr.Wrap(trusterr.CodeInternal, "build NATS accepted result", resultErr)
	}

	if retryableCode(trusterr.CodeOf(err)) && metadata.NumDelivered < w.maxDeliver {
		stop()
		if nakErr := message.NakWithDelay(w.nakDelay); nakErr != nil {
			return fmt.Errorf("schedule NATS ingress redelivery: %w", nakErr)
		}
		w.observer.DeliveryAction(DeliveryActionNak)
		return nil
	}

	result, resultErr := NewErrorResult(request, err)
	if resultErr != nil {
		return fmt.Errorf("build NATS terminal result: %w", resultErr)
	}
	return w.storeAndTerminate(ctx, message, DeliveryOutcome{Request: &request, Result: &result}, stop)
}

func (w *Worker) decodeMessage(message jetstream.Msg) (Request, error) {
	if message.Subject() != w.subject {
		return Request{}, fmt.Errorf("unexpected NATS ingress subject %q", message.Subject())
	}
	headers := message.Headers()
	if headers.Get(HeaderContentType) != ContentType {
		return Request{}, fmt.Errorf("unexpected NATS ingress content type %q", headers.Get(HeaderContentType))
	}
	if headers.Get(HeaderSchemaVersion) != SchemaRequest {
		return Request{}, fmt.Errorf("unexpected NATS ingress schema header %q", headers.Get(HeaderSchemaVersion))
	}
	request, err := DecodeRequest(message.Data())
	if err != nil {
		return Request{}, err
	}
	if headers.Get(HeaderMessageID) != request.MessageID {
		return Request{}, fmt.Errorf("NATS ingress message ID header %q does not match request %q", headers.Get(HeaderMessageID), request.MessageID)
	}
	return request, nil
}

func (w *Worker) storeAndTerminate(ctx context.Context, message jetstream.Msg, outcome DeliveryOutcome, stopHeartbeat func()) error {
	if err := w.storeUntilConfirmed(ctx, outcome); err != nil {
		return err
	}
	stopHeartbeat()
	if err := message.Term(); err != nil {
		return fmt.Errorf("terminate NATS ingress delivery: %w", err)
	}
	action := DeliveryActionTermResult
	if outcome.Rejection != nil {
		action = DeliveryActionTermRejection
	}
	w.observer.DeliveryAction(action)
	return nil
}

func (w *Worker) storeUntilConfirmed(ctx context.Context, outcome DeliveryOutcome) error {
	if err := outcome.Validate(); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := w.sink.Store(ctx, outcome); err == nil {
			return nil
		} else {
			w.observer.OutcomeStoreRetry(outcomeKind(outcome))
			w.report(fmt.Errorf("store NATS ingress delivery outcome: %w", err))
		}

		timer := time.NewTimer(w.outcomeRetryWait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

func (w *Worker) keepAlive(ctx context.Context, message jetstream.Msg) func() {
	interval := max(time.Millisecond, w.ackWait/3)
	done := make(chan struct{})
	finished := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(finished)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := message.InProgress(); err != nil && ctx.Err() == nil {
					w.observer.WorkerError(WorkerErrorStageAckProgress)
					w.report(fmt.Errorf("extend NATS ingress acknowledgement deadline: %w", err))
				}
			case <-ctx.Done():
				return
			case <-done:
				return
			}
		}
	}()
	return func() {
		once.Do(func() {
			close(done)
			<-finished
		})
	}
}

func outcomeKind(outcome DeliveryOutcome) string {
	if outcome.Rejection != nil {
		return OutcomeKindRejection
	}
	return OutcomeKindResult
}

func (w *Worker) report(err error) {
	if err != nil {
		w.onError(err)
	}
}

func retryableCode(code trusterr.Code) bool {
	switch code {
	case trusterr.CodeInvalidArgument, trusterr.CodeAlreadyExists, trusterr.CodeDataLoss:
		return false
	default:
		return true
	}
}

func newRejection(message jetstream.Msg, metadata *jetstream.MsgMetadata, code trusterr.Code, err error) Rejection {
	headers := cloneHeader(message.Headers())
	rejection := Rejection{
		ID:      rejectionID(metadata, message.Subject(), message.Reply(), headers, message.Data()),
		Subject: message.Subject(),
		Reply:   message.Reply(),
		Headers: headers,
		Data:    slices.Clone(message.Data()),
		Code:    code,
		Message: err.Error(),
	}
	if metadata != nil {
		rejection.Stream = metadata.Stream
		rejection.Consumer = metadata.Consumer
		rejection.StreamSequence = metadata.Sequence.Stream
		rejection.ConsumerSequence = metadata.Sequence.Consumer
		rejection.NumDelivered = metadata.NumDelivered
	}
	return rejection
}

func rejectionID(metadata *jetstream.MsgMetadata, subject, reply string, headers nats.Header, data []byte) string {
	var stream string
	var streamSequence uint64
	if metadata != nil {
		stream = metadata.Stream
		streamSequence = metadata.Sequence.Stream
	}
	return rejectionIdentity(stream, streamSequence, subject, reply, headers, data)
}

func rejectionIdentity(stream string, streamSequence uint64, subject, reply string, headers nats.Header, data []byte) string {
	parts := []string{subject, reply, string(data)}
	if stream != "" {
		parts = append(parts, stream, fmt.Sprintf("%d", streamSequence))
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		parts = append(parts, key)
		parts = append(parts, headers[key]...)
	}
	return digestIdentity("tnj1", "trustdb.nats-rejection.v1", parts...)
}

func cloneHeader(source nats.Header) nats.Header {
	if source == nil {
		return nil
	}
	clone := make(nats.Header, len(source))
	for key, values := range source {
		clone[key] = slices.Clone(values)
	}
	return clone
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
