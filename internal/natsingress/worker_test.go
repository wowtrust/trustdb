package natsingress

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/wowtrust/trustdb/internal/config"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/submission"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestResolveWorkerCountIsBounded(t *testing.T) {
	t.Parallel()

	if got := ResolveWorkerCount(12, 256, 2048); got != 12 {
		t.Fatalf("ResolveWorkerCount(explicit) = %d, want 12", got)
	}
	if got := ResolveWorkerCount(4096, 256, 2048); got != 2048 {
		t.Fatalf("ResolveWorkerCount(bounded explicit) = %d, want 2048", got)
	}
	if got := ResolveWorkerCount(0, 3, 2048); got < 1 || got > 3 {
		t.Fatalf("ResolveWorkerCount(auto) = %d, want 1..3", got)
	}
}

func TestNewWorkerBoundsCombinedPullBuffers(t *testing.T) {
	t.Parallel()

	s := startTestServer(t, nil)
	cfg := testNATSConfig(s.ClientURL())
	cfg.Workers = 12
	cfg.FetchBatch = 64
	cfg.MaxAckPending = 100
	runtime, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { closeRuntime(t, runtime) })
	worker, err := NewWorker(
		runtime.Consumer(),
		submitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) { return fixtureOutcome(), nil }),
		sinkFunc(func(context.Context, DeliveryOutcome) error { return nil }),
		cfg,
	)
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}
	if worker.Workers() != 12 || worker.PerWorkerBatch() != 8 || worker.Workers()*worker.PerWorkerBatch() > cfg.MaxAckPending {
		t.Fatalf("worker buffers = %d x %d, max_ack_pending=%d", worker.Workers(), worker.PerWorkerBatch(), cfg.MaxAckPending)
	}
}

func TestWorkerProcessPersistsAcceptedResultBeforeConfirmedAck(t *testing.T) {
	t.Parallel()

	request := mustRequest(t)
	message := newWorkerTestMessage(t, request, 1)
	sequence := &eventSequence{}
	message.events = sequence
	worker := testWorker(
		submitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) {
			sequence.add("submit")
			return fixtureOutcome(), nil
		}),
		sinkFunc(func(_ context.Context, outcome DeliveryOutcome) error {
			sequence.add("store")
			if outcome.Result == nil || outcome.Result.Accepted == nil {
				t.Fatalf("stored outcome = %+v, want accepted result", outcome)
			}
			return nil
		}),
	)

	if err := worker.Process(context.Background(), message); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if got, want := sequence.snapshot(), []string{"submit", "store", "double_ack"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestWorkerObserverTracksBoundedDeliveryActions(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		message    func(*testing.T) *workerTestMessage
		submit     submission.Submitter
		wantAction string
	}{
		{
			name:       "accepted",
			message:    func(t *testing.T) *workerTestMessage { return newWorkerTestMessage(t, mustRequest(t), 1) },
			submit:     submitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) { return fixtureOutcome(), nil }),
			wantAction: DeliveryActionAck,
		},
		{
			name:    "scheduled redelivery",
			message: func(t *testing.T) *workerTestMessage { return newWorkerTestMessage(t, mustRequest(t), 1) },
			submit: submitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) {
				return submission.Outcome{}, trusterr.New(trusterr.CodeResourceExhausted, "busy")
			}),
			wantAction: DeliveryActionNak,
		},
		{
			name:    "terminal result",
			message: func(t *testing.T) *workerTestMessage { return newWorkerTestMessage(t, mustRequest(t), 1) },
			submit: submitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) {
				return submission.Outcome{}, trusterr.New(trusterr.CodeInvalidArgument, "invalid")
			}),
			wantAction: DeliveryActionTermResult,
		},
		{
			name: "terminal rejection",
			message: func(t *testing.T) *workerTestMessage {
				message := newWorkerTestMessage(t, mustRequest(t), 1)
				message.data = []byte("malformed")
				return message
			},
			submit: submitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) {
				t.Fatal("malformed delivery reached submitter")
				return submission.Outcome{}, nil
			}),
			wantAction: DeliveryActionTermRejection,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			observer := newWorkerTestObserver()
			worker := testWorker(tc.submit, sinkFunc(func(context.Context, DeliveryOutcome) error { return nil }))
			worker.observer = observer
			if err := worker.Process(context.Background(), tc.message(t)); err != nil {
				t.Fatalf("Process() error = %v", err)
			}
			current, maximum, actions, _, _ := observer.snapshot()
			if current != 0 || maximum != 1 || !reflect.DeepEqual(actions, []string{tc.wantAction}) {
				t.Fatalf("observer current=%d max=%d actions=%v", current, maximum, actions)
			}
		})
	}
}

func TestWorkerProcessPersistsMalformedDeliveryBeforeTerm(t *testing.T) {
	t.Parallel()

	sequence := &eventSequence{}
	message := &workerTestMessage{
		subject: "trustdb.ingress.test.claims",
		headers: nats.Header{
			HeaderContentType:   []string{ContentType},
			HeaderSchemaVersion: []string{SchemaRequest},
			HeaderMessageID:     []string{"untrusted"},
		},
		data:   []byte("malformed"),
		meta:   &jetstream.MsgMetadata{Stream: "TEST", Consumer: "worker", NumDelivered: 1},
		events: sequence,
	}
	worker := testWorker(
		submitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) {
			t.Fatal("malformed delivery reached submitter")
			return submission.Outcome{}, nil
		}),
		sinkFunc(func(_ context.Context, outcome DeliveryOutcome) error {
			sequence.add("store")
			if outcome.Rejection == nil || outcome.Rejection.Code != trusterr.CodeInvalidArgument || string(outcome.Rejection.Data) != "malformed" {
				t.Fatalf("stored outcome = %+v, want copied rejection", outcome)
			}
			return nil
		}),
	)

	if err := worker.Process(context.Background(), message); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if got, want := sequence.snapshot(), []string{"store", "term"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestRejectionIDIsStableAcrossRedeliveryAndUniquePerStreamMessage(t *testing.T) {
	t.Parallel()

	request := mustRequest(t)
	message := newWorkerTestMessage(t, request, 1)
	first := newRejection(message, message.meta, trusterr.CodeInvalidArgument, errors.New("bad"))
	redeliveryMetadata := *message.meta
	redeliveryMetadata.NumDelivered = 2
	redeliveryMetadata.Sequence.Consumer = 2
	redelivery := newRejection(message, &redeliveryMetadata, trusterr.CodeInvalidArgument, errors.New("bad"))
	if first.ID != redelivery.ID {
		t.Fatalf("rejection ID changed across redelivery: %q != %q", first.ID, redelivery.ID)
	}
	differentMetadata := redeliveryMetadata
	differentMetadata.Sequence.Stream = 2
	different := newRejection(message, &differentMetadata, trusterr.CodeInvalidArgument, errors.New("bad"))
	if first.ID == different.ID {
		t.Fatal("rejection ID did not change for a distinct stream message")
	}
}

func TestWorkerProcessRetriesThenPersistsFinalFailure(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		code         trusterr.Code
		delivered    uint64
		wantEvents   []string
		wantSinkCall bool
	}{
		{name: "retryable before final", code: trusterr.CodeResourceExhausted, delivered: 1, wantEvents: []string{"submit", "nak"}},
		{name: "retryable at final", code: trusterr.CodeInternal, delivered: 3, wantEvents: []string{"submit", "store", "term"}, wantSinkCall: true},
		{name: "terminal immediately", code: trusterr.CodeInvalidArgument, delivered: 1, wantEvents: []string{"submit", "store", "term"}, wantSinkCall: true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			request := mustRequest(t)
			message := newWorkerTestMessage(t, request, tc.delivered)
			sequence := &eventSequence{}
			message.events = sequence
			worker := testWorker(
				submitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) {
					sequence.add("submit")
					return submission.Outcome{}, trusterr.New(tc.code, "submit failed")
				}),
				sinkFunc(func(_ context.Context, outcome DeliveryOutcome) error {
					sequence.add("store")
					if !tc.wantSinkCall || outcome.Result == nil || outcome.Result.Error == nil || outcome.Result.Error.Code != tc.code {
						t.Fatalf("stored outcome = %+v", outcome)
					}
					return nil
				}),
			)

			if err := worker.Process(context.Background(), message); err != nil {
				t.Fatalf("Process() error = %v", err)
			}
			if got := sequence.snapshot(); !reflect.DeepEqual(got, tc.wantEvents) {
				t.Fatalf("events = %v, want %v", got, tc.wantEvents)
			}
		})
	}
}

func TestWorkerProcessRetriesOutcomeSinkWithoutResubmitting(t *testing.T) {
	t.Parallel()

	request := mustRequest(t)
	message := newWorkerTestMessage(t, request, 1)
	var submitCalls atomic.Int32
	var sinkCalls atomic.Int32
	worker := testWorker(
		submitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) {
			submitCalls.Add(1)
			return fixtureOutcome(), nil
		}),
		sinkFunc(func(context.Context, DeliveryOutcome) error {
			if sinkCalls.Add(1) < 3 {
				return errors.New("sink unavailable")
			}
			return nil
		}),
	)
	observer := newWorkerTestObserver()
	worker.observer = observer
	worker.ackWait = 6 * time.Millisecond
	worker.outcomeRetryWait = 4 * time.Millisecond

	if err := worker.Process(context.Background(), message); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if submitCalls.Load() != 1 || sinkCalls.Load() != 3 {
		t.Fatalf("submit calls = %d sink calls = %d", submitCalls.Load(), sinkCalls.Load())
	}
	if message.inProgress.Load() == 0 {
		t.Fatal("worker did not extend ack deadline during sink outage")
	}
	_, _, _, retries, _ := observer.snapshot()
	if !reflect.DeepEqual(retries, []string{OutcomeKindResult, OutcomeKindResult}) {
		t.Fatalf("outcome store retries = %v", retries)
	}
}

func TestWorkerObserverTracksProcessAndAckProgressErrors(t *testing.T) {
	t.Parallel()

	observer := newWorkerTestObserver()
	request := mustRequest(t)
	message := newWorkerTestMessage(t, request, 1)
	message.doubleAckErr = errors.New("ack unavailable")
	worker := testWorker(
		submitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) { return fixtureOutcome(), nil }),
		sinkFunc(func(context.Context, DeliveryOutcome) error { return nil }),
	)
	worker.observer = observer
	if err := worker.Process(context.Background(), message); err == nil {
		t.Fatal("Process() error = nil, want acknowledgement failure")
	}
	select {
	case <-observer.errorObserved:
	default:
		t.Fatal("process error was not observed")
	}

	heartbeatMessage := newWorkerTestMessage(t, request, 1)
	heartbeatMessage.inProgressErr = errors.New("heartbeat unavailable")
	worker.ackWait = 3 * time.Millisecond
	stop := worker.keepAlive(context.Background(), heartbeatMessage)
	select {
	case <-observer.errorObserved:
	case <-time.After(time.Second):
		stop()
		t.Fatal("ack progress error was not observed")
	}
	stop()

	_, _, _, _, stages := observer.snapshot()
	if !slices.Contains(stages, WorkerErrorStageProcess) || !slices.Contains(stages, WorkerErrorStageAckProgress) {
		t.Fatalf("worker error stages = %v", stages)
	}
}

func TestWorkerProcessCancellationLeavesMessageUnacknowledged(t *testing.T) {
	t.Parallel()

	request := mustRequest(t)
	message := newWorkerTestMessage(t, request, 1)
	storeStarted := make(chan struct{})
	worker := testWorker(
		submitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) {
			return fixtureOutcome(), nil
		}),
		sinkFunc(func(ctx context.Context, _ DeliveryOutcome) error {
			select {
			case <-storeStarted:
			default:
				close(storeStarted)
			}
			<-ctx.Done()
			return ctx.Err()
		}),
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Process(ctx, message) }()
	<-storeStarted
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Process() error = %v, want context.Canceled", err)
	}
	if actions := message.events.snapshot(); len(actions) != 0 {
		t.Fatalf("message actions = %v, want unacknowledged", actions)
	}
}

func TestWorkerRunEmbeddedJetStreamDeliveryPolicies(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		publish     func(*testing.T, *Runtime, config.NATS)
		submit      func(int32) (submission.Outcome, error)
		maxDeliver  int
		wantCalls   int32
		wantReject  bool
		wantFailure trusterr.Code
	}{
		{
			name: "accepted",
			publish: func(t *testing.T, runtime *Runtime, cfg config.NATS) {
				publishWorkerRequest(t, runtime, cfg, mustRequest(t))
			},
			submit:    func(int32) (submission.Outcome, error) { return fixtureOutcome(), nil },
			wantCalls: 1,
		},
		{
			name: "transient then accepted",
			publish: func(t *testing.T, runtime *Runtime, cfg config.NATS) {
				publishWorkerRequest(t, runtime, cfg, mustRequest(t))
			},
			submit: func(call int32) (submission.Outcome, error) {
				if call == 1 {
					return submission.Outcome{}, trusterr.New(trusterr.CodeResourceExhausted, "busy")
				}
				return fixtureOutcome(), nil
			},
			wantCalls: 2,
		},
		{
			name: "retry limit",
			publish: func(t *testing.T, runtime *Runtime, cfg config.NATS) {
				publishWorkerRequest(t, runtime, cfg, mustRequest(t))
			},
			submit: func(int32) (submission.Outcome, error) {
				return submission.Outcome{}, trusterr.New(trusterr.CodeInternal, "failed")
			},
			maxDeliver:  2,
			wantCalls:   2,
			wantFailure: trusterr.CodeInternal,
		},
		{
			name: "malformed",
			publish: func(t *testing.T, runtime *Runtime, cfg config.NATS) {
				message := &nats.Msg{Subject: cfg.Subject, Data: []byte("invalid"), Header: workerHeaders("invalid")}
				if _, err := runtime.JetStream().PublishMsg(context.Background(), message); err != nil {
					t.Fatalf("PublishMsg() error = %v", err)
				}
			},
			submit:     func(int32) (submission.Outcome, error) { return fixtureOutcome(), nil },
			wantReject: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := startTestServer(t, nil)
			cfg := testNATSConfig(s.ClientURL())
			cfg.Workers = 1
			cfg.NakDelay = "10ms"
			cfg.ResultRetryWait = "10ms"
			if tc.maxDeliver != 0 {
				cfg.MaxDeliver = tc.maxDeliver
			}
			runtime, err := Open(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			t.Cleanup(func() { closeRuntime(t, runtime) })

			var calls atomic.Int32
			stored := make(chan DeliveryOutcome, 1)
			worker, err := NewWorker(
				runtime.Consumer(),
				submitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) {
					return tc.submit(calls.Add(1))
				}),
				sinkFunc(func(_ context.Context, outcome DeliveryOutcome) error {
					select {
					case stored <- outcome:
					default:
					}
					return nil
				}),
				cfg,
			)
			if err != nil {
				t.Fatalf("NewWorker() error = %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			runDone := make(chan error, 1)
			go func() { runDone <- worker.Run(ctx) }()
			tc.publish(t, runtime, cfg)

			select {
			case outcome := <-stored:
				if tc.wantReject != (outcome.Rejection != nil) {
					t.Fatalf("stored outcome = %+v", outcome)
				}
				if tc.wantFailure != "" && (outcome.Result == nil || outcome.Result.Error == nil || outcome.Result.Error.Code != tc.wantFailure) {
					t.Fatalf("stored outcome = %+v, want failure %s", outcome, tc.wantFailure)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for stored outcome")
			}
			if got := calls.Load(); got != tc.wantCalls {
				t.Fatalf("submit calls = %d, want %d", got, tc.wantCalls)
			}
			waitForWorkerAck(t, runtime.Consumer())
			cancel()
			if err := <-runDone; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestWorkerRunSinkOutageDoesNotConsumeDeliveryBudget(t *testing.T) {
	t.Parallel()

	s := startTestServer(t, nil)
	cfg := testNATSConfig(s.ClientURL())
	cfg.Workers = 1
	cfg.AckWait = "90ms"
	cfg.ResultRetryWait = "70ms"
	runtime, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { closeRuntime(t, runtime) })

	var submitCalls atomic.Int32
	var sinkCalls atomic.Int32
	stored := make(chan struct{}, 1)
	worker, err := NewWorker(
		runtime.Consumer(),
		submitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) {
			submitCalls.Add(1)
			return fixtureOutcome(), nil
		}),
		sinkFunc(func(context.Context, DeliveryOutcome) error {
			if sinkCalls.Add(1) < 3 {
				return errors.New("sink unavailable")
			}
			select {
			case stored <- struct{}{}:
			default:
			}
			return nil
		}),
		cfg,
	)
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	publishWorkerRequest(t, runtime, cfg, mustRequest(t))
	select {
	case <-stored:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for recovered sink")
	}
	if submitCalls.Load() != 1 || sinkCalls.Load() != 3 {
		t.Fatalf("submit calls = %d sink calls = %d", submitCalls.Load(), sinkCalls.Load())
	}
	waitForWorkerAck(t, runtime.Consumer())
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestWorkerRunCancellationLeavesDeliveryForRedelivery(t *testing.T) {
	t.Parallel()

	s := startTestServer(t, nil)
	cfg := testNATSConfig(s.ClientURL())
	cfg.Workers = 1
	cfg.AckWait = "100ms"
	cfg.ResultRetryWait = "10ms"
	runtime, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { closeRuntime(t, runtime) })

	storeStarted := make(chan struct{})
	blockedWorker, err := NewWorker(
		runtime.Consumer(),
		submitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) { return fixtureOutcome(), nil }),
		sinkFunc(func(ctx context.Context, _ DeliveryOutcome) error {
			select {
			case <-storeStarted:
			default:
				close(storeStarted)
			}
			<-ctx.Done()
			return ctx.Err()
		}),
		cfg,
	)
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}
	blockedCtx, blockedCancel := context.WithCancel(context.Background())
	blockedDone := make(chan error, 1)
	go func() { blockedDone <- blockedWorker.Run(blockedCtx) }()
	publishWorkerRequest(t, runtime, cfg, mustRequest(t))
	select {
	case <-storeStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for blocked sink")
	}
	blockedCancel()
	if err := <-blockedDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked Run() error = %v", err)
	}

	redelivered := make(chan struct{}, 1)
	recoveryWorker, err := NewWorker(
		runtime.Consumer(),
		submitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) { return fixtureOutcome(), nil }),
		sinkFunc(func(context.Context, DeliveryOutcome) error {
			select {
			case redelivered <- struct{}{}:
			default:
			}
			return nil
		}),
		cfg,
	)
	if err != nil {
		t.Fatalf("NewWorker(recovery) error = %v", err)
	}
	recoveryCtx, recoveryCancel := context.WithCancel(context.Background())
	recoveryDone := make(chan error, 1)
	go func() { recoveryDone <- recoveryWorker.Run(recoveryCtx) }()
	select {
	case <-redelivered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for message redelivery")
	}
	waitForWorkerAck(t, runtime.Consumer())
	recoveryCancel()
	if err := <-recoveryDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("recovery Run() error = %v", err)
	}
}

type submitterFunc func(context.Context, model.SignedClaim) (submission.Outcome, error)

func (function submitterFunc) Submit(ctx context.Context, claim model.SignedClaim) (submission.Outcome, error) {
	return function(ctx, claim)
}

type sinkFunc func(context.Context, DeliveryOutcome) error

func (function sinkFunc) Store(ctx context.Context, outcome DeliveryOutcome) error {
	return function(ctx, outcome)
}

type eventSequence struct {
	mu     sync.Mutex
	events []string
}

func (sequence *eventSequence) add(event string) {
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	sequence.events = append(sequence.events, event)
}

func (sequence *eventSequence) snapshot() []string {
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	return append([]string(nil), sequence.events...)
}

type workerTestMessage struct {
	subject       string
	reply         string
	headers       nats.Header
	data          []byte
	meta          *jetstream.MsgMetadata
	metadataErr   error
	doubleAckErr  error
	inProgressErr error
	events        *eventSequence
	inProgress    atomic.Int32
}

func newWorkerTestMessage(t *testing.T, request Request, delivered uint64) *workerTestMessage {
	t.Helper()
	data, err := EncodeRequest(request)
	if err != nil {
		t.Fatalf("EncodeRequest() error = %v", err)
	}
	return &workerTestMessage{
		subject: "trustdb.ingress.test.claims",
		headers: workerHeaders(request.MessageID),
		data:    data,
		meta: &jetstream.MsgMetadata{
			Stream:       "TEST",
			Consumer:     "worker",
			NumDelivered: delivered,
			Sequence:     jetstream.SequencePair{Stream: 1, Consumer: delivered},
		},
		events: &eventSequence{},
	}
}

func (message *workerTestMessage) Metadata() (*jetstream.MsgMetadata, error) {
	return message.meta, message.metadataErr
}
func (message *workerTestMessage) Data() []byte         { return message.data }
func (message *workerTestMessage) Headers() nats.Header { return message.headers }
func (message *workerTestMessage) Subject() string      { return message.subject }
func (message *workerTestMessage) Reply() string        { return message.reply }
func (message *workerTestMessage) Ack() error           { message.events.add("ack"); return nil }
func (message *workerTestMessage) DoubleAck(context.Context) error {
	message.events.add("double_ack")
	return message.doubleAckErr
}
func (message *workerTestMessage) Nak() error { message.events.add("nak"); return nil }
func (message *workerTestMessage) NakWithDelay(time.Duration) error {
	message.events.add("nak")
	return nil
}
func (message *workerTestMessage) InProgress() error {
	message.inProgress.Add(1)
	return message.inProgressErr
}
func (message *workerTestMessage) Term() error { message.events.add("term"); return nil }
func (message *workerTestMessage) TermWithReason(string) error {
	message.events.add("term")
	return nil
}

func testWorker(submitter submission.Submitter, sink OutcomeSink) *Worker {
	return &Worker{
		submitter:        submitter,
		sink:             sink,
		observer:         noopWorkerObserver{},
		ackWait:          time.Hour,
		nakDelay:         time.Millisecond,
		outcomeRetryWait: time.Millisecond,
		maxDeliver:       3,
		subject:          "trustdb.ingress.test.claims",
		onError:          func(error) {},
	}
}

type workerTestObserver struct {
	mu            sync.Mutex
	inFlight      int
	maxInFlight   int
	actions       []string
	retries       []string
	errors        []string
	errorObserved chan struct{}
}

func newWorkerTestObserver() *workerTestObserver {
	return &workerTestObserver{errorObserved: make(chan struct{}, 8)}
}

func (o *workerTestObserver) DeliveryStarted() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.inFlight++
	o.maxInFlight = max(o.maxInFlight, o.inFlight)
}

func (o *workerTestObserver) DeliveryFinished() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.inFlight--
}

func (o *workerTestObserver) DeliveryAction(action string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.actions = append(o.actions, action)
}

func (o *workerTestObserver) OutcomeStoreRetry(kind string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.retries = append(o.retries, kind)
}

func (o *workerTestObserver) WorkerError(stage string) {
	o.mu.Lock()
	o.errors = append(o.errors, stage)
	o.mu.Unlock()
	select {
	case o.errorObserved <- struct{}{}:
	default:
	}
}

func (o *workerTestObserver) snapshot() (int, int, []string, []string, []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.inFlight, o.maxInFlight, slices.Clone(o.actions), slices.Clone(o.retries), slices.Clone(o.errors)
}

func workerHeaders(messageID string) nats.Header {
	return nats.Header{
		HeaderContentType:   []string{ContentType},
		HeaderSchemaVersion: []string{SchemaRequest},
		HeaderMessageID:     []string{messageID},
	}
}

func publishWorkerRequest(t *testing.T, runtime *Runtime, cfg config.NATS, request Request) {
	t.Helper()
	data, err := EncodeRequest(request)
	if err != nil {
		t.Fatalf("EncodeRequest() error = %v", err)
	}
	message := &nats.Msg{Subject: cfg.Subject, Data: data, Header: workerHeaders(request.MessageID)}
	if _, err := runtime.JetStream().PublishMsg(context.Background(), message); err != nil {
		t.Fatalf("PublishMsg() error = %v", err)
	}
}

func waitForWorkerAck(t *testing.T, consumer jetstream.Consumer) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		info, err := consumer.Info(context.Background())
		if err == nil && info.NumAckPending == 0 && info.NumPending == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	info, err := consumer.Info(context.Background())
	t.Fatalf("timed out waiting for worker ACK: info=%+v err=%v", info, err)
}

var _ jetstream.Msg = (*workerTestMessage)(nil)
