package natsingress

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/wowtrust/trustdb/internal/config"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestJetStreamOutcomeSinkStoresResultsAndDeadLetters(t *testing.T) {
	t.Parallel()

	runtime, cfg := openOutcomeTestRuntime(t, nil)
	sink := mustOutcomeSink(t, runtime, cfg)

	request := mustRequest(t)
	result, err := NewErrorResult(request, trusterr.New(trusterr.CodeInvalidArgument, "invalid claim"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Store(context.Background(), DeliveryOutcome{Request: &request, Result: &result}); err != nil {
		t.Fatalf("Store(result) error = %v", err)
	}
	resultSubject := mustOutcomeSubject(t, cfg.ResultSubject, request.MessageID)
	storedResult, err := runtime.ResultStream().GetLastMsgForSubject(context.Background(), resultSubject)
	if err != nil {
		t.Fatalf("GetLastMsgForSubject(result) error = %v", err)
	}
	decodedResult, err := DecodeResult(storedResult.Data)
	if err != nil {
		t.Fatalf("DecodeResult() error = %v", err)
	}
	if decodedResult.MessageID != request.MessageID || decodedResult.Error == nil || decodedResult.Error.Message != "invalid claim" {
		t.Fatalf("stored result = %+v", decodedResult)
	}
	assertOutcomeHeaders(t, storedResult.Header, SchemaResult, request.MessageID)

	rejection := rejectionForConfig(cfg)
	if err := sink.Store(context.Background(), DeliveryOutcome{Rejection: &rejection}); err != nil {
		t.Fatalf("Store(rejection) error = %v", err)
	}
	deadLetterSubject := mustOutcomeSubject(t, cfg.DLQSubject, rejection.ID)
	storedDeadLetter, err := runtime.DeadLetterStream().GetLastMsgForSubject(context.Background(), deadLetterSubject)
	if err != nil {
		t.Fatalf("GetLastMsgForSubject(dead-letter) error = %v", err)
	}
	deadLetter, err := DecodeDeadLetter(storedDeadLetter.Data)
	if err != nil {
		t.Fatalf("DecodeDeadLetter() error = %v", err)
	}
	if deadLetter.ID != rejection.ID || deadLetter.Headers.Get("X-Trace") != "trace-a" || string(deadLetter.Data) != "malformed" {
		t.Fatalf("stored dead-letter = %+v", deadLetter)
	}
	assertOutcomeHeaders(t, storedDeadLetter.Header, SchemaDeadLetter, rejection.ID)
}

func TestJetStreamOutcomeSinkIsIdempotentBeyondDuplicateWindowAndRestart(t *testing.T) {
	t.Parallel()

	runtime, cfg := openOutcomeTestRuntime(t, func(cfg *config.NATS) {
		cfg.DuplicateWindow = "100ms"
	})
	sink := mustOutcomeSink(t, runtime, cfg)
	outcome := errorOutcome(t, mustRequest(t), "terminal")
	if err := sink.Store(context.Background(), outcome); err != nil {
		t.Fatalf("Store(first) error = %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	const attempts = 8
	var wg sync.WaitGroup
	errorsSeen := make(chan error, attempts)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sink.Store(context.Background(), outcome); err != nil {
				errorsSeen <- err
			}
		}()
	}
	wg.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Errorf("concurrent exact Store() error = %v", err)
	}
	info, err := runtime.ResultStream().Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 1 {
		t.Fatalf("result stream messages = %d, want exactly 1", info.State.Msgs)
	}

	closeRuntime(t, runtime)
	cfg.Provision = false
	restarted, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Open(restart) error = %v", err)
	}
	t.Cleanup(func() { closeRuntime(t, restarted) })
	if err := mustOutcomeSink(t, restarted, cfg).Store(context.Background(), outcome); err != nil {
		t.Fatalf("Store(after restart) error = %v", err)
	}
	info, err = restarted.ResultStream().Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 1 {
		t.Fatalf("result stream messages after restart = %d, want exactly 1", info.State.Msgs)
	}
}

func TestJetStreamOutcomeSinkRejectsBodyAndCriticalHeaderConflicts(t *testing.T) {
	t.Parallel()

	runtime, cfg := openOutcomeTestRuntime(t, nil)
	sink := mustOutcomeSink(t, runtime, cfg)
	request := mustRequest(t)
	first := errorOutcome(t, request, "first")
	if err := sink.Store(context.Background(), first); err != nil {
		t.Fatalf("Store(first) error = %v", err)
	}
	conflict := errorOutcome(t, request, "different")
	if err := sink.Store(context.Background(), conflict); !errors.Is(err, ErrOutcomeConflict) {
		t.Fatalf("Store(body conflict) error = %v, want ErrOutcomeConflict", err)
	}

	headerRequest := mustRequestWithIdempotencyKey(t, "header-conflict")
	headerOutcome := errorOutcome(t, headerRequest, "same body")
	body, err := EncodeResult(*headerOutcome.Result)
	if err != nil {
		t.Fatal(err)
	}
	subject := mustOutcomeSubject(t, cfg.ResultSubject, headerRequest.MessageID)
	message := nats.NewMsg(subject)
	message.Header.Set(HeaderContentType, ContentType)
	message.Header.Set(HeaderSchemaVersion, "wrong-schema")
	message.Header.Set(HeaderMessageID, headerRequest.MessageID)
	message.Data = body
	if _, err := runtime.JetStream().PublishMsg(
		context.Background(),
		message,
		jetstream.WithExpectStream(cfg.ResultStream),
		jetstream.WithExpectLastSequencePerSubject(0),
		jetstream.WithMsgID(headerRequest.MessageID),
	); err != nil {
		t.Fatalf("PublishMsg(conflicting header) error = %v", err)
	}
	if err := sink.Store(context.Background(), headerOutcome); !errors.Is(err, ErrOutcomeConflict) {
		t.Fatalf("Store(header conflict) error = %v, want ErrOutcomeConflict", err)
	}
}

func TestJetStreamOutcomeSinkRejectsForeignDeadLetterMetadata(t *testing.T) {
	t.Parallel()

	runtime, cfg := openOutcomeTestRuntime(t, nil)
	sink := mustOutcomeSink(t, runtime, cfg)
	rejection := rejectionForConfig(cfg)
	rejection.Stream = "FOREIGN_STREAM"
	rejection.ID = rejectionIdentity(rejection.Stream, rejection.StreamSequence, rejection.Subject, rejection.Reply, rejection.Headers, rejection.Data)
	if err := sink.Store(context.Background(), DeliveryOutcome{Rejection: &rejection}); err == nil || !strings.Contains(err.Error(), "does not match configured ingress") {
		t.Fatalf("Store(foreign rejection) error = %v", err)
	}
	info, err := runtime.DeadLetterStream().Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 0 {
		t.Fatalf("dead-letter stream messages = %d, want 0", info.State.Msgs)
	}
}

func TestJetStreamOutcomeSinkKeepsDeadLetterImmutableBeyondDuplicateWindow(t *testing.T) {
	t.Parallel()

	runtime, cfg := openOutcomeTestRuntime(t, func(cfg *config.NATS) {
		cfg.DuplicateWindow = "100ms"
	})
	sink := mustOutcomeSink(t, runtime, cfg)
	rejection := rejectionForConfig(cfg)
	outcome := DeliveryOutcome{Rejection: &rejection}
	if err := sink.Store(context.Background(), outcome); err != nil {
		t.Fatalf("Store(first rejection) error = %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := sink.Store(context.Background(), outcome); err != nil {
		t.Fatalf("Store(exact rejection retry) error = %v", err)
	}

	conflict := rejection
	conflict.Message = "different rejection explanation"
	if err := sink.Store(context.Background(), DeliveryOutcome{Rejection: &conflict}); !errors.Is(err, ErrOutcomeConflict) {
		t.Fatalf("Store(rejection conflict) error = %v, want ErrOutcomeConflict", err)
	}
	info, err := runtime.DeadLetterStream().Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 1 {
		t.Fatalf("dead-letter stream messages = %d, want exactly 1", info.State.Msgs)
	}
}

func TestJetStreamOutcomeSinkAppliesBackpressureWhenResultStreamIsFull(t *testing.T) {
	t.Parallel()

	runtime, cfg := openOutcomeTestRuntime(t, func(cfg *config.NATS) {
		cfg.ResultMaxBytes = 1024
	})
	sink := mustOutcomeSink(t, runtime, cfg)

	var firstSubject string
	var capacityErr error
	for i := range 100 {
		request := mustRequestWithIdempotencyKey(t, fmt.Sprintf("capacity-%d", i))
		outcome := errorOutcome(t, request, strings.Repeat("x", 64))
		if i == 0 {
			firstSubject = mustOutcomeSubject(t, cfg.ResultSubject, request.MessageID)
		}
		if err := sink.Store(context.Background(), outcome); err != nil {
			capacityErr = err
			break
		}
	}
	if capacityErr == nil {
		t.Fatal("result stream accepted every outcome despite the configured max_bytes limit")
	}
	if errors.Is(capacityErr, ErrOutcomeConflict) {
		t.Fatalf("capacity error was reported as an immutable conflict: %v", capacityErr)
	}
	if _, err := runtime.ResultStream().GetLastMsgForSubject(context.Background(), firstSubject); err != nil {
		t.Fatalf("oldest result was evicted after capacity was reached: %v", err)
	}
	info, err := runtime.ResultStream().Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs == 0 || info.State.Bytes > uint64(cfg.ResultMaxBytes) {
		t.Fatalf("bounded result state = %+v, max_bytes=%d", info.State, cfg.ResultMaxBytes)
	}
}

func TestNewJetStreamOutcomeSinkRejectsDisabledOrUnboundRuntime(t *testing.T) {
	t.Parallel()

	cfg := config.Default().NATS
	if _, err := NewJetStreamOutcomeSink(nil, cfg); err == nil || !strings.Contains(err.Error(), "enabled") {
		t.Fatalf("NewJetStreamOutcomeSink(disabled) error = %v", err)
	}
	cfg.Enabled = true
	if _, err := NewJetStreamOutcomeSink(nil, cfg); err == nil || !strings.Contains(err.Error(), "open runtime") {
		t.Fatalf("NewJetStreamOutcomeSink(nil runtime) error = %v", err)
	}
}

func openOutcomeTestRuntime(t *testing.T, configure func(*config.NATS)) (*Runtime, config.NATS) {
	t.Helper()
	s := startTestServer(t, nil)
	cfg := testNATSConfig(s.ClientURL())
	if configure != nil {
		configure(&cfg)
	}
	runtime, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		if runtime.Conn() != nil && !runtime.Conn().IsClosed() {
			closeRuntime(t, runtime)
		}
	})
	return runtime, cfg
}

func mustOutcomeSink(t *testing.T, runtime *Runtime, cfg config.NATS) *JetStreamOutcomeSink {
	t.Helper()
	sink, err := NewJetStreamOutcomeSink(runtime, cfg)
	if err != nil {
		t.Fatalf("NewJetStreamOutcomeSink() error = %v", err)
	}
	return sink
}

func errorOutcome(t *testing.T, request Request, message string) DeliveryOutcome {
	t.Helper()
	result, err := NewErrorResult(request, trusterr.New(trusterr.CodeInvalidArgument, message))
	if err != nil {
		t.Fatal(err)
	}
	return DeliveryOutcome{Request: &request, Result: &result}
}

func mustRequestWithIdempotencyKey(t *testing.T, key string) Request {
	t.Helper()
	signed := fixtureSignedClaim()
	signed.Claim.IdempotencyKey = key
	request, err := NewRequest(signed)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func rejectionForConfig(cfg config.NATS) Rejection {
	rejection := Rejection{
		Subject:          cfg.Subject,
		Headers:          nats.Header{HeaderMessageID: {"untrusted"}, "X-Trace": {"trace-a"}},
		Data:             []byte("malformed"),
		Stream:           cfg.Stream,
		Consumer:         cfg.Durable,
		StreamSequence:   1,
		ConsumerSequence: 1,
		NumDelivered:     1,
		Code:             trusterr.CodeInvalidArgument,
		Message:          "malformed request",
	}
	rejection.ID = rejectionIdentity(rejection.Stream, rejection.StreamSequence, rejection.Subject, rejection.Reply, rejection.Headers, rejection.Data)
	return rejection
}

func mustOutcomeSubject(t *testing.T, pattern, id string) string {
	t.Helper()
	subject, err := outcomeSubject(pattern, id)
	if err != nil {
		t.Fatal(err)
	}
	return subject
}

func assertOutcomeHeaders(t *testing.T, headers nats.Header, schema, id string) {
	t.Helper()
	if headers.Get(HeaderContentType) != ContentType || headers.Get(HeaderSchemaVersion) != schema || headers.Get(HeaderMessageID) != id {
		t.Fatalf("outcome headers = %v", headers)
	}
}
