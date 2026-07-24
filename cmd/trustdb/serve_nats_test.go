package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus/testutil"
	trustconfig "github.com/wowtrust/trustdb/internal/config"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/natsingress"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/prooflevel"
	"github.com/wowtrust/trustdb/internal/submission"
)

func TestStartServeNATSIngressDisabledIsStrictNoOp(t *testing.T) {
	cfg := trustconfig.Default().NATS
	cfg.URLs = []string{"nats://127.0.0.1:1"}
	service, err := startServeNATSIngress(context.Background(), cfg, nil, nil, silentLogger())
	if err != nil {
		t.Fatalf("startServeNATSIngress() error = %v", err)
	}
	if service != nil {
		t.Fatalf("startServeNATSIngress() service = %#v, want nil", service)
	}
}

func TestStartServeNATSIngressFailsClosedWhenBrokerIsUnavailable(t *testing.T) {
	cfg := serveNATSTestConfig("nats://127.0.0.1:1")
	cfg.ConnectTimeout = "50ms"
	service, err := startServeNATSIngress(context.Background(), cfg, acceptedServeNATSSubmitter(), nil, silentLogger())
	if err == nil || !strings.Contains(err.Error(), "start optional NATS ingress") {
		t.Fatalf("startServeNATSIngress() service=%#v error=%v", service, err)
	}
	if service != nil {
		t.Fatalf("startServeNATSIngress() service = %#v, want nil", service)
	}
}

func TestServeNATSIngressStoresAcceptedResultBeforeAck(t *testing.T) {
	s := startServeNATSTestServer(t)
	cfg := serveNATSTestConfig(s.ClientURL())
	var mu sync.Mutex
	var submitted int
	submitter := serveNATSSubmitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) {
		mu.Lock()
		submitted++
		mu.Unlock()
		return acceptedServeNATSOutcome(), nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	_, metrics := observability.NewRegistry()
	service, err := startServeNATSIngress(ctx, cfg, submitter, metrics, silentLogger())
	if err != nil {
		t.Fatalf("startServeNATSIngress() error = %v", err)
	}
	t.Cleanup(func() {
		cancel()
		closeServeNATSIngress(t, service)
	})

	request := serveNATSRequest(t, "accepted")
	publishServeNATSRequest(t, service.runtime.JetStream(), cfg, request)
	select {
	case <-service.Done():
		t.Fatalf("NATS worker stopped before processing: %v", service.Err())
	case <-time.After(100 * time.Millisecond):
	}
	stored := waitForServeNATSMessage(t, service.runtime.ResultStream(), serveNATSOutcomeSubject(cfg.ResultSubject, request.MessageID))
	result, err := natsingress.DecodeResult(stored.Data)
	if err != nil {
		t.Fatalf("DecodeResult() error = %v", err)
	}
	if result.Accepted == nil || result.Accepted.RecordID != acceptedServeNATSOutcome().RecordID {
		t.Fatalf("stored result = %+v", result)
	}
	if stored.Header.Get(natsingress.HeaderSchemaVersion) != natsingress.SchemaResult || stored.Header.Get(natsingress.HeaderMessageID) != request.MessageID {
		t.Fatalf("stored result headers = %v", stored.Header)
	}
	waitForServeNATSStreamMessages(t, service.runtime.Stream(), 0)
	mu.Lock()
	defer mu.Unlock()
	if submitted != 1 {
		t.Fatalf("submission count = %d, want 1", submitted)
	}
	if got := testutil.ToFloat64(metrics.NATSIngressDeliveries.WithLabelValues(natsingress.DeliveryActionAck)); got != 1 {
		t.Fatalf("NATS ack metric = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.NATSIngressInFlight); got != 0 {
		t.Fatalf("NATS in-flight metric = %v, want 0", got)
	}
}

func TestServeNATSIngressStoresMalformedDeliveryInDeadLetterStream(t *testing.T) {
	s := startServeNATSTestServer(t)
	cfg := serveNATSTestConfig(s.ClientURL())
	service, err := startServeNATSIngress(context.Background(), cfg, acceptedServeNATSSubmitter(), nil, silentLogger())
	if err != nil {
		t.Fatalf("startServeNATSIngress() error = %v", err)
	}
	t.Cleanup(func() { closeServeNATSIngress(t, service) })

	message := nats.NewMsg(cfg.Subject)
	message.Header.Set(natsingress.HeaderContentType, "application/json")
	message.Header.Set(natsingress.HeaderSchemaVersion, natsingress.SchemaRequest)
	message.Header.Set(natsingress.HeaderMessageID, "caller-controlled")
	message.Data = []byte("malformed")
	if _, err := service.runtime.JetStream().PublishMsg(context.Background(), message, jetstream.WithExpectStream(cfg.Stream)); err != nil {
		t.Fatalf("PublishMsg(malformed) error = %v", err)
	}

	state := waitForServeNATSStreamMessages(t, service.runtime.DeadLetterStream(), 1)
	stored, err := service.runtime.DeadLetterStream().GetMsg(context.Background(), state.FirstSeq)
	if err != nil {
		t.Fatalf("DeadLetterStream.GetMsg() error = %v", err)
	}
	deadLetter, err := natsingress.DecodeDeadLetter(stored.Data)
	if err != nil {
		t.Fatalf("DecodeDeadLetter() error = %v", err)
	}
	if string(deadLetter.Data) != "malformed" || deadLetter.Headers.Get(natsingress.HeaderMessageID) != "caller-controlled" {
		t.Fatalf("dead-letter evidence = %+v", deadLetter)
	}
	if deadLetter.ID == "caller-controlled" || deadLetter.Stream != cfg.Stream || deadLetter.Consumer != cfg.Durable {
		t.Fatalf("dead-letter identity = %+v", deadLetter)
	}
}

func TestServeNATSIngressShutdownLeavesInFlightDeliveryForRestart(t *testing.T) {
	s := startServeNATSTestServer(t)
	cfg := serveNATSTestConfig(s.ClientURL())
	started := make(chan struct{})
	firstSubmitter := serveNATSSubmitterFunc(func(ctx context.Context, _ model.SignedClaim) (submission.Outcome, error) {
		select {
		case <-started:
		default:
			close(started)
		}
		<-ctx.Done()
		return submission.Outcome{}, ctx.Err()
	})

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	first, err := startServeNATSIngress(firstCtx, cfg, firstSubmitter, nil, silentLogger())
	if err != nil {
		t.Fatalf("startServeNATSIngress(first) error = %v", err)
	}
	request := serveNATSRequest(t, "redelivery")
	publishServeNATSRequest(t, first.runtime.JetStream(), cfg, request)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("first NATS submission did not start")
	}
	cancelFirst()
	closeServeNATSIngress(t, first)
	if err := first.Err(); err != nil {
		t.Fatalf("first lifecycle error after cancellation = %v", err)
	}

	cfg.Provision = false
	second, err := startServeNATSIngress(context.Background(), cfg, acceptedServeNATSSubmitter(), nil, silentLogger())
	if err != nil {
		t.Fatalf("startServeNATSIngress(second) error = %v", err)
	}
	t.Cleanup(func() { closeServeNATSIngress(t, second) })
	stored := waitForServeNATSMessage(t, second.runtime.ResultStream(), serveNATSOutcomeSubject(cfg.ResultSubject, request.MessageID))
	result, err := natsingress.DecodeResult(stored.Data)
	if err != nil || result.Accepted == nil {
		t.Fatalf("redelivered result = %+v error=%v", result, err)
	}
}

func TestServeNATSIngressReportsUnexpectedWorkerExit(t *testing.T) {
	s := startServeNATSTestServer(t)
	cfg := serveNATSTestConfig(s.ClientURL())
	_, metrics := observability.NewRegistry()
	service, err := startServeNATSIngress(context.Background(), cfg, acceptedServeNATSSubmitter(), metrics, silentLogger())
	if err != nil {
		t.Fatalf("startServeNATSIngress() error = %v", err)
	}
	service.runtime.Conn().Close()
	select {
	case <-service.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not report the closed NATS connection")
	}
	if err := service.Err(); err == nil {
		t.Fatal("worker exit error = nil, want fatal transport error")
	}
	if got := testutil.ToFloat64(metrics.NATSIngressErrors.WithLabelValues(natsingress.WorkerErrorStageConsume)); got == 0 {
		t.Fatal("NATS consume error metric = 0, want non-zero")
	}
	closeServeNATSIngress(t, service)
}

func TestWaitForServeStopTreatsUnexpectedNATSExitAsFatal(t *testing.T) {
	runErr := errors.New("consumer stopped")
	service := &serveNATSIngress{
		done:   make(chan struct{}),
		runErr: runErr,
	}
	close(service.done)

	err := waitForServeStop(context.Background(), make(chan error), service)
	if !errors.Is(err, runErr) || !strings.Contains(err.Error(), "stopped unexpectedly") {
		t.Fatalf("waitForServeStop() error = %v", err)
	}
}

func TestWaitForServeStopAllowsNATSExitAfterLifecycleCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service := &serveNATSIngress{done: make(chan struct{})}
	close(service.done)

	if err := waitForServeStop(ctx, make(chan error), service); err != nil {
		t.Fatalf("waitForServeStop() error = %v", err)
	}
}

type serveNATSSubmitterFunc func(context.Context, model.SignedClaim) (submission.Outcome, error)

func (f serveNATSSubmitterFunc) Submit(ctx context.Context, signed model.SignedClaim) (submission.Outcome, error) {
	return f(ctx, signed)
}

func acceptedServeNATSSubmitter() submission.Submitter {
	return serveNATSSubmitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) {
		return acceptedServeNATSOutcome(), nil
	})
}

func acceptedServeNATSOutcome() submission.Outcome {
	const recordID = "tr1natsserveruntime"
	return submission.Outcome{
		RecordID:      recordID,
		Status:        "accepted",
		ProofLevel:    prooflevel.L2.String(),
		BatchEnqueued: true,
		ServerRecord: model.ServerRecord{
			SchemaVersion: model.SchemaServerRecord,
			RecordID:      recordID,
		},
		AcceptedReceipt: model.AcceptedReceipt{
			SchemaVersion: model.SchemaAcceptedReceipt,
			RecordID:      recordID,
			Status:        "accepted",
		},
	}
}

func serveNATSRequest(t *testing.T, idempotencyKey string) natsingress.Request {
	t.Helper()
	request, err := natsingress.NewRequest(model.SignedClaim{
		SchemaVersion: model.SchemaSignedClaim,
		Claim: model.ClientClaim{
			SchemaVersion:  model.SchemaClientClaim,
			TenantID:       "tenant-a",
			ClientID:       "client-a",
			IdempotencyKey: idempotencyKey,
		},
		Signature: model.Signature{
			Alg:       model.DefaultSignatureAlg,
			KeyID:     "client-key",
			Signature: []byte("test-signature"),
		},
	})
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	return request
}

func publishServeNATSRequest(t *testing.T, js jetstream.JetStream, cfg trustconfig.NATS, request natsingress.Request) {
	t.Helper()
	body, err := natsingress.EncodeRequest(request)
	if err != nil {
		t.Fatalf("EncodeRequest() error = %v", err)
	}
	message := nats.NewMsg(cfg.Subject)
	message.Header.Set(natsingress.HeaderContentType, natsingress.ContentType)
	message.Header.Set(natsingress.HeaderSchemaVersion, natsingress.SchemaRequest)
	message.Header.Set(natsingress.HeaderMessageID, request.MessageID)
	message.Data = body
	if _, err := js.PublishMsg(context.Background(), message, jetstream.WithExpectStream(cfg.Stream), jetstream.WithMsgID(request.MessageID)); err != nil {
		t.Fatalf("PublishMsg(request) error = %v", err)
	}
}

func waitForServeNATSMessage(t *testing.T, stream jetstream.Stream, subject string) *jetstream.RawStreamMsg {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		message, err := stream.GetLastMsgForSubject(context.Background(), subject)
		if err == nil {
			return message
		}
		if !errors.Is(err, jetstream.ErrMsgNotFound) {
			t.Fatalf("GetLastMsgForSubject(%s) error = %v", subject, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("message on subject %s was not stored", subject)
	return nil
}

func waitForServeNATSStreamMessages(t *testing.T, stream jetstream.Stream, want uint64) jetstream.StreamState {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var state jetstream.StreamState
	for time.Now().Before(deadline) {
		info, err := stream.Info(context.Background())
		if err != nil {
			t.Fatalf("Stream.Info() error = %v", err)
		}
		state = info.State
		if state.Msgs == want {
			return state
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("stream messages = %d, want %d", state.Msgs, want)
	return state
}

func serveNATSOutcomeSubject(pattern, id string) string {
	return strings.TrimSuffix(pattern, "*") + id
}

func serveNATSTestConfig(url string) trustconfig.NATS {
	cfg := trustconfig.Default().NATS
	cfg.Enabled = true
	cfg.URLs = []string{url}
	cfg.Stream = "TRUSTDB_SERVE_INGRESS_TEST"
	cfg.Subject = "trustdb.serve.test.claims"
	cfg.Durable = "trustdb-serve-test"
	cfg.ResultStream = "TRUSTDB_SERVE_RESULTS_TEST"
	cfg.ResultSubject = "trustdb.serve.test.results.*"
	cfg.DLQStream = "TRUSTDB_SERVE_DLQ_TEST"
	cfg.DLQSubject = "trustdb.serve.test.dlq.*"
	cfg.StreamStorage = "memory"
	cfg.StreamMaxBytes = 64 << 10
	cfg.ResultMaxBytes = 64 << 10
	cfg.DLQMaxBytes = 64 << 10
	cfg.Workers = 2
	cfg.FetchBatch = 4
	cfg.FetchWait = "1s"
	cfg.AckWait = "500ms"
	cfg.NakDelay = "100ms"
	cfg.ResultRetryWait = "20ms"
	cfg.MaxAckPending = 8
	cfg.ConnectTimeout = "1s"
	cfg.ReconnectWait = "20ms"
	cfg.MaxReconnects = 0
	cfg.DrainTimeout = "1s"
	return cfg
}

func startServeNATSTestServer(t *testing.T) *server.Server {
	t.Helper()
	s, err := server.NewServer(&server.Options{
		Host:      "127.0.0.1",
		Port:      -1,
		JetStream: true,
		StoreDir:  t.TempDir(),
		NoLog:     true,
		NoSigs:    true,
	})
	if err != nil {
		t.Fatalf("server.NewServer() error = %v", err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		s.Shutdown()
		t.Fatal("embedded NATS server did not become ready")
	}
	t.Cleanup(func() {
		s.Shutdown()
		s.WaitForShutdown()
	})
	return s
}

func closeServeNATSIngress(t *testing.T, service *serveNATSIngress) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := service.Close(ctx); err != nil {
		t.Fatalf("serveNATSIngress.Close() error = %v", err)
	}
}
