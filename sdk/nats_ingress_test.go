package sdk

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/wowtrust/trustdb/internal/cborx"
	trustconfig "github.com/wowtrust/trustdb/internal/config"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/natsingress"
	"github.com/wowtrust/trustdb/internal/prooflevel"
	"github.com/wowtrust/trustdb/internal/submission"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestNATSIngressClientSubmitSignedClaim(t *testing.T) {
	fixture := startSDKNATSFixture(t, acceptedSDKNATSSubmitter())
	client := openSDKNATSClient(t, fixture)
	signed := sdkNATSSignedClaim("submit")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := client.SubmitSignedClaim(ctx, signed)
	if err != nil {
		t.Fatalf("SubmitSignedClaim() error = %v", err)
	}
	if result.RecordID != acceptedSDKNATSOutcome().RecordID || result.ProofLevel != ProofLevelL2 || !result.BatchEnqueued {
		t.Fatalf("SubmitSignedClaim() result = %+v", result)
	}
	if result.SignedClaim.Claim.IdempotencyKey != signed.Claim.IdempotencyKey {
		t.Fatalf("SubmitSignedClaim() signed claim = %+v", result.SignedClaim)
	}
}

func TestNATSIngressClientWaitResultCoversLiveCommit(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	fixture := startSDKNATSFixture(t, sdkNATSSubmitterFunc(func(ctx context.Context, _ model.SignedClaim) (submission.Outcome, error) {
		select {
		case <-started:
		default:
			close(started)
		}
		select {
		case <-release:
			return acceptedSDKNATSOutcome(), nil
		case <-ctx.Done():
			return submission.Outcome{}, ctx.Err()
		}
	}))
	client := openSDKNATSClient(t, fixture)
	handle, err := client.PublishSignedClaim(context.Background(), sdkNATSSignedClaim("live"))
	if err != nil {
		t.Fatalf("PublishSignedClaim() error = %v", err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("NATS worker did not start the submission")
	}

	type waitResult struct {
		result SubmitResult
		err    error
	}
	waited := make(chan waitResult, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		result, err := client.WaitResult(ctx, handle)
		waited <- waitResult{result: result, err: err}
	}()
	waitForSDKNATSSubscriptions(t, client, 1)
	close(release)

	got := <-waited
	if got.err != nil || got.result.RecordID != acceptedSDKNATSOutcome().RecordID {
		t.Fatalf("WaitResult() result=%+v error=%v", got.result, got.err)
	}
}

func TestNATSIngressClientWaitResultRecoversStoredOutcome(t *testing.T) {
	fixture := startSDKNATSFixture(t, acceptedSDKNATSSubmitter())
	client := openSDKNATSClient(t, fixture)
	handle, err := client.PublishSignedClaim(context.Background(), sdkNATSSignedClaim("stored"))
	if err != nil {
		t.Fatalf("PublishSignedClaim() error = %v", err)
	}
	resultSubject, err := natsResultSubject(fixture.cfg.ResultSubject, handle.MessageID)
	if err != nil {
		t.Fatal(err)
	}
	waitForSDKNATSStoredResult(t, fixture.runtime.ResultStream(), resultSubject)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := client.WaitResult(ctx, handle)
	if err != nil || result.RecordID != acceptedSDKNATSOutcome().RecordID {
		t.Fatalf("WaitResult() result=%+v error=%v", result, err)
	}
}

func TestNATSIngressClientDuplicatePublishReturnsImmutableResult(t *testing.T) {
	var submitted atomic.Int64
	fixture := startSDKNATSFixture(t, sdkNATSSubmitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) {
		submitted.Add(1)
		return acceptedSDKNATSOutcome(), nil
	}))
	client := openSDKNATSClient(t, fixture)
	signed := sdkNATSSignedClaim("duplicate")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := client.SubmitSignedClaim(ctx, signed)
	if err != nil {
		t.Fatalf("SubmitSignedClaim(first) error = %v", err)
	}
	second, err := client.SubmitSignedClaim(ctx, signed)
	if err != nil {
		t.Fatalf("SubmitSignedClaim(second) error = %v", err)
	}
	if first.RecordID != second.RecordID || submitted.Load() != 1 {
		t.Fatalf("duplicate results first=%+v second=%+v submissions=%d", first, second, submitted.Load())
	}
}

func TestNATSIngressClientReturnsTypedServerFailure(t *testing.T) {
	fixture := startSDKNATSFixture(t, sdkNATSSubmitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) {
		return submission.Outcome{}, trusterr.New(trusterr.CodeInvalidArgument, "claim rejected")
	}))
	client := openSDKNATSClient(t, fixture)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.SubmitSignedClaim(ctx, sdkNATSSignedClaim("failure"))
	var sdkErr *Error
	if !errors.As(err, &sdkErr) || sdkErr.Code != string(trusterr.CodeInvalidArgument) || sdkErr.Message != "claim rejected" {
		t.Fatalf("SubmitSignedClaim() error = %#v", err)
	}
}

func TestNATSIngressClientWaitResultHonorsCancellation(t *testing.T) {
	fixture := startSDKNATSFixtureWithoutWorker(t)
	client := openSDKNATSClient(t, fixture)
	handle, err := client.PublishSignedClaim(context.Background(), sdkNATSSignedClaim("cancel"))
	if err != nil {
		t.Fatalf("PublishSignedClaim() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = client.WaitResult(ctx, handle)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitResult() error = %v, want deadline exceeded", err)
	}
}

func TestNATSIngressClientRejectsTamperedDurableResults(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*nats.Msg, natsingress.Request)
		want   string
	}{
		{
			name: "content type",
			mutate: func(message *nats.Msg, _ natsingress.Request) {
				message.Header.Del(natsingress.HeaderContentType)
			},
			want: "content type",
		},
		{
			name: "schema header",
			mutate: func(message *nats.Msg, _ natsingress.Request) {
				message.Header.Set(natsingress.HeaderSchemaVersion, "trustdb.nats-ingress-result.v999")
			},
			want: "schema header",
		},
		{
			name: "message id header",
			mutate: func(message *nats.Msg, _ natsingress.Request) {
				message.Header.Set(natsingress.HeaderMessageID, "wrong")
			},
			want: "message_id header",
		},
		{
			name: "malformed body",
			mutate: func(message *nats.Msg, _ natsingress.Request) {
				message.Data = []byte("malformed")
			},
			want: "decode NATS result",
		},
		{
			name: "inconsistent accepted result",
			mutate: func(message *nats.Msg, request natsingress.Request) {
				result, err := natsingress.NewAcceptedResult(request, acceptedSDKNATSOutcome())
				if err != nil {
					t.Fatal(err)
				}
				result.Accepted.RecordID = "different-record"
				message.Data, err = cborx.Marshal(result)
				if err != nil {
					t.Fatal(err)
				}
			},
			want: "inconsistent record_id",
		},
	}

	for index, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := startSDKNATSFixtureWithoutWorker(t)
			client := openSDKNATSClient(t, fixture)
			signed := sdkNATSSignedClaim("tampered-" + string(rune('a'+index)))
			handle, err := client.PublishSignedClaim(context.Background(), signed)
			if err != nil {
				t.Fatalf("PublishSignedClaim() error = %v", err)
			}
			request, err := natsingress.NewRequest(signed)
			if err != nil {
				t.Fatal(err)
			}
			result, err := natsingress.NewAcceptedResult(request, acceptedSDKNATSOutcome())
			if err != nil {
				t.Fatal(err)
			}
			body, err := natsingress.EncodeResult(result)
			if err != nil {
				t.Fatal(err)
			}
			subject, err := natsResultSubject(fixture.cfg.ResultSubject, handle.MessageID)
			if err != nil {
				t.Fatal(err)
			}
			message := nats.NewMsg(subject)
			message.Header.Set(natsingress.HeaderContentType, natsingress.ContentType)
			message.Header.Set(natsingress.HeaderSchemaVersion, natsingress.SchemaResult)
			message.Header.Set(natsingress.HeaderMessageID, handle.MessageID)
			message.Data = body
			tc.mutate(message, request)
			if _, err := fixture.runtime.JetStream().PublishMsg(context.Background(), message, jetstream.WithExpectStream(fixture.cfg.ResultStream)); err != nil {
				t.Fatalf("PublishMsg(tampered result) error = %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err = client.WaitResult(ctx, handle)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("WaitResult() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNATSIngressClientRejectsSubmissionHandleTampering(t *testing.T) {
	fixture := startSDKNATSFixtureWithoutWorker(t)
	client := openSDKNATSClient(t, fixture)
	handle, err := client.PublishSignedClaim(context.Background(), sdkNATSSignedClaim("handle"))
	if err != nil {
		t.Fatal(err)
	}
	handle.MessageID = "caller-controlled"
	_, err = client.WaitResult(context.Background(), handle)
	if err == nil || !strings.Contains(err.Error(), "does not match signed claim") {
		t.Fatalf("WaitResult() error = %v", err)
	}
}

func TestNewNATSIngressClientDoesNotProvisionMissingTopology(t *testing.T) {
	s := startSDKNATSServer(t)
	cfg := sdkNATSClientConfig(s.ClientURL(), sdkNATSServerConfig(s.ClientURL()))
	client, err := NewNATSIngressClient(context.Background(), cfg)
	if err == nil || client != nil || !strings.Contains(err.Error(), "stream not found") {
		t.Fatalf("NewNATSIngressClient() client=%#v error=%v", client, err)
	}

	conn, err := nats.Connect(s.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Stream(context.Background(), cfg.Stream); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("ingress stream lookup error = %v", err)
	}
	if _, err := js.Stream(context.Background(), cfg.ResultStream); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("result stream lookup error = %v", err)
	}
}

func TestNewNATSIngressClientDoesNotCreateConsumers(t *testing.T) {
	fixture := startSDKNATSFixtureWithoutWorker(t)
	before, err := fixture.runtime.Stream().Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	client := openSDKNATSClient(t, fixture)
	after, err := fixture.runtime.Stream().Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if after.State.Consumers != before.State.Consumers {
		t.Fatalf("consumer count changed from %d to %d", before.State.Consumers, after.State.Consumers)
	}
	if client.Endpoint() == "" {
		t.Fatal("NATS client endpoint is empty")
	}
}

func TestNewNATSIngressClientFailsWhenBrokerIsUnavailable(t *testing.T) {
	cfg := DefaultNATSIngressConfig()
	cfg.URLs = []string{"nats://127.0.0.1:1"}
	cfg.ConnectTimeout = 50 * time.Millisecond
	client, err := NewNATSIngressClient(context.Background(), cfg)
	if err == nil || client != nil || !strings.Contains(err.Error(), "connect NATS ingress") {
		t.Fatalf("NewNATSIngressClient() client=%#v error=%v", client, err)
	}
}

func TestNewNATSIngressClientRejectsMutableResultStream(t *testing.T) {
	s := startSDKNATSServer(t)
	serverCfg := sdkNATSServerConfig(s.ClientURL())
	conn, err := nats.Connect(s.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.CreateStream(context.Background(), jetstream.StreamConfig{
		Name:       serverCfg.Stream,
		Subjects:   []string{serverCfg.Subject},
		MaxMsgSize: natsingress.MaxMessageBytes,
		Storage:    jetstream.MemoryStorage,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := js.CreateStream(context.Background(), jetstream.StreamConfig{
		Name:              serverCfg.ResultStream,
		Subjects:          []string{serverCfg.ResultSubject},
		MaxMsgsPerSubject: 2,
		MaxMsgSize:        natsingress.MaxMessageBytes,
		Storage:           jetstream.MemoryStorage,
	}); err != nil {
		t.Fatal(err)
	}

	client, err := NewNATSIngressClient(context.Background(), sdkNATSClientConfig(s.ClientURL(), serverCfg))
	if err == nil || client != nil || !strings.Contains(err.Error(), "one immutable result") {
		t.Fatalf("NewNATSIngressClient() client=%#v error=%v", client, err)
	}
}

func TestNATSIngressClientCloseIsIdempotent(t *testing.T) {
	fixture := startSDKNATSFixtureWithoutWorker(t)
	client := openSDKNATSClientWithoutCleanup(t, fixture)
	if err := client.Close(); err != nil {
		t.Fatalf("Close(first) error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close(second) error = %v", err)
	}
	if !client.conn.IsClosed() {
		t.Fatal("NATS connection is not closed")
	}
	if _, err := client.PublishSignedClaim(context.Background(), sdkNATSSignedClaim("closed")); err == nil {
		t.Fatal("PublishSignedClaim() after Close error = nil")
	}
}

func TestNATSIngressConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*NATSIngressConfig)
		want   string
	}{
		{name: "missing URLs", mutate: func(cfg *NATSIngressConfig) { cfg.URLs = nil }, want: "URLs are required"},
		{name: "URL credentials", mutate: func(cfg *NATSIngressConfig) { cfg.URLs = []string{"nats://user:pass@127.0.0.1:4222"} }, want: "must not contain credentials"},
		{name: "URL query", mutate: func(cfg *NATSIngressConfig) { cfg.URLs = []string{"nats://127.0.0.1:4222?token=secret"} }, want: "query parameters"},
		{name: "wildcard ingress", mutate: func(cfg *NATSIngressConfig) { cfg.Subject = "trustdb.claims.*" }, want: "concrete subject"},
		{name: "invalid result pattern", mutate: func(cfg *NATSIngressConfig) { cfg.ResultSubject = "trustdb.results" }, want: "ending in .*"},
		{name: "same stream", mutate: func(cfg *NATSIngressConfig) { cfg.ResultStream = cfg.Stream }, want: "must be distinct"},
		{name: "negative connect timeout", mutate: func(cfg *NATSIngressConfig) { cfg.ConnectTimeout = -time.Second }, want: "ConnectTimeout"},
		{name: "negative drain timeout", mutate: func(cfg *NATSIngressConfig) { cfg.DrainTimeout = -time.Second }, want: "DrainTimeout"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultNATSIngressConfig()
			tc.mutate(&cfg)
			client, err := NewNATSIngressClient(context.Background(), cfg)
			if err == nil || client != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewNATSIngressClient() client=%#v error=%v, want %q", client, err, tc.want)
			}
		})
	}
}

func TestDecodeNATSSubmitResultRejectsWrongSubject(t *testing.T) {
	request, err := natsingress.NewRequest(sdkNATSSignedClaim("wrong-subject"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := natsingress.NewAcceptedResult(request, acceptedSDKNATSOutcome())
	if err != nil {
		t.Fatal(err)
	}
	body, err := natsingress.EncodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	header := nats.Header{}
	header.Set(natsingress.HeaderContentType, natsingress.ContentType)
	header.Set(natsingress.HeaderSchemaVersion, natsingress.SchemaResult)
	header.Set(natsingress.HeaderMessageID, request.MessageID)
	_, err = decodeNATSSubmitResult(
		"nats://example:4222",
		"trustdb.results.another",
		"trustdb.results."+request.MessageID,
		header,
		body,
		request,
	)
	if err == nil || !strings.Contains(err.Error(), "received subject") {
		t.Fatalf("decodeNATSSubmitResult() error = %v", err)
	}
}

type sdkNATSFixture struct {
	runtime *natsingress.Runtime
	cfg     trustconfig.NATS
}

func startSDKNATSFixture(t *testing.T, submitter submission.Submitter) sdkNATSFixture {
	t.Helper()
	fixture := startSDKNATSFixtureWithoutWorker(t)
	sink, err := natsingress.NewJetStreamOutcomeSink(fixture.runtime, fixture.cfg)
	if err != nil {
		t.Fatalf("NewJetStreamOutcomeSink() error = %v", err)
	}
	worker, err := natsingress.NewWorker(fixture.runtime.Consumer(), submitter, sink, fixture.cfg)
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("Worker.Run() error = %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("NATS worker did not stop")
		}
	})
	return fixture
}

func startSDKNATSFixtureWithoutWorker(t *testing.T) sdkNATSFixture {
	t.Helper()
	s := startSDKNATSServer(t)
	cfg := sdkNATSServerConfig(s.ClientURL())
	runtime, err := natsingress.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("natsingress.Open() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("Runtime.Close() error = %v", err)
		}
	})
	return sdkNATSFixture{runtime: runtime, cfg: cfg}
}

func openSDKNATSClient(t *testing.T, fixture sdkNATSFixture) *NATSIngressClient {
	t.Helper()
	client := openSDKNATSClientWithoutCleanup(t, fixture)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("NATSIngressClient.Close() error = %v", err)
		}
	})
	return client
}

func openSDKNATSClientWithoutCleanup(t *testing.T, fixture sdkNATSFixture) *NATSIngressClient {
	t.Helper()
	client, err := NewNATSIngressClient(context.Background(), sdkNATSClientConfig(fixture.runtime.Conn().ConnectedUrl(), fixture.cfg))
	if err != nil {
		t.Fatalf("NewNATSIngressClient() error = %v", err)
	}
	return client
}

func sdkNATSClientConfig(url string, serverCfg trustconfig.NATS) NATSIngressConfig {
	return NATSIngressConfig{
		URLs:           []string{url},
		Stream:         serverCfg.Stream,
		Subject:        serverCfg.Subject,
		ResultStream:   serverCfg.ResultStream,
		ResultSubject:  serverCfg.ResultSubject,
		ConnectTimeout: time.Second,
		DrainTimeout:   time.Second,
	}
}

func sdkNATSServerConfig(url string) trustconfig.NATS {
	cfg := trustconfig.Default().NATS
	cfg.Enabled = true
	cfg.URLs = []string{url}
	cfg.Stream = "TRUSTDB_SDK_INGRESS_TEST"
	cfg.Subject = "trustdb.sdk.ingress.test.claims"
	cfg.Durable = "trustdb-sdk-ingress-test"
	cfg.ResultStream = "TRUSTDB_SDK_RESULTS_TEST"
	cfg.ResultSubject = "trustdb.sdk.ingress.test.results.*"
	cfg.DLQStream = "TRUSTDB_SDK_DLQ_TEST"
	cfg.DLQSubject = "trustdb.sdk.ingress.test.dlq.*"
	cfg.StreamStorage = "memory"
	cfg.StreamMaxBytes = 4 << 20
	cfg.ResultMaxBytes = 4 << 20
	cfg.DLQMaxBytes = 4 << 20
	cfg.Workers = 1
	cfg.FetchBatch = 4
	cfg.FetchWait = "1s"
	cfg.AckWait = "500ms"
	cfg.NakDelay = "50ms"
	cfg.ResultRetryWait = "20ms"
	cfg.MaxAckPending = 4
	cfg.ConnectTimeout = "1s"
	cfg.ReconnectWait = "20ms"
	cfg.MaxReconnects = 0
	cfg.DrainTimeout = "1s"
	return cfg
}

func startSDKNATSServer(t *testing.T) *server.Server {
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

type sdkNATSSubmitterFunc func(context.Context, model.SignedClaim) (submission.Outcome, error)

func (function sdkNATSSubmitterFunc) Submit(ctx context.Context, signed model.SignedClaim) (submission.Outcome, error) {
	return function(ctx, signed)
}

func acceptedSDKNATSSubmitter() submission.Submitter {
	return sdkNATSSubmitterFunc(func(context.Context, model.SignedClaim) (submission.Outcome, error) {
		return acceptedSDKNATSOutcome(), nil
	})
}

func acceptedSDKNATSOutcome() submission.Outcome {
	const recordID = "tr1sdk-nats-ingress"
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

func sdkNATSSignedClaim(idempotencyKey string) SignedClaim {
	return SignedClaim{
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
	}
}

func waitForSDKNATSStoredResult(t *testing.T, stream jetstream.Stream, subject string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := stream.GetLastMsgForSubject(context.Background(), subject); err == nil {
			return
		} else if !errors.Is(err, jetstream.ErrMsgNotFound) {
			t.Fatalf("GetLastMsgForSubject() error = %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("result subject %s was not stored", subject)
}

func waitForSDKNATSSubscriptions(t *testing.T, client *NATSIngressClient, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if client.conn.NumSubscriptions() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("NATS subscriptions = %d, want at least %d", client.conn.NumSubscriptions(), want)
}
