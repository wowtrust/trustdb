package natsingress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/wowtrust/trustdb/internal/config"
)

func TestOpenDisabledIsStrictNoOp(t *testing.T) {
	t.Parallel()

	cfg := config.Default().NATS
	cfg.URLs = []string{"nats://127.0.0.1:1"}
	runtime, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if runtime != nil {
		t.Fatalf("Open() runtime = %#v, want nil", runtime)
	}
}

func TestOpenHonorsCanceledContextBeforeDial(t *testing.T) {
	t.Parallel()

	cfg := config.Default().NATS
	cfg.Enabled = true
	cfg.URLs = []string{"nats://127.0.0.1:1"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Open(ctx, cfg)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Open() error = %v, want context.Canceled", err)
	}
}

func TestConnectionOptionsMapLifecycleSettings(t *testing.T) {
	t.Parallel()

	cfg := config.Default().NATS
	cfg.Enabled = true
	cfg.ConnectTimeout = "3s"
	cfg.ReconnectWait = "750ms"
	cfg.MaxReconnects = 17
	cfg.DrainTimeout = "9s"
	topology, err := parseTopology(cfg)
	if err != nil {
		t.Fatalf("parseTopology() error = %v", err)
	}
	options, err := connectionOptions(cfg, topology)
	if err != nil {
		t.Fatalf("connectionOptions() error = %v", err)
	}
	var actual nats.Options
	for _, option := range options {
		if err := option(&actual); err != nil {
			t.Fatalf("apply NATS option: %v", err)
		}
	}
	if actual.Name != connectionName || actual.Timeout != 3*time.Second || actual.ReconnectWait != 750*time.Millisecond || actual.MaxReconnect != 17 || actual.DrainTimeout != 9*time.Second {
		t.Fatalf("NATS lifecycle options = %+v", actual)
	}
}

func TestOpenProvisionsBoundedJetStreamTopology(t *testing.T) {
	t.Parallel()

	s := startTestServer(t, nil)
	cfg := testNATSConfig(s.ClientURL())
	runtime, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { closeRuntime(t, runtime) })

	topology, err := parseTopology(cfg)
	if err != nil {
		t.Fatalf("parseTopology() error = %v", err)
	}
	streamInfo, err := runtime.Stream().Info(context.Background())
	if err != nil {
		t.Fatalf("Stream.Info() error = %v", err)
	}
	if err := validateStreamConfig(streamInfo.Config, desiredStreamConfig(cfg, topology), "ingress"); err != nil {
		t.Fatal(err)
	}
	consumerInfo, err := runtime.Consumer().Info(context.Background())
	if err != nil {
		t.Fatalf("Consumer.Info() error = %v", err)
	}
	if err := validateConsumerConfig(consumerInfo.Config, desiredConsumerConfig(cfg, topology)); err != nil {
		t.Fatal(err)
	}
	resultInfo, err := runtime.ResultStream().Info(context.Background())
	if err != nil {
		t.Fatalf("ResultStream.Info() error = %v", err)
	}
	if err := validateStreamConfig(resultInfo.Config, desiredResultStreamConfig(cfg, topology), "result"); err != nil {
		t.Fatal(err)
	}
	deadLetterInfo, err := runtime.DeadLetterStream().Info(context.Background())
	if err != nil {
		t.Fatalf("DeadLetterStream.Info() error = %v", err)
	}
	if err := validateStreamConfig(deadLetterInfo.Config, desiredDeadLetterStreamConfig(cfg, topology), "dead-letter"); err != nil {
		t.Fatal(err)
	}
	if resultInfo.Config.Retention != jetstream.LimitsPolicy || resultInfo.Config.Discard != jetstream.DiscardNew || !resultInfo.Config.DiscardNewPerSubject || resultInfo.Config.MaxMsgsPerSubject != 1 {
		t.Fatalf("result stream is not immutable and bounded: %+v", resultInfo.Config)
	}
	if deadLetterInfo.Config.Retention != jetstream.LimitsPolicy || deadLetterInfo.Config.Discard != jetstream.DiscardNew || !deadLetterInfo.Config.DiscardNewPerSubject || deadLetterInfo.Config.MaxMsgsPerSubject != 1 {
		t.Fatalf("dead-letter stream is not immutable and bounded: %+v", deadLetterInfo.Config)
	}

	if _, err := runtime.JetStream().Publish(context.Background(), cfg.Subject, make([]byte, 800)); err != nil {
		t.Fatalf("first publish error = %v", err)
	}
	if _, err := runtime.JetStream().Publish(context.Background(), cfg.Subject, make([]byte, 800)); err == nil {
		t.Fatal("second publish succeeded after bounded stream reached max_bytes")
	}
}

func TestOpenBindsPreprovisionedTopology(t *testing.T) {
	t.Parallel()

	s := startTestServer(t, nil)
	cfg := testNATSConfig(s.ClientURL())
	first, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	closeRuntime(t, first)

	cfg.Provision = false
	second, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Open() with preprovisioned resources error = %v", err)
	}
	closeRuntime(t, second)
}

func TestOpenDoesNotProvisionWhenDisabledByConfig(t *testing.T) {
	t.Parallel()

	s := startTestServer(t, nil)
	cfg := testNATSConfig(s.ClientURL())
	cfg.Provision = false

	_, err := Open(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "stream") || !strings.Contains(err.Error(), "provision is false") {
		t.Fatalf("Open() error = %v, want missing stream error", err)
	}
}

func TestOpenRejectsIncompatibleExistingStreamWithoutUpdatingIt(t *testing.T) {
	t.Parallel()

	s := startTestServer(t, nil)
	cfg := testNATSConfig(s.ClientURL())
	conn, js := connectTestJetStream(t, s.ClientURL())
	t.Cleanup(conn.Close)

	topology, err := parseTopology(cfg)
	if err != nil {
		t.Fatalf("parseTopology() error = %v", err)
	}
	bad := desiredStreamConfig(cfg, topology)
	bad.Retention = jetstream.LimitsPolicy
	stream, err := js.CreateStream(context.Background(), bad)
	if err != nil {
		t.Fatalf("CreateStream() error = %v", err)
	}

	_, err = Open(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "incompatible configuration") {
		t.Fatalf("Open() error = %v, want incompatible stream error", err)
	}
	info, err := stream.Info(context.Background())
	if err != nil {
		t.Fatalf("Stream.Info() error = %v", err)
	}
	if info.Config.Retention != jetstream.LimitsPolicy {
		t.Fatalf("stream retention = %v, want unchanged LimitsPolicy", info.Config.Retention)
	}
}

func TestOpenRejectsIncompatibleExistingConsumerWithoutUpdatingIt(t *testing.T) {
	t.Parallel()

	s := startTestServer(t, nil)
	cfg := testNATSConfig(s.ClientURL())
	conn, js := connectTestJetStream(t, s.ClientURL())
	t.Cleanup(conn.Close)

	topology, err := parseTopology(cfg)
	if err != nil {
		t.Fatalf("parseTopology() error = %v", err)
	}
	stream, err := js.CreateStream(context.Background(), desiredStreamConfig(cfg, topology))
	if err != nil {
		t.Fatalf("CreateStream() error = %v", err)
	}
	bad := desiredConsumerConfig(cfg, topology)
	bad.AckWait += time.Second
	consumer, err := stream.CreateConsumer(context.Background(), bad)
	if err != nil {
		t.Fatalf("CreateConsumer() error = %v", err)
	}

	_, err = Open(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "incompatible configuration") {
		t.Fatalf("Open() error = %v, want incompatible consumer error", err)
	}
	info, err := consumer.Info(context.Background())
	if err != nil {
		t.Fatalf("Consumer.Info() error = %v", err)
	}
	if info.Config.AckWait != bad.AckWait {
		t.Fatalf("consumer ack wait = %v, want unchanged %v", info.Config.AckWait, bad.AckWait)
	}
}

func TestOpenRejectsIncompatibleOutcomeStreamWithoutUpdatingIt(t *testing.T) {
	t.Parallel()

	s := startTestServer(t, nil)
	cfg := testNATSConfig(s.ClientURL())
	conn, js := connectTestJetStream(t, s.ClientURL())
	t.Cleanup(conn.Close)

	topology, err := parseTopology(cfg)
	if err != nil {
		t.Fatalf("parseTopology() error = %v", err)
	}
	ingress, err := js.CreateStream(context.Background(), desiredStreamConfig(cfg, topology))
	if err != nil {
		t.Fatalf("CreateStream(ingress) error = %v", err)
	}
	if _, err := ingress.CreateConsumer(context.Background(), desiredConsumerConfig(cfg, topology)); err != nil {
		t.Fatalf("CreateConsumer() error = %v", err)
	}
	bad := desiredResultStreamConfig(cfg, topology)
	bad.MaxBytes++
	resultStream, err := js.CreateStream(context.Background(), bad)
	if err != nil {
		t.Fatalf("CreateStream(result) error = %v", err)
	}

	_, err = Open(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "NATS result stream") || !strings.Contains(err.Error(), "incompatible configuration") {
		t.Fatalf("Open() error = %v, want incompatible result stream error", err)
	}
	info, err := resultStream.Info(context.Background())
	if err != nil {
		t.Fatalf("ResultStream.Info() error = %v", err)
	}
	if info.Config.MaxBytes != bad.MaxBytes {
		t.Fatalf("result stream max bytes = %d, want unchanged %d", info.Config.MaxBytes, bad.MaxBytes)
	}
	if _, err := js.Stream(context.Background(), cfg.DLQStream); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("DLQ lookup error = %v, want no mutation after incompatible result stream", err)
	}
}

func TestOpenMapsAuthentication(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		server    *server.Options
		configure func(*config.NATS)
	}{
		{
			name:   "username password",
			server: &server.Options{Username: "trustdb", Password: "secret"},
			configure: func(cfg *config.NATS) {
				cfg.Username = "trustdb"
				cfg.Password = "secret"
			},
		},
		{
			name:   "token",
			server: &server.Options{Authorization: "token-secret"},
			configure: func(cfg *config.NATS) {
				cfg.Token = "token-secret"
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := startTestServer(t, tc.server)
			cfg := testNATSConfig(s.ClientURL())
			tc.configure(&cfg)
			runtime, err := Open(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			closeRuntime(t, runtime)
		})
	}
}

func TestOpenMapsMutualTLS(t *testing.T) {
	t.Parallel()

	certificates := writeTestCertificates(t)
	s := startTestServer(t, &server.Options{
		TLS:       true,
		TLSVerify: true,
		TLSCert:   certificates.serverCert,
		TLSKey:    certificates.serverKey,
		TLSCaCert: certificates.caCert,
	})
	cfg := testNATSConfig(s.ClientURL())
	cfg.TLS = config.NATSTLS{
		Enabled:    true,
		CAFile:     certificates.caCert,
		CertFile:   certificates.clientCert,
		KeyFile:    certificates.clientKey,
		ServerName: "localhost",
	}

	runtime, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	closeRuntime(t, runtime)
}

func TestBuildTLSConfigRejectsInvalidCA(t *testing.T) {
	t.Parallel()

	path := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write invalid CA: %v", err)
	}
	_, err := buildTLSConfig(config.NATSTLS{Enabled: true, CAFile: path})
	if err == nil || !strings.Contains(err.Error(), "no valid certificates") {
		t.Fatalf("buildTLSConfig() error = %v", err)
	}
}

func TestCloseHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	s := startTestServer(t, nil)
	runtime, err := Open(context.Background(), testNATSConfig(s.ClientURL()))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = runtime.Close(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Close() error = %v", err)
	}
	if !runtime.Conn().IsClosed() {
		t.Fatal("NATS connection remains open after Close")
	}
}

func TestCloseAlreadyClosedConnectionIsIdempotent(t *testing.T) {
	t.Parallel()

	s := startTestServer(t, nil)
	cfg := testNATSConfig(s.ClientURL())
	runtime, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	runtime.Conn().Close()
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("Runtime.Close() error = %v", err)
	}
}

func startTestServer(t *testing.T, custom *server.Options) *server.Server {
	t.Helper()
	opts := &server.Options{
		Host:      "127.0.0.1",
		Port:      -1,
		JetStream: true,
		StoreDir:  t.TempDir(),
		NoLog:     true,
		NoSigs:    true,
	}
	if custom != nil {
		opts.Username = custom.Username
		opts.Password = custom.Password
		opts.Authorization = custom.Authorization
		opts.TLS = custom.TLS
		opts.TLSVerify = custom.TLSVerify
		opts.TLSCert = custom.TLSCert
		opts.TLSKey = custom.TLSKey
		opts.TLSCaCert = custom.TLSCaCert
		if custom.TLS {
			tlsConfig, err := server.GenTLSConfig(&server.TLSConfigOpts{
				CertFile: custom.TLSCert,
				KeyFile:  custom.TLSKey,
				CaFile:   custom.TLSCaCert,
				Verify:   custom.TLSVerify,
			})
			if err != nil {
				t.Fatalf("GenTLSConfig() error = %v", err)
			}
			opts.TLSConfig = tlsConfig
		}
	}
	s, err := server.NewServer(opts)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		s.Shutdown()
		t.Fatal("embedded NATS server did not become ready")
	}
	t.Cleanup(func() {
		s.Shutdown()
		s.WaitForShutdown()
	})
	return s
}

type testCertificates struct {
	caCert     string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string
}

func writeTestCertificates(t *testing.T) testCertificates {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	serial := int64(1)
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate test key: %v", err)
		}
		return key
	}
	writeKey := func(name string, key *ecdsa.PrivateKey) string {
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatalf("marshal test key: %v", err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			t.Fatalf("write test key: %v", err)
		}
		return path
	}
	writeCert := func(name string, template, parent *x509.Certificate, publicKey *ecdsa.PublicKey, signer *ecdsa.PrivateKey) string {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
		if err != nil {
			t.Fatalf("create test certificate: %v", err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatalf("write test certificate: %v", err)
		}
		return path
	}
	nextSerial := func() *big.Int {
		value := big.NewInt(serial)
		serial++
		return value
	}

	caKey := newKey()
	caTemplate := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: "TrustDB test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caCert := writeCert("ca.pem", caTemplate, caTemplate, &caKey.PublicKey, caKey)

	serverKey := newKey()
	serverTemplate := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverCert := writeCert("server.pem", serverTemplate, caTemplate, &serverKey.PublicKey, caKey)

	clientKey := newKey()
	clientTemplate := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: "trustdb-client"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCert := writeCert("client.pem", clientTemplate, caTemplate, &clientKey.PublicKey, caKey)

	return testCertificates{
		caCert:     caCert,
		serverCert: serverCert,
		serverKey:  writeKey("server-key.pem", serverKey),
		clientCert: clientCert,
		clientKey:  writeKey("client-key.pem", clientKey),
	}
}

func testNATSConfig(url string) config.NATS {
	cfg := config.Default().NATS
	cfg.Enabled = true
	cfg.URLs = []string{url}
	cfg.Stream = "TRUSTDB_INGRESS_TEST"
	cfg.Subject = "trustdb.ingress.test.claims"
	cfg.Durable = "trustdb-ingress-test"
	cfg.ResultStream = "TRUSTDB_INGRESS_RESULTS_TEST"
	cfg.ResultSubject = "trustdb.ingress.test.results.*"
	cfg.DLQStream = "TRUSTDB_INGRESS_DLQ_TEST"
	cfg.DLQSubject = "trustdb.ingress.test.dlq.*"
	cfg.StreamStorage = "memory"
	cfg.StreamMaxBytes = 1024
	cfg.ResultMaxBytes = 64 << 10
	cfg.DLQMaxBytes = 64 << 10
	cfg.ConnectTimeout = "1s"
	cfg.ReconnectWait = "50ms"
	cfg.MaxReconnects = 0
	cfg.DrainTimeout = "1s"
	return cfg
}

func connectTestJetStream(t *testing.T, url string) (*nats.Conn, jetstream.JetStream) {
	t.Helper()
	conn, err := nats.Connect(url, nats.Timeout(time.Second))
	if err != nil {
		t.Fatalf("nats.Connect() error = %v", err)
	}
	js, err := jetstream.New(conn)
	if err != nil {
		conn.Close()
		t.Fatalf("jetstream.New() error = %v", err)
	}
	return conn, js
}

func closeRuntime(t *testing.T, runtime *Runtime) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := runtime.Close(ctx); err != nil {
		t.Fatalf("Runtime.Close() error = %v", err)
	}
}
