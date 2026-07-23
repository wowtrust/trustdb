package natsingress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/wowtrust/trustdb/internal/config"
)

const connectionName = "trustdb-nats-ingress"

// Runtime owns the optional NATS connection and the validated JetStream
// ingress resources. Message consumption is intentionally implemented by a
// separate worker layer.
type Runtime struct {
	conn             *nats.Conn
	js               jetstream.JetStream
	stream           jetstream.Stream
	consumer         jetstream.Consumer
	resultStream     jetstream.Stream
	deadLetterStream jetstream.Stream

	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

// Open connects to NATS and creates or validates the configured JetStream
// resources. A disabled configuration is a strict no-op and returns nil.
func Open(ctx context.Context, cfg config.NATS) (*Runtime, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	topology, err := parseTopology(cfg)
	if err != nil {
		return nil, err
	}
	options, err := connectionOptions(cfg, topology)
	if err != nil {
		return nil, err
	}

	urls := make([]string, len(cfg.URLs))
	for i, raw := range cfg.URLs {
		urls[i] = strings.TrimSpace(raw)
	}
	conn, err := nats.Connect(strings.Join(urls, ","), options...)
	if err != nil {
		return nil, fmt.Errorf("connect NATS ingress: %w", err)
	}
	fail := func(err error) (*Runtime, error) {
		conn.Close()
		return nil, err
	}

	js, err := jetstream.New(conn)
	if err != nil {
		return fail(fmt.Errorf("create JetStream context: %w", err))
	}
	stream, err := ensureStream(ctx, js, cfg, topology)
	if err != nil {
		return fail(err)
	}
	consumer, err := ensureConsumer(ctx, stream, cfg, topology)
	if err != nil {
		return fail(err)
	}
	resultStream, err := ensureOutcomeStream(ctx, js, desiredResultStreamConfig(cfg, topology), cfg.Provision, "result")
	if err != nil {
		return fail(err)
	}
	deadLetterStream, err := ensureOutcomeStream(ctx, js, desiredDeadLetterStreamConfig(cfg, topology), cfg.Provision, "dead-letter")
	if err != nil {
		return fail(err)
	}

	return &Runtime{
		conn:             conn,
		js:               js,
		stream:           stream,
		consumer:         consumer,
		resultStream:     resultStream,
		deadLetterStream: deadLetterStream,
		closeDone:        make(chan struct{}),
	}, nil
}

func (r *Runtime) Conn() *nats.Conn {
	if r == nil {
		return nil
	}
	return r.conn
}

func (r *Runtime) JetStream() jetstream.JetStream {
	if r == nil {
		return nil
	}
	return r.js
}

func (r *Runtime) Stream() jetstream.Stream {
	if r == nil {
		return nil
	}
	return r.stream
}

func (r *Runtime) Consumer() jetstream.Consumer {
	if r == nil {
		return nil
	}
	return r.consumer
}

func (r *Runtime) ResultStream() jetstream.Stream {
	if r == nil {
		return nil
	}
	return r.resultStream
}

func (r *Runtime) DeadLetterStream() jetstream.Stream {
	if r == nil {
		return nil
	}
	return r.deadLetterStream
}

// Close drains buffered protocol traffic before closing the connection. The
// configured drain timeout bounds the NATS drain; ctx can shorten that bound.
func (r *Runtime) Close(ctx context.Context) error {
	if r == nil || r.conn == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		go func() {
			if !r.conn.IsClosed() {
				r.closeErr = r.conn.Drain()
				if errors.Is(r.closeErr, nats.ErrConnectionClosed) {
					r.closeErr = nil
				}
			}
			if !r.conn.IsClosed() {
				r.conn.Close()
			}
			close(r.closeDone)
		}()
	})

	select {
	case <-r.closeDone:
		return r.closeErr
	case <-ctx.Done():
		r.conn.Close()
		<-r.closeDone
		return ctx.Err()
	}
}

type topologyConfig struct {
	connectTimeout   time.Duration
	reconnectWait    time.Duration
	drainTimeout     time.Duration
	streamMaxAge     time.Duration
	resultMaxAge     time.Duration
	deadLetterMaxAge time.Duration
	duplicateWindow  time.Duration
	ackWait          time.Duration
	fetchWait        time.Duration
	storage          jetstream.StorageType
}

func parseTopology(cfg config.NATS) (topologyConfig, error) {
	parse := func(name, value string) (time.Duration, error) {
		d, err := time.ParseDuration(value)
		if err != nil {
			return 0, fmt.Errorf("parse %s: %w", name, err)
		}
		return d, nil
	}

	var result topologyConfig
	var err error
	if result.connectTimeout, err = parse("nats.connect_timeout", cfg.ConnectTimeout); err != nil {
		return topologyConfig{}, err
	}
	if result.reconnectWait, err = parse("nats.reconnect_wait", cfg.ReconnectWait); err != nil {
		return topologyConfig{}, err
	}
	if result.drainTimeout, err = parse("nats.drain_timeout", cfg.DrainTimeout); err != nil {
		return topologyConfig{}, err
	}
	if result.streamMaxAge, err = parse("nats.stream_max_age", cfg.StreamMaxAge); err != nil {
		return topologyConfig{}, err
	}
	if result.resultMaxAge, err = parse("nats.result_max_age", cfg.ResultMaxAge); err != nil {
		return topologyConfig{}, err
	}
	if result.deadLetterMaxAge, err = parse("nats.dlq_max_age", cfg.DLQMaxAge); err != nil {
		return topologyConfig{}, err
	}
	if result.duplicateWindow, err = parse("nats.duplicate_window", cfg.DuplicateWindow); err != nil {
		return topologyConfig{}, err
	}
	if result.ackWait, err = parse("nats.ack_wait", cfg.AckWait); err != nil {
		return topologyConfig{}, err
	}
	if result.fetchWait, err = parse("nats.fetch_wait", cfg.FetchWait); err != nil {
		return topologyConfig{}, err
	}

	switch strings.ToLower(strings.TrimSpace(cfg.StreamStorage)) {
	case "file":
		result.storage = jetstream.FileStorage
	case "memory":
		result.storage = jetstream.MemoryStorage
	default:
		return topologyConfig{}, fmt.Errorf("unsupported NATS stream storage %q", cfg.StreamStorage)
	}
	return result, nil
}

func connectionOptions(cfg config.NATS, topology topologyConfig) ([]nats.Option, error) {
	options := []nats.Option{
		nats.Name(connectionName),
		nats.Timeout(topology.connectTimeout),
		nats.ReconnectWait(topology.reconnectWait),
		nats.MaxReconnects(cfg.MaxReconnects),
		nats.DrainTimeout(topology.drainTimeout),
	}

	switch {
	case strings.TrimSpace(cfg.CredentialsFile) != "":
		options = append(options, nats.UserCredentials(cfg.CredentialsFile))
	case strings.TrimSpace(cfg.Username) != "":
		options = append(options, nats.UserInfo(cfg.Username, cfg.Password))
	case strings.TrimSpace(cfg.Token) != "":
		options = append(options, nats.Token(cfg.Token))
	}

	if tlsConfigured(cfg.TLS) {
		tlsConfig, err := buildTLSConfig(cfg.TLS)
		if err != nil {
			return nil, err
		}
		options = append(options, nats.Secure(tlsConfig))
	}
	return options, nil
}

func tlsConfigured(cfg config.NATSTLS) bool {
	return cfg.Enabled || cfg.CAFile != "" || cfg.CertFile != "" || cfg.KeyFile != "" || cfg.ServerName != "" || cfg.InsecureSkipVerify
}

func buildTLSConfig(cfg config.NATSTLS) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         strings.TrimSpace(cfg.ServerName),
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // Explicit compatibility opt-in from trusted configuration.
	}
	if strings.TrimSpace(cfg.CAFile) != "" {
		pemData, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read nats.tls.ca_file: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pemData) {
			return nil, errors.New("nats.tls.ca_file contains no valid certificates")
		}
		tlsConfig.RootCAs = roots
	}
	if strings.TrimSpace(cfg.CertFile) != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load NATS client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	return tlsConfig, nil
}

func desiredStreamConfig(cfg config.NATS, topology topologyConfig) jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:              cfg.Stream,
		Subjects:          []string{cfg.Subject},
		Retention:         jetstream.WorkQueuePolicy,
		MaxMsgs:           -1,
		MaxBytes:          cfg.StreamMaxBytes,
		MaxAge:            topology.streamMaxAge,
		MaxMsgsPerSubject: -1,
		MaxMsgSize:        MaxMessageBytes,
		Storage:           topology.storage,
		Discard:           jetstream.DiscardNew,
		Replicas:          cfg.StreamReplicas,
		Duplicates:        topology.duplicateWindow,
	}
}

func desiredResultStreamConfig(cfg config.NATS, topology topologyConfig) jetstream.StreamConfig {
	return desiredOutcomeStreamConfig(cfg.ResultStream, cfg.ResultSubject, cfg.ResultMaxBytes, topology.resultMaxAge, MaxMessageBytes, cfg, topology)
}

func desiredDeadLetterStreamConfig(cfg config.NATS, topology topologyConfig) jetstream.StreamConfig {
	return desiredOutcomeStreamConfig(cfg.DLQStream, cfg.DLQSubject, cfg.DLQMaxBytes, topology.deadLetterMaxAge, MaxDeadLetterBytes, cfg, topology)
}

func desiredOutcomeStreamConfig(name, subject string, maxBytes int64, maxAge time.Duration, maxMessageBytes int32, cfg config.NATS, topology topologyConfig) jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:                 name,
		Subjects:             []string{subject},
		Retention:            jetstream.LimitsPolicy,
		MaxMsgs:              -1,
		MaxBytes:             maxBytes,
		Discard:              jetstream.DiscardNew,
		DiscardNewPerSubject: true,
		MaxAge:               maxAge,
		MaxMsgsPerSubject:    1,
		MaxMsgSize:           maxMessageBytes,
		Storage:              topology.storage,
		Replicas:             cfg.StreamReplicas,
		Duplicates:           topology.duplicateWindow,
	}
}

func ensureStream(ctx context.Context, js jetstream.JetStream, cfg config.NATS, topology topologyConfig) (jetstream.Stream, error) {
	desired := desiredStreamConfig(cfg, topology)
	return ensureConfiguredStream(ctx, js, desired, cfg.Provision, "ingress")
}

func ensureOutcomeStream(ctx context.Context, js jetstream.JetStream, desired jetstream.StreamConfig, provision bool, kind string) (jetstream.Stream, error) {
	return ensureConfiguredStream(ctx, js, desired, provision, kind)
}

func ensureConfiguredStream(ctx context.Context, js jetstream.JetStream, desired jetstream.StreamConfig, provision bool, kind string) (jetstream.Stream, error) {
	stream, err := js.Stream(ctx, desired.Name)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		if !provision {
			return nil, fmt.Errorf("NATS %s stream %q is missing and nats.provision is false", kind, desired.Name)
		}
		stream, err = js.CreateStream(ctx, desired)
	}
	if err != nil {
		return nil, fmt.Errorf("open NATS %s stream %q: %w", kind, desired.Name, err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("inspect NATS %s stream %q: %w", kind, desired.Name, err)
	}
	if err := validateStreamConfig(info.Config, desired, kind); err != nil {
		return nil, err
	}
	return stream, nil
}

func validateStreamConfig(actual, desired jetstream.StreamConfig, kind string) error {
	var mismatches []string
	if actual.Name != desired.Name {
		mismatches = append(mismatches, fmt.Sprintf("name=%q want %q", actual.Name, desired.Name))
	}
	if !slices.Equal(actual.Subjects, desired.Subjects) {
		mismatches = append(mismatches, fmt.Sprintf("subjects=%v want %v", actual.Subjects, desired.Subjects))
	}
	if actual.Retention != desired.Retention {
		mismatches = append(mismatches, fmt.Sprintf("retention=%v want %v", actual.Retention, desired.Retention))
	}
	if actual.Discard != desired.Discard {
		mismatches = append(mismatches, fmt.Sprintf("discard=%v want %v", actual.Discard, desired.Discard))
	}
	if actual.DiscardNewPerSubject != desired.DiscardNewPerSubject {
		mismatches = append(mismatches, fmt.Sprintf("discard_new_per_subject=%t want %t", actual.DiscardNewPerSubject, desired.DiscardNewPerSubject))
	}
	if actual.MaxMsgs != desired.MaxMsgs {
		mismatches = append(mismatches, fmt.Sprintf("max_msgs=%d want %d", actual.MaxMsgs, desired.MaxMsgs))
	}
	if actual.MaxBytes != desired.MaxBytes {
		mismatches = append(mismatches, fmt.Sprintf("max_bytes=%d want %d", actual.MaxBytes, desired.MaxBytes))
	}
	if actual.MaxAge != desired.MaxAge {
		mismatches = append(mismatches, fmt.Sprintf("max_age=%s want %s", actual.MaxAge, desired.MaxAge))
	}
	if actual.MaxMsgsPerSubject != desired.MaxMsgsPerSubject {
		mismatches = append(mismatches, fmt.Sprintf("max_msgs_per_subject=%d want %d", actual.MaxMsgsPerSubject, desired.MaxMsgsPerSubject))
	}
	if actual.MaxMsgSize != desired.MaxMsgSize {
		mismatches = append(mismatches, fmt.Sprintf("max_msg_size=%d want %d", actual.MaxMsgSize, desired.MaxMsgSize))
	}
	if actual.Storage != desired.Storage {
		mismatches = append(mismatches, fmt.Sprintf("storage=%v want %v", actual.Storage, desired.Storage))
	}
	if actual.Replicas != desired.Replicas {
		mismatches = append(mismatches, fmt.Sprintf("replicas=%d want %d", actual.Replicas, desired.Replicas))
	}
	if actual.Duplicates != desired.Duplicates {
		mismatches = append(mismatches, fmt.Sprintf("duplicate_window=%s want %s", actual.Duplicates, desired.Duplicates))
	}
	if len(mismatches) != 0 {
		return fmt.Errorf("NATS %s stream %q has incompatible configuration: %s", kind, desired.Name, strings.Join(mismatches, "; "))
	}
	return nil
}

func desiredConsumerConfig(cfg config.NATS, topology topologyConfig) jetstream.ConsumerConfig {
	return jetstream.ConsumerConfig{
		Name:              cfg.Durable,
		Durable:           cfg.Durable,
		AckPolicy:         jetstream.AckExplicitPolicy,
		AckWait:           topology.ackWait,
		MaxDeliver:        cfg.MaxDeliver,
		FilterSubject:     cfg.Subject,
		ReplayPolicy:      jetstream.ReplayInstantPolicy,
		MaxAckPending:     cfg.MaxAckPending,
		MaxRequestBatch:   cfg.FetchBatch,
		MaxRequestExpires: topology.fetchWait,
	}
}

func ensureConsumer(ctx context.Context, stream jetstream.Stream, cfg config.NATS, topology topologyConfig) (jetstream.Consumer, error) {
	desired := desiredConsumerConfig(cfg, topology)
	consumer, err := stream.Consumer(ctx, cfg.Durable)
	if errors.Is(err, jetstream.ErrConsumerNotFound) {
		if !cfg.Provision {
			return nil, fmt.Errorf("NATS ingress consumer %q is missing and nats.provision is false", cfg.Durable)
		}
		consumer, err = stream.CreateConsumer(ctx, desired)
	}
	if err != nil {
		return nil, fmt.Errorf("open NATS ingress consumer %q: %w", cfg.Durable, err)
	}
	info, err := consumer.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("inspect NATS ingress consumer %q: %w", cfg.Durable, err)
	}
	if err := validateConsumerConfig(info.Config, desired); err != nil {
		return nil, err
	}
	return consumer, nil
}

func validateConsumerConfig(actual, desired jetstream.ConsumerConfig) error {
	var mismatches []string
	if actual.Name != desired.Name || actual.Durable != desired.Durable {
		mismatches = append(mismatches, fmt.Sprintf("name/durable=%q/%q want %q/%q", actual.Name, actual.Durable, desired.Name, desired.Durable))
	}
	if actual.AckPolicy != desired.AckPolicy {
		mismatches = append(mismatches, fmt.Sprintf("ack_policy=%v want %v", actual.AckPolicy, desired.AckPolicy))
	}
	if actual.AckWait != desired.AckWait {
		mismatches = append(mismatches, fmt.Sprintf("ack_wait=%s want %s", actual.AckWait, desired.AckWait))
	}
	if actual.MaxDeliver != desired.MaxDeliver {
		mismatches = append(mismatches, fmt.Sprintf("max_deliver=%d want %d", actual.MaxDeliver, desired.MaxDeliver))
	}
	if actual.FilterSubject != desired.FilterSubject {
		mismatches = append(mismatches, fmt.Sprintf("filter_subject=%q want %q", actual.FilterSubject, desired.FilterSubject))
	}
	if actual.ReplayPolicy != desired.ReplayPolicy {
		mismatches = append(mismatches, fmt.Sprintf("replay_policy=%v want %v", actual.ReplayPolicy, desired.ReplayPolicy))
	}
	if actual.MaxAckPending != desired.MaxAckPending {
		mismatches = append(mismatches, fmt.Sprintf("max_ack_pending=%d want %d", actual.MaxAckPending, desired.MaxAckPending))
	}
	if actual.MaxRequestBatch != desired.MaxRequestBatch {
		mismatches = append(mismatches, fmt.Sprintf("max_request_batch=%d want %d", actual.MaxRequestBatch, desired.MaxRequestBatch))
	}
	if actual.MaxRequestExpires != desired.MaxRequestExpires {
		mismatches = append(mismatches, fmt.Sprintf("max_request_expires=%s want %s", actual.MaxRequestExpires, desired.MaxRequestExpires))
	}
	if len(mismatches) != 0 {
		return fmt.Errorf("NATS ingress consumer %q has incompatible configuration: %s", desired.Name, strings.Join(mismatches, "; "))
	}
	return nil
}
