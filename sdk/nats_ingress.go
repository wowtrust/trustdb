package sdk

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/wowtrust/trustdb/internal/natsingress"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const (
	defaultNATSIngressConnectTimeout = 5 * time.Second
	defaultNATSIngressDrainTimeout   = 10 * time.Second
)

// NATSIngressConfig identifies existing TrustDB JetStream ingress and result
// resources. The SDK validates but never creates, updates, or deletes them.
// ConnectionOptions can carry authentication, TLS, proxy, and callback options;
// TrustDB still enforces the configured connection and drain time bounds.
type NATSIngressConfig struct {
	URLs              []string
	Stream            string
	Subject           string
	ResultStream      string
	ResultSubject     string
	ConnectTimeout    time.Duration
	DrainTimeout      time.Duration
	ConnectionOptions []nats.Option
}

// DefaultNATSIngressConfig matches the default optional NATS section emitted by
// TrustDB. Callers should normally replace URLs and connection options for the
// target deployment.
func DefaultNATSIngressConfig() NATSIngressConfig {
	return NATSIngressConfig{
		URLs:           []string{"nats://127.0.0.1:4222"},
		Stream:         "TRUSTDB_INGRESS",
		Subject:        "trustdb.ingress.v1.claims",
		ResultStream:   "TRUSTDB_INGRESS_RESULTS",
		ResultSubject:  "trustdb.ingress.v1.results.*",
		ConnectTimeout: defaultNATSIngressConnectTimeout,
		DrainTimeout:   defaultNATSIngressDrainTimeout,
	}
}

// NATSSubmission is a reusable handle for recovering the immutable result of
// one exact SignedClaim. WaitResult revalidates both fields before trusting it.
type NATSSubmission struct {
	MessageID   string
	SignedClaim SignedClaim
}

// NATSIngressClient publishes the existing TrustDB NATS v1 request contract
// and recovers its immutable result. It intentionally does not implement the
// read-oriented Transport interface used by Client.
type NATSIngressClient struct {
	endpoint      string
	stream        string
	subject       string
	resultPattern string
	resultStream  jetstream.Stream
	conn          *nats.Conn
	js            jetstream.JetStream
	drainTimeout  time.Duration

	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

// NewNATSIngressClient connects to NATS and fail-closed validates the existing
// ingress and immutable result streams without mutating broker topology.
func NewNATSIngressClient(ctx context.Context, cfg NATSIngressConfig) (*NATSIngressClient, error) {
	ctx = nonNilContext(ctx)
	normalized, endpoint, err := normalizeNATSIngressConfig(cfg)
	if err != nil {
		return nil, &Error{Op: "new NATS ingress client", URL: endpoint, Err: err}
	}
	if err := ctx.Err(); err != nil {
		return nil, &Error{Op: "connect NATS ingress", URL: endpoint, Err: err}
	}

	options := append([]nats.Option(nil), normalized.ConnectionOptions...)
	options = append(options,
		nats.Name("trustdb-go-sdk-nats-ingress"),
		nats.Timeout(normalized.ConnectTimeout),
		nats.DrainTimeout(normalized.DrainTimeout),
	)
	conn, err := connectNATSWithContext(ctx, strings.Join(normalized.URLs, ","), options...)
	if err != nil {
		return nil, &Error{Op: "connect NATS ingress", URL: endpoint, Err: err}
	}
	fail := func(op string, err error) (*NATSIngressClient, error) {
		conn.Close()
		return nil, &Error{Op: op, URL: endpoint, Err: err}
	}

	js, err := jetstream.New(conn)
	if err != nil {
		return fail("create NATS JetStream context", err)
	}
	ingressStream, err := js.Stream(ctx, normalized.Stream)
	if err != nil {
		return fail("open NATS ingress stream", err)
	}
	if err := validateNATSIngressStream(ctx, ingressStream, normalized.Subject); err != nil {
		return fail("validate NATS ingress stream", err)
	}
	resultStream, err := js.Stream(ctx, normalized.ResultStream)
	if err != nil {
		return fail("open NATS result stream", err)
	}
	if err := validateNATSResultStream(ctx, resultStream, normalized.ResultSubject); err != nil {
		return fail("validate NATS result stream", err)
	}

	return &NATSIngressClient{
		endpoint:      endpoint,
		stream:        normalized.Stream,
		subject:       normalized.Subject,
		resultPattern: normalized.ResultSubject,
		resultStream:  resultStream,
		conn:          conn,
		js:            js,
		drainTimeout:  normalized.DrainTimeout,
		closeDone:     make(chan struct{}),
	}, nil
}

func (c *NATSIngressClient) Endpoint() string {
	if c == nil {
		return ""
	}
	return c.endpoint
}

// PublishSignedClaim durably publishes one exact NATS v1 request and returns a
// handle that can recover the matching result after a caller or process retry.
func (c *NATSIngressClient) PublishSignedClaim(ctx context.Context, signed SignedClaim) (NATSSubmission, error) {
	ctx = nonNilContext(ctx)
	if c == nil || c.conn == nil || c.js == nil {
		return NATSSubmission{}, &Error{Op: "publish NATS claim", Message: "NATS ingress client is nil"}
	}
	if err := ctx.Err(); err != nil {
		return NATSSubmission{}, &Error{Op: "publish NATS claim", URL: c.endpoint, Err: err}
	}
	if c.conn.IsClosed() || c.conn.IsDraining() {
		return NATSSubmission{}, &Error{Op: "publish NATS claim", URL: c.endpoint, Err: nats.ErrConnectionClosed}
	}

	request, err := natsingress.NewRequest(signed)
	if err != nil {
		return NATSSubmission{}, &Error{Op: "build NATS claim request", URL: c.endpoint, Err: err}
	}
	body, err := natsingress.EncodeRequest(request)
	if err != nil {
		return NATSSubmission{}, &Error{Op: "encode NATS claim request", URL: c.endpoint, Err: err}
	}
	message := nats.NewMsg(c.subject)
	message.Header.Set(natsingress.HeaderContentType, natsingress.ContentType)
	message.Header.Set(natsingress.HeaderSchemaVersion, natsingress.SchemaRequest)
	message.Header.Set(natsingress.HeaderMessageID, request.MessageID)
	message.Data = body

	ack, err := c.js.PublishMsg(
		ctx,
		message,
		jetstream.WithExpectStream(c.stream),
		jetstream.WithMsgID(request.MessageID),
	)
	if err != nil {
		return NATSSubmission{}, &Error{Op: "publish NATS claim", URL: c.endpoint, Err: err}
	}
	if ack == nil {
		return NATSSubmission{}, &Error{Op: "publish NATS claim", URL: c.endpoint, Message: "JetStream returned no publish acknowledgement"}
	}
	if ack.Stream != c.stream {
		return NATSSubmission{}, &Error{
			Op:      "publish NATS claim",
			URL:     c.endpoint,
			Message: fmt.Sprintf("JetStream acknowledged stream %q, want %q", ack.Stream, c.stream),
		}
	}
	return NATSSubmission{MessageID: request.MessageID, SignedClaim: signed}, nil
}

// WaitResult subscribes before reading the durable result snapshot. This order
// covers both possible races: a stored result is recovered immediately, while
// a result committed during or after the lookup is delivered to the live
// subscription without polling.
func (c *NATSIngressClient) WaitResult(ctx context.Context, submission NATSSubmission) (SubmitResult, error) {
	ctx = nonNilContext(ctx)
	request, err := requestForNATSSubmission(submission)
	if err != nil {
		return SubmitResult{}, &Error{Op: "validate NATS submission", Err: err}
	}
	if c == nil || c.conn == nil || c.resultStream == nil {
		return SubmitResult{}, &Error{Op: "wait for NATS result", Message: "NATS ingress client is nil"}
	}
	if err := ctx.Err(); err != nil {
		return SubmitResult{}, &Error{Op: "wait for NATS result", URL: c.endpoint, Err: err}
	}
	if c.conn.IsClosed() {
		return SubmitResult{}, &Error{Op: "wait for NATS result", URL: c.endpoint, Err: nats.ErrConnectionClosed}
	}

	resultSubject, err := natsResultSubject(c.resultPattern, request.MessageID)
	if err != nil {
		return SubmitResult{}, &Error{Op: "build NATS result subject", URL: c.endpoint, Err: err}
	}
	sub, err := c.conn.SubscribeSync(resultSubject)
	if err != nil {
		return SubmitResult{}, &Error{Op: "subscribe to NATS result", URL: c.endpoint, Err: err}
	}
	defer sub.Unsubscribe()
	if err := sub.AutoUnsubscribe(1); err != nil {
		return SubmitResult{}, &Error{Op: "bound NATS result subscription", URL: c.endpoint, Err: err}
	}
	if err := flushNATSSubscription(ctx, c.conn, c.drainTimeout); err != nil {
		return SubmitResult{}, &Error{Op: "activate NATS result subscription", URL: c.endpoint, Err: err}
	}

	stored, err := c.resultStream.GetLastMsgForSubject(ctx, resultSubject)
	if err == nil {
		return decodeNATSSubmitResult(c.endpoint, stored.Subject, resultSubject, stored.Header, stored.Data, request)
	}
	if !errors.Is(err, jetstream.ErrMsgNotFound) {
		return SubmitResult{}, &Error{Op: "read durable NATS result", URL: c.endpoint, Err: err}
	}

	message, err := sub.NextMsgWithContext(ctx)
	if err != nil {
		return SubmitResult{}, &Error{Op: "wait for NATS result", URL: c.endpoint, Err: err}
	}
	return decodeNATSSubmitResult(c.endpoint, message.Subject, resultSubject, message.Header, message.Data, request)
}

// SubmitSignedClaim is the synchronous publish-and-wait convenience path.
func (c *NATSIngressClient) SubmitSignedClaim(ctx context.Context, signed SignedClaim) (SubmitResult, error) {
	submission, err := c.PublishSignedClaim(ctx, signed)
	if err != nil {
		return SubmitResult{}, err
	}
	return c.WaitResult(ctx, submission)
}

// Close starts a bounded NATS drain and is safe to call repeatedly.
func (c *NATSIngressClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		go c.close()
	})
	<-c.closeDone
	return c.closeErr
}

func (c *NATSIngressClient) close() {
	defer close(c.closeDone)
	if c.conn.IsClosed() {
		return
	}
	closed := c.conn.StatusChanged(nats.CLOSED)
	defer c.conn.RemoveStatusListener(closed)
	if err := c.conn.Drain(); err != nil {
		if errors.Is(err, nats.ErrConnectionClosed) {
			return
		}
		c.closeErr = &Error{Op: "drain NATS ingress client", URL: c.endpoint, Err: err}
		return
	}

	timer := time.NewTimer(c.drainTimeout)
	defer timer.Stop()
	select {
	case <-closed:
		if err := c.conn.LastError(); errors.Is(err, nats.ErrDrainTimeout) {
			c.closeErr = &Error{Op: "drain NATS ingress client", URL: c.endpoint, Err: err}
		}
	case <-timer.C:
		c.conn.Close()
		c.closeErr = &Error{Op: "drain NATS ingress client", URL: c.endpoint, Err: context.DeadlineExceeded}
	}
}

func normalizeNATSIngressConfig(cfg NATSIngressConfig) (NATSIngressConfig, string, error) {
	result := cfg
	result.URLs = append([]string(nil), cfg.URLs...)
	result.ConnectionOptions = append([]nats.Option(nil), cfg.ConnectionOptions...)
	for i := range result.URLs {
		result.URLs[i] = strings.TrimSpace(result.URLs[i])
	}
	result.Stream = strings.TrimSpace(result.Stream)
	result.Subject = strings.TrimSpace(result.Subject)
	result.ResultStream = strings.TrimSpace(result.ResultStream)
	result.ResultSubject = strings.TrimSpace(result.ResultSubject)
	endpoint := strings.Join(result.URLs, ",")

	if len(result.URLs) == 0 {
		return result, endpoint, errors.New("NATS URLs are required")
	}
	for _, raw := range result.URLs {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return result, endpoint, fmt.Errorf("invalid NATS URL %q", raw)
		}
		switch strings.ToLower(parsed.Scheme) {
		case "nats", "tls", "ws", "wss":
		default:
			return result, endpoint, fmt.Errorf("unsupported NATS URL scheme %q", parsed.Scheme)
		}
		if parsed.User != nil {
			return result, endpoint, errors.New("NATS URLs must not contain credentials; use ConnectionOptions")
		}
		if parsed.RawQuery != "" || parsed.Fragment != "" {
			return result, endpoint, errors.New("NATS URLs must not contain query parameters or fragments")
		}
	}
	if err := validateNATSStreamName("Stream", result.Stream); err != nil {
		return result, endpoint, err
	}
	if err := validateNATSConcreteSubject("Subject", result.Subject); err != nil {
		return result, endpoint, err
	}
	if err := validateNATSStreamName("ResultStream", result.ResultStream); err != nil {
		return result, endpoint, err
	}
	if result.Stream == result.ResultStream {
		return result, endpoint, errors.New("NATS ingress and result streams must be distinct")
	}
	if err := validateNATSResultPattern(result.ResultSubject); err != nil {
		return result, endpoint, err
	}
	if result.ConnectTimeout == 0 {
		result.ConnectTimeout = defaultNATSIngressConnectTimeout
	}
	if result.DrainTimeout == 0 {
		result.DrainTimeout = defaultNATSIngressDrainTimeout
	}
	if result.ConnectTimeout < 0 {
		return result, endpoint, errors.New("NATS ConnectTimeout must be positive")
	}
	if result.DrainTimeout < 0 {
		return result, endpoint, errors.New("NATS DrainTimeout must be positive")
	}
	return result, endpoint, nil
}

func validateNATSStreamName(field, value string) error {
	if value == "" {
		return fmt.Errorf("NATS %s is required", field)
	}
	if strings.ContainsAny(value, ".*>/ \t\r\n") {
		return fmt.Errorf("NATS %s contains invalid characters", field)
	}
	return nil
}

func validateNATSConcreteSubject(field, value string) error {
	if value == "" || strings.ContainsAny(value, "*> \t\r\n") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return fmt.Errorf("NATS %s must be a concrete subject", field)
	}
	return nil
}

func validateNATSResultPattern(value string) error {
	if !strings.HasSuffix(value, ".*") || strings.Count(value, "*") != 1 || strings.Contains(value, ">") {
		return errors.New("NATS ResultSubject must be a subject pattern ending in .*")
	}
	return validateNATSConcreteSubject("ResultSubject", strings.TrimSuffix(value, ".*"))
}

func validateNATSIngressStream(ctx context.Context, stream jetstream.Stream, subject string) error {
	info, err := stream.Info(ctx)
	if err != nil {
		return err
	}
	if !slices.Contains(info.Config.Subjects, subject) {
		return fmt.Errorf("stream %q does not contain exact subject %q", info.Config.Name, subject)
	}
	if info.Config.MaxMsgSize > 0 && info.Config.MaxMsgSize < natsingress.MaxMessageBytes {
		return fmt.Errorf("stream %q max message size %d is below TrustDB NATS v1 limit %d", info.Config.Name, info.Config.MaxMsgSize, natsingress.MaxMessageBytes)
	}
	return nil
}

func validateNATSResultStream(ctx context.Context, stream jetstream.Stream, subject string) error {
	info, err := stream.Info(ctx)
	if err != nil {
		return err
	}
	if !slices.Contains(info.Config.Subjects, subject) {
		return fmt.Errorf("stream %q does not contain exact subject %q", info.Config.Name, subject)
	}
	if info.Config.MaxMsgsPerSubject != 1 || info.Config.Discard != jetstream.DiscardNew || !info.Config.DiscardNewPerSubject {
		return fmt.Errorf("stream %q does not enforce one immutable result per subject", info.Config.Name)
	}
	if info.Config.MaxMsgSize > 0 && info.Config.MaxMsgSize < natsingress.MaxMessageBytes {
		return fmt.Errorf("stream %q max message size %d is below TrustDB NATS v1 limit %d", info.Config.Name, info.Config.MaxMsgSize, natsingress.MaxMessageBytes)
	}
	return nil
}

func connectNATSWithContext(ctx context.Context, urls string, options ...nats.Option) (*nats.Conn, error) {
	type connectResult struct {
		conn *nats.Conn
		err  error
	}
	resultCh := make(chan connectResult, 1)
	go func() {
		conn, err := nats.Connect(urls, options...)
		resultCh <- connectResult{conn: conn, err: err}
	}()

	select {
	case result := <-resultCh:
		return result.conn, result.err
	case <-ctx.Done():
		go func() {
			result := <-resultCh
			if result.conn != nil {
				result.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

func requestForNATSSubmission(submission NATSSubmission) (natsingress.Request, error) {
	request, err := natsingress.NewRequest(submission.SignedClaim)
	if err != nil {
		return natsingress.Request{}, err
	}
	if submission.MessageID != request.MessageID {
		return natsingress.Request{}, fmt.Errorf("NATS submission message_id %q does not match signed claim %q", submission.MessageID, request.MessageID)
	}
	return request, nil
}

func natsResultSubject(pattern, messageID string) (string, error) {
	if err := validateNATSResultPattern(pattern); err != nil {
		return "", err
	}
	if strings.TrimSpace(messageID) == "" {
		return "", errors.New("NATS result message_id is required")
	}
	return strings.TrimSuffix(pattern, "*") + messageID, nil
}

func flushNATSSubscription(ctx context.Context, conn *nats.Conn, fallback time.Duration) error {
	if _, ok := ctx.Deadline(); ok {
		return conn.FlushWithContext(ctx)
	}
	flushCtx, cancel := context.WithTimeout(ctx, fallback)
	defer cancel()
	return conn.FlushWithContext(flushCtx)
}

func decodeNATSSubmitResult(endpoint, actualSubject, expectedSubject string, header nats.Header, data []byte, request natsingress.Request) (SubmitResult, error) {
	if actualSubject != expectedSubject {
		return SubmitResult{}, &Error{
			Op:      "validate NATS result",
			URL:     endpoint,
			Message: fmt.Sprintf("received subject %q, want %q", actualSubject, expectedSubject),
		}
	}
	if header.Get(natsingress.HeaderContentType) != natsingress.ContentType {
		return SubmitResult{}, &Error{Op: "validate NATS result", URL: endpoint, Message: "unexpected or missing content type"}
	}
	if header.Get(natsingress.HeaderSchemaVersion) != natsingress.SchemaResult {
		return SubmitResult{}, &Error{Op: "validate NATS result", URL: endpoint, Message: "unexpected or missing result schema header"}
	}
	if header.Get(natsingress.HeaderMessageID) != request.MessageID {
		return SubmitResult{}, &Error{Op: "validate NATS result", URL: endpoint, Message: "result message_id header does not match submission"}
	}
	result, err := natsingress.DecodeResult(data)
	if err != nil {
		return SubmitResult{}, &Error{Op: "decode NATS result", URL: endpoint, Err: err}
	}
	if err := result.ValidateFor(request); err != nil {
		return SubmitResult{}, &Error{Op: "validate NATS result", URL: endpoint, Err: err}
	}
	if result.Error != nil {
		return SubmitResult{}, &Error{
			Op:        "submit NATS claim",
			URL:       endpoint,
			Code:      string(result.Error.Code),
			Message:   result.Error.Message,
			retryable: retryableNATSFailure(result.Error.Code),
		}
	}
	accepted := result.Accepted
	return SubmitResult{
		RecordID:        accepted.RecordID,
		Status:          accepted.Status,
		ProofLevel:      accepted.ProofLevel,
		Idempotent:      accepted.Idempotent,
		BatchEnqueued:   accepted.BatchEnqueued,
		BatchError:      accepted.BatchError,
		ServerRecord:    accepted.ServerRecord,
		AcceptedReceipt: accepted.AcceptedReceipt,
		SignedClaim:     request.SignedClaim,
	}, nil
}

func retryableNATSFailure(code trusterr.Code) bool {
	switch code {
	case trusterr.CodeResourceExhausted, trusterr.CodeDeadlineExceeded, trusterr.CodeInternal:
		return true
	default:
		return false
	}
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
