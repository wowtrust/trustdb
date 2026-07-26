package sdk

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/formatregistry"
	"github.com/wowtrust/trustdb/v2/internal/idempotency"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/modelsuite"
	"github.com/wowtrust/trustdb/v2/internal/sproof"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
	"github.com/wowtrust/trustdb/v2/internal/trusterr"
	"github.com/wowtrust/trustdb/v2/transporttls"
)

const defaultHTTPTimeout = 15 * time.Second
const defaultHTTPConcurrency = 64

type Transport interface {
	Endpoint() string
	CheckHealth(context.Context) HealthStatus
	SubmitSignedClaim(context.Context, SignedClaim) (SubmitResult, error)
	GetRecord(context.Context, string) (RecordIndex, error)
	ListRecords(context.Context, ListRecordsOptions) (RecordPage, error)
	ListRootsPage(context.Context, ListPageOptions) (RootPage, error)
	GetProofBundle(context.Context, string) (ProofBundle, error)
	ListRoots(context.Context, int) ([]BatchRoot, error)
	LatestRoot(context.Context) (BatchRoot, error)
	ListSTHs(context.Context, ListPageOptions) (TreeHeadPage, error)
	GetGlobalProof(context.Context, string) (GlobalLogProof, error)
	ListGlobalLeaves(context.Context, ListPageOptions) (GlobalLeafPage, error)
	ListAnchors(context.Context, ListPageOptions) (AnchorPage, error)
	GetAnchor(context.Context, uint64) (AnchorStatus, error)
	LatestSTH(context.Context) (SignedTreeHead, error)
	GetSTH(context.Context, uint64) (SignedTreeHead, error)
	MetricsRaw(context.Context) (string, error)
}

type signedClaimBatchTransport interface {
	SubmitSignedClaims(context.Context, []SignedClaim) ([]signedClaimBatchItemResult, error)
}

type globalEvidenceTransport interface {
	GetGlobalEvidence(context.Context, string) (GlobalLogEvidence, error)
}

type recordStatusTransport interface {
	GetRecordStatus(context.Context, string) (RecordStatus, error)
	GetRecordStatuses(context.Context, []string) (RecordStatusBatch, error)
}

type statusSubscriptionTransport interface {
	CreateStatusSubscription(context.Context, CreateStatusSubscriptionOptions) (StatusSubscription, error)
	DeleteStatusSubscription(context.Context, string) error
	GetStatusSubscriptionStatuses(context.Context, string) (RecordStatusBatch, error)
	SubscribeStatusRefresh(context.Context, string) (<-chan StatusRefresh, <-chan error, error)
}

type anchorSystemTransport interface {
	ListAnchorSystems(context.Context) ([]AnchorSystem, error)
	GetAnchorSystem(context.Context, string) (AnchorSystem, error)
	GetAnchorSystemStatus(context.Context, string) (AnchorSystemStatus, error)
	ListAnchorSystemResources(context.Context, string, AnchorResourceListOptions) (AnchorSystemResourcePage, error)
	GetAnchorSystemResource(context.Context, string, string, string) (AnchorSystemResource, error)
}

type signedClaimStreamTransport interface {
	SubmitSignedClaimStream(context.Context, <-chan signedClaimStreamItem) (<-chan signedClaimStreamItemResult, error)
}

type signedClaimBatchItemResult struct {
	Index  int
	Result SubmitResult
	Err    error
}

type signedClaimStreamItem struct {
	Index       int
	SignedClaim SignedClaim
}

type signedClaimStreamItemResult struct {
	Index  int
	Result SubmitResult
	Err    error
}

type Client struct {
	transport   Transport
	cryptoSuite CryptoSuite
}

type cryptoSuiteTransport interface {
	CryptoSuite() CryptoSuite
}

type Option func(*httpTransport)

func WithHTTPClient(client *http.Client) Option {
	return func(t *httpTransport) {
		if client != nil {
			t.httpClient = client
		}
	}
}

func WithUserAgent(userAgent string) Option {
	return func(t *httpTransport) {
		t.userAgent = strings.TrimSpace(userAgent)
	}
}

func WithHTTPTransport(transport http.RoundTripper) Option {
	return func(t *httpTransport) {
		if transport != nil {
			t.httpClient.Transport = transport
		}
	}
}

// TLSConfig is transport certificate trust. It is intentionally separate from
// TrustedKeys, which verifies signed TrustDB proof material.
type TLSConfig = transporttls.ClientConfig

// WithTLSConfig configures CA trust/pinning, hostname verification, optional
// mTLS, revocation, and reload for an HTTPS SDK client. HTTP proxies are
// rejected because net/http performs the post-CONNECT TLS handshake outside a
// custom DialTLSContext, which would bypass the reloadable policy.
func WithTLSConfig(config TLSConfig) Option {
	return func(t *httpTransport) {
		copy := config
		t.tlsConfig = &copy
	}
}

func NewHTTPClientForConcurrency(concurrency int) *http.Client {
	return &http.Client{
		Timeout:   defaultHTTPTimeout,
		Transport: NewHTTPTransportForConcurrency(concurrency),
	}
}

func NewHTTPTransportForConcurrency(concurrency int) *http.Transport {
	if concurrency <= 0 {
		concurrency = defaultHTTPConcurrency
	}
	maxPerHost := concurrency * 2
	if maxPerHost < defaultHTTPConcurrency {
		maxPerHost = defaultHTTPConcurrency
	}
	base, _ := http.DefaultTransport.(*http.Transport)
	transport := base.Clone()
	transport.MaxIdleConns = maxPerHost * 2
	transport.MaxIdleConnsPerHost = maxPerHost
	transport.MaxConnsPerHost = maxPerHost
	transport.IdleConnTimeout = 90 * time.Second
	transport.ForceAttemptHTTP2 = true
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return transport
}

func NewClient(baseURL string, opts ...Option) (*Client, error) {
	return NewClientForSuite(baseURL, cryptosuite.INTLV1, opts...)
}

// NewClientForSuite creates an HTTP client bound to one immutable server
// namespace suite. Requests and every suite-bearing response fail closed when
// they do not exactly match expectedSuite.
func NewClientForSuite(baseURL string, expectedSuite CryptoSuite, opts ...Option) (*Client, error) {
	if _, _, err := formatregistry.RequireWritable(formatregistry.SDKV2, expectedSuite); err != nil {
		return nil, fmt.Errorf("sdk: select crypto suite: %w", err)
	}
	trimmed := strings.TrimSpace(baseURL)
	if trimmed == "" {
		return nil, errors.New("sdk: server url is empty")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("sdk: parse server url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("sdk: server url must include scheme and host: %s", trimmed)
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("sdk: server url scheme must be http or https: %s", trimmed)
	}
	if strings.EqualFold(u.Scheme, "http") && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("sdk: plaintext HTTP is limited to loopback endpoints; use https for %s", u.Hostname())
	}
	transport := &httpTransport{
		baseURL:     strings.TrimRight(trimmed, "/"),
		httpClient:  NewHTTPClientForConcurrency(defaultHTTPConcurrency),
		userAgent:   "trustdb-go-sdk",
		cryptoSuite: expectedSuite,
	}
	for _, apply := range opts {
		apply(transport)
	}
	if transport.tlsConfig != nil {
		if !strings.EqualFold(u.Scheme, "https") {
			return nil, errors.New("sdk: TLS configuration requires an https server URL")
		}
		manager, err := transporttls.NewClientManager(*transport.tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("sdk: initialize TLS: %w", err)
		}
		manager.Start(context.Background(), transport.tlsConfig.ReloadError)
		base, ok := transport.httpClient.Transport.(*http.Transport)
		if transport.httpClient.Transport == nil {
			base, _ = http.DefaultTransport.(*http.Transport)
			ok = base != nil
		}
		if !ok {
			_ = manager.Close()
			return nil, errors.New("sdk: WithTLSConfig requires an *http.Transport")
		}
		clone := base.Clone()
		clone.Proxy = rejectHTTPProxy(clone.Proxy)
		clone.TLSClientConfig = nil
		clone.DialTLSContext = manager.DialTLSContext
		clone.ForceAttemptHTTP2 = true
		transport.httpClient.Transport = clone
		transport.tlsManager = manager
	}
	return NewClientWithTransportForSuite(transport, expectedSuite)
}

func rejectHTTPProxy(proxy func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	if proxy == nil {
		return nil
	}
	return func(request *http.Request) (*url.URL, error) {
		proxyURL, err := proxy(request)
		if err != nil {
			return nil, err
		}
		if proxyURL != nil {
			return nil, errors.New("sdk: HTTP proxies are unsupported with reloadable TLS configuration")
		}
		return nil, nil
	}
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func NewClientWithTransport(transport Transport) (*Client, error) {
	return NewClientWithTransportForSuite(transport, cryptosuite.INTLV1)
}

func NewClientWithTransportForSuite(transport Transport, expectedSuite CryptoSuite) (*Client, error) {
	if transport == nil {
		return nil, errors.New("sdk: transport is nil")
	}
	if _, _, err := formatregistry.RequireWritable(formatregistry.SDKV2, expectedSuite); err != nil {
		return nil, fmt.Errorf("sdk: select crypto suite: %w", err)
	}
	if bound, ok := transport.(cryptoSuiteTransport); ok && bound.CryptoSuite() != expectedSuite {
		return nil, fmt.Errorf(
			"sdk: transport crypto_suite %s does not match client suite %s",
			bound.CryptoSuite(),
			expectedSuite,
		)
	}
	return &Client{transport: transport, cryptoSuite: expectedSuite}, nil
}

func (c *Client) BaseURL() string {
	return c.transport.Endpoint()
}

func (c *Client) CryptoSuite() CryptoSuite { return c.cryptoSuite }

func (c *Client) Close() error {
	closer, ok := c.transport.(interface{ Close() error })
	if !ok {
		return nil
	}
	return closer.Close()
}

func (c *Client) Health(ctx context.Context) error {
	status := c.CheckHealth(ctx)
	if status.OK {
		return nil
	}
	return &Error{Op: "health", URL: c.BaseURL(), StatusCode: status.StatusCode, Message: status.Error}
}

func (c *Client) CheckHealth(ctx context.Context) HealthStatus {
	return c.transport.CheckHealth(ctx)
}

func (c *Client) SubmitFile(ctx context.Context, raw io.Reader, id Identity, opts FileClaimOptions) (SubmitResult, error) {
	if err := c.requireIdentitySuite("submit file", id); err != nil {
		return SubmitResult{}, err
	}
	signed, err := BuildSignedFileClaimContext(ctx, raw, id, opts)
	if err != nil {
		return SubmitResult{}, err
	}
	result, err := c.SubmitSignedClaim(ctx, signed)
	if err != nil {
		return SubmitResult{}, err
	}
	result.SignedClaim = signed
	return result, nil
}

func (c *Client) SubmitSignedClaim(ctx context.Context, signed SignedClaim) (SubmitResult, error) {
	if err := c.requireSuite("submit signed claim", signed); err != nil {
		return SubmitResult{}, err
	}
	result, err := c.transport.SubmitSignedClaim(ctx, signed)
	if err != nil {
		return SubmitResult{}, err
	}
	if err := c.validateSubmitResult("submit signed claim", signed, result); err != nil {
		return SubmitResult{}, err
	}
	return result, nil
}

func (c *Client) GetRecord(ctx context.Context, recordID string) (RecordIndex, error) {
	record, err := c.transport.GetRecord(ctx, recordID)
	if err != nil {
		return RecordIndex{}, err
	}
	if err := c.requireSuite("get record", record); err != nil {
		return RecordIndex{}, err
	}
	return record, nil
}

func (c *Client) GetRecordStatus(ctx context.Context, recordID string) (RecordStatus, error) {
	transport, ok := c.transport.(recordStatusTransport)
	if !ok {
		return RecordStatus{}, &Error{Op: "get record status", Message: "transport does not support record status queries"}
	}
	status, err := transport.GetRecordStatus(ctx, recordID)
	if err != nil {
		return RecordStatus{}, err
	}
	if err := c.requireSuite("get record status", status); err != nil {
		return RecordStatus{}, err
	}
	return status, nil
}

func (c *Client) GetRecordStatuses(ctx context.Context, recordIDs []string) (RecordStatusBatch, error) {
	transport, ok := c.transport.(recordStatusTransport)
	if !ok {
		return RecordStatusBatch{}, &Error{Op: "get record statuses", Message: "transport does not support record status queries"}
	}
	statuses, err := transport.GetRecordStatuses(ctx, recordIDs)
	if err != nil {
		return RecordStatusBatch{}, err
	}
	if err := c.validateRecordStatuses("get record statuses", statuses); err != nil {
		return RecordStatusBatch{}, err
	}
	return statuses, nil
}

func (c *Client) CreateStatusSubscription(ctx context.Context, opts CreateStatusSubscriptionOptions) (StatusSubscription, error) {
	transport, ok := c.transport.(statusSubscriptionTransport)
	if !ok {
		return StatusSubscription{}, &Error{Op: "create status subscription", Message: "transport does not support status subscriptions"}
	}
	descriptor, _, err := opts.Identity.signingMaterial()
	if err != nil {
		return StatusSubscription{}, err
	}
	if descriptor.CryptoSuite != c.cryptoSuite {
		return StatusSubscription{}, c.mismatch("create status subscription", descriptor.CryptoSuite)
	}
	return transport.CreateStatusSubscription(ctx, opts)
}

func (c *Client) DeleteStatusSubscription(ctx context.Context, subscriptionID string) error {
	transport, ok := c.transport.(statusSubscriptionTransport)
	if !ok {
		return &Error{Op: "delete status subscription", Message: "transport does not support status subscriptions"}
	}
	return transport.DeleteStatusSubscription(ctx, subscriptionID)
}

func (c *Client) GetStatusSubscriptionStatuses(ctx context.Context, subscriptionID string) (RecordStatusBatch, error) {
	transport, ok := c.transport.(statusSubscriptionTransport)
	if !ok {
		return RecordStatusBatch{}, &Error{Op: "get subscription statuses", Message: "transport does not support status subscriptions"}
	}
	statuses, err := transport.GetStatusSubscriptionStatuses(ctx, subscriptionID)
	if err != nil {
		return RecordStatusBatch{}, err
	}
	if err := c.validateRecordStatuses("get subscription statuses", statuses); err != nil {
		return RecordStatusBatch{}, err
	}
	return statuses, nil
}

// SubscribeStatusRefresh opens the SSE invalidation stream. The status
// channel closes when ctx is canceled or the stream ends; terminal stream
// errors are reported on the separate buffered error channel.
func (c *Client) SubscribeStatusRefresh(ctx context.Context, subscriptionID string) (<-chan StatusRefresh, <-chan error, error) {
	transport, ok := c.transport.(statusSubscriptionTransport)
	if !ok {
		return nil, nil, &Error{Op: "subscribe status refresh", Message: "transport does not support status subscriptions"}
	}
	streamCtx, cancel := context.WithCancel(nonNilContext(ctx))
	events, errorsCh, err := transport.SubscribeStatusRefresh(streamCtx, subscriptionID)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	validatedEvents, validatedErrors := c.validateStatusRefreshStream(streamCtx, cancel, events, errorsCh)
	return validatedEvents, validatedErrors, nil
}

func (c *Client) ListRecords(ctx context.Context, opts ListRecordsOptions) (RecordPage, error) {
	page, err := c.transport.ListRecords(ctx, opts)
	if err != nil {
		return RecordPage{}, err
	}
	for index := range page.Records {
		if err := c.requireSuite("list records", page.Records[index]); err != nil {
			return RecordPage{}, err
		}
	}
	return page, nil
}

func (c *Client) ListRootsPage(ctx context.Context, opts ListPageOptions) (RootPage, error) {
	page, err := c.transport.ListRootsPage(ctx, opts)
	if err != nil {
		return RootPage{}, err
	}
	for index := range page.Roots {
		if err := c.requireSuite("list roots", page.Roots[index]); err != nil {
			return RootPage{}, err
		}
	}
	return page, nil
}

func (c *Client) ListRoots(ctx context.Context, limit int) ([]BatchRoot, error) {
	page, err := c.ListRootsPage(ctx, ListPageOptions{Limit: limit, Direction: RecordListDirectionDesc})
	if err != nil {
		return nil, err
	}
	return page.Roots, nil
}

func (c *Client) LatestRoot(ctx context.Context) (BatchRoot, error) {
	root, err := c.transport.LatestRoot(ctx)
	if err != nil {
		return BatchRoot{}, err
	}
	if err := c.requireSuite("latest root", root); err != nil {
		return BatchRoot{}, err
	}
	return root, nil
}

func (c *Client) GetProofBundle(ctx context.Context, recordID string) (ProofBundle, error) {
	bundle, err := c.transport.GetProofBundle(ctx, recordID)
	if err != nil {
		return ProofBundle{}, err
	}
	if err := c.requireSuite("get proof bundle", bundle); err != nil {
		return ProofBundle{}, err
	}
	return bundle, nil
}

func (c *Client) GetGlobalProof(ctx context.Context, batchID string) (GlobalLogProof, error) {
	proof, err := c.transport.GetGlobalProof(ctx, batchID)
	if err != nil {
		return GlobalLogProof{}, err
	}
	if err := c.requireSuite("get global proof", proof); err != nil {
		return GlobalLogProof{}, err
	}
	return proof, nil
}

func (c *Client) GetGlobalEvidence(ctx context.Context, batchID string) (GlobalLogEvidence, error) {
	transport, ok := c.transport.(globalEvidenceTransport)
	if !ok {
		return GlobalLogEvidence{}, &Error{Op: "get global evidence", Message: "transport does not support global evidence"}
	}
	evidence, err := transport.GetGlobalEvidence(ctx, batchID)
	if err != nil {
		return GlobalLogEvidence{}, err
	}
	if err := c.requireSuite("get global evidence", evidence.GlobalProof); err != nil {
		return GlobalLogEvidence{}, err
	}
	if evidence.AnchorResult != nil {
		if err := c.requireSuite("get global evidence", *evidence.AnchorResult); err != nil {
			return GlobalLogEvidence{}, err
		}
	}
	return evidence, nil
}

func (c *Client) ListSTHs(ctx context.Context, opts ListPageOptions) (TreeHeadPage, error) {
	page, err := c.transport.ListSTHs(ctx, opts)
	if err != nil {
		return TreeHeadPage{}, err
	}
	for index := range page.STHs {
		if err := c.requireSuite("list STHs", page.STHs[index]); err != nil {
			return TreeHeadPage{}, err
		}
	}
	return page, nil
}

func (c *Client) ListGlobalLeaves(ctx context.Context, opts ListPageOptions) (GlobalLeafPage, error) {
	page, err := c.transport.ListGlobalLeaves(ctx, opts)
	if err != nil {
		return GlobalLeafPage{}, err
	}
	for index := range page.Leaves {
		if err := c.requireSuite("list global leaves", page.Leaves[index]); err != nil {
			return GlobalLeafPage{}, err
		}
	}
	return page, nil
}

func (c *Client) ListAnchors(ctx context.Context, opts ListPageOptions) (AnchorPage, error) {
	page, err := c.transport.ListAnchors(ctx, opts)
	if err != nil {
		return AnchorPage{}, err
	}
	for index := range page.Anchors {
		if page.Anchors[index].Result == nil {
			continue
		}
		if err := c.requireSuite("list anchors", *page.Anchors[index].Result); err != nil {
			return AnchorPage{}, err
		}
	}
	return page, nil
}

func (c *Client) GetAnchor(ctx context.Context, treeSize uint64) (AnchorStatus, error) {
	status, err := c.transport.GetAnchor(ctx, treeSize)
	if err != nil {
		return AnchorStatus{}, err
	}
	if status.Result != nil {
		if err := c.requireSuite("get anchor", *status.Result); err != nil {
			return AnchorStatus{}, err
		}
	}
	return status, nil
}

func (c *Client) ListAnchorSystems(ctx context.Context) ([]AnchorSystem, error) {
	transport, ok := c.transport.(anchorSystemTransport)
	if !ok {
		return nil, &Error{Op: "list anchor systems", Message: "transport does not support anchor systems"}
	}
	return transport.ListAnchorSystems(ctx)
}

func (c *Client) GetAnchorSystem(ctx context.Context, systemID string) (AnchorSystem, error) {
	transport, ok := c.transport.(anchorSystemTransport)
	if !ok {
		return AnchorSystem{}, &Error{Op: "get anchor system", Message: "transport does not support anchor systems"}
	}
	return transport.GetAnchorSystem(ctx, systemID)
}

func (c *Client) GetAnchorSystemStatus(ctx context.Context, systemID string) (AnchorSystemStatus, error) {
	transport, ok := c.transport.(anchorSystemTransport)
	if !ok {
		return AnchorSystemStatus{}, &Error{Op: "get anchor system status", Message: "transport does not support anchor systems"}
	}
	return transport.GetAnchorSystemStatus(ctx, systemID)
}

func (c *Client) ListAnchorSystemResources(ctx context.Context, systemID string, opts AnchorResourceListOptions) (AnchorSystemResourcePage, error) {
	transport, ok := c.transport.(anchorSystemTransport)
	if !ok {
		return AnchorSystemResourcePage{}, &Error{Op: "list anchor system resources", Message: "transport does not support anchor systems"}
	}
	return transport.ListAnchorSystemResources(ctx, systemID, opts)
}

func (c *Client) GetAnchorSystemResource(ctx context.Context, systemID, kind, resourceID string) (AnchorSystemResource, error) {
	transport, ok := c.transport.(anchorSystemTransport)
	if !ok {
		return AnchorSystemResource{}, &Error{Op: "get anchor system resource", Message: "transport does not support anchor systems"}
	}
	return transport.GetAnchorSystemResource(ctx, systemID, kind, resourceID)
}

func (c *Client) LatestSTH(ctx context.Context) (SignedTreeHead, error) {
	sth, err := c.transport.LatestSTH(ctx)
	if err != nil {
		return SignedTreeHead{}, err
	}
	if err := c.requireSuite("latest STH", sth); err != nil {
		return SignedTreeHead{}, err
	}
	return sth, nil
}

func (c *Client) GetSTH(ctx context.Context, treeSize uint64) (SignedTreeHead, error) {
	sth, err := c.transport.GetSTH(ctx, treeSize)
	if err != nil {
		return SignedTreeHead{}, err
	}
	if err := c.requireSuite("get STH", sth); err != nil {
		return SignedTreeHead{}, err
	}
	return sth, nil
}

func (c *Client) ExportSingleProof(ctx context.Context, recordID string) (SingleProof, error) {
	bundle, err := c.GetProofBundle(ctx, recordID)
	if err != nil {
		return SingleProof{}, err
	}
	opts := sproof.Options{ExportedAtUnixN: time.Now().UTC().UnixNano()}
	evidence, err := c.GetGlobalEvidence(ctx, bundle.CommittedReceipt.BatchID)
	if err != nil {
		if !IsUnavailable(err) {
			return SingleProof{}, fmt.Errorf("sdk: fetch global evidence: %w", err)
		}
		return sproof.New(bundle, opts)
	}
	opts.GlobalProof = &evidence.GlobalProof
	opts.AnchorResult = evidence.AnchorResult
	return sproof.New(bundle, opts)
}

func (c *Client) WriteSingleProofFile(ctx context.Context, recordID, path string) error {
	proof, err := c.ExportSingleProof(ctx, recordID)
	if err != nil {
		return err
	}
	return sproof.WriteFile(path, proof)
}

func (c *Client) MetricsRaw(ctx context.Context) (string, error) {
	return c.transport.MetricsRaw(ctx)
}

func (c *Client) requireSuite(op string, value any) error {
	if err := modelsuite.Require(c.cryptoSuite, value); err != nil {
		return &Error{
			Op:      op,
			URL:     c.BaseURL(),
			Code:    string(trusterr.CodeFailedPrecondition),
			Message: fmt.Sprintf("response/request crypto_suite does not match client suite %s", c.cryptoSuite),
			Err:     err,
		}
	}
	return nil
}

func (c *Client) mismatch(op string, actual CryptoSuite) error {
	return &Error{
		Op:      op,
		URL:     c.BaseURL(),
		Code:    string(trusterr.CodeFailedPrecondition),
		Message: fmt.Sprintf("crypto_suite %s does not match client suite %s", actual, c.cryptoSuite),
	}
}

func (c *Client) validateSubmitResult(op string, expected SignedClaim, result SubmitResult) error {
	malformed := func(message string) error {
		return &Error{
			Op:      op,
			URL:     c.BaseURL(),
			Code:    string(trusterr.CodeDataLoss),
			Message: message,
		}
	}
	if result.ServerRecord.SchemaVersion != model.SchemaServerRecord {
		return malformed(fmt.Sprintf("server returned unexpected server record schema %q", result.ServerRecord.SchemaVersion))
	}
	if err := c.requireSuite(op, result.ServerRecord); err != nil {
		return err
	}
	if result.AcceptedReceipt.SchemaVersion != model.SchemaAcceptedReceipt {
		return malformed(fmt.Sprintf("server returned unexpected accepted receipt schema %q", result.AcceptedReceipt.SchemaVersion))
	}
	if err := c.requireSuite(op, result.AcceptedReceipt); err != nil {
		return err
	}
	if result.SignedClaim.SchemaVersion != model.SchemaSignedClaim ||
		result.SignedClaim.Claim.SchemaVersion != model.SchemaClientClaim {
		return malformed(fmt.Sprintf(
			"server returned unexpected signed claim schemas %q/%q",
			result.SignedClaim.SchemaVersion,
			result.SignedClaim.Claim.SchemaVersion,
		))
	}
	if err := c.requireSuite(op, result.SignedClaim); err != nil {
		return err
	}
	if !reflect.DeepEqual(result.SignedClaim, expected) {
		return malformed("server returned a signed claim that differs from the submitted claim")
	}
	if result.RecordID == "" {
		return malformed("server returned an empty record_id")
	}
	if result.Status != model.RecordStatusAccepted {
		return malformed(fmt.Sprintf("server returned unexpected submit status %q", result.Status))
	}
	if result.ProofLevel != ProofLevelL2 {
		return malformed(fmt.Sprintf("server returned unexpected submit proof_level %q", result.ProofLevel))
	}
	if result.ServerRecord.RecordID != result.RecordID ||
		result.AcceptedReceipt.RecordID != result.RecordID {
		return malformed("server returned inconsistent submit record_id values")
	}
	if result.AcceptedReceipt.Status != result.Status {
		return malformed("server returned inconsistent submit status values")
	}
	if result.Idempotent && result.BatchEnqueued {
		return malformed("server returned an idempotent result that enqueues a duplicate batch entry")
	}
	if result.Idempotent && result.BatchError != "" {
		return malformed("server returned an idempotent result with batch_error")
	}
	if result.BatchEnqueued && result.BatchError != "" {
		return malformed("server returned batch_enqueued with batch_error")
	}
	provider, err := trustcrypto.ProviderForSuite(c.cryptoSuite)
	if err != nil {
		return malformed(fmt.Sprintf("initialize response crypto provider: %v", err))
	}
	if err := idempotency.ValidateAcceptedResponseWithProvider(
		provider,
		expected,
		result.ServerRecord,
		result.AcceptedReceipt,
	); err != nil {
		return malformed(fmt.Sprintf("server returned an invalid accepted response: %v", err))
	}
	return nil
}

func (c *Client) validateRecordStatuses(op string, statuses RecordStatusBatch) error {
	for index := range statuses.Statuses {
		if err := c.requireSuite(op, statuses.Statuses[index]); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) validateStatusRefreshStream(
	ctx context.Context,
	cancel context.CancelFunc,
	events <-chan StatusRefresh,
	upstreamErrors <-chan error,
) (<-chan StatusRefresh, <-chan error) {
	out := make(chan StatusRefresh, 1)
	errs := make(chan error, 1)
	ctx = nonNilContext(ctx)
	go func() {
		defer cancel()
		defer close(out)
		defer close(errs)
		for events != nil || upstreamErrors != nil {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-events:
				if !ok {
					events = nil
					continue
				}
				if err := c.requireSuite("subscribe status refresh", event); err != nil {
					errs <- err
					return
				}
				select {
				case out <- event:
				case <-ctx.Done():
					return
				}
			case err, ok := <-upstreamErrors:
				if !ok {
					upstreamErrors = nil
					continue
				}
				if err != nil {
					errs <- err
					return
				}
			}
		}
	}()
	return out, errs
}
