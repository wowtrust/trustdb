package sdk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wowtrust/trustdb/internal/sproof"
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
	transport Transport
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
	return transport
}

func NewClient(baseURL string, opts ...Option) (*Client, error) {
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
	transport := &httpTransport{
		baseURL:    strings.TrimRight(trimmed, "/"),
		httpClient: NewHTTPClientForConcurrency(defaultHTTPConcurrency),
		userAgent:  "trustdb-go-sdk",
	}
	for _, apply := range opts {
		apply(transport)
	}
	return NewClientWithTransport(transport)
}

func NewClientWithTransport(transport Transport) (*Client, error) {
	if transport == nil {
		return nil, errors.New("sdk: transport is nil")
	}
	return &Client{transport: transport}, nil
}

func (c *Client) BaseURL() string {
	return c.transport.Endpoint()
}

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
	signed, err := BuildSignedFileClaim(raw, id, opts)
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
	return c.transport.SubmitSignedClaim(ctx, signed)
}

func (c *Client) GetRecord(ctx context.Context, recordID string) (RecordIndex, error) {
	return c.transport.GetRecord(ctx, recordID)
}

func (c *Client) GetRecordStatus(ctx context.Context, recordID string) (RecordStatus, error) {
	transport, ok := c.transport.(recordStatusTransport)
	if !ok {
		return RecordStatus{}, &Error{Op: "get record status", Message: "transport does not support record status queries"}
	}
	return transport.GetRecordStatus(ctx, recordID)
}

func (c *Client) GetRecordStatuses(ctx context.Context, recordIDs []string) (RecordStatusBatch, error) {
	transport, ok := c.transport.(recordStatusTransport)
	if !ok {
		return RecordStatusBatch{}, &Error{Op: "get record statuses", Message: "transport does not support record status queries"}
	}
	return transport.GetRecordStatuses(ctx, recordIDs)
}

func (c *Client) CreateStatusSubscription(ctx context.Context, opts CreateStatusSubscriptionOptions) (StatusSubscription, error) {
	transport, ok := c.transport.(statusSubscriptionTransport)
	if !ok {
		return StatusSubscription{}, &Error{Op: "create status subscription", Message: "transport does not support status subscriptions"}
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
	return transport.GetStatusSubscriptionStatuses(ctx, subscriptionID)
}

// SubscribeStatusRefresh opens the SSE invalidation stream. The status
// channel closes when ctx is canceled or the stream ends; terminal stream
// errors are reported on the separate buffered error channel.
func (c *Client) SubscribeStatusRefresh(ctx context.Context, subscriptionID string) (<-chan StatusRefresh, <-chan error, error) {
	transport, ok := c.transport.(statusSubscriptionTransport)
	if !ok {
		return nil, nil, &Error{Op: "subscribe status refresh", Message: "transport does not support status subscriptions"}
	}
	return transport.SubscribeStatusRefresh(ctx, subscriptionID)
}

func (c *Client) ListRecords(ctx context.Context, opts ListRecordsOptions) (RecordPage, error) {
	return c.transport.ListRecords(ctx, opts)
}

func (c *Client) ListRootsPage(ctx context.Context, opts ListPageOptions) (RootPage, error) {
	return c.transport.ListRootsPage(ctx, opts)
}

func (c *Client) ListRoots(ctx context.Context, limit int) ([]BatchRoot, error) {
	page, err := c.transport.ListRootsPage(ctx, ListPageOptions{Limit: limit, Direction: RecordListDirectionDesc})
	if err != nil {
		return nil, err
	}
	return page.Roots, nil
}

func (c *Client) LatestRoot(ctx context.Context) (BatchRoot, error) {
	return c.transport.LatestRoot(ctx)
}

func (c *Client) GetProofBundle(ctx context.Context, recordID string) (ProofBundle, error) {
	return c.transport.GetProofBundle(ctx, recordID)
}

func (c *Client) GetGlobalProof(ctx context.Context, batchID string) (GlobalLogProof, error) {
	return c.transport.GetGlobalProof(ctx, batchID)
}

func (c *Client) GetGlobalEvidence(ctx context.Context, batchID string) (GlobalLogEvidence, error) {
	transport, ok := c.transport.(globalEvidenceTransport)
	if !ok {
		return GlobalLogEvidence{}, &Error{Op: "get global evidence", Message: "transport does not support global evidence"}
	}
	return transport.GetGlobalEvidence(ctx, batchID)
}

func (c *Client) ListSTHs(ctx context.Context, opts ListPageOptions) (TreeHeadPage, error) {
	return c.transport.ListSTHs(ctx, opts)
}

func (c *Client) ListGlobalLeaves(ctx context.Context, opts ListPageOptions) (GlobalLeafPage, error) {
	return c.transport.ListGlobalLeaves(ctx, opts)
}

func (c *Client) ListAnchors(ctx context.Context, opts ListPageOptions) (AnchorPage, error) {
	return c.transport.ListAnchors(ctx, opts)
}

func (c *Client) GetAnchor(ctx context.Context, treeSize uint64) (AnchorStatus, error) {
	return c.transport.GetAnchor(ctx, treeSize)
}

func (c *Client) LatestSTH(ctx context.Context) (SignedTreeHead, error) {
	return c.transport.LatestSTH(ctx)
}

func (c *Client) GetSTH(ctx context.Context, treeSize uint64) (SignedTreeHead, error) {
	return c.transport.GetSTH(ctx, treeSize)
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
