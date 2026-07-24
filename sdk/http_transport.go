package sdk

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/statusnotify"
	"github.com/wowtrust/trustdb/transporttls"
)

type httpTransport struct {
	baseURL     string
	httpClient  *http.Client
	userAgent   string
	tlsConfig   *TLSConfig
	tlsManager  *transporttls.Manager
	cryptoSuite CryptoSuite
}

func (t *httpTransport) Endpoint() string {
	return t.baseURL
}

func (t *httpTransport) CryptoSuite() CryptoSuite {
	return t.cryptoSuite
}

func (t *httpTransport) Close() error {
	if t.httpClient != nil {
		t.httpClient.CloseIdleConnections()
	}
	if t.tlsManager != nil {
		return t.tlsManager.Close()
	}
	return nil
}

func (t *httpTransport) CheckHealth(ctx context.Context) HealthStatus {
	start := time.Now()
	var out struct {
		OK                bool   `json:"ok"`
		TransportSecurity string `json:"transport_security"`
		TLSVersion        string `json:"tls_version"`
		PeerAuthenticated bool   `json:"peer_authenticated"`
		PeerSubject       string `json:"peer_subject"`
	}
	err := t.getJSON(ctx, "/healthz", nil, &out)
	rtt := time.Since(start).Milliseconds()
	if err != nil {
		statusCode := 0
		if sdkErr, ok := asSDKError(err); ok {
			statusCode = sdkErr.StatusCode
		}
		return HealthStatus{ServerURL: t.baseURL, RTTMillis: rtt, StatusCode: statusCode, Error: err.Error()}
	}
	if !out.OK {
		return HealthStatus{ServerURL: t.baseURL, RTTMillis: rtt, Error: "server returned ok=false"}
	}
	return HealthStatus{OK: true, ServerURL: t.baseURL, RTTMillis: rtt, TransportSecurity: out.TransportSecurity, TLSVersion: out.TLSVersion, PeerAuthenticated: out.PeerAuthenticated, PeerSubject: out.PeerSubject}
}

func (t *httpTransport) SubmitSignedClaim(ctx context.Context, signed SignedClaim) (SubmitResult, error) {
	body, err := cborx.Marshal(signed)
	if err != nil {
		return SubmitResult{}, err
	}
	var env submitClaimEnvelope
	if err := t.doJSON(ctx, http.MethodPost, "/v2/claims", nil, bytes.NewReader(body), "application/cbor", &env); err != nil {
		return SubmitResult{}, err
	}
	return submitResultFromEnvelope(env, signed), nil
}

func (t *httpTransport) SubmitSignedClaims(ctx context.Context, signed []SignedClaim) ([]signedClaimBatchItemResult, error) {
	body, err := cborx.Marshal(submitClaimsBatchRequestEnvelope{Claims: signed})
	if err != nil {
		return nil, err
	}
	var env submitClaimsBatchEnvelope
	if err := t.doJSON(ctx, http.MethodPost, "/v2/claims/batch", nil, bytes.NewReader(body), "application/cbor", &env); err != nil {
		return nil, err
	}
	if len(env.Results) != len(signed) {
		return nil, &Error{Op: "submit claim batch", URL: t.baseURL, Message: fmt.Sprintf("server returned %d results for %d claims", len(env.Results), len(signed))}
	}
	results := make([]signedClaimBatchItemResult, len(env.Results))
	for _, item := range env.Results {
		if item.Index < 0 || item.Index >= len(signed) {
			return nil, &Error{Op: "submit claim batch", URL: t.baseURL, Message: fmt.Sprintf("server returned out-of-range result index %d", item.Index)}
		}
		results[item.Index] = signedClaimBatchItemResult{Index: item.Index}
		if item.Error != nil {
			results[item.Index].Err = &Error{
				Op:      "submit claim batch item",
				URL:     t.baseURL,
				Code:    item.Error.Code,
				Message: item.Error.Message,
			}
			continue
		}
		if item.Result == nil {
			results[item.Index].Err = &Error{Op: "submit claim batch item", URL: t.baseURL, Message: "server returned neither result nor error"}
			continue
		}
		results[item.Index].Result = submitResultFromEnvelope(*item.Result, signed[item.Index])
	}
	return results, nil
}

func (t *httpTransport) GetRecord(ctx context.Context, recordID string) (RecordIndex, error) {
	var idx model.RecordIndex
	if err := t.getJSON(ctx, "/v2/records/"+url.PathEscape(recordID), nil, &idx); err != nil {
		return RecordIndex{}, err
	}
	if idx.RecordID == "" {
		return RecordIndex{}, &Error{Op: "get record", Message: "server returned empty record index"}
	}
	return idx, nil
}

func (t *httpTransport) GetRecordStatus(ctx context.Context, recordID string) (RecordStatus, error) {
	var status model.RecordStatus
	if err := t.getJSON(ctx, "/v2/records/"+url.PathEscape(recordID)+"/status", nil, &status); err != nil {
		return RecordStatus{}, err
	}
	return status, nil
}

func (t *httpTransport) GetRecordStatuses(ctx context.Context, recordIDs []string) (RecordStatusBatch, error) {
	body, err := json.Marshal(recordStatusesRequestEnvelope{RecordIDs: recordIDs})
	if err != nil {
		return RecordStatusBatch{}, err
	}
	var response recordStatusesEnvelope
	if err := t.doJSON(ctx, http.MethodPost, "/v2/records/status:batchGet", nil, bytes.NewReader(body), "application/json", &response); err != nil {
		return RecordStatusBatch{}, err
	}
	return RecordStatusBatch{Statuses: response.Statuses, MissingRecordIDs: response.MissingRecordIDs}, nil
}

func (t *httpTransport) CreateStatusSubscription(ctx context.Context, opts CreateStatusSubscriptionOptions) (StatusSubscription, error) {
	if opts.TTL < 0 {
		return StatusSubscription{}, &Error{Op: "create status subscription", Message: "subscription TTL must not be negative"}
	}
	descriptor, signer, err := opts.Identity.signingMaterial()
	if err != nil {
		return StatusSubscription{}, &Error{Op: "create status subscription", Err: err}
	}
	ttlSeconds := int64(0)
	if opts.TTL > 0 {
		ttlSeconds = int64((opts.TTL + time.Second - 1) / time.Second)
	}
	request := statusnotify.CreateRequest{
		TenantID:      opts.Identity.TenantID,
		ClientID:      opts.Identity.ClientID,
		KeyID:         descriptor.KeyID,
		RecordIDs:     append([]string(nil), opts.RecordIDs...),
		Channels:      opts.Channels,
		TTLSeconds:    ttlSeconds,
		SignedAtUnixN: time.Now().UTC().UnixNano(),
	}
	nonce := make([]byte, 18)
	if _, err := rand.Read(nonce); err != nil {
		return StatusSubscription{}, err
	}
	request.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	if err := statusnotify.SignCreateRequest(nonNilContext(ctx), descriptor.CryptoSuite, signer, &request); err != nil {
		return StatusSubscription{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return StatusSubscription{}, err
	}
	var subscription statusnotify.Subscription
	if err := t.doJSON(ctx, http.MethodPost, "/v2/status-subscriptions", nil, bytes.NewReader(body), "application/json", &subscription); err != nil {
		return StatusSubscription{}, err
	}
	return subscription, nil
}

func (t *httpTransport) DeleteStatusSubscription(ctx context.Context, subscriptionID string) error {
	return t.doJSON(ctx, http.MethodDelete, "/v2/status-subscriptions/"+url.PathEscape(subscriptionID), nil, nil, "", nil)
}

func (t *httpTransport) GetStatusSubscriptionStatuses(ctx context.Context, subscriptionID string) (RecordStatusBatch, error) {
	var response recordStatusesEnvelope
	path := "/v2/status-subscriptions/" + url.PathEscape(subscriptionID) + "/statuses"
	if err := t.getJSON(ctx, path, nil, &response); err != nil {
		return RecordStatusBatch{}, err
	}
	return RecordStatusBatch{Statuses: response.Statuses, MissingRecordIDs: response.MissingRecordIDs}, nil
}

func (t *httpTransport) SubscribeStatusRefresh(ctx context.Context, subscriptionID string) (<-chan StatusRefresh, <-chan error, error) {
	path := "/v2/status-subscriptions/" + url.PathEscape(subscriptionID) + "/events"
	endpoint := t.endpoint(path, nil)
	ctx = nonNilContext(ctx)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, &Error{Op: "subscribe status refresh", URL: endpoint, Err: err}
	}
	request.Header.Set("Accept", "text/event-stream")
	if t.userAgent != "" {
		request.Header.Set("User-Agent", t.userAgent)
	}
	client := *t.httpClient
	client.Timeout = 0
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, &Error{Op: "subscribe status refresh", URL: endpoint, Err: err}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		defer response.Body.Close()
		return nil, nil, decodeHTTPError(http.MethodGet, endpoint, response)
	}
	events := make(chan StatusRefresh, 1)
	errorsCh := make(chan error, 1)
	go func() {
		defer close(events)
		defer close(errorsCh)
		defer response.Body.Close()
		scanner := bufio.NewScanner(response.Body)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		var data string
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "data: "):
				data = strings.TrimPrefix(line, "data: ")
			case line == "" && data != "":
				var notification model.StatusRefresh
				if err := json.Unmarshal([]byte(data), &notification); err != nil {
					errorsCh <- &Error{Op: "subscribe status refresh", URL: endpoint, Err: fmt.Errorf("decode SSE notification: %w", err)}
					return
				}
				select {
				case events <- notification:
				default:
					// A queued invalidation already instructs the caller to pull
					// current state, so another SSE hint can be coalesced.
				}
				data = ""
			}
		}
		if err := scanner.Err(); err != nil && ctx.Err() == nil {
			errorsCh <- &Error{Op: "subscribe status refresh", URL: endpoint, Err: err}
		}
	}()
	return events, errorsCh, nil
}

func (t *httpTransport) ListRecords(ctx context.Context, opts ListRecordsOptions) (RecordPage, error) {
	values := url.Values{}
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	values.Set("limit", strconv.Itoa(limit))
	direction := opts.Direction
	if direction == "" {
		direction = model.RecordListDirectionDesc
	}
	values.Set("direction", direction)
	setQuery(values, "cursor", opts.Cursor)
	setQuery(values, "batch_id", opts.BatchID)
	setQuery(values, "tenant_id", opts.TenantID)
	setQuery(values, "client_id", opts.ClientID)
	setQuery(values, "level", opts.ProofLevel)
	setQuery(values, "q", opts.Query)
	setQuery(values, "content_hash", opts.ContentHashHex)
	if opts.ReceivedFromUnixN > 0 {
		values.Set("received_from", strconv.FormatInt(opts.ReceivedFromUnixN, 10))
	}
	if opts.ReceivedToUnixN > 0 {
		values.Set("received_to", strconv.FormatInt(opts.ReceivedToUnixN, 10))
	}
	var env recordsEnvelope
	if err := t.getJSON(ctx, "/v2/records", values, &env); err != nil {
		return RecordPage{}, err
	}
	return recordPageFromEnvelope(env), nil
}

func recordPageFromEnvelope(env recordsEnvelope) RecordPage {
	records := env.Records
	if records == nil {
		records = []RecordIndex{}
	}
	return RecordPage{Records: records, Limit: env.Limit, Direction: env.Direction, NextCursor: env.NextCursor}
}

func (t *httpTransport) ListRootsPage(ctx context.Context, opts ListPageOptions) (RootPage, error) {
	values := pageValues(opts)
	var env rootsEnvelope
	if err := t.getJSON(ctx, "/v2/roots", values, &env); err != nil {
		return RootPage{}, err
	}
	return RootPage{Roots: env.Roots, Limit: env.Limit, Direction: env.Direction, NextCursor: env.NextCursor}, nil
}

func (t *httpTransport) ListRoots(ctx context.Context, limit int) ([]BatchRoot, error) {
	page, err := t.ListRootsPage(ctx, ListPageOptions{Limit: limit, Direction: model.RecordListDirectionDesc})
	if err != nil {
		return nil, err
	}
	return page.Roots, nil
}

func (t *httpTransport) ListSTHs(ctx context.Context, opts ListPageOptions) (TreeHeadPage, error) {
	values := pageValues(opts)
	var env sthsEnvelope
	if err := t.getJSON(ctx, "/v2/sth", values, &env); err != nil {
		return TreeHeadPage{}, err
	}
	return TreeHeadPage{STHs: env.STHs, Limit: env.Limit, Direction: env.Direction, NextCursor: env.NextCursor}, nil
}

func (t *httpTransport) ListGlobalLeaves(ctx context.Context, opts ListPageOptions) (GlobalLeafPage, error) {
	values := pageValues(opts)
	var env globalLeavesEnvelope
	if err := t.getJSON(ctx, "/v2/global-log/leaves", values, &env); err != nil {
		return GlobalLeafPage{}, err
	}
	return GlobalLeafPage{Leaves: env.Leaves, Limit: env.Limit, Direction: env.Direction, NextCursor: env.NextCursor}, nil
}

func (t *httpTransport) ListAnchors(ctx context.Context, opts ListPageOptions) (AnchorPage, error) {
	values := pageValues(opts)
	var env anchorsEnvelope
	if err := t.getStrictJSON(ctx, "/v2/anchors/sth", values, &env); err != nil {
		return AnchorPage{}, err
	}
	items := make([]AnchorPageItem, 0, len(env.Anchors))
	for _, item := range env.Anchors {
		if err := validatePublishedAnchorEnvelope("list anchors", t.endpoint("/v2/anchors/sth", values), item); err != nil {
			return AnchorPage{}, err
		}
		items = append(items, AnchorPageItem{
			TreeSize: item.TreeSize,
			Status:   item.Status,
			Result:   item.Result,
		})
	}
	return AnchorPage{Anchors: items, Limit: env.Limit, Direction: env.Direction, NextCursor: env.NextCursor}, nil
}

func (t *httpTransport) LatestRoot(ctx context.Context) (BatchRoot, error) {
	var root model.BatchRoot
	if err := t.getJSON(ctx, "/v2/roots/latest", nil, &root); err != nil {
		return BatchRoot{}, err
	}
	return root, nil
}

func (t *httpTransport) GetProofBundle(ctx context.Context, recordID string) (ProofBundle, error) {
	var env proofEnvelope
	if err := t.getJSON(ctx, "/v2/proofs/"+url.PathEscape(recordID), nil, &env); err != nil {
		return ProofBundle{}, err
	}
	if env.ProofBundle.RecordID == "" {
		return ProofBundle{}, &Error{Op: "get proof bundle", Message: "server returned empty proof bundle"}
	}
	return env.ProofBundle, nil
}

func (t *httpTransport) GetGlobalProof(ctx context.Context, batchID string) (GlobalLogProof, error) {
	var proof model.GlobalLogProof
	if err := t.getJSON(ctx, "/v2/global-log/inclusion/"+url.PathEscape(batchID), nil, &proof); err != nil {
		return GlobalLogProof{}, err
	}
	return proof, nil
}

func (t *httpTransport) GetGlobalEvidence(ctx context.Context, batchID string) (GlobalLogEvidence, error) {
	var evidence model.GlobalLogEvidence
	if err := t.getJSON(ctx, "/v2/global-log/evidence/"+url.PathEscape(batchID), nil, &evidence); err != nil {
		return GlobalLogEvidence{}, err
	}
	return evidence, nil
}

func (t *httpTransport) GetAnchor(ctx context.Context, treeSize uint64) (AnchorStatus, error) {
	var env anchorEnvelope
	path := "/v2/anchors/sth/" + strconv.FormatUint(treeSize, 10)
	if err := t.getStrictJSON(ctx, path, nil, &env); err != nil {
		return AnchorStatus{}, err
	}
	if err := validatePublishedAnchorEnvelope("get anchor", t.endpoint(path, nil), env); err != nil {
		return AnchorStatus{}, err
	}
	return AnchorStatus{TreeSize: env.TreeSize, Status: env.Status, Result: env.Result}, nil
}

func (t *httpTransport) ListAnchorSystems(ctx context.Context) ([]AnchorSystem, error) {
	var response struct {
		Systems []model.AnchorSystem `json:"systems"`
	}
	if err := t.getStrictJSON(ctx, "/v2/anchor-systems", nil, &response); err != nil {
		return nil, err
	}
	if response.Systems == nil {
		response.Systems = []model.AnchorSystem{}
	}
	for _, system := range response.Systems {
		if err := validateAnchorSystem(system); err != nil {
			return nil, err
		}
	}
	return response.Systems, nil
}

func (t *httpTransport) GetAnchorSystem(ctx context.Context, systemID string) (AnchorSystem, error) {
	var system model.AnchorSystem
	path := "/v2/anchor-systems/" + url.PathEscape(systemID)
	if err := t.getStrictJSON(ctx, path, nil, &system); err != nil {
		return AnchorSystem{}, err
	}
	if err := validateAnchorSystem(system); err != nil {
		return AnchorSystem{}, err
	}
	return system, nil
}

func (t *httpTransport) GetAnchorSystemStatus(ctx context.Context, systemID string) (AnchorSystemStatus, error) {
	var status model.AnchorSystemStatus
	path := "/v2/anchor-systems/" + url.PathEscape(systemID) + "/status"
	if err := t.getStrictJSON(ctx, path, nil, &status); err != nil {
		return AnchorSystemStatus{}, err
	}
	if status.SchemaVersion != model.SchemaAnchorSystemStatus || status.SystemID != systemID {
		return AnchorSystemStatus{}, &Error{Op: "get anchor system status", URL: t.endpoint(path, nil), Message: "server returned mismatched anchor system status"}
	}
	return status, nil
}

func (t *httpTransport) ListAnchorSystemResources(ctx context.Context, systemID string, opts AnchorResourceListOptions) (AnchorSystemResourcePage, error) {
	values := url.Values{}
	values.Set("kind", opts.Kind)
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	values.Set("limit", strconv.Itoa(limit))
	setQuery(values, "cursor", opts.Cursor)
	var page model.AnchorSystemResourcePage
	path := "/v2/anchor-systems/" + url.PathEscape(systemID) + "/resources"
	if err := t.getStrictJSON(ctx, path, values, &page); err != nil {
		return AnchorSystemResourcePage{}, err
	}
	for _, resource := range page.Resources {
		if err := validateAnchorResource(systemID, opts.Kind, resource); err != nil {
			return AnchorSystemResourcePage{}, err
		}
	}
	return page, nil
}

func (t *httpTransport) GetAnchorSystemResource(ctx context.Context, systemID, kind, resourceID string) (AnchorSystemResource, error) {
	var resource model.AnchorSystemResource
	path := "/v2/anchor-systems/" + url.PathEscape(systemID) + "/resources/" + url.PathEscape(kind) + "/" + url.PathEscape(resourceID)
	if err := t.getStrictJSON(ctx, path, nil, &resource); err != nil {
		return AnchorSystemResource{}, err
	}
	if err := validateAnchorResource(systemID, kind, resource); err != nil {
		return AnchorSystemResource{}, err
	}
	return resource, nil
}

func validateAnchorSystem(system model.AnchorSystem) error {
	if system.SchemaVersion != model.SchemaAnchorSystem || system.SystemID == "" || system.SinkName == "" || system.Kind == "" {
		return &Error{Op: "decode anchor system", Message: "server returned invalid anchor system descriptor"}
	}
	return nil
}

func validateAnchorResource(systemID, kind string, resource model.AnchorSystemResource) error {
	if resource.SchemaVersion != model.SchemaAnchorSystemResource || resource.SystemID != systemID || resource.Kind != kind || resource.ResourceID == "" {
		return &Error{Op: "decode anchor system resource", Message: "server returned mismatched anchor system resource"}
	}
	return nil
}

func (t *httpTransport) LatestSTH(ctx context.Context) (SignedTreeHead, error) {
	var sth model.SignedTreeHead
	if err := t.getJSON(ctx, "/v2/sth/latest", nil, &sth); err != nil {
		return SignedTreeHead{}, err
	}
	return sth, nil
}

func (t *httpTransport) GetSTH(ctx context.Context, treeSize uint64) (SignedTreeHead, error) {
	var sth model.SignedTreeHead
	if err := t.getJSON(ctx, "/v2/sth/"+strconv.FormatUint(treeSize, 10), nil, &sth); err != nil {
		return SignedTreeHead{}, err
	}
	return sth, nil
}

func (t *httpTransport) MetricsRaw(ctx context.Context) (string, error) {
	raw, err := t.doRaw(ctx, http.MethodGet, "/metrics", nil, nil, "", 1<<20)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (t *httpTransport) getJSON(ctx context.Context, path string, query url.Values, dst any) error {
	return t.doJSON(ctx, http.MethodGet, path, query, nil, "", dst)
}

func (t *httpTransport) getStrictJSON(ctx context.Context, path string, query url.Values, dst any) error {
	raw, err := t.doRaw(ctx, http.MethodGet, path, query, nil, "", 0)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return &Error{Op: http.MethodGet, URL: t.endpoint(path, query), Err: fmt.Errorf("decode json: %w", err)}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return &Error{Op: http.MethodGet, URL: t.endpoint(path, query), Err: fmt.Errorf("decode json: %w", err)}
	}
	return nil
}

func (t *httpTransport) doJSON(ctx context.Context, method, path string, query url.Values, body io.Reader, contentType string, dst any) error {
	raw, err := t.doRaw(ctx, method, path, query, body, contentType, 0)
	if err != nil {
		return err
	}
	if dst == nil {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return &Error{Op: method, URL: t.endpoint(path, query), Err: fmt.Errorf("decode json: %w", err)}
	}
	return nil
}

func (t *httpTransport) doRaw(ctx context.Context, method, path string, query url.Values, body io.Reader, contentType string, limit int64) ([]byte, error) {
	endpoint := t.endpoint(path, query)
	reqCtx, cancel := contextWithDefaultTimeout(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, endpoint, body)
	if err != nil {
		return nil, &Error{Op: method, URL: endpoint, Err: err}
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if t.userAgent != "" {
		req.Header.Set("User-Agent", t.userAgent)
	}
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, &Error{Op: method, URL: endpoint, Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, decodeHTTPError(method, endpoint, resp)
	}
	if limit <= 0 {
		limit = 16 << 20
	}
	raw, err := readAllLimit(resp.Body, limit)
	if err != nil {
		return nil, &Error{Op: method, URL: endpoint, Err: err}
	}
	return raw, nil
}

func (t *httpTransport) endpoint(path string, query url.Values) string {
	endpoint := t.baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	return endpoint
}

func decodeHTTPError(method, endpoint string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	var env struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &env); err == nil && (env.Code != "" || env.Message != "") {
		return &Error{Op: method, URL: endpoint, StatusCode: resp.StatusCode, Code: env.Code, Message: env.Message}
	}
	return &Error{Op: method, URL: endpoint, StatusCode: resp.StatusCode, Message: strings.TrimSpace(string(body))}
}

func setQuery(values url.Values, name, value string) {
	if strings.TrimSpace(value) != "" {
		values.Set(name, value)
	}
}

func readAllLimit(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("response body limit must be positive")
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response body too large: %d > %d", len(body), limit)
	}
	return body, nil
}

func pageValues(opts ListPageOptions) url.Values {
	values := url.Values{}
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	values.Set("limit", strconv.Itoa(limit))
	direction := opts.Direction
	if direction == "" {
		direction = model.RecordListDirectionDesc
	}
	values.Set("direction", direction)
	setQuery(values, "cursor", opts.Cursor)
	return values
}

type submitClaimEnvelope struct {
	RecordID        string          `json:"record_id"`
	Status          string          `json:"status"`
	ProofLevel      string          `json:"proof_level"`
	Idempotent      bool            `json:"idempotent"`
	BatchEnqueued   bool            `json:"batch_enqueued"`
	BatchError      string          `json:"batch_error,omitempty"`
	ServerRecord    ServerRecord    `json:"server_record"`
	AcceptedReceipt AcceptedReceipt `json:"accepted_receipt"`
}

func submitResultFromEnvelope(env submitClaimEnvelope, signed SignedClaim) SubmitResult {
	return SubmitResult{
		RecordID:        env.RecordID,
		Status:          env.Status,
		ProofLevel:      env.ProofLevel,
		Idempotent:      env.Idempotent,
		BatchEnqueued:   env.BatchEnqueued,
		BatchError:      env.BatchError,
		ServerRecord:    env.ServerRecord,
		AcceptedReceipt: env.AcceptedReceipt,
		SignedClaim:     signed,
	}
}

type submitClaimsBatchRequestEnvelope struct {
	Claims []SignedClaim `cbor:"claims" json:"claims"`
}

type submitClaimsBatchEnvelope struct {
	Results   []submitClaimsBatchItemEnvelope `json:"results"`
	Submitted int                             `json:"submitted"`
	Failed    int                             `json:"failed"`
}

type submitClaimsBatchItemEnvelope struct {
	Index  int                       `json:"index"`
	Result *submitClaimEnvelope      `json:"result,omitempty"`
	Error  *submitClaimErrorEnvelope `json:"error,omitempty"`
}

type submitClaimErrorEnvelope struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type proofEnvelope struct {
	RecordID    string      `json:"record_id"`
	ProofLevel  string      `json:"proof_level"`
	ProofBundle ProofBundle `json:"proof_bundle"`
}

type recordsEnvelope struct {
	Records    []RecordIndex `json:"records"`
	Limit      int           `json:"limit"`
	Direction  string        `json:"direction"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

type recordStatusesRequestEnvelope struct {
	RecordIDs []string `json:"record_ids"`
}

type recordStatusesEnvelope struct {
	Statuses         []RecordStatus `json:"statuses"`
	MissingRecordIDs []string       `json:"missing_record_ids,omitempty"`
}

type rootsEnvelope struct {
	Roots      []BatchRoot `json:"roots"`
	Limit      int         `json:"limit"`
	Direction  string      `json:"direction"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

type anchorEnvelope struct {
	TreeSize   uint64           `json:"tree_size"`
	Status     string           `json:"status"`
	ProofLevel string           `json:"proof_level"`
	Result     *STHAnchorResult `json:"result,omitempty"`
}

func validatePublishedAnchorEnvelope(op, endpoint string, env anchorEnvelope) error {
	validPublished := env.Status == model.AnchorStatePublished && env.ProofLevel == ProofLevelL5 &&
		env.Result != nil && env.Result.EvidenceStage == model.AnchorEvidenceStageOfflineVerified
	validObserved := env.Status == model.AnchorStateObserved && env.ProofLevel == ProofLevelL4 &&
		env.Result != nil && env.Result.EvidenceStage == model.AnchorEvidenceStageRaw
	validLocalOnly := env.Status == model.AnchorStateLocalOnly && env.ProofLevel == ProofLevelL4 &&
		env.Result != nil && env.Result.EvidenceStage == model.AnchorEvidenceStageLocalOnly
	if (!validPublished && !validObserved && !validLocalOnly) || env.Result == nil {
		return &Error{Op: op, URL: endpoint, Message: "server returned a non-published or incomplete anchor result"}
	}
	if env.TreeSize == 0 || env.Result.TreeSize != env.TreeSize || env.Result.SchemaVersion != model.SchemaSTHAnchorResult || env.Result.AnchorID == "" {
		return &Error{Op: op, URL: endpoint, Message: "server returned an inconsistent anchor result"}
	}
	return nil
}

type sthsEnvelope struct {
	STHs       []SignedTreeHead `json:"sths"`
	Limit      int              `json:"limit"`
	Direction  string           `json:"direction"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

type globalLeavesEnvelope struct {
	Leaves     []model.GlobalLogLeaf `json:"leaves"`
	Limit      int                   `json:"limit"`
	Direction  string                `json:"direction"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

type anchorsEnvelope struct {
	Anchors    []anchorEnvelope `json:"anchors"`
	Limit      int              `json:"limit"`
	Direction  string           `json:"direction"`
	NextCursor string           `json:"next_cursor,omitempty"`
}
