package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/model"
)

type httpTransport struct {
	baseURL    string
	httpClient *http.Client
	userAgent  string
}

func (t *httpTransport) Endpoint() string {
	return t.baseURL
}

func (t *httpTransport) Close() error {
	if t.httpClient != nil {
		t.httpClient.CloseIdleConnections()
	}
	return nil
}

func (t *httpTransport) CheckHealth(ctx context.Context) HealthStatus {
	start := time.Now()
	var out struct {
		OK bool `json:"ok"`
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
	return HealthStatus{OK: true, ServerURL: t.baseURL, RTTMillis: rtt}
}

func (t *httpTransport) SubmitSignedClaim(ctx context.Context, signed SignedClaim) (SubmitResult, error) {
	body, err := cborx.Marshal(signed)
	if err != nil {
		return SubmitResult{}, err
	}
	var env submitClaimEnvelope
	if err := t.doJSON(ctx, http.MethodPost, "/v1/claims", nil, bytes.NewReader(body), "application/cbor", &env); err != nil {
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
	if err := t.doJSON(ctx, http.MethodPost, "/v1/claims/batch", nil, bytes.NewReader(body), "application/cbor", &env); err != nil {
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
	if err := t.getJSON(ctx, "/v1/records/"+url.PathEscape(recordID), nil, &idx); err != nil {
		return RecordIndex{}, err
	}
	if idx.RecordID == "" {
		return RecordIndex{}, &Error{Op: "get record", Message: "server returned empty record index"}
	}
	return idx, nil
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
	if err := t.getJSON(ctx, "/v1/records", values, &env); err != nil {
		return RecordPage{}, err
	}
	records := make([]RecordIndex, 0, len(env.Records))
	records = append(records, env.Records...)
	return RecordPage{Records: records, Limit: env.Limit, Direction: env.Direction, NextCursor: env.NextCursor}, nil
}

func (t *httpTransport) ListRootsPage(ctx context.Context, opts ListPageOptions) (RootPage, error) {
	values := pageValues(opts)
	var env rootsEnvelope
	if err := t.getJSON(ctx, "/v1/roots", values, &env); err != nil {
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
	if err := t.getJSON(ctx, "/v1/sth", values, &env); err != nil {
		return TreeHeadPage{}, err
	}
	return TreeHeadPage{STHs: env.STHs, Limit: env.Limit, Direction: env.Direction, NextCursor: env.NextCursor}, nil
}

func (t *httpTransport) ListGlobalLeaves(ctx context.Context, opts ListPageOptions) (GlobalLeafPage, error) {
	values := pageValues(opts)
	var env globalLeavesEnvelope
	if err := t.getJSON(ctx, "/v1/global-log/leaves", values, &env); err != nil {
		return GlobalLeafPage{}, err
	}
	return GlobalLeafPage{Leaves: env.Leaves, Limit: env.Limit, Direction: env.Direction, NextCursor: env.NextCursor}, nil
}

func (t *httpTransport) ListAnchors(ctx context.Context, opts ListPageOptions) (AnchorPage, error) {
	values := pageValues(opts)
	var env anchorsEnvelope
	if err := t.getJSON(ctx, "/v1/anchors/sth", values, &env); err != nil {
		return AnchorPage{}, err
	}
	items := make([]AnchorPageItem, 0, len(env.Anchors))
	for _, item := range env.Anchors {
		items = append(items, AnchorPageItem{
			TreeSize: item.TreeSize,
			Status:   item.Status,
			Result:   item.Result,
			Outbox:   item.Outbox,
		})
	}
	return AnchorPage{Anchors: items, Limit: env.Limit, Direction: env.Direction, NextCursor: env.NextCursor}, nil
}

func (t *httpTransport) LatestRoot(ctx context.Context) (BatchRoot, error) {
	var root model.BatchRoot
	if err := t.getJSON(ctx, "/v1/roots/latest", nil, &root); err != nil {
		return BatchRoot{}, err
	}
	return root, nil
}

func (t *httpTransport) GetProofBundle(ctx context.Context, recordID string) (ProofBundle, error) {
	var env proofEnvelope
	if err := t.getJSON(ctx, "/v1/proofs/"+url.PathEscape(recordID), nil, &env); err != nil {
		return ProofBundle{}, err
	}
	if env.ProofBundle.RecordID == "" {
		return ProofBundle{}, &Error{Op: "get proof bundle", Message: "server returned empty proof bundle"}
	}
	return env.ProofBundle, nil
}

func (t *httpTransport) GetGlobalProof(ctx context.Context, batchID string) (GlobalLogProof, error) {
	var proof model.GlobalLogProof
	if err := t.getJSON(ctx, "/v1/global-log/inclusion/"+url.PathEscape(batchID), nil, &proof); err != nil {
		return GlobalLogProof{}, err
	}
	return proof, nil
}

func (t *httpTransport) GetAnchor(ctx context.Context, treeSize uint64) (AnchorStatus, error) {
	var env anchorEnvelope
	if err := t.getJSON(ctx, "/v1/anchors/sth/"+strconv.FormatUint(treeSize, 10), nil, &env); err != nil {
		return AnchorStatus{}, err
	}
	return AnchorStatus{TreeSize: env.TreeSize, Status: env.Status, Result: env.Result}, nil
}

func (t *httpTransport) LatestSTH(ctx context.Context) (SignedTreeHead, error) {
	var sth model.SignedTreeHead
	if err := t.getJSON(ctx, "/v1/sth/latest", nil, &sth); err != nil {
		return SignedTreeHead{}, err
	}
	return sth, nil
}

func (t *httpTransport) GetSTH(ctx context.Context, treeSize uint64) (SignedTreeHead, error) {
	var sth model.SignedTreeHead
	if err := t.getJSON(ctx, "/v1/sth/"+strconv.FormatUint(treeSize, 10), nil, &sth); err != nil {
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

type rootsEnvelope struct {
	Roots      []BatchRoot `json:"roots"`
	Limit      int         `json:"limit"`
	Direction  string      `json:"direction"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

type anchorEnvelope struct {
	TreeSize uint64                     `json:"tree_size"`
	Status   string                     `json:"status"`
	Result   *STHAnchorResult           `json:"result,omitempty"`
	Outbox   *model.STHAnchorOutboxItem `json:"outbox,omitempty"`
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
