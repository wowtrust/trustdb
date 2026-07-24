package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/ingest"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/prooflevel"
	"github.com/wowtrust/trustdb/internal/statusnotify"
	"github.com/wowtrust/trustdb/internal/submission"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"github.com/wowtrust/trustdb/transporttls"
)

const (
	maxClaimBytes             = 1 << 20
	maxClaimBatchBytes        = 16 << 20
	maxClaimBatchItems        = 1000
	maxClaimBatchWorkers      = 64
	maxClaimCBORMapPairs      = 4096
	maxPooledRequestBodyBytes = maxClaimBytes
)

var requestBodyBufferPool = sync.Pool{New: func() any { return new([]byte) }}

type Handler struct {
	CryptoSuite   cryptosuite.ID
	Submitter     submission.Submitter
	Batch         BatchService
	Global        GlobalLogService
	Anchors       AnchorService
	AnchorSystems AnchorSystemService
	Metrics       http.Handler
	Statuses      RecordStatusService
	StatusHub     *statusnotify.Hub
}

type cryptoSuiteProvider interface {
	CryptoSuite() cryptosuite.ID
}

type BatchService interface {
	Enqueue(context.Context, model.SignedClaim, model.ServerRecord, model.AcceptedReceipt) error
	Proof(context.Context, string) (model.ProofBundle, error)
	RecordIndex(context.Context, string) (model.RecordIndex, bool, error)
	Records(context.Context, model.RecordListOptions) ([]model.RecordIndex, error)
	Roots(context.Context, int) ([]model.BatchRoot, error)
	RootsAfter(context.Context, int64, int) ([]model.BatchRoot, error)
	RootsPage(context.Context, model.RootListOptions) ([]model.BatchRoot, error)
	LatestRoot(context.Context) (model.BatchRoot, error)
	Manifest(context.Context, string) (model.BatchManifest, error)
	BatchTreeLeaves(context.Context, model.BatchTreeLeafListOptions) ([]model.BatchTreeLeaf, error)
	BatchTreeNodes(context.Context, model.BatchTreeNodeListOptions) ([]model.BatchTreeNode, error)
}

type RecordStatusService interface {
	RecordStatus(context.Context, string) (model.RecordStatus, bool, error)
	RecordStatuses(context.Context, []string) ([]model.RecordStatus, error)
}

// AnchorService exposes immutable L5 publication evidence only. Mutable
// scheduler state is intentionally not part of the public API.
type AnchorService interface {
	AnchorResult(context.Context, uint64) (model.STHAnchorResult, bool, error)
	Anchors(context.Context, model.AnchorListOptions) ([]model.STHAnchorResult, error)
}

// AnchorSystemService exposes mutable discovery and read-only explorer data.
// It is deliberately separate from AnchorService's immutable L5 evidence.
type AnchorSystemService interface {
	Systems(context.Context) ([]model.AnchorSystem, error)
	System(context.Context, string) (model.AnchorSystem, bool, error)
	Status(context.Context, string) (model.AnchorSystemStatus, bool, error)
	Resources(context.Context, string, model.AnchorResourceListOptions) (model.AnchorSystemResourcePage, bool, error)
	Resource(context.Context, string, string, string) (model.AnchorSystemResource, bool, error)
}

type GlobalLogService interface {
	LatestSTH(context.Context) (model.SignedTreeHead, bool, error)
	STH(context.Context, uint64) (model.SignedTreeHead, bool, error)
	ListSTHs(context.Context, model.TreeHeadListOptions) ([]model.SignedTreeHead, error)
	ListLeaves(context.Context, model.GlobalLeafListOptions) ([]model.GlobalLogLeaf, error)
	State(context.Context) (model.GlobalLogState, bool, error)
	Node(context.Context, uint64, uint64) (model.GlobalLogNode, bool, error)
	ListNodesAfter(context.Context, uint64, uint64, int) ([]model.GlobalLogNode, error)
	InclusionProof(context.Context, string, uint64) (model.GlobalLogProof, error)
	ConsistencyProof(context.Context, uint64, uint64) (model.GlobalConsistencyProof, error)
}

type GlobalEvidenceService interface {
	Evidence(context.Context, string) (model.GlobalLogEvidence, error)
}

type healthResponse struct {
	OK                bool   `json:"ok"`
	TransportSecurity string `json:"transport_security"`
	TLSVersion        string `json:"tls_version,omitempty"`
	PeerAuthenticated bool   `json:"peer_authenticated"`
	PeerSubject       string `json:"peer_subject,omitempty"`
}

type submitClaimResponse struct {
	RecordID        string                `json:"record_id"`
	Status          string                `json:"status"`
	ProofLevel      string                `json:"proof_level"`
	Idempotent      bool                  `json:"idempotent"`
	BatchEnqueued   bool                  `json:"batch_enqueued"`
	BatchError      string                `json:"batch_error,omitempty"`
	ServerRecord    model.ServerRecord    `json:"server_record"`
	AcceptedReceipt model.AcceptedReceipt `json:"accepted_receipt"`
}

type submitClaimsBatchRequest struct {
	Claims []model.SignedClaim `cbor:"claims" json:"claims"`
}

type submitClaimsBatchResponse struct {
	Results   []submitClaimsBatchItemResponse `json:"results"`
	Submitted int                             `json:"submitted"`
	Failed    int                             `json:"failed"`
}

type submitClaimsBatchItemResponse struct {
	Index  int                  `json:"index"`
	Result *submitClaimResponse `json:"result,omitempty"`
	Error  *errorResponse       `json:"error,omitempty"`
}

type proofResponse struct {
	RecordID    string            `json:"record_id"`
	ProofLevel  string            `json:"proof_level"`
	ProofBundle model.ProofBundle `json:"proof_bundle"`
}

type rootsResponse struct {
	Roots      []model.BatchRoot `json:"roots"`
	Limit      int               `json:"limit"`
	Direction  string            `json:"direction"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

type batchResponse struct {
	Root        model.BatchRoot     `json:"root"`
	Manifest    model.BatchManifest `json:"manifest"`
	RecordCount int                 `json:"record_count"`
}

type batchLeavesResponse struct {
	Leaves     []model.BatchTreeLeaf `json:"leaves"`
	Limit      int                   `json:"limit"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

type batchNodesResponse struct {
	Nodes      []model.BatchTreeNode `json:"nodes"`
	Limit      int                   `json:"limit"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

type recordsResponse struct {
	Records    []model.RecordIndex `json:"records"`
	Limit      int                 `json:"limit"`
	Direction  string              `json:"direction"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

type recordStatusesRequest struct {
	RecordIDs []string `json:"record_ids"`
}

type recordStatusesResponse struct {
	Statuses         []model.RecordStatus `json:"statuses"`
	MissingRecordIDs []string             `json:"missing_record_ids,omitempty"`
}

type sthsResponse struct {
	STHs       []model.SignedTreeHead `json:"sths"`
	Limit      int                    `json:"limit"`
	Direction  string                 `json:"direction"`
	NextCursor string                 `json:"next_cursor,omitempty"`
}

type globalLeavesResponse struct {
	Leaves     []model.GlobalLogLeaf `json:"leaves"`
	Limit      int                   `json:"limit"`
	Direction  string                `json:"direction"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

type globalTreeResponse struct {
	STH   *model.SignedTreeHead `json:"sth,omitempty"`
	State model.GlobalLogState  `json:"state"`
	OK    bool                  `json:"ok"`
}

type globalNodesResponse struct {
	Nodes      []model.GlobalLogNode `json:"nodes"`
	Limit      int                   `json:"limit"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

type anchorsResponse struct {
	Anchors    []anchorResponse `json:"anchors"`
	Limit      int              `json:"limit"`
	Direction  string           `json:"direction"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

type anchorResponse struct {
	TreeSize   uint64                 `json:"tree_size"`
	Status     string                 `json:"status"`
	ProofLevel string                 `json:"proof_level"`
	Result     *model.STHAnchorResult `json:"result,omitempty"`
}

type anchorSystemsResponse struct {
	Systems []model.AnchorSystem `json:"systems"`
}

type errorResponse struct {
	Code    trusterr.Code `json:"code"`
	Message string        `json:"message"`
}

func New(ingestSvc *ingest.Service, metrics http.Handler, batchSvc ...BatchService) http.Handler {
	h := Handler{Metrics: metrics}
	if len(batchSvc) > 0 {
		h.Batch = batchSvc[0]
	}
	h.Submitter = submission.New(ingestSvc, h.Batch)
	return buildMux(h)
}

// NewWithAnchors is the richer constructor used by serve when the L5
// anchor service is wired up. It is kept separate from New so existing
// callers (tests, CLIs, backwards-compatible fixtures) do not need to
// learn about the anchor API when they don't need it.
func NewWithAnchors(ingestSvc *ingest.Service, metrics http.Handler, batchSvc BatchService, anchorSvc AnchorService) http.Handler {
	return buildMux(Handler{
		Submitter: submission.New(ingestSvc, batchSvc),
		Batch:     batchSvc,
		Anchors:   anchorSvc,
		Metrics:   metrics,
	})
}

func NewWithGlobalAndAnchors(
	ingestSvc *ingest.Service,
	metrics http.Handler,
	batchSvc BatchService,
	globalSvc GlobalLogService,
	anchorSvc AnchorService,
) http.Handler {
	return NewWithSubmitterAndGlobalAndAnchors(
		submission.New(ingestSvc, batchSvc),
		metrics,
		batchSvc,
		globalSvc,
		anchorSvc,
	)
}

// NewWithSubmitterAndGlobalAndAnchors wires a transport-independent submitter
// shared with other ingress transports while retaining the batch service for
// proof and record query endpoints.
func NewWithSubmitterAndGlobalAndAnchors(
	submitter submission.Submitter,
	metrics http.Handler,
	batchSvc BatchService,
	globalSvc GlobalLogService,
	anchorSvc AnchorService,
	statusHub ...*statusnotify.Hub,
) http.Handler {
	return NewWithSubmitterGlobalAnchorsAndSystems(submitter, metrics, batchSvc, globalSvc, anchorSvc, nil, statusHub...)
}

func NewWithSubmitterGlobalAnchorsAndSystems(
	submitter submission.Submitter,
	metrics http.Handler,
	batchSvc BatchService,
	globalSvc GlobalLogService,
	anchorSvc AnchorService,
	anchorSystems AnchorSystemService,
	statusHub ...*statusnotify.Hub,
) http.Handler {
	h := Handler{
		Submitter:     submitter,
		Batch:         batchSvc,
		Global:        globalSvc,
		Anchors:       anchorSvc,
		AnchorSystems: anchorSystems,
		Metrics:       metrics,
	}
	if statuses, ok := batchSvc.(RecordStatusService); ok {
		h.Statuses = statuses
	}
	if len(statusHub) > 0 {
		h.StatusHub = statusHub[0]
	}
	return buildMux(h)
}

func buildMux(h Handler) http.Handler {
	h = normalizeHandler(h)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("POST /v2/claims", h.submitClaim)
	mux.HandleFunc("POST /v2/claims/batch", h.submitClaimsBatch)
	mux.HandleFunc("GET /v2/records", h.listRecords)
	mux.HandleFunc("GET /v2/records/{record_id}", h.getRecordIndex)
	if h.Statuses != nil {
		mux.HandleFunc("GET /v2/records/{record_id}/status", h.getRecordStatus)
		mux.HandleFunc("POST /v2/records/status:batchGet", h.getRecordStatuses)
	}
	if h.StatusHub != nil && h.Statuses != nil {
		mux.HandleFunc("POST /v2/status-subscriptions", h.createStatusSubscription)
		mux.HandleFunc("DELETE /v2/status-subscriptions/{subscription_id}", h.deleteStatusSubscription)
		mux.HandleFunc("GET /v2/status-subscriptions/{subscription_id}/statuses", h.getSubscriptionStatuses)
		mux.HandleFunc("GET /v2/status-subscriptions/{subscription_id}/events", h.streamStatusSubscription)
	}
	mux.HandleFunc("GET /v2/proofs/{record_id}", h.getProof)
	mux.HandleFunc("GET /v2/roots", h.listRoots)
	mux.HandleFunc("GET /v2/roots/latest", h.latestRoot)
	mux.HandleFunc("GET /v2/batches", h.listRoots)
	mux.HandleFunc("GET /v2/batches/{batch_id}", h.getBatch)
	mux.HandleFunc("GET /v2/batches/{batch_id}/tree/leaves", h.listBatchTreeLeaves)
	mux.HandleFunc("GET /v2/batches/{batch_id}/tree/nodes", h.listBatchTreeNodes)
	if h.Global != nil {
		mux.HandleFunc("GET /v2/sth", h.listSTHs)
		mux.HandleFunc("GET /v2/sth/latest", h.latestSTH)
		mux.HandleFunc("GET /v2/sth/{tree_size}", h.getSTH)
		mux.HandleFunc("GET /v2/global-log/leaves", h.listGlobalLeaves)
		mux.HandleFunc("GET /v2/global-log/tree", h.getGlobalTree)
		mux.HandleFunc("GET /v2/global-log/tree/nodes", h.listGlobalTreeNodes)
		mux.HandleFunc("GET /v2/global-log/tree/leaves", h.listGlobalLeaves)
		mux.HandleFunc("GET /v2/global-log/inclusion/{batch_id}", h.getGlobalInclusion)
		mux.HandleFunc("GET /v2/global-log/evidence/{batch_id}", h.getGlobalEvidence)
		mux.HandleFunc("GET /v2/global-log/consistency", h.getGlobalConsistency)
	}
	if h.Anchors != nil {
		mux.HandleFunc("GET /v2/anchors/sth", h.listAnchors)
		mux.HandleFunc("GET /v2/anchors/sth/{tree_size}", h.getAnchor)
	}
	if h.AnchorSystems != nil {
		mux.HandleFunc("GET /v2/anchor-systems", h.listAnchorSystems)
		mux.HandleFunc("GET /v2/anchor-systems/{system_id}", h.getAnchorSystem)
		mux.HandleFunc("GET /v2/anchor-systems/{system_id}/status", h.getAnchorSystemStatus)
		mux.HandleFunc("GET /v2/anchor-systems/{system_id}/resources", h.listAnchorSystemResources)
		mux.HandleFunc("GET /v2/anchor-systems/{system_id}/resources/{kind}/{resource_id}", h.getAnchorSystemResource)
	}
	if h.Metrics != nil {
		mux.Handle("GET /metrics", h.Metrics)
	}
	return mux
}

func normalizeHandler(h Handler) Handler {
	if isTypedNil(h.Submitter) {
		h.Submitter = nil
	}
	if isTypedNil(h.Batch) {
		h.Batch = nil
	}
	if isTypedNil(h.Global) {
		h.Global = nil
	}
	if isTypedNil(h.Anchors) {
		h.Anchors = nil
	}
	if isTypedNil(h.AnchorSystems) {
		h.AnchorSystems = nil
	}
	if isTypedNil(h.Statuses) {
		h.Statuses = nil
	}
	if h.Statuses == nil && h.Batch != nil {
		if statuses, ok := h.Batch.(RecordStatusService); ok && !isTypedNil(statuses) {
			h.Statuses = statuses
		}
	}
	if h.CryptoSuite == "" && h.Batch != nil {
		if provider, ok := h.Batch.(cryptoSuiteProvider); ok {
			h.CryptoSuite = provider.CryptoSuite()
		}
	}
	if h.StatusHub == nil {
		h.StatusHub = nil
	}
	return h
}

func isTypedNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func (h Handler) health(w http.ResponseWriter, r *http.Request) {
	response := healthResponse{OK: true, TransportSecurity: transporttls.ModePlaintext}
	if r.TLS != nil {
		response.TransportSecurity = transporttls.ModeTLS
		response.TLSVersion = transporttls.VersionName(r.TLS.Version)
	}
	if identity, ok := transporttls.PeerIdentityFromContext(r.Context()); ok {
		response.TransportSecurity = transporttls.ModeMTLS
		response.PeerAuthenticated = true
		response.PeerSubject = identity.Subject
	}
	writeJSON(w, http.StatusOK, response)
}

func (h Handler) submitClaim(w http.ResponseWriter, r *http.Request) {
	var signed model.SignedClaim
	if err := decodeCBORRequest(r.Body, r.ContentLength, maxClaimBytes, &signed); err != nil {
		writeError(w, trusterr.Wrap(trusterr.CodeInvalidArgument, "decode signed claim", err))
		return
	}
	resp, err := h.submitSignedClaim(r.Context(), signed)
	if err != nil {
		writeError(w, err)
		return
	}
	status := http.StatusAccepted
	if resp.Idempotent {
		status = http.StatusOK
	}
	writeJSON(w, status, resp)
}

func (h Handler) submitClaimsBatch(w http.ResponseWriter, r *http.Request) {
	var req submitClaimsBatchRequest
	if err := decodeCBORRequest(r.Body, r.ContentLength, maxClaimBatchBytes, &req); err != nil {
		writeError(w, trusterr.Wrap(trusterr.CodeInvalidArgument, "decode signed claim batch", err))
		return
	}
	if len(req.Claims) == 0 {
		writeError(w, trusterr.New(trusterr.CodeInvalidArgument, "claims batch must contain at least one claim"))
		return
	}
	if len(req.Claims) > maxClaimBatchItems {
		writeError(w, trusterr.New(trusterr.CodeInvalidArgument, "claims batch exceeds 1000 claims"))
		return
	}

	resp := submitClaimsBatchResponse{Results: make([]submitClaimsBatchItemResponse, len(req.Claims))}
	workers := len(req.Claims)
	if workers > maxClaimBatchWorkers {
		workers = maxClaimBatchWorkers
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	wg.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wg.Done()
			for index := range jobs {
				item := submitClaimsBatchItemResponse{Index: index}
				result, err := h.submitSignedClaim(r.Context(), req.Claims[index])
				if err != nil {
					item.Error = errorPayload(err)
				} else {
					item.Result = &result
				}
				resp.Results[index] = item
			}
		}()
	}
	for index := range req.Claims {
		select {
		case jobs <- index:
		case <-r.Context().Done():
			close(jobs)
			wg.Wait()
			writeError(w, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "request context canceled", r.Context().Err()))
			return
		}
	}
	close(jobs)
	wg.Wait()

	for _, item := range resp.Results {
		if item.Error != nil {
			resp.Failed++
			continue
		}
		resp.Submitted++
	}
	status := http.StatusAccepted
	if resp.Failed > 0 {
		status = http.StatusMultiStatus
	}
	writeJSON(w, status, resp)
}

func decodeCBORRequest(body io.Reader, contentLength int64, maxBytes int, out any) error {
	if contentLength > int64(maxBytes) {
		return &http.MaxBytesError{Limit: int64(maxBytes)}
	}
	if contentLength >= 0 && contentLength <= int64(maxPooledRequestBodyBytes) {
		buffer := acquireRequestBodyBuffer(int(contentLength))
		defer releaseRequestBodyBuffer(buffer)
		if err := readKnownLengthRequestBody(body, contentLength, *buffer); err != nil {
			return err
		}
		return cborx.UnmarshalLimits(*buffer, out, maxBytes, maxClaimBatchItems, maxClaimCBORMapPairs)
	}
	raw, err := readBoundedRequestBody(body, contentLength, maxBytes)
	if err != nil {
		return err
	}
	return cborx.UnmarshalLimits(raw, out, maxBytes, maxClaimBatchItems, maxClaimCBORMapPairs)
}

func decodeJSONRequest(body io.Reader, maxBytes int64, out any) error {
	decoder := json.NewDecoder(io.LimitReader(body, maxBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("request contains multiple JSON values")
		}
		return err
	}
	return nil
}

func acquireRequestBodyBuffer(size int) *[]byte {
	buffer := requestBodyBufferPool.Get().(*[]byte)
	if cap(*buffer) < size {
		*buffer = make([]byte, size)
	} else {
		*buffer = (*buffer)[:size]
	}
	return buffer
}

func releaseRequestBodyBuffer(buffer *[]byte) {
	if buffer == nil || cap(*buffer) > maxPooledRequestBodyBytes {
		return
	}
	*buffer = (*buffer)[:0]
	requestBodyBufferPool.Put(buffer)
}

func readKnownLengthRequestBody(body io.Reader, contentLength int64, raw []byte) error {
	if _, err := io.ReadFull(body, raw); err != nil {
		return err
	}
	var extra [1]byte
	if n, err := io.ReadFull(body, extra[:]); n > 0 {
		return fmt.Errorf("http: request body exceeds content length %d", contentLength)
	} else if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return err
	}
	return nil
}

func readBoundedRequestBody(body io.Reader, contentLength int64, maxBytes int) ([]byte, error) {
	if contentLength > int64(maxBytes) {
		return nil, &http.MaxBytesError{Limit: int64(maxBytes)}
	}
	if contentLength >= 0 {
		raw := make([]byte, int(contentLength))
		if err := readKnownLengthRequestBody(body, contentLength, raw); err != nil {
			return nil, err
		}
		return raw, nil
	}
	raw, err := io.ReadAll(io.LimitReader(body, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBytes {
		return nil, &http.MaxBytesError{Limit: int64(maxBytes)}
	}
	return raw, nil
}

func (h Handler) submitSignedClaim(ctx context.Context, signed model.SignedClaim) (submitClaimResponse, error) {
	if h.Submitter == nil {
		return submitClaimResponse{}, trusterr.New(trusterr.CodeFailedPrecondition, "ingest service is not configured")
	}
	outcome, err := h.Submitter.Submit(ctx, signed)
	if err != nil {
		return submitClaimResponse{}, err
	}
	return submitClaimResponse{
		RecordID:        outcome.RecordID,
		Status:          outcome.Status,
		ProofLevel:      outcome.ProofLevel,
		Idempotent:      outcome.Idempotent,
		BatchEnqueued:   outcome.BatchEnqueued,
		BatchError:      outcome.BatchError,
		ServerRecord:    outcome.ServerRecord,
		AcceptedReceipt: outcome.AcceptedReceipt,
	}, nil
}

func (h Handler) getProof(w http.ResponseWriter, r *http.Request) {
	if h.Batch == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "batch service is not configured"))
		return
	}
	recordID := r.PathValue("record_id")
	bundle, err := h.Batch.Proof(r.Context(), recordID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proofResponse{
		RecordID:    bundle.RecordID,
		ProofLevel:  prooflevel.L3.String(),
		ProofBundle: bundle,
	})
}

func (h Handler) getRecordIndex(w http.ResponseWriter, r *http.Request) {
	if h.Batch == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "batch service is not configured"))
		return
	}
	idx, ok, err := h.Batch.RecordIndex(r.Context(), r.PathValue("record_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	if !ok {
		writeError(w, trusterr.New(trusterr.CodeNotFound, "record index not found"))
		return
	}
	writeJSON(w, http.StatusOK, idx)
}

func (h Handler) getRecordStatus(w http.ResponseWriter, r *http.Request) {
	status, found, err := h.Statuses.RecordStatus(r.Context(), r.PathValue("record_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	if !found {
		writeError(w, trusterr.New(trusterr.CodeNotFound, "record status not found"))
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (h Handler) getRecordStatuses(w http.ResponseWriter, r *http.Request) {
	var request recordStatusesRequest
	if err := decodeJSONRequest(r.Body, 1<<20, &request); err != nil {
		writeError(w, trusterr.Wrap(trusterr.CodeInvalidArgument, "decode record status batch", err))
		return
	}
	h.writeRecordStatuses(w, r, request.RecordIDs)
}

func (h Handler) createStatusSubscription(w http.ResponseWriter, r *http.Request) {
	var request statusnotify.CreateRequest
	if err := decodeJSONRequest(r.Body, 1<<20, &request); err != nil {
		writeError(w, trusterr.Wrap(trusterr.CodeInvalidArgument, "decode status subscription", err))
		return
	}
	// Authenticate and bound the request before performing the selected-record
	// lookups. Otherwise an unsigned request could amplify one HTTP call into up
	// to maxRecordIDs proofstore reads.
	if err := h.StatusHub.ValidateCreateRequest(request); err != nil {
		writeError(w, err)
		return
	}
	recordIDs, err := normalizeStatusRecordIDs(request.RecordIDs)
	if err != nil {
		writeError(w, err)
		return
	}
	statuses, err := h.Statuses.RecordStatuses(r.Context(), recordIDs)
	if err != nil {
		writeError(w, err)
		return
	}
	if len(statuses) != len(recordIDs) {
		writeError(w, trusterr.New(trusterr.CodeNotFound, "one or more subscribed record_ids were not found"))
		return
	}
	for i := range statuses {
		if statuses[i].TenantID != strings.TrimSpace(request.TenantID) || statuses[i].ClientID != strings.TrimSpace(request.ClientID) {
			writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "subscribed record does not belong to the upstream identity"))
			return
		}
	}
	subscription, err := h.StatusHub.Create(r.Context(), request)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, subscription)
}

func normalizeStatusRecordIDs(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 1000 {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "record_ids must contain between 1 and 1000 items")
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "record_id must not be empty")
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out, nil
}

func (h Handler) deleteStatusSubscription(w http.ResponseWriter, r *http.Request) {
	if err := h.StatusHub.Delete(r.Context(), r.PathValue("subscription_id")); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h Handler) getSubscriptionStatuses(w http.ResponseWriter, r *http.Request) {
	subscription, found := h.StatusHub.Get(r.PathValue("subscription_id"))
	if !found {
		writeError(w, trusterr.New(trusterr.CodeNotFound, "status subscription not found"))
		return
	}
	h.writeRecordStatuses(w, r, subscription.RecordIDs)
}

func (h Handler) writeRecordStatuses(w http.ResponseWriter, r *http.Request, recordIDs []string) {
	recordIDs, err := normalizeStatusRecordIDs(recordIDs)
	if err != nil {
		writeError(w, err)
		return
	}
	statuses, err := h.Statuses.RecordStatuses(r.Context(), recordIDs)
	if err != nil {
		writeError(w, err)
		return
	}
	found := make(map[string]struct{}, len(statuses))
	for i := range statuses {
		found[statuses[i].RecordID] = struct{}{}
	}
	missing := make([]string, 0)
	for _, recordID := range recordIDs {
		if _, ok := found[recordID]; !ok {
			missing = append(missing, recordID)
		}
	}
	writeJSON(w, http.StatusOK, recordStatusesResponse{Statuses: statuses, MissingRecordIDs: missing})
}

func (h Handler) streamStatusSubscription(w http.ResponseWriter, r *http.Request) {
	events, cancel, err := h.StatusHub.Watch(r.PathValue("subscription_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Time{})
	if _, err := io.WriteString(w, ": trustdb status stream\n\n"); err != nil {
		return
	}
	if err := controller.Flush(); err != nil {
		return
	}
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case notification, ok := <-events:
			if !ok {
				return
			}
			data, err := json.Marshal(notification)
			if err != nil {
				return
			}
			if _, err := fmt.Fprintf(w, "id: %d\nevent: refresh_required\ndata: %s\n\n", notification.Version, data); err != nil {
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
		case <-keepalive.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
		}
	}
}

func (h Handler) listRecords(w http.ResponseWriter, r *http.Request) {
	if h.Batch == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "batch service is not configured"))
		return
	}
	opts, err := parseRecordListOptions(r, h.CryptoSuite)
	if err != nil {
		writeError(w, err)
		return
	}
	records, err := h.Batch.Records(r.Context(), opts)
	if err != nil {
		writeError(w, err)
		return
	}
	next := ""
	if len(records) == opts.Limit {
		next = encodeRecordCursor(records[len(records)-1])
	}
	writeJSON(w, http.StatusOK, recordsResponse{
		Records:    records,
		Limit:      opts.Limit,
		Direction:  opts.Direction,
		NextCursor: next,
	})
}

func (h Handler) listRoots(w http.ResponseWriter, r *http.Request) {
	if h.Batch == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "batch service is not configured"))
		return
	}
	opts, err := parseRootListOptions(r)
	if err != nil {
		writeError(w, err)
		return
	}
	roots, err := h.Batch.RootsPage(r.Context(), opts)
	if err != nil {
		writeError(w, err)
		return
	}
	next := ""
	if len(roots) == opts.Limit {
		next = encodeRootCursor(roots[len(roots)-1])
	}
	writeJSON(w, http.StatusOK, rootsResponse{Roots: roots, Limit: opts.Limit, Direction: opts.Direction, NextCursor: next})
}

func (h Handler) getBatch(w http.ResponseWriter, r *http.Request) {
	if h.Batch == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "batch service is not configured"))
		return
	}
	batchID := strings.TrimSpace(r.PathValue("batch_id"))
	if batchID == "" {
		writeError(w, trusterr.New(trusterr.CodeInvalidArgument, "batch_id is required"))
		return
	}
	manifest, err := h.Batch.Manifest(r.Context(), batchID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, batchResponse{
		Root: model.BatchRoot{
			SchemaVersion: model.SchemaBatchRoot,
			CryptoSuite:   manifest.CryptoSuite,
			BatchID:       manifest.BatchID,
			NodeID:        manifest.NodeID,
			LogID:         manifest.LogID,
			BatchRoot:     append([]byte(nil), manifest.BatchRoot...),
			TreeSize:      manifest.TreeSize,
			ClosedAtUnixN: manifest.ClosedAtUnixN,
		},
		Manifest:    manifest,
		RecordCount: len(manifest.RecordIDs),
	})
}

func (h Handler) listBatchTreeLeaves(w http.ResponseWriter, r *http.Request) {
	if h.Batch == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "batch service is not configured"))
		return
	}
	opts, err := parseBatchTreeLeafListOptions(r, r.PathValue("batch_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	leaves, err := h.Batch.BatchTreeLeaves(r.Context(), opts)
	if err != nil {
		writeError(w, err)
		return
	}
	if len(leaves) == 0 && !opts.HasAfter {
		if err := h.requireBatchTreeIndex(r.Context(), opts.BatchID); err != nil {
			writeError(w, err)
			return
		}
	}
	next := ""
	if len(leaves) == opts.Limit {
		next = encodeUint64Cursor(leaves[len(leaves)-1].LeafIndex)
	}
	writeJSON(w, http.StatusOK, batchLeavesResponse{Leaves: leaves, Limit: opts.Limit, NextCursor: next})
}

func (h Handler) listBatchTreeNodes(w http.ResponseWriter, r *http.Request) {
	if h.Batch == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "batch service is not configured"))
		return
	}
	opts, err := parseBatchTreeNodeListOptions(r, r.PathValue("batch_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	nodes, err := h.Batch.BatchTreeNodes(r.Context(), opts)
	if err != nil {
		writeError(w, err)
		return
	}
	if len(nodes) == 0 && !opts.HasAfter {
		if err := h.requireBatchTreeIndex(r.Context(), opts.BatchID); err != nil {
			writeError(w, err)
			return
		}
	}
	next := ""
	if len(nodes) == opts.Limit {
		next = encodeUint64Cursor(nodes[len(nodes)-1].StartIndex)
	}
	writeJSON(w, http.StatusOK, batchNodesResponse{Nodes: nodes, Limit: opts.Limit, NextCursor: next})
}

func (h Handler) requireBatchTreeIndex(ctx context.Context, batchID string) error {
	probe, err := h.Batch.BatchTreeLeaves(ctx, model.BatchTreeLeafListOptions{BatchID: batchID, Limit: 1})
	if err != nil {
		return err
	}
	if len(probe) > 0 {
		return nil
	}
	manifest, err := h.Batch.Manifest(ctx, batchID)
	if err != nil {
		return err
	}
	if len(manifest.RecordIDs) > 0 || manifest.TreeSize > 0 {
		return trusterr.New(trusterr.CodeFailedPrecondition, "batch tree index is not available for this batch")
	}
	return nil
}

func parseRecordListOptions(r *http.Request, suiteID cryptosuite.ID) (model.RecordListOptions, error) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > 1000 {
			return model.RecordListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "limit must be between 1 and 1000")
		}
		limit = parsed
	}
	direction := r.URL.Query().Get("direction")
	switch direction {
	case "":
		direction = model.RecordListDirectionDesc
	case model.RecordListDirectionAsc, model.RecordListDirectionDesc:
	default:
		return model.RecordListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "direction must be asc or desc")
	}
	opts := model.RecordListOptions{
		Limit:      limit,
		Direction:  direction,
		BatchID:    r.URL.Query().Get("batch_id"),
		TenantID:   r.URL.Query().Get("tenant_id"),
		ClientID:   r.URL.Query().Get("client_id"),
		ProofLevel: strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("level"))),
		Query:      strings.TrimSpace(r.URL.Query().Get("q")),
	}
	if opts.ProofLevel != "" && model.NormalizedProofLevel(opts.ProofLevel) == "" {
		return model.RecordListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "level must be one of L1-L5")
	}
	opts.ProofLevel = model.NormalizedProofLevel(opts.ProofLevel)
	if opts.BatchID == "" && strings.HasPrefix(strings.ToLower(opts.Query), "batch-") {
		opts.BatchID = opts.Query
		opts.Query = ""
	}
	hashRaw := strings.TrimSpace(r.URL.Query().Get("content_hash"))
	if hashRaw != "" {
		hash, err := parseContentHashHex(hashRaw, suiteID)
		if err != nil {
			return model.RecordListOptions{}, err
		}
		opts.ContentHash = hash
	}
	if opts.Query != "" && model.RecordStorageQueryToken(opts.Query) == "" {
		return model.RecordListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "q must contain at least two letters or digits")
	}
	from, err := parseRecordTimeQuery(r, "received_from", "created_from", "from")
	if err != nil {
		return model.RecordListOptions{}, err
	}
	to, err := parseRecordTimeQuery(r, "received_to", "created_to", "to")
	if err != nil {
		return model.RecordListOptions{}, err
	}
	if from > 0 && to > 0 && from > to {
		return model.RecordListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "received_from must be <= received_to")
	}
	opts.ReceivedFromUnixN = from
	opts.ReceivedToUnixN = to
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		cursor, err := decodeRecordCursor(raw)
		if err != nil {
			return model.RecordListOptions{}, err
		}
		opts.AfterReceivedAtUnixN = cursor.ReceivedAtUnixN
		opts.AfterRecordID = cursor.RecordID
	}
	return opts, nil
}

func parseRootListOptions(r *http.Request) (model.RootListOptions, error) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > 1000 {
			return model.RootListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "limit must be between 1 and 1000")
		}
		limit = parsed
	}
	direction, err := parseDirection(r.URL.Query().Get("direction"))
	if err != nil {
		return model.RootListOptions{}, err
	}
	opts := model.RootListOptions{Limit: limit, Direction: direction}
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		cursor, err := decodeRootCursor(raw)
		if err != nil {
			return model.RootListOptions{}, err
		}
		opts.AfterClosedAtUnixN = cursor.ClosedAtUnixN
		opts.AfterBatchID = cursor.BatchID
		return opts, nil
	}
	if raw := r.URL.Query().Get("after"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			return model.RootListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "after must be a non-negative unix nano cursor")
		}
		opts.AfterClosedAtUnixN = parsed
	}
	return opts, nil
}

func parseTreeHeadListOptions(r *http.Request) (model.TreeHeadListOptions, error) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > 1000 {
			return model.TreeHeadListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "limit must be between 1 and 1000")
		}
		limit = parsed
	}
	direction, err := parseDirection(r.URL.Query().Get("direction"))
	if err != nil {
		return model.TreeHeadListOptions{}, err
	}
	opts := model.TreeHeadListOptions{Limit: limit, Direction: direction}
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		cursor, err := decodeUint64Cursor(raw)
		if err != nil {
			return model.TreeHeadListOptions{}, err
		}
		opts.AfterTreeSize = cursor.Value
	}
	return opts, nil
}

func parseGlobalLeafListOptions(r *http.Request) (model.GlobalLeafListOptions, error) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > 1000 {
			return model.GlobalLeafListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "limit must be between 1 and 1000")
		}
		limit = parsed
	}
	direction, err := parseDirection(r.URL.Query().Get("direction"))
	if err != nil {
		return model.GlobalLeafListOptions{}, err
	}
	opts := model.GlobalLeafListOptions{Limit: limit, Direction: direction}
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		cursor, err := decodeUint64Cursor(raw)
		if err != nil {
			return model.GlobalLeafListOptions{}, err
		}
		opts.AfterLeafIndex = cursor.Value
	}
	return opts, nil
}

func parseBatchTreeLeafListOptions(r *http.Request, batchID string) (model.BatchTreeLeafListOptions, error) {
	limit, err := parseLimitQuery(r, 100, 1000)
	if err != nil {
		return model.BatchTreeLeafListOptions{}, err
	}
	opts := model.BatchTreeLeafListOptions{
		BatchID: strings.TrimSpace(batchID),
		Limit:   limit,
	}
	if opts.BatchID == "" {
		return model.BatchTreeLeafListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "batch_id is required")
	}
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		cursor, err := decodeUint64Cursor(raw)
		if err != nil {
			return model.BatchTreeLeafListOptions{}, err
		}
		opts.AfterLeafIndex = cursor.Value
		opts.HasAfter = true
	}
	return opts, nil
}

func parseBatchTreeNodeListOptions(r *http.Request, batchID string) (model.BatchTreeNodeListOptions, error) {
	limit, err := parseLimitQuery(r, 100, 1000)
	if err != nil {
		return model.BatchTreeNodeListOptions{}, err
	}
	level, err := parseUint64Query(r, "level", 0)
	if err != nil {
		return model.BatchTreeNodeListOptions{}, err
	}
	start, err := parseUint64Query(r, "start", 0)
	if err != nil {
		return model.BatchTreeNodeListOptions{}, err
	}
	opts := model.BatchTreeNodeListOptions{
		BatchID:    strings.TrimSpace(batchID),
		Level:      level,
		StartIndex: start,
		Limit:      limit,
	}
	if opts.BatchID == "" {
		return model.BatchTreeNodeListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "batch_id is required")
	}
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		cursor, err := decodeUint64Cursor(raw)
		if err != nil {
			return model.BatchTreeNodeListOptions{}, err
		}
		opts.AfterStartIndex = cursor.Value
		opts.HasAfter = true
	}
	return opts, nil
}

func parseGlobalNodeListOptions(r *http.Request) (afterLevel, afterStart uint64, limit int, err error) {
	limit, err = parseLimitQuery(r, 100, 1000)
	if err != nil {
		return 0, 0, 0, err
	}
	afterLevel, afterStart = ^uint64(0), ^uint64(0)
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		cursor, err := decodeGlobalNodeCursor(raw)
		if err != nil {
			return 0, 0, 0, err
		}
		return cursor.Level, cursor.StartIndex, limit, nil
	}
	if raw := r.URL.Query().Get("level"); raw != "" {
		afterLevel, err = strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return 0, 0, 0, trusterr.New(trusterr.CodeInvalidArgument, "level must be a non-negative integer")
		}
		afterStart = ^uint64(0)
	}
	return afterLevel, afterStart, limit, nil
}

func parseLimitQuery(r *http.Request, fallback, max int) (int, error) {
	limit := fallback
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > max {
			return 0, trusterr.New(trusterr.CodeInvalidArgument, fmt.Sprintf("limit must be between 1 and %d", max))
		}
		limit = parsed
	}
	return limit, nil
}

func parseUint64Query(r *http.Request, name string, fallback uint64) (uint64, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, trusterr.New(trusterr.CodeInvalidArgument, name+" must be a non-negative integer")
	}
	return value, nil
}

func parseAnchorListOptions(r *http.Request) (model.AnchorListOptions, error) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > 1000 {
			return model.AnchorListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "limit must be between 1 and 1000")
		}
		limit = parsed
	}
	direction, err := parseDirection(r.URL.Query().Get("direction"))
	if err != nil {
		return model.AnchorListOptions{}, err
	}
	opts := model.AnchorListOptions{Limit: limit, Direction: direction}
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		cursor, err := decodeAnchorCursor(raw)
		if err != nil {
			return model.AnchorListOptions{}, err
		}
		opts.AfterResultKey = cursor.resultKey()
		opts.HasAfter = true
	}
	return opts, nil
}

func firstQueryValue(r *http.Request, names ...string) string {
	for _, name := range names {
		if raw := strings.TrimSpace(r.URL.Query().Get(name)); raw != "" {
			return raw
		}
	}
	return ""
}

func parseContentHashHex(raw string, suiteID cryptosuite.ID) ([]byte, error) {
	suite, err := cryptosuite.RequireAvailable(suiteID)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeFailedPrecondition, "HTTP crypto_suite", err)
	}
	raw = strings.ToLower(strings.TrimSpace(raw))
	if algorithm, encoded, ok := strings.Cut(raw, ":"); ok {
		if algorithm != suite.ContentHash.Algorithm {
			return nil, trusterr.New(
				trusterr.CodeInvalidArgument,
				fmt.Sprintf("content_hash algorithm must be %s for crypto_suite %s", suite.ContentHash.Algorithm, suite.ID),
			)
		}
		raw = encoded
	}
	expectedHexLen := suite.ContentHash.DigestBytes * 2
	if len(raw) != expectedHexLen {
		return nil, trusterr.New(
			trusterr.CodeInvalidArgument,
			fmt.Sprintf("content_hash must be a %d-character %s hex string", expectedHexLen, suite.ContentHash.Algorithm),
		)
	}
	hash, err := hex.DecodeString(raw)
	if err != nil || len(hash) != suite.ContentHash.DigestBytes {
		return nil, trusterr.New(
			trusterr.CodeInvalidArgument,
			fmt.Sprintf("content_hash must be a valid %s hex string", suite.ContentHash.Algorithm),
		)
	}
	return hash, nil
}

func parseRecordTimeQuery(r *http.Request, names ...string) (int64, error) {
	raw := firstQueryValue(r, names...)
	if raw == "" {
		return 0, nil
	}
	if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if parsed < 0 {
			return 0, trusterr.New(trusterr.CodeInvalidArgument, names[0]+" must be non-negative")
		}
		return parsed, nil
	}
	ts, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return 0, trusterr.New(trusterr.CodeInvalidArgument, names[0]+" must be unix nano or RFC3339 timestamp")
	}
	return ts.UTC().UnixNano(), nil
}

type recordCursor struct {
	ReceivedAtUnixN int64  `json:"t"`
	RecordID        string `json:"r"`
}

func encodeRecordCursor(idx model.RecordIndex) string {
	data, err := json.Marshal(recordCursor{ReceivedAtUnixN: idx.ReceivedAtUnixN, RecordID: idx.RecordID})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeRecordCursor(raw string) (recordCursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return recordCursor{}, trusterr.New(trusterr.CodeInvalidArgument, "cursor is invalid")
	}
	var cursor recordCursor
	if err := json.Unmarshal(data, &cursor); err != nil || cursor.RecordID == "" {
		return recordCursor{}, trusterr.New(trusterr.CodeInvalidArgument, "cursor is invalid")
	}
	return cursor, nil
}

type rootCursor struct {
	ClosedAtUnixN int64  `json:"t"`
	BatchID       string `json:"b"`
}

func encodeRootCursor(root model.BatchRoot) string {
	data, err := json.Marshal(rootCursor{ClosedAtUnixN: root.ClosedAtUnixN, BatchID: root.BatchID})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeRootCursor(raw string) (rootCursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return rootCursor{}, trusterr.New(trusterr.CodeInvalidArgument, "cursor is invalid")
	}
	var cursor rootCursor
	if err := json.Unmarshal(data, &cursor); err != nil || cursor.BatchID == "" {
		return rootCursor{}, trusterr.New(trusterr.CodeInvalidArgument, "cursor is invalid")
	}
	return cursor, nil
}

type uint64Cursor struct {
	Value uint64 `json:"v"`
}

type anchorCursor struct {
	TreeSize uint64 `json:"t"`
	NodeID   string `json:"n,omitempty"`
	LogID    string `json:"l,omitempty"`
	SinkName string `json:"s"`
}

type globalNodeCursor struct {
	Level      uint64 `json:"l"`
	StartIndex uint64 `json:"s"`
}

func encodeUint64Cursor(value uint64) string {
	data, err := json.Marshal(uint64Cursor{Value: value})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeUint64Cursor(raw string) (uint64Cursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return uint64Cursor{}, trusterr.New(trusterr.CodeInvalidArgument, "cursor is invalid")
	}
	var cursor uint64Cursor
	if err := json.Unmarshal(data, &cursor); err != nil {
		return uint64Cursor{}, trusterr.New(trusterr.CodeInvalidArgument, "cursor is invalid")
	}
	return cursor, nil
}

func encodeAnchorCursor(key model.STHAnchorResultKey) string {
	data, err := json.Marshal(anchorCursor{TreeSize: key.TreeSize, NodeID: key.NodeID, LogID: key.LogID, SinkName: key.SinkName})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeAnchorCursor(raw string) (anchorCursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return anchorCursor{}, trusterr.New(trusterr.CodeInvalidArgument, "cursor is invalid")
	}
	var cursor anchorCursor
	if err := json.Unmarshal(data, &cursor); err != nil || cursor.TreeSize == 0 || cursor.SinkName == "" {
		return anchorCursor{}, trusterr.New(trusterr.CodeInvalidArgument, "cursor is invalid")
	}
	return cursor, nil
}

func (c anchorCursor) resultKey() model.STHAnchorResultKey {
	return model.STHAnchorResultKey{NodeID: c.NodeID, LogID: c.LogID, SinkName: c.SinkName, TreeSize: c.TreeSize}
}

func encodeGlobalNodeCursor(level, startIndex uint64) string {
	data, err := json.Marshal(globalNodeCursor{Level: level, StartIndex: startIndex})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeGlobalNodeCursor(raw string) (globalNodeCursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return globalNodeCursor{}, trusterr.New(trusterr.CodeInvalidArgument, "cursor is invalid")
	}
	var cursor globalNodeCursor
	if err := json.Unmarshal(data, &cursor); err != nil {
		return globalNodeCursor{}, trusterr.New(trusterr.CodeInvalidArgument, "cursor is invalid")
	}
	return cursor, nil
}

func parseDirection(raw string) (string, error) {
	switch raw {
	case "":
		return model.RecordListDirectionDesc, nil
	case model.RecordListDirectionAsc, model.RecordListDirectionDesc:
		return raw, nil
	default:
		return "", trusterr.New(trusterr.CodeInvalidArgument, "direction must be asc or desc")
	}
}

func (h Handler) latestSTH(w http.ResponseWriter, r *http.Request) {
	if h.Global == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "global log service is not configured"))
		return
	}
	sth, ok, err := h.Global.LatestSTH(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	if !ok {
		writeError(w, trusterr.New(trusterr.CodeNotFound, "signed tree head not found"))
		return
	}
	writeJSON(w, http.StatusOK, sth)
}

func (h Handler) listSTHs(w http.ResponseWriter, r *http.Request) {
	if h.Global == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "global log service is not configured"))
		return
	}
	opts, err := parseTreeHeadListOptions(r)
	if err != nil {
		writeError(w, err)
		return
	}
	sths, err := h.Global.ListSTHs(r.Context(), opts)
	if err != nil {
		writeError(w, err)
		return
	}
	next := ""
	if len(sths) == opts.Limit {
		next = encodeUint64Cursor(sths[len(sths)-1].TreeSize)
	}
	writeJSON(w, http.StatusOK, sthsResponse{
		STHs:       sths,
		Limit:      opts.Limit,
		Direction:  opts.Direction,
		NextCursor: next,
	})
}

func (h Handler) getSTH(w http.ResponseWriter, r *http.Request) {
	if h.Global == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "global log service is not configured"))
		return
	}
	treeSize, err := parseTreeSize(r.PathValue("tree_size"))
	if err != nil {
		writeError(w, err)
		return
	}
	sth, ok, err := h.Global.STH(r.Context(), treeSize)
	if err != nil {
		writeError(w, err)
		return
	}
	if !ok {
		writeError(w, trusterr.New(trusterr.CodeNotFound, "signed tree head not found"))
		return
	}
	writeJSON(w, http.StatusOK, sth)
}

func (h Handler) getGlobalInclusion(w http.ResponseWriter, r *http.Request) {
	if h.Global == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "global log service is not configured"))
		return
	}
	treeSize := uint64(0)
	if raw := r.URL.Query().Get("tree_size"); raw != "" {
		parsed, err := parseTreeSize(raw)
		if err != nil {
			writeError(w, err)
			return
		}
		treeSize = parsed
	}
	proof, err := h.Global.InclusionProof(r.Context(), r.PathValue("batch_id"), treeSize)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proof)
}

func (h Handler) listGlobalLeaves(w http.ResponseWriter, r *http.Request) {
	if h.Global == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "global log service is not configured"))
		return
	}
	opts, err := parseGlobalLeafListOptions(r)
	if err != nil {
		writeError(w, err)
		return
	}
	leaves, err := h.Global.ListLeaves(r.Context(), opts)
	if err != nil {
		writeError(w, err)
		return
	}
	next := ""
	if len(leaves) == opts.Limit {
		next = encodeUint64Cursor(leaves[len(leaves)-1].LeafIndex)
	}
	writeJSON(w, http.StatusOK, globalLeavesResponse{
		Leaves:     leaves,
		Limit:      opts.Limit,
		Direction:  opts.Direction,
		NextCursor: next,
	})
}

func (h Handler) getGlobalTree(w http.ResponseWriter, r *http.Request) {
	if h.Global == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "global log service is not configured"))
		return
	}
	state, found, err := h.Global.State(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	if !found {
		writeJSON(w, http.StatusOK, globalTreeResponse{OK: false})
		return
	}
	sth, sthFound, err := h.Global.LatestSTH(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	resp := globalTreeResponse{State: state, OK: true}
	if sthFound {
		resp.STH = &sth
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h Handler) listGlobalTreeNodes(w http.ResponseWriter, r *http.Request) {
	if h.Global == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "global log service is not configured"))
		return
	}
	if strings.TrimSpace(r.URL.Query().Get("start")) != "" {
		level, err := parseUint64Query(r, "level", 0)
		if err != nil {
			writeError(w, err)
			return
		}
		start, err := parseUint64Query(r, "start", 0)
		if err != nil {
			writeError(w, err)
			return
		}
		node, ok, err := h.Global.Node(r.Context(), level, start)
		if err != nil {
			writeError(w, err)
			return
		}
		nodes := []model.GlobalLogNode(nil)
		if ok {
			nodes = append(nodes, node)
		}
		writeJSON(w, http.StatusOK, globalNodesResponse{Nodes: nodes, Limit: 1})
		return
	}
	afterLevel, afterStart, limit, err := parseGlobalNodeListOptions(r)
	if err != nil {
		writeError(w, err)
		return
	}
	nodes, err := h.Global.ListNodesAfter(r.Context(), afterLevel, afterStart, limit)
	if err != nil {
		writeError(w, err)
		return
	}
	next := ""
	if len(nodes) == limit {
		last := nodes[len(nodes)-1]
		next = encodeGlobalNodeCursor(last.Level, last.StartIndex)
	}
	writeJSON(w, http.StatusOK, globalNodesResponse{Nodes: nodes, Limit: limit, NextCursor: next})
}

func (h Handler) getGlobalConsistency(w http.ResponseWriter, r *http.Request) {
	if h.Global == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "global log service is not configured"))
		return
	}
	from, err := parseTreeSize(r.URL.Query().Get("from"))
	if err != nil {
		writeError(w, err)
		return
	}
	to, err := parseTreeSize(r.URL.Query().Get("to"))
	if err != nil {
		writeError(w, err)
		return
	}
	proof, err := h.Global.ConsistencyProof(r.Context(), from, to)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proof)
}

func (h Handler) getGlobalEvidence(w http.ResponseWriter, r *http.Request) {
	service, ok := h.Global.(GlobalEvidenceService)
	if !ok {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "global evidence service is not configured"))
		return
	}
	evidence, err := service.Evidence(r.Context(), r.PathValue("batch_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, evidence)
}

// getAnchor exposes one immutable, successfully published L5 result.
// Pending and retry state remain internal to the durable scheduler.
func (h Handler) getAnchor(w http.ResponseWriter, r *http.Request) {
	if h.Anchors == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "anchor service is not configured"))
		return
	}
	treeSize, err := parseTreeSize(r.PathValue("tree_size"))
	if err != nil {
		writeError(w, err)
		return
	}
	result, ok, err := h.Anchors.AnchorResult(r.Context(), treeSize)
	if err != nil {
		writeError(w, err)
		return
	}
	if !ok {
		writeError(w, trusterr.New(trusterr.CodeNotFound, "anchor not found for STH"))
		return
	}
	response, err := buildAnchorResponse(result)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func buildAnchorResponse(result model.STHAnchorResult) (anchorResponse, error) {
	if !model.ValidAnchorEvidenceStage(result.EvidenceStage) {
		return anchorResponse{}, trusterr.New(trusterr.CodeDataLoss, "anchor result has an unknown evidence stage")
	}
	r := result
	if result.EvidenceStage == model.AnchorEvidenceStageLocalOnly {
		return anchorResponse{
			TreeSize: result.TreeSize, Status: model.AnchorStateLocalOnly,
			ProofLevel: prooflevel.L4.String(), Result: &r,
		}, nil
	}
	if !model.AnchorResultProvidesOfflineL5(result) {
		return anchorResponse{
			TreeSize: result.TreeSize, Status: model.AnchorStateObserved,
			ProofLevel: prooflevel.L4.String(), Result: &r,
		}, nil
	}
	return anchorResponse{
		TreeSize: result.TreeSize, Status: model.AnchorStatePublished,
		ProofLevel: prooflevel.L5.String(), Result: &r,
	}, nil
}

func (h Handler) listAnchors(w http.ResponseWriter, r *http.Request) {
	if h.Anchors == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "anchor service is not configured"))
		return
	}
	opts, err := parseAnchorListOptions(r)
	if err != nil {
		writeError(w, err)
		return
	}
	items, err := h.Anchors.Anchors(r.Context(), opts)
	if err != nil {
		writeError(w, err)
		return
	}
	anchors := make([]anchorResponse, 0, len(items))
	for _, result := range items {
		response, err := buildAnchorResponse(result)
		if err != nil {
			writeError(w, err)
			return
		}
		anchors = append(anchors, response)
	}
	next := ""
	if len(items) == opts.Limit {
		last := items[len(items)-1]
		next = encodeAnchorCursor(model.STHAnchorResultKey{NodeID: last.NodeID, LogID: last.LogID, SinkName: last.SinkName, TreeSize: last.TreeSize})
	}
	writeJSON(w, http.StatusOK, anchorsResponse{
		Anchors:    anchors,
		Limit:      opts.Limit,
		Direction:  opts.Direction,
		NextCursor: next,
	})
}

func (h Handler) listAnchorSystems(w http.ResponseWriter, r *http.Request) {
	items, err := h.AnchorSystems.Systems(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, anchorSystemsResponse{Systems: items})
}

func (h Handler) getAnchorSystem(w http.ResponseWriter, r *http.Request) {
	item, found, err := h.AnchorSystems.System(r.Context(), r.PathValue("system_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	if !found {
		writeError(w, trusterr.New(trusterr.CodeNotFound, "anchor system not found"))
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h Handler) getAnchorSystemStatus(w http.ResponseWriter, r *http.Request) {
	item, found, err := h.AnchorSystems.Status(r.Context(), r.PathValue("system_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	if !found {
		writeError(w, trusterr.New(trusterr.CodeNotFound, "anchor system not found"))
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h Handler) listAnchorSystemResources(w http.ResponseWriter, r *http.Request) {
	limit, err := parseLimitQuery(r, 100, 1000)
	if err != nil {
		writeError(w, err)
		return
	}
	page, found, err := h.AnchorSystems.Resources(r.Context(), r.PathValue("system_id"), model.AnchorResourceListOptions{
		Kind:   strings.TrimSpace(r.URL.Query().Get("kind")),
		Limit:  limit,
		Cursor: strings.TrimSpace(r.URL.Query().Get("cursor")),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	if !found {
		writeError(w, trusterr.New(trusterr.CodeNotFound, "anchor system not found"))
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (h Handler) getAnchorSystemResource(w http.ResponseWriter, r *http.Request) {
	item, found, err := h.AnchorSystems.Resource(r.Context(), r.PathValue("system_id"), r.PathValue("kind"), r.PathValue("resource_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	if !found {
		writeError(w, trusterr.New(trusterr.CodeNotFound, "anchor system resource not found"))
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h Handler) latestRoot(w http.ResponseWriter, r *http.Request) {
	if h.Batch == nil {
		writeError(w, trusterr.New(trusterr.CodeFailedPrecondition, "batch service is not configured"))
		return
	}
	root, err := h.Batch.LatestRoot(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, root)
}

func parseTreeSize(raw string) (uint64, error) {
	if raw == "" {
		return 0, trusterr.New(trusterr.CodeInvalidArgument, "tree_size is required")
	}
	treeSize, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || treeSize == 0 {
		return 0, trusterr.New(trusterr.CodeInvalidArgument, "tree_size must be a positive integer")
	}
	return treeSize, nil
}

func writeError(w http.ResponseWriter, err error) {
	code := trusterr.CodeOf(err)
	status := httpStatus(code)
	writeJSON(w, status, *errorPayload(err))
}

func errorPayload(err error) *errorResponse {
	code := trusterr.CodeOf(err)
	return &errorResponse{Code: code, Message: err.Error()}
}

func httpStatus(code trusterr.Code) int {
	switch code {
	case trusterr.CodeInvalidArgument:
		return http.StatusBadRequest
	case trusterr.CodeAlreadyExists:
		return http.StatusConflict
	case trusterr.CodeFailedPrecondition:
		return http.StatusPreconditionFailed
	case trusterr.CodeNotFound:
		return http.StatusNotFound
	case trusterr.CodeResourceExhausted:
		return http.StatusTooManyRequests
	case trusterr.CodeDeadlineExceeded:
		return http.StatusGatewayTimeout
	case trusterr.CodeDataLoss:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusInternalServerError
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		_, _ = fmt.Fprintf(w, `{"code":"INTERNAL","message":"encode response: %v"}`+"\n", err)
	}
}

func MetricsHandler() (http.Handler, *observability.Metrics) {
	reg, metrics := observability.NewRegistry()
	return observability.Handler(reg), metrics
}
