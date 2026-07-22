package grpcapi

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"

	"github.com/wowtrust/trustdb/internal/httpapi"
	"github.com/wowtrust/trustdb/internal/ingest"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/prooflevel"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const submitClaimStreamWorkers = 64

type Server struct {
	Ingest         *ingest.Service
	Batch          httpapi.BatchService
	Global         httpapi.GlobalLogService
	Anchors        httpapi.AnchorService
	MetricsHandler http.Handler
}

func NewServer(
	ingestSvc *ingest.Service,
	batchSvc httpapi.BatchService,
	globalSvc httpapi.GlobalLogService,
	anchorSvc httpapi.AnchorService,
	metrics http.Handler,
) *Server {
	if isTypedNil(globalSvc) {
		globalSvc = nil
	}
	if isTypedNil(anchorSvc) {
		anchorSvc = nil
	}
	return &Server{Ingest: ingestSvc, Batch: batchSvc, Global: globalSvc, Anchors: anchorSvc, MetricsHandler: metrics}
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

func (s *Server) Health(context.Context, *HealthRequest) (*HealthResponse, error) {
	return &HealthResponse{OK: true}, nil
}

func (s *Server) SubmitClaim(ctx context.Context, req *SubmitClaimRequest) (*SubmitClaimResponse, error) {
	resp, err := s.submitSignedClaim(ctx, req.SignedClaim)
	if err != nil {
		return nil, toStatusError(err)
	}
	return resp, nil
}

func (s *Server) SubmitClaimStream(stream TrustDBService_SubmitClaimStreamServer) error {
	if s.Ingest == nil {
		return toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "ingest service is not configured"))
	}
	ctx := stream.Context()
	jobs := make(chan *SubmitClaimStreamRequest, submitClaimStreamWorkers)
	errCh := make(chan error, 1)
	var sendMu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(submitClaimStreamWorkers)
	for worker := 0; worker < submitClaimStreamWorkers; worker++ {
		go func() {
			defer wg.Done()
			for req := range jobs {
				resp := &SubmitClaimStreamResponse{Index: req.Index}
				result, err := s.submitSignedClaim(ctx, req.SignedClaim)
				if err != nil {
					resp.Error = grpcErrorPayload(err)
				} else {
					resp.Result = result
				}
				sendMu.Lock()
				err = stream.Send(resp)
				sendMu.Unlock()
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
			}
		}()
	}
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			close(jobs)
			wg.Wait()
			select {
			case err := <-errCh:
				return err
			default:
				return nil
			}
		}
		if err != nil {
			close(jobs)
			wg.Wait()
			return err
		}
		select {
		case err := <-errCh:
			close(jobs)
			wg.Wait()
			return err
		case jobs <- req:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return toStatusError(trusterr.Wrap(trusterr.CodeDeadlineExceeded, "request context canceled", ctx.Err()))
		}
	}
}

func (s *Server) submitSignedClaim(ctx context.Context, signed model.SignedClaim) (*SubmitClaimResponse, error) {
	if s.Ingest == nil {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "ingest service is not configured")
	}
	record, accepted, idempotent, err := s.Ingest.Submit(ctx, signed)
	if err != nil {
		return nil, err
	}
	batchEnqueued := false
	batchErr := ""
	if s.Batch != nil && !idempotent {
		if err := s.Batch.Enqueue(context.WithoutCancel(ctx), signed, record, accepted); err != nil {
			batchErr = err.Error()
		} else {
			batchEnqueued = true
		}
	}
	return &SubmitClaimResponse{
		RecordID:        record.RecordID,
		Status:          accepted.Status,
		ProofLevel:      prooflevel.L2.String(),
		Idempotent:      idempotent,
		BatchEnqueued:   batchEnqueued,
		BatchError:      batchErr,
		ServerRecord:    record,
		AcceptedReceipt: accepted,
	}, nil
}

func (s *Server) GetRecord(ctx context.Context, req *GetRecordRequest) (*GetRecordResponse, error) {
	if s.Batch == nil {
		return nil, toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "batch service is not configured"))
	}
	idx, ok, err := s.Batch.RecordIndex(ctx, req.RecordID)
	if err != nil {
		return nil, toStatusError(err)
	}
	if !ok {
		return nil, toStatusError(trusterr.New(trusterr.CodeNotFound, "record index not found"))
	}
	return &GetRecordResponse{Record: idx}, nil
}

func (s *Server) ListRecords(ctx context.Context, req *ListRecordsRequest) (*ListRecordsResponse, error) {
	if s.Batch == nil {
		return nil, toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "batch service is not configured"))
	}
	opts, err := recordListOptions(req)
	if err != nil {
		return nil, toStatusError(err)
	}
	records, err := s.Batch.Records(ctx, opts)
	if err != nil {
		return nil, toStatusError(err)
	}
	next := ""
	if len(records) == opts.Limit {
		next = encodeRecordCursor(records[len(records)-1])
	}
	return &ListRecordsResponse{Records: records, Limit: opts.Limit, Direction: opts.Direction, NextCursor: next}, nil
}

func (s *Server) GetProofBundle(ctx context.Context, req *GetProofBundleRequest) (*GetProofBundleResponse, error) {
	if s.Batch == nil {
		return nil, toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "batch service is not configured"))
	}
	bundle, err := s.Batch.Proof(ctx, req.RecordID)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &GetProofBundleResponse{RecordID: bundle.RecordID, ProofLevel: prooflevel.L3.String(), ProofBundle: bundle}, nil
}

func (s *Server) ListRoots(ctx context.Context, req *ListRootsRequest) (*ListRootsResponse, error) {
	if s.Batch == nil {
		return nil, toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "batch service is not configured"))
	}
	direction, err := parseDirection(req.Direction)
	if err != nil {
		return nil, toStatusError(err)
	}
	opts := model.RootListOptions{Limit: req.Limit, Direction: direction}
	if opts.Limit <= 0 {
		opts.Limit = 100
	}
	if opts.Limit > 1000 {
		return nil, toStatusError(trusterr.New(trusterr.CodeInvalidArgument, "limit must be between 1 and 1000"))
	}
	if req.Cursor != "" {
		cursor, err := decodeRootCursor(req.Cursor)
		if err != nil {
			return nil, toStatusError(err)
		}
		opts.AfterClosedAtUnixN = cursor.ClosedAtUnixN
		opts.AfterBatchID = cursor.BatchID
	} else if req.After > 0 {
		opts.AfterClosedAtUnixN = req.After
	}
	roots, err := s.Batch.RootsPage(ctx, opts)
	if err != nil {
		return nil, toStatusError(err)
	}
	next := ""
	if len(roots) == opts.Limit {
		next = encodeRootCursor(roots[len(roots)-1])
	}
	return &ListRootsResponse{Roots: roots, Limit: opts.Limit, Direction: opts.Direction, NextCursor: next}, nil
}

func (s *Server) LatestRoot(ctx context.Context, _ *LatestRootRequest) (*LatestRootResponse, error) {
	if s.Batch == nil {
		return nil, toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "batch service is not configured"))
	}
	root, err := s.Batch.LatestRoot(ctx)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &LatestRootResponse{Root: root}, nil
}

func (s *Server) ListSTHs(ctx context.Context, req *ListSTHsRequest) (*ListSTHsResponse, error) {
	if s.Global == nil {
		return nil, toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "global log service is not configured"))
	}
	direction, err := parseDirection(req.Direction)
	if err != nil {
		return nil, toStatusError(err)
	}
	opts := model.TreeHeadListOptions{Limit: req.Limit, Direction: direction}
	if opts.Limit <= 0 {
		opts.Limit = 100
	}
	if opts.Limit > 1000 {
		return nil, toStatusError(trusterr.New(trusterr.CodeInvalidArgument, "limit must be between 1 and 1000"))
	}
	if req.Cursor != "" {
		cursor, err := decodeUint64Cursor(req.Cursor)
		if err != nil {
			return nil, toStatusError(err)
		}
		opts.AfterTreeSize = cursor.Value
	}
	sths, err := s.Global.ListSTHs(ctx, opts)
	if err != nil {
		return nil, toStatusError(err)
	}
	next := ""
	if len(sths) == opts.Limit {
		next = encodeUint64Cursor(sths[len(sths)-1].TreeSize)
	}
	return &ListSTHsResponse{STHs: sths, Limit: opts.Limit, Direction: opts.Direction, NextCursor: next}, nil
}

func (s *Server) LatestSTH(ctx context.Context, _ *LatestSTHRequest) (*LatestSTHResponse, error) {
	if s.Global == nil {
		return nil, toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "global log service is not configured"))
	}
	sth, ok, err := s.Global.LatestSTH(ctx)
	if err != nil {
		return nil, toStatusError(err)
	}
	if !ok {
		return nil, toStatusError(trusterr.New(trusterr.CodeNotFound, "signed tree head not found"))
	}
	return &LatestSTHResponse{STH: sth}, nil
}

func (s *Server) GetSTH(ctx context.Context, req *GetSTHRequest) (*GetSTHResponse, error) {
	if s.Global == nil {
		return nil, toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "global log service is not configured"))
	}
	if req.TreeSize == 0 {
		return nil, toStatusError(trusterr.New(trusterr.CodeInvalidArgument, "tree_size must be a positive integer"))
	}
	sth, ok, err := s.Global.STH(ctx, req.TreeSize)
	if err != nil {
		return nil, toStatusError(err)
	}
	if !ok {
		return nil, toStatusError(trusterr.New(trusterr.CodeNotFound, "signed tree head not found"))
	}
	return &GetSTHResponse{STH: sth}, nil
}

func (s *Server) GetGlobalProof(ctx context.Context, req *GetGlobalProofRequest) (*GetGlobalProofResponse, error) {
	if s.Global == nil {
		return nil, toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "global log service is not configured"))
	}
	proof, err := s.Global.InclusionProof(ctx, req.BatchID, req.TreeSize)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &GetGlobalProofResponse{Proof: proof}, nil
}

func (s *Server) GetGlobalEvidence(ctx context.Context, req *GetGlobalEvidenceRequest) (*GetGlobalEvidenceResponse, error) {
	if s.Global == nil {
		return nil, toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "global log service is not configured"))
	}
	service, ok := s.Global.(httpapi.GlobalEvidenceService)
	if !ok {
		return nil, toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "global evidence service is not configured"))
	}
	evidence, err := service.Evidence(ctx, req.BatchID)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &GetGlobalEvidenceResponse{Evidence: evidence}, nil
}

func (s *Server) ListGlobalLeaves(ctx context.Context, req *ListGlobalLeavesRequest) (*ListGlobalLeavesResponse, error) {
	if s.Global == nil {
		return nil, toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "global log service is not configured"))
	}
	direction, err := parseDirection(req.Direction)
	if err != nil {
		return nil, toStatusError(err)
	}
	opts := model.GlobalLeafListOptions{Limit: req.Limit, Direction: direction}
	if opts.Limit <= 0 {
		opts.Limit = 100
	}
	if opts.Limit > 1000 {
		return nil, toStatusError(trusterr.New(trusterr.CodeInvalidArgument, "limit must be between 1 and 1000"))
	}
	if req.Cursor != "" {
		cursor, err := decodeUint64Cursor(req.Cursor)
		if err != nil {
			return nil, toStatusError(err)
		}
		opts.AfterLeafIndex = cursor.Value
	}
	leaves, err := s.Global.ListLeaves(ctx, opts)
	if err != nil {
		return nil, toStatusError(err)
	}
	next := ""
	if len(leaves) == opts.Limit {
		next = encodeUint64Cursor(leaves[len(leaves)-1].LeafIndex)
	}
	return &ListGlobalLeavesResponse{Leaves: leaves, Limit: opts.Limit, Direction: opts.Direction, NextCursor: next}, nil
}

func (s *Server) GetAnchor(ctx context.Context, req *GetAnchorRequest) (*GetAnchorResponse, error) {
	if s.Anchors == nil {
		return nil, toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "anchor service is not configured"))
	}
	if req.TreeSize == 0 {
		return nil, toStatusError(trusterr.New(trusterr.CodeInvalidArgument, "tree_size must be a positive integer"))
	}
	result, ok, err := s.Anchors.AnchorResult(ctx, req.TreeSize)
	if err != nil {
		return nil, toStatusError(err)
	}
	if !ok {
		return nil, toStatusError(trusterr.New(trusterr.CodeNotFound, "anchor not found for STH"))
	}
	return anchorEnvelopeResponse(result), nil
}

func (s *Server) ListAnchors(ctx context.Context, req *ListAnchorsRequest) (*ListAnchorsResponse, error) {
	if s.Anchors == nil {
		return nil, toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "anchor service is not configured"))
	}
	direction, err := parseDirection(req.Direction)
	if err != nil {
		return nil, toStatusError(err)
	}
	opts := model.AnchorListOptions{Limit: req.Limit, Direction: direction}
	if opts.Limit <= 0 {
		opts.Limit = 100
	}
	if opts.Limit > 1000 {
		return nil, toStatusError(trusterr.New(trusterr.CodeInvalidArgument, "limit must be between 1 and 1000"))
	}
	if req.Cursor != "" {
		cursor, err := decodeAnchorCursor(req.Cursor)
		if err != nil {
			return nil, toStatusError(err)
		}
		opts.AfterResultKey = cursor.resultKey()
		opts.HasAfter = true
	}
	items, err := s.Anchors.Anchors(ctx, opts)
	if err != nil {
		return nil, toStatusError(err)
	}
	anchors := make([]GetAnchorResponse, 0, len(items))
	for _, result := range items {
		anchors = append(anchors, *anchorEnvelopeResponse(result))
	}
	next := ""
	if len(items) == opts.Limit {
		last := items[len(items)-1]
		next = encodeAnchorCursor(model.STHAnchorResultKey{NodeID: last.NodeID, LogID: last.LogID, SinkName: last.SinkName, TreeSize: last.TreeSize})
	}
	return &ListAnchorsResponse{Anchors: anchors, Limit: opts.Limit, Direction: opts.Direction, NextCursor: next}, nil
}

func (s *Server) Metrics(ctx context.Context, _ *MetricsRequest) (*MetricsResponse, error) {
	if s.MetricsHandler == nil {
		return nil, toStatusError(trusterr.New(trusterr.CodeFailedPrecondition, "metrics handler is not configured"))
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	s.MetricsHandler.ServeHTTP(rr, req)
	if rr.Code < 200 || rr.Code >= 300 {
		return nil, toStatusError(trusterr.New(trusterr.CodeInternal, fmt.Sprintf("metrics handler returned http %d", rr.Code)))
	}
	return &MetricsResponse{Text: rr.Body.String()}, nil
}

func recordListOptions(req *ListRecordsRequest) (model.RecordListOptions, error) {
	limit := req.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		return model.RecordListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "limit must be between 1 and 1000")
	}
	direction := req.Direction
	switch direction {
	case "":
		direction = model.RecordListDirectionDesc
	case model.RecordListDirectionAsc, model.RecordListDirectionDesc:
	default:
		return model.RecordListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "direction must be asc or desc")
	}
	opts := model.RecordListOptions{
		Limit:             limit,
		Direction:         direction,
		BatchID:           req.BatchID,
		TenantID:          req.TenantID,
		ClientID:          req.ClientID,
		ProofLevel:        model.NormalizedProofLevel(req.ProofLevel),
		Query:             strings.TrimSpace(req.Query),
		ReceivedFromUnixN: req.ReceivedFromUnixN,
		ReceivedToUnixN:   req.ReceivedToUnixN,
	}
	if req.ProofLevel != "" && opts.ProofLevel == "" {
		return model.RecordListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "level must be one of L1-L5")
	}
	if opts.BatchID == "" && strings.HasPrefix(strings.ToLower(opts.Query), "batch-") {
		opts.BatchID = opts.Query
		opts.Query = ""
	}
	hashRaw := strings.TrimSpace(req.ContentHashHex)
	if hashRaw == "" && looksLikeHexSHA256(opts.Query) {
		hashRaw = opts.Query
		opts.Query = ""
	}
	if hashRaw != "" {
		hash, err := parseSHA256Hex(hashRaw)
		if err != nil {
			return model.RecordListOptions{}, err
		}
		opts.ContentHash = hash
	}
	if opts.Query != "" && model.RecordStorageQueryToken(opts.Query) == "" {
		return model.RecordListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "q must contain at least two letters or digits")
	}
	if opts.ReceivedFromUnixN > 0 && opts.ReceivedToUnixN > 0 && opts.ReceivedFromUnixN > opts.ReceivedToUnixN {
		return model.RecordListOptions{}, trusterr.New(trusterr.CodeInvalidArgument, "received_from must be <= received_to")
	}
	if req.Cursor != "" {
		cursor, err := decodeRecordCursor(req.Cursor)
		if err != nil {
			return model.RecordListOptions{}, err
		}
		opts.AfterReceivedAtUnixN = cursor.ReceivedAtUnixN
		opts.AfterRecordID = cursor.RecordID
	}
	return opts, nil
}

func looksLikeHexSHA256(raw string) bool {
	raw = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "sha256:")
	if len(raw) != 64 {
		return false
	}
	for _, r := range raw {
		if r < '0' || r > '9' && r < 'a' || r > 'f' {
			return false
		}
	}
	return true
}

func parseSHA256Hex(raw string) ([]byte, error) {
	raw = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "sha256:")
	if len(raw) != 64 {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "content_hash must be a 64-character sha256 hex string")
	}
	hash, err := hex.DecodeString(raw)
	if err != nil || len(hash) != 32 {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "content_hash must be a valid sha256 hex string")
	}
	return hash, nil
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

func anchorEnvelopeResponse(result model.STHAnchorResult) *GetAnchorResponse {
	return &GetAnchorResponse{
		TreeSize: result.TreeSize, Status: model.AnchorStatePublished,
		ProofLevel: prooflevel.L5.String(), Result: &result,
	}
}

func toStatusError(err error) error {
	if err == nil {
		return nil
	}
	return status.Error(grpcCode(trusterr.CodeOf(err)), err.Error())
}

func grpcErrorPayload(err error) *ErrorResponse {
	return &ErrorResponse{Code: string(trusterr.CodeOf(err)), Message: err.Error()}
}

func grpcCode(code trusterr.Code) codes.Code {
	switch code {
	case trusterr.CodeInvalidArgument:
		return codes.InvalidArgument
	case trusterr.CodeAlreadyExists:
		return codes.AlreadyExists
	case trusterr.CodeFailedPrecondition:
		return codes.FailedPrecondition
	case trusterr.CodeNotFound:
		return codes.NotFound
	case trusterr.CodeResourceExhausted:
		return codes.ResourceExhausted
	case trusterr.CodeDeadlineExceeded:
		return codes.DeadlineExceeded
	case trusterr.CodeDataLoss:
		return codes.DataLoss
	default:
		return codes.Internal
	}
}
