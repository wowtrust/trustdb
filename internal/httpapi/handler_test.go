package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/ingest"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/statusnotify"
	"github.com/wowtrust/trustdb/internal/submission"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestSubmitClaim(t *testing.T) {
	t.Parallel()

	p := processorFunc(func(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
		return model.ServerRecord{RecordID: "tr1http"}, model.AcceptedReceipt{RecordID: "tr1http", Status: "accepted"}, false, nil
	})
	svc := ingest.New(p, ingest.Options{QueueSize: 1, Workers: 1}, nil)
	defer svc.Shutdown(context.Background())
	handler := New(svc, nil)
	body, err := cborx.Marshal(model.SignedClaim{SchemaVersion: model.SchemaSignedClaim})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/claims", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	if got["record_id"] != "tr1http" || got["status"] != "accepted" {
		t.Fatalf("response = %#v", got)
	}
	if got["proof_level"] != "L2" {
		t.Fatalf("proof_level = %#v", got["proof_level"])
	}
}

func TestSubmitClaimsBatch(t *testing.T) {
	t.Parallel()

	p := processorFunc(func(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
		idem := signed.Claim.IdempotencyKey
		if idem == "bad" {
			return model.ServerRecord{}, model.AcceptedReceipt{}, false, trusterr.New(trusterr.CodeInvalidArgument, "bad claim")
		}
		recordID := "tr1" + idem
		return model.ServerRecord{RecordID: recordID}, model.AcceptedReceipt{RecordID: recordID, Status: "accepted"}, idem == "replay", nil
	})
	svc := ingest.New(p, ingest.Options{QueueSize: 8, Workers: 2}, nil)
	defer svc.Shutdown(context.Background())
	handler := New(svc, nil, &fakeBatchService{})
	body, err := cborx.Marshal(submitClaimsBatchRequest{Claims: []model.SignedClaim{
		{SchemaVersion: model.SchemaSignedClaim, Claim: model.ClientClaim{IdempotencyKey: "one"}},
		{SchemaVersion: model.SchemaSignedClaim, Claim: model.ClientClaim{IdempotencyKey: "bad"}},
		{SchemaVersion: model.SchemaSignedClaim, Claim: model.ClientClaim{IdempotencyKey: "replay"}},
	}})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/claims/batch", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got submitClaimsBatchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	if got.Submitted != 2 || got.Failed != 1 || len(got.Results) != 3 {
		t.Fatalf("response = %+v", got)
	}
	if got.Results[0].Result == nil || got.Results[0].Result.RecordID != "tr1one" {
		t.Fatalf("result[0] = %+v", got.Results[0])
	}
	if got.Results[1].Error == nil || got.Results[1].Error.Code != trusterr.CodeInvalidArgument {
		t.Fatalf("result[1] = %+v", got.Results[1])
	}
	if got.Results[2].Result == nil || !got.Results[2].Result.Idempotent || got.Results[2].Result.BatchEnqueued {
		t.Fatalf("result[2] = %+v", got.Results[2])
	}
}

func BenchmarkHTTPClaimBatchDecode1000(b *testing.B) {
	claims := make([]model.SignedClaim, maxClaimBatchItems)
	for i := range claims {
		claims[i] = model.SignedClaim{
			SchemaVersion: model.SchemaSignedClaim,
			Claim: model.ClientClaim{
				SchemaVersion:  model.SchemaClientClaim,
				TenantID:       "tenant-benchmark",
				ClientID:       "client-benchmark",
				KeyID:          "key-benchmark",
				Nonce:          bytes.Repeat([]byte{byte(i)}, 16),
				IdempotencyKey: "benchmark-idempotency-key",
				Content: model.Content{
					HashAlg:       model.DefaultHashAlg,
					ContentHash:   bytes.Repeat([]byte{byte(i + 1)}, 32),
					ContentLength: 1024,
					MediaType:     "application/json",
				},
				Metadata: model.Metadata{
					EventType: "log.record",
					Source:    "sdk-benchmark",
					Custom: map[string]string{
						"environment": "production",
						"service":     "trustdb-benchmark",
					},
				},
			},
			Signature: model.Signature{
				Alg:       model.DefaultSignatureAlg,
				KeyID:     "key-benchmark",
				Signature: bytes.Repeat([]byte{byte(i + 2)}, 64),
			},
		}
	}
	body, err := cborx.Marshal(submitClaimsBatchRequest{Claims: claims})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		var req submitClaimsBatchRequest
		if err := decodeCBORRequest(bytes.NewReader(body), int64(len(body)), maxClaimBatchBytes, &req); err != nil {
			b.Fatal(err)
		}
		if len(req.Claims) != maxClaimBatchItems {
			b.Fatalf("decoded claims = %d", len(req.Claims))
		}
	}
}

func TestSubmitClaimEnqueuesBatch(t *testing.T) {
	t.Parallel()

	p := processorFunc(func(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
		return model.ServerRecord{RecordID: "tr1batch"}, model.AcceptedReceipt{RecordID: "tr1batch", Status: "accepted"}, false, nil
	})
	svc := ingest.New(p, ingest.Options{QueueSize: 1, Workers: 1}, nil)
	defer svc.Shutdown(context.Background())
	batchSvc := &fakeBatchService{}
	handler := New(svc, nil, batchSvc)
	body, err := cborx.Marshal(model.SignedClaim{SchemaVersion: model.SchemaSignedClaim})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/claims", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got submitClaimResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	if !got.BatchEnqueued {
		t.Fatalf("BatchEnqueued = false response=%+v", got)
	}
	if batchSvc.enqueuedRecordID() != "tr1batch" {
		t.Fatalf("enqueued record id = %s", batchSvc.enqueuedRecordID())
	}
}

func TestSubmitClaimKeepsAcceptedBatchEnqueueAliveAfterRequestCancellation(t *testing.T) {
	t.Parallel()

	p := processorFunc(func(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
		return model.ServerRecord{RecordID: "tr1backpressure"}, model.AcceptedReceipt{RecordID: "tr1backpressure", Status: "accepted"}, false, nil
	})
	ingestSvc := ingest.New(p, ingest.Options{QueueSize: 1, Workers: 1}, nil)
	defer ingestSvc.Shutdown(context.Background())
	batchSvc := &blockingBatchService{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	handler := Handler{Submitter: submission.New(ingestSvc, batchSvc), Batch: batchSvc}
	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		response submitClaimResponse
		err      error
	}
	done := make(chan result, 1)
	go func() {
		response, err := handler.submitSignedClaim(ctx, model.SignedClaim{SchemaVersion: model.SchemaSignedClaim})
		done <- result{response: response, err: err}
	}()

	select {
	case <-batchSvc.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("batch enqueue was not reached")
	}
	cancel()
	select {
	case got := <-done:
		t.Fatalf("submit returned while accepted batch enqueue was blocked: response=%+v err=%v", got.response, got.err)
	case <-time.After(100 * time.Millisecond):
	}

	close(batchSvc.release)
	select {
	case got := <-done:
		if got.err != nil || !got.response.BatchEnqueued || got.response.BatchError != "" {
			t.Fatalf("submit result after releasing backpressure = %+v err=%v", got.response, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("submit did not finish after releasing batch backpressure")
	}
}

func TestSubmitClaimIdempotentReplaySkipsBatch(t *testing.T) {
	t.Parallel()

	p := processorFunc(func(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
		return model.ServerRecord{RecordID: "tr1replay"}, model.AcceptedReceipt{RecordID: "tr1replay", Status: "accepted"}, true, nil
	})
	svc := ingest.New(p, ingest.Options{QueueSize: 1, Workers: 1}, nil)
	defer svc.Shutdown(context.Background())
	batchSvc := &fakeBatchService{}
	handler := New(svc, nil, batchSvc)
	body, err := cborx.Marshal(model.SignedClaim{SchemaVersion: model.SchemaSignedClaim})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/claims", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("idempotent replay status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var got submitClaimResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	if !got.Idempotent {
		t.Fatalf("Idempotent = false, want true response=%+v", got)
	}
	if got.BatchEnqueued {
		t.Fatalf("BatchEnqueued = true, idempotent replay must not re-enqueue")
	}
	if id := batchSvc.enqueuedRecordID(); id != "" {
		t.Fatalf("batch enqueued record id = %q, want empty", id)
	}
}

func TestSubmitClaimIdempotencyConflictReturns409(t *testing.T) {
	t.Parallel()

	p := processorFunc(func(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
		return model.ServerRecord{}, model.AcceptedReceipt{}, false, trusterr.New(trusterr.CodeAlreadyExists, "idempotency_key conflict")
	})
	svc := ingest.New(p, ingest.Options{QueueSize: 1, Workers: 1}, nil)
	defer svc.Shutdown(context.Background())
	handler := New(svc, nil)
	body, err := cborx.Marshal(model.SignedClaim{SchemaVersion: model.SchemaSignedClaim})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/claims", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	var got errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	if got.Code != trusterr.CodeAlreadyExists {
		t.Fatalf("response code = %s, want %s", got.Code, trusterr.CodeAlreadyExists)
	}
}

func TestSubmitClaimRejectsBadCBOR(t *testing.T) {
	t.Parallel()

	svc := ingest.New(processorFunc(nil), ingest.Options{QueueSize: 1, Workers: 1}, nil)
	defer svc.Shutdown(context.Background())
	handler := New(svc, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/claims", strings.NewReader("not cbor"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSubmitClaimRejectsTrailingCBORData(t *testing.T) {
	t.Parallel()

	svc := ingest.New(processorFunc(nil), ingest.Options{QueueSize: 1, Workers: 1}, nil)
	defer svc.Shutdown(context.Background())
	handler := New(svc, nil)
	body, err := cborx.Marshal(model.SignedClaim{SchemaVersion: model.SchemaSignedClaim})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	body = append(body, 0x00)
	req := httptest.NewRequest(http.MethodPost, "/v1/claims", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDecodeCBORRequestRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	var out []byte
	err := decodeCBORRequest(bytes.NewReader([]byte{0x45, 1, 2, 3, 4, 5}), -1, 4, &out)
	if err == nil || !strings.Contains(err.Error(), "request body too large") {
		t.Fatalf("decodeCBORRequest() error = %v, want request body too large", err)
	}
}

func TestDecodeCBORRequestAcceptsKnownAndUnknownLength(t *testing.T) {
	t.Parallel()

	body, err := cborx.Marshal(model.SignedClaim{SchemaVersion: model.SchemaSignedClaim})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	tests := []struct {
		name          string
		contentLength int64
	}{
		{name: "known", contentLength: int64(len(body))},
		{name: "unknown", contentLength: -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got model.SignedClaim
			if err := decodeCBORRequest(bytes.NewReader(body), tt.contentLength, len(body), &got); err != nil {
				t.Fatalf("decodeCBORRequest() error = %v", err)
			}
			if got.SchemaVersion != model.SchemaSignedClaim {
				t.Fatalf("schema version = %q, want %q", got.SchemaVersion, model.SchemaSignedClaim)
			}
		})
	}
}

func TestDecodeCBORRequestRejectsContentLengthMismatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		body          []byte
		contentLength int64
	}{
		{name: "short body", body: []byte{0x41}, contentLength: 2},
		{name: "extra body", body: []byte{0x41, 1, 0}, contentLength: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out []byte
			if err := decodeCBORRequest(bytes.NewReader(tt.body), tt.contentLength, maxClaimBytes, &out); err == nil {
				t.Fatal("decodeCBORRequest() error = nil, want content length mismatch")
			}
		})
	}
}

func TestHealthAndMetrics(t *testing.T) {
	t.Parallel()

	metricsHandler, _ := MetricsHandler()
	handler := New(nil, metricsHandler)
	for _, path := range []string{"/healthz", "/metrics"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d", path, rec.Code)
		}
	}
}

func TestProofAndRootEndpoints(t *testing.T) {
	t.Parallel()

	batchSvc := &fakeBatchService{
		proof: model.ProofBundle{
			SchemaVersion: model.SchemaProofBundle,
			RecordID:      "tr1proof",
			BatchProof:    model.BatchProof{TreeSize: 1},
		},
		roots: []model.BatchRoot{
			{SchemaVersion: model.SchemaBatchRoot, BatchID: "batch-a", TreeSize: 1},
		},
	}
	handler := New(nil, nil, batchSvc)

	req := httptest.NewRequest(http.MethodGet, "/v1/proofs/tr1proof", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("proof status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/roots/latest", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("latest root status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/roots?limit=1", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("roots status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRecordEndpoints(t *testing.T) {
	t.Parallel()

	batchSvc := &fakeBatchService{
		records: []model.RecordIndex{
			{SchemaVersion: model.SchemaRecordIndex, RecordID: "rec-3", TenantID: "tenant-b", BatchID: "batch-2", ProofLevel: "L5", ReceivedAtUnixN: 300, ContentHash: bytes.Repeat([]byte{3}, 32), StorageURI: "file:///vault/report-final.pdf"},
			{SchemaVersion: model.SchemaRecordIndex, RecordID: "rec-2", TenantID: "tenant-a", BatchID: "batch-1", ProofLevel: "L4", ReceivedAtUnixN: 200, ContentHash: bytes.Repeat([]byte{2}, 32), StorageURI: "file:///vault/screenshot-alpha.png"},
			{SchemaVersion: model.SchemaRecordIndex, RecordID: "rec-1", TenantID: "tenant-a", BatchID: "batch-1", ProofLevel: "L3", ReceivedAtUnixN: 100, ContentHash: bytes.Repeat([]byte{1}, 32), StorageURI: "file:///vault/notes.txt"},
		},
	}
	handler := New(nil, nil, batchSvc)

	req := httptest.NewRequest(http.MethodGet, "/v1/records?limit=2", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("records status = %d body=%s", rec.Code, rec.Body.String())
	}
	var page recordsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode records response: %v", err)
	}
	if len(page.Records) != 2 || page.Records[0].RecordID != "rec-3" || page.NextCursor == "" {
		t.Fatalf("records page = %+v", page)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/records?limit=2&cursor="+page.NextCursor, nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("records next status = %d body=%s", rec.Code, rec.Body.String())
	}
	var next recordsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &next); err != nil {
		t.Fatalf("decode next records response: %v", err)
	}
	if len(next.Records) != 1 || next.Records[0].RecordID != "rec-1" {
		t.Fatalf("next records page = %+v", next)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/records/rec-2", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("record index status = %d body=%s", rec.Code, rec.Body.String())
	}
	var idx model.RecordIndex
	if err := json.Unmarshal(rec.Body.Bytes(), &idx); err != nil {
		t.Fatalf("decode record index: %v", err)
	}
	if idx.RecordID != "rec-2" || idx.BatchID != "batch-1" {
		t.Fatalf("record index = %+v", idx)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/records/rec-2/status", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"committed"`) {
		t.Fatalf("record status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/records/status:batchGet", strings.NewReader(`{"record_ids":["rec-2","missing"]}`))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"missing_record_ids":["missing"]`) {
		t.Fatalf("record status batch = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/records/status:batchGet", strings.NewReader(`{"record_ids":[" rec-2 ","rec-2"]}`))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("normalized record status batch = %d body=%s", rec.Code, rec.Body.String())
	}
	var normalizedStatuses recordStatusesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &normalizedStatuses); err != nil {
		t.Fatalf("decode normalized status batch: %v", err)
	}
	if len(normalizedStatuses.Statuses) != 1 || len(normalizedStatuses.MissingRecordIDs) != 0 {
		t.Fatalf("normalized status batch = %+v", normalizedStatuses)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/records?q=screenshot&limit=10", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("records q status = %d body=%s", rec.Code, rec.Body.String())
	}
	var byQuery recordsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &byQuery); err != nil {
		t.Fatalf("decode q records response: %v", err)
	}
	if len(byQuery.Records) != 1 || byQuery.Records[0].RecordID != "rec-2" {
		t.Fatalf("q records page = %+v", byQuery)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/records?content_hash="+strings.Repeat("02", 32)+"&limit=10", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("records content_hash status = %d body=%s", rec.Code, rec.Body.String())
	}
	var byHash recordsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &byHash); err != nil {
		t.Fatalf("decode hash records response: %v", err)
	}
	if len(byHash.Records) != 1 || byHash.Records[0].RecordID != "rec-2" {
		t.Fatalf("hash records page = %+v", byHash)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/records?received_from=150&received_to=250&limit=10", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("records range status = %d body=%s", rec.Code, rec.Body.String())
	}
	var byRange recordsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &byRange); err != nil {
		t.Fatalf("decode range records response: %v", err)
	}
	if len(byRange.Records) != 1 || byRange.Records[0].RecordID != "rec-2" {
		t.Fatalf("range records page = %+v", byRange)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/records?level=L5&limit=10", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("records level status = %d body=%s", rec.Code, rec.Body.String())
	}
	var byLevel recordsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &byLevel); err != nil {
		t.Fatalf("decode level records response: %v", err)
	}
	if len(byLevel.Records) != 1 || byLevel.Records[0].RecordID != "rec-3" {
		t.Fatalf("level records page = %+v", byLevel)
	}
}

func TestCreateStatusSubscriptionAuthenticatesBeforeRecordLookups(t *testing.T) {
	t.Parallel()

	clientPublic, _, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	_, serverPrivate, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	resolver := staticStatusRouteResolver{key: model.ClientKey{
		TenantID: "tenant", ClientID: "client", KeyID: "key",
		Alg: cryptosuite.SignatureEd25519, PublicKey: clientPublic, Status: model.KeyStatusValid,
	}}
	hub, err := statusnotify.New(statusnotify.Config{
		Routes: resolver,
		Signer: trustcrypto.MustNewEd25519Signer("server-key", serverPrivate),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()

	statuses := &countingRecordStatusService{}
	handler := buildMux(Handler{Statuses: statuses, StatusHub: hub})
	body := `{"tenant_id":"tenant","client_id":"client","key_id":"key","record_ids":["tr1"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/status-subscriptions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if got := statuses.calls.Load(); got != 0 {
		t.Fatalf("RecordStatuses calls = %d, want 0 for unauthenticated request", got)
	}
}

func TestGlobalAndAnchorListEndpoints(t *testing.T) {
	t.Parallel()

	handler := NewWithGlobalAndAnchors(nil, nil, &fakeBatchService{}, fakeGlobalService{
		sths: []model.SignedTreeHead{
			{SchemaVersion: model.SchemaSignedTreeHead, TreeSize: 3, RootHash: []byte{3}},
			{SchemaVersion: model.SchemaSignedTreeHead, TreeSize: 2, RootHash: []byte{2}},
			{SchemaVersion: model.SchemaSignedTreeHead, TreeSize: 1, RootHash: []byte{1}},
		},
		leaves: []model.GlobalLogLeaf{
			{SchemaVersion: model.SchemaGlobalLogLeaf, BatchID: "batch-3", LeafIndex: 2},
			{SchemaVersion: model.SchemaGlobalLogLeaf, BatchID: "batch-2", LeafIndex: 1},
			{SchemaVersion: model.SchemaGlobalLogLeaf, BatchID: "batch-1", LeafIndex: 0},
		},
	}, fakeAnchorService{
		results: []model.STHAnchorResult{
			{SchemaVersion: model.SchemaSTHAnchorResult, TreeSize: 2, AnchorID: "anchor-2", SinkName: "ots"},
			{SchemaVersion: model.SchemaSTHAnchorResult, TreeSize: 2, AnchorID: "anchor-2-file", SinkName: "file"},
			{SchemaVersion: model.SchemaSTHAnchorResult, TreeSize: 1, AnchorID: "anchor-1", SinkName: "ots"},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/sth?limit=2", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sth list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var sthsPage sthsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &sthsPage); err != nil {
		t.Fatalf("decode sth page: %v", err)
	}
	if len(sthsPage.STHs) != 2 || sthsPage.STHs[0].TreeSize != 3 || sthsPage.NextCursor == "" {
		t.Fatalf("sth page = %+v", sthsPage)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/global-log/leaves?limit=2", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("global leaves status = %d body=%s", rec.Code, rec.Body.String())
	}
	var leavesPage globalLeavesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &leavesPage); err != nil {
		t.Fatalf("decode leaves page: %v", err)
	}
	if len(leavesPage.Leaves) != 2 || leavesPage.Leaves[0].LeafIndex != 2 || leavesPage.NextCursor == "" {
		t.Fatalf("leaves page = %+v", leavesPage)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/anchors/sth?limit=2", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("anchor list status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"outbox"`) {
		t.Fatalf("anchor list leaked mutable scheduler state: %s", rec.Body.String())
	}
	var anchorsPage anchorsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &anchorsPage); err != nil {
		t.Fatalf("decode anchor page: %v", err)
	}
	if len(anchorsPage.Anchors) != 2 || anchorsPage.Anchors[0].TreeSize != 2 || anchorsPage.NextCursor == "" {
		t.Fatalf("anchor page = %+v", anchorsPage)
	}
	for _, item := range anchorsPage.Anchors {
		if item.Status != model.AnchorStatePublished || item.ProofLevel != "L5" || item.Result == nil {
			t.Fatalf("anchor list item is not immutable publication evidence: %+v", item)
		}
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/anchors/sth?limit=2&cursor="+anchorsPage.NextCursor, nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second anchor page status = %d body=%s", rec.Code, rec.Body.String())
	}
	var secondAnchorsPage anchorsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &secondAnchorsPage); err != nil {
		t.Fatalf("decode second anchor page: %v", err)
	}
	if len(secondAnchorsPage.Anchors) != 1 || secondAnchorsPage.Anchors[0].TreeSize != 1 {
		t.Fatalf("second anchor page skipped or duplicated a same-tree sink: %+v", secondAnchorsPage)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/anchors/sth/2", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("anchor get status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"outbox"`) {
		t.Fatalf("anchor get leaked mutable scheduler state: %s", rec.Body.String())
	}
	var anchorItem anchorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &anchorItem); err != nil {
		t.Fatalf("decode anchor response: %v", err)
	}
	if anchorItem.Status != model.AnchorStatePublished || anchorItem.ProofLevel != "L5" || anchorItem.Result == nil || anchorItem.Result.AnchorID != "anchor-2" {
		t.Fatalf("anchor response = %+v", anchorItem)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/anchors/sth/3", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unpublished anchor status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestBatchTreeEndpoints(t *testing.T) {
	t.Parallel()

	handler := New(nil, nil, &fakeBatchService{
		roots: []model.BatchRoot{{SchemaVersion: model.SchemaBatchRoot, BatchID: "batch-a", TreeSize: 2, BatchRoot: []byte{9}, ClosedAtUnixN: 100}},
		manifests: map[string]model.BatchManifest{
			"batch-a": {SchemaVersion: model.SchemaBatchManifest, BatchID: "batch-a", State: model.BatchStateCommitted, TreeSize: 2, BatchRoot: []byte{9}, RecordIDs: []string{"rec-a", "rec-b"}, ClosedAtUnixN: 100},
		},
		treeLeaves: []model.BatchTreeLeaf{
			{SchemaVersion: model.SchemaBatchTreeLeaf, BatchID: "batch-a", RecordID: "rec-a", LeafIndex: 0, LeafHash: []byte{1}},
			{SchemaVersion: model.SchemaBatchTreeLeaf, BatchID: "batch-a", RecordID: "rec-b", LeafIndex: 1, LeafHash: []byte{2}},
		},
		treeNodes: []model.BatchTreeNode{
			{SchemaVersion: model.SchemaBatchTreeNode, BatchID: "batch-a", Level: 0, StartIndex: 0, Width: 1, Hash: []byte{1}},
			{SchemaVersion: model.SchemaBatchTreeNode, BatchID: "batch-a", Level: 0, StartIndex: 1, Width: 1, Hash: []byte{2}},
			{SchemaVersion: model.SchemaBatchTreeNode, BatchID: "batch-a", Level: 1, StartIndex: 0, Width: 2, Hash: []byte{9}},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/batches/batch-a", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch detail status = %d body=%s", rec.Code, rec.Body.String())
	}
	var detail batchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode batch detail: %v", err)
	}
	if detail.RecordCount != 2 || detail.Root.BatchID != "batch-a" {
		t.Fatalf("batch detail = %+v", detail)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/batches/batch-a/tree/leaves?limit=1", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch leaves status = %d body=%s", rec.Code, rec.Body.String())
	}
	var leaves batchLeavesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &leaves); err != nil {
		t.Fatalf("decode batch leaves: %v", err)
	}
	if len(leaves.Leaves) != 1 || leaves.Leaves[0].RecordID != "rec-a" || leaves.NextCursor == "" {
		t.Fatalf("batch leaves = %+v", leaves)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/batches/batch-a/tree/nodes?level=0&limit=2", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch nodes status = %d body=%s", rec.Code, rec.Body.String())
	}
	var nodes batchNodesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("decode batch nodes: %v", err)
	}
	if len(nodes.Nodes) != 2 || nodes.Nodes[0].StartIndex != 0 || nodes.NextCursor == "" {
		t.Fatalf("batch nodes = %+v", nodes)
	}
}

func TestBatchTreeEndpointReportsMissingIndex(t *testing.T) {
	t.Parallel()

	handler := New(nil, nil, &fakeBatchService{
		manifests: map[string]model.BatchManifest{
			"old-batch": {SchemaVersion: model.SchemaBatchManifest, BatchID: "old-batch", State: model.BatchStateCommitted, TreeSize: 2, RecordIDs: []string{"rec-a", "rec-b"}},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/batches/old-batch/tree/leaves?limit=1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("batch leaves status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestGlobalTreeEndpoints(t *testing.T) {
	t.Parallel()

	handler := NewWithGlobalAndAnchors(nil, nil, &fakeBatchService{}, fakeGlobalService{
		sths:  []model.SignedTreeHead{{SchemaVersion: model.SchemaSignedTreeHead, TreeSize: 2, RootHash: []byte{9}}},
		state: model.GlobalLogState{SchemaVersion: model.SchemaGlobalLogState, TreeSize: 2, RootHash: []byte{9}},
		nodes: []model.GlobalLogNode{
			{SchemaVersion: model.SchemaGlobalLogNode, Level: 0, StartIndex: 0, Width: 1, Hash: []byte{1}},
			{SchemaVersion: model.SchemaGlobalLogNode, Level: 0, StartIndex: 1, Width: 1, Hash: []byte{2}},
		},
	}, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/global-log/tree", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("global tree status = %d body=%s", rec.Code, rec.Body.String())
	}
	var tree globalTreeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &tree); err != nil {
		t.Fatalf("decode global tree: %v", err)
	}
	if !tree.OK || tree.State.TreeSize != 2 || tree.STH == nil {
		t.Fatalf("global tree = %+v", tree)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/global-log/tree/nodes?limit=1", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("global nodes status = %d body=%s", rec.Code, rec.Body.String())
	}
	var nodes globalNodesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("decode global nodes: %v", err)
	}
	if len(nodes.Nodes) != 1 || nodes.NextCursor == "" {
		t.Fatalf("global nodes = %+v", nodes)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/global-log/tree/nodes?level=0&start=1", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("global exact node status = %d body=%s", rec.Code, rec.Body.String())
	}
	var exact globalNodesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &exact); err != nil {
		t.Fatalf("decode global exact node: %v", err)
	}
	if len(exact.Nodes) != 1 || exact.Nodes[0].StartIndex != 1 || exact.NextCursor != "" {
		t.Fatalf("global exact node = %+v", exact)
	}
}

func TestGlobalEvidenceEndpoint(t *testing.T) {
	t.Parallel()
	want := model.GlobalLogEvidence{
		GlobalProof:  model.GlobalLogProof{SchemaVersion: model.SchemaGlobalLogProof, BatchID: "batch-1", TreeSize: 3},
		AnchorResult: &model.STHAnchorResult{SchemaVersion: model.SchemaSTHAnchorResult, TreeSize: 3, AnchorID: "anchor-3"},
	}
	handler := NewWithGlobalAndAnchors(nil, nil, &fakeBatchService{}, fakeGlobalService{evidence: want}, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/global-log/evidence/batch-1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("global evidence status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got model.GlobalLogEvidence
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode global evidence: %v", err)
	}
	if got.GlobalProof.TreeSize != 3 || got.AnchorResult == nil || got.AnchorResult.TreeSize != 3 {
		t.Fatalf("global evidence=%+v", got)
	}
}

func TestGlobalRoutesAreNotRegisteredWithoutGlobalService(t *testing.T) {
	t.Parallel()

	handler := NewWithGlobalAndAnchors(nil, nil, &fakeBatchService{}, nil, nil)
	for _, path := range []string{
		"/v1/sth/latest",
		"/v1/sth",
		"/v1/global-log/leaves",
		"/v1/global-log/tree",
		"/v1/global-log/tree/nodes",
		"/v1/global-log/inclusion/batch-1",
		"/v1/global-log/evidence/batch-1",
		"/v1/global-log/consistency?from=1&to=2",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404 body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestGlobalRoutesAreNotRegisteredWithTypedNilGlobalService(t *testing.T) {
	t.Parallel()

	var global *fakeGlobalService
	handler := NewWithGlobalAndAnchors(nil, nil, &fakeBatchService{}, global, nil)
	for _, path := range []string{
		"/v1/sth/latest",
		"/v1/sth",
		"/v1/global-log/leaves",
		"/v1/global-log/tree",
		"/v1/global-log/tree/nodes",
		"/v1/global-log/inclusion/batch-1",
		"/v1/global-log/evidence/batch-1",
		"/v1/global-log/consistency?from=1&to=2",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404 body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

type processorFunc func(context.Context, model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error)

func (f processorFunc) Submit(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
	if f == nil {
		return model.ServerRecord{}, model.AcceptedReceipt{}, false, nil
	}
	return f(ctx, signed)
}

type fakeBatchService struct {
	mu         sync.Mutex
	enqueued   string
	proof      model.ProofBundle
	roots      []model.BatchRoot
	records    []model.RecordIndex
	manifests  map[string]model.BatchManifest
	treeLeaves []model.BatchTreeLeaf
	treeNodes  []model.BatchTreeNode
}

type staticStatusRouteResolver struct {
	key model.ClientKey
}

func (r staticStatusRouteResolver) LookupClientKeyAt(tenantID, clientID, keyID string, _ time.Time) (model.ClientKey, error) {
	if tenantID != r.key.TenantID || clientID != r.key.ClientID || keyID != r.key.KeyID {
		return model.ClientKey{}, trusterr.New(trusterr.CodeNotFound, "key not found")
	}
	return r.key, nil
}

func (r staticStatusRouteResolver) LookupNotificationRoute(tenantID, clientID, keyID string) (model.UpstreamNotificationRoute, bool) {
	if tenantID != r.key.TenantID || clientID != r.key.ClientID || keyID != r.key.KeyID {
		return model.UpstreamNotificationRoute{}, false
	}
	return model.UpstreamNotificationRoute{}, true
}

type countingRecordStatusService struct {
	calls atomic.Int64
}

func (s *countingRecordStatusService) RecordStatus(context.Context, string) (model.RecordStatus, bool, error) {
	return model.RecordStatus{}, false, nil
}

func (s *countingRecordStatusService) RecordStatuses(context.Context, []string) ([]model.RecordStatus, error) {
	s.calls.Add(1)
	return nil, nil
}

type blockingBatchService struct {
	BatchService
	entered chan struct{}
	release chan struct{}
}

func (f *blockingBatchService) Enqueue(ctx context.Context, _ model.SignedClaim, _ model.ServerRecord, _ model.AcceptedReceipt) error {
	close(f.entered)
	select {
	case <-f.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *fakeBatchService) Enqueue(ctx context.Context, signed model.SignedClaim, record model.ServerRecord, accepted model.AcceptedReceipt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enqueued = record.RecordID
	return nil
}

func (f *fakeBatchService) Proof(ctx context.Context, recordID string) (model.ProofBundle, error) {
	if f.proof.RecordID == "" {
		f.proof = model.ProofBundle{SchemaVersion: model.SchemaProofBundle, RecordID: recordID}
	}
	return f.proof, nil
}

func (f *fakeBatchService) RecordIndex(ctx context.Context, recordID string) (model.RecordIndex, bool, error) {
	for _, idx := range f.records {
		if idx.RecordID == recordID {
			return idx, true, nil
		}
	}
	return model.RecordIndex{}, false, nil
}

func (f *fakeBatchService) RecordStatus(ctx context.Context, recordID string) (model.RecordStatus, bool, error) {
	for _, idx := range f.records {
		if idx.RecordID == recordID {
			return model.RecordStatus{
				SchemaVersion: model.SchemaRecordStatus,
				RecordID:      idx.RecordID,
				TenantID:      idx.TenantID,
				ClientID:      idx.ClientID,
				KeyID:         idx.KeyID,
				Status:        model.RecordStatusCommitted,
				ProofLevel:    model.RecordIndexProofLevel(idx),
				BatchID:       idx.BatchID,
				Terminal:      true,
			}, true, nil
		}
	}
	return model.RecordStatus{}, false, nil
}

func (f *fakeBatchService) RecordStatuses(ctx context.Context, recordIDs []string) ([]model.RecordStatus, error) {
	statuses := make([]model.RecordStatus, 0, len(recordIDs))
	for _, recordID := range recordIDs {
		status, found, err := f.RecordStatus(ctx, recordID)
		if err != nil {
			return nil, err
		}
		if found {
			statuses = append(statuses, status)
		}
	}
	return statuses, nil
}

func (f *fakeBatchService) Records(ctx context.Context, opts model.RecordListOptions) ([]model.RecordIndex, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	records := append([]model.RecordIndex(nil), f.records...)
	desc := !strings.EqualFold(opts.Direction, model.RecordListDirectionAsc)
	sort.Slice(records, func(i, j int) bool {
		cmp := model.CompareRecordPosition(records[i].ReceivedAtUnixN, records[i].RecordID, records[j].ReceivedAtUnixN, records[j].RecordID)
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
	out := make([]model.RecordIndex, 0, limit)
	for _, idx := range records {
		if !model.RecordIndexMatchesListOptions(idx, opts) || !model.RecordIndexAfterCursor(idx, opts) {
			continue
		}
		out = append(out, idx)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f *fakeBatchService) Roots(ctx context.Context, limit int) ([]model.BatchRoot, error) {
	return f.roots, nil
}

func (f *fakeBatchService) RootsAfter(ctx context.Context, afterClosedAtUnixN int64, limit int) ([]model.BatchRoot, error) {
	out := make([]model.BatchRoot, 0, len(f.roots))
	for _, root := range f.roots {
		if root.ClosedAtUnixN > afterClosedAtUnixN {
			out = append(out, root)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (f *fakeBatchService) RootsPage(ctx context.Context, opts model.RootListOptions) ([]model.BatchRoot, error) {
	roots := append([]model.BatchRoot(nil), f.roots...)
	desc := !strings.EqualFold(opts.Direction, model.RecordListDirectionAsc)
	sort.Slice(roots, func(i, j int) bool {
		cmp := model.CompareBatchRootPosition(roots[i].ClosedAtUnixN, roots[i].BatchID, roots[j].ClosedAtUnixN, roots[j].BatchID)
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
	out := make([]model.BatchRoot, 0, opts.Limit)
	for _, root := range roots {
		if !model.BatchRootAfterCursor(root, opts) {
			continue
		}
		out = append(out, root)
		if len(out) >= opts.Limit {
			break
		}
	}
	return out, nil
}

func (f *fakeBatchService) LatestRoot(ctx context.Context) (model.BatchRoot, error) {
	if len(f.roots) == 0 {
		return model.BatchRoot{}, nil
	}
	return f.roots[0], nil
}

func (f *fakeBatchService) Manifest(ctx context.Context, batchID string) (model.BatchManifest, error) {
	if f.manifests != nil {
		if manifest, ok := f.manifests[batchID]; ok {
			return manifest, nil
		}
	}
	for _, root := range f.roots {
		if root.BatchID == batchID {
			return model.BatchManifest{
				SchemaVersion: model.SchemaBatchManifest,
				BatchID:       root.BatchID,
				NodeID:        root.NodeID,
				LogID:         root.LogID,
				State:         model.BatchStateCommitted,
				TreeSize:      root.TreeSize,
				BatchRoot:     append([]byte(nil), root.BatchRoot...),
				ClosedAtUnixN: root.ClosedAtUnixN,
			}, nil
		}
	}
	return model.BatchManifest{}, trusterr.New(trusterr.CodeNotFound, "batch manifest not found")
}

func (f *fakeBatchService) BatchTreeLeaves(ctx context.Context, opts model.BatchTreeLeafListOptions) ([]model.BatchTreeLeaf, error) {
	out := make([]model.BatchTreeLeaf, 0, opts.Limit)
	for _, leaf := range f.treeLeaves {
		if leaf.BatchID != opts.BatchID {
			continue
		}
		if opts.HasAfter && leaf.LeafIndex <= opts.AfterLeafIndex {
			continue
		}
		out = append(out, leaf)
		if len(out) >= opts.Limit {
			break
		}
	}
	return out, nil
}

func (f *fakeBatchService) BatchTreeNodes(ctx context.Context, opts model.BatchTreeNodeListOptions) ([]model.BatchTreeNode, error) {
	out := make([]model.BatchTreeNode, 0, opts.Limit)
	for _, node := range f.treeNodes {
		if node.BatchID != opts.BatchID || node.Level != opts.Level || node.StartIndex < opts.StartIndex {
			continue
		}
		if opts.HasAfter && node.StartIndex <= opts.AfterStartIndex {
			continue
		}
		out = append(out, node)
		if len(out) >= opts.Limit {
			break
		}
	}
	return out, nil
}

func (f *fakeBatchService) enqueuedRecordID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enqueued
}

type fakeGlobalService struct {
	sths     []model.SignedTreeHead
	leaves   []model.GlobalLogLeaf
	state    model.GlobalLogState
	nodes    []model.GlobalLogNode
	evidence model.GlobalLogEvidence
}

func (f fakeGlobalService) LatestSTH(context.Context) (model.SignedTreeHead, bool, error) {
	if len(f.sths) == 0 {
		return model.SignedTreeHead{}, false, nil
	}
	return f.sths[0], true, nil
}

func (f fakeGlobalService) STH(_ context.Context, treeSize uint64) (model.SignedTreeHead, bool, error) {
	for _, sth := range f.sths {
		if sth.TreeSize == treeSize {
			return sth, true, nil
		}
	}
	return model.SignedTreeHead{}, false, nil
}

func (f fakeGlobalService) ListSTHs(_ context.Context, opts model.TreeHeadListOptions) ([]model.SignedTreeHead, error) {
	sths := append([]model.SignedTreeHead(nil), f.sths...)
	desc := !strings.EqualFold(opts.Direction, model.RecordListDirectionAsc)
	sort.Slice(sths, func(i, j int) bool {
		cmp := model.CompareUint64Position(sths[i].TreeSize, sths[j].TreeSize)
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
	out := make([]model.SignedTreeHead, 0, opts.Limit)
	for _, sth := range sths {
		if !model.Uint64AfterCursor(sth.TreeSize, opts.AfterTreeSize, opts.Direction) {
			continue
		}
		out = append(out, sth)
		if len(out) >= opts.Limit {
			break
		}
	}
	return out, nil
}

func (f fakeGlobalService) ListLeaves(_ context.Context, opts model.GlobalLeafListOptions) ([]model.GlobalLogLeaf, error) {
	leaves := append([]model.GlobalLogLeaf(nil), f.leaves...)
	desc := !strings.EqualFold(opts.Direction, model.RecordListDirectionAsc)
	sort.Slice(leaves, func(i, j int) bool {
		cmp := model.CompareUint64Position(leaves[i].LeafIndex, leaves[j].LeafIndex)
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
	out := make([]model.GlobalLogLeaf, 0, opts.Limit)
	for _, leaf := range leaves {
		if !model.Uint64AfterCursor(leaf.LeafIndex, opts.AfterLeafIndex, opts.Direction) {
			continue
		}
		out = append(out, leaf)
		if len(out) >= opts.Limit {
			break
		}
	}
	return out, nil
}

func (f fakeGlobalService) State(context.Context) (model.GlobalLogState, bool, error) {
	if f.state.TreeSize == 0 && len(f.state.RootHash) == 0 {
		return model.GlobalLogState{}, false, nil
	}
	return f.state, true, nil
}

func (f fakeGlobalService) Node(_ context.Context, level, startIndex uint64) (model.GlobalLogNode, bool, error) {
	for _, node := range f.nodes {
		if node.Level == level && node.StartIndex == startIndex {
			return node, true, nil
		}
	}
	return model.GlobalLogNode{}, false, nil
}

func (f fakeGlobalService) ListNodesAfter(_ context.Context, afterLevel, afterStartIndex uint64, limit int) ([]model.GlobalLogNode, error) {
	out := make([]model.GlobalLogNode, 0, limit)
	hasCursor := afterLevel != ^uint64(0) || afterStartIndex != ^uint64(0)
	for _, node := range f.nodes {
		if hasCursor && (node.Level < afterLevel || node.Level == afterLevel && node.StartIndex <= afterStartIndex) {
			continue
		}
		out = append(out, node)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f fakeGlobalService) InclusionProof(context.Context, string, uint64) (model.GlobalLogProof, error) {
	return model.GlobalLogProof{}, nil
}

func (f fakeGlobalService) ConsistencyProof(context.Context, uint64, uint64) (model.GlobalConsistencyProof, error) {
	return model.GlobalConsistencyProof{}, nil
}

func (f fakeGlobalService) Evidence(context.Context, string) (model.GlobalLogEvidence, error) {
	return f.evidence, nil
}

type fakeAnchorService struct {
	results []model.STHAnchorResult
}

func (f fakeAnchorService) AnchorResult(_ context.Context, treeSize uint64) (model.STHAnchorResult, bool, error) {
	for _, result := range f.results {
		if result.TreeSize == treeSize {
			return result, true, nil
		}
	}
	return model.STHAnchorResult{}, false, nil
}

func (f fakeAnchorService) Anchors(_ context.Context, opts model.AnchorListOptions) ([]model.STHAnchorResult, error) {
	items := append([]model.STHAnchorResult(nil), f.results...)
	desc := !strings.EqualFold(opts.Direction, model.RecordListDirectionAsc)
	sort.Slice(items, func(i, j int) bool {
		cmp := anchorschedule.CompareResultKeys(anchorschedule.ResultKey(items[i]), anchorschedule.ResultKey(items[j]))
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
	out := make([]model.STHAnchorResult, 0, opts.Limit)
	for _, item := range items {
		if opts.HasAfter {
			cmp := anchorschedule.CompareResultKeys(anchorschedule.ResultKey(item), opts.AfterResultKey)
			if opts.Direction == model.RecordListDirectionAsc && cmp <= 0 || opts.Direction != model.RecordListDirectionAsc && cmp >= 0 {
				continue
			}
		}
		out = append(out, item)
		if len(out) >= opts.Limit {
			break
		}
	}
	return out, nil
}
