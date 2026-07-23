package grpcapi

import (
	"context"
	"encoding/base64"
	"sort"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/httpapi"
	"github.com/wowtrust/trustdb/internal/ingest"
	"github.com/wowtrust/trustdb/internal/model"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSubmitClaimKeepsAcceptedBatchEnqueueAliveAfterRequestCancellation(t *testing.T) {
	t.Parallel()

	ingestSvc := ingest.New(grpcProcessorFunc(func(context.Context, model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
		return model.ServerRecord{RecordID: "tr1backpressure"}, model.AcceptedReceipt{RecordID: "tr1backpressure", Status: "accepted"}, false, nil
	}), ingest.Options{QueueSize: 1, Workers: 1}, nil)
	defer ingestSvc.Shutdown(context.Background())
	batchSvc := &blockingBatchService{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	server := NewServer(ingestSvc, batchSvc, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		response *SubmitClaimResponse
		err      error
	}
	done := make(chan result, 1)
	go func() {
		response, err := server.SubmitClaim(ctx, &SubmitClaimRequest{SignedClaim: model.SignedClaim{SchemaVersion: model.SchemaSignedClaim}})
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
		t.Fatalf("SubmitClaim returned while accepted batch enqueue was blocked: response=%+v err=%v", got.response, got.err)
	case <-time.After(100 * time.Millisecond):
	}

	close(batchSvc.release)
	select {
	case got := <-done:
		if got.err != nil || got.response == nil || !got.response.BatchEnqueued || got.response.BatchError != "" {
			t.Fatalf("SubmitClaim result after releasing backpressure = %+v err=%v", got.response, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SubmitClaim did not finish after releasing batch backpressure")
	}
}

type grpcProcessorFunc func(context.Context, model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error)

func (f grpcProcessorFunc) Submit(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
	return f(ctx, signed)
}

type blockingBatchService struct {
	httpapi.BatchService
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

type evidenceGlobalService struct {
	httpapi.GlobalLogService
	evidence model.GlobalLogEvidence
}

func (s evidenceGlobalService) Evidence(context.Context, string) (model.GlobalLogEvidence, error) {
	return s.evidence, nil
}

func TestGetGlobalEvidence(t *testing.T) {
	t.Parallel()
	want := model.GlobalLogEvidence{GlobalProof: model.GlobalLogProof{BatchID: "batch-1", TreeSize: 7}}
	server := NewServer(nil, nil, evidenceGlobalService{evidence: want}, nil, nil)
	got, err := server.GetGlobalEvidence(context.Background(), &GetGlobalEvidenceRequest{BatchID: "batch-1"})
	if err != nil {
		t.Fatalf("GetGlobalEvidence: %v", err)
	}
	if got.Evidence.GlobalProof.TreeSize != 7 {
		t.Fatalf("GetGlobalEvidence=%+v", got)
	}
}

func TestAnchorEndpointsExposePublishedResultsOnly(t *testing.T) {
	t.Parallel()

	anchors := resultAnchorService{results: []model.STHAnchorResult{
		{SchemaVersion: model.SchemaSTHAnchorResult, TreeSize: 4, SinkName: "ots", AnchorID: "anchor-4"},
		{SchemaVersion: model.SchemaSTHAnchorResult, TreeSize: 4, SinkName: "file", AnchorID: "anchor-4-file"},
		{SchemaVersion: model.SchemaSTHAnchorResult, TreeSize: 2, SinkName: "ots", AnchorID: "anchor-2"},
	}}
	server := NewServer(nil, nil, nil, anchors, nil)

	got, err := server.GetAnchor(context.Background(), &GetAnchorRequest{TreeSize: 4})
	if err != nil {
		t.Fatalf("GetAnchor: %v", err)
	}
	if got.TreeSize != 4 || got.Status != model.AnchorStatePublished || got.ProofLevel != "L5" || got.Result == nil || got.Result.AnchorID != "anchor-4" {
		t.Fatalf("GetAnchor = %+v", got)
	}

	page, err := server.ListAnchors(context.Background(), &ListAnchorsRequest{Limit: 1, Direction: model.RecordListDirectionDesc})
	if err != nil {
		t.Fatalf("ListAnchors: %v", err)
	}
	if len(page.Anchors) != 1 || page.Anchors[0].Result == nil || page.Anchors[0].Result.AnchorID != "anchor-4" || page.Anchors[0].Status != model.AnchorStatePublished || page.NextCursor == "" {
		t.Fatalf("ListAnchors = %+v", page)
	}
	secondPage, err := server.ListAnchors(context.Background(), &ListAnchorsRequest{Limit: 1, Direction: model.RecordListDirectionDesc, Cursor: page.NextCursor})
	if err != nil {
		t.Fatalf("ListAnchors second page: %v", err)
	}
	if len(secondPage.Anchors) != 1 || secondPage.Anchors[0].Result == nil || secondPage.Anchors[0].Result.AnchorID != "anchor-4-file" {
		t.Fatalf("ListAnchors second page skipped same-tree sink: %+v", secondPage)
	}

	_, err = server.GetAnchor(context.Background(), &GetAnchorRequest{TreeSize: 3})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("GetAnchor unpublished status = %v, want %v err=%v", status.Code(err), codes.NotFound, err)
	}
}

func TestNewServerNormalizesTypedNilGlobalService(t *testing.T) {
	t.Parallel()

	var global *typedNilGlobalService
	server := NewServer(nil, nil, global, nil, nil)
	if server.Global != nil {
		t.Fatalf("server.Global = %#v, want nil", server.Global)
	}
	_, err := server.GetGlobalProof(context.Background(), &GetGlobalProofRequest{BatchID: "batch-1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("GetGlobalProof status = %v, want %v err=%v", status.Code(err), codes.FailedPrecondition, err)
	}
}

func TestDecodeCursorsRejectTrailingJSONData(t *testing.T) {
	t.Parallel()

	recordRaw := base64.RawURLEncoding.EncodeToString([]byte(`{"t":1,"r":"rec-1"}{}`))
	if _, err := decodeRecordCursor(recordRaw); err == nil {
		t.Fatal("decodeRecordCursor() error = nil, want trailing JSON rejection")
	}

	rootRaw := base64.RawURLEncoding.EncodeToString([]byte(`{"t":1,"b":"batch-1"}{}`))
	if _, err := decodeRootCursor(rootRaw); err == nil {
		t.Fatal("decodeRootCursor() error = nil, want trailing JSON rejection")
	}

	uint64Raw := base64.RawURLEncoding.EncodeToString([]byte(`{"v":1}{}`))
	if _, err := decodeUint64Cursor(uint64Raw); err == nil {
		t.Fatal("decodeUint64Cursor() error = nil, want trailing JSON rejection")
	}

	anchorRaw := base64.RawURLEncoding.EncodeToString([]byte(`{"t":1,"s":"file"}{}`))
	if _, err := decodeAnchorCursor(anchorRaw); err == nil {
		t.Fatal("decodeAnchorCursor() error = nil, want trailing JSON rejection")
	}
}

type typedNilGlobalService struct{}

type resultAnchorService struct {
	results []model.STHAnchorResult
}

func (s resultAnchorService) AnchorResult(_ context.Context, treeSize uint64) (model.STHAnchorResult, bool, error) {
	for _, result := range s.results {
		if result.TreeSize == treeSize {
			return result, true, nil
		}
	}
	return model.STHAnchorResult{}, false, nil
}

func (s resultAnchorService) Anchors(_ context.Context, opts model.AnchorListOptions) ([]model.STHAnchorResult, error) {
	ordered := append([]model.STHAnchorResult(nil), s.results...)
	sort.Slice(ordered, func(i, j int) bool {
		cmp := anchorschedule.CompareResultKeys(anchorschedule.ResultKey(ordered[i]), anchorschedule.ResultKey(ordered[j]))
		if opts.Direction == model.RecordListDirectionAsc {
			return cmp < 0
		}
		return cmp > 0
	})
	results := make([]model.STHAnchorResult, 0, min(opts.Limit, len(ordered)))
	for _, result := range ordered {
		if opts.HasAfter {
			cmp := anchorschedule.CompareResultKeys(anchorschedule.ResultKey(result), opts.AfterResultKey)
			if opts.Direction == model.RecordListDirectionAsc && cmp <= 0 || opts.Direction != model.RecordListDirectionAsc && cmp >= 0 {
				continue
			}
		}
		results = append(results, result)
		if len(results) == opts.Limit {
			break
		}
	}
	return results, nil
}

func (*typedNilGlobalService) LatestSTH(context.Context) (model.SignedTreeHead, bool, error) {
	panic("typed nil global service should be normalized before use")
}

func (*typedNilGlobalService) STH(context.Context, uint64) (model.SignedTreeHead, bool, error) {
	panic("typed nil global service should be normalized before use")
}

func (*typedNilGlobalService) ListSTHs(context.Context, model.TreeHeadListOptions) ([]model.SignedTreeHead, error) {
	panic("typed nil global service should be normalized before use")
}

func (*typedNilGlobalService) ListLeaves(context.Context, model.GlobalLeafListOptions) ([]model.GlobalLogLeaf, error) {
	panic("typed nil global service should be normalized before use")
}

func (*typedNilGlobalService) State(context.Context) (model.GlobalLogState, bool, error) {
	panic("typed nil global service should be normalized before use")
}

func (*typedNilGlobalService) Node(context.Context, uint64, uint64) (model.GlobalLogNode, bool, error) {
	panic("typed nil global service should be normalized before use")
}

func (*typedNilGlobalService) ListNodesAfter(context.Context, uint64, uint64, int) ([]model.GlobalLogNode, error) {
	panic("typed nil global service should be normalized before use")
}

func (*typedNilGlobalService) InclusionProof(context.Context, string, uint64) (model.GlobalLogProof, error) {
	panic("typed nil global service should be normalized before use")
}

func (*typedNilGlobalService) ConsistencyProof(context.Context, uint64, uint64) (model.GlobalConsistencyProof, error) {
	panic("typed nil global service should be normalized before use")
}
