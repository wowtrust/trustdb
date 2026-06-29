package grpcapi

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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
}

type typedNilGlobalService struct{}

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
