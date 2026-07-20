package sdk

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/grpcapi"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type GRPCOption func(*grpcTransportConfig)

type grpcTransportConfig struct {
	dialOptions          []grpc.DialOption
	transportCredentials credentials.TransportCredentials
}

func WithGRPCDialOptions(opts ...grpc.DialOption) GRPCOption {
	return func(c *grpcTransportConfig) {
		c.dialOptions = append(c.dialOptions, opts...)
	}
}

func WithGRPCTransportCredentials(creds credentials.TransportCredentials) GRPCOption {
	return func(c *grpcTransportConfig) {
		if creds != nil {
			c.transportCredentials = creds
		}
	}
}

func NewGRPCClient(target string, opts ...GRPCOption) (*Client, error) {
	transport, err := NewGRPCTransport(target, opts...)
	if err != nil {
		return nil, err
	}
	return NewClientWithTransport(transport)
}

func NewGRPCTransport(target string, opts ...GRPCOption) (Transport, error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return nil, errors.New("sdk: grpc target is empty")
	}
	cfg := grpcTransportConfig{}
	for _, apply := range opts {
		apply(&cfg)
	}
	if cfg.transportCredentials == nil {
		cfg.transportCredentials = insecure.NewCredentials()
	}
	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(cfg.transportCredentials),
		grpc.WithDefaultCallOptions(
			grpc.ForceCodec(grpcapi.Codec()),
			grpc.MaxCallRecvMsgSize(grpcapi.MaxMessageBytes),
			grpc.MaxCallSendMsgSize(grpcapi.MaxMessageBytes),
		),
	}
	dialOptions = append(dialOptions, cfg.dialOptions...)
	ctx, cancel := context.WithTimeout(context.Background(), defaultHTTPTimeout)
	defer cancel()
	conn, err := grpc.DialContext(ctx, trimmed, dialOptions...)
	if err != nil {
		return nil, &Error{Op: "grpc dial", URL: trimmed, Err: err}
	}
	return NewGRPCTransportFromConn(trimmed, conn), nil
}

func NewGRPCTransportFromConn(target string, conn *grpc.ClientConn) Transport {
	return &grpcTransport{target: target, conn: conn}
}

type grpcTransport struct {
	target string
	conn   *grpc.ClientConn
}

func (t *grpcTransport) Endpoint() string {
	return t.target
}

func (t *grpcTransport) Close() error {
	if t.conn == nil {
		return nil
	}
	return t.conn.Close()
}

func (t *grpcTransport) CheckHealth(ctx context.Context) HealthStatus {
	start := time.Now()
	callCtx, cancel := contextWithDefaultTimeout(ctx)
	defer cancel()
	var out grpcapi.HealthResponse
	err := t.invoke(callCtx, grpcapi.FullMethodHealth, &grpcapi.HealthRequest{}, &out)
	rtt := time.Since(start).Milliseconds()
	if err != nil {
		return HealthStatus{ServerURL: t.target, RTTMillis: rtt, Error: err.Error()}
	}
	if !out.OK {
		return HealthStatus{ServerURL: t.target, RTTMillis: rtt, Error: "server returned ok=false"}
	}
	return HealthStatus{OK: true, ServerURL: t.target, RTTMillis: rtt}
}

func (t *grpcTransport) SubmitSignedClaim(ctx context.Context, signed SignedClaim) (SubmitResult, error) {
	var out grpcapi.SubmitClaimResponse
	if err := t.invoke(ctx, grpcapi.FullMethodSubmitClaim, &grpcapi.SubmitClaimRequest{SignedClaim: signed}, &out); err != nil {
		return SubmitResult{}, err
	}
	return submitResultFromGRPC(out, signed), nil
}

func (t *grpcTransport) SubmitSignedClaims(ctx context.Context, signed []SignedClaim) ([]signedClaimBatchItemResult, error) {
	in := make(chan signedClaimStreamItem)
	out, err := t.SubmitSignedClaimStream(ctx, in)
	if err != nil {
		return nil, err
	}
	sendCtx := ctx
	if sendCtx == nil {
		sendCtx = context.Background()
	}
	go func() {
		defer close(in)
		for index, claim := range signed {
			select {
			case in <- signedClaimStreamItem{Index: index, SignedClaim: claim}:
			case <-sendCtx.Done():
				return
			}
		}
	}()
	results := make([]signedClaimBatchItemResult, len(signed))
	seen := 0
	for item := range out {
		if item.Index < 0 {
			return nil, item.Err
		}
		if item.Index >= len(signed) {
			return nil, &Error{Op: "grpc submit claim stream", URL: t.target, Message: "server returned out-of-range result index"}
		}
		results[item.Index] = signedClaimBatchItemResult{Index: item.Index, Result: item.Result, Err: item.Err}
		seen++
	}
	if seen != len(signed) {
		return nil, &Error{Op: "grpc submit claim stream", URL: t.target, Message: "server returned incomplete batch results"}
	}
	return results, nil
}

func (t *grpcTransport) SubmitSignedClaimStream(ctx context.Context, in <-chan signedClaimStreamItem) (<-chan signedClaimStreamItemResult, error) {
	if t.conn == nil {
		return nil, &Error{Op: "grpc submit claim stream", URL: t.target, Message: "grpc connection is nil"}
	}
	if in == nil {
		return nil, errors.New("sdk: signed claim stream is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithCancel(ctx)
	stream, err := t.conn.NewStream(callCtx, &grpc.StreamDesc{
		StreamName:    "SubmitClaimStream",
		ServerStreams: true,
		ClientStreams: true,
	}, grpcapi.FullMethodSubmitClaimStream, grpc.ForceCodec(grpcapi.Codec()))
	if err != nil {
		cancel()
		return nil, grpcError(grpcapi.FullMethodSubmitClaimStream, t.target, err)
	}
	out := make(chan signedClaimStreamItemResult, defaultHTTPConcurrency)
	var sent sync.Map
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer stream.CloseSend()
		for {
			var item signedClaimStreamItem
			var ok bool
			select {
			case <-callCtx.Done():
				return
			case item, ok = <-in:
				if !ok {
					return
				}
			}
			req := grpcapi.SubmitClaimStreamRequest{Index: item.Index, SignedClaim: item.SignedClaim}
			sent.Store(item.Index, item.SignedClaim)
			if err := stream.SendMsg(&req); err != nil {
				item := signedClaimStreamItemResult{Index: item.Index, Err: grpcError(grpcapi.FullMethodSubmitClaimStream, t.target, err)}
				select {
				case out <- item:
				default:
				}
				cancel()
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			var resp grpcapi.SubmitClaimStreamResponse
			if err := stream.RecvMsg(&resp); err != nil {
				if err != io.EOF {
					item := signedClaimStreamItemResult{Index: -1, Err: grpcError(grpcapi.FullMethodSubmitClaimStream, t.target, err)}
					select {
					case out <- item:
					default:
					}
				}
				return
			}
			cached, _ := sent.LoadAndDelete(resp.Index)
			item := signedClaimStreamItemResult{Index: resp.Index}
			if resp.Error != nil {
				item.Err = &Error{
					Op:      "grpc submit claim stream item",
					URL:     t.target,
					Code:    resp.Error.Code,
					Message: resp.Error.Message,
				}
			} else if resp.Result == nil {
				item.Err = &Error{Op: "grpc submit claim stream item", URL: t.target, Message: "server returned neither result nor error"}
			} else {
				signed, _ := cached.(SignedClaim)
				item.Result = submitResultFromGRPC(*resp.Result, signed)
			}
			select {
			case out <- item:
			case <-callCtx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		cancel()
		close(out)
	}()
	return out, nil
}

func (t *grpcTransport) GetRecord(ctx context.Context, recordID string) (RecordIndex, error) {
	var out grpcapi.GetRecordResponse
	if err := t.invoke(ctx, grpcapi.FullMethodGetRecord, &grpcapi.GetRecordRequest{RecordID: recordID}, &out); err != nil {
		return RecordIndex{}, err
	}
	if out.Record.RecordID == "" {
		return RecordIndex{}, &Error{Op: "grpc get record", URL: t.target, Message: "server returned empty record index"}
	}
	return out.Record, nil
}

func submitResultFromGRPC(out grpcapi.SubmitClaimResponse, signed SignedClaim) SubmitResult {
	return SubmitResult{
		RecordID:        out.RecordID,
		Status:          out.Status,
		ProofLevel:      out.ProofLevel,
		Idempotent:      out.Idempotent,
		BatchEnqueued:   out.BatchEnqueued,
		BatchError:      out.BatchError,
		ServerRecord:    out.ServerRecord,
		AcceptedReceipt: out.AcceptedReceipt,
		SignedClaim:     signed,
	}
}

func (t *grpcTransport) ListRecords(ctx context.Context, opts ListRecordsOptions) (RecordPage, error) {
	var out grpcapi.ListRecordsResponse
	in := grpcapi.ListRecordsRequest{
		Limit:             opts.Limit,
		Direction:         opts.Direction,
		Cursor:            opts.Cursor,
		BatchID:           opts.BatchID,
		TenantID:          opts.TenantID,
		ClientID:          opts.ClientID,
		ProofLevel:        opts.ProofLevel,
		Query:             opts.Query,
		ContentHashHex:    opts.ContentHashHex,
		ReceivedFromUnixN: opts.ReceivedFromUnixN,
		ReceivedToUnixN:   opts.ReceivedToUnixN,
	}
	if err := t.invoke(ctx, grpcapi.FullMethodListRecords, &in, &out); err != nil {
		return RecordPage{}, err
	}
	return RecordPage{Records: out.Records, Limit: out.Limit, Direction: out.Direction, NextCursor: out.NextCursor}, nil
}

func (t *grpcTransport) GetProofBundle(ctx context.Context, recordID string) (ProofBundle, error) {
	var out grpcapi.GetProofBundleResponse
	if err := t.invoke(ctx, grpcapi.FullMethodGetProofBundle, &grpcapi.GetProofBundleRequest{RecordID: recordID}, &out); err != nil {
		return ProofBundle{}, err
	}
	if out.ProofBundle.RecordID == "" {
		return ProofBundle{}, &Error{Op: "grpc get proof bundle", URL: t.target, Message: "server returned empty proof bundle"}
	}
	return out.ProofBundle, nil
}

func (t *grpcTransport) ListRootsPage(ctx context.Context, opts ListPageOptions) (RootPage, error) {
	var out grpcapi.ListRootsResponse
	in := grpcapi.ListRootsRequest{Limit: opts.Limit, Direction: opts.Direction, Cursor: opts.Cursor}
	if err := t.invoke(ctx, grpcapi.FullMethodListRoots, &in, &out); err != nil {
		return RootPage{}, err
	}
	return RootPage{Roots: out.Roots, Limit: out.Limit, Direction: out.Direction, NextCursor: out.NextCursor}, nil
}

func (t *grpcTransport) ListRoots(ctx context.Context, limit int) ([]BatchRoot, error) {
	page, err := t.ListRootsPage(ctx, ListPageOptions{Limit: limit, Direction: RecordListDirectionDesc})
	if err != nil {
		return nil, err
	}
	return page.Roots, nil
}

func (t *grpcTransport) LatestRoot(ctx context.Context) (BatchRoot, error) {
	var out grpcapi.LatestRootResponse
	if err := t.invoke(ctx, grpcapi.FullMethodLatestRoot, &grpcapi.LatestRootRequest{}, &out); err != nil {
		return BatchRoot{}, err
	}
	return out.Root, nil
}

func (t *grpcTransport) GetGlobalProof(ctx context.Context, batchID string) (GlobalLogProof, error) {
	var out grpcapi.GetGlobalProofResponse
	if err := t.invoke(ctx, grpcapi.FullMethodGetGlobalProof, &grpcapi.GetGlobalProofRequest{BatchID: batchID}, &out); err != nil {
		return GlobalLogProof{}, err
	}
	return out.Proof, nil
}

func (t *grpcTransport) ListSTHs(ctx context.Context, opts ListPageOptions) (TreeHeadPage, error) {
	var out grpcapi.ListSTHsResponse
	in := grpcapi.ListSTHsRequest{Limit: opts.Limit, Direction: opts.Direction, Cursor: opts.Cursor}
	if err := t.invoke(ctx, grpcapi.FullMethodListSTHs, &in, &out); err != nil {
		return TreeHeadPage{}, err
	}
	return TreeHeadPage{STHs: out.STHs, Limit: out.Limit, Direction: out.Direction, NextCursor: out.NextCursor}, nil
}

func (t *grpcTransport) ListGlobalLeaves(ctx context.Context, opts ListPageOptions) (GlobalLeafPage, error) {
	var out grpcapi.ListGlobalLeavesResponse
	in := grpcapi.ListGlobalLeavesRequest{Limit: opts.Limit, Direction: opts.Direction, Cursor: opts.Cursor}
	if err := t.invoke(ctx, grpcapi.FullMethodListGlobalLeaves, &in, &out); err != nil {
		return GlobalLeafPage{}, err
	}
	return GlobalLeafPage{Leaves: out.Leaves, Limit: out.Limit, Direction: out.Direction, NextCursor: out.NextCursor}, nil
}

func (t *grpcTransport) ListAnchors(ctx context.Context, opts ListPageOptions) (AnchorPage, error) {
	var out grpcapi.ListAnchorsResponse
	in := grpcapi.ListAnchorsRequest{Limit: opts.Limit, Direction: opts.Direction, Cursor: opts.Cursor}
	if err := t.invoke(ctx, grpcapi.FullMethodListAnchors, &in, &out); err != nil {
		return AnchorPage{}, err
	}
	items := make([]AnchorPageItem, 0, len(out.Anchors))
	for _, item := range out.Anchors {
		items = append(items, AnchorPageItem{
			TreeSize: item.TreeSize,
			Status:   item.Status,
			Result:   item.Result,
			Outbox:   item.Outbox,
		})
	}
	return AnchorPage{Anchors: items, Limit: out.Limit, Direction: out.Direction, NextCursor: out.NextCursor}, nil
}

func (t *grpcTransport) GetAnchor(ctx context.Context, treeSize uint64) (AnchorStatus, error) {
	var out grpcapi.GetAnchorResponse
	if err := t.invoke(ctx, grpcapi.FullMethodGetAnchor, &grpcapi.GetAnchorRequest{TreeSize: treeSize}, &out); err != nil {
		return AnchorStatus{}, err
	}
	return AnchorStatus{TreeSize: out.TreeSize, Status: out.Status, Result: out.Result}, nil
}

func (t *grpcTransport) LatestSTH(ctx context.Context) (SignedTreeHead, error) {
	var out grpcapi.LatestSTHResponse
	if err := t.invoke(ctx, grpcapi.FullMethodLatestSTH, &grpcapi.LatestSTHRequest{}, &out); err != nil {
		return SignedTreeHead{}, err
	}
	return out.STH, nil
}

func (t *grpcTransport) GetSTH(ctx context.Context, treeSize uint64) (SignedTreeHead, error) {
	var out grpcapi.GetSTHResponse
	if err := t.invoke(ctx, grpcapi.FullMethodGetSTH, &grpcapi.GetSTHRequest{TreeSize: treeSize}, &out); err != nil {
		return SignedTreeHead{}, err
	}
	return out.STH, nil
}

func (t *grpcTransport) MetricsRaw(ctx context.Context) (string, error) {
	var out grpcapi.MetricsResponse
	if err := t.invoke(ctx, grpcapi.FullMethodMetrics, &grpcapi.MetricsRequest{}, &out); err != nil {
		return "", err
	}
	return out.Text, nil
}

func (t *grpcTransport) invoke(ctx context.Context, method string, in any, out any) error {
	if t.conn == nil {
		return &Error{Op: "grpc invoke", URL: t.target, Message: "grpc connection is nil"}
	}
	callCtx, cancel := contextWithDefaultTimeout(ctx)
	defer cancel()
	if err := t.conn.Invoke(callCtx, method, in, out, grpc.ForceCodec(grpcapi.Codec())); err != nil {
		return grpcError(method, t.target, err)
	}
	return nil
}

func contextWithDefaultTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		return context.WithTimeout(context.Background(), defaultHTTPTimeout)
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, defaultHTTPTimeout)
}

func grpcError(method, target string, err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return &Error{Op: method, URL: target, Err: err}
	}
	return &Error{Op: method, URL: target, Code: trustCodeFromGRPC(st.Code()), Message: st.Message(), Err: err}
}

func trustCodeFromGRPC(code codes.Code) string {
	switch code {
	case codes.InvalidArgument:
		return string(trusterr.CodeInvalidArgument)
	case codes.AlreadyExists:
		return string(trusterr.CodeAlreadyExists)
	case codes.FailedPrecondition:
		return string(trusterr.CodeFailedPrecondition)
	case codes.NotFound:
		return string(trusterr.CodeNotFound)
	case codes.ResourceExhausted:
		return string(trusterr.CodeResourceExhausted)
	case codes.DeadlineExceeded:
		return string(trusterr.CodeDeadlineExceeded)
	case codes.DataLoss:
		return string(trusterr.CodeDataLoss)
	case codes.Unavailable:
		return string(trusterr.CodeFailedPrecondition)
	default:
		return string(trusterr.CodeInternal)
	}
}
