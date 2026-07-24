package sdk

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/grpcapi"
	"github.com/wowtrust/trustdb/internal/ingest"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPCTransportOperationalEndpoints(t *testing.T) {
	t.Parallel()

	client := newBufconnClient(t, grpcapi.NewServerWithSubmitterAndAnchorSystems(nil, grpcTestBatch{}, nil, grpcTestAnchors{}, grpcTestAnchorSystems{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("trustdb_ingest_total 1\n"))
	})))

	if status := client.CheckHealth(context.Background()); !status.OK || status.ServerURL != "bufnet" {
		t.Fatalf("health status = %+v", status)
	}
	record, err := client.GetRecord(context.Background(), "tr1record")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if record.RecordID != "tr1record" || record.BatchID != "batch-1" {
		t.Fatalf("record = %+v", record)
	}
	page, err := client.ListRecords(context.Background(), ListRecordsOptions{Limit: 5, Direction: RecordListDirectionAsc, Query: "hello"})
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(page.Records) != 1 || page.Direction != RecordListDirectionAsc {
		t.Fatalf("page = %+v", page)
	}
	roots, err := client.ListRoots(context.Background(), 7)
	if err != nil {
		t.Fatalf("ListRoots: %v", err)
	}
	if len(roots) != 1 || roots[0].BatchID != "batch-1" {
		t.Fatalf("roots = %+v", roots)
	}
	latest, err := client.LatestRoot(context.Background())
	if err != nil {
		t.Fatalf("LatestRoot: %v", err)
	}
	if latest.BatchID != "batch-latest" {
		t.Fatalf("latest = %+v", latest)
	}
	anchors, err := client.ListAnchors(context.Background(), ListPageOptions{Limit: 5, Direction: RecordListDirectionDesc})
	if err != nil {
		t.Fatalf("ListAnchors: %v", err)
	}
	if len(anchors.Anchors) != 1 || anchors.Anchors[0].Status != model.AnchorStatePublished || anchors.Anchors[0].Result == nil || anchors.Anchors[0].Result.AnchorID != "anchor-4" {
		t.Fatalf("anchors = %+v", anchors)
	}
	anchorStatus, err := client.GetAnchor(context.Background(), 4)
	if err != nil {
		t.Fatalf("GetAnchor: %v", err)
	}
	if anchorStatus.Status != model.AnchorStatePublished || anchorStatus.Result == nil || anchorStatus.Result.AnchorID != "anchor-4" {
		t.Fatalf("anchor status = %+v", anchorStatus)
	}
	systems, err := client.ListAnchorSystems(context.Background())
	if err != nil || len(systems) != 1 || systems[0].SystemID != "chain-a" {
		t.Fatalf("ListAnchorSystems()=%+v err=%v", systems, err)
	}
	systemStatus, err := client.GetAnchorSystemStatus(context.Background(), "chain-a")
	if err != nil || systemStatus.State != model.AnchorSystemStateHealthy {
		t.Fatalf("GetAnchorSystemStatus()=%+v err=%v", systemStatus, err)
	}
	resources, err := client.ListAnchorSystemResources(context.Background(), "chain-a", AnchorResourceListOptions{Kind: model.AnchorResourceKindNode, Limit: 5})
	if err != nil || len(resources.Resources) != 1 || resources.Resources[0].ResourceID != "node-1" {
		t.Fatalf("ListAnchorSystemResources()=%+v err=%v", resources, err)
	}
	bundle, err := client.GetProofBundle(context.Background(), "tr1record")
	if err != nil {
		t.Fatalf("GetProofBundle: %v", err)
	}
	if bundle.RecordID != "tr1record" {
		t.Fatalf("bundle = %+v", bundle)
	}
	metrics, err := client.MetricsRaw(context.Background())
	if err != nil {
		t.Fatalf("MetricsRaw: %v", err)
	}
	if !strings.Contains(metrics, "trustdb_ingest_total") {
		t.Fatalf("metrics = %q", metrics)
	}
}

type grpcTestAnchorSystems struct{}

func (grpcTestAnchorSystems) Systems(context.Context) ([]model.AnchorSystem, error) {
	return []model.AnchorSystem{grpcSDKTestSystem()}, nil
}
func (grpcTestAnchorSystems) System(_ context.Context, id string) (model.AnchorSystem, bool, error) {
	return grpcSDKTestSystem(), id == "chain-a", nil
}
func (grpcTestAnchorSystems) Status(_ context.Context, id string) (model.AnchorSystemStatus, bool, error) {
	return model.AnchorSystemStatus{SchemaVersion: model.SchemaAnchorSystemStatus, SystemID: "chain-a", State: model.AnchorSystemStateHealthy, ObservedAtUnixN: 1}, id == "chain-a", nil
}
func (grpcTestAnchorSystems) Resources(_ context.Context, id string, opts model.AnchorResourceListOptions) (model.AnchorSystemResourcePage, bool, error) {
	return model.AnchorSystemResourcePage{Resources: []model.AnchorSystemResource{{SchemaVersion: model.SchemaAnchorSystemResource, SystemID: "chain-a", Kind: opts.Kind, ResourceID: "node-1"}}, Limit: opts.Limit}, id == "chain-a", nil
}
func (grpcTestAnchorSystems) Resource(_ context.Context, id, kind, resourceID string) (model.AnchorSystemResource, bool, error) {
	return model.AnchorSystemResource{SchemaVersion: model.SchemaAnchorSystemResource, SystemID: "chain-a", Kind: kind, ResourceID: resourceID}, id == "chain-a", nil
}
func grpcSDKTestSystem() model.AnchorSystem {
	return model.AnchorSystem{SchemaVersion: model.SchemaAnchorSystem, SystemID: "chain-a", SinkName: "chain", DisplayName: "Chain A", Kind: model.AnchorSystemKindEvidenceBlockchain, Capabilities: []string{model.AnchorCapabilityNodeRead}}
}

func TestGRPCTransportMapsNotFound(t *testing.T) {
	t.Parallel()

	client := newBufconnClient(t, grpcapi.NewServer(nil, grpcTestBatch{}, nil, nil, nil))
	_, err := client.GetRecord(context.Background(), "missing")
	if err == nil {
		t.Fatal("GetRecord error = nil, want not found")
	}
	if !IsNotFound(err) {
		t.Fatalf("IsNotFound(%T %v) = false", err, err)
	}
}

func TestGRPCEndpointErrorRetryability(t *testing.T) {
	t.Parallel()

	unavailable := grpcError("test", "primary", status.Error(codes.Unavailable, "down"))
	if !retryableEndpointError(unavailable) {
		t.Fatalf("Unavailable error is terminal: %v", unavailable)
	}
	failedPrecondition := grpcError("test", "primary", status.Error(codes.FailedPrecondition, "invalid state"))
	if retryableEndpointError(failedPrecondition) {
		t.Fatalf("FailedPrecondition error is retryable: %v", failedPrecondition)
	}
}

func TestGRPCTransportSubmitLogStream(t *testing.T) {
	t.Parallel()

	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	processor := grpcProcessorFunc(func(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
		result := validSDKSubmitResult(signed, "")
		return result.ServerRecord, result.AcceptedReceipt, false, nil
	})
	ingestSvc := ingest.New(processor, ingest.Options{QueueSize: 8, Workers: 2}, nil)
	defer ingestSvc.Shutdown(context.Background())
	client := newBufconnClient(t, grpcapi.NewServer(ingestSvc, grpcTestBatch{}, nil, nil, nil))

	entries := make(chan LogEntry)
	out, err := client.SubmitLogStream(
		context.Background(),
		entries,
		mustINTLV1Identity(t, "tenant-1", "client-1", "client-key-1", priv),
		LogStreamOptions{QueueSize: 2},
	)
	if err != nil {
		t.Fatalf("SubmitLogStream: %v", err)
	}
	go func() {
		defer close(entries)
		entries <- LogEntry{Body: []byte(`{"n":1}`), Options: LogClaimOptions{CustomMetadata: map[string]string{"log_id": "one"}}}
		entries <- LogEntry{Body: []byte(`{"n":2}`), Options: LogClaimOptions{CustomMetadata: map[string]string{"log_id": "two"}}}
	}()

	got := map[string]bool{}
	for item := range out {
		if item.Err != nil {
			t.Fatalf("stream item error: %v", item.Err)
		}
		logID := item.Result.SignedClaim.Claim.Metadata.Custom["log_id"]
		got[logID] = true
		if logID == "" {
			t.Fatalf("signed claim was not attached to result: %+v", item.Result)
		}
	}
	if !got["one"] || !got["two"] || len(got) != 2 {
		t.Fatalf("records = %v", got)
	}
}

func TestGRPCTransportRemoteStreamTerminationClosesLogStream(t *testing.T) {
	t.Parallel()

	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	server := &grpcTerminatingStreamServer{Server: grpcapi.NewServer(nil, grpcTestBatch{}, nil, nil, nil)}
	client := newBufconnClient(t, server)
	entries := make(chan LogEntry)
	t.Cleanup(func() { close(entries) })
	out, err := client.SubmitLogStream(
		context.Background(),
		entries,
		mustINTLV1Identity(t, "tenant", "client", "key", privateKey),
		LogStreamOptions{QueueSize: 1},
	)
	if err != nil {
		t.Fatalf("SubmitLogStream: %v", err)
	}

	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("result stream emitted an item after the remote stream ended")
		}
	case <-time.After(time.Second):
		t.Fatal("result stream did not close after the remote stream ended")
	}
}

func TestGRPCV1ServiceIsNotRegistered(t *testing.T) {
	t.Parallel()

	conn := newBufconnConnection(t, grpcapi.NewServer(nil, grpcTestBatch{}, nil, nil, nil))
	var out grpcapi.HealthResponse
	err := conn.Invoke(
		context.Background(),
		"/trustdb.v1.TrustDB/Health",
		&grpcapi.HealthRequest{},
		&out,
		grpc.ForceCodec(grpcapi.Codec()),
	)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("legacy service code = %s err=%v, want UNIMPLEMENTED", status.Code(err), err)
	}
}

func newBufconnConnection(t *testing.T, srv grpcapi.TrustDBServiceServer) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(grpcapi.MaxMessageBytes),
		grpc.MaxSendMsgSize(grpcapi.MaxMessageBytes),
	)
	grpcapi.RegisterTrustDBServiceServer(server, srv)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.ForceCodec(grpcapi.Codec()),
			grpc.MaxCallRecvMsgSize(grpcapi.MaxMessageBytes),
			grpc.MaxCallSendMsgSize(grpcapi.MaxMessageBytes),
		),
	)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func newBufconnClient(t *testing.T, srv grpcapi.TrustDBServiceServer) *Client {
	t.Helper()
	conn := newBufconnConnection(t, srv)
	client, err := NewClientWithTransport(NewGRPCTransportFromConn("bufnet", conn))
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	return client
}

type grpcTestBatch struct{}

type grpcTestAnchors struct{}

type grpcTerminatingStreamServer struct {
	*grpcapi.Server
}

func (*grpcTerminatingStreamServer) SubmitClaimStream(grpcapi.TrustDBService_SubmitClaimStreamServer) error {
	return nil
}

type grpcProcessorFunc func(context.Context, model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error)

func (f grpcProcessorFunc) Submit(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
	return f(ctx, signed)
}

func (grpcTestBatch) Enqueue(context.Context, model.SignedClaim, model.ServerRecord, model.AcceptedReceipt) error {
	return nil
}

func (grpcTestBatch) Proof(context.Context, string) (model.ProofBundle, error) {
	return model.ProofBundle{SchemaVersion: model.SchemaProofBundle, CryptoSuite: cryptosuite.INTLV1, RecordID: "tr1record"}, nil
}

func (grpcTestBatch) RecordIndex(_ context.Context, recordID string) (model.RecordIndex, bool, error) {
	if recordID == "missing" {
		return model.RecordIndex{}, false, nil
	}
	return model.RecordIndex{SchemaVersion: model.SchemaRecordIndex, CryptoSuite: cryptosuite.INTLV1, RecordID: "tr1record", BatchID: "batch-1"}, true, nil
}

func (grpcTestBatch) Records(_ context.Context, opts model.RecordListOptions) ([]model.RecordIndex, error) {
	if opts.Query != "" && opts.Query != "hello" {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "unexpected query")
	}
	return []model.RecordIndex{{SchemaVersion: model.SchemaRecordIndex, CryptoSuite: cryptosuite.INTLV1, RecordID: "tr1record", BatchID: "batch-1", ReceivedAtUnixN: 10}}, nil
}

func (grpcTestBatch) Roots(context.Context, int) ([]model.BatchRoot, error) {
	return []model.BatchRoot{{SchemaVersion: model.SchemaBatchRoot, CryptoSuite: cryptosuite.INTLV1, BatchID: "batch-1", TreeSize: 1}}, nil
}

func (grpcTestBatch) RootsAfter(context.Context, int64, int) ([]model.BatchRoot, error) {
	return []model.BatchRoot{{SchemaVersion: model.SchemaBatchRoot, CryptoSuite: cryptosuite.INTLV1, BatchID: "batch-2", TreeSize: 2, ClosedAtUnixN: 20}}, nil
}

func (grpcTestBatch) RootsPage(context.Context, model.RootListOptions) ([]model.BatchRoot, error) {
	return []model.BatchRoot{{SchemaVersion: model.SchemaBatchRoot, CryptoSuite: cryptosuite.INTLV1, BatchID: "batch-1", TreeSize: 1, ClosedAtUnixN: 10}}, nil
}

func (grpcTestBatch) LatestRoot(context.Context) (model.BatchRoot, error) {
	return model.BatchRoot{SchemaVersion: model.SchemaBatchRoot, CryptoSuite: cryptosuite.INTLV1, BatchID: "batch-latest", TreeSize: 3}, nil
}

func (grpcTestBatch) Manifest(context.Context, string) (model.BatchManifest, error) {
	return model.BatchManifest{SchemaVersion: model.SchemaBatchManifest, CryptoSuite: cryptosuite.INTLV1, BatchID: "batch-1", TreeSize: 1}, nil
}

func (grpcTestBatch) BatchTreeLeaves(context.Context, model.BatchTreeLeafListOptions) ([]model.BatchTreeLeaf, error) {
	return []model.BatchTreeLeaf{{SchemaVersion: model.SchemaBatchTreeLeaf, CryptoSuite: cryptosuite.INTLV1, BatchID: "batch-1", RecordID: "tr1record", LeafIndex: 0}}, nil
}

func (grpcTestBatch) BatchTreeNodes(context.Context, model.BatchTreeNodeListOptions) ([]model.BatchTreeNode, error) {
	return []model.BatchTreeNode{{SchemaVersion: model.SchemaBatchTreeNode, CryptoSuite: cryptosuite.INTLV1, BatchID: "batch-1", Level: 0, StartIndex: 0, Width: 1}}, nil
}

func (grpcTestAnchors) AnchorResult(_ context.Context, treeSize uint64) (model.STHAnchorResult, bool, error) {
	if treeSize != 4 {
		return model.STHAnchorResult{}, false, nil
	}
	return model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		CryptoSuite:   cryptosuite.INTLV1,
		EvidenceStage: model.AnchorEvidenceStageOfflineVerified,
		TreeSize:      4,
		SinkName:      "ots",
		AnchorID:      "anchor-4",
		STH:           model.SignedTreeHead{CryptoSuite: cryptosuite.INTLV1},
	}, true, nil
}

func (grpcTestAnchors) Anchors(context.Context, model.AnchorListOptions) ([]model.STHAnchorResult, error) {
	return []model.STHAnchorResult{{
		SchemaVersion: model.SchemaSTHAnchorResult,
		CryptoSuite:   cryptosuite.INTLV1,
		EvidenceStage: model.AnchorEvidenceStageOfflineVerified,
		TreeSize:      4,
		SinkName:      "ots",
		AnchorID:      "anchor-4",
		STH:           model.SignedTreeHead{CryptoSuite: cryptosuite.INTLV1},
	}}, nil
}
