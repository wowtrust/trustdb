package anchorplugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const helperEnv = "TRUSTDB_ANCHOR_PLUGIN_TEST_HELPER"

type helperPlugin struct{}

func (helperPlugin) Info(context.Context) (Info, error) {
	return Info{SinkName: "test-go", ProofSchema: "test-proof.v1", System: &System{
		SystemID: "test-chain", DisplayName: "Test chain", Kind: SystemKindEvidenceBlockchain,
		Capabilities: []string{CapabilitySystemStatusRead, CapabilityNodeRead},
	}}, nil
}

func (helperPlugin) Publish(_ context.Context, sth SignedTreeHead) (AnchorResult, error) {
	sum := sha256.Sum256(sth.RootHash)
	return AnchorResult{AnchorID: fmt.Sprintf("test-%d", sth.TreeSize), Proof: sum[:], PublishedAtUnixN: 1}, nil
}

func (helperPlugin) Verify(_ context.Context, sth SignedTreeHead, result AnchorResult) error {
	sum := sha256.Sum256(sth.RootHash)
	if result.AnchorID != fmt.Sprintf("test-%d", sth.TreeSize) || !bytes.Equal(result.Proof, sum[:]) {
		return Permanent(fmt.Errorf("invalid test proof"))
	}
	return nil
}

func (helperPlugin) Status(context.Context) (SystemStatus, error) {
	return SystemStatus{State: "healthy", ObservedAtUnixN: 2, Details: map[string]string{"node_count": "1"}}, nil
}

func (helperPlugin) ListResources(_ context.Context, req ListResourcesRequest) (ListResourcesResponse, error) {
	return ListResourcesResponse{Resources: []Resource{{Kind: req.Kind, ResourceID: "node-1", Status: "online"}}, Limit: req.Limit}, nil
}

func (helperPlugin) Resource(_ context.Context, kind, id string) (Resource, bool, error) {
	if kind == "node" && id == "node-1" {
		return Resource{Kind: kind, ResourceID: id, Status: "online"}, true, nil
	}
	return Resource{}, false, nil
}

func TestAnchorPluginHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		return
	}
	if err := Serve(context.Background(), helperPlugin{}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(0)
}

func TestProcessPublishAndVerify(t *testing.T) {
	process, err := StartProcess(context.Background(), ProcessConfig{
		Command:      os.Args[0],
		Args:         []string{"-test.run=TestAnchorPluginHelperProcess"},
		Env:          []string{helperEnv + "=1"},
		StartTimeout: 5 * time.Second,
		RPCTimeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("StartProcess() error = %v", err)
	}
	defer process.Close()

	if got := process.Info().SinkName; got != "test-go" {
		t.Fatalf("sink name = %q", got)
	}
	if process.Info().System == nil || process.Info().System.SystemID != "test-chain" {
		t.Fatalf("system info = %+v", process.Info().System)
	}
	sth := SignedTreeHead{SchemaVersion: "sth.v1", TreeSize: 7, RootHash: bytes.Repeat([]byte{0x23}, 32)}
	result, err := process.Publish(context.Background(), sth)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if err := process.Verify(context.Background(), sth, result); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	result.Proof[0] ^= 0xff
	err = process.Verify(context.Background(), sth, result)
	if err == nil || !IsPermanentRPC(err) {
		t.Fatalf("tampered Verify() error = %v, want permanent RPC error", err)
	}
	status, err := process.Status(context.Background())
	if err != nil || status.State != "healthy" {
		t.Fatalf("Status() = %+v err=%v", status, err)
	}
	page, err := process.ListResources(context.Background(), ListResourcesRequest{Kind: "node", Limit: 10})
	if err != nil || len(page.Resources) != 1 || page.Resources[0].ResourceID != "node-1" {
		t.Fatalf("ListResources() = %+v err=%v", page, err)
	}
	resource, found, err := process.Resource(context.Background(), "node", "node-1")
	if err != nil || !found || resource.Status != "online" {
		t.Fatalf("Resource() = %+v found=%v err=%v", resource, found, err)
	}
}

func TestValidateSinkName(t *testing.T) {
	for _, valid := range []string{"bcos", "example-go", "vendor.chain_v2"} {
		if err := ValidateSinkName(valid); err != nil {
			t.Fatalf("ValidateSinkName(%q) error = %v", valid, err)
		}
	}
	for _, invalid := range []string{"", "UPPER", "-leading", "has space"} {
		if err := ValidateSinkName(invalid); err == nil {
			t.Fatalf("ValidateSinkName(%q) succeeded", invalid)
		}
	}
}

func TestRPCRejectsMissingMagicCookie(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(
		grpc.ForceServerCodec(Codec()),
		grpc.UnaryInterceptor(cookieInterceptor("expected-cookie")),
	)
	RegisterRPCServer(server, pluginServer{plugin: helperPlugin{}})
	go server.Serve(listener)
	defer server.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(Codec())),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = NewRPCClient(conn).GetInfo(ctx, &GetInfoRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("GetInfo() error = %v, want Unauthenticated", err)
	}
}
