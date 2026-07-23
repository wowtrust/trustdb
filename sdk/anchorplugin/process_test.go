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
	return Info{SinkName: "test-go", ProofSchema: "test-proof.v1"}, nil
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
