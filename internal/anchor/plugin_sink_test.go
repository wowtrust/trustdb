package anchor

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/sdk/anchorplugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakePluginProcess struct {
	info       anchorplugin.GetInfoResponse
	result     anchorplugin.AnchorResult
	publishErr error
	verifyErr  error
	closed     int
}

func (p *fakePluginProcess) Info() anchorplugin.GetInfoResponse { return p.info }
func (p *fakePluginProcess) Publish(context.Context, anchorplugin.SignedTreeHead) (anchorplugin.AnchorResult, error) {
	return p.result, p.publishErr
}
func (p *fakePluginProcess) Verify(context.Context, anchorplugin.SignedTreeHead, anchorplugin.AnchorResult) error {
	return p.verifyErr
}
func (p *fakePluginProcess) Close() error { p.closed++; return nil }

func TestPluginSinkRestartsAfterTransientRPCFailure(t *testing.T) {
	first := &fakePluginProcess{
		info:       anchorplugin.GetInfoResponse{SinkName: "vendor-chain"},
		publishErr: status.Error(codes.Unavailable, "crashed"),
	}
	second := &fakePluginProcess{
		info:   anchorplugin.GetInfoResponse{SinkName: "vendor-chain"},
		result: anchorplugin.AnchorResult{AnchorID: "external-1", Proof: []byte("proof"), PublishedAtUnixN: 11},
	}
	processes := []pluginProcess{first, second}
	factoryCalls := 0
	sink, err := newPluginSink(context.Background(), PluginSinkOptions{Command: "helper"}, func(context.Context, anchorplugin.ProcessConfig) (pluginProcess, error) {
		process := processes[factoryCalls]
		factoryCalls++
		return process, nil
	})
	if err != nil {
		t.Fatalf("newPluginSink() error = %v", err)
	}
	defer sink.Close()

	sth := model.SignedTreeHead{TreeSize: 1, RootHash: bytes.Repeat([]byte{1}, 32)}
	if _, err := sink.Publish(context.Background(), sth); err == nil || errors.Is(err, ErrPermanent) {
		t.Fatalf("first Publish() error = %v, want transient", err)
	}
	if first.closed != 1 {
		t.Fatalf("first process close count = %d", first.closed)
	}
	result, err := sink.Publish(context.Background(), sth)
	if err != nil {
		t.Fatalf("second Publish() error = %v", err)
	}
	if result.AnchorID != "external-1" || !bytes.Equal(result.Proof, []byte("proof")) || factoryCalls != 2 {
		t.Fatalf("second result = %+v factoryCalls=%d", result, factoryCalls)
	}
}

func TestPluginSinkMapsPermanentRPCFailure(t *testing.T) {
	process := &fakePluginProcess{
		info:       anchorplugin.GetInfoResponse{SinkName: "vendor-chain"},
		publishErr: status.Error(codes.FailedPrecondition, "schema rejected"),
	}
	sink, err := newPluginSink(context.Background(), PluginSinkOptions{Command: "helper"}, func(context.Context, anchorplugin.ProcessConfig) (pluginProcess, error) {
		return process, nil
	})
	if err != nil {
		t.Fatalf("newPluginSink() error = %v", err)
	}
	defer sink.Close()
	_, err = sink.Publish(context.Background(), model.SignedTreeHead{TreeSize: 1, RootHash: bytes.Repeat([]byte{1}, 32)})
	if !errors.Is(err, ErrPermanent) {
		t.Fatalf("Publish() error = %v, want ErrPermanent", err)
	}
}

func TestPluginSinkRejectsBuiltInName(t *testing.T) {
	process := &fakePluginProcess{info: anchorplugin.GetInfoResponse{SinkName: OtsSinkName}}
	_, err := newPluginSink(context.Background(), PluginSinkOptions{Command: "helper"}, func(context.Context, anchorplugin.ProcessConfig) (pluginProcess, error) {
		return process, nil
	})
	if err == nil {
		t.Fatal("newPluginSink() succeeded with built-in sink name")
	}
}
