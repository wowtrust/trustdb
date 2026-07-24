package anchorplugin

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	EnvMagicCookie = "TRUSTDB_ANCHOR_PLUGIN_MAGIC_COOKIE"
	EnvProtocol    = "TRUSTDB_ANCHOR_PLUGIN_PROTOCOL"
	CookieMetadata = "x-trustdb-anchor-plugin-cookie"
)

// Plugin is implemented by a standalone anchor provider. Verify must validate
// the provider-specific proof without trusting fields outside the supplied
// immutable STH and provider result.
type Plugin interface {
	Info(context.Context) (Info, error)
	Publish(context.Context, SignedTreeHead) (AnchorResult, error)
	Verify(context.Context, SignedTreeHead, AnchorResult) error
}

// Explorer is optional. Implementing it lets TrustDB expose provider status
// and read-only node/block/transaction/account/contract resources without
// changing the immutable Publish/Verify proof contract.
type Explorer interface {
	Status(context.Context) (SystemStatus, error)
	ListResources(context.Context, ListResourcesRequest) (ListResourcesResponse, error)
	Resource(context.Context, string, string) (Resource, bool, error)
}

type Info struct {
	SinkName    string
	ProofSchema string
	System      *System
}

type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

// Permanent marks a provider error as non-retryable. TrustDB records the
// current anchor generation as terminal instead of retrying it forever.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return permanentError{err: err}
}

func IsPermanent(err error) bool {
	var target permanentError
	return errors.As(err, &target)
}

type pluginServer struct{ plugin Plugin }

func (s pluginServer) GetInfo(ctx context.Context, _ *GetInfoRequest) (*GetInfoResponse, error) {
	info, err := s.plugin.Info(ctx)
	if err != nil {
		return nil, rpcError(err)
	}
	capabilities := []string{CapabilityPublish, CapabilityVerify}
	if info.System != nil {
		capabilities = append(capabilities, info.System.Capabilities...)
	}
	return &GetInfoResponse{
		ProtocolVersion: ProtocolVersion,
		SinkName:        info.SinkName,
		Capabilities:    capabilities,
		ProofSchema:     info.ProofSchema,
		System:          info.System,
	}, nil
}

func (s pluginServer) Publish(ctx context.Context, req *PublishRequest) (*PublishResponse, error) {
	if req == nil || req.STH.TreeSize == 0 || len(req.STH.RootHash) == 0 {
		return nil, status.Error(codes.InvalidArgument, "signed tree head is required")
	}
	result, err := s.plugin.Publish(ctx, req.STH)
	if err != nil {
		return nil, rpcError(err)
	}
	return &PublishResponse{Result: result}, nil
}

func (s pluginServer) Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error) {
	if req == nil || req.STH.TreeSize == 0 || len(req.STH.RootHash) == 0 {
		return nil, status.Error(codes.InvalidArgument, "signed tree head is required")
	}
	if err := s.plugin.Verify(ctx, req.STH, req.Result); err != nil {
		return nil, rpcError(err)
	}
	return &VerifyResponse{Valid: true}, nil
}

func (s pluginServer) GetStatus(ctx context.Context, _ *GetStatusRequest) (*GetStatusResponse, error) {
	explorer, ok := s.plugin.(Explorer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "anchor plugin does not expose system status")
	}
	value, err := explorer.Status(ctx)
	if err != nil {
		return nil, rpcError(err)
	}
	return &GetStatusResponse{Status: value}, nil
}

func (s pluginServer) ListResources(ctx context.Context, req *ListResourcesRequest) (*ListResourcesResponse, error) {
	explorer, ok := s.plugin.(Explorer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "anchor plugin does not expose explorer resources")
	}
	if req == nil || strings.TrimSpace(req.Kind) == "" || req.Limit < 1 || req.Limit > 1000 {
		return nil, status.Error(codes.InvalidArgument, "resource kind and limit between 1 and 1000 are required")
	}
	response, err := explorer.ListResources(ctx, *req)
	if err != nil {
		return nil, rpcError(err)
	}
	return &response, nil
}

func (s pluginServer) GetResource(ctx context.Context, req *GetResourceRequest) (*GetResourceResponse, error) {
	explorer, ok := s.plugin.(Explorer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "anchor plugin does not expose explorer resources")
	}
	if req == nil || strings.TrimSpace(req.Kind) == "" || strings.TrimSpace(req.ResourceID) == "" {
		return nil, status.Error(codes.InvalidArgument, "resource kind and resource_id are required")
	}
	resource, found, err := explorer.Resource(ctx, req.Kind, req.ResourceID)
	if err != nil {
		return nil, rpcError(err)
	}
	return &GetResourceResponse{Resource: resource, Found: found}, nil
}

func rpcError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		if status.Code(err) != codes.Unknown {
			return err
		}
	}
	if IsPermanent(err) {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	return status.Error(codes.Unavailable, err.Error())
}

type handshake struct {
	ProtocolVersion string `json:"protocol_version"`
	Address         string `json:"address"`
	MagicCookie     string `json:"magic_cookie"`
}

// Serve listens on a random loopback port, writes one handshake JSON object
// to stdout, and serves the plugin until ctx is canceled or the process is
// terminated. Plugin logs must go to stderr because stdout is reserved for
// the startup handshake.
func Serve(ctx context.Context, plugin Plugin) error {
	if plugin == nil {
		return fmt.Errorf("anchor plugin is required")
	}
	cookie := strings.TrimSpace(os.Getenv(EnvMagicCookie))
	if cookie == "" || os.Getenv(EnvProtocol) != ProtocolVersion {
		return fmt.Errorf("anchor plugin must be launched by a compatible TrustDB host")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen for anchor plugin RPC: %w", err)
	}
	server := grpc.NewServer(
		grpc.ForceServerCodec(Codec()),
		grpc.MaxRecvMsgSize(MaxMessageBytes),
		grpc.MaxSendMsgSize(MaxMessageBytes),
		grpc.UnaryInterceptor(cookieInterceptor(cookie)),
	)
	RegisterRPCServer(server, pluginServer{plugin: plugin})
	if err := writeHandshake(os.Stdout, handshake{
		ProtocolVersion: ProtocolVersion,
		Address:         listener.Addr().String(),
		MagicCookie:     cookie,
	}); err != nil {
		_ = listener.Close()
		return err
	}
	if ctx != nil && ctx.Done() != nil {
		go func() {
			<-ctx.Done()
			server.GracefulStop()
		}()
	}
	if err := server.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve anchor plugin RPC: %w", err)
	}
	return nil
}

func cookieInterceptor(cookie string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		metadataValues, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "anchor plugin magic cookie is required")
		}
		values := metadataValues.Get(CookieMetadata)
		if len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), []byte(cookie)) != 1 {
			return nil, status.Error(codes.Unauthenticated, "anchor plugin magic cookie is invalid")
		}
		return handler(ctx, req)
	}
}
