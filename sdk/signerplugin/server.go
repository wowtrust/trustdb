package signerplugin

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	EnvMagicCookie = "TRUSTDB_SIGNER_PLUGIN_MAGIC_COOKIE"
	EnvProtocol    = "TRUSTDB_SIGNER_PLUGIN_PROTOCOL"
	CookieMetadata = "x-trustdb-signer-plugin-cookie"
)

// Plugin is implemented by a standalone signer/key-custody provider.  The
// message supplied to Sign is the final suite-specific signature input built
// by the TrustDB host.  Implementations must sign those exact bytes and must
// not add domains, select a prehash, or reinterpret canonical objects.
type Plugin interface {
	Info(context.Context) (Info, error)
	Health(context.Context) error
	PublicKey(context.Context, Key) ([]byte, error)
	Sign(context.Context, Key, []byte) ([]byte, error)
}

type ErrorCode string

const (
	ErrorInvalidArgument    ErrorCode = "invalid_argument"
	ErrorKeyNotFound        ErrorCode = "key_not_found"
	ErrorFailedPrecondition ErrorCode = "failed_precondition"
	ErrorUnauthenticated    ErrorCode = "unauthenticated"
	ErrorPermissionDenied   ErrorCode = "permission_denied"
	ErrorUnsupported        ErrorCode = "unsupported"
	ErrorBusy               ErrorCode = "busy"
	ErrorUnavailable        ErrorCode = "unavailable"
	ErrorInternal           ErrorCode = "internal"
)

// ProviderError carries an explicitly safe message across the subprocess
// boundary.  Arbitrary implementation errors are replaced with a generic
// message so credentials, provider handles, paths, and signing inputs are not
// reflected to the host.
type ProviderError struct {
	Code        ErrorCode
	SafeMessage string
}

func (e *ProviderError) Error() string {
	if e == nil {
		return ""
	}
	return e.SafeMessage
}

func NewProviderError(code ErrorCode, safeMessage string) error {
	return &ProviderError{Code: code, SafeMessage: safeMessage}
}

type pluginServer struct {
	plugin    Plugin
	info      GetInfoResponse
	signSlots chan struct{}
}

func newPluginServer(plugin Plugin, info GetInfoResponse) *pluginServer {
	return &pluginServer{
		plugin:    plugin,
		info:      cloneInfoResponse(info),
		signSlots: make(chan struct{}, info.MaxConcurrentSigns),
	}
}

func (s *pluginServer) GetInfo(_ context.Context, request *GetInfoRequest) (*GetInfoResponse, error) {
	if request == nil || request.ProtocolVersion != ProtocolVersion {
		return nil, status.Error(codes.InvalidArgument, "signer plugin protocol_version is required and must match")
	}
	response := cloneInfoResponse(s.info)
	return &response, nil
}

func (s *pluginServer) Health(ctx context.Context, request *HealthRequest) (*HealthResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "signer plugin health request is required")
	}
	if err := ValidateHealthRequest(*request, s.info); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.plugin.Health(ctx); err != nil {
		return nil, rpcError(err)
	}
	return &HealthResponse{
		ProtocolVersion: ProtocolVersion,
		PluginID:        s.info.PluginID,
		Status:          HealthServing,
	}, nil
}

func (s *pluginServer) GetPublicKey(ctx context.Context, request *GetPublicKeyRequest) (*GetPublicKeyResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "signer plugin public-key request is required")
	}
	key := cloneKey(request.Key)
	if err := s.validateKey(key); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	publicKey, err := s.plugin.PublicKey(ctx, key)
	if err != nil {
		return nil, rpcError(err)
	}
	publicKey = append([]byte(nil), publicKey...)
	if err := validatePublicKey(key.Binding, publicKey); err != nil {
		return nil, protocolOutputError("signer plugin returned an invalid public key")
	}
	return &GetPublicKeyResponse{
		Binding:   key.Binding,
		PublicKey: publicKey,
	}, nil
}

func (s *pluginServer) Sign(ctx context.Context, request *SignRequest) (*SignResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "signer plugin sign request is required")
	}
	key := cloneKey(request.Key)
	if err := s.validateKey(key); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if len(request.Message) > MaxSignInputBytes {
		return nil, status.Error(codes.InvalidArgument, "signer plugin signing input is too large")
	}
	select {
	case s.signSlots <- struct{}{}:
		defer func() { <-s.signSlots }()
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	message := append([]byte(nil), request.Message...)
	signature, err := s.plugin.Sign(ctx, key, message)
	if err != nil {
		return nil, rpcError(err)
	}
	signature = append([]byte(nil), signature...)
	if err := validateSignature(key.Binding, signature); err != nil {
		return nil, protocolOutputError("signer plugin returned an invalid signature encoding")
	}
	return &SignResponse{
		Binding:   key.Binding,
		Signature: signature,
	}, nil
}

func (s *pluginServer) validateKey(key Key) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	return ValidateBindingForInfo(key.Binding, s.info)
}

func rpcError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return status.Error(codes.Canceled, context.Canceled.Error())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
	}
	var providerError *ProviderError
	if !errors.As(err, &providerError) || providerError == nil {
		return status.Error(codes.Internal, "signer provider operation failed")
	}
	code, fallback := rpcCode(providerError.Code)
	message := providerError.SafeMessage
	if !validSafeMessage(message) {
		message = fallback
	}
	return status.Error(code, message)
}

// protocolOutputError is reserved for an implementation that returned bytes
// which violate the immutable wire contract.  Provider operation failures use
// rpcError instead, so the host can distinguish a compromised/incompatible
// plugin from a transient provider failure without inspecting error strings.
func protocolOutputError(message string) error {
	return status.Error(codes.DataLoss, message)
}

func rpcCode(code ErrorCode) (codes.Code, string) {
	switch code {
	case ErrorInvalidArgument:
		return codes.InvalidArgument, "signer provider rejected the request"
	case ErrorKeyNotFound:
		return codes.NotFound, "signing key was not found"
	case ErrorFailedPrecondition:
		return codes.FailedPrecondition, "signing key is not ready"
	case ErrorUnauthenticated:
		return codes.Unauthenticated, "signer provider authentication failed"
	case ErrorPermissionDenied:
		return codes.PermissionDenied, "signer provider denied the operation"
	case ErrorUnsupported:
		return codes.Unimplemented, "signer provider does not support the operation"
	case ErrorBusy:
		return codes.ResourceExhausted, "signer provider is busy"
	case ErrorUnavailable:
		return codes.Unavailable, "signer provider is unavailable"
	case ErrorInternal:
		return codes.Internal, "signer provider operation failed"
	default:
		return codes.Internal, "signer provider operation failed"
	}
}

func validSafeMessage(message string) bool {
	if len(message) == 0 || len(message) > 256 || !utf8.ValidString(message) || strings.TrimSpace(message) != message {
		return false
	}
	for _, r := range message {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

type handshake struct {
	ProtocolVersion string `json:"protocol_version"`
	Address         string `json:"address"`
	MagicCookie     string `json:"magic_cookie"`
}

// Serve validates immutable Info, listens on a random loopback port, writes a
// single startup-handshake JSON object to stdout, and serves until ctx is
// canceled or the process is terminated.  Plugin logs must go to stderr.
func Serve(ctx context.Context, plugin Plugin) error {
	if plugin == nil {
		return errors.New("signer plugin is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cookie := strings.TrimSpace(os.Getenv(EnvMagicCookie))
	if cookie == "" || os.Getenv(EnvProtocol) != ProtocolVersion {
		return errors.New("signer plugin must be launched by a compatible TrustDB host")
	}
	pluginInfo, err := plugin.Info(ctx)
	if err != nil {
		return fmt.Errorf("read signer plugin info: %w", err)
	}
	info := pluginInfo.response()
	if err := ValidateGetInfoResponse(info); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen for signer plugin RPC: %w", err)
	}
	server := grpc.NewServer(
		grpc.ForceServerCodec(Codec()),
		grpc.MaxRecvMsgSize(MaxMessageBytes),
		grpc.MaxSendMsgSize(MaxMessageBytes),
		grpc.UnaryInterceptor(cookieInterceptor(cookie)),
	)
	RegisterRPCServer(server, newPluginServer(plugin, info))
	if err := writeHandshake(os.Stdout, handshake{
		ProtocolVersion: ProtocolVersion,
		Address:         listener.Addr().String(),
		MagicCookie:     cookie,
	}); err != nil {
		_ = listener.Close()
		return err
	}
	if ctx.Done() != nil {
		go func() {
			<-ctx.Done()
			server.GracefulStop()
		}()
	}
	if err := server.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve signer plugin RPC: %w", err)
	}
	return nil
}

func cookieInterceptor(cookie string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		metadataValues, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "signer plugin magic cookie is required")
		}
		values := metadataValues.Get(CookieMetadata)
		if len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), []byte(cookie)) != 1 {
			return nil, status.Error(codes.Unauthenticated, "signer plugin magic cookie is invalid")
		}
		return handler(ctx, request)
	}
}

func cloneKey(in Key) Key {
	out := in
	if in.Reference.PKCS11 != nil {
		value := *in.Reference.PKCS11
		out.Reference.PKCS11 = &value
	}
	if in.Reference.SDF != nil {
		value := *in.Reference.SDF
		out.Reference.SDF = &value
	}
	if in.Reference.Remote != nil {
		value := *in.Reference.Remote
		out.Reference.Remote = &value
	}
	return out
}
