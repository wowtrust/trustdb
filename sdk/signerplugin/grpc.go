package signerplugin

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
)

const (
	FullMethodGetInfo      = "/" + ServiceName + "/GetInfo"
	FullMethodHealth       = "/" + ServiceName + "/Health"
	FullMethodGetPublicKey = "/" + ServiceName + "/GetPublicKey"
	FullMethodSign         = "/" + ServiceName + "/Sign"
)

type RPCClient interface {
	GetInfo(context.Context, *GetInfoRequest, ...grpc.CallOption) (*GetInfoResponse, error)
	Health(context.Context, *HealthRequest, ...grpc.CallOption) (*HealthResponse, error)
	GetPublicKey(context.Context, *GetPublicKeyRequest, ...grpc.CallOption) (*GetPublicKeyResponse, error)
	Sign(context.Context, *SignRequest, ...grpc.CallOption) (*SignResponse, error)
}

type rpcClient struct{ cc grpc.ClientConnInterface }

func NewRPCClient(cc grpc.ClientConnInterface) RPCClient { return &rpcClient{cc: cc} }

func (c *rpcClient) GetInfo(ctx context.Context, in *GetInfoRequest, opts ...grpc.CallOption) (*GetInfoResponse, error) {
	out := new(GetInfoResponse)
	if err := c.invoke(ctx, FullMethodGetInfo, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rpcClient) Health(ctx context.Context, in *HealthRequest, opts ...grpc.CallOption) (*HealthResponse, error) {
	out := new(HealthResponse)
	if err := c.invoke(ctx, FullMethodHealth, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rpcClient) GetPublicKey(ctx context.Context, in *GetPublicKeyRequest, opts ...grpc.CallOption) (*GetPublicKeyResponse, error) {
	out := new(GetPublicKeyResponse)
	if err := c.invoke(ctx, FullMethodGetPublicKey, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rpcClient) Sign(ctx context.Context, in *SignRequest, opts ...grpc.CallOption) (*SignResponse, error) {
	out := new(SignResponse)
	if err := c.invoke(ctx, FullMethodSign, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rpcClient) invoke(ctx context.Context, method string, in, out any, opts ...grpc.CallOption) error {
	tracker := trackDecodeFailure(out)
	err := c.cc.Invoke(ctx, method, in, out, opts...)
	if finishDecodeFailureTracking(out, tracker) {
		return fmt.Errorf("%w: %s response is not valid canonical CBOR", ErrProtocolViolation, method)
	}
	return err
}

type RPCServer interface {
	GetInfo(context.Context, *GetInfoRequest) (*GetInfoResponse, error)
	Health(context.Context, *HealthRequest) (*HealthResponse, error)
	GetPublicKey(context.Context, *GetPublicKeyRequest) (*GetPublicKeyResponse, error)
	Sign(context.Context, *SignRequest) (*SignResponse, error)
}

func RegisterRPCServer(registrar grpc.ServiceRegistrar, server RPCServer) {
	registrar.RegisterService(&ServiceDesc, server)
}

var ServiceDesc = grpc.ServiceDesc{
	ServiceName: ServiceName,
	HandlerType: (*RPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "GetInfo", Handler: getInfoHandler},
		{MethodName: "Health", Handler: healthHandler},
		{MethodName: "GetPublicKey", Handler: getPublicKeyHandler},
		{MethodName: "Sign", Handler: signHandler},
	},
	Metadata: ProtocolVersion,
}

func unaryHandler[Request any](
	srv any,
	ctx context.Context,
	decode func(any) error,
	interceptor grpc.UnaryServerInterceptor,
	method string,
	call func(RPCServer, context.Context, *Request) (any, error),
) (any, error) {
	in := new(Request)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return call(srv.(RPCServer), ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + ServiceName + "/" + method}
	handler := func(ctx context.Context, request any) (any, error) {
		return call(srv.(RPCServer), ctx, request.(*Request))
	}
	return interceptor(ctx, in, info, handler)
}

func getInfoHandler(srv any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[GetInfoRequest](srv, ctx, decode, interceptor, "GetInfo", func(server RPCServer, ctx context.Context, request *GetInfoRequest) (any, error) {
		return server.GetInfo(ctx, request)
	})
}

func healthHandler(srv any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[HealthRequest](srv, ctx, decode, interceptor, "Health", func(server RPCServer, ctx context.Context, request *HealthRequest) (any, error) {
		return server.Health(ctx, request)
	})
}

func getPublicKeyHandler(srv any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[GetPublicKeyRequest](srv, ctx, decode, interceptor, "GetPublicKey", func(server RPCServer, ctx context.Context, request *GetPublicKeyRequest) (any, error) {
		return server.GetPublicKey(ctx, request)
	})
}

func signHandler(srv any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[SignRequest](srv, ctx, decode, interceptor, "Sign", func(server RPCServer, ctx context.Context, request *SignRequest) (any, error) {
		return server.Sign(ctx, request)
	})
}
