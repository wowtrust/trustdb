package anchorplugin

import (
	"context"

	"google.golang.org/grpc"
)

const (
	FullMethodGetInfo       = "/" + ServiceName + "/GetInfo"
	FullMethodPublish       = "/" + ServiceName + "/Publish"
	FullMethodVerify        = "/" + ServiceName + "/Verify"
	FullMethodGetStatus     = "/" + ServiceName + "/GetStatus"
	FullMethodListResources = "/" + ServiceName + "/ListResources"
	FullMethodGetResource   = "/" + ServiceName + "/GetResource"
)

type RPCClient interface {
	GetInfo(context.Context, *GetInfoRequest, ...grpc.CallOption) (*GetInfoResponse, error)
	Publish(context.Context, *PublishRequest, ...grpc.CallOption) (*PublishResponse, error)
	Verify(context.Context, *VerifyRequest, ...grpc.CallOption) (*VerifyResponse, error)
	GetStatus(context.Context, *GetStatusRequest, ...grpc.CallOption) (*GetStatusResponse, error)
	ListResources(context.Context, *ListResourcesRequest, ...grpc.CallOption) (*ListResourcesResponse, error)
	GetResource(context.Context, *GetResourceRequest, ...grpc.CallOption) (*GetResourceResponse, error)
}

type rpcClient struct{ cc grpc.ClientConnInterface }

func NewRPCClient(cc grpc.ClientConnInterface) RPCClient { return &rpcClient{cc: cc} }

func (c *rpcClient) GetInfo(ctx context.Context, in *GetInfoRequest, opts ...grpc.CallOption) (*GetInfoResponse, error) {
	out := new(GetInfoResponse)
	if err := c.cc.Invoke(ctx, FullMethodGetInfo, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rpcClient) Publish(ctx context.Context, in *PublishRequest, opts ...grpc.CallOption) (*PublishResponse, error) {
	out := new(PublishResponse)
	if err := c.cc.Invoke(ctx, FullMethodPublish, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rpcClient) Verify(ctx context.Context, in *VerifyRequest, opts ...grpc.CallOption) (*VerifyResponse, error) {
	out := new(VerifyResponse)
	if err := c.cc.Invoke(ctx, FullMethodVerify, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rpcClient) GetStatus(ctx context.Context, in *GetStatusRequest, opts ...grpc.CallOption) (*GetStatusResponse, error) {
	out := new(GetStatusResponse)
	if err := c.cc.Invoke(ctx, FullMethodGetStatus, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rpcClient) ListResources(ctx context.Context, in *ListResourcesRequest, opts ...grpc.CallOption) (*ListResourcesResponse, error) {
	out := new(ListResourcesResponse)
	if err := c.cc.Invoke(ctx, FullMethodListResources, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rpcClient) GetResource(ctx context.Context, in *GetResourceRequest, opts ...grpc.CallOption) (*GetResourceResponse, error) {
	out := new(GetResourceResponse)
	if err := c.cc.Invoke(ctx, FullMethodGetResource, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

type RPCServer interface {
	GetInfo(context.Context, *GetInfoRequest) (*GetInfoResponse, error)
	Publish(context.Context, *PublishRequest) (*PublishResponse, error)
	Verify(context.Context, *VerifyRequest) (*VerifyResponse, error)
	GetStatus(context.Context, *GetStatusRequest) (*GetStatusResponse, error)
	ListResources(context.Context, *ListResourcesRequest) (*ListResourcesResponse, error)
	GetResource(context.Context, *GetResourceRequest) (*GetResourceResponse, error)
}

func RegisterRPCServer(registrar grpc.ServiceRegistrar, server RPCServer) {
	registrar.RegisterService(&ServiceDesc, server)
}

var ServiceDesc = grpc.ServiceDesc{
	ServiceName: ServiceName,
	HandlerType: (*RPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "GetInfo", Handler: getInfoHandler},
		{MethodName: "Publish", Handler: publishHandler},
		{MethodName: "Verify", Handler: verifyHandler},
		{MethodName: "GetStatus", Handler: getStatusHandler},
		{MethodName: "ListResources", Handler: listResourcesHandler},
		{MethodName: "GetResource", Handler: getResourceHandler},
	},
	Metadata: ProtocolVersion,
}

func unaryHandler[Req any](
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
	method string,
	call func(RPCServer, context.Context, *Req) (any, error),
) (any, error) {
	in := new(Req)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return call(srv.(RPCServer), ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + ServiceName + "/" + method}
	handler := func(ctx context.Context, req any) (any, error) {
		return call(srv.(RPCServer), ctx, req.(*Req))
	}
	return interceptor(ctx, in, info, handler)
}

func getInfoHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[GetInfoRequest](srv, ctx, dec, interceptor, "GetInfo", func(server RPCServer, ctx context.Context, req *GetInfoRequest) (any, error) {
		return server.GetInfo(ctx, req)
	})
}

func publishHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[PublishRequest](srv, ctx, dec, interceptor, "Publish", func(server RPCServer, ctx context.Context, req *PublishRequest) (any, error) {
		return server.Publish(ctx, req)
	})
}

func verifyHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[VerifyRequest](srv, ctx, dec, interceptor, "Verify", func(server RPCServer, ctx context.Context, req *VerifyRequest) (any, error) {
		return server.Verify(ctx, req)
	})
}

func getStatusHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[GetStatusRequest](srv, ctx, dec, interceptor, "GetStatus", func(server RPCServer, ctx context.Context, req *GetStatusRequest) (any, error) {
		return server.GetStatus(ctx, req)
	})
}

func listResourcesHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[ListResourcesRequest](srv, ctx, dec, interceptor, "ListResources", func(server RPCServer, ctx context.Context, req *ListResourcesRequest) (any, error) {
		return server.ListResources(ctx, req)
	})
}

func getResourceHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[GetResourceRequest](srv, ctx, dec, interceptor, "GetResource", func(server RPCServer, ctx context.Context, req *GetResourceRequest) (any, error) {
		return server.GetResource(ctx, req)
	})
}
