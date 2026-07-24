package grpcapi

import (
	"context"

	"google.golang.org/grpc"
)

type TrustDBServiceServer interface {
	Health(context.Context, *HealthRequest) (*HealthResponse, error)
	SubmitClaim(context.Context, *SubmitClaimRequest) (*SubmitClaimResponse, error)
	SubmitClaimStream(TrustDBService_SubmitClaimStreamServer) error
	GetRecord(context.Context, *GetRecordRequest) (*GetRecordResponse, error)
	ListRecords(context.Context, *ListRecordsRequest) (*ListRecordsResponse, error)
	GetProofBundle(context.Context, *GetProofBundleRequest) (*GetProofBundleResponse, error)
	ListRoots(context.Context, *ListRootsRequest) (*ListRootsResponse, error)
	LatestRoot(context.Context, *LatestRootRequest) (*LatestRootResponse, error)
	ListSTHs(context.Context, *ListSTHsRequest) (*ListSTHsResponse, error)
	LatestSTH(context.Context, *LatestSTHRequest) (*LatestSTHResponse, error)
	GetSTH(context.Context, *GetSTHRequest) (*GetSTHResponse, error)
	ListGlobalLeaves(context.Context, *ListGlobalLeavesRequest) (*ListGlobalLeavesResponse, error)
	GetGlobalProof(context.Context, *GetGlobalProofRequest) (*GetGlobalProofResponse, error)
	GetGlobalEvidence(context.Context, *GetGlobalEvidenceRequest) (*GetGlobalEvidenceResponse, error)
	ListAnchors(context.Context, *ListAnchorsRequest) (*ListAnchorsResponse, error)
	GetAnchor(context.Context, *GetAnchorRequest) (*GetAnchorResponse, error)
	ListAnchorSystems(context.Context, *ListAnchorSystemsRequest) (*ListAnchorSystemsResponse, error)
	GetAnchorSystem(context.Context, *GetAnchorSystemRequest) (*GetAnchorSystemResponse, error)
	GetAnchorSystemStatus(context.Context, *GetAnchorSystemStatusRequest) (*GetAnchorSystemStatusResponse, error)
	ListAnchorSystemResources(context.Context, *ListAnchorSystemResourcesRequest) (*ListAnchorSystemResourcesResponse, error)
	GetAnchorSystemResource(context.Context, *GetAnchorSystemResourceRequest) (*GetAnchorSystemResourceResponse, error)
	Metrics(context.Context, *MetricsRequest) (*MetricsResponse, error)
}

func RegisterTrustDBServiceServer(s grpc.ServiceRegistrar, srv TrustDBServiceServer) {
	s.RegisterService(&TrustDBService_ServiceDesc, srv)
}

var TrustDBService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: ServiceName,
	HandlerType: (*TrustDBServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Health", Handler: _TrustDB_Health_Handler},
		{MethodName: "SubmitClaim", Handler: _TrustDB_SubmitClaim_Handler},
		{MethodName: "GetRecord", Handler: _TrustDB_GetRecord_Handler},
		{MethodName: "ListRecords", Handler: _TrustDB_ListRecords_Handler},
		{MethodName: "GetProofBundle", Handler: _TrustDB_GetProofBundle_Handler},
		{MethodName: "ListRoots", Handler: _TrustDB_ListRoots_Handler},
		{MethodName: "LatestRoot", Handler: _TrustDB_LatestRoot_Handler},
		{MethodName: "ListSTHs", Handler: _TrustDB_ListSTHs_Handler},
		{MethodName: "LatestSTH", Handler: _TrustDB_LatestSTH_Handler},
		{MethodName: "GetSTH", Handler: _TrustDB_GetSTH_Handler},
		{MethodName: "ListGlobalLeaves", Handler: _TrustDB_ListGlobalLeaves_Handler},
		{MethodName: "GetGlobalProof", Handler: _TrustDB_GetGlobalProof_Handler},
		{MethodName: "GetGlobalEvidence", Handler: _TrustDB_GetGlobalEvidence_Handler},
		{MethodName: "ListAnchors", Handler: _TrustDB_ListAnchors_Handler},
		{MethodName: "GetAnchor", Handler: _TrustDB_GetAnchor_Handler},
		{MethodName: "ListAnchorSystems", Handler: _TrustDB_ListAnchorSystems_Handler},
		{MethodName: "GetAnchorSystem", Handler: _TrustDB_GetAnchorSystem_Handler},
		{MethodName: "GetAnchorSystemStatus", Handler: _TrustDB_GetAnchorSystemStatus_Handler},
		{MethodName: "ListAnchorSystemResources", Handler: _TrustDB_ListAnchorSystemResources_Handler},
		{MethodName: "GetAnchorSystemResource", Handler: _TrustDB_GetAnchorSystemResource_Handler},
		{MethodName: "Metrics", Handler: _TrustDB_Metrics_Handler},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "SubmitClaimStream",
			Handler:       _TrustDB_SubmitClaimStream_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "trustdb/v1/cbor",
}

type TrustDBService_SubmitClaimStreamServer interface {
	Send(*SubmitClaimStreamResponse) error
	Recv() (*SubmitClaimStreamRequest, error)
	grpc.ServerStream
}

type trustDBServiceSubmitClaimStreamServer struct {
	grpc.ServerStream
}

func (x *trustDBServiceSubmitClaimStreamServer) Send(m *SubmitClaimStreamResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *trustDBServiceSubmitClaimStreamServer) Recv() (*SubmitClaimStreamRequest, error) {
	m := new(SubmitClaimStreamRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func unaryHandler[Req any](
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
	method string,
	call func(TrustDBServiceServer, context.Context, *Req) (any, error),
) (any, error) {
	in := new(Req)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return call(srv.(TrustDBServiceServer), ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + ServiceName + "/" + method}
	handler := func(ctx context.Context, req any) (any, error) {
		return call(srv.(TrustDBServiceServer), ctx, req.(*Req))
	}
	return interceptor(ctx, in, info, handler)
}

func _TrustDB_Health_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[HealthRequest](srv, ctx, dec, interceptor, "Health", func(s TrustDBServiceServer, ctx context.Context, req *HealthRequest) (any, error) {
		return s.Health(ctx, req)
	})
}

func _TrustDB_SubmitClaim_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[SubmitClaimRequest](srv, ctx, dec, interceptor, "SubmitClaim", func(s TrustDBServiceServer, ctx context.Context, req *SubmitClaimRequest) (any, error) {
		return s.SubmitClaim(ctx, req)
	})
}

func _TrustDB_SubmitClaimStream_Handler(srv any, stream grpc.ServerStream) error {
	return srv.(TrustDBServiceServer).SubmitClaimStream(&trustDBServiceSubmitClaimStreamServer{ServerStream: stream})
}

func _TrustDB_GetRecord_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[GetRecordRequest](srv, ctx, dec, interceptor, "GetRecord", func(s TrustDBServiceServer, ctx context.Context, req *GetRecordRequest) (any, error) {
		return s.GetRecord(ctx, req)
	})
}

func _TrustDB_ListRecords_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[ListRecordsRequest](srv, ctx, dec, interceptor, "ListRecords", func(s TrustDBServiceServer, ctx context.Context, req *ListRecordsRequest) (any, error) {
		return s.ListRecords(ctx, req)
	})
}

func _TrustDB_GetProofBundle_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[GetProofBundleRequest](srv, ctx, dec, interceptor, "GetProofBundle", func(s TrustDBServiceServer, ctx context.Context, req *GetProofBundleRequest) (any, error) {
		return s.GetProofBundle(ctx, req)
	})
}

func _TrustDB_ListRoots_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[ListRootsRequest](srv, ctx, dec, interceptor, "ListRoots", func(s TrustDBServiceServer, ctx context.Context, req *ListRootsRequest) (any, error) {
		return s.ListRoots(ctx, req)
	})
}

func _TrustDB_LatestRoot_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[LatestRootRequest](srv, ctx, dec, interceptor, "LatestRoot", func(s TrustDBServiceServer, ctx context.Context, req *LatestRootRequest) (any, error) {
		return s.LatestRoot(ctx, req)
	})
}

func _TrustDB_ListSTHs_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[ListSTHsRequest](srv, ctx, dec, interceptor, "ListSTHs", func(s TrustDBServiceServer, ctx context.Context, req *ListSTHsRequest) (any, error) {
		return s.ListSTHs(ctx, req)
	})
}

func _TrustDB_LatestSTH_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[LatestSTHRequest](srv, ctx, dec, interceptor, "LatestSTH", func(s TrustDBServiceServer, ctx context.Context, req *LatestSTHRequest) (any, error) {
		return s.LatestSTH(ctx, req)
	})
}

func _TrustDB_GetSTH_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[GetSTHRequest](srv, ctx, dec, interceptor, "GetSTH", func(s TrustDBServiceServer, ctx context.Context, req *GetSTHRequest) (any, error) {
		return s.GetSTH(ctx, req)
	})
}

func _TrustDB_ListGlobalLeaves_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[ListGlobalLeavesRequest](srv, ctx, dec, interceptor, "ListGlobalLeaves", func(s TrustDBServiceServer, ctx context.Context, req *ListGlobalLeavesRequest) (any, error) {
		return s.ListGlobalLeaves(ctx, req)
	})
}

func _TrustDB_GetGlobalProof_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[GetGlobalProofRequest](srv, ctx, dec, interceptor, "GetGlobalProof", func(s TrustDBServiceServer, ctx context.Context, req *GetGlobalProofRequest) (any, error) {
		return s.GetGlobalProof(ctx, req)
	})
}

func _TrustDB_GetGlobalEvidence_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[GetGlobalEvidenceRequest](srv, ctx, dec, interceptor, "GetGlobalEvidence", func(s TrustDBServiceServer, ctx context.Context, req *GetGlobalEvidenceRequest) (any, error) {
		return s.GetGlobalEvidence(ctx, req)
	})
}

func _TrustDB_ListAnchors_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[ListAnchorsRequest](srv, ctx, dec, interceptor, "ListAnchors", func(s TrustDBServiceServer, ctx context.Context, req *ListAnchorsRequest) (any, error) {
		return s.ListAnchors(ctx, req)
	})
}

func _TrustDB_GetAnchor_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[GetAnchorRequest](srv, ctx, dec, interceptor, "GetAnchor", func(s TrustDBServiceServer, ctx context.Context, req *GetAnchorRequest) (any, error) {
		return s.GetAnchor(ctx, req)
	})
}

func _TrustDB_ListAnchorSystems_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[ListAnchorSystemsRequest](srv, ctx, dec, interceptor, "ListAnchorSystems", func(s TrustDBServiceServer, ctx context.Context, req *ListAnchorSystemsRequest) (any, error) {
		return s.ListAnchorSystems(ctx, req)
	})
}

func _TrustDB_GetAnchorSystem_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[GetAnchorSystemRequest](srv, ctx, dec, interceptor, "GetAnchorSystem", func(s TrustDBServiceServer, ctx context.Context, req *GetAnchorSystemRequest) (any, error) {
		return s.GetAnchorSystem(ctx, req)
	})
}

func _TrustDB_GetAnchorSystemStatus_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[GetAnchorSystemStatusRequest](srv, ctx, dec, interceptor, "GetAnchorSystemStatus", func(s TrustDBServiceServer, ctx context.Context, req *GetAnchorSystemStatusRequest) (any, error) {
		return s.GetAnchorSystemStatus(ctx, req)
	})
}

func _TrustDB_ListAnchorSystemResources_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[ListAnchorSystemResourcesRequest](srv, ctx, dec, interceptor, "ListAnchorSystemResources", func(s TrustDBServiceServer, ctx context.Context, req *ListAnchorSystemResourcesRequest) (any, error) {
		return s.ListAnchorSystemResources(ctx, req)
	})
}

func _TrustDB_GetAnchorSystemResource_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[GetAnchorSystemResourceRequest](srv, ctx, dec, interceptor, "GetAnchorSystemResource", func(s TrustDBServiceServer, ctx context.Context, req *GetAnchorSystemResourceRequest) (any, error) {
		return s.GetAnchorSystemResource(ctx, req)
	})
}

func _TrustDB_Metrics_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return unaryHandler[MetricsRequest](srv, ctx, dec, interceptor, "Metrics", func(s TrustDBServiceServer, ctx context.Context, req *MetricsRequest) (any, error) {
		return s.Metrics(ctx, req)
	})
}
