package grpcapi

import "github.com/wowtrust/trustdb/internal/model"

const MaxMessageBytes = 16 << 20

const ServiceName = "trustdb.v1.TrustDB"

const (
	FullMethodHealth            = "/" + ServiceName + "/Health"
	FullMethodSubmitClaim       = "/" + ServiceName + "/SubmitClaim"
	FullMethodSubmitClaimStream = "/" + ServiceName + "/SubmitClaimStream"
	FullMethodGetRecord         = "/" + ServiceName + "/GetRecord"
	FullMethodListRecords       = "/" + ServiceName + "/ListRecords"
	FullMethodGetProofBundle    = "/" + ServiceName + "/GetProofBundle"
	FullMethodListRoots         = "/" + ServiceName + "/ListRoots"
	FullMethodLatestRoot        = "/" + ServiceName + "/LatestRoot"
	FullMethodListSTHs          = "/" + ServiceName + "/ListSTHs"
	FullMethodLatestSTH         = "/" + ServiceName + "/LatestSTH"
	FullMethodGetSTH            = "/" + ServiceName + "/GetSTH"
	FullMethodListGlobalLeaves  = "/" + ServiceName + "/ListGlobalLeaves"
	FullMethodGetGlobalProof    = "/" + ServiceName + "/GetGlobalProof"
	FullMethodGetGlobalEvidence = "/" + ServiceName + "/GetGlobalEvidence"
	FullMethodListAnchors       = "/" + ServiceName + "/ListAnchors"
	FullMethodGetAnchor         = "/" + ServiceName + "/GetAnchor"
	FullMethodMetrics           = "/" + ServiceName + "/Metrics"
)

type HealthRequest struct{}

type HealthResponse struct {
	OK bool `cbor:"ok" json:"ok"`
}

type SubmitClaimRequest struct {
	SignedClaim model.SignedClaim `cbor:"signed_claim" json:"signed_claim"`
}

type SubmitClaimResponse struct {
	RecordID        string                `cbor:"record_id" json:"record_id"`
	Status          string                `cbor:"status" json:"status"`
	ProofLevel      string                `cbor:"proof_level" json:"proof_level"`
	Idempotent      bool                  `cbor:"idempotent" json:"idempotent"`
	BatchEnqueued   bool                  `cbor:"batch_enqueued" json:"batch_enqueued"`
	BatchError      string                `cbor:"batch_error,omitempty" json:"batch_error,omitempty"`
	ServerRecord    model.ServerRecord    `cbor:"server_record" json:"server_record"`
	AcceptedReceipt model.AcceptedReceipt `cbor:"accepted_receipt" json:"accepted_receipt"`
}

type SubmitClaimStreamRequest struct {
	Index       int               `cbor:"index" json:"index"`
	SignedClaim model.SignedClaim `cbor:"signed_claim" json:"signed_claim"`
}

type SubmitClaimStreamResponse struct {
	Index  int                  `cbor:"index" json:"index"`
	Result *SubmitClaimResponse `cbor:"result,omitempty" json:"result,omitempty"`
	Error  *ErrorResponse       `cbor:"error,omitempty" json:"error,omitempty"`
}

type ErrorResponse struct {
	Code    string `cbor:"code" json:"code"`
	Message string `cbor:"message" json:"message"`
}

type GetRecordRequest struct {
	RecordID string `cbor:"record_id" json:"record_id"`
}

type GetRecordResponse struct {
	Record model.RecordIndex `cbor:"record" json:"record"`
}

type ListRecordsRequest struct {
	Limit             int    `cbor:"limit" json:"limit"`
	Direction         string `cbor:"direction" json:"direction"`
	Cursor            string `cbor:"cursor,omitempty" json:"cursor,omitempty"`
	BatchID           string `cbor:"batch_id,omitempty" json:"batch_id,omitempty"`
	TenantID          string `cbor:"tenant_id,omitempty" json:"tenant_id,omitempty"`
	ClientID          string `cbor:"client_id,omitempty" json:"client_id,omitempty"`
	ProofLevel        string `cbor:"proof_level,omitempty" json:"proof_level,omitempty"`
	Query             string `cbor:"query,omitempty" json:"query,omitempty"`
	ContentHashHex    string `cbor:"content_hash_hex,omitempty" json:"content_hash_hex,omitempty"`
	ReceivedFromUnixN int64  `cbor:"received_from_unix_nano,omitempty" json:"received_from_unix_nano,omitempty"`
	ReceivedToUnixN   int64  `cbor:"received_to_unix_nano,omitempty" json:"received_to_unix_nano,omitempty"`
}

type ListRecordsResponse struct {
	Records    []model.RecordIndex `cbor:"records" json:"records"`
	Limit      int                 `cbor:"limit" json:"limit"`
	Direction  string              `cbor:"direction" json:"direction"`
	NextCursor string              `cbor:"next_cursor,omitempty" json:"next_cursor,omitempty"`
}

type GetProofBundleRequest struct {
	RecordID string `cbor:"record_id" json:"record_id"`
}

type GetProofBundleResponse struct {
	RecordID    string            `cbor:"record_id" json:"record_id"`
	ProofLevel  string            `cbor:"proof_level" json:"proof_level"`
	ProofBundle model.ProofBundle `cbor:"proof_bundle" json:"proof_bundle"`
}

type ListRootsRequest struct {
	Limit     int    `cbor:"limit" json:"limit"`
	Direction string `cbor:"direction" json:"direction"`
	Cursor    string `cbor:"cursor,omitempty" json:"cursor,omitempty"`
	After     int64  `cbor:"after,omitempty" json:"after,omitempty"`
}

type ListRootsResponse struct {
	Roots      []model.BatchRoot `cbor:"roots" json:"roots"`
	Limit      int               `cbor:"limit" json:"limit"`
	Direction  string            `cbor:"direction" json:"direction"`
	NextCursor string            `cbor:"next_cursor,omitempty" json:"next_cursor,omitempty"`
}

type LatestRootRequest struct{}

type LatestRootResponse struct {
	Root model.BatchRoot `cbor:"root" json:"root"`
}

type LatestSTHRequest struct{}

type LatestSTHResponse struct {
	STH model.SignedTreeHead `cbor:"sth" json:"sth"`
}

type GetSTHRequest struct {
	TreeSize uint64 `cbor:"tree_size" json:"tree_size"`
}

type GetSTHResponse struct {
	STH model.SignedTreeHead `cbor:"sth" json:"sth"`
}

type ListSTHsRequest struct {
	Limit     int    `cbor:"limit" json:"limit"`
	Direction string `cbor:"direction" json:"direction"`
	Cursor    string `cbor:"cursor,omitempty" json:"cursor,omitempty"`
}

type ListSTHsResponse struct {
	STHs       []model.SignedTreeHead `cbor:"sths" json:"sths"`
	Limit      int                    `cbor:"limit" json:"limit"`
	Direction  string                 `cbor:"direction" json:"direction"`
	NextCursor string                 `cbor:"next_cursor,omitempty" json:"next_cursor,omitempty"`
}

type GetGlobalProofRequest struct {
	BatchID  string `cbor:"batch_id" json:"batch_id"`
	TreeSize uint64 `cbor:"tree_size,omitempty" json:"tree_size,omitempty"`
}

type GetGlobalProofResponse struct {
	Proof model.GlobalLogProof `cbor:"proof" json:"proof"`
}

type GetGlobalEvidenceRequest struct {
	BatchID string `cbor:"batch_id" json:"batch_id"`
}

type GetGlobalEvidenceResponse struct {
	Evidence model.GlobalLogEvidence `cbor:"evidence" json:"evidence"`
}

type ListGlobalLeavesRequest struct {
	Limit     int    `cbor:"limit" json:"limit"`
	Direction string `cbor:"direction" json:"direction"`
	Cursor    string `cbor:"cursor,omitempty" json:"cursor,omitempty"`
}

type ListGlobalLeavesResponse struct {
	Leaves     []model.GlobalLogLeaf `cbor:"leaves" json:"leaves"`
	Limit      int                   `cbor:"limit" json:"limit"`
	Direction  string                `cbor:"direction" json:"direction"`
	NextCursor string                `cbor:"next_cursor,omitempty" json:"next_cursor,omitempty"`
}

type GetAnchorRequest struct {
	TreeSize uint64 `cbor:"tree_size" json:"tree_size"`
}

type GetAnchorResponse struct {
	TreeSize   uint64                 `cbor:"tree_size" json:"tree_size"`
	Status     string                 `cbor:"status" json:"status"`
	ProofLevel string                 `cbor:"proof_level" json:"proof_level"`
	Result     *model.STHAnchorResult `cbor:"result,omitempty" json:"result,omitempty"`
}

type ListAnchorsRequest struct {
	Limit     int    `cbor:"limit" json:"limit"`
	Direction string `cbor:"direction" json:"direction"`
	Cursor    string `cbor:"cursor,omitempty" json:"cursor,omitempty"`
}

type ListAnchorsResponse struct {
	Anchors    []GetAnchorResponse `cbor:"anchors" json:"anchors"`
	Limit      int                 `cbor:"limit" json:"limit"`
	Direction  string              `cbor:"direction" json:"direction"`
	NextCursor string              `cbor:"next_cursor,omitempty" json:"next_cursor,omitempty"`
}

type MetricsRequest struct{}

type MetricsResponse struct {
	Text string `cbor:"text" json:"text"`
}
