package sdk

import (
	"crypto/ed25519"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
)

type ClientClaim = model.ClientClaim
type SignedClaim = model.SignedClaim
type Content = model.Content
type Metadata = model.Metadata
type ServerRecord = model.ServerRecord
type AcceptedReceipt = model.AcceptedReceipt
type CommittedReceipt = model.CommittedReceipt
type ProofBundle = model.ProofBundle
type RecordIndex = model.RecordIndex
type BatchRoot = model.BatchRoot
type SignedTreeHead = model.SignedTreeHead
type GlobalLogProof = model.GlobalLogProof
type GlobalLogEvidence = model.GlobalLogEvidence
type STHAnchorResult = model.STHAnchorResult
type SingleProof = model.SingleProof

const (
	ProofLevelL1 = "L1"
	ProofLevelL2 = "L2"
	ProofLevelL3 = "L3"
	ProofLevelL4 = "L4"
	ProofLevelL5 = "L5"

	RecordListDirectionAsc  = model.RecordListDirectionAsc
	RecordListDirectionDesc = model.RecordListDirectionDesc
)

type Identity struct {
	TenantID   string
	ClientID   string
	KeyID      string
	PrivateKey ed25519.PrivateKey
}

type FileClaimOptions struct {
	ProducedAt     time.Time
	Nonce          []byte
	IdempotencyKey string
	HashAlg        string
	MediaType      string
	StorageURI     string
	EventType      string
	Source         string
	CustomMetadata map[string]string
}

type SubmitResult struct {
	RecordID        string
	Status          string
	ProofLevel      string
	Idempotent      bool
	BatchEnqueued   bool
	BatchError      string
	ServerRecord    ServerRecord
	AcceptedReceipt AcceptedReceipt
	SignedClaim     SignedClaim
}

type ListRecordsOptions struct {
	Limit             int
	Direction         string
	Cursor            string
	BatchID           string
	TenantID          string
	ClientID          string
	ProofLevel        string
	Query             string
	ContentHashHex    string
	ReceivedFromUnixN int64
	ReceivedToUnixN   int64
}

type ListPageOptions struct {
	Limit     int
	Direction string
	Cursor    string
}

type RecordPage struct {
	Records    []RecordIndex
	Limit      int
	Direction  string
	NextCursor string
}

type RootPage struct {
	Roots      []BatchRoot
	Limit      int
	Direction  string
	NextCursor string
}

type TreeHeadPage struct {
	STHs       []SignedTreeHead
	Limit      int
	Direction  string
	NextCursor string
}

type GlobalLeafPage struct {
	Leaves     []model.GlobalLogLeaf
	Limit      int
	Direction  string
	NextCursor string
}

type AnchorPageItem struct {
	TreeSize uint64
	Status   string
	Result   *STHAnchorResult
}

type AnchorPage struct {
	Anchors    []AnchorPageItem
	Limit      int
	Direction  string
	NextCursor string
}

type HealthStatus struct {
	OK         bool
	ServerURL  string
	RTTMillis  int64
	Error      string
	StatusCode int
}

type AnchorStatus struct {
	TreeSize uint64
	Status   string
	Result   *STHAnchorResult
}

type TrustedKeys struct {
	ClientPublicKey ed25519.PublicKey
	ServerPublicKey ed25519.PublicKey
}

type VerifyOptions struct {
	SkipAnchor bool
}

type ProofArtifacts struct {
	Bundle       ProofBundle
	GlobalProof  *GlobalLogProof
	AnchorResult *STHAnchorResult
}

type VerifyResult struct {
	Valid      bool
	RecordID   string
	ProofLevel string
	AnchorSink string
	AnchorID   string
}
