package sdk

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/statusnotify"
	"github.com/wowtrust/trustdb/v2/sdk/anchorplugin"
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
type AnchorSystem = model.AnchorSystem
type AnchorSystemStatus = model.AnchorSystemStatus
type AnchorSystemResource = model.AnchorSystemResource
type AnchorSystemResourcePage = model.AnchorSystemResourcePage
type SingleProof = model.SingleProof
type RecordStatus = model.RecordStatus
type StatusRefresh = model.StatusRefresh
type StatusSubscription = statusnotify.Subscription
type StatusSubscriptionChannels = statusnotify.Channels

type CreateStatusSubscriptionOptions struct {
	Identity  Identity
	RecordIDs []string
	Channels  StatusSubscriptionChannels
	TTL       time.Duration
}

type RecordStatusBatch struct {
	Statuses         []RecordStatus
	MissingRecordIDs []string
}

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
	TenantID string
	ClientID string
	KeyID    string
	Signer   Signer
}

// NewIdentity binds tenant/client identity to a suite-aware signer.
func NewIdentity(tenantID, clientID string, signer Signer) (Identity, error) {
	id := Identity{TenantID: tenantID, ClientID: clientID, Signer: signer}
	if signer != nil {
		id.KeyID = signer.Descriptor().KeyID
	}
	if _, _, err := id.signingMaterial(); err != nil {
		return Identity{}, err
	}
	return id, nil
}

// NewINTLV1Identity is the simple Ed25519 software-key convenience
// constructor. The resulting identity is explicitly bound to INTL_V1.
func NewINTLV1Identity(tenantID, clientID, keyID string, privateKey ed25519.PrivateKey) (Identity, error) {
	signer, err := NewINTLV1SoftwareSigner(keyID, privateKey)
	if err != nil {
		return Identity{}, err
	}
	return NewIdentity(tenantID, clientID, signer)
}

// NewCNSMV1Identity is the development/reference SM2 software-key
// constructor. Production applications should pass a callback signer to
// NewIdentity so private key material never enters SDK memory.
func NewCNSMV1Identity(tenantID, clientID, keyID string, privateKey []byte) (Identity, error) {
	signer, err := NewCNSMV1SoftwareSigner(keyID, privateKey)
	if err != nil {
		return Identity{}, err
	}
	return NewIdentity(tenantID, clientID, signer)
}

func (id Identity) signingMaterial() (KeyDescriptor, *sdkSignerAdapter, error) {
	if id.TenantID == "" || id.ClientID == "" {
		return KeyDescriptor{}, nil, fmt.Errorf("sdk: tenant_id and client_id are required")
	}
	adapter, err := signerAdapter(id.Signer)
	if err != nil {
		return KeyDescriptor{}, nil, err
	}
	if id.KeyID == "" || id.KeyID != adapter.descriptor.KeyID {
		return KeyDescriptor{}, nil, fmt.Errorf(
			"sdk: identity key_id %q does not match signer key_id %q",
			id.KeyID,
			adapter.descriptor.KeyID,
		)
	}
	return adapter.descriptor.Clone(), adapter, nil
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

type AnchorResourceListOptions struct {
	Kind   string
	Limit  int
	Cursor string
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
	OK                bool
	ServerURL         string
	RTTMillis         int64
	Error             string
	StatusCode        int
	TransportSecurity string
	TLSVersion        string
	PeerAuthenticated bool
	PeerSubject       string
}

type AnchorStatus struct {
	TreeSize uint64
	Status   string
	Result   *STHAnchorResult
}

type TrustedKeys struct {
	ClientPublicKey           KeyDescriptor
	ServerPublicKey           KeyDescriptor
	AcceptedReceiptPublicKey  KeyDescriptor
	CommittedReceiptPublicKey KeyDescriptor
	SignedTreeHeadPublicKey   KeyDescriptor
}

type VerifyOptions struct {
	SkipAnchor     bool
	AnchorVerifier AnchorVerifier
}

// AnchorVerifier is satisfied by *anchorplugin.Process. It lets SDK callers
// verify provider-specific L5 proof bytes without importing TrustDB internals.
type AnchorVerifier interface {
	Info() anchorplugin.GetInfoResponse
	Verify(context.Context, anchorplugin.SignedTreeHead, anchorplugin.AnchorResult) error
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
