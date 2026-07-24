// Package anchorplugin defines the public process boundary for custom TrustDB
// L5 anchor providers. Plugins are independent executables that communicate
// with TrustDB over a versioned gRPC protocol and never import internal model
// packages.
package anchorplugin

const (
	ProtocolVersion = "trustdb.anchor-plugin.v1"
	ServiceName     = "trustdb.anchorplugin.v1.AnchorPlugin"
	MaxMessageBytes = 16 << 20
)

const (
	CapabilityPublish = "publish"
	CapabilityVerify  = "verify"

	CapabilitySystemStatusRead = "system.status.read"
	CapabilityNodeRead         = "node.read"
	CapabilityBlockRead        = "block.read"
	CapabilityTransactionRead  = "transaction.read"
	CapabilityAccountRead      = "account.read"
	CapabilityContractRead     = "contract.read"
	CapabilityDataSync         = "data.sync"
	CapabilityBlockProduce     = "block.produce"
	CapabilityTransactionSend  = "transaction.send"
	CapabilityContractCall     = "contract.call"
	CapabilityContractDeploy   = "contract.deploy"
)

const (
	SystemKindTimestampEvidence  = "timestamp_evidence"
	SystemKindEvidenceBlockchain = "evidence_blockchain"
	SystemKindFullBlockchain     = "full_blockchain"
)

const (
	ResourceKindNode        = "node"
	ResourceKindBlock       = "block"
	ResourceKindTransaction = "transaction"
	ResourceKindAccount     = "account"
	ResourceKindContract    = "contract"

	SystemStateHealthy     = "healthy"
	SystemStateDegraded    = "degraded"
	SystemStateUnavailable = "unavailable"
	SystemStateUnknown     = "unknown"
)

type Assurance struct {
	IndependentTime    bool   `cbor:"independent_time" json:"independent_time"`
	PubliclyVerifiable bool   `cbor:"publicly_verifiable" json:"publicly_verifiable"`
	Decentralized      bool   `cbor:"decentralized" json:"decentralized"`
	Finality           string `cbor:"finality,omitempty" json:"finality,omitempty"`
	Custody            string `cbor:"custody,omitempty" json:"custody,omitempty"`
}

// System describes one configured downstream anchor provider instance. It is
// optional so existing v1 plugins remain source- and wire-compatible.
type System struct {
	SystemID     string            `cbor:"system_id" json:"system_id"`
	DisplayName  string            `cbor:"display_name" json:"display_name"`
	Kind         string            `cbor:"kind" json:"kind"`
	Network      string            `cbor:"network,omitempty" json:"network,omitempty"`
	Provider     string            `cbor:"provider,omitempty" json:"provider,omitempty"`
	Capabilities []string          `cbor:"capabilities,omitempty" json:"capabilities,omitempty"`
	Assurance    Assurance         `cbor:"assurance" json:"assurance"`
	Metadata     map[string]string `cbor:"metadata,omitempty" json:"metadata,omitempty"`
}

type SystemStatus struct {
	State           string            `cbor:"state" json:"state"`
	ObservedAtUnixN int64             `cbor:"observed_at_unix_nano" json:"observed_at_unix_nano"`
	Message         string            `cbor:"message,omitempty" json:"message,omitempty"`
	Details         map[string]string `cbor:"details,omitempty" json:"details,omitempty"`
}

type Resource struct {
	Kind           string            `cbor:"kind" json:"kind"`
	ResourceID     string            `cbor:"resource_id" json:"resource_id"`
	ParentID       string            `cbor:"parent_id,omitempty" json:"parent_id,omitempty"`
	Hash           string            `cbor:"hash,omitempty" json:"hash,omitempty"`
	Status         string            `cbor:"status,omitempty" json:"status,omitempty"`
	Height         uint64            `cbor:"height,omitempty" json:"height,omitempty"`
	TimestampUnixN int64             `cbor:"timestamp_unix_nano,omitempty" json:"timestamp_unix_nano,omitempty"`
	Summary        string            `cbor:"summary,omitempty" json:"summary,omitempty"`
	Attributes     map[string]string `cbor:"attributes,omitempty" json:"attributes,omitempty"`
}

type Signature struct {
	Alg       string `cbor:"alg" json:"alg"`
	KeyID     string `cbor:"key_id" json:"key_id"`
	Signature []byte `cbor:"signature" json:"signature"`
}

// SignedTreeHead is the immutable L4 object presented to a plugin. A plugin
// anchors RootHash but should retain the complete object in its external
// evidence so NodeID, LogID and TreeSize remain auditable.
type SignedTreeHead struct {
	SchemaVersion  string    `cbor:"schema_version" json:"schema_version"`
	TreeAlg        string    `cbor:"tree_alg" json:"tree_alg"`
	TreeSize       uint64    `cbor:"tree_size" json:"tree_size"`
	RootHash       []byte    `cbor:"root_hash" json:"root_hash"`
	TimestampUnixN int64     `cbor:"timestamp_unix_nano" json:"timestamp_unix_nano"`
	NodeID         string    `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID          string    `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	Signature      Signature `cbor:"signature" json:"signature"`
}

// AnchorResult contains only provider-controlled publication fields. TrustDB
// reconstructs and validates all immutable STH binding fields before storage.
type AnchorResult struct {
	AnchorID         string `cbor:"anchor_id" json:"anchor_id"`
	Proof            []byte `cbor:"proof,omitempty" json:"proof,omitempty"`
	PublishedAtUnixN int64  `cbor:"published_at_unix_nano,omitempty" json:"published_at_unix_nano,omitempty"`
}

type GetInfoRequest struct{}

type GetInfoResponse struct {
	ProtocolVersion string   `cbor:"protocol_version" json:"protocol_version"`
	SinkName        string   `cbor:"sink_name" json:"sink_name"`
	Capabilities    []string `cbor:"capabilities" json:"capabilities"`
	ProofSchema     string   `cbor:"proof_schema,omitempty" json:"proof_schema,omitempty"`
	System          *System  `cbor:"system,omitempty" json:"system,omitempty"`
}

type PublishRequest struct {
	STH SignedTreeHead `cbor:"sth" json:"sth"`
}

type PublishResponse struct {
	Result AnchorResult `cbor:"result" json:"result"`
}

type VerifyRequest struct {
	STH    SignedTreeHead `cbor:"sth" json:"sth"`
	Result AnchorResult   `cbor:"result" json:"result"`
}

type VerifyResponse struct {
	Valid bool `cbor:"valid" json:"valid"`
}

type GetStatusRequest struct{}

type GetStatusResponse struct {
	Status SystemStatus `cbor:"status" json:"status"`
}

type ListResourcesRequest struct {
	Kind   string `cbor:"kind" json:"kind"`
	Limit  int    `cbor:"limit" json:"limit"`
	Cursor string `cbor:"cursor,omitempty" json:"cursor,omitempty"`
}

type ListResourcesResponse struct {
	Resources  []Resource `cbor:"resources" json:"resources"`
	Limit      int        `cbor:"limit" json:"limit"`
	NextCursor string     `cbor:"next_cursor,omitempty" json:"next_cursor,omitempty"`
}

type GetResourceRequest struct {
	Kind       string `cbor:"kind" json:"kind"`
	ResourceID string `cbor:"resource_id" json:"resource_id"`
}

type GetResourceResponse struct {
	Resource Resource `cbor:"resource" json:"resource"`
	Found    bool     `cbor:"found" json:"found"`
}
