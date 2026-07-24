package model

const (
	SchemaAnchorSystem         = "trustdb.anchor-system.v1"
	SchemaAnchorSystemStatus   = "trustdb.anchor-system-status.v1"
	SchemaAnchorSystemResource = "trustdb.anchor-system-resource.v1"

	AnchorSystemKindTimestampEvidence  = "timestamp_evidence"
	AnchorSystemKindEvidenceBlockchain = "evidence_blockchain"
	AnchorSystemKindFullBlockchain     = "full_blockchain"

	AnchorCapabilityPublish          = "anchor.publish"
	AnchorCapabilityVerify           = "anchor.verify"
	AnchorCapabilityEvidenceRead     = "evidence.read"
	AnchorCapabilitySystemStatusRead = "system.status.read"
	AnchorCapabilityNodeRead         = "node.read"
	AnchorCapabilityBlockRead        = "block.read"
	AnchorCapabilityTransactionRead  = "transaction.read"
	AnchorCapabilityAccountRead      = "account.read"
	AnchorCapabilityContractRead     = "contract.read"
	AnchorCapabilityDataSync         = "data.sync"
	AnchorCapabilityBlockProduce     = "block.produce"
	AnchorCapabilityTransactionSend  = "transaction.send"
	AnchorCapabilityContractCall     = "contract.call"
	AnchorCapabilityContractDeploy   = "contract.deploy"

	AnchorResourceKindNode        = "node"
	AnchorResourceKindBlock       = "block"
	AnchorResourceKindTransaction = "transaction"
	AnchorResourceKindAccount     = "account"
	AnchorResourceKindContract    = "contract"

	AnchorSystemStateHealthy     = "healthy"
	AnchorSystemStateDegraded    = "degraded"
	AnchorSystemStateUnavailable = "unavailable"
	AnchorSystemStateUnknown     = "unknown"
)

// AnchorAssurance describes the external trust properties of one configured
// system. It is informational metadata and is never used as a substitute for
// verifying an immutable STHAnchorResult.
type AnchorAssurance struct {
	IndependentTime    bool   `cbor:"independent_time" json:"independent_time"`
	PubliclyVerifiable bool   `cbor:"publicly_verifiable" json:"publicly_verifiable"`
	Decentralized      bool   `cbor:"decentralized" json:"decentralized"`
	Finality           string `cbor:"finality,omitempty" json:"finality,omitempty"`
	Custody            string `cbor:"custody,omitempty" json:"custody,omitempty"`
}

// AnchorSystem is the stable descriptor exposed to upstream clients. SystemID
// identifies a configured provider instance; SinkName keeps the exact binding
// to immutable L5 anchor results.
type AnchorSystem struct {
	SchemaVersion string            `cbor:"schema_version" json:"schema_version"`
	SystemID      string            `cbor:"system_id" json:"system_id"`
	SinkName      string            `cbor:"sink_name" json:"sink_name"`
	DisplayName   string            `cbor:"display_name" json:"display_name"`
	Kind          string            `cbor:"kind" json:"kind"`
	Network       string            `cbor:"network,omitempty" json:"network,omitempty"`
	Provider      string            `cbor:"provider,omitempty" json:"provider,omitempty"`
	Capabilities  []string          `cbor:"capabilities" json:"capabilities"`
	Assurance     AnchorAssurance   `cbor:"assurance" json:"assurance"`
	Metadata      map[string]string `cbor:"metadata,omitempty" json:"metadata,omitempty"`
}

// AnchorSystemStatus is mutable provider state. ObservedAtUnixN tells callers
// when the provider produced the snapshot; Details carries bounded summary
// values such as chain height, peer count, or synchronization lag.
type AnchorSystemStatus struct {
	SchemaVersion   string            `cbor:"schema_version" json:"schema_version"`
	SystemID        string            `cbor:"system_id" json:"system_id"`
	State           string            `cbor:"state" json:"state"`
	ObservedAtUnixN int64             `cbor:"observed_at_unix_nano" json:"observed_at_unix_nano"`
	Message         string            `cbor:"message,omitempty" json:"message,omitempty"`
	Details         map[string]string `cbor:"details,omitempty" json:"details,omitempty"`
}

// AnchorSystemResource is a provider-neutral read model for explorer data.
// Common fields remain typed while Attributes preserves provider-specific
// information without making the TrustDB API depend on one chain vendor.
type AnchorSystemResource struct {
	SchemaVersion  string            `cbor:"schema_version" json:"schema_version"`
	SystemID       string            `cbor:"system_id" json:"system_id"`
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

type AnchorResourceListOptions struct {
	Kind   string
	Limit  int
	Cursor string
}

type AnchorSystemResourcePage struct {
	Resources  []AnchorSystemResource `cbor:"resources" json:"resources"`
	Limit      int                    `cbor:"limit" json:"limit"`
	NextCursor string                 `cbor:"next_cursor,omitempty" json:"next_cursor,omitempty"`
}
