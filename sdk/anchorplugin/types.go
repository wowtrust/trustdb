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
)

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
