package model

const (
	SchemaClientClaim       = "trustdb.claim.v1"
	SchemaSignedClaim       = "trustdb.signed-claim.v1"
	SchemaServerRecord      = "trustdb.server-record.v1"
	SchemaAcceptedReceipt   = "trustdb.accepted-receipt.v1"
	SchemaCommittedReceipt  = "trustdb.committed-receipt.v1"
	SchemaProofBundle       = "trustdb.proof-bundle.v1"
	SchemaSingleProof       = "trustdb.sproof.v1"
	SchemaRecordIndex       = "trustdb.record-index.v1"
	SchemaBatchRoot         = "trustdb.batch-root.v1"
	SchemaBatchManifest     = "trustdb.batch-manifest.v1"
	SchemaBatchTreeLeaf     = "trustdb.batch-tree-leaf.v1"
	SchemaBatchTreeNode     = "trustdb.batch-tree-node.v1"
	SchemaWALCheckpoint     = "trustdb.wal-checkpoint.v1"
	SchemaKeyEvent          = "trustdb.key-event.v1"
	SchemaGlobalLogLeaf     = "trustdb.global-log-leaf.v1"
	SchemaGlobalLogNode     = "trustdb.global-log-node.v1"
	SchemaGlobalLogState    = "trustdb.global-log-state.v1"
	SchemaSignedTreeHead    = "trustdb.signed-tree-head.v1"
	SchemaGlobalLogProof    = "trustdb.global-log-proof.v1"
	SchemaGlobalLogTile     = "trustdb.global-log-tile.v1"
	SchemaGlobalLogOutbox   = "trustdb.global-log-outbox.v1"
	SchemaSTHAnchorOutbox   = "trustdb.sth-anchor-outbox.v1"
	SchemaSTHAnchorResult   = "trustdb.sth-anchor-result.v1"
	DefaultHashAlg          = "sha256"
	DefaultSignatureAlg     = "ed25519"
	DefaultMerkleTreeAlg    = "rfc6962-sha256"
	DefaultValidationPolicy = "trustdb.policy.v1"
)

const (
	KeyEventRegister   = "KEY_REGISTERED"
	KeyEventRevoke     = "KEY_REVOKED"
	KeyEventCompromise = "KEY_COMPROMISED"

	KeyStatusValid       = "valid"
	KeyStatusRevoked     = "revoked"
	KeyStatusCompromised = "compromised"

	BatchStatePreparing = "preparing"
	BatchStatePrepared  = "prepared"
	BatchStateCommitted = "committed"
	BatchStateFailed    = "failed"

	// Anchor lifecycle states. Items start Pending, move to Published
	// after AnchorSink.Publish succeeds, and Failed only when a sink
	// reports a permanent error (transient errors stay Pending with an
	// incremented attempt counter so the worker can retry them).
	AnchorStatePending   = "pending"
	AnchorStatePublished = "published"
	AnchorStateFailed    = "failed"
)

type Content struct {
	HashAlg       string `cbor:"hash_alg" json:"hash_alg"`
	ContentHash   []byte `cbor:"content_hash" json:"content_hash"`
	ContentLength int64  `cbor:"content_length" json:"content_length"`
	MediaType     string `cbor:"media_type,omitempty" json:"media_type,omitempty"`
	StorageURI    string `cbor:"storage_uri,omitempty" json:"storage_uri,omitempty"`
}

type Metadata struct {
	EventType string            `cbor:"event_type" json:"event_type"`
	Source    string            `cbor:"source,omitempty" json:"source,omitempty"`
	TraceID   string            `cbor:"trace_id,omitempty" json:"trace_id,omitempty"`
	Parents   []string          `cbor:"parents,omitempty" json:"parents,omitempty"`
	Custom    map[string]string `cbor:"custom,omitempty" json:"custom,omitempty"`
}

type TimeAttestation struct {
	Type  string `cbor:"type" json:"type"`
	Token []byte `cbor:"token,omitempty" json:"token,omitempty"`
}

type ClientClaim struct {
	SchemaVersion   string          `cbor:"schema_version" json:"schema_version"`
	TenantID        string          `cbor:"tenant_id" json:"tenant_id"`
	ClientID        string          `cbor:"client_id" json:"client_id"`
	KeyID           string          `cbor:"key_id" json:"key_id"`
	ProducedAtUnixN int64           `cbor:"produced_at_unix_nano" json:"produced_at_unix_nano"`
	Nonce           []byte          `cbor:"nonce" json:"nonce"`
	IdempotencyKey  string          `cbor:"idempotency_key" json:"idempotency_key"`
	Content         Content         `cbor:"content" json:"content"`
	Metadata        Metadata        `cbor:"metadata" json:"metadata"`
	TimeAttestation TimeAttestation `cbor:"time_attestation,omitempty" json:"time_attestation,omitempty"`
}

type Signature struct {
	Alg       string `cbor:"alg" json:"alg"`
	KeyID     string `cbor:"key_id" json:"key_id"`
	Signature []byte `cbor:"signature" json:"signature"`
}

type SignedClaim struct {
	SchemaVersion string      `cbor:"schema_version" json:"schema_version"`
	Claim         ClientClaim `cbor:"claim" json:"claim"`
	Signature     Signature   `cbor:"signature" json:"signature"`
}

type WALPosition struct {
	SegmentID uint64 `cbor:"segment_id" json:"segment_id"`
	Offset    int64  `cbor:"offset" json:"offset"`
	Sequence  uint64 `cbor:"sequence" json:"sequence"`
}

type Validation struct {
	PolicyVersion       string `cbor:"policy_version" json:"policy_version"`
	HashAlgAllowed      bool   `cbor:"hash_alg_allowed" json:"hash_alg_allowed"`
	SignatureAlgAllowed bool   `cbor:"signature_alg_allowed" json:"signature_alg_allowed"`
	KeyStatus           string `cbor:"key_status" json:"key_status"`
}

type ServerRecord struct {
	SchemaVersion       string      `cbor:"schema_version" json:"schema_version"`
	RecordID            string      `cbor:"record_id" json:"record_id"`
	TenantID            string      `cbor:"tenant_id" json:"tenant_id"`
	ClientID            string      `cbor:"client_id" json:"client_id"`
	KeyID               string      `cbor:"key_id" json:"key_id"`
	ClaimHash           []byte      `cbor:"claim_hash" json:"claim_hash"`
	ClientSignatureHash []byte      `cbor:"client_signature_hash" json:"client_signature_hash"`
	ReceivedAtUnixN     int64       `cbor:"received_at_unix_nano" json:"received_at_unix_nano"`
	WAL                 WALPosition `cbor:"wal" json:"wal"`
	Validation          Validation  `cbor:"validation" json:"validation"`
}

type AcceptedReceipt struct {
	SchemaVersion   string      `cbor:"schema_version" json:"schema_version"`
	RecordID        string      `cbor:"record_id" json:"record_id"`
	Status          string      `cbor:"status" json:"status"`
	ServerID        string      `cbor:"server_id" json:"server_id"`
	ReceivedAtUnixN int64       `cbor:"server_received_at_unix_nano" json:"server_received_at_unix_nano"`
	WAL             WALPosition `cbor:"wal" json:"wal"`
	ServerSig       Signature   `cbor:"server_signature" json:"server_signature"`
}

type CommittedReceipt struct {
	SchemaVersion string `cbor:"schema_version" json:"schema_version"`
	RecordID      string `cbor:"record_id" json:"record_id"`
	Status        string `cbor:"status" json:"status"`
	BatchID       string `cbor:"batch_id" json:"batch_id"`
	LeafIndex     uint64 `cbor:"leaf_index" json:"leaf_index"`
	LeafHash      []byte `cbor:"leaf_hash" json:"leaf_hash"`
	BatchRoot     []byte `cbor:"batch_root" json:"batch_root"`
	ClosedAtUnixN int64  `cbor:"batch_closed_at_unix_nano" json:"batch_closed_at_unix_nano"`
	// NodeID identifies the compute node that issued this receipt (same meaning as AcceptedReceipt.ServerID).
	NodeID string `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	// LogID scopes batch/STH identifiers to a node-local transparency log.
	LogID     string    `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	ServerSig Signature `cbor:"server_signature" json:"server_signature"`
}

type BatchProof struct {
	TreeAlg   string   `cbor:"tree_alg" json:"tree_alg"`
	LeafIndex uint64   `cbor:"leaf_index" json:"leaf_index"`
	TreeSize  uint64   `cbor:"tree_size" json:"tree_size"`
	AuditPath [][]byte `cbor:"audit_path" json:"audit_path"`
}

type ProofBundle struct {
	SchemaVersion string `cbor:"schema_version" json:"schema_version"`
	RecordID      string `cbor:"record_id" json:"record_id"`
	// NodeID is the compute node identity (mirrors AcceptedReceipt.ServerID when populated).
	NodeID           string           `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID            string           `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	SignedClaim      SignedClaim      `cbor:"signed_claim" json:"signed_claim"`
	ServerRecord     ServerRecord     `cbor:"server_record" json:"server_record"`
	AcceptedReceipt  AcceptedReceipt  `cbor:"accepted_receipt" json:"accepted_receipt"`
	CommittedReceipt CommittedReceipt `cbor:"committed_receipt" json:"committed_receipt"`
	BatchProof       BatchProof       `cbor:"batch_proof" json:"batch_proof"`
}

// SingleProof is the portable, one-file desktop proof format. It keeps the
// required L1-L3 ProofBundle together with the optional L4 GlobalLogProof and
// optional L5 STHAnchorResult so auditors can verify the strongest currently
// available level without juggling multiple files.
type SingleProof struct {
	SchemaVersion string `cbor:"schema_version" json:"schema_version"`
	FormatVersion uint64 `cbor:"format_version" json:"format_version"`
	RecordID      string `cbor:"record_id" json:"record_id"`
	ProofLevel    string `cbor:"proof_level" json:"proof_level"`
	// NodeID and LogID duplicate proof_bundle hints for lightweight clients (optional).
	NodeID          string           `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID           string           `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	ProofBundle     ProofBundle      `cbor:"proof_bundle" json:"proof_bundle"`
	GlobalProof     *GlobalLogProof  `cbor:"global_proof,omitempty" json:"global_proof,omitempty"`
	AnchorResult    *STHAnchorResult `cbor:"anchor_result,omitempty" json:"anchor_result,omitempty"`
	ExportedAtUnixN int64            `cbor:"exported_at_unix_nano" json:"exported_at_unix_nano"`
}

// RecordIndex is the small server-side list/search projection derived from a
// committed ProofBundle. It avoids loading full proof bundles when operators
// or desktop clients need a paginated record list.
type RecordIndex struct {
	SchemaVersion      string `cbor:"schema_version" json:"schema_version"`
	RecordID           string `cbor:"record_id" json:"record_id"`
	NodeID             string `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID              string `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	TenantID           string `cbor:"tenant_id,omitempty" json:"tenant_id,omitempty"`
	ClientID           string `cbor:"client_id,omitempty" json:"client_id,omitempty"`
	KeyID              string `cbor:"key_id,omitempty" json:"key_id,omitempty"`
	ProofLevel         string `cbor:"proof_level,omitempty" json:"proof_level,omitempty"`
	BatchID            string `cbor:"batch_id,omitempty" json:"batch_id,omitempty"`
	BatchLeafIndex     uint64 `cbor:"batch_leaf_index" json:"batch_leaf_index"`
	BatchClosedAtUnixN int64  `cbor:"batch_closed_at_unix_nano,omitempty" json:"batch_closed_at_unix_nano,omitempty"`
	ReceivedAtUnixN    int64  `cbor:"received_at_unix_nano" json:"received_at_unix_nano"`
	ContentHash        []byte `cbor:"content_hash,omitempty" json:"content_hash,omitempty"`
	ContentLength      int64  `cbor:"content_length,omitempty" json:"content_length,omitempty"`
	MediaType          string `cbor:"media_type,omitempty" json:"media_type,omitempty"`
	StorageURI         string `cbor:"storage_uri,omitempty" json:"storage_uri,omitempty"`
	FileName           string `cbor:"file_name,omitempty" json:"file_name,omitempty"`
	EventType          string `cbor:"event_type,omitempty" json:"event_type,omitempty"`
	Source             string `cbor:"source,omitempty" json:"source,omitempty"`
}

type RecordListOptions struct {
	Limit                int
	Direction            string
	BatchID              string
	TenantID             string
	ClientID             string
	ProofLevel           string
	Query                string
	ContentHash          []byte
	ReceivedFromUnixN    int64
	ReceivedToUnixN      int64
	AfterReceivedAtUnixN int64
	AfterRecordID        string
}

const (
	RecordListDirectionAsc  = "asc"
	RecordListDirectionDesc = "desc"
)

type RootListOptions struct {
	Limit              int
	Direction          string
	AfterClosedAtUnixN int64
	AfterBatchID       string
}

type BatchTreeLeafListOptions struct {
	BatchID        string
	Limit          int
	AfterLeafIndex uint64
	HasAfter       bool
}

type BatchTreeNodeListOptions struct {
	BatchID         string
	Level           uint64
	StartIndex      uint64
	Limit           int
	AfterStartIndex uint64
	HasAfter        bool
}

type TreeHeadListOptions struct {
	Limit         int
	Direction     string
	AfterTreeSize uint64
}

type GlobalLeafListOptions struct {
	Limit          int
	Direction      string
	AfterLeafIndex uint64
}

type AnchorListOptions struct {
	Limit         int
	Direction     string
	AfterTreeSize uint64
}

func RecordIndexFromBundle(bundle ProofBundle) RecordIndex {
	record := bundle.ServerRecord
	if record.RecordID == "" {
		record.RecordID = bundle.RecordID
	}
	return RecordIndexFromBatchInputs(
		bundle.SignedClaim,
		record,
		bundle.AcceptedReceipt,
		bundle.NodeID,
		bundle.LogID,
		bundle.CommittedReceipt.BatchID,
		bundle.CommittedReceipt.LeafIndex,
		bundle.CommittedReceipt.ClosedAtUnixN,
		"L3",
	)
}

func RecordIndexFromBatchInputs(
	signed SignedClaim,
	record ServerRecord,
	accepted AcceptedReceipt,
	nodeID string,
	logID string,
	batchID string,
	leafIndex uint64,
	closedAtUnixN int64,
	proofLevel string,
) RecordIndex {
	claim := signed.Claim
	tenantID := record.TenantID
	if tenantID == "" {
		tenantID = claim.TenantID
	}
	clientID := record.ClientID
	if clientID == "" {
		clientID = claim.ClientID
	}
	keyID := record.KeyID
	if keyID == "" {
		keyID = claim.KeyID
	}
	fileName := claim.Metadata.Custom["file_name"]
	if fileName == "" {
		fileName = claim.Metadata.Custom["filename"]
	}
	receivedAt := record.ReceivedAtUnixN
	if receivedAt == 0 {
		receivedAt = accepted.ReceivedAtUnixN
	}
	if receivedAt == 0 {
		receivedAt = closedAtUnixN
	}
	return RecordIndex{
		SchemaVersion:      SchemaRecordIndex,
		RecordID:           record.RecordID,
		NodeID:             nodeID,
		LogID:              logID,
		TenantID:           tenantID,
		ClientID:           clientID,
		KeyID:              keyID,
		ProofLevel:         proofLevel,
		BatchID:            batchID,
		BatchLeafIndex:     leafIndex,
		BatchClosedAtUnixN: closedAtUnixN,
		ReceivedAtUnixN:    receivedAt,
		ContentHash:        append([]byte(nil), claim.Content.ContentHash...),
		ContentLength:      claim.Content.ContentLength,
		MediaType:          claim.Content.MediaType,
		StorageURI:         claim.Content.StorageURI,
		FileName:           fileName,
		EventType:          claim.Metadata.EventType,
		Source:             claim.Metadata.Source,
	}
}

type BatchRoot struct {
	SchemaVersion string `cbor:"schema_version" json:"schema_version"`
	BatchID       string `cbor:"batch_id" json:"batch_id"`
	NodeID        string `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID         string `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	BatchRoot     []byte `cbor:"batch_root" json:"batch_root"`
	TreeSize      uint64 `cbor:"tree_size" json:"tree_size"`
	ClosedAtUnixN int64  `cbor:"closed_at_unix_nano" json:"closed_at_unix_nano"`
}

type WALRange struct {
	From WALPosition `cbor:"from" json:"from"`
	To   WALPosition `cbor:"to" json:"to"`
}

// WALCheckpoint marks a safe-to-skip boundary inside the WAL. Any record
// whose WAL sequence is less than or equal to LastSequence has already been
// covered by a committed batch, so replay on startup can ignore it instead of
// rebuilding an Accepted entry. The checkpoint is advanced monotonically
// after a BatchManifest reaches the committed state and is kept as
// best-effort metadata: losing it never causes data loss because replay can
// always fall back to scanning the full WAL.
type WALCheckpoint struct {
	SchemaVersion   string `cbor:"schema_version" json:"schema_version"`
	SegmentID       uint64 `cbor:"segment_id" json:"segment_id"`
	LastSequence    uint64 `cbor:"last_sequence" json:"last_sequence"`
	LastOffset      int64  `cbor:"last_offset" json:"last_offset"`
	BatchID         string `cbor:"batch_id,omitempty" json:"batch_id,omitempty"`
	RecordedAtUnixN int64  `cbor:"recorded_at_unix_nano" json:"recorded_at_unix_nano"`
}

type BatchManifest struct {
	SchemaVersion          string   `cbor:"schema_version" json:"schema_version"`
	BatchID                string   `cbor:"batch_id" json:"batch_id"`
	NodeID                 string   `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID                  string   `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	State                  string   `cbor:"state" json:"state"`
	TreeAlg                string   `cbor:"tree_alg" json:"tree_alg"`
	TreeSize               uint64   `cbor:"tree_size" json:"tree_size"`
	BatchRoot              []byte   `cbor:"batch_root" json:"batch_root"`
	RecordIDs              []string `cbor:"record_ids" json:"record_ids"`
	WALRange               WALRange `cbor:"wal_range" json:"wal_range"`
	ClosedAtUnixN          int64    `cbor:"closed_at_unix_nano" json:"closed_at_unix_nano"`
	PreparingAtUnixN       int64    `cbor:"preparing_at_unix_nano,omitempty" json:"preparing_at_unix_nano,omitempty"`
	PreparedAtUnixN        int64    `cbor:"prepared_at_unix_nano,omitempty" json:"prepared_at_unix_nano,omitempty"`
	CommittedAtUnixN       int64    `cbor:"committed_at_unix_nano,omitempty" json:"committed_at_unix_nano,omitempty"`
	MaterializeAttempts    int      `cbor:"materialize_attempts,omitempty" json:"materialize_attempts,omitempty"`
	MaterializeNextUnixN   int64    `cbor:"materialize_next_unix_nano,omitempty" json:"materialize_next_unix_nano,omitempty"`
	MaterializeLastError   string   `cbor:"materialize_last_error,omitempty" json:"materialize_last_error,omitempty"`
	MaterializeFailureCode string   `cbor:"materialize_failure_code,omitempty" json:"materialize_failure_code,omitempty"`
}

// BatchTreeLeaf is a lightweight projection for browsing a batch Merkle tree.
// It intentionally stores only the record binding and leaf hash so API callers
// can page through huge batches without loading full proof bundles.
type BatchTreeLeaf struct {
	SchemaVersion  string `cbor:"schema_version" json:"schema_version"`
	BatchID        string `cbor:"batch_id" json:"batch_id"`
	RecordID       string `cbor:"record_id" json:"record_id"`
	LeafIndex      uint64 `cbor:"leaf_index" json:"leaf_index"`
	LeafHash       []byte `cbor:"leaf_hash" json:"leaf_hash"`
	CreatedAtUnixN int64  `cbor:"created_at_unix_nano" json:"created_at_unix_nano"`
}

// BatchTreeNode stores complete Merkle subtrees for one batch. The pair
// (level,start_index) is ordered for range scans; width is usually 2^level
// except for right-edge RFC6962 subtrees in non-power-of-two batches.
type BatchTreeNode struct {
	SchemaVersion  string `cbor:"schema_version" json:"schema_version"`
	BatchID        string `cbor:"batch_id" json:"batch_id"`
	Level          uint64 `cbor:"level" json:"level"`
	StartIndex     uint64 `cbor:"start_index" json:"start_index"`
	Width          uint64 `cbor:"width" json:"width"`
	Hash           []byte `cbor:"hash" json:"hash"`
	CreatedAtUnixN int64  `cbor:"created_at_unix_nano" json:"created_at_unix_nano"`
}

// GlobalLogLeaf is the append-only global transparency log item for one
// committed batch. L4 proofs show that a batch leaf is included in a
// SignedTreeHead.
type GlobalLogLeaf struct {
	SchemaVersion      string `cbor:"schema_version" json:"schema_version"`
	NodeID             string `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID              string `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	BatchID            string `cbor:"batch_id" json:"batch_id"`
	BatchRoot          []byte `cbor:"batch_root" json:"batch_root"`
	BatchTreeSize      uint64 `cbor:"batch_tree_size" json:"batch_tree_size"`
	BatchClosedAtUnixN int64  `cbor:"batch_closed_at_unix_nano" json:"batch_closed_at_unix_nano"`
	LeafIndex          uint64 `cbor:"leaf_index" json:"leaf_index"`
	LeafHash           []byte `cbor:"leaf_hash" json:"leaf_hash"`
	AppendedAtUnixN    int64  `cbor:"appended_at_unix_nano" json:"appended_at_unix_nano"`
}

// GlobalLogNode stores the hash for a complete, power-of-two sized subtree
// in the global log. Nodes make STH append/proof generation read O(log N)
// indexed hashes instead of rebuilding from every historical leaf.
type GlobalLogNode struct {
	SchemaVersion  string `cbor:"schema_version" json:"schema_version"`
	Level          uint64 `cbor:"level" json:"level"`
	StartIndex     uint64 `cbor:"start_index" json:"start_index"`
	Width          uint64 `cbor:"width" json:"width"`
	Hash           []byte `cbor:"hash" json:"hash"`
	CreatedAtUnixN int64  `cbor:"created_at_unix_nano" json:"created_at_unix_nano"`
}

// GlobalLogState is the latest append frontier for the global transparency
// log. Frontier[level] is the root of the rightmost complete subtree of
// width 2^level when that level is present in TreeSize's binary form.
type GlobalLogState struct {
	SchemaVersion  string   `cbor:"schema_version" json:"schema_version"`
	TreeSize       uint64   `cbor:"tree_size" json:"tree_size"`
	RootHash       []byte   `cbor:"root_hash,omitempty" json:"root_hash,omitempty"`
	Frontier       [][]byte `cbor:"frontier" json:"frontier"`
	UpdatedAtUnixN int64    `cbor:"updated_at_unix_nano" json:"updated_at_unix_nano"`
}

// SignedTreeHead is the global log root after TreeSize leaves. L5 anchors
// publish this structure's RootHash, never a per-batch root.
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

// GlobalLogAppend is the atomic persistence unit for one Global Log append.
// It keeps the async outbox boundary intact while allowing a proofstore
// backend to persist leaf indexes, internal nodes, frontier state, and STH in
// one backend transaction when supported.
type GlobalLogAppend struct {
	Leaf  GlobalLogLeaf   `json:"leaf"`
	Nodes []GlobalLogNode `json:"nodes"`
	State GlobalLogState  `json:"state"`
	STH   SignedTreeHead  `json:"sth"`
}

type GlobalConsistencyProof struct {
	FromTreeSize uint64   `cbor:"from_tree_size" json:"from_tree_size"`
	ToTreeSize   uint64   `cbor:"to_tree_size" json:"to_tree_size"`
	AuditPath    [][]byte `cbor:"audit_path" json:"audit_path"`
}

// GlobalLogProof binds a batch root to an STH. The InclusionPath proves the
// batch leaf is in STH; Consistency is optional and links a previous STH to
// the target STH when callers request historical continuity.
type GlobalLogProof struct {
	SchemaVersion string                 `cbor:"schema_version" json:"schema_version"`
	NodeID        string                 `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID         string                 `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	BatchID       string                 `cbor:"batch_id" json:"batch_id"`
	LeafIndex     uint64                 `cbor:"leaf_index" json:"leaf_index"`
	LeafHash      []byte                 `cbor:"leaf_hash" json:"leaf_hash"`
	TreeSize      uint64                 `cbor:"tree_size" json:"tree_size"`
	InclusionPath [][]byte               `cbor:"inclusion_path" json:"inclusion_path"`
	STH           SignedTreeHead         `cbor:"sth" json:"sth"`
	Consistency   GlobalConsistencyProof `cbor:"consistency,omitempty" json:"consistency,omitempty"`
}

// GlobalLogTile is a compacted immutable range of global log leaf hashes.
// The first implementation stores deterministic CBOR tiles so old proofs can
// be restored without keeping every hot in-memory node forever.
type GlobalLogTile struct {
	SchemaVersion  string   `cbor:"schema_version" json:"schema_version"`
	Level          uint64   `cbor:"level" json:"level"`
	StartIndex     uint64   `cbor:"start_index" json:"start_index"`
	Width          uint64   `cbor:"width" json:"width"`
	Hashes         [][]byte `cbor:"hashes" json:"hashes"`
	Compressed     bool     `cbor:"compressed" json:"compressed"`
	CreatedAtUnixN int64    `cbor:"created_at_unix_nano" json:"created_at_unix_nano"`
}

// GlobalLogOutboxItem decouples batch commit from global-log append. A batch
// worker only persists this item; a separate worker appends the batch root,
// creates the STH, and then enqueues the STH anchor outbox item.
type GlobalLogOutboxItem struct {
	SchemaVersion    string         `cbor:"schema_version" json:"schema_version"`
	BatchID          string         `cbor:"batch_id" json:"batch_id"`
	BatchRoot        BatchRoot      `cbor:"batch_root" json:"batch_root"`
	Status           string         `cbor:"status" json:"status"`
	STH              SignedTreeHead `cbor:"sth,omitempty" json:"sth,omitempty"`
	Attempts         int            `cbor:"attempts" json:"attempts"`
	EnqueuedAtUnixN  int64          `cbor:"enqueued_at_unix_nano" json:"enqueued_at_unix_nano"`
	NextAttemptUnixN int64          `cbor:"next_attempt_unix_nano,omitempty" json:"next_attempt_unix_nano,omitempty"`
	LastAttemptUnixN int64          `cbor:"last_attempt_unix_nano,omitempty" json:"last_attempt_unix_nano,omitempty"`
	LastErrorMessage string         `cbor:"last_error_message,omitempty" json:"last_error_message,omitempty"`
	CompletedAtUnixN int64          `cbor:"completed_at_unix_nano,omitempty" json:"completed_at_unix_nano,omitempty"`
}

type ClientKey struct {
	TenantID           string `cbor:"tenant_id" json:"tenant_id"`
	ClientID           string `cbor:"client_id" json:"client_id"`
	KeyID              string `cbor:"key_id" json:"key_id"`
	Alg                string `cbor:"alg" json:"alg"`
	PublicKey          []byte `cbor:"public_key" json:"public_key"`
	ValidFromUnixN     int64  `cbor:"valid_from_unix_nano" json:"valid_from_unix_nano"`
	ValidUntilUnixN    int64  `cbor:"valid_until_unix_nano,omitempty" json:"valid_until_unix_nano,omitempty"`
	Status             string `cbor:"status" json:"status"`
	RevokedAtUnixN     int64  `cbor:"revoked_at_unix_nano,omitempty" json:"revoked_at_unix_nano,omitempty"`
	CompromisedAtUnixN int64  `cbor:"compromised_at_unix_nano,omitempty" json:"compromised_at_unix_nano,omitempty"`
}

// STHAnchorOutboxItem is the unit of work consumed by the L5 anchor worker.
// It is keyed by STH tree size; batch roots are never directly anchored.
type STHAnchorOutboxItem struct {
	SchemaVersion    string         `cbor:"schema_version" json:"schema_version"`
	TreeSize         uint64         `cbor:"tree_size" json:"tree_size"`
	Status           string         `cbor:"status" json:"status"`
	SinkName         string         `cbor:"sink_name" json:"sink_name"`
	STH              SignedTreeHead `cbor:"sth" json:"sth"`
	Attempts         int            `cbor:"attempts" json:"attempts"`
	EnqueuedAtUnixN  int64          `cbor:"enqueued_at_unix_nano" json:"enqueued_at_unix_nano"`
	NextAttemptUnixN int64          `cbor:"next_attempt_unix_nano,omitempty" json:"next_attempt_unix_nano,omitempty"`
	LastErrorMessage string         `cbor:"last_error_message,omitempty" json:"last_error_message,omitempty"`
	LastAttemptUnixN int64          `cbor:"last_attempt_unix_nano,omitempty" json:"last_attempt_unix_nano,omitempty"`
}

// STHAnchorResult records a successful external publication of an STH/global
// root. AnchorID identifies the external artefact and Proof is sink-specific.
type STHAnchorResult struct {
	SchemaVersion    string         `cbor:"schema_version" json:"schema_version"`
	NodeID           string         `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID            string         `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	TreeSize         uint64         `cbor:"tree_size" json:"tree_size"`
	SinkName         string         `cbor:"sink_name" json:"sink_name"`
	AnchorID         string         `cbor:"anchor_id" json:"anchor_id"`
	RootHash         []byte         `cbor:"root_hash" json:"root_hash"`
	STH              SignedTreeHead `cbor:"sth" json:"sth"`
	Proof            []byte         `cbor:"proof,omitempty" json:"proof,omitempty"`
	PublishedAtUnixN int64          `cbor:"published_at_unix_nano" json:"published_at_unix_nano"`
}

type KeyEvent struct {
	SchemaVersion      string    `cbor:"schema_version" json:"schema_version"`
	Sequence           uint64    `cbor:"sequence" json:"sequence"`
	Type               string    `cbor:"type" json:"type"`
	TenantID           string    `cbor:"tenant_id" json:"tenant_id"`
	ClientID           string    `cbor:"client_id" json:"client_id"`
	KeyID              string    `cbor:"key_id" json:"key_id"`
	Alg                string    `cbor:"alg" json:"alg"`
	PublicKey          []byte    `cbor:"public_key,omitempty" json:"public_key,omitempty"`
	ValidFromUnixN     int64     `cbor:"valid_from_unix_nano,omitempty" json:"valid_from_unix_nano,omitempty"`
	ValidUntilUnixN    int64     `cbor:"valid_until_unix_nano,omitempty" json:"valid_until_unix_nano,omitempty"`
	RevokedAtUnixN     int64     `cbor:"revoked_at_unix_nano,omitempty" json:"revoked_at_unix_nano,omitempty"`
	CompromisedAtUnixN int64     `cbor:"compromised_at_unix_nano,omitempty" json:"compromised_at_unix_nano,omitempty"`
	Reason             string    `cbor:"reason,omitempty" json:"reason,omitempty"`
	PrevEventHash      []byte    `cbor:"prev_event_hash,omitempty" json:"prev_event_hash,omitempty"`
	EventHash          []byte    `cbor:"event_hash" json:"event_hash"`
	RegistrySignature  Signature `cbor:"registry_signature" json:"registry_signature"`
}
