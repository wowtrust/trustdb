package model

import "github.com/wowtrust/trustdb/internal/cryptosuite"

const (
	SchemaClientClaim          = "trustdb.claim.v2"
	SchemaSignedClaim          = "trustdb.signed-claim.v2"
	SchemaServerRecord         = "trustdb.server-record.v2"
	SchemaAcceptedReceipt      = "trustdb.accepted-receipt.v2"
	SchemaCommittedReceipt     = "trustdb.committed-receipt.v2"
	SchemaProofBundle          = "trustdb.proof-bundle.v2"
	SchemaSingleProof          = "trustdb.sproof.v2"
	SchemaProofIdentity        = "trustdb.proof-identity-evidence.v1"
	SchemaCertificateStatus    = "trustdb.certificate-status-evidence.v1"
	SchemaRecordIndex          = "trustdb.record-index.v2"
	SchemaRecordStatus         = "trustdb.record-status.v2"
	SchemaStatusRefresh        = "trustdb.status-refresh.v2"
	SchemaBatchRoot            = "trustdb.batch-root.v2"
	SchemaBatchManifest        = "trustdb.batch-manifest.v2"
	SchemaBatchTreeLeaf        = "trustdb.batch-tree-leaf.v2"
	SchemaBatchTreeNode        = "trustdb.batch-tree-node.v2"
	SchemaWALCheckpoint        = "trustdb.wal-checkpoint.v3"
	SchemaKeyEvent             = "trustdb.key-event.v3"
	SchemaGlobalLogLeaf        = "trustdb.global-log-leaf.v2"
	SchemaGlobalLogNode        = "trustdb.global-log-node.v2"
	SchemaGlobalLogState       = "trustdb.global-log-state.v2"
	SchemaSignedTreeHead       = "trustdb.signed-tree-head.v2"
	SchemaGlobalLogProof       = "trustdb.global-log-proof.v2"
	SchemaGlobalLogTile        = "trustdb.global-log-tile.v2"
	SchemaGlobalLogOutbox      = "trustdb.global-log-outbox.v2"
	SchemaSTHAnchorResult      = "trustdb.sth-anchor-result.v2"
	SchemaSTHAnchorSchedule    = "trustdb.sth-anchor-schedule.v2"
	SchemaSTHAnchorLatest      = "trustdb.sth-anchor-latest.v2"
	SchemaSTHAnchorLatestEmpty = "trustdb.sth-anchor-latest-empty.v2"
	SchemaL5Coverage           = "trustdb.l5-coverage-checkpoint.v2"
	DefaultCryptoSuite         = string(cryptosuite.INTLV1)
	DefaultHashAlg             = cryptosuite.HashSHA256
	DefaultSignatureAlg        = cryptosuite.SignatureEd25519
	DefaultMerkleTreeAlg       = cryptosuite.MerkleRFC6962SHA256
	DefaultValidationPolicy    = "trustdb.policy.v2"
)

const SchemaWALCheckpointContiguous = SchemaWALCheckpoint

const (
	KeyEventRegister   = "KEY_REGISTERED"
	KeyEventRotate     = "KEY_ROTATED"
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
	AnchorStateObserved  = "observed"
	AnchorStateLocalOnly = "local_only"
	AnchorStateFailed    = "failed"

	// AnchorEvidenceStageOfflineVerified is the sole stage allowed to promote
	// records to L5. AnchorEvidenceStageRaw records a durable external-chain
	// observation that has not passed TrustDB's offline verification gates.
	AnchorEvidenceStageOfflineVerified = "offline_verified"
	AnchorEvidenceStageRaw             = "external_observation"
	AnchorEvidenceStageLocalOnly       = "local_only"

	RecordStatusAccepted     = "accepted"
	RecordStatusProcessing   = "processing"
	RecordStatusRetryPending = "retry_pending"
	RecordStatusCommitted    = "committed"
	RecordStatusFailed       = "failed"
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
	CryptoSuite     cryptosuite.ID  `cbor:"crypto_suite" json:"crypto_suite"`
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
	SchemaVersion string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite   cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	Claim         ClientClaim    `cbor:"claim" json:"claim"`
	Signature     Signature      `cbor:"signature" json:"signature"`
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
	SchemaVersion       string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite         cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	RecordID            string         `cbor:"record_id" json:"record_id"`
	TenantID            string         `cbor:"tenant_id" json:"tenant_id"`
	ClientID            string         `cbor:"client_id" json:"client_id"`
	KeyID               string         `cbor:"key_id" json:"key_id"`
	ClaimHash           []byte         `cbor:"claim_hash" json:"claim_hash"`
	ClientSignatureHash []byte         `cbor:"client_signature_hash" json:"client_signature_hash"`
	ReceivedAtUnixN     int64          `cbor:"received_at_unix_nano" json:"received_at_unix_nano"`
	WAL                 WALPosition    `cbor:"wal" json:"wal"`
	Validation          Validation     `cbor:"validation" json:"validation"`
}

type AcceptedReceipt struct {
	SchemaVersion   string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite     cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	RecordID        string         `cbor:"record_id" json:"record_id"`
	Status          string         `cbor:"status" json:"status"`
	ServerID        string         `cbor:"server_id" json:"server_id"`
	ReceivedAtUnixN int64          `cbor:"server_received_at_unix_nano" json:"server_received_at_unix_nano"`
	WAL             WALPosition    `cbor:"wal" json:"wal"`
	ServerSig       Signature      `cbor:"server_signature" json:"server_signature"`
}

type CommittedReceipt struct {
	SchemaVersion string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite   cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	RecordID      string         `cbor:"record_id" json:"record_id"`
	Status        string         `cbor:"status" json:"status"`
	BatchID       string         `cbor:"batch_id" json:"batch_id"`
	LeafIndex     uint64         `cbor:"leaf_index" json:"leaf_index"`
	LeafHash      []byte         `cbor:"leaf_hash" json:"leaf_hash"`
	BatchRoot     []byte         `cbor:"batch_root" json:"batch_root"`
	ClosedAtUnixN int64          `cbor:"batch_closed_at_unix_nano" json:"batch_closed_at_unix_nano"`
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
	SchemaVersion string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite   cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	RecordID      string         `cbor:"record_id" json:"record_id"`
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
	SchemaVersion string         `cbor:"schema_version" json:"schema_version"`
	FormatVersion uint64         `cbor:"format_version" json:"format_version"`
	CryptoSuite   cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	RecordID      string         `cbor:"record_id" json:"record_id"`
	ProofLevel    string         `cbor:"proof_level" json:"proof_level"`
	// NodeID and LogID are mandatory V2 namespace bindings and must exactly
	// match every embedded proof, STH, and anchor object.
	NodeID           string                  `cbor:"node_id" json:"node_id"`
	LogID            string                  `cbor:"log_id" json:"log_id"`
	ProofBundle      ProofBundle             `cbor:"proof_bundle" json:"proof_bundle"`
	GlobalProof      *GlobalLogProof         `cbor:"global_proof,omitempty" json:"global_proof,omitempty"`
	AnchorResult     *STHAnchorResult        `cbor:"anchor_result,omitempty" json:"anchor_result,omitempty"`
	IdentityEvidence []ProofIdentityEvidence `cbor:"identity_evidence,omitempty" json:"identity_evidence,omitempty"`
	ExportedAtUnixN  int64                   `cbor:"exported_at_unix_nano" json:"exported_at_unix_nano"`
}

const (
	ProofIdentityRoleClient = "client"
	ProofIdentityRoleServer = "server"

	CertificateStatusCRL = "crl"
)

// ProofIdentityEvidence carries portable public identity and certificate
// status material. It never establishes trust by itself: offline verifiers
// must bind it to verifier-local public-key, CA, and registry trust roots.
//
// RegistryV2 optionally contains the complete bounded key-registry V2 byte
// stream needed to reconstruct a client's signing-time lifecycle. It is
// evidence, not an embedded registry trust root.
type ProofIdentityEvidence struct {
	SchemaVersion       string                      `cbor:"schema_version" json:"schema_version"`
	CryptoSuite         cryptosuite.ID              `cbor:"crypto_suite" json:"crypto_suite"`
	Role                string                      `cbor:"role" json:"role"`
	KeyID               string                      `cbor:"key_id" json:"key_id"`
	KeyDescriptor       []byte                      `cbor:"key_descriptor" json:"key_descriptor"`
	RegistryV2          []byte                      `cbor:"registry_v2,omitempty" json:"registry_v2,omitempty"`
	CertificateStatuses []CertificateStatusEvidence `cbor:"certificate_statuses,omitempty" json:"certificate_statuses,omitempty"`
}

// CertificateStatusEvidence contains one immutable, signed status object for
// an issuer in a descriptor's leaf-first certificate chain. V1 accepts only a
// strict DER CRL. IssuerFingerprint uses the selected suite's
// KeyFingerprintHash and prevents ambiguous issuer selection.
type CertificateStatusEvidence struct {
	SchemaVersion     string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite       cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	Type              string         `cbor:"type" json:"type"`
	IssuerFingerprint []byte         `cbor:"issuer_fingerprint" json:"issuer_fingerprint"`
	Status            []byte         `cbor:"status" json:"status"`
}

// RecordIndex is the small server-side list/search projection derived from a
// committed ProofBundle. It avoids loading full proof bundles when operators
// or desktop clients need a paginated record list.
type RecordIndex struct {
	SchemaVersion      string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite        cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	RecordID           string         `cbor:"record_id" json:"record_id"`
	NodeID             string         `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID              string         `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	TenantID           string         `cbor:"tenant_id,omitempty" json:"tenant_id,omitempty"`
	ClientID           string         `cbor:"client_id,omitempty" json:"client_id,omitempty"`
	KeyID              string         `cbor:"key_id,omitempty" json:"key_id,omitempty"`
	ProofLevel         string         `cbor:"proof_level,omitempty" json:"proof_level,omitempty"`
	BatchID            string         `cbor:"batch_id,omitempty" json:"batch_id,omitempty"`
	BatchLeafIndex     uint64         `cbor:"batch_leaf_index" json:"batch_leaf_index"`
	BatchClosedAtUnixN int64          `cbor:"batch_closed_at_unix_nano,omitempty" json:"batch_closed_at_unix_nano,omitempty"`
	ReceivedAtUnixN    int64          `cbor:"received_at_unix_nano" json:"received_at_unix_nano"`
	ContentHash        []byte         `cbor:"content_hash,omitempty" json:"content_hash,omitempty"`
	ContentLength      int64          `cbor:"content_length,omitempty" json:"content_length,omitempty"`
	MediaType          string         `cbor:"media_type,omitempty" json:"media_type,omitempty"`
	StorageURI         string         `cbor:"storage_uri,omitempty" json:"storage_uri,omitempty"`
	FileName           string         `cbor:"file_name,omitempty" json:"file_name,omitempty"`
	EventType          string         `cbor:"event_type,omitempty" json:"event_type,omitempty"`
	Source             string         `cbor:"source,omitempty" json:"source,omitempty"`
}

// RecordStatus is the lightweight, real-time projection returned to an
// upstream while a record moves from durable L2 acceptance to a committed
// proof. It deliberately excludes proof material so point and batch lookups
// remain cheap under high concurrency.
type RecordStatus struct {
	SchemaVersion  string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite    cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	RecordID       string         `cbor:"record_id" json:"record_id"`
	TenantID       string         `cbor:"tenant_id,omitempty" json:"tenant_id,omitempty"`
	ClientID       string         `cbor:"client_id,omitempty" json:"client_id,omitempty"`
	KeyID          string         `cbor:"key_id,omitempty" json:"key_id,omitempty"`
	Status         string         `cbor:"status" json:"status"`
	ProofLevel     string         `cbor:"proof_level" json:"proof_level"`
	StatusVersion  uint64         `cbor:"status_version" json:"status_version"`
	BatchID        string         `cbor:"batch_id,omitempty" json:"batch_id,omitempty"`
	UpdatedAtUnixN int64          `cbor:"updated_at_unix_nano" json:"updated_at_unix_nano"`
	Terminal       bool           `cbor:"terminal" json:"terminal"`
	Retryable      bool           `cbor:"retryable,omitempty" json:"retryable,omitempty"`
	FailureCode    string         `cbor:"failure_code,omitempty" json:"failure_code,omitempty"`
}

// UpstreamNotificationRoute is administrator-controlled metadata associated
// with an upstream identity. It is stored in a registry-signed sidecar rather
// than the Key Registry V2 event stream; public subscription APIs may select a
// channel but can never inject or replace its delivery destination.
type UpstreamNotificationRoute struct {
	WebhookURL     string `cbor:"webhook_url,omitempty" json:"webhook_url,omitempty"`
	NATSSubject    string `cbor:"nats_subject,omitempty" json:"nats_subject,omitempty"`
	NATSQueueGroup string `cbor:"nats_queue_group,omitempty" json:"nats_queue_group,omitempty"`
}

func (r UpstreamNotificationRoute) Empty() bool {
	return r.WebhookURL == "" && r.NATSSubject == "" && r.NATSQueueGroup == ""
}

// StatusRefresh is a signed invalidation hint. Receivers always pull the
// current status projection after receiving it; therefore repeated or merged
// notifications are harmless and no historical event queue is required.
type StatusRefresh struct {
	SchemaVersion   string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite     cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	SubscriptionID  string         `cbor:"subscription_id" json:"subscription_id"`
	TenantID        string         `cbor:"tenant_id" json:"tenant_id"`
	ClientID        string         `cbor:"client_id" json:"client_id"`
	Version         uint64         `cbor:"version" json:"version"`
	RefreshRequired bool           `cbor:"refresh_required" json:"refresh_required"`
	EmittedAtUnixN  int64          `cbor:"emitted_at_unix_nano" json:"emitted_at_unix_nano"`
	ServerSig       Signature      `cbor:"server_signature" json:"server_signature"`
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
	Limit          int
	Direction      string
	AfterResultKey STHAnchorResultKey
	HasAfter       bool
}

func RecordIndexFromBundle(bundle ProofBundle) RecordIndex {
	record := bundle.ServerRecord
	if record.RecordID == "" {
		record.RecordID = bundle.RecordID
	}
	idx := RecordIndexFromBatchInputs(
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
	if idx.CryptoSuite == "" {
		idx.CryptoSuite = bundle.CryptoSuite
	}
	return idx
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
		CryptoSuite:        signed.CryptoSuite,
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
	SchemaVersion string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite   cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	BatchID       string         `cbor:"batch_id" json:"batch_id"`
	NodeID        string         `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID         string         `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	BatchRoot     []byte         `cbor:"batch_root" json:"batch_root"`
	TreeSize      uint64         `cbor:"tree_size" json:"tree_size"`
	ClosedAtUnixN int64          `cbor:"closed_at_unix_nano" json:"closed_at_unix_nano"`
}

func (r BatchRoot) TreeAlg() string {
	suite, ok := cryptosuite.Lookup(r.CryptoSuite)
	if !ok {
		return ""
	}
	return suite.Merkle.Algorithm
}

// WALRange is the smallest sequence envelope containing a batch's WAL
// positions. It does not imply that every sequence between From and To belongs
// to the batch; checkpoint code must use the exact committed record positions.
type WALRange struct {
	From WALPosition `cbor:"from" json:"from"`
	To   WALPosition `cbor:"to" json:"to"`
}

// WALCheckpoint stores a recovery boundary inside the WAL. A v2 checkpoint
// certifies that every record through LastSequence belongs to the contiguous
// prefix covered by committed batches, so startup replay may skip it. Legacy
// v1 checkpoints were derived from min/max batch envelopes and must be rebuilt
// before they are trusted. Checkpoints remain best-effort metadata: losing one
// only forces a retained-WAL scan.
type WALCheckpoint struct {
	SchemaVersion   string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite     cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	NodeID          string         `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	WALID           string         `cbor:"wal_id,omitempty" json:"wal_id,omitempty"`
	SegmentID       uint64         `cbor:"segment_id" json:"segment_id"`
	LastSequence    uint64         `cbor:"last_sequence" json:"last_sequence"`
	LastOffset      int64          `cbor:"last_offset" json:"last_offset"`
	BatchID         string         `cbor:"batch_id,omitempty" json:"batch_id,omitempty"`
	RecordedAtUnixN int64          `cbor:"recorded_at_unix_nano" json:"recorded_at_unix_nano"`
}

type BatchManifest struct {
	SchemaVersion          string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite            cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	BatchID                string         `cbor:"batch_id" json:"batch_id"`
	NodeID                 string         `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID                  string         `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	State                  string         `cbor:"state" json:"state"`
	TreeAlg                string         `cbor:"tree_alg" json:"tree_alg"`
	TreeSize               uint64         `cbor:"tree_size" json:"tree_size"`
	BatchRoot              []byte         `cbor:"batch_root" json:"batch_root"`
	RecordIDs              []string       `cbor:"record_ids" json:"record_ids"`
	WALRange               WALRange       `cbor:"wal_range" json:"wal_range"`
	ClosedAtUnixN          int64          `cbor:"closed_at_unix_nano" json:"closed_at_unix_nano"`
	PreparingAtUnixN       int64          `cbor:"preparing_at_unix_nano,omitempty" json:"preparing_at_unix_nano,omitempty"`
	PreparedAtUnixN        int64          `cbor:"prepared_at_unix_nano,omitempty" json:"prepared_at_unix_nano,omitempty"`
	CommittedAtUnixN       int64          `cbor:"committed_at_unix_nano,omitempty" json:"committed_at_unix_nano,omitempty"`
	MaterializeAttempts    int            `cbor:"materialize_attempts,omitempty" json:"materialize_attempts,omitempty"`
	MaterializeNextUnixN   int64          `cbor:"materialize_next_unix_nano,omitempty" json:"materialize_next_unix_nano,omitempty"`
	MaterializeLastError   string         `cbor:"materialize_last_error,omitempty" json:"materialize_last_error,omitempty"`
	MaterializeFailureCode string         `cbor:"materialize_failure_code,omitempty" json:"materialize_failure_code,omitempty"`
}

// BatchTreeLeaf is a lightweight projection for browsing a batch Merkle tree.
// It intentionally stores only the record binding and leaf hash so API callers
// can page through huge batches without loading full proof bundles.
type BatchTreeLeaf struct {
	SchemaVersion  string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite    cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	BatchID        string         `cbor:"batch_id" json:"batch_id"`
	RecordID       string         `cbor:"record_id" json:"record_id"`
	LeafIndex      uint64         `cbor:"leaf_index" json:"leaf_index"`
	LeafHash       []byte         `cbor:"leaf_hash" json:"leaf_hash"`
	CreatedAtUnixN int64          `cbor:"created_at_unix_nano" json:"created_at_unix_nano"`
}

// BatchTreeNode stores complete Merkle subtrees for one batch. The pair
// (level,start_index) is ordered for range scans; width is usually 2^level
// except for right-edge RFC6962 subtrees in non-power-of-two batches.
type BatchTreeNode struct {
	SchemaVersion  string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite    cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	BatchID        string         `cbor:"batch_id" json:"batch_id"`
	Level          uint64         `cbor:"level" json:"level"`
	StartIndex     uint64         `cbor:"start_index" json:"start_index"`
	Width          uint64         `cbor:"width" json:"width"`
	Hash           []byte         `cbor:"hash" json:"hash"`
	CreatedAtUnixN int64          `cbor:"created_at_unix_nano" json:"created_at_unix_nano"`
}

// GlobalLogLeaf is the append-only global transparency log item for one
// committed batch. L4 proofs show that a batch leaf is included in a
// SignedTreeHead.
type GlobalLogLeaf struct {
	SchemaVersion      string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite        cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	NodeID             string         `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID              string         `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	BatchID            string         `cbor:"batch_id" json:"batch_id"`
	BatchRoot          []byte         `cbor:"batch_root" json:"batch_root"`
	BatchTreeSize      uint64         `cbor:"batch_tree_size" json:"batch_tree_size"`
	BatchClosedAtUnixN int64          `cbor:"batch_closed_at_unix_nano" json:"batch_closed_at_unix_nano"`
	LeafIndex          uint64         `cbor:"leaf_index" json:"leaf_index"`
	LeafHash           []byte         `cbor:"leaf_hash" json:"leaf_hash"`
	AppendedAtUnixN    int64          `cbor:"appended_at_unix_nano" json:"appended_at_unix_nano"`
}

// GlobalLogNode stores the hash for a complete, power-of-two sized subtree
// in the global log. Nodes make STH append/proof generation read O(log N)
// indexed hashes instead of rebuilding from every historical leaf.
type GlobalLogNode struct {
	SchemaVersion  string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite    cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	Level          uint64         `cbor:"level" json:"level"`
	StartIndex     uint64         `cbor:"start_index" json:"start_index"`
	Width          uint64         `cbor:"width" json:"width"`
	Hash           []byte         `cbor:"hash" json:"hash"`
	CreatedAtUnixN int64          `cbor:"created_at_unix_nano" json:"created_at_unix_nano"`
}

// GlobalLogState is the latest append frontier for the global transparency
// log. Frontier[level] is the root of the rightmost complete subtree of
// width 2^level when that level is present in TreeSize's binary form.
type GlobalLogState struct {
	SchemaVersion  string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite    cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	TreeSize       uint64         `cbor:"tree_size" json:"tree_size"`
	RootHash       []byte         `cbor:"root_hash,omitempty" json:"root_hash,omitempty"`
	Frontier       [][]byte       `cbor:"frontier" json:"frontier"`
	UpdatedAtUnixN int64          `cbor:"updated_at_unix_nano" json:"updated_at_unix_nano"`
}

// SignedTreeHead is the global log root after TreeSize leaves. L5 anchors
// publish this structure's RootHash, never a per-batch root.
type SignedTreeHead struct {
	SchemaVersion  string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite    cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	TreeAlg        string         `cbor:"tree_alg" json:"tree_alg"`
	TreeSize       uint64         `cbor:"tree_size" json:"tree_size"`
	RootHash       []byte         `cbor:"root_hash" json:"root_hash"`
	TimestampUnixN int64          `cbor:"timestamp_unix_nano" json:"timestamp_unix_nano"`
	NodeID         string         `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID          string         `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	Signature      Signature      `cbor:"signature" json:"signature"`
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
	CryptoSuite   cryptosuite.ID         `cbor:"crypto_suite" json:"crypto_suite"`
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

// GlobalLogEvidence is the strongest currently available Global Log evidence
// for one batch. When AnchorResult is present, GlobalProof is generated
// directly against the exact SignedTreeHead carried by that result. When no
// published anchor covers the batch yet, AnchorResult is nil and GlobalProof
// targets the latest STH so callers can still export an L4 proof.
type GlobalLogEvidence struct {
	GlobalProof  GlobalLogProof   `cbor:"global_proof" json:"global_proof"`
	AnchorResult *STHAnchorResult `cbor:"anchor_result,omitempty" json:"anchor_result,omitempty"`
}

// GlobalLogTile is a compacted immutable range of global log leaf hashes.
// The first implementation stores deterministic CBOR tiles so old proofs can
// be restored without keeping every hot in-memory node forever.
type GlobalLogTile struct {
	SchemaVersion  string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite    cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	Level          uint64         `cbor:"level" json:"level"`
	StartIndex     uint64         `cbor:"start_index" json:"start_index"`
	Width          uint64         `cbor:"width" json:"width"`
	Hashes         [][]byte       `cbor:"hashes" json:"hashes"`
	Compressed     bool           `cbor:"compressed" json:"compressed"`
	CreatedAtUnixN int64          `cbor:"created_at_unix_nano" json:"created_at_unix_nano"`
}

// GlobalLogOutboxItem decouples batch commit from global-log append. A batch
// worker only persists this item; a separate worker appends the batch root,
// creates the STH, and coalesces the batch's final STH into anchor state.
type GlobalLogOutboxItem struct {
	SchemaVersion    string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite      cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
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
	TenantID           string         `cbor:"tenant_id" json:"tenant_id"`
	ClientID           string         `cbor:"client_id" json:"client_id"`
	KeyID              string         `cbor:"key_id" json:"key_id"`
	CryptoSuite        cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	Alg                string         `cbor:"alg" json:"alg"`
	PublicKeyEncoding  string         `cbor:"public_key_encoding" json:"public_key_encoding"`
	PublicKey          []byte         `cbor:"public_key" json:"public_key"`
	SM2UserID          string         `cbor:"sm2_user_id,omitempty" json:"sm2_user_id,omitempty"`
	CertificateChain   [][]byte       `cbor:"certificate_chain,omitempty" json:"certificate_chain,omitempty"`
	Provider           string         `cbor:"provider" json:"provider"`
	KeyDescriptor      []byte         `cbor:"key_descriptor" json:"key_descriptor"`
	ValidFromUnixN     int64          `cbor:"valid_from_unix_nano" json:"valid_from_unix_nano"`
	ValidUntilUnixN    int64          `cbor:"valid_until_unix_nano,omitempty" json:"valid_until_unix_nano,omitempty"`
	Status             string         `cbor:"status" json:"status"`
	RevokedAtUnixN     int64          `cbor:"revoked_at_unix_nano,omitempty" json:"revoked_at_unix_nano,omitempty"`
	CompromisedAtUnixN int64          `cbor:"compromised_at_unix_nano,omitempty" json:"compromised_at_unix_nano,omitempty"`
}

// STHAnchorResult records a successful external publication of an STH/global
// root. AnchorID identifies the external artefact and Proof is sink-specific.
type STHAnchorResult struct {
	SchemaVersion    string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite      cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	NodeID           string         `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID            string         `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	TreeSize         uint64         `cbor:"tree_size" json:"tree_size"`
	SinkName         string         `cbor:"sink_name" json:"sink_name"`
	AnchorID         string         `cbor:"anchor_id" json:"anchor_id"`
	RootHash         []byte         `cbor:"root_hash" json:"root_hash"`
	STH              SignedTreeHead `cbor:"sth" json:"sth"`
	Proof            []byte         `cbor:"proof,omitempty" json:"proof,omitempty"`
	EvidenceStage    string         `cbor:"evidence_stage,omitempty" json:"evidence_stage,omitempty"`
	PublishedAtUnixN int64          `cbor:"published_at_unix_nano" json:"published_at_unix_nano"`
}

// AnchorResultProvidesOfflineL5 is the only allowed bridge from an immutable
// external result to TrustDB's L5 projection. This is intentionally an
// allowlist: empty, unknown, and raw observation stages must all fail closed.
func AnchorResultProvidesOfflineL5(result STHAnchorResult) bool {
	// These stable wire sink names are local test/development backends, not
	// independent witnesses. Reject them even if a corrupt store or plugin
	// forges evidence_stage=offline_verified.
	switch result.SinkName {
	case "file", "noop":
		return false
	}
	return result.EvidenceStage == AnchorEvidenceStageOfflineVerified
}

func ValidAnchorEvidenceStage(stage string) bool {
	return stage == AnchorEvidenceStageOfflineVerified ||
		stage == AnchorEvidenceStageRaw ||
		stage == AnchorEvidenceStageLocalOnly
}

// STHAnchorResultKey is the immutable storage identity of one sink-specific
// publication. TreeSize alone is not unique when a log is anchored through
// more than one provider.
type STHAnchorResultKey struct {
	NodeID   string `cbor:"node_id" json:"node_id"`
	LogID    string `cbor:"log_id" json:"log_id"`
	SinkName string `cbor:"sink_name" json:"sink_name"`
	TreeSize uint64 `cbor:"tree_size" json:"tree_size"`
}

// STHAnchorLatestReference is derived, rebuildable state. RootHash and
// AnchorID fence a corrupted or stale pointer from silently selecting a
// different immutable result at the same key.
type STHAnchorLatestReference struct {
	SchemaVersion string             `cbor:"schema_version" json:"schema_version"`
	CryptoSuite   cryptosuite.ID     `cbor:"crypto_suite" json:"crypto_suite"`
	Key           STHAnchorResultKey `cbor:"key" json:"key"`
	RootHash      []byte             `cbor:"root_hash" json:"root_hash"`
	AnchorID      string             `cbor:"anchor_id" json:"anchor_id"`
}

// STHAnchorScheduleKey scopes one constant-space anchor scheduler. Current
// deployments use one global log and sink, while the tuple keeps the durable
// format safe for multiple logs or providers.
type STHAnchorScheduleKey struct {
	NodeID   string `cbor:"node_id,omitempty" json:"node_id,omitempty"`
	LogID    string `cbor:"log_id,omitempty" json:"log_id,omitempty"`
	SinkName string `cbor:"sink_name" json:"sink_name"`
}

// STHAnchorCandidate is the observation submitted by the Global Log
// publisher. DueAtUnixN is computed once from the first observation and is
// preserved when later STHs replace the pending target.
type STHAnchorCandidate struct {
	Key             STHAnchorScheduleKey `cbor:"key" json:"key"`
	STH             SignedTreeHead       `cbor:"sth" json:"sth"`
	ObservedAtUnixN int64                `cbor:"observed_at_unix_nano" json:"observed_at_unix_nano"`
	DueAtUnixN      int64                `cbor:"due_at_unix_nano" json:"due_at_unix_nano"`
}

type STHAnchorWindow struct {
	Generation     uint64         `cbor:"generation" json:"generation"`
	Target         SignedTreeHead `cbor:"target" json:"target"`
	OpenedAtUnixN  int64          `cbor:"opened_at_unix_nano" json:"opened_at_unix_nano"`
	DueAtUnixN     int64          `cbor:"due_at_unix_nano" json:"due_at_unix_nano"`
	UpdatedAtUnixN int64          `cbor:"updated_at_unix_nano" json:"updated_at_unix_nano"`
}

type STHAnchorAttempt struct {
	Generation       uint64         `cbor:"generation" json:"generation"`
	Target           SignedTreeHead `cbor:"target" json:"target"`
	OpenedAtUnixN    int64          `cbor:"opened_at_unix_nano" json:"opened_at_unix_nano"`
	DueAtUnixN       int64          `cbor:"due_at_unix_nano" json:"due_at_unix_nano"`
	Attempts         int            `cbor:"attempts" json:"attempts"`
	NextAttemptUnixN int64          `cbor:"next_attempt_unix_nano,omitempty" json:"next_attempt_unix_nano,omitempty"`
	LastAttemptUnixN int64          `cbor:"last_attempt_unix_nano,omitempty" json:"last_attempt_unix_nano,omitempty"`
	LastErrorMessage string         `cbor:"last_error_message,omitempty" json:"last_error_message,omitempty"`
	TerminalFailure  bool           `cbor:"terminal_failure,omitempty" json:"terminal_failure,omitempty"`
	LeaseOwner       string         `cbor:"lease_owner,omitempty" json:"lease_owner,omitempty"`
	LeaseToken       string         `cbor:"lease_token,omitempty" json:"lease_token,omitempty"`
	LeaseUntilUnixN  int64          `cbor:"lease_until_unix_nano,omitempty" json:"lease_until_unix_nano,omitempty"`
}

// STHAnchorSchedule contains at most one pending coalescing window and one
// immutable in-flight target. Revision protects read/modify/write transitions;
// Generation identifies work even while Pending changes concurrently.
type STHAnchorSchedule struct {
	SchemaVersion  string               `cbor:"schema_version" json:"schema_version"`
	CryptoSuite    cryptosuite.ID       `cbor:"crypto_suite" json:"crypto_suite"`
	Key            STHAnchorScheduleKey `cbor:"key" json:"key"`
	Revision       uint64               `cbor:"revision" json:"revision"`
	NextGeneration uint64               `cbor:"next_generation" json:"next_generation"`
	Pending        *STHAnchorWindow     `cbor:"pending,omitempty" json:"pending,omitempty"`
	InFlight       *STHAnchorAttempt    `cbor:"in_flight,omitempty" json:"in_flight,omitempty"`
}

// L5CoverageCheckpoint is derived, rebuildable projection state. Every
// Global Log leaf with index less than CoveredTreeSize has had its batch and
// record indexes durably promoted to L5 for Key's anchor stream.
type L5CoverageCheckpoint struct {
	SchemaVersion   string               `cbor:"schema_version" json:"schema_version"`
	CryptoSuite     cryptosuite.ID       `cbor:"crypto_suite" json:"crypto_suite"`
	Key             STHAnchorScheduleKey `cbor:"key" json:"key"`
	CoveredTreeSize uint64               `cbor:"covered_tree_size" json:"covered_tree_size"`
	Revision        uint64               `cbor:"revision" json:"revision"`
	UpdatedAtUnixN  int64                `cbor:"updated_at_unix_nano" json:"updated_at_unix_nano"`
}

type KeyEvent struct {
	SchemaVersion      string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite        cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	Sequence           uint64         `cbor:"sequence" json:"sequence"`
	Type               string         `cbor:"type" json:"type"`
	TenantID           string         `cbor:"tenant_id" json:"tenant_id"`
	ClientID           string         `cbor:"client_id" json:"client_id"`
	KeyID              string         `cbor:"key_id" json:"key_id"`
	PreviousKeyID      string         `cbor:"previous_key_id,omitempty" json:"previous_key_id,omitempty"`
	KeyDescriptor      []byte         `cbor:"key_descriptor,omitempty" json:"key_descriptor,omitempty"`
	ValidFromUnixN     int64          `cbor:"valid_from_unix_nano,omitempty" json:"valid_from_unix_nano,omitempty"`
	ValidUntilUnixN    int64          `cbor:"valid_until_unix_nano,omitempty" json:"valid_until_unix_nano,omitempty"`
	RotatedAtUnixN     int64          `cbor:"rotated_at_unix_nano,omitempty" json:"rotated_at_unix_nano,omitempty"`
	RevokedAtUnixN     int64          `cbor:"revoked_at_unix_nano,omitempty" json:"revoked_at_unix_nano,omitempty"`
	CompromisedAtUnixN int64          `cbor:"compromised_at_unix_nano,omitempty" json:"compromised_at_unix_nano,omitempty"`
	Reason             string         `cbor:"reason,omitempty" json:"reason,omitempty"`
	PrevEventHash      []byte         `cbor:"prev_event_hash,omitempty" json:"prev_event_hash,omitempty"`
	EventHash          []byte         `cbor:"event_hash" json:"event_hash"`
	RegistrySignature  Signature      `cbor:"registry_signature" json:"registry_signature"`
}
