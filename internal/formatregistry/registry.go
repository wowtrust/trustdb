// Package formatregistry defines TrustDB's immutable format generations and
// migration boundaries. It is a design registry: reserved generations are
// discoverable for implementation and conformance work, but cannot be used by
// production writers until their descriptors become available.
package formatregistry

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
)

type Family string

const (
	FamilyModel       Family = "model"
	FamilySingleProof Family = "single-proof"
	FamilyBackup      Family = "backup"
	FamilyWAL         Family = "wal"
	FamilyProofstore  Family = "proofstore"
	FamilyHTTP        Family = "http"
	FamilyGRPC        Family = "grpc"
	FamilySDK         Family = "sdk"
)

type Availability string

const (
	AvailabilityAvailable Availability = "available"
	AvailabilityReserved  Availability = "reserved"
)

type MigrationPolicy string

const (
	MigrationImmutableArtifact MigrationPolicy = "immutable-artifact"
	MigrationFreshNamespace    MigrationPolicy = "fresh-namespace"
	MigrationParallelEndpoint  MigrationPolicy = "parallel-endpoint"
)

const (
	EncodingDeterministicCBOR = "cbor-core-deterministic-rfc8949"
	EncodingBackupArchiveV4   = "pax-tar+json-manifest+deterministic-cbor-entries"
	EncodingBackupArchiveV5   = "pax-tar+deterministic-cbor-manifest-and-entries"
	EncodingWALFrames         = "trustdb-wal-frames+deterministic-cbor-payload"
	EncodingProofstore        = "backend-native-keys+deterministic-cbor-values"
	EncodingHTTPCBOR          = "http+application-cbor"
	EncodingGRPCCBOR          = "grpc+trustdb-cbor"
	EncodingGoSDKCBOR         = "go-models+deterministic-cbor"
)

const (
	ModelV1       = "trustdb.model-generation.v1"
	ModelV2       = "trustdb.model-generation.v2"
	SingleProofV1 = "trustdb.sproof.v1"
	SingleProofV2 = "trustdb.sproof.v2"
	BackupV4      = "trustdb.backup.v4"
	BackupV5      = "trustdb.backup.v5"
	WALV1         = "trustdb.wal.v1"
	WALV2         = "trustdb.wal.v2"
	ProofstoreV4  = "trustdb-proofstore-v4"
	ProofstoreV5  = "trustdb-proofstore-v5"
	HTTPV1        = "trustdb.http.v1"
	HTTPV2        = "trustdb.http.v2"
	GRPCV1        = "trustdb.v1.TrustDB"
	GRPCV2        = "trustdb.v2.TrustDB"
	SDKV1         = "trustdb.sdk-model.v1"
	SDKV2         = "trustdb.sdk-model.v2"

	RegistryManifestV1 = "trustdb.format-registry.v1"
)

// Evidence and transport limits for the crypto-agile generation. Limits are
// applied before certificate, BCOS, CBOR, or signature parsing so hostile
// evidence cannot force unbounded allocation or verification work.
const (
	MaxCertificateCountV2            = 16
	MaxCertificateBytesV2            = 128 << 10
	MaxCertificateChainBytesV2       = 1 << 20
	MaxBCOSReceiptProofBytesV2       = 4 << 20
	MaxBCOSFinalityBytesV2           = 8 << 20
	MaxAnchorEvidenceBytesV2         = 16 << 20
	MaxSingleProofBytesV2            = 24 << 20
	MaxTransportMessageBytesV2       = 32 << 20
	MaxStoredObjectBytesV2           = 64 << 20
	MaxBackupEntryBytesV2      int64 = 128 << 20
)

type Descriptor struct {
	Family               Family           `cbor:"family" json:"family"`
	Identifier           string           `cbor:"identifier" json:"identifier"`
	Version              uint16           `cbor:"version" json:"version"`
	Availability         Availability     `cbor:"availability" json:"availability"`
	CanonicalEncoding    string           `cbor:"canonical_encoding" json:"canonical_encoding"`
	AllowedSuites        []cryptosuite.ID `cbor:"allowed_suites" json:"allowed_suites"`
	SuiteField           string           `cbor:"suite_field,omitempty" json:"suite_field,omitempty"`
	RejectUnknownFields  bool             `cbor:"reject_unknown_fields" json:"reject_unknown_fields"`
	RejectUnknownSuites  bool             `cbor:"reject_unknown_suites" json:"reject_unknown_suites"`
	RejectUnknownEntries bool             `cbor:"reject_unknown_entries" json:"reject_unknown_entries"`
	Migration            MigrationPolicy  `cbor:"migration" json:"migration"`
	MaxBytes             int64            `cbor:"max_bytes" json:"max_bytes"`
}

var registry = map[string]Descriptor{
	ModelV1: descriptor(FamilyModel, ModelV1, 1, AvailabilityAvailable, EncodingDeterministicCBOR, []cryptosuite.ID{cryptosuite.INTLV1}, "", MigrationFreshNamespace, 0),
	ModelV2: descriptor(FamilyModel, ModelV2, 2, AvailabilityReserved, EncodingDeterministicCBOR, []cryptosuite.ID{cryptosuite.CNSMV1, cryptosuite.INTLV1}, "crypto_suite", MigrationFreshNamespace, MaxStoredObjectBytesV2),

	SingleProofV1: descriptor(FamilySingleProof, SingleProofV1, 1, AvailabilityAvailable, EncodingDeterministicCBOR, []cryptosuite.ID{cryptosuite.INTLV1}, "", MigrationImmutableArtifact, 16<<20),
	SingleProofV2: descriptor(FamilySingleProof, SingleProofV2, 2, AvailabilityReserved, EncodingDeterministicCBOR, []cryptosuite.ID{cryptosuite.CNSMV1, cryptosuite.INTLV1}, "crypto_suite", MigrationImmutableArtifact, MaxSingleProofBytesV2),

	BackupV4: descriptorWithStrictness(FamilyBackup, BackupV4, 4, AvailabilityAvailable, EncodingBackupArchiveV4, []cryptosuite.ID{cryptosuite.INTLV1}, "", MigrationFreshNamespace, 128<<20, false, false),
	BackupV5: descriptorWithStrictness(FamilyBackup, BackupV5, 5, AvailabilityReserved, EncodingBackupArchiveV5, []cryptosuite.ID{cryptosuite.CNSMV1, cryptosuite.INTLV1}, "crypto_suite", MigrationFreshNamespace, MaxBackupEntryBytesV2, true, true),

	WALV1: descriptor(FamilyWAL, WALV1, 1, AvailabilityAvailable, EncodingWALFrames, []cryptosuite.ID{cryptosuite.INTLV1}, "", MigrationFreshNamespace, 0),
	WALV2: descriptor(FamilyWAL, WALV2, 2, AvailabilityReserved, EncodingWALFrames, []cryptosuite.ID{cryptosuite.CNSMV1, cryptosuite.INTLV1}, "crypto_suite", MigrationFreshNamespace, MaxStoredObjectBytesV2),

	ProofstoreV4: descriptor(FamilyProofstore, ProofstoreV4, 4, AvailabilityAvailable, EncodingProofstore, []cryptosuite.ID{cryptosuite.INTLV1}, "", MigrationFreshNamespace, 64<<20),
	ProofstoreV5: descriptor(FamilyProofstore, ProofstoreV5, 5, AvailabilityReserved, EncodingProofstore, []cryptosuite.ID{cryptosuite.CNSMV1, cryptosuite.INTLV1}, "crypto_suite", MigrationFreshNamespace, MaxStoredObjectBytesV2),

	HTTPV1: descriptor(FamilyHTTP, HTTPV1, 1, AvailabilityAvailable, EncodingHTTPCBOR, []cryptosuite.ID{cryptosuite.INTLV1}, "", MigrationParallelEndpoint, 16<<20),
	HTTPV2: descriptor(FamilyHTTP, HTTPV2, 2, AvailabilityReserved, EncodingHTTPCBOR, []cryptosuite.ID{cryptosuite.CNSMV1, cryptosuite.INTLV1}, "crypto_suite", MigrationParallelEndpoint, MaxTransportMessageBytesV2),

	GRPCV1: descriptor(FamilyGRPC, GRPCV1, 1, AvailabilityAvailable, EncodingGRPCCBOR, []cryptosuite.ID{cryptosuite.INTLV1}, "", MigrationParallelEndpoint, 16<<20),
	GRPCV2: descriptor(FamilyGRPC, GRPCV2, 2, AvailabilityReserved, EncodingGRPCCBOR, []cryptosuite.ID{cryptosuite.CNSMV1, cryptosuite.INTLV1}, "crypto_suite", MigrationParallelEndpoint, MaxTransportMessageBytesV2),

	SDKV1: descriptor(FamilySDK, SDKV1, 1, AvailabilityAvailable, EncodingGoSDKCBOR, []cryptosuite.ID{cryptosuite.INTLV1}, "", MigrationParallelEndpoint, 16<<20),
	SDKV2: descriptor(FamilySDK, SDKV2, 2, AvailabilityReserved, EncodingGoSDKCBOR, []cryptosuite.ID{cryptosuite.CNSMV1, cryptosuite.INTLV1}, "crypto_suite", MigrationParallelEndpoint, MaxTransportMessageBytesV2),
}

func descriptor(
	family Family,
	identifier string,
	version uint16,
	availability Availability,
	encoding string,
	suites []cryptosuite.ID,
	suiteField string,
	migration MigrationPolicy,
	maxBytes int64,
) Descriptor {
	return descriptorWithStrictness(family, identifier, version, availability, encoding, suites, suiteField, migration, maxBytes, true, true)
}

func descriptorWithStrictness(
	family Family,
	identifier string,
	version uint16,
	availability Availability,
	encoding string,
	suites []cryptosuite.ID,
	suiteField string,
	migration MigrationPolicy,
	maxBytes int64,
	rejectUnknownFields bool,
	rejectUnknownEntries bool,
) Descriptor {
	return Descriptor{
		Family:               family,
		Identifier:           identifier,
		Version:              version,
		Availability:         availability,
		CanonicalEncoding:    encoding,
		AllowedSuites:        suites,
		SuiteField:           suiteField,
		RejectUnknownFields:  rejectUnknownFields,
		RejectUnknownSuites:  true,
		RejectUnknownEntries: rejectUnknownEntries,
		Migration:            migration,
		MaxBytes:             maxBytes,
	}
}

var modelSchemas = []SchemaTransition{
	{Artifact: "accepted_receipt", Current: "trustdb.accepted-receipt.v1", Next: "trustdb.accepted-receipt.v2"},
	{Artifact: "batch_manifest", Current: "trustdb.batch-manifest.v1", Next: "trustdb.batch-manifest.v2"},
	{Artifact: "batch_root", Current: "trustdb.batch-root.v1", Next: "trustdb.batch-root.v2"},
	{Artifact: "batch_tree_leaf", Current: "trustdb.batch-tree-leaf.v1", Next: "trustdb.batch-tree-leaf.v2"},
	{Artifact: "batch_tree_node", Current: "trustdb.batch-tree-node.v1", Next: "trustdb.batch-tree-node.v2"},
	{Artifact: "client_claim", Current: "trustdb.claim.v1", Next: "trustdb.claim.v2"},
	{Artifact: "committed_receipt", Current: "trustdb.committed-receipt.v1", Next: "trustdb.committed-receipt.v2"},
	{Artifact: "global_log_leaf", Current: "trustdb.global-log-leaf.v1", Next: "trustdb.global-log-leaf.v2"},
	{Artifact: "global_log_node", Current: "trustdb.global-log-node.v1", Next: "trustdb.global-log-node.v2"},
	{Artifact: "global_log_outbox", Current: "trustdb.global-log-outbox.v1", Next: "trustdb.global-log-outbox.v2"},
	{Artifact: "global_log_proof", Current: "trustdb.global-log-proof.v1", Next: "trustdb.global-log-proof.v2"},
	{Artifact: "global_log_state", Current: "trustdb.global-log-state.v1", Next: "trustdb.global-log-state.v2"},
	{Artifact: "global_log_tile", Current: "trustdb.global-log-tile.v1", Next: "trustdb.global-log-tile.v2"},
	{Artifact: "idempotency_decision", Current: "trustdb.idempotency-decision.v1", Next: "trustdb.idempotency-decision.v2"},
	{Artifact: "key_event", Current: "trustdb.key-event.v1", Next: "trustdb.key-event.v2"},
	{Artifact: "l5_coverage_checkpoint", Current: "trustdb.l5-coverage-checkpoint.v1", Next: "trustdb.l5-coverage-checkpoint.v2"},
	{Artifact: "proof_bundle", Current: "trustdb.proof-bundle.v1", Next: "trustdb.proof-bundle.v2"},
	{Artifact: "record_index", Current: "trustdb.record-index.v1", Next: "trustdb.record-index.v2"},
	{Artifact: "server_record", Current: "trustdb.server-record.v1", Next: "trustdb.server-record.v2"},
	{Artifact: "signed_claim", Current: "trustdb.signed-claim.v1", Next: "trustdb.signed-claim.v2"},
	{Artifact: "signed_tree_head", Current: "trustdb.signed-tree-head.v1", Next: "trustdb.signed-tree-head.v2"},
	{Artifact: "sth_anchor_latest", Current: "trustdb.sth-anchor-latest.v1", Next: "trustdb.sth-anchor-latest.v2"},
	{Artifact: "sth_anchor_latest_empty", Current: "trustdb.sth-anchor-latest-empty.v1", Next: "trustdb.sth-anchor-latest-empty.v2"},
	{Artifact: "sth_anchor_result", Current: "trustdb.sth-anchor-result.v1", Next: "trustdb.sth-anchor-result.v2"},
	{Artifact: "sth_anchor_schedule", Current: "trustdb.sth-anchor-schedule.v1", Next: "trustdb.sth-anchor-schedule.v2"},
	{Artifact: "wal_checkpoint", Current: "trustdb.wal-checkpoint.v2", Next: "trustdb.wal-checkpoint.v3"},
}

type SchemaTransition struct {
	Artifact string `cbor:"artifact" json:"artifact"`
	Current  string `cbor:"current" json:"current"`
	Next     string `cbor:"next" json:"next"`
}

type EvidenceLimits struct {
	CertificateCount      int   `cbor:"certificate_count" json:"certificate_count"`
	CertificateBytes      int   `cbor:"certificate_bytes" json:"certificate_bytes"`
	CertificateChainBytes int   `cbor:"certificate_chain_bytes" json:"certificate_chain_bytes"`
	BCOSReceiptProofBytes int   `cbor:"bcos_receipt_proof_bytes" json:"bcos_receipt_proof_bytes"`
	BCOSFinalityBytes     int   `cbor:"bcos_finality_bytes" json:"bcos_finality_bytes"`
	AnchorEvidenceBytes   int   `cbor:"anchor_evidence_bytes" json:"anchor_evidence_bytes"`
	SingleProofBytes      int   `cbor:"single_proof_bytes" json:"single_proof_bytes"`
	TransportMessageBytes int   `cbor:"transport_message_bytes" json:"transport_message_bytes"`
	StoredObjectBytes     int   `cbor:"stored_object_bytes" json:"stored_object_bytes"`
	BackupEntryBytes      int64 `cbor:"backup_entry_bytes" json:"backup_entry_bytes"`
}

type RegistryManifest struct {
	SchemaVersion string             `cbor:"schema_version" json:"schema_version"`
	Formats       []Descriptor       `cbor:"formats" json:"formats"`
	ModelSchemas  []SchemaTransition `cbor:"model_schemas" json:"model_schemas"`
	Limits        EvidenceLimits     `cbor:"limits" json:"limits"`
}

var (
	ErrUnknownFormat        = errors.New("unknown format")
	ErrUnavailableFormat    = errors.New("format is not available")
	ErrSuiteNotAllowed      = errors.New("cryptographic suite is not allowed by format")
	ErrFormatNamespaceReuse = errors.New("format generation change reuses a log or storage namespace")
	ErrUnboundNonEmptyData  = errors.New("non-empty data has no format binding")
)

func Lookup(identifier string) (Descriptor, bool) {
	descriptor, ok := registry[identifier]
	return cloneDescriptor(descriptor), ok
}

func All() []Descriptor {
	identifiers := make([]string, 0, len(registry))
	for identifier := range registry {
		identifiers = append(identifiers, identifier)
	}
	sort.Strings(identifiers)
	out := make([]Descriptor, 0, len(identifiers))
	for _, identifier := range identifiers {
		out = append(out, cloneDescriptor(registry[identifier]))
	}
	return out
}

func ModelSchemas() []SchemaTransition {
	out := make([]SchemaTransition, len(modelSchemas))
	copy(out, modelSchemas)
	return out
}

// Snapshot returns a deterministic, map-free representation suitable for
// canonical CBOR golden vectors and design review tooling.
func Snapshot() RegistryManifest {
	return RegistryManifest{
		SchemaVersion: RegistryManifestV1,
		Formats:       All(),
		ModelSchemas:  ModelSchemas(),
		Limits: EvidenceLimits{
			CertificateCount:      MaxCertificateCountV2,
			CertificateBytes:      MaxCertificateBytesV2,
			CertificateChainBytes: MaxCertificateChainBytesV2,
			BCOSReceiptProofBytes: MaxBCOSReceiptProofBytesV2,
			BCOSFinalityBytes:     MaxBCOSFinalityBytesV2,
			AnchorEvidenceBytes:   MaxAnchorEvidenceBytesV2,
			SingleProofBytes:      MaxSingleProofBytesV2,
			TransportMessageBytes: MaxTransportMessageBytesV2,
			StoredObjectBytes:     MaxStoredObjectBytesV2,
			BackupEntryBytes:      MaxBackupEntryBytesV2,
		},
	}
}

func RequireKnown(identifier string) (Descriptor, error) {
	descriptor, ok := Lookup(identifier)
	if !ok {
		return Descriptor{}, fmt.Errorf("%w: %q", ErrUnknownFormat, identifier)
	}
	return descriptor, nil
}

// RequireAvailable is the production writer/startup gate. Reserved formats
// remain visible to conformance tests and implementation planning only.
func RequireAvailable(identifier string) (Descriptor, error) {
	descriptor, err := RequireKnown(identifier)
	if err != nil {
		return Descriptor{}, err
	}
	if descriptor.Availability != AvailabilityAvailable {
		return Descriptor{}, fmt.Errorf("%w: %s is %s", ErrUnavailableFormat, identifier, descriptor.Availability)
	}
	return descriptor, nil
}

// RequireSuite rejects empty, unknown, or disallowed suite identifiers. It
// does not enable a reserved suite; production writers must additionally call
// cryptosuite.RequireAvailable.
func RequireSuite(identifier string, suiteID cryptosuite.ID) error {
	descriptor, err := RequireKnown(identifier)
	if err != nil {
		return err
	}
	if _, err := cryptosuite.RequireKnown(suiteID); err != nil {
		return err
	}
	for _, allowed := range descriptor.AllowedSuites {
		if suiteID == allowed {
			return nil
		}
	}
	return fmt.Errorf("%w: format=%s suite=%s", ErrSuiteNotAllowed, identifier, suiteID)
}

// RequireWritable combines the format and cryptographic-suite production
// gates. Today only current INTL_V1 formats pass this function.
func RequireWritable(identifier string, suiteID cryptosuite.ID) (Descriptor, cryptosuite.Suite, error) {
	descriptor, err := RequireAvailable(identifier)
	if err != nil {
		return Descriptor{}, cryptosuite.Suite{}, err
	}
	if err := RequireSuite(identifier, suiteID); err != nil {
		return Descriptor{}, cryptosuite.Suite{}, err
	}
	suite, err := cryptosuite.RequireAvailable(suiteID)
	if err != nil {
		return Descriptor{}, cryptosuite.Suite{}, err
	}
	return descriptor, suite, nil
}

type NamespaceBinding struct {
	FormatIdentifier string
	LogID            string
	StorageNamespace string
	NonEmpty         bool
}

// ValidateNamespaceTransition requires a new LogID and storage namespace when
// the format identifier changes. It validates transition shape, not whether a
// reserved target is ready for production writes.
func ValidateNamespaceTransition(current, next NamespaceBinding) error {
	if _, err := RequireKnown(next.FormatIdentifier); err != nil {
		return fmt.Errorf("next binding: %w", err)
	}
	if strings.TrimSpace(next.LogID) == "" {
		return errors.New("next binding log_id is required")
	}
	if strings.TrimSpace(next.StorageNamespace) == "" {
		return errors.New("next binding storage namespace is required")
	}
	if current.FormatIdentifier == "" {
		if current.NonEmpty {
			return ErrUnboundNonEmptyData
		}
		return nil
	}
	if _, err := RequireKnown(current.FormatIdentifier); err != nil {
		return fmt.Errorf("current binding: %w", err)
	}
	if current.FormatIdentifier == next.FormatIdentifier {
		return nil
	}
	if strings.TrimSpace(current.LogID) == strings.TrimSpace(next.LogID) {
		return fmt.Errorf("%w: log_id %q", ErrFormatNamespaceReuse, next.LogID)
	}
	if strings.TrimSpace(current.StorageNamespace) == strings.TrimSpace(next.StorageNamespace) {
		return fmt.Errorf("%w: storage namespace %q", ErrFormatNamespaceReuse, next.StorageNamespace)
	}
	return nil
}

func cloneDescriptor(descriptor Descriptor) Descriptor {
	descriptor.AllowedSuites = append([]cryptosuite.ID(nil), descriptor.AllowedSuites...)
	return descriptor
}
