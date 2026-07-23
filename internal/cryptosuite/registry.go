// Package cryptosuite defines TrustDB's immutable cryptographic suite
// identifiers and the parameters bound to each suite. It intentionally does
// not implement cryptographic providers; provider selection and format
// versioning are separate compatibility boundaries.
package cryptosuite

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type ID string

const (
	INTLV1 ID = "INTL_V1"
	CNSMV1 ID = "CN_SM_V1"
)

type Availability string

const (
	AvailabilityAvailable Availability = "available"
	AvailabilityReserved  Availability = "reserved"
)

const (
	HashSHA256 = "sha256"
	HashSM3    = "sm3"

	SignatureEd25519 = "ed25519"
	SignatureSM2SM3  = "sm2-sm3"

	MerkleRFC6962SHA256 = "rfc6962-sha256"
	MerkleRFC6962SM3    = "rfc6962-sm3"

	CanonicalCBOR = "cbor-core-deterministic-rfc8949"

	SignatureInputLegacyV1      = "domain-nul-payload"
	SignatureInputSuiteFramedV2 = "domain-nul-suite-nul-payload"

	Ed25519SignatureEncoding  = "raw-64-byte-rfc8032"
	Ed25519PublicKeyEncoding  = "raw-32-byte-rfc8032"
	Ed25519PrivateKeyEncoding = "trustdb-ed25519-private-key-64-byte"
	Ed25519CertificateProfile = "x509-ed25519-rfc8410"

	SM2SignatureEncoding  = "asn1-der-sequence-r-s"
	SM2PublicKeyEncoding  = "sec1-uncompressed-65-byte-sm2p256v1"
	SM2PrivateKeyEncoding = "fixed-32-byte-big-endian-scalar"
	SM2CertificateProfile = "x509-sm2-gbt35276"
	SM2DefaultUserID      = "1234567812345678"
)

type HashSpec struct {
	Algorithm   string
	DigestBytes int
}

type SignatureSpec struct {
	Algorithm            string
	MessageHashAlgorithm string
	Encoding             string
	PublicKeyEncoding    string
	PrivateKeyEncoding   string
	CertificateProfile   string
	SM2UserID            string
}

type MerkleSpec struct {
	Algorithm  string
	Hash       HashSpec
	LeafPrefix byte
	NodePrefix byte
}

type EncodingSpec struct {
	CanonicalObjectEncoding string
	SignatureInputEncoding  string
	DomainSeparator         byte
}

type DomainSet struct {
	ClientClaimSigning    string
	RecordID              string
	AcceptedReceipt       string
	CommittedReceipt      string
	KeyEventSigning       string
	KeyEventHash          string
	GlobalLogLeaf         string
	SignedTreeHead        string
	IdempotencyStorageKey string
}

type Suite struct {
	ID                   ID
	Availability         Availability
	ContentHash          HashSpec
	ClaimHash            HashSpec
	SignatureHash        HashSpec
	RecordIDHash         HashSpec
	KeyEventHash         HashSpec
	KeyFingerprintHash   HashSpec
	StorageIntegrityHash HashSpec
	Signature            SignatureSpec
	Merkle               MerkleSpec
	Encoding             EncodingSpec
	AnchorDigest         HashSpec
	Domains              DomainSet
}

var registry = map[ID]Suite{
	INTLV1: {
		ID:                   INTLV1,
		Availability:         AvailabilityAvailable,
		ContentHash:          HashSpec{Algorithm: HashSHA256, DigestBytes: 32},
		ClaimHash:            HashSpec{Algorithm: HashSHA256, DigestBytes: 32},
		SignatureHash:        HashSpec{Algorithm: HashSHA256, DigestBytes: 32},
		RecordIDHash:         HashSpec{Algorithm: HashSHA256, DigestBytes: 32},
		KeyEventHash:         HashSpec{Algorithm: HashSHA256, DigestBytes: 32},
		KeyFingerprintHash:   HashSpec{Algorithm: HashSHA256, DigestBytes: 32},
		StorageIntegrityHash: HashSpec{Algorithm: HashSHA256, DigestBytes: 32},
		Signature: SignatureSpec{
			Algorithm:          SignatureEd25519,
			Encoding:           Ed25519SignatureEncoding,
			PublicKeyEncoding:  Ed25519PublicKeyEncoding,
			PrivateKeyEncoding: Ed25519PrivateKeyEncoding,
			CertificateProfile: Ed25519CertificateProfile,
		},
		Merkle: MerkleSpec{
			Algorithm:  MerkleRFC6962SHA256,
			Hash:       HashSpec{Algorithm: HashSHA256, DigestBytes: 32},
			LeafPrefix: 0x00,
			NodePrefix: 0x01,
		},
		Encoding: EncodingSpec{
			CanonicalObjectEncoding: CanonicalCBOR,
			SignatureInputEncoding:  SignatureInputLegacyV1,
			DomainSeparator:         0x00,
		},
		AnchorDigest: HashSpec{Algorithm: HashSHA256, DigestBytes: 32},
		Domains: DomainSet{
			ClientClaimSigning:    "trustdb.client-claim.v1",
			RecordID:              "trustdb.record-id.v1",
			AcceptedReceipt:       "trustdb.accepted-receipt.v1",
			CommittedReceipt:      "trustdb.committed-receipt.v1",
			KeyEventSigning:       "trustdb.key-event.v1",
			KeyEventHash:          "trustdb.key-event-hash.v1",
			GlobalLogLeaf:         "trustdb.global-log-leaf.v1",
			SignedTreeHead:        "trustdb.signed-tree-head.v1",
			IdempotencyStorageKey: "trustdb.idempotency-storage-key.v1",
		},
	},
	CNSMV1: {
		ID:                   CNSMV1,
		Availability:         AvailabilityReserved,
		ContentHash:          HashSpec{Algorithm: HashSM3, DigestBytes: 32},
		ClaimHash:            HashSpec{Algorithm: HashSM3, DigestBytes: 32},
		SignatureHash:        HashSpec{Algorithm: HashSM3, DigestBytes: 32},
		RecordIDHash:         HashSpec{Algorithm: HashSM3, DigestBytes: 32},
		KeyEventHash:         HashSpec{Algorithm: HashSM3, DigestBytes: 32},
		KeyFingerprintHash:   HashSpec{Algorithm: HashSM3, DigestBytes: 32},
		StorageIntegrityHash: HashSpec{Algorithm: HashSM3, DigestBytes: 32},
		Signature: SignatureSpec{
			Algorithm:            SignatureSM2SM3,
			MessageHashAlgorithm: HashSM3,
			Encoding:             SM2SignatureEncoding,
			PublicKeyEncoding:    SM2PublicKeyEncoding,
			PrivateKeyEncoding:   SM2PrivateKeyEncoding,
			CertificateProfile:   SM2CertificateProfile,
			SM2UserID:            SM2DefaultUserID,
		},
		Merkle: MerkleSpec{
			Algorithm:  MerkleRFC6962SM3,
			Hash:       HashSpec{Algorithm: HashSM3, DigestBytes: 32},
			LeafPrefix: 0x00,
			NodePrefix: 0x01,
		},
		Encoding: EncodingSpec{
			CanonicalObjectEncoding: CanonicalCBOR,
			SignatureInputEncoding:  SignatureInputSuiteFramedV2,
			DomainSeparator:         0x00,
		},
		AnchorDigest: HashSpec{Algorithm: HashSM3, DigestBytes: 32},
		Domains: DomainSet{
			ClientClaimSigning:    "trustdb.client-claim.v2",
			RecordID:              "trustdb.record-id.v2",
			AcceptedReceipt:       "trustdb.accepted-receipt.v2",
			CommittedReceipt:      "trustdb.committed-receipt.v2",
			KeyEventSigning:       "trustdb.key-event.v2",
			KeyEventHash:          "trustdb.key-event-hash.v2",
			GlobalLogLeaf:         "trustdb.global-log-leaf.v2",
			SignedTreeHead:        "trustdb.signed-tree-head.v2",
			IdempotencyStorageKey: "trustdb.idempotency-storage-key.v2",
		},
	},
}

var (
	ErrUnknownSuite        = errors.New("unknown cryptographic suite")
	ErrUnavailableSuite    = errors.New("cryptographic suite is not available")
	ErrMixedSuite          = errors.New("mixed cryptographic suites")
	ErrNamespaceReuse      = errors.New("cryptographic suite change reuses a log or storage namespace")
	ErrUnboundNonEmptyData = errors.New("non-empty data has no cryptographic suite binding")
)

func Lookup(id ID) (Suite, bool) {
	suite, ok := registry[id]
	return suite, ok
}

func All() []Suite {
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	out := make([]Suite, 0, len(ids))
	for _, raw := range ids {
		out = append(out, registry[ID(raw)])
	}
	return out
}

func RequireKnown(id ID) (Suite, error) {
	suite, ok := Lookup(id)
	if !ok {
		return Suite{}, fmt.Errorf("%w: %q", ErrUnknownSuite, id)
	}
	return suite, nil
}

// RequireAvailable is the generation/startup gate. Reserved suites remain
// discoverable for format design and conformance work but cannot be enabled.
func RequireAvailable(id ID) (Suite, error) {
	suite, err := RequireKnown(id)
	if err != nil {
		return Suite{}, err
	}
	if suite.Availability != AvailabilityAvailable {
		return Suite{}, fmt.Errorf("%w: %s is %s", ErrUnavailableSuite, id, suite.Availability)
	}
	return suite, nil
}

// RequireSame rejects empty, unknown, or mixed suite identifiers. Format and
// persistence code can use this at every composition boundary.
func RequireSame(expected ID, actual ...ID) error {
	if _, err := RequireKnown(expected); err != nil {
		return err
	}
	for i, id := range actual {
		if _, err := RequireKnown(id); err != nil {
			return fmt.Errorf("suite at index %d: %w", i, err)
		}
		if id != expected {
			return fmt.Errorf("%w: expected %s, got %s at index %d", ErrMixedSuite, expected, id, i)
		}
	}
	return nil
}

type NamespaceBinding struct {
	Suite            ID
	LogID            string
	StorageNamespace string
	NonEmpty         bool
}

// ValidateNamespaceTransition enforces that a suite change creates both a new
// transparency-log identity and a new proofstore namespace. Existing non-empty
// data without a persisted suite marker is always rejected.
func ValidateNamespaceTransition(current, next NamespaceBinding) error {
	if _, err := RequireKnown(next.Suite); err != nil {
		return fmt.Errorf("next binding: %w", err)
	}
	if strings.TrimSpace(next.LogID) == "" {
		return errors.New("next binding log_id is required")
	}
	if strings.TrimSpace(next.StorageNamespace) == "" {
		return errors.New("next binding storage namespace is required")
	}
	if current.Suite == "" {
		if current.NonEmpty {
			return ErrUnboundNonEmptyData
		}
		return nil
	}
	if _, err := RequireKnown(current.Suite); err != nil {
		return fmt.Errorf("current binding: %w", err)
	}
	if current.Suite == next.Suite {
		return nil
	}
	if strings.TrimSpace(current.LogID) == strings.TrimSpace(next.LogID) {
		return fmt.Errorf("%w: log_id %q", ErrNamespaceReuse, next.LogID)
	}
	if strings.TrimSpace(current.StorageNamespace) == strings.TrimSpace(next.StorageNamespace) {
		return fmt.Errorf("%w: storage namespace %q", ErrNamespaceReuse, next.StorageNamespace)
	}
	return nil
}
