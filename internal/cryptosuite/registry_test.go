package cryptosuite

import (
	"errors"
	"reflect"
	"testing"
)

func TestRegistryPinsCanonicalSuites(t *testing.T) {
	intl, ok := Lookup(INTLV1)
	if !ok {
		t.Fatal("INTL_V1 missing from registry")
	}
	if intl.Availability != AvailabilityAvailable ||
		intl.ContentHash != (HashSpec{Algorithm: HashSHA256, DigestBytes: 32}) ||
		intl.ClaimHash != (HashSpec{Algorithm: HashSHA256, DigestBytes: 32}) ||
		intl.SignatureHash != (HashSpec{Algorithm: HashSHA256, DigestBytes: 32}) ||
		intl.KeyEventHash != (HashSpec{Algorithm: HashSHA256, DigestBytes: 32}) ||
		intl.KeyFingerprintHash != (HashSpec{Algorithm: HashSHA256, DigestBytes: 32}) ||
		intl.StorageIntegrityHash != (HashSpec{Algorithm: HashSHA256, DigestBytes: 32}) ||
		intl.Signature.Algorithm != SignatureEd25519 ||
		intl.Signature.Encoding != Ed25519SignatureEncoding ||
		intl.Merkle.Algorithm != MerkleRFC6962SHA256 ||
		intl.AnchorDigest.Algorithm != HashSHA256 ||
		intl.Encoding != (EncodingSpec{
			CanonicalObjectEncoding: CanonicalCBOR,
			SignatureInputEncoding:  SignatureInputLegacyV1,
			DomainSeparator:         0x00,
		}) ||
		intl.Domains != (DomainSet{
			ClientClaimSigning:    "trustdb.client-claim.v1",
			RecordID:              "trustdb.record-id.v1",
			AcceptedReceipt:       "trustdb.accepted-receipt.v1",
			CommittedReceipt:      "trustdb.committed-receipt.v1",
			KeyEventSigning:       "trustdb.key-event.v1",
			KeyEventHash:          "trustdb.key-event-hash.v1",
			GlobalLogLeaf:         "trustdb.global-log-leaf.v1",
			SignedTreeHead:        "trustdb.signed-tree-head.v1",
			IdempotencyStorageKey: "trustdb.idempotency-storage-key.v1",
		}) {
		t.Fatalf("unexpected INTL_V1 descriptor: %#v", intl)
	}

	cn, ok := Lookup(CNSMV1)
	if !ok {
		t.Fatal("CN_SM_V1 missing from registry")
	}
	if cn.Availability != AvailabilityReserved ||
		cn.ContentHash != (HashSpec{Algorithm: HashSM3, DigestBytes: 32}) ||
		cn.ClaimHash != (HashSpec{Algorithm: HashSM3, DigestBytes: 32}) ||
		cn.SignatureHash != (HashSpec{Algorithm: HashSM3, DigestBytes: 32}) ||
		cn.KeyEventHash != (HashSpec{Algorithm: HashSM3, DigestBytes: 32}) ||
		cn.KeyFingerprintHash != (HashSpec{Algorithm: HashSM3, DigestBytes: 32}) ||
		cn.StorageIntegrityHash != (HashSpec{Algorithm: HashSM3, DigestBytes: 32}) ||
		cn.Signature.Algorithm != SignatureSM2SM3 ||
		cn.Signature.MessageHashAlgorithm != HashSM3 ||
		cn.Signature.SM2UserID != SM2DefaultUserID ||
		cn.Merkle.Algorithm != MerkleRFC6962SM3 ||
		cn.AnchorDigest.Algorithm != HashSM3 ||
		cn.Encoding != (EncodingSpec{
			CanonicalObjectEncoding: CanonicalCBOR,
			SignatureInputEncoding:  SignatureInputSuiteFramedV2,
			DomainSeparator:         0x00,
		}) ||
		cn.Domains != (DomainSet{
			ClientClaimSigning:    "trustdb.client-claim.v2",
			RecordID:              "trustdb.record-id.v2",
			AcceptedReceipt:       "trustdb.accepted-receipt.v2",
			CommittedReceipt:      "trustdb.committed-receipt.v2",
			KeyEventSigning:       "trustdb.key-event.v2",
			KeyEventHash:          "trustdb.key-event-hash.v2",
			GlobalLogLeaf:         "trustdb.global-log-leaf.v2",
			SignedTreeHead:        "trustdb.signed-tree-head.v2",
			IdempotencyStorageKey: "trustdb.idempotency-storage-key.v2",
		}) {
		t.Fatalf("unexpected CN_SM_V1 descriptor: %#v", cn)
	}
}

func TestRegistryDescriptorsAreComplete(t *testing.T) {
	for _, suite := range All() {
		hashes := map[string]HashSpec{
			"content":           suite.ContentHash,
			"claim":             suite.ClaimHash,
			"signature":         suite.SignatureHash,
			"record_id":         suite.RecordIDHash,
			"key_event":         suite.KeyEventHash,
			"key_fingerprint":   suite.KeyFingerprintHash,
			"storage_integrity": suite.StorageIntegrityHash,
			"merkle":            suite.Merkle.Hash,
			"anchor":            suite.AnchorDigest,
		}
		for name, spec := range hashes {
			if spec.Algorithm == "" || spec.DigestBytes <= 0 {
				t.Fatalf("suite %s has incomplete %s hash spec: %#v", suite.ID, name, spec)
			}
		}
		if suite.Signature.Algorithm == "" || suite.Signature.Encoding == "" ||
			suite.Signature.PublicKeyEncoding == "" || suite.Signature.PrivateKeyEncoding == "" ||
			suite.Signature.CertificateProfile == "" {
			t.Fatalf("suite %s has incomplete signature spec: %#v", suite.ID, suite.Signature)
		}
		if suite.Merkle.Algorithm == "" || suite.Merkle.LeafPrefix == suite.Merkle.NodePrefix {
			t.Fatalf("suite %s has incomplete merkle spec: %#v", suite.ID, suite.Merkle)
		}
		if suite.Encoding.CanonicalObjectEncoding == "" || suite.Encoding.SignatureInputEncoding == "" {
			t.Fatalf("suite %s has incomplete encoding spec: %#v", suite.ID, suite.Encoding)
		}
	}
}

func TestAllReturnsStableSortedRegistry(t *testing.T) {
	want := []ID{CNSMV1, INTLV1}
	gotSuites := All()
	got := make([]ID, len(gotSuites))
	for i := range gotSuites {
		got[i] = gotSuites[i].ID
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("All() IDs = %v, want %v", got, want)
	}
}

func TestRequireAvailableRejectsReservedAndUnknownSuites(t *testing.T) {
	if _, err := RequireAvailable(INTLV1); err != nil {
		t.Fatalf("RequireAvailable(INTL_V1) error = %v", err)
	}
	if _, err := RequireAvailable(CNSMV1); !errors.Is(err, ErrUnavailableSuite) {
		t.Fatalf("RequireAvailable(CN_SM_V1) error = %v, want ErrUnavailableSuite", err)
	}
	if _, err := RequireAvailable(ID("UNKNOWN")); !errors.Is(err, ErrUnknownSuite) {
		t.Fatalf("RequireAvailable(UNKNOWN) error = %v, want ErrUnknownSuite", err)
	}
	if _, err := RequireAvailable(ID("intl_v1")); !errors.Is(err, ErrUnknownSuite) {
		t.Fatalf("RequireAvailable(intl_v1) error = %v, want ErrUnknownSuite", err)
	}
}

func TestRequireSameFailsClosedOnMixedOrMissingSuites(t *testing.T) {
	if err := RequireSame(INTLV1, INTLV1, INTLV1); err != nil {
		t.Fatalf("RequireSame matching suites error = %v", err)
	}
	if err := RequireSame(INTLV1, CNSMV1); !errors.Is(err, ErrMixedSuite) {
		t.Fatalf("RequireSame mixed suites error = %v, want ErrMixedSuite", err)
	}
	if err := RequireSame(INTLV1, ""); !errors.Is(err, ErrUnknownSuite) {
		t.Fatalf("RequireSame empty suite error = %v, want ErrUnknownSuite", err)
	}
}

func TestValidateNamespaceTransitionRequiresNewIdentitiesForSuiteChange(t *testing.T) {
	current := NamespaceBinding{
		Suite:            INTLV1,
		LogID:            "log-intl-v1",
		StorageNamespace: "proofstore/intl-v1",
		NonEmpty:         true,
	}

	if err := ValidateNamespaceTransition(current, current); err != nil {
		t.Fatalf("same-suite transition error = %v", err)
	}
	if err := ValidateNamespaceTransition(current, NamespaceBinding{
		Suite:            CNSMV1,
		LogID:            current.LogID,
		StorageNamespace: "proofstore/cn-sm-v1",
	}); !errors.Is(err, ErrNamespaceReuse) {
		t.Fatalf("reused log_id error = %v, want ErrNamespaceReuse", err)
	}
	if err := ValidateNamespaceTransition(current, NamespaceBinding{
		Suite:            CNSMV1,
		LogID:            "log-cn-sm-v1",
		StorageNamespace: current.StorageNamespace,
	}); !errors.Is(err, ErrNamespaceReuse) {
		t.Fatalf("reused storage namespace error = %v, want ErrNamespaceReuse", err)
	}
	if err := ValidateNamespaceTransition(current, NamespaceBinding{
		Suite:            CNSMV1,
		LogID:            "log-cn-sm-v1",
		StorageNamespace: "proofstore/cn-sm-v1",
	}); err != nil {
		t.Fatalf("new log and namespace transition error = %v", err)
	}
}

func TestValidateNamespaceTransitionRejectsUnboundNonEmptyData(t *testing.T) {
	err := ValidateNamespaceTransition(
		NamespaceBinding{NonEmpty: true},
		NamespaceBinding{Suite: INTLV1, LogID: "log-intl-v1", StorageNamespace: "proofstore/intl-v1"},
	)
	if !errors.Is(err, ErrUnboundNonEmptyData) {
		t.Fatalf("transition error = %v, want ErrUnboundNonEmptyData", err)
	}
}
