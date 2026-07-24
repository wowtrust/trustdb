package sproof

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/formatregistry"
	"github.com/wowtrust/trustdb/internal/globallog"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/model"
)

func TestNewBuildsAvailableV2Generation(t *testing.T) {
	t.Parallel()

	for _, suite := range []cryptosuite.ID{cryptosuite.INTLV1, cryptosuite.CNSMV1} {
		bundle := vectorProof().ProofBundle
		bundle.CryptoSuite = suite
		proof, err := New(bundle, Options{ExportedAtUnixN: 1_700_000_000_000_000_000})
		if err != nil {
			t.Fatalf("New(%s) error=%v", suite, err)
		}
		if proof.SchemaVersion != model.SchemaSingleProof || proof.FormatVersion != FormatVersion ||
			proof.CryptoSuite != suite || proof.ProofBundle.CryptoSuite != suite {
			t.Fatalf("New(%s) = %+v", suite, proof)
		}
	}
}

func TestCanonicalV2GoldenVectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		suite      cryptosuite.ID
		wantBytes  int
		wantDigest string
	}{
		{
			suite:      cryptosuite.INTLV1,
			wantBytes:  1268,
			wantDigest: "5e0547ff15886829fdf49562ca7d2783968730eb760f6977352d5a4fce266219",
		},
		{
			suite:      cryptosuite.CNSMV1,
			wantBytes:  1270,
			wantDigest: "e09e8bb5b995fa93c2dad1dcb6db2715027a2ffc044b2c1d08b7aba5a99219fd",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.suite), func(t *testing.T) {
			proof := vectorProof()
			proof.CryptoSuite = test.suite
			proof.ProofBundle.CryptoSuite = test.suite
			encoded, err := Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(encoded); got != test.wantBytes {
				t.Fatalf("encoded length = %d", got)
			}
			digest, err := Digest(proof)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(digest); got != test.wantDigest {
				t.Fatalf("digest = %s", got)
			}
		})
	}
}

func TestValidateRejectsAnchorWithoutGlobalProof(t *testing.T) {
	t.Parallel()

	proof := vectorProof()
	proof.AnchorResult = &model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		CryptoSuite:   cryptosuite.INTLV1,
		TreeSize:      1,
		AnchorID:      "anchor-1",
	}
	if err := Validate(proof); err == nil || !strings.Contains(err.Error(), "requires global_proof") {
		t.Fatalf("Validate() error = %v, want global_proof requirement", err)
	}
}

func TestValidateRejectsOversizedAnchorEvidence(t *testing.T) {
	t.Parallel()

	proof := vectorProof()
	proof.GlobalProof = &model.GlobalLogProof{}
	proof.AnchorResult = &model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		CryptoSuite:   cryptosuite.INTLV1,
		Proof:         make([]byte, formatregistry.MaxAnchorEvidenceBytesV2+1),
	}
	if err := Validate(proof); err == nil || !strings.Contains(err.Error(), "anchor_result proof exceeds") {
		t.Fatalf("Validate(oversized anchor) error = %v", err)
	}
}

func TestValidateRejectsDriftedEnvelopeMetadata(t *testing.T) {
	t.Parallel()

	proof := vectorProof()
	proof.RecordID = "other-record"
	if err := Validate(proof); err == nil || !strings.Contains(err.Error(), "record_id mismatch") {
		t.Fatalf("Validate() error = %v, want record_id mismatch", err)
	}

	proof = vectorProof()
	proof.ProofLevel = "L5"
	if err := Validate(proof); err == nil || !strings.Contains(err.Error(), "proof_level") {
		t.Fatalf("Validate() error = %v, want proof_level mismatch", err)
	}
}

func TestValidateStrictlyDecodesFISCOBCOSProviderProof(t *testing.T) {
	t.Parallel()

	proof := vectorProof()
	proof.ProofLevel = "L5"
	proof.NodeID = "node-1"
	proof.LogID = "log-1"
	proof.ProofBundle.NodeID = proof.NodeID
	proof.ProofBundle.LogID = proof.LogID
	proof.ProofBundle.CommittedReceipt = model.CommittedReceipt{
		SchemaVersion: model.SchemaCommittedReceipt, CryptoSuite: cryptosuite.INTLV1,
		BatchID: "batch-1", BatchRoot: make([]byte, 32), ClosedAtUnixN: 7,
	}
	proof.ProofBundle.CryptoSuite = cryptosuite.INTLV1
	proof.ProofBundle.BatchProof = model.BatchProof{TreeSize: 1}
	leaf := model.GlobalLogLeaf{
		SchemaVersion: model.SchemaGlobalLogLeaf, CryptoSuite: cryptosuite.INTLV1, NodeID: proof.NodeID, LogID: proof.LogID,
		BatchID: "batch-1", BatchRoot: make([]byte, 32), BatchTreeSize: 1, BatchClosedAtUnixN: 7,
	}
	leafHash, err := globallog.HashLeaf(leaf)
	if err != nil {
		t.Fatal(err)
	}
	sth := model.SignedTreeHead{
		SchemaVersion: model.SchemaSignedTreeHead, CryptoSuite: cryptosuite.INTLV1, TreeAlg: cryptosuite.MerkleRFC6962SHA256,
		TreeSize: 1, RootHash: leafHash, TimestampUnixN: 8, NodeID: proof.NodeID, LogID: proof.LogID,
		Signature: model.Signature{Alg: cryptosuite.SignatureEd25519, KeyID: "server", Signature: []byte{1}},
	}
	proof.GlobalProof = &model.GlobalLogProof{
		SchemaVersion: model.SchemaGlobalLogProof, CryptoSuite: cryptosuite.INTLV1, NodeID: proof.NodeID, LogID: proof.LogID,
		BatchID: "batch-1", LeafIndex: 0, LeafHash: leafHash, TreeSize: 1, STH: sth,
	}
	proof.AnchorResult = &model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult, CryptoSuite: cryptosuite.INTLV1,
		EvidenceStage: model.AnchorEvidenceStageOfflineVerified,
		NodeID:        proof.NodeID, LogID: proof.LogID,
		TreeSize: 1, SinkName: fiscobcos.SinkName, AnchorID: strings.Repeat("0", 64),
		RootHash: leafHash, STH: sth, Proof: []byte{0xa1, 0x61, 0x78, 0x01}, PublishedAtUnixN: 9,
	}
	if err := Validate(proof); err == nil || !strings.Contains(err.Error(), "FISCO BCOS") {
		t.Fatalf("Validate() error = %v, want strict FISCO BCOS proof decoding failure", err)
	}
}

func TestSProofV1L3VectorIsRejected(t *testing.T) {
	t.Parallel()

	vectorPath := filepath.Join("..", "..", "test", "vectors", "sproof-v1-l3.cbor")
	fixture, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	if _, err := Unmarshal(fixture); err == nil {
		t.Fatal("Unmarshal(v1 vector) error = nil, want retired generation rejection")
	}
}

func TestUnmarshalRejectsMissingAndCrossSuiteBindings(t *testing.T) {
	t.Parallel()

	proof := vectorProof()
	raw, err := cborx.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var missing model.SingleProof
	if err := cborx.UnmarshalLimit(raw, &missing, MaxBytes); err != nil {
		t.Fatal(err)
	}
	missing.CryptoSuite = ""
	raw, err = cborx.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unmarshal(raw); err == nil || !strings.Contains(err.Error(), "cryptographic suite") {
		t.Fatalf("Unmarshal(missing suite) error = %v", err)
	}

	proof = vectorProof()
	proof.ProofBundle.CryptoSuite = cryptosuite.CNSMV1
	raw, err = cborx.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unmarshal(raw); err == nil || !strings.Contains(err.Error(), "crypto_suite") {
		t.Fatalf("Unmarshal(cross suite) error = %v", err)
	}
}

func TestUnmarshalRejectsNonCanonicalV2Encoding(t *testing.T) {
	t.Parallel()

	proof := vectorProof()
	canonical, err := Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	options := cbor.CoreDetEncOptions()
	options.Sort = cbor.SortNone
	mode, err := options.EncMode()
	if err != nil {
		t.Fatal(err)
	}
	nonCanonical, err := mode.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(nonCanonical, canonical) {
		t.Fatal("non-canonical test encoder unexpectedly matched canonical bytes")
	}
	if _, err := Unmarshal(nonCanonical); err == nil || !strings.Contains(err.Error(), "non-canonical") {
		t.Fatalf("Unmarshal(non-canonical) error = %v", err)
	}
}

func TestUnmarshalRejectsOversizedCollectionsBeforeValidation(t *testing.T) {
	t.Parallel()

	proof := vectorProof()
	proof.IdentityEvidence = make([]model.ProofIdentityEvidence, MaxCollectionElements+1)
	raw, err := cborx.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unmarshal(raw); err == nil || !strings.Contains(err.Error(), "exceeded max number of elements") {
		t.Fatalf("Unmarshal(oversized collection) error = %v", err)
	}
}

func TestIdentityEvidenceIsPublicBoundedAndDefensivelyCopied(t *testing.T) {
	t.Parallel()

	proof := vectorProof()
	proof.ProofBundle.SignedClaim.Signature.KeyID = "client-key"
	descriptor := verifierDescriptor(t, "client-key")
	evidence := model.ProofIdentityEvidence{
		SchemaVersion: model.SchemaProofIdentity,
		CryptoSuite:   cryptosuite.INTLV1,
		Role:          model.ProofIdentityRoleClient,
		KeyID:         "client-key",
		KeyDescriptor: descriptor,
	}
	created, err := New(proof.ProofBundle, Options{
		IdentityEvidence: []model.ProofIdentityEvidence{evidence},
		ExportedAtUnixN:  proof.ExportedAtUnixN,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	evidence.KeyDescriptor[0] ^= 0xff
	if bytes.Equal(created.IdentityEvidence[0].KeyDescriptor, evidence.KeyDescriptor) {
		t.Fatal("New() retained caller-owned key descriptor bytes")
	}

	tampered := created
	tampered.IdentityEvidence = cloneIdentityEvidence(created.IdentityEvidence)
	tampered.IdentityEvidence[0].Role = "self-authorizing-root"
	if err := Validate(tampered); err == nil || !strings.Contains(err.Error(), "role") {
		t.Fatalf("Validate(unknown role) error = %v", err)
	}

	tampered = created
	tampered.IdentityEvidence = cloneIdentityEvidence(created.IdentityEvidence)
	tampered.IdentityEvidence[0].RegistryV2 = []byte("not-a-registry")
	if err := Validate(tampered); err == nil || !strings.Contains(err.Error(), "registry_v2") {
		t.Fatalf("Validate(invalid registry) error = %v", err)
	}

	tampered = created
	tampered.IdentityEvidence = cloneIdentityEvidence(created.IdentityEvidence)
	tampered.IdentityEvidence[0].CertificateStatuses = []model.CertificateStatusEvidence{{
		SchemaVersion:     model.SchemaCertificateStatus,
		CryptoSuite:       cryptosuite.INTLV1,
		Type:              model.CertificateStatusCRL,
		IssuerFingerprint: make([]byte, cryptosuite.DigestSize),
		Status:            []byte{1},
	}}
	if err := Validate(tampered); err == nil || !strings.Contains(err.Error(), "require a certificate chain") {
		t.Fatalf("Validate(status without chain) error = %v", err)
	}
}

func TestReadFileRejectsOversizedSingleProof(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "oversized.sproof")
	if err := os.WriteFile(path, make([]byte, MaxBytes+1), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := ReadFile(path); err == nil {
		t.Fatal("ReadFile() error = nil, want oversized invalid proof rejection")
	}
}

func TestWriteFileRoundTripsV2Generation(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proof.sproof")
	proof := vectorProof()
	if err := WriteFile(path, proof); err != nil {
		t.Fatalf("WriteFile() error=%v", err)
	}
	loaded, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error=%v", err)
	}
	equal, err := EqualEncoded(proof, loaded)
	if err != nil || !equal {
		t.Fatalf("EqualEncoded()=%v err=%v", equal, err)
	}
	digest, err := Digest(loaded)
	if err != nil || len(digest) != cryptosuite.DigestSize || bytes.Equal(digest, make([]byte, cryptosuite.DigestSize)) {
		t.Fatalf("Digest()=%x err=%v", digest, err)
	}
}

func TestWriteFileCleansTemporaryFileOnFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "existing-dir")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := WriteFile(target, vectorProof()); err == nil {
		t.Fatal("WriteFile() error = nil, want failure when target is a directory")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat(target) error = %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("target was replaced; mode=%s", info.Mode())
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".existing-dir.*.tmp"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files left behind: %v", matches)
	}
}

func vectorProof() model.SingleProof {
	return model.SingleProof{
		SchemaVersion:   model.SchemaSingleProof,
		FormatVersion:   FormatVersion,
		CryptoSuite:     cryptosuite.INTLV1,
		RecordID:        "rec-vector-1",
		ProofLevel:      "L3",
		NodeID:          "node-1",
		LogID:           "log-1",
		ExportedAtUnixN: 1_700_000_000_000_000_000,
		ProofBundle: model.ProofBundle{
			SchemaVersion: model.SchemaProofBundle,
			CryptoSuite:   cryptosuite.INTLV1,
			RecordID:      "rec-vector-1",
			NodeID:        "node-1",
			LogID:         "log-1",
		},
	}
}

func verifierDescriptor(t testing.TB, keyID string) []byte {
	t.Helper()
	public := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	encoded, err := keydescriptor.Marshal(keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindVerifier,
		Provider:      keydescriptor.ProviderPublic,
		CryptoSuite:   cryptosuite.INTLV1,
		KeyID:         keyID,
		Algorithm:     cryptosuite.SignatureEd25519,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: cryptosuite.Ed25519PublicKeyEncoding,
			Bytes:    public,
		},
	})
	if err != nil {
		t.Fatalf("marshal verifier descriptor: %v", err)
	}
	return encoded
}
