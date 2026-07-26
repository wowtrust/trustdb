package sproof

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/keystore"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

func TestVerifyIdentityEvidenceWithCertificateStatus(t *testing.T) {
	t.Parallel()

	for _, suiteID := range []cryptosuite.ID{cryptosuite.INTLV1, cryptosuite.CNSMV1} {
		suiteID := suiteID
		t.Run(string(suiteID), func(t *testing.T) {
			t.Parallel()

			signingTime := time.Unix(1_700_000_000, 0).UTC()
			identity := newCertificateIdentity(t, suiteID, signingTime)
			status := identity.status(t, signingTime.Add(-time.Hour), signingTime.Add(time.Hour), nil)
			proof := identityProof(t, suiteID, signingTime, identity.descriptor, status)

			report, err := VerifyIdentityEvidence(proof, IdentityTrust{
				ClientPublicKeys:         []trustcrypto.PublicKeyDescriptor{identity.publicKey},
				ClientCertificateRoots:   [][]byte{identity.root.Raw},
				RequireEvidence:          true,
				RequireCertificateStatus: true,
			})
			if err != nil {
				t.Fatalf("VerifyIdentityEvidence() error = %v", err)
			}
			if report.EvidenceCount != 1 ||
				report.PublicKeyBindingsVerified != 1 ||
				report.CertificateChainsVerified != 1 ||
				report.CertificateStatusesVerified != 1 {
				t.Fatalf("VerifyIdentityEvidence() report = %+v", report)
			}
		})
	}
}

func TestVerifyIdentityEvidenceRejectsUntrustedAndInvalidStatus(t *testing.T) {
	t.Parallel()

	signingTime := time.Unix(1_700_000_000, 0).UTC()
	identity := newCertificateIdentity(t, cryptosuite.INTLV1, signingTime)
	validStatus := identity.status(t, signingTime.Add(-time.Hour), signingTime.Add(time.Hour), nil)
	validProof := identityProof(t, cryptosuite.INTLV1, signingTime, identity.descriptor, validStatus)
	validTrust := IdentityTrust{
		ClientPublicKeys:         []trustcrypto.PublicKeyDescriptor{identity.publicKey},
		ClientCertificateRoots:   [][]byte{identity.root.Raw},
		RequireEvidence:          true,
		RequireCertificateStatus: true,
	}

	tests := []struct {
		name    string
		mutate  func(*model.SingleProof, *IdentityTrust)
		wantErr string
	}{
		{
			name: "embedded descriptor is not a trust root",
			mutate: func(_ *model.SingleProof, trust *IdentityTrust) {
				trust.ClientPublicKeys = nil
			},
			wantErr: "verifier-local trust bindings",
		},
		{
			name: "duplicate local public key binding",
			mutate: func(_ *model.SingleProof, trust *IdentityTrust) {
				trust.ClientPublicKeys = append(trust.ClientPublicKeys, identity.publicKey)
			},
			wantErr: "2 exact verifier-local trust bindings",
		},
		{
			name: "missing local CA root",
			mutate: func(_ *model.SingleProof, trust *IdentityTrust) {
				trust.ClientCertificateRoots = nil
			},
			wantErr: "certificate roots are required",
		},
		{
			name: "stale CRL",
			mutate: func(proof *model.SingleProof, _ *IdentityTrust) {
				proof.IdentityEvidence[0].CertificateStatuses[0] = identity.status(
					t,
					signingTime.Add(-2*time.Hour),
					signingTime.Add(-time.Hour),
					nil,
				)
			},
			wantErr: "does not cover signature time",
		},
		{
			name: "tampered CRL",
			mutate: func(proof *model.SingleProof, _ *IdentityTrust) {
				proof.IdentityEvidence[0].CertificateStatuses[0].Status =
					append([]byte(nil), proof.IdentityEvidence[0].CertificateStatuses[0].Status...)
				proof.IdentityEvidence[0].CertificateStatuses[0].Status[len(proof.IdentityEvidence[0].CertificateStatuses[0].Status)-1] ^= 1
			},
			wantErr: "CRL",
		},
		{
			name: "revoked at signature time",
			mutate: func(proof *model.SingleProof, _ *IdentityTrust) {
				revokedAt := signingTime.Add(-time.Minute)
				proof.IdentityEvidence[0].CertificateStatuses[0] = identity.status(
					t,
					signingTime.Add(-time.Hour),
					signingTime.Add(time.Hour),
					&revokedAt,
				)
			},
			wantErr: "revoked at signature time",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			proof := cloneProofIdentity(validProof)
			trust := cloneIdentityTrust(validTrust)
			test.mutate(&proof, &trust)
			if _, err := VerifyIdentityEvidence(proof, trust); err == nil ||
				!strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("VerifyIdentityEvidence() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestVerifyIdentityEvidenceBindsRegistryLifecycleAtSigningTime(t *testing.T) {
	t.Parallel()

	signingTime := time.Unix(1_700_000_000, 0).UTC()
	clientPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientDescriptor := verifierDescriptorForPublicKey(
		t,
		cryptosuite.INTLV1,
		"client-key",
		clientPublic,
		nil,
	)
	publicKey, err := clientDescriptor.PublicKeyDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	registryPublic, registryPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registrySigner, err := trustcrypto.NewEd25519Signer("registry-key", registryPrivate)
	if err != nil {
		t.Fatal(err)
	}
	registryTrust, err := trustcrypto.NewEd25519PublicKey("registry-key", registryPublic)
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(t.TempDir(), "identity.tdkeys")
	registry, err := keystore.Open(registryPath, registrySigner, registryTrust)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RegisterClientKey(
		"tenant-1",
		"client-1",
		clientDescriptor,
		signingTime.Add(-time.Hour),
		time.Time{},
	); err != nil {
		t.Fatal(err)
	}
	registryEvidence, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	encodedDescriptor, err := keydescriptor.Marshal(clientDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	proof := identityProof(t, cryptosuite.INTLV1, signingTime, encodedDescriptor)
	proof.IdentityEvidence[0].RegistryV2 = registryEvidence
	trust := IdentityTrust{
		ClientPublicKeys:  []trustcrypto.PublicKeyDescriptor{publicKey},
		RegistryPublicKey: registryTrust,
		RequireEvidence:   true,
	}

	report, err := VerifyIdentityEvidence(proof, trust)
	if err != nil {
		t.Fatalf("VerifyIdentityEvidence() error = %v", err)
	}
	if report.LifecycleBindingsVerified != 1 {
		t.Fatalf("VerifyIdentityEvidence() report = %+v", report)
	}

	tampered := cloneProofIdentity(proof)
	tampered.IdentityEvidence[0].RegistryV2[len(tampered.IdentityEvidence[0].RegistryV2)-1] ^= 1
	if _, err := VerifyIdentityEvidence(tampered, trust); err == nil ||
		!strings.Contains(err.Error(), "registry lifecycle") {
		t.Fatalf("VerifyIdentityEvidence(tampered registry) error = %v", err)
	}

	beforeValidity := cloneProofIdentity(proof)
	beforeValidity.ProofBundle.SignedClaim.Claim.ProducedAtUnixN = signingTime.Add(-2 * time.Hour).UnixNano()
	if _, err := VerifyIdentityEvidence(beforeValidity, trust); err == nil ||
		!strings.Contains(err.Error(), "signing-time lifecycle") {
		t.Fatalf("VerifyIdentityEvidence(before validity) error = %v", err)
	}
}

func TestVerifyIdentityEvidenceRequiresReferencedKeys(t *testing.T) {
	t.Parallel()

	proof := vectorProof()
	proof.ProofBundle.SignedClaim = model.SignedClaim{
		SchemaVersion: model.SchemaSignedClaim,
		CryptoSuite:   cryptosuite.INTLV1,
		Claim: model.ClientClaim{
			SchemaVersion:   model.SchemaClientClaim,
			CryptoSuite:     cryptosuite.INTLV1,
			ProducedAtUnixN: time.Unix(1_700_000_000, 0).UnixNano(),
		},
		Signature: model.Signature{KeyID: "missing-client"},
	}
	if _, err := VerifyIdentityEvidence(proof, IdentityTrust{RequireEvidence: true}); err == nil ||
		!strings.Contains(err.Error(), "required identity evidence") {
		t.Fatalf("VerifyIdentityEvidence() error = %v", err)
	}
}

type certificateIdentity struct {
	suiteID    cryptosuite.ID
	root       *smx509.Certificate
	rootSigner crypto.Signer
	leaf       *smx509.Certificate
	publicKey  trustcrypto.PublicKeyDescriptor
	descriptor []byte
}

func newCertificateIdentity(t *testing.T, suiteID cryptosuite.ID, signingTime time.Time) certificateIdentity {
	t.Helper()

	rootPublic, rootSigner, _ := identityKeyPair(t, suiteID)
	leafPublic, _, leafPublicBytes := identityKeyPair(t, suiteID)
	rootTemplate := &smx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TrustDB offline identity root"},
		SubjectKeyId:          bytes.Repeat([]byte{0x11}, 20),
		NotBefore:             signingTime.Add(-24 * time.Hour),
		NotAfter:              signingTime.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign,
	}
	rootDER, err := smx509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootSigner)
	if err != nil {
		t.Fatal(err)
	}
	root, err := smx509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &smx509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "TrustDB offline signer"},
		NotBefore:    signingTime.Add(-12 * time.Hour),
		NotAfter:     signingTime.Add(12 * time.Hour),
		KeyUsage:     smx509.KeyUsageDigitalSignature,
	}
	leafDER, err := smx509.CreateCertificate(rand.Reader, leafTemplate, root, leafPublic, rootSigner)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := smx509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := verifierDescriptorForPublicKey(
		t,
		suiteID,
		"client-key",
		leafPublicBytes,
		[][]byte{leafDER, rootDER},
	)
	encoded, err := keydescriptor.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := descriptor.PublicKeyDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	return certificateIdentity{
		suiteID:    suiteID,
		root:       root,
		rootSigner: rootSigner,
		leaf:       leaf,
		publicKey:  publicKey,
		descriptor: encoded,
	}
}

func (identity certificateIdentity) status(
	t *testing.T,
	thisUpdate, nextUpdate time.Time,
	revokedAt *time.Time,
) model.CertificateStatusEvidence {
	t.Helper()

	var entries []smx509.RevocationListEntry
	if revokedAt != nil {
		entries = []smx509.RevocationListEntry{{
			SerialNumber:   new(big.Int).Set(identity.leaf.SerialNumber),
			RevocationTime: *revokedAt,
		}}
	}
	raw, err := smx509.CreateRevocationList(rand.Reader, &smx509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}, identity.root, identity.rootSigner)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := certificateFingerprint(identity.suiteID, identity.root)
	if err != nil {
		t.Fatal(err)
	}
	return model.CertificateStatusEvidence{
		SchemaVersion:     model.SchemaCertificateStatus,
		CryptoSuite:       identity.suiteID,
		Type:              model.CertificateStatusCRL,
		IssuerFingerprint: fingerprint,
		Status:            raw,
	}
}

func identityKeyPair(t *testing.T, suiteID cryptosuite.ID) (any, crypto.Signer, []byte) {
	t.Helper()

	switch suiteID {
	case cryptosuite.INTLV1:
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return publicKey, privateKey, append([]byte(nil), publicKey...)
	case cryptosuite.CNSMV1:
		privateKey, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publicKey := &privateKey.PublicKey
		return publicKey, privateKey, elliptic.Marshal(sm2.P256(), publicKey.X, publicKey.Y)
	default:
		t.Fatalf("unsupported suite %s", suiteID)
		return nil, nil, nil
	}
}

func verifierDescriptorForPublicKey(
	t *testing.T,
	suiteID cryptosuite.ID,
	keyID string,
	publicKey []byte,
	chain [][]byte,
) keydescriptor.Descriptor {
	t.Helper()

	suite, err := cryptosuite.RequireAvailable(suiteID)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindVerifier,
		Provider:      keydescriptor.ProviderPublic,
		CryptoSuite:   suiteID,
		KeyID:         keyID,
		Algorithm:     suite.Signature.Algorithm,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: suite.Signature.PublicKeyEncoding,
			Bytes:    append([]byte(nil), publicKey...),
		},
		CertificateChain: cloneBytes(chain),
	}
	if suiteID == cryptosuite.CNSMV1 {
		descriptor.SM2UserID = cryptosuite.SM2DefaultUserID
	}
	return descriptor
}

func identityProof(
	t *testing.T,
	suiteID cryptosuite.ID,
	signingTime time.Time,
	descriptor []byte,
	statuses ...model.CertificateStatusEvidence,
) model.SingleProof {
	t.Helper()

	suite, err := cryptosuite.RequireAvailable(suiteID)
	if err != nil {
		t.Fatal(err)
	}
	proof := vectorProof()
	proof.CryptoSuite = suiteID
	proof.ProofBundle.CryptoSuite = suiteID
	proof.ProofBundle.SignedClaim = model.SignedClaim{
		SchemaVersion: model.SchemaSignedClaim,
		CryptoSuite:   suiteID,
		Claim: model.ClientClaim{
			SchemaVersion:   model.SchemaClientClaim,
			CryptoSuite:     suiteID,
			TenantID:        "tenant-1",
			ClientID:        "client-1",
			KeyID:           "client-key",
			ProducedAtUnixN: signingTime.UnixNano(),
		},
		Signature: model.Signature{
			Alg:   suite.Signature.Algorithm,
			KeyID: "client-key",
		},
	}
	proof.IdentityEvidence = []model.ProofIdentityEvidence{{
		SchemaVersion:       model.SchemaProofIdentity,
		CryptoSuite:         suiteID,
		Role:                model.ProofIdentityRoleClient,
		KeyID:               "client-key",
		KeyDescriptor:       append([]byte(nil), descriptor...),
		CertificateStatuses: append([]model.CertificateStatusEvidence(nil), statuses...),
	}}
	if err := Validate(proof); err != nil {
		t.Fatalf("Validate(identity proof) error = %v", err)
	}
	return proof
}

func cloneProofIdentity(proof model.SingleProof) model.SingleProof {
	proof.IdentityEvidence = cloneIdentityEvidence(proof.IdentityEvidence)
	return proof
}

func cloneIdentityTrust(trust IdentityTrust) IdentityTrust {
	trust.ClientPublicKeys = append([]trustcrypto.PublicKeyDescriptor(nil), trust.ClientPublicKeys...)
	trust.ServerPublicKeys = append([]trustcrypto.PublicKeyDescriptor(nil), trust.ServerPublicKeys...)
	trust.ClientCertificateRoots = cloneBytes(trust.ClientCertificateRoots)
	trust.ServerCertificateRoots = cloneBytes(trust.ServerCertificateRoots)
	return trust
}

func cloneBytes(input [][]byte) [][]byte {
	output := make([][]byte, len(input))
	for index := range input {
		output[index] = append([]byte(nil), input[index]...)
	}
	return output
}
