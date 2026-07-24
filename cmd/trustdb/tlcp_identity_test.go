package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func TestActiveProofDescriptorUsesTheResolvedTrustDBSigner(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := trustcrypto.MustNewEd25519Signer("active-proof", privateKey)
	privateDescriptor := testProofSignerDescriptor(publicKey)
	publicDescriptor := privateDescriptor.Clone()
	publicDescriptor.Kind = keydescriptor.KindVerifier
	publicDescriptor.Provider = keydescriptor.ProviderPublic
	publicDescriptor.Software = nil
	configuredPublic, err := publicDescriptor.PublicKeyDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	data, err := activeProofDescriptorData(
		context.Background(),
		signer,
		privateDescriptor,
		configuredPublic,
		publicDescriptor,
	)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := keydescriptor.Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Kind != keydescriptor.KindVerifier ||
		!samePublicKeyDescriptor(configuredPublic, mustPublicDescriptor(t, decoded)) {
		t.Fatalf("unexpected active proof descriptor: %+v", decoded)
	}

	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mismatch := publicDescriptor.Clone()
	mismatch.PublicKey.Bytes = otherPublic
	mismatchPublic := mustPublicDescriptor(t, mismatch)
	if _, err := activeProofDescriptorData(
		context.Background(),
		signer,
		privateDescriptor,
		mismatchPublic,
		mismatch,
	); err == nil {
		t.Fatal("a configured public descriptor for another key was accepted")
	}
}

func TestTLCPIdentityBoundaryNeverSilentlyAcceptsEmptyConfiguration(
	t *testing.T,
) {
	if _, err := configureTLCPIdentityBoundary(
		context.Background(),
		"",
		"",
		"",
		"",
		false,
		trustcrypto.PublicKeyDescriptor{},
		nil,
		keydescriptor.Descriptor{},
	); err == nil {
		t.Fatal("empty TLCP identity boundary was silently skipped")
	}
}

func testProofSignerDescriptor(publicKey ed25519.PublicKey) keydescriptor.Descriptor {
	return keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindSigner,
		Provider:      keydescriptor.ProviderSoftware,
		CryptoSuite:   cryptosuite.INTLV1,
		KeyID:         "active-proof",
		Algorithm:     cryptosuite.SignatureEd25519,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: cryptosuite.Ed25519PublicKeyEncoding,
			Bytes:    append([]byte(nil), publicKey...),
		},
		Software: &keydescriptor.SoftwareKeyReference{
			MaterialPath: "active-proof.key",
			Encoding:     cryptosuite.Ed25519PrivateKeyEncoding,
			Protection:   keydescriptor.SoftwareProtectionPlaintextDev,
		},
	}
}

func mustPublicDescriptor(
	t *testing.T,
	descriptor keydescriptor.Descriptor,
) trustcrypto.PublicKeyDescriptor {
	t.Helper()
	publicKey, err := descriptor.PublicKeyDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}
