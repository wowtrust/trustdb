package keydescriptor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
)

func TestDescriptorCanonicalRoundTripEveryProvider(t *testing.T) {
	t.Parallel()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := intlDescriptor(publicKey)
	tests := map[string]Descriptor{
		"public": func() Descriptor {
			d := base
			d.Kind = KindVerifier
			d.Provider = ProviderPublic
			return d
		}(),
		"software": func() Descriptor {
			d := base
			d.Software = &SoftwareKeyReference{
				MaterialPath: "client.material",
				Encoding:     cryptosuite.Ed25519PrivateKeyEncoding,
				Protection:   SoftwareProtectionPlaintextDev,
			}
			return d
		}(),
		"pkcs11": func() Descriptor {
			d := base
			d.Provider = ProviderPKCS11
			d.PKCS11 = &PKCS11KeyReference{URI: "pkcs11:object=trustdb;type=private"}
			return d
		}(),
		"sdf": func() Descriptor {
			d := base
			d.Provider = ProviderSDF
			d.SDF = &SDFKeyReference{DeviceRef: "device-a", KeyIndex: 7, CredentialRef: "env:SDF_PIN"}
			return d
		}(),
		"remote": func() Descriptor {
			d := base
			d.Provider = ProviderRemote
			d.Remote = &RemoteKeyReference{
				Endpoint:      "https://kms.example.test",
				Handle:        "keys/trustdb/client",
				CredentialRef: "env:KMS_TOKEN",
			}
			return d
		}(),
	}
	for name, descriptor := range tests {
		descriptor := descriptor
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			encoded, err := Marshal(descriptor)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			decoded, err := Unmarshal(encoded)
			if err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			reencoded, err := Marshal(decoded)
			if err != nil {
				t.Fatalf("Marshal(decoded) error = %v", err)
			}
			if !bytes.Equal(encoded, reencoded) {
				t.Fatal("descriptor encoding is not stable")
			}
		})
	}
}

func TestVerifierDescriptorCanonicalGolden(t *testing.T) {
	t.Parallel()
	descriptor := intlDescriptor(bytes.Repeat([]byte{1}, ed25519.PublicKeySize))
	descriptor.Kind = KindVerifier
	descriptor.Provider = ProviderPublic
	descriptor.KeyID = "golden-key"
	encoded, err := Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	const wantHex = "a7646b696e64687665726966696572666b65795f69646a676f6c64656e2d6b65796870726f7669646572667075626c696369616c676f726974686d67656432353531396a7075626c69635f6b6579a26562797465735820010101010101010101010101010101010101010101010101010101010101010168656e636f64696e67737261772d33322d627974652d726663383033326c63727970746f5f737569746567494e544c5f56316e736368656d615f76657273696f6e7819747275737464622e6b65792d64657363726970746f722e7631"
	if got := hex.EncodeToString(encoded); got != wantHex {
		t.Fatalf("canonical descriptor = %s", got)
	}
}

func TestDescriptorSM2Policy(t *testing.T) {
	t.Parallel()
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := Descriptor{
		SchemaVersion: SchemaV1,
		Kind:          KindSigner,
		Provider:      ProviderSoftware,
		CryptoSuite:   cryptosuite.CNSMV1,
		KeyID:         "sm2-key",
		Algorithm:     cryptosuite.SignatureSM2SM3,
		SM2UserID:     cryptosuite.SM2DefaultUserID,
		PublicKey: PublicKeyMaterial{
			Encoding: cryptosuite.SM2PublicKeyEncoding,
			Bytes:    elliptic.Marshal(sm2.P256(), privateKey.X, privateKey.Y),
		},
		Software: &SoftwareKeyReference{
			MaterialPath: "sm2.material",
			Encoding:     cryptosuite.SM2PrivateKeyEncoding,
			Protection:   SoftwareProtectionSM4Envelope,
		},
	}
	if _, err := Marshal(descriptor); err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	descriptor.SM2UserID = "different-user"
	if err := descriptor.Validate(); err == nil || !strings.Contains(err.Error(), "sm2_user_id") {
		t.Fatalf("Validate() error = %v, want SM2 user ID rejection", err)
	}
}

func TestDescriptorRejectsInvalidUnionAndProviderDetails(t *testing.T) {
	t.Parallel()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := intlDescriptor(publicKey)
	valid.Software = &SoftwareKeyReference{
		MaterialPath: "key.material",
		Encoding:     cryptosuite.Ed25519PrivateKeyEncoding,
		Protection:   SoftwareProtectionPlaintextDev,
	}
	tests := map[string]func(Descriptor) Descriptor{
		"unknown provider": func(d Descriptor) Descriptor { d.Provider = "unknown"; return d },
		"multiple references": func(d Descriptor) Descriptor {
			d.Remote = &RemoteKeyReference{Endpoint: "https://kms.example", Handle: "key", CredentialRef: "env:TOKEN"}
			return d
		},
		"absolute material":      func(d Descriptor) Descriptor { d.Software.MaterialPath = "/tmp/key"; return d },
		"traversing material":    func(d Descriptor) Descriptor { d.Software.MaterialPath = "../key"; return d },
		"wrong private encoding": func(d Descriptor) Descriptor { d.Software.Encoding = "raw"; return d },
		"pkcs11 secret": func(d Descriptor) Descriptor {
			d.Provider, d.Software = ProviderPKCS11, nil
			d.PKCS11 = &PKCS11KeyReference{URI: "pkcs11:object=key;pin-value=secret;type=private"}
			return d
		},
		"pkcs11 public": func(d Descriptor) Descriptor {
			d.Provider, d.Software = ProviderPKCS11, nil
			d.PKCS11 = &PKCS11KeyReference{URI: "pkcs11:object=key;type=public"}
			return d
		},
		"pkcs11 unsorted": func(d Descriptor) Descriptor {
			d.Provider, d.Software = ProviderPKCS11, nil
			d.PKCS11 = &PKCS11KeyReference{URI: "pkcs11:token=token;object=key;type=private"}
			return d
		},
		"remote http": func(d Descriptor) Descriptor {
			d.Provider, d.Software = ProviderRemote, nil
			d.Remote = &RemoteKeyReference{Endpoint: "http://kms.example", Handle: "key", CredentialRef: "env:TOKEN"}
			return d
		},
		"remote credentials": func(d Descriptor) Descriptor {
			d.Provider, d.Software = ProviderRemote, nil
			d.Remote = &RemoteKeyReference{Endpoint: "https://user:pass@kms.example", Handle: "key", CredentialRef: "env:TOKEN"}
			return d
		},
		"verifier signer reference": func(d Descriptor) Descriptor {
			d.Kind, d.Provider = KindVerifier, ProviderPublic
			return d
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			descriptor := mutate(valid.Clone())
			if err := descriptor.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestDescriptorDiagnosticsAreSecretSafe(t *testing.T) {
	t.Parallel()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptors := []Descriptor{
		func() Descriptor {
			d := intlDescriptor(publicKey)
			d.Software = &SoftwareKeyReference{MaterialPath: "private/secret.key", Encoding: cryptosuite.Ed25519PrivateKeyEncoding, Protection: SoftwareProtectionPlaintextDev}
			return d
		}(),
		func() Descriptor {
			d := intlDescriptor(publicKey)
			d.Provider = ProviderPKCS11
			d.PKCS11 = &PKCS11KeyReference{URI: "pkcs11:object=secret-key;token=secret-token;type=private"}
			return d
		}(),
		func() Descriptor {
			d := intlDescriptor(publicKey)
			d.Provider = ProviderSDF
			d.SDF = &SDFKeyReference{DeviceRef: "secret-device", KeyIndex: 9, CredentialRef: "secret-pin-ref"}
			return d
		}(),
		func() Descriptor {
			d := intlDescriptor(publicKey)
			d.Provider = ProviderRemote
			d.Remote = &RemoteKeyReference{Endpoint: "https://secret-kms.example", Handle: "secret-handle", CredentialRef: "secret-token-ref"}
			return d
		}(),
	}
	secrets := []string{"private/secret.key", "secret-token", "secret-key", "secret-device", "secret-pin-ref", "secret-kms", "secret-handle", "secret-token-ref"}
	for _, descriptor := range descriptors {
		outputs := []string{descriptor.String()}
		encoded, err := json.Marshal(descriptor)
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, string(encoded))
		for _, output := range outputs {
			for _, secret := range secrets {
				if strings.Contains(output, secret) {
					t.Fatalf("diagnostic leaked %q: %s", secret, output)
				}
			}
		}
	}
}

func TestDescriptorCertificateChainBindsLeafKey(t *testing.T) {
	t.Parallel()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &smx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TrustDB Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              smx509.KeyUsageCertSign,
	}
	caDER, err := smx509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &smx509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "TrustDB Signer"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     smx509.KeyUsageDigitalSignature,
	}
	leafDER, err := smx509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, leafPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := intlDescriptor(leafPublic)
	descriptor.Kind = KindVerifier
	descriptor.Provider = ProviderPublic
	descriptor.CertificateChain = [][]byte{leafDER, caDER}
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	descriptor.PublicKey.Bytes = caPublic
	if err := descriptor.Validate(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Validate() error = %v, want leaf mismatch", err)
	}
}

func TestDescriptorSM2CertificateBindsLeafKey(t *testing.T) {
	t.Parallel()
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &smx509.Certificate{
		SerialNumber: big.NewInt(8),
		Subject:      pkix.Name{CommonName: "TrustDB SM2 Signer"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     smx509.KeyUsageDigitalSignature,
	}
	der, err := smx509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := Descriptor{
		SchemaVersion: SchemaV1,
		Kind:          KindVerifier,
		Provider:      ProviderPublic,
		CryptoSuite:   cryptosuite.CNSMV1,
		KeyID:         "sm2-cert-key",
		Algorithm:     cryptosuite.SignatureSM2SM3,
		SM2UserID:     cryptosuite.SM2DefaultUserID,
		PublicKey: PublicKeyMaterial{
			Encoding: cryptosuite.SM2PublicKeyEncoding,
			Bytes:    elliptic.Marshal(sm2.P256(), privateKey.X, privateKey.Y),
		},
		CertificateChain: [][]byte{der},
	}
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	descriptor.CryptoSuite = cryptosuite.INTLV1
	descriptor.Algorithm = cryptosuite.SignatureEd25519
	descriptor.SM2UserID = ""
	descriptor.PublicKey.Encoding = cryptosuite.Ed25519PublicKeyEncoding
	descriptor.PublicKey.Bytes = bytes.Repeat([]byte{1}, ed25519.PublicKeySize)
	if err := descriptor.Validate(); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("Validate(wrong suite) error = %v", err)
	}
}

func TestUnmarshalRejectsUnknownTrailingAndNonCanonicalData(t *testing.T) {
	t.Parallel()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := intlDescriptor(publicKey)
	descriptor.Kind = KindVerifier
	descriptor.Provider = ProviderPublic
	canonical, err := Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unmarshal(append(append([]byte(nil), canonical...), 0)); err == nil {
		t.Fatal("Unmarshal() accepted trailing data")
	}
	var fields map[string]any
	if err := cborx.Unmarshal(canonical, &fields); err != nil {
		t.Fatal(err)
	}
	fields["unknown"] = "rejected"
	unknown, err := cborx.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unmarshal(unknown); err == nil {
		t.Fatal("Unmarshal() accepted unknown field")
	}
	if _, err := Unmarshal(make([]byte, maxDescriptorBytes+1)); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("Unmarshal(oversized) error = %v", err)
	}
}

func TestDescriptorCloneOwnsMutableData(t *testing.T) {
	t.Parallel()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := intlDescriptor(publicKey)
	descriptor.Kind = KindVerifier
	descriptor.Provider = ProviderPublic
	descriptor.CertificateChain = [][]byte{{1, 2, 3}}
	clone := descriptor.Clone()
	clone.PublicKey.Bytes[0] ^= 0xff
	clone.CertificateChain[0][0] ^= 0xff
	if bytes.Equal(clone.PublicKey.Bytes, descriptor.PublicKey.Bytes) || bytes.Equal(clone.CertificateChain[0], descriptor.CertificateChain[0]) {
		t.Fatal("Clone() retained mutable aliases")
	}
}

func FuzzUnmarshal(f *testing.F) {
	publicKey := bytes.Repeat([]byte{1}, ed25519.PublicKeySize)
	descriptor := intlDescriptor(publicKey)
	descriptor.Kind = KindVerifier
	descriptor.Provider = ProviderPublic
	if encoded, err := Marshal(descriptor); err == nil {
		f.Add(encoded)
	}
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, data []byte) {
		descriptor, err := Unmarshal(data)
		if err != nil {
			return
		}
		encoded, err := Marshal(descriptor)
		if err != nil {
			t.Fatalf("Marshal(accepted descriptor) error = %v", err)
		}
		if !bytes.Equal(data, encoded) {
			t.Fatal("accepted descriptor was not canonical")
		}
	})
}

func intlDescriptor(publicKey ed25519.PublicKey) Descriptor {
	return Descriptor{
		SchemaVersion: SchemaV1,
		Kind:          KindSigner,
		Provider:      ProviderSoftware,
		CryptoSuite:   cryptosuite.INTLV1,
		KeyID:         "test-key",
		Algorithm:     cryptosuite.SignatureEd25519,
		PublicKey: PublicKeyMaterial{
			Encoding: cryptosuite.Ed25519PublicKeyEncoding,
			Bytes:    append([]byte(nil), publicKey...),
		},
	}
}
