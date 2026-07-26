package tlcpprofile

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"

	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
)

const (
	proofKeyDescriptorSchema   = "trustdb.key-descriptor.v1"
	maxProofKeyDescriptorBytes = 2 << 20
	maxProofCertificateCount   = 16
)

// proofKeyDescriptor is the public-only projection of TrustDB's canonical key
// descriptor. Provider-specific fields are retained solely so the decoder can
// reject any descriptor that carries a private-key location or credential
// reference across the gateway boundary.
type proofKeyDescriptor struct {
	SchemaVersion    string                 `cbor:"schema_version"`
	Kind             string                 `cbor:"kind"`
	Provider         string                 `cbor:"provider"`
	CryptoSuite      cryptosuite.ID         `cbor:"crypto_suite"`
	KeyID            string                 `cbor:"key_id"`
	Algorithm        string                 `cbor:"algorithm"`
	SM2UserID        string                 `cbor:"sm2_user_id,omitempty"`
	PublicKey        proofPublicKeyMaterial `cbor:"public_key"`
	CertificateChain [][]byte               `cbor:"certificate_chain,omitempty"`
	Software         any                    `cbor:"software,omitempty"`
	PKCS11           any                    `cbor:"pkcs11,omitempty"`
	SDF              any                    `cbor:"sdf,omitempty"`
	Remote           any                    `cbor:"remote,omitempty"`
}

type proofPublicKeyMaterial struct {
	Encoding string `cbor:"encoding"`
	Bytes    []byte `cbor:"bytes"`
}

type proofKeyInventory struct {
	descriptorSHA256 string
	publicKeySHA256  string
}

func decodeProofKeyDescriptor(data []byte) (proofKeyDescriptor, error) {
	var descriptor proofKeyDescriptor
	if err := cborx.UnmarshalLimits(
		data,
		&descriptor,
		maxProofKeyDescriptorBytes,
		maxProofCertificateCount,
		16,
	); err != nil {
		return proofKeyDescriptor{}, err
	}
	canonical, err := cborx.Marshal(descriptor)
	if err != nil {
		return proofKeyDescriptor{}, err
	}
	if !bytes.Equal(canonical, data) {
		return proofKeyDescriptor{}, errors.New("proof-key descriptor is not canonical")
	}
	if descriptor.SchemaVersion != proofKeyDescriptorSchema ||
		descriptor.Kind != "verifier" ||
		descriptor.Provider != "public" {
		return proofKeyDescriptor{}, errors.New(
			"proof-key descriptor must be a canonical TrustDB public verifier descriptor",
		)
	}
	if descriptor.Software != nil || descriptor.PKCS11 != nil ||
		descriptor.SDF != nil || descriptor.Remote != nil {
		return proofKeyDescriptor{}, errors.New(
			"proof-key descriptor contains a private provider reference",
		)
	}
	if err := validateString("proof-key descriptor key_id", descriptor.KeyID); err != nil {
		return proofKeyDescriptor{}, err
	}
	suite, err := cryptosuite.RequireKnown(descriptor.CryptoSuite)
	if err != nil {
		return proofKeyDescriptor{}, err
	}
	if descriptor.Algorithm != suite.Signature.Algorithm ||
		descriptor.PublicKey.Encoding != suite.Signature.PublicKeyEncoding {
		return proofKeyDescriptor{}, errors.New(
			"proof-key descriptor algorithm or public-key encoding does not match its suite",
		)
	}
	switch descriptor.CryptoSuite {
	case cryptosuite.INTLV1:
		if descriptor.SM2UserID != "" ||
			len(descriptor.PublicKey.Bytes) != ed25519.PublicKeySize {
			return proofKeyDescriptor{}, errors.New("invalid Ed25519 proof-key descriptor")
		}
	case cryptosuite.CNSMV1:
		if descriptor.SM2UserID != cryptosuite.SM2DefaultUserID {
			return proofKeyDescriptor{}, errors.New("invalid SM2 proof-key user ID")
		}
		if _, err := sm2.NewPublicKey(descriptor.PublicKey.Bytes); err != nil {
			return proofKeyDescriptor{}, fmt.Errorf("invalid SM2 proof public key: %w", err)
		}
	default:
		return proofKeyDescriptor{}, fmt.Errorf(
			"unsupported proof-key crypto suite %q",
			descriptor.CryptoSuite,
		)
	}
	return descriptor, nil
}

func proofPublicKeyDER(descriptor proofKeyDescriptor) ([]byte, error) {
	switch descriptor.CryptoSuite {
	case cryptosuite.INTLV1:
		return smx509.MarshalPKIXPublicKey(ed25519.PublicKey(descriptor.PublicKey.Bytes))
	case cryptosuite.CNSMV1:
		publicKey, err := sm2.NewPublicKey(descriptor.PublicKey.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse SM2 public key: %w", err)
		}
		return smx509.MarshalPKIXPublicKey(publicKey)
	default:
		return nil, fmt.Errorf("unsupported crypto suite %q", descriptor.CryptoSuite)
	}
}
