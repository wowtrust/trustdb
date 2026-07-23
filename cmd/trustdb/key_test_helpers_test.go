package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
)

// writeKey keeps test fixtures concise while exercising the production
// descriptor readers. Runtime code has no raw-key fallback.
func writeKey(path string, key []byte) error {
	keyID := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)) + "-key"
	switch len(key) {
	case ed25519.PublicKeySize:
		return writeKeyDescriptor(path, testVerifierDescriptor(keyID, key))
	case ed25519.PrivateKeySize:
		privateKey := ed25519.PrivateKey(key)
		materialName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)) + ".material"
		if err := writeFileAtomic(filepath.Join(filepath.Dir(path), materialName), []byte(base64.RawURLEncoding.EncodeToString(privateKey)), 0o600); err != nil {
			return err
		}
		descriptor := testVerifierDescriptor(keyID, privateKey.Public().(ed25519.PublicKey))
		descriptor.Kind = keydescriptor.KindSigner
		descriptor.Provider = keydescriptor.ProviderSoftware
		descriptor.Software = &keydescriptor.SoftwareKeyReference{
			MaterialPath: materialName,
			Encoding:     cryptosuite.Ed25519PrivateKeyEncoding,
			Protection:   keydescriptor.SoftwareProtectionPlaintextDev,
		}
		return writeKeyDescriptor(path, descriptor)
	default:
		return fmt.Errorf("unsupported key material size %d", len(key))
	}
}

func testVerifierDescriptor(keyID string, publicKey []byte) keydescriptor.Descriptor {
	return keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindVerifier,
		Provider:      keydescriptor.ProviderPublic,
		CryptoSuite:   cryptosuite.INTLV1,
		KeyID:         keyID,
		Algorithm:     cryptosuite.SignatureEd25519,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: cryptosuite.Ed25519PublicKeyEncoding,
			Bytes:    append([]byte(nil), publicKey...),
		},
	}
}
