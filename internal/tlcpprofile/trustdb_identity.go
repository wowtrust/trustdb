package tlcpprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	TrustDBIdentityManifestSchema   = "trustdb.active-public-identities.v1"
	MaxTrustDBIdentityManifestBytes = 256 << 10

	identityRoleProofSigner    = "proof_signer"
	identityRoleRegistrySigner = "registry_signer"
)

type TrustDBIdentityManifest struct {
	SchemaVersion  string          `json:"schema_version"`
	ProofSigner    PublicIdentity  `json:"proof_signer"`
	RegistrySigner *PublicIdentity `json:"registry_signer,omitempty"`
}

type PublicIdentity struct {
	Role                 string `json:"role"`
	KeyID                string `json:"key_id"`
	CryptoSuite          string `json:"crypto_suite"`
	Algorithm            string `json:"algorithm"`
	PublicKeyEncoding    string `json:"public_key_encoding"`
	DescriptorCBORBase64 string `json:"descriptor_cbor_base64"`
	DescriptorSHA256     string `json:"descriptor_sha256"`
	PublicKeySHA256      string `json:"public_key_sha256"`
}

// WriteTrustDBIdentityManifest publishes only public verifier descriptors and
// fingerprints. The caller is TrustDB's serve startup after it has resolved
// the active signer and compared it with the configured public descriptor.
func WriteTrustDBIdentityManifest(
	path string,
	proofDescriptor []byte,
	registryDescriptor []byte,
) (TrustDBIdentityManifest, error) {
	if err := validateAbsoluteCleanPath("trustdb_identity_manifest_file", path); err != nil {
		return TrustDBIdentityManifest{}, err
	}
	proof, _, err := publicIdentityFromDescriptor(
		identityRoleProofSigner,
		proofDescriptor,
	)
	if err != nil {
		return TrustDBIdentityManifest{}, fmt.Errorf("active proof signer: %w", err)
	}
	manifest := TrustDBIdentityManifest{
		SchemaVersion: TrustDBIdentityManifestSchema,
		ProofSigner:   proof,
	}
	if len(registryDescriptor) != 0 {
		registry, _, err := publicIdentityFromDescriptor(
			identityRoleRegistrySigner,
			registryDescriptor,
		)
		if err != nil {
			return TrustDBIdentityManifest{}, fmt.Errorf("active registry signer: %w", err)
		}
		if registry.PublicKeySHA256 == proof.PublicKeySHA256 {
			return TrustDBIdentityManifest{}, errors.New(
				"active proof signer and registry signer must be distinct",
			)
		}
		manifest.RegistrySigner = &registry
	}
	data, err := encodeTrustDBIdentityManifest(manifest)
	if err != nil {
		return TrustDBIdentityManifest{}, err
	}
	if err := atomicWritePublicIdentityFile(path, data); err != nil {
		return TrustDBIdentityManifest{}, fmt.Errorf(
			"write TrustDB active identity manifest: %w",
			err,
		)
	}
	return manifest, nil
}

func loadTrustDBIdentityManifest(
	path string,
) (TrustDBIdentityManifest, []proofKeyInventory, string, error) {
	data, err := readBoundedRegularFile(path, MaxTrustDBIdentityManifestBytes)
	if err != nil {
		return TrustDBIdentityManifest{}, nil, "", fmt.Errorf(
			"read TrustDB active identity manifest: %w",
			err,
		)
	}
	var manifest TrustDBIdentityManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return TrustDBIdentityManifest{}, nil, "", fmt.Errorf(
			"decode TrustDB active identity manifest: %w",
			err,
		)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return TrustDBIdentityManifest{}, nil, "", errors.New(
			"TrustDB active identity manifest contains trailing data",
		)
	}
	canonical, err := encodeTrustDBIdentityManifest(manifest)
	if err != nil {
		return TrustDBIdentityManifest{}, nil, "", err
	}
	if !bytes.Equal(canonical, data) {
		return TrustDBIdentityManifest{}, nil, "", errors.New(
			"TrustDB active identity manifest is not canonical",
		)
	}
	if manifest.SchemaVersion != TrustDBIdentityManifestSchema {
		return TrustDBIdentityManifest{}, nil, "", fmt.Errorf(
			"TrustDB active identity manifest schema_version must be %q",
			TrustDBIdentityManifestSchema,
		)
	}
	_, proofInventory, err := validatePublicIdentity(
		identityRoleProofSigner,
		manifest.ProofSigner,
	)
	if err != nil {
		return TrustDBIdentityManifest{}, nil, "", fmt.Errorf("active proof signer: %w", err)
	}
	inventory := []proofKeyInventory{proofInventory}
	if manifest.RegistrySigner != nil {
		_, registryInventory, err := validatePublicIdentity(
			identityRoleRegistrySigner,
			*manifest.RegistrySigner,
		)
		if err != nil {
			return TrustDBIdentityManifest{}, nil, "", fmt.Errorf(
				"active registry signer: %w",
				err,
			)
		}
		if registryInventory.publicKeySHA256 == proofInventory.publicKeySHA256 {
			return TrustDBIdentityManifest{}, nil, "", errors.New(
				"active proof signer and registry signer must be distinct",
			)
		}
	}
	return manifest, inventory, digestBytes(data), nil
}

func publicIdentityFromDescriptor(
	role string,
	data []byte,
) (PublicIdentity, proofKeyInventory, error) {
	descriptor, err := decodeProofKeyDescriptor(data)
	if err != nil {
		return PublicIdentity{}, proofKeyInventory{}, err
	}
	publicKeyDER, err := proofPublicKeyDER(descriptor)
	if err != nil {
		return PublicIdentity{}, proofKeyInventory{}, err
	}
	descriptorHash := sha256.Sum256(data)
	publicKeyHash := sha256.Sum256(publicKeyDER)
	inventory := proofKeyInventory{
		descriptorSHA256: hex.EncodeToString(descriptorHash[:]),
		publicKeySHA256:  hex.EncodeToString(publicKeyHash[:]),
	}
	return PublicIdentity{
		Role:                 role,
		KeyID:                descriptor.KeyID,
		CryptoSuite:          string(descriptor.CryptoSuite),
		Algorithm:            descriptor.Algorithm,
		PublicKeyEncoding:    descriptor.PublicKey.Encoding,
		DescriptorCBORBase64: base64.StdEncoding.EncodeToString(data),
		DescriptorSHA256:     inventory.descriptorSHA256,
		PublicKeySHA256:      inventory.publicKeySHA256,
	}, inventory, nil
}

func validatePublicIdentity(
	role string,
	identity PublicIdentity,
) (proofKeyDescriptor, proofKeyInventory, error) {
	if identity.Role != role {
		return proofKeyDescriptor{}, proofKeyInventory{}, fmt.Errorf(
			"role must be %q",
			role,
		)
	}
	data, err := base64.StdEncoding.Strict().DecodeString(identity.DescriptorCBORBase64)
	if err != nil || base64.StdEncoding.EncodeToString(data) != identity.DescriptorCBORBase64 {
		return proofKeyDescriptor{}, proofKeyInventory{}, errors.New(
			"descriptor_cbor_base64 is not canonical base64",
		)
	}
	expected, inventory, err := publicIdentityFromDescriptor(role, data)
	if err != nil {
		return proofKeyDescriptor{}, proofKeyInventory{}, err
	}
	if identity != expected {
		return proofKeyDescriptor{}, proofKeyInventory{}, errors.New(
			"public identity metadata does not match its canonical descriptor",
		)
	}
	descriptor, err := decodeProofKeyDescriptor(data)
	return descriptor, inventory, err
}

func encodeTrustDBIdentityManifest(
	manifest TrustDBIdentityManifest,
) ([]byte, error) {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode TrustDB active identity manifest: %w", err)
	}
	return append(data, '\n'), nil
}

func atomicWritePublicIdentityFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o644); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
