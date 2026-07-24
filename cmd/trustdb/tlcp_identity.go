package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/tlcpprofile"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func configureTLCPIdentityBoundary(
	ctx context.Context,
	profilePath string,
	manifestPath string,
	serverPublicPath string,
	registryPublicPath string,
	registryActive bool,
	activeRegistryPublic trustcrypto.PublicKeyDescriptor,
	serverSigner trustcrypto.Signer,
	serverPrivate keydescriptor.Descriptor,
) (*tlcpprofile.ActiveIdentityChallengeService, error) {
	if profilePath == "" || manifestPath == "" || serverPublicPath == "" {
		return nil, usageError(
			"TLCP identity binding requires tlcp-gateway-profile, tlcp-identity-manifest, and server-public-key",
		)
	}
	for name, path := range map[string]string{
		"TLCP gateway profile":   profilePath,
		"TLCP identity manifest": manifestPath,
		"server public key":      serverPublicPath,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, usageError(name + " must be an absolute clean path")
		}
	}
	profileData, err := readFileLimit(profilePath, tlcpprofile.MaxProfileBytes)
	if err != nil {
		return nil, fmt.Errorf("read TLCP gateway profile declaration: %w", err)
	}
	profile, err := tlcpprofile.Decode(profileData)
	if err != nil {
		return nil, err
	}
	if profile.TrustDBIdentityManifestFile != manifestPath {
		return nil, usageError(
			"TLCP gateway profile and TrustDB must name the exact same active identity manifest",
		)
	}

	configuredPublic, configuredDescriptor, err := readPublicKeyDescriptor(
		serverPublicPath,
	)
	if err != nil {
		return nil, err
	}
	proofDescriptorData, err := activeProofDescriptorData(
		ctx,
		serverSigner,
		serverPrivate,
		configuredPublic,
		configuredDescriptor,
	)
	if err != nil {
		return nil, err
	}

	var registryDescriptorData []byte
	if registryActive {
		if registryPublicPath == "" {
			return nil, usageError(
				"TLCP identity binding with a key registry requires registry-public-key",
			)
		}
		configuredRegistryPublic, registryDescriptor, err :=
			readPublicKeyDescriptor(registryPublicPath)
		if err != nil {
			return nil, err
		}
		if !samePublicKeyDescriptor(
			activeRegistryPublic,
			configuredRegistryPublic,
		) {
			return nil, usageError(
				"active TrustDB key registry does not exactly match registry-public-key",
			)
		}
		registryDescriptorData, err = keydescriptor.Marshal(registryDescriptor)
		if err != nil {
			return nil, err
		}
	}
	manifest, err := tlcpprofile.WriteTrustDBIdentityManifest(
		manifestPath,
		proofDescriptorData,
		registryDescriptorData,
	)
	if err != nil {
		return nil, err
	}
	validated, report, err := tlcpprofile.LoadAndValidate(
		profilePath,
		tlcpprofile.Options{},
	)
	if err != nil {
		return nil, fmt.Errorf("authenticate TLCP gateway profile: %w", err)
	}
	if validated.TrustDBIdentityManifestFile != manifestPath ||
		len(report.ProofSigningPublicKeySHA256) != 1 {
		return nil, errors.New(
			"TLCP gateway profile did not resolve exactly one active TrustDB proof signer",
		)
	}
	service, err := tlcpprofile.NewActiveIdentityChallengeService(
		manifest,
		serverSigner,
	)
	if err != nil {
		return nil, err
	}
	return service, nil
}

func activeProofDescriptorData(
	ctx context.Context,
	signer trustcrypto.Signer,
	privateDescriptor keydescriptor.Descriptor,
	configuredPublic trustcrypto.PublicKeyDescriptor,
	configuredDescriptor keydescriptor.Descriptor,
) ([]byte, error) {
	activePublic, err := signer.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve active TrustDB proof signer public key: %w", err)
	}
	privatePublic, err := privateDescriptor.PublicKeyDescriptor()
	if err != nil {
		return nil, err
	}
	if !samePublicKeyDescriptor(activePublic, privatePublic) ||
		!samePublicKeyDescriptor(activePublic, configuredPublic) {
		return nil, usageError(
			"active TrustDB proof signer does not exactly match server-private-key and server-public-key",
		)
	}
	return keydescriptor.Marshal(configuredDescriptor)
}

func samePublicKeyDescriptor(
	left trustcrypto.PublicKeyDescriptor,
	right trustcrypto.PublicKeyDescriptor,
) bool {
	return left.Suite == right.Suite &&
		left.KeyID == right.KeyID &&
		left.Algorithm == right.Algorithm &&
		left.Encoding == right.Encoding &&
		bytes.Equal(left.Bytes, right.Bytes)
}
