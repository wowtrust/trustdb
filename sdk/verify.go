package sdk

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/wowtrust/trustdb/v2/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/sproof"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
	"github.com/wowtrust/trustdb/v2/internal/verify"
	"github.com/wowtrust/trustdb/v2/sdk/anchorplugin"
)

type OfflineStageStatus = sproof.OfflineStageStatus
type OfflineStageResult = sproof.OfflineStageResult
type OfflineVerifyResult = sproof.OfflineResult
type OfflineIdentityReport = sproof.IdentityReport

const (
	OfflineStagePassed     = sproof.OfflineStagePassed
	OfflineStageFailed     = sproof.OfflineStageFailed
	OfflineStageNotPresent = sproof.OfflineStageNotPresent
	OfflineStageSkipped    = sproof.OfflineStageSkipped
	OfflineStageNotRun     = sproof.OfflineStageNotRun

	OfflineStageBCOSReceiptInclusion = sproof.OfflineStageBCOSReceiptInclusion
	OfflineStageBCOSPBFTFinality     = sproof.OfflineStageBCOSPBFTFinality
	OfflineStageBCOSAnchorBinding    = sproof.OfflineStageBCOSAnchorBinding
)

// OfflineIdentityTrust is verifier-local trust. Public keys or certificates
// embedded in an evidence file never populate this structure automatically.
type OfflineIdentityTrust struct {
	ClientPublicKeys         []KeyDescriptor
	ServerPublicKeys         []KeyDescriptor
	ClientCertificateRoots   [][]byte
	ServerCertificateRoots   [][]byte
	RegistryPublicKey        KeyDescriptor
	RequireEvidence          bool
	RequireCertificateStatus bool
}

type OfflineTrust struct {
	Proof     TrustedKeys
	Identity  OfflineIdentityTrust
	FISCOBCOS *FISCOBCOSTrustConfig
}

// FISCOBCOSTrustConfig is verifier-local chain and contract trust. Offline
// verification compares it to evidence but never opens its endpoints,
// provider references, keys, or certificates.
type FISCOBCOSTrustConfig = fiscobcos.TrustConfig

type OfflineVerifyOptions struct {
	SkipAnchor bool
}

func ReadSingleProofFile(path string) (SingleProof, error) {
	return sproof.ReadFile(path)
}

func WriteSingleProofFile(path string, proof SingleProof) error {
	return sproof.WriteFile(path, proof)
}

func VerifySingleProof(raw io.Reader, proof SingleProof, keys TrustedKeys, opts VerifyOptions) (VerifyResult, error) {
	if err := sproof.Validate(proof); err != nil {
		return VerifyResult{}, err
	}
	verifyOpts := []verify.Option{}
	if proof.GlobalProof != nil {
		verifyOpts = append(verifyOpts, verify.WithGlobalProof(*proof.GlobalProof))
	}
	if proof.AnchorResult != nil && !opts.SkipAnchor {
		verifyOpts = append(verifyOpts, verify.WithAnchor(*proof.AnchorResult))
		if opts.AnchorVerifier != nil {
			verifyOpts = append(verifyOpts, verify.WithAnchorVerifier(sdkAnchorVerifier{verifier: opts.AnchorVerifier}))
		}
	}
	return verifyProofBundle(raw, proof.ProofBundle, keys, verifyOpts...)
}

func VerifyProofBundle(raw io.Reader, bundle ProofBundle, keys TrustedKeys) (VerifyResult, error) {
	return verifyProofBundle(raw, bundle, keys)
}

func VerifyArtifacts(raw io.Reader, artifacts ProofArtifacts, keys TrustedKeys, opts VerifyOptions) (VerifyResult, error) {
	verifyOpts := []verify.Option{}
	if artifacts.GlobalProof != nil {
		verifyOpts = append(verifyOpts, verify.WithGlobalProof(*artifacts.GlobalProof))
	}
	if artifacts.AnchorResult != nil && !opts.SkipAnchor {
		verifyOpts = append(verifyOpts, verify.WithAnchor(*artifacts.AnchorResult))
		if opts.AnchorVerifier != nil {
			verifyOpts = append(verifyOpts, verify.WithAnchorVerifier(sdkAnchorVerifier{verifier: opts.AnchorVerifier}))
		}
	}
	return verifyProofBundle(raw, artifacts.Bundle, keys, verifyOpts...)
}

// VerifySingleProofOffline verifies content, signatures, Merkle paths,
// identity lifecycle/certificate evidence, and optional anchors without
// server, DNS, network, CA, or external provider access.
func VerifySingleProofOffline(
	raw io.Reader,
	proof SingleProof,
	trust OfflineTrust,
	opts OfflineVerifyOptions,
) (OfflineVerifyResult, error) {
	provider, err := trustcrypto.ProviderForSuite(proof.CryptoSuite)
	if err != nil {
		return OfflineVerifyResult{}, err
	}
	proofKeys, err := internalTrustedKeys(proof.CryptoSuite, trust.Proof)
	if err != nil {
		return OfflineVerifyResult{}, err
	}
	proofKeys.CryptoProvider = provider
	identity, err := internalIdentityTrust(proof.CryptoSuite, trust.Identity)
	if err != nil {
		return OfflineVerifyResult{}, err
	}
	return sproof.VerifyOffline(raw, proof, sproof.OfflineTrust{
		Proof:     proofKeys,
		Identity:  identity,
		FISCOBCOS: trust.FISCOBCOS,
	}, sproof.OfflineOptions{SkipAnchor: opts.SkipAnchor})
}

type sdkAnchorVerifier struct{ verifier AnchorVerifier }

func (v sdkAnchorVerifier) VerifyAnchor(sth model.SignedTreeHead, result model.STHAnchorResult) error {
	info := v.verifier.Info()
	if info.SinkName != result.SinkName {
		return fmt.Errorf("anchor plugin %q cannot verify sink %q", info.SinkName, result.SinkName)
	}
	return v.verifier.Verify(context.Background(), anchorPluginSTH(sth), anchorplugin.AnchorResult{
		AnchorID:         result.AnchorID,
		Proof:            append([]byte(nil), result.Proof...),
		PublishedAtUnixN: result.PublishedAtUnixN,
	})
}

func anchorPluginSTH(sth model.SignedTreeHead) anchorplugin.SignedTreeHead {
	return anchorplugin.SignedTreeHead{
		SchemaVersion:  sth.SchemaVersion,
		TreeAlg:        sth.TreeAlg,
		TreeSize:       sth.TreeSize,
		RootHash:       append([]byte(nil), sth.RootHash...),
		TimestampUnixN: sth.TimestampUnixN,
		NodeID:         sth.NodeID,
		LogID:          sth.LogID,
		Signature: anchorplugin.Signature{
			Alg:       sth.Signature.Alg,
			KeyID:     sth.Signature.KeyID,
			Signature: append([]byte(nil), sth.Signature.Signature...),
		},
	}
}

func verifyProofBundle(raw io.Reader, bundle ProofBundle, keys TrustedKeys, opts ...verify.Option) (VerifyResult, error) {
	trusted, err := internalTrustedKeys(bundle.CryptoSuite, keys)
	if err != nil {
		return VerifyResult{}, err
	}
	if len(trusted.ClientPublicKey.Bytes) == 0 {
		return VerifyResult{}, errors.New("sdk: client public key is required")
	}
	if len(trusted.ServerPublicKey.Bytes) == 0 &&
		(len(trusted.AcceptedReceiptPublicKey.Bytes) == 0 || len(trusted.CommittedReceiptPublicKey.Bytes) == 0) {
		return VerifyResult{}, errors.New("sdk: server public key or both receipt-specific public keys are required")
	}
	provider, err := trustcrypto.ProviderForSuite(bundle.CryptoSuite)
	if err != nil {
		return VerifyResult{}, err
	}
	trusted.CryptoProvider = provider
	result, err := verify.ProofBundle(raw, bundle, trusted, opts...)
	if err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{
		Valid:      result.Valid,
		RecordID:   result.RecordID,
		ProofLevel: result.ProofLevel,
		AnchorSink: result.AnchorSink,
		AnchorID:   result.AnchorID,
	}, nil
}

func internalTrustedKeys(suite CryptoSuite, keys TrustedKeys) (verify.TrustedKeys, error) {
	if _, err := cryptosuite.RequireAvailable(suite); err != nil {
		return verify.TrustedKeys{}, err
	}
	client, err := optionalInternalDescriptor(suite, "client public key", keys.ClientPublicKey)
	if err != nil {
		return verify.TrustedKeys{}, err
	}
	server, err := optionalInternalDescriptor(suite, "server public key", keys.ServerPublicKey)
	if err != nil {
		return verify.TrustedKeys{}, err
	}
	accepted, err := optionalInternalDescriptor(suite, "accepted receipt public key", keys.AcceptedReceiptPublicKey)
	if err != nil {
		return verify.TrustedKeys{}, err
	}
	committed, err := optionalInternalDescriptor(suite, "committed receipt public key", keys.CommittedReceiptPublicKey)
	if err != nil {
		return verify.TrustedKeys{}, err
	}
	sth, err := optionalInternalDescriptor(suite, "signed tree head public key", keys.SignedTreeHeadPublicKey)
	if err != nil {
		return verify.TrustedKeys{}, err
	}
	return verify.TrustedKeys{
		ClientPublicKey:           client,
		ServerPublicKey:           server,
		AcceptedReceiptPublicKey:  accepted,
		CommittedReceiptPublicKey: committed,
		SignedTreeHeadPublicKey:   sth,
	}, nil
}

func requiredInternalDescriptor(suite CryptoSuite, name string, descriptor KeyDescriptor) (trustcrypto.PublicKeyDescriptor, error) {
	internal, err := optionalInternalDescriptor(suite, name, descriptor)
	if err != nil {
		return trustcrypto.PublicKeyDescriptor{}, err
	}
	if len(internal.Bytes) == 0 {
		return trustcrypto.PublicKeyDescriptor{}, fmt.Errorf("sdk: %s is required", name)
	}
	return internal, nil
}

func optionalInternalDescriptor(suite CryptoSuite, name string, descriptor KeyDescriptor) (trustcrypto.PublicKeyDescriptor, error) {
	if len(descriptor.PublicKey) == 0 {
		return trustcrypto.PublicKeyDescriptor{}, nil
	}
	if err := descriptor.Validate(); err != nil {
		return trustcrypto.PublicKeyDescriptor{}, fmt.Errorf("sdk: %s: %w", name, err)
	}
	if err := cryptosuite.RequireSame(suite, descriptor.CryptoSuite); err != nil {
		return trustcrypto.PublicKeyDescriptor{}, fmt.Errorf("sdk: %s crypto_suite: %w", name, err)
	}
	return descriptor.internalPublicKey(), nil
}

func internalIdentityTrust(suite CryptoSuite, trust OfflineIdentityTrust) (sproof.IdentityTrust, error) {
	client, err := internalDescriptorList(suite, "client identity public keys", trust.ClientPublicKeys)
	if err != nil {
		return sproof.IdentityTrust{}, err
	}
	server, err := internalDescriptorList(suite, "server identity public keys", trust.ServerPublicKeys)
	if err != nil {
		return sproof.IdentityTrust{}, err
	}
	registry, err := optionalInternalDescriptor(suite, "registry public key", trust.RegistryPublicKey)
	if err != nil {
		return sproof.IdentityTrust{}, err
	}
	return sproof.IdentityTrust{
		ClientPublicKeys:         client,
		ServerPublicKeys:         server,
		ClientCertificateRoots:   cloneBytesList(trust.ClientCertificateRoots),
		ServerCertificateRoots:   cloneBytesList(trust.ServerCertificateRoots),
		RegistryPublicKey:        registry,
		RequireEvidence:          trust.RequireEvidence,
		RequireCertificateStatus: trust.RequireCertificateStatus,
	}, nil
}

func internalDescriptorList(suite CryptoSuite, name string, descriptors []KeyDescriptor) ([]trustcrypto.PublicKeyDescriptor, error) {
	out := make([]trustcrypto.PublicKeyDescriptor, len(descriptors))
	for index := range descriptors {
		descriptor, err := requiredInternalDescriptor(suite, fmt.Sprintf("%s[%d]", name, index), descriptors[index])
		if err != nil {
			return nil, err
		}
		out[index] = descriptor
	}
	return out, nil
}
