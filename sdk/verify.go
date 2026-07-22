package sdk

import (
	"io"

	"github.com/wowtrust/trustdb/internal/sproof"
	"github.com/wowtrust/trustdb/internal/verify"
)

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
	}
	return verifyProofBundle(raw, artifacts.Bundle, keys, verifyOpts...)
}

func verifyProofBundle(raw io.Reader, bundle ProofBundle, keys TrustedKeys, opts ...verify.Option) (VerifyResult, error) {
	result, err := verify.ProofBundle(raw, bundle, verify.TrustedKeys{
		ClientPublicKey: keys.ClientPublicKey,
		ServerPublicKey: keys.ServerPublicKey,
	}, opts...)
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
