package sdk

import (
	"context"
	"fmt"
	"io"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/sproof"
	"github.com/wowtrust/trustdb/internal/verify"
	"github.com/wowtrust/trustdb/sdk/anchorplugin"
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
