package sproof

import (
	"fmt"
	"io"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/prooflevel"
	"github.com/wowtrust/trustdb/internal/verify"
)

type OfflineStageStatus string

const (
	OfflineStagePassed     OfflineStageStatus = "passed"
	OfflineStageFailed     OfflineStageStatus = "failed"
	OfflineStageNotPresent OfflineStageStatus = "not_present"
	OfflineStageSkipped    OfflineStageStatus = "skipped"
	OfflineStageNotRun     OfflineStageStatus = "not_run"
)

const (
	OfflineStageContainer            = "sproof_container"
	OfflineStageIdentity             = "identity_evidence"
	OfflineStageBCOSReceiptInclusion = "bcos_receipt_inclusion"
	OfflineStageBCOSPBFTFinality     = "bcos_pbft_finality"
	OfflineStageBCOSAnchorBinding    = "bcos_exact_anchor_binding"
)

// OfflineStageResult is a deterministic account of each local verification
// boundary. A failed stage prevents every later applicable stage from running.
type OfflineStageResult struct {
	Name   string             `json:"name"`
	Status OfflineStageStatus `json:"status"`
	Error  string             `json:"error,omitempty"`
}

// OfflineResult reports only independently recomputed values. ProofLevel is
// never copied from the descriptive label inside the evidence file.
type OfflineResult struct {
	Valid                  bool                 `json:"valid"`
	RecordID               string               `json:"record_id,omitempty"`
	ProofLevel             string               `json:"proof_level,omitempty"`
	AnchorSink             string               `json:"anchor_sink,omitempty"`
	AnchorID               string               `json:"anchor_id,omitempty"`
	Identity               IdentityReport       `json:"identity"`
	Stages                 []OfflineStageResult `json:"stages"`
	ExternalNetworkAccess  bool                 `json:"external_network_access"`
	ExternalProviderAccess bool                 `json:"external_provider_access"`
}

type OfflineTrust struct {
	Proof     verify.TrustedKeys
	Identity  IdentityTrust
	FISCOBCOS *fiscobcos.TrustConfig
}

type OfflineOptions struct {
	SkipAnchor bool
}

// ContainerFailureResult builds the structured fail-closed result used when a
// .sproof cannot be decoded far enough to call VerifyOffline.
func ContainerFailureResult(err error) OfflineResult {
	result := OfflineResult{
		Stages: make([]OfflineStageResult, 0, 14),
	}
	result.Stages = append(result.Stages, failedOfflineStage(OfflineStageContainer, err))
	appendAfterContainerFailure(&result, model.SingleProof{}, OfflineOptions{})
	return result
}

// VerifyOffline verifies a complete .sproof without server, CA, provider, DNS,
// or network access. Every trust root must already be present in trust.
func VerifyOffline(
	raw io.Reader,
	proof model.SingleProof,
	trust OfflineTrust,
	options OfflineOptions,
) (OfflineResult, error) {
	result := OfflineResult{
		RecordID: proof.RecordID,
		Stages:   make([]OfflineStageResult, 0, 14),
	}
	if err := validateContainer(proof); err != nil {
		result.Stages = append(result.Stages, failedOfflineStage(OfflineStageContainer, err))
		appendAfterContainerFailure(&result, proof, options)
		return result, err
	}
	result.Stages = append(result.Stages, passedOfflineStage(OfflineStageContainer))

	identityReport, err := VerifyIdentityEvidence(proof, trust.Identity)
	if err != nil {
		result.Stages = append(result.Stages, failedOfflineStage(OfflineStageIdentity, err))
		appendNotRunProofStages(&result, proof, options)
		return result, err
	}
	result.Identity = identityReport
	if len(proof.IdentityEvidence) == 0 {
		result.Stages = append(result.Stages, OfflineStageResult{
			Name:   OfflineStageIdentity,
			Status: OfflineStageNotPresent,
		})
	} else {
		result.Stages = append(result.Stages, passedOfflineStage(OfflineStageIdentity))
	}

	verifyOptions := make([]verify.Option, 0, 4)
	verifyOptions = append(
		verifyOptions,
		verify.WithExactNamespaceBinding(proof.NodeID, proof.LogID),
	)
	if proof.GlobalProof != nil {
		verifyOptions = append(verifyOptions, verify.WithGlobalProof(*proof.GlobalProof))
	}
	if proof.AnchorResult != nil && !options.SkipAnchor && !isRawFISCOBCOSProof(proof) {
		verifyOptions = append(verifyOptions, verify.WithAnchor(*proof.AnchorResult))
	}
	proofTrust, err := bindEvidenceProofKeys(proof, trust.Proof)
	if err != nil {
		appendProofStages(&result, proof, options, verify.StageProofBundle, err)
		return result, err
	}
	verified, err := verify.ProofBundle(raw, proof.ProofBundle, proofTrust, verifyOptions...)
	if err != nil {
		failed, ok := verify.FailedStage(err)
		if !ok {
			failed = verify.StageProofBundle
		}
		appendProofStages(&result, proof, options, failed, err)
		return result, err
	}
	appendProofStages(&result, proof, options, "", nil)
	result.Valid = verified.Valid
	result.RecordID = verified.RecordID
	result.ProofLevel = verified.ProofLevel
	result.AnchorSink = verified.AnchorSink
	result.AnchorID = verified.AnchorID
	if isRawFISCOBCOSProof(proof) && !options.SkipAnchor {
		if trust.FISCOBCOS == nil {
			err := fmt.Errorf("sproof: verifier-local FISCO BCOS trust config is required")
			setBCOSStage(&result, OfflineStageBCOSReceiptInclusion, OfflineStageFailed, err)
			result.Valid = false
			return result, err
		}
		if err := fiscobcos.VerifyNativeReceiptInclusion(
			proof.GlobalProof.STH,
			*proof.AnchorResult,
			*trust.FISCOBCOS,
		); err != nil {
			setBCOSStage(&result, OfflineStageBCOSReceiptInclusion, OfflineStageFailed, err)
			result.Valid = false
			return result, err
		}
		setBCOSStage(&result, OfflineStageBCOSReceiptInclusion, OfflineStagePassed, nil)
		if err := fiscobcos.VerifyStaticPBFTFinality(
			proof.GlobalProof.STH,
			*proof.AnchorResult,
			*trust.FISCOBCOS,
		); err != nil {
			setBCOSStage(&result, OfflineStageBCOSPBFTFinality, OfflineStageFailed, err)
			result.Valid = false
			return result, err
		}
		setBCOSStage(&result, OfflineStageBCOSPBFTFinality, OfflineStagePassed, nil)
		if err := fiscobcos.VerifyExactAnchorBinding(
			proof.GlobalProof.STH,
			*proof.AnchorResult,
			*trust.FISCOBCOS,
		); err != nil {
			setBCOSStage(&result, OfflineStageBCOSAnchorBinding, OfflineStageFailed, err)
			result.Valid = false
			return result, err
		}
		setBCOSStage(&result, OfflineStageBCOSAnchorBinding, OfflineStagePassed, nil)
		result.AnchorSink = proof.AnchorResult.SinkName
		result.AnchorID = proof.AnchorResult.AnchorID
		result.ProofLevel = prooflevel.L5.String()
	}
	return result, nil
}

func bindEvidenceProofKeys(
	proof model.SingleProof,
	trust verify.TrustedKeys,
) (verify.TrustedKeys, error) {
	for index := range proof.IdentityEvidence {
		evidence := proof.IdentityEvidence[index]
		descriptor, err := keydescriptor.Unmarshal(evidence.KeyDescriptor)
		if err != nil {
			return verify.TrustedKeys{}, fmt.Errorf("sproof: identity_evidence[%d] descriptor: %w", index, err)
		}
		publicKey, err := descriptor.PublicKeyDescriptor()
		if err != nil {
			return verify.TrustedKeys{}, fmt.Errorf("sproof: identity_evidence[%d] public key: %w", index, err)
		}
		switch evidence.Role {
		case model.ProofIdentityRoleClient:
			if evidence.KeyID == proof.ProofBundle.SignedClaim.Signature.KeyID {
				trust.ClientPublicKey = publicKey
			}
		case model.ProofIdentityRoleServer:
			if evidence.KeyID == proof.ProofBundle.AcceptedReceipt.ServerSig.KeyID {
				trust.AcceptedReceiptPublicKey = publicKey
			}
			if evidence.KeyID == proof.ProofBundle.CommittedReceipt.ServerSig.KeyID {
				trust.CommittedReceiptPublicKey = publicKey
			}
			if proof.GlobalProof != nil && evidence.KeyID == proof.GlobalProof.STH.Signature.KeyID {
				trust.SignedTreeHeadPublicKey = publicKey
			}
		}
	}
	return trust, nil
}

var orderedProofStages = []verify.Stage{
	verify.StageProofBundle,
	verify.StageContent,
	verify.StageClientClaim,
	verify.StageBundleBindings,
	verify.StageAcceptedReceipt,
	verify.StageCommittedReceipt,
	verify.StageBatchMerkle,
	verify.StageGlobalLog,
	verify.StageAnchor,
}

func appendAfterContainerFailure(result *OfflineResult, proof model.SingleProof, options OfflineOptions) {
	result.Stages = append(result.Stages, OfflineStageResult{
		Name:   OfflineStageIdentity,
		Status: OfflineStageNotRun,
	})
	appendNotRunProofStages(result, proof, options)
}

func appendNotRunProofStages(result *OfflineResult, proof model.SingleProof, options OfflineOptions) {
	appendProofStages(result, proof, options, verify.StageProofBundle, fmt.Errorf("verification did not reach the proof bundle"))
	if len(result.Stages) != 0 {
		for index := range result.Stages {
			if result.Stages[index].Name == string(verify.StageProofBundle) {
				result.Stages[index].Status = OfflineStageNotRun
				result.Stages[index].Error = ""
				break
			}
		}
	}
}

func appendProofStages(
	result *OfflineResult,
	proof model.SingleProof,
	options OfflineOptions,
	failed verify.Stage,
	failure error,
) {
	reachedFailure := false
	for _, stage := range orderedProofStages {
		switch stage {
		case verify.StageGlobalLog:
			if proof.GlobalProof == nil {
				result.Stages = append(result.Stages, OfflineStageResult{
					Name:   string(stage),
					Status: OfflineStageNotPresent,
				})
				continue
			}
		case verify.StageAnchor:
			if isRawFISCOBCOSProof(proof) {
				result.Stages = append(result.Stages, OfflineStageResult{
					Name:   string(stage),
					Status: OfflineStageNotPresent,
				})
				continue
			}
			if proof.AnchorResult == nil {
				result.Stages = append(result.Stages, OfflineStageResult{
					Name:   string(stage),
					Status: OfflineStageNotPresent,
				})
				continue
			}
			if options.SkipAnchor {
				result.Stages = append(result.Stages, OfflineStageResult{
					Name:   string(stage),
					Status: OfflineStageSkipped,
				})
				continue
			}
		}
		if failed != "" && stage == failed {
			result.Stages = append(result.Stages, failedOfflineStage(string(stage), failure))
			reachedFailure = true
			continue
		}
		status := OfflineStagePassed
		if reachedFailure {
			status = OfflineStageNotRun
		}
		result.Stages = append(result.Stages, OfflineStageResult{
			Name:   string(stage),
			Status: status,
		})
	}
	status := OfflineStageNotRun
	if !isRawFISCOBCOSProof(proof) {
		status = OfflineStageNotPresent
	} else if options.SkipAnchor {
		status = OfflineStageSkipped
	}
	for _, name := range []string{
		OfflineStageBCOSReceiptInclusion,
		OfflineStageBCOSPBFTFinality,
		OfflineStageBCOSAnchorBinding,
	} {
		result.Stages = append(result.Stages, OfflineStageResult{
			Name:   name,
			Status: status,
		})
	}
}

func setBCOSStage(
	result *OfflineResult,
	name string,
	status OfflineStageStatus,
	err error,
) {
	for index := range result.Stages {
		if result.Stages[index].Name != name {
			continue
		}
		result.Stages[index].Status = status
		if err == nil {
			result.Stages[index].Error = ""
		} else {
			result.Stages[index].Error = err.Error()
		}
		return
	}
}

func passedOfflineStage(name string) OfflineStageResult {
	return OfflineStageResult{Name: name, Status: OfflineStagePassed}
}

func failedOfflineStage(name string, err error) OfflineStageResult {
	stage := OfflineStageResult{Name: name, Status: OfflineStageFailed}
	if err != nil {
		stage.Error = err.Error()
	}
	return stage
}
