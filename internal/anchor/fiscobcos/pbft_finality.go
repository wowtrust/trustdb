package fiscobcos

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"math/bits"

	gmsm2 "github.com/emmansun/gmsm/sm2"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
)

const (
	bcosConsensusPublicKeyBytes = 64
	bcosStandardSignatureBytes  = 65
	bcosGuomiSignatureBytes     = 64
)

// VerifyPBFTFinality dispatches only from the verifier-local transition
// policy. Evidence cannot select a more permissive validator policy.
func VerifyPBFTFinality(
	sth model.SignedTreeHead,
	result model.STHAnchorResult,
	config TrustConfig,
) error {
	switch config.ValidatorTransitionPolicy {
	case ValidatorPolicyStatic:
		return VerifyStaticPBFTFinality(sth, result, config)
	case ValidatorPolicyTransitions:
		return VerifyAuthenticatedPBFTFinality(sth, result, config)
	default:
		return fmt.Errorf("%w: unsupported local validator transition policy %q", ErrInvalidTrustConfig, config.ValidatorTransitionPolicy)
	}
}

// VerifyStaticPBFTFinality verifies the persisted block commit proof against
// the verifier-local static validator checkpoint. It performs no RPC, DNS,
// certificate, provider, or other network access. FISCO BCOS v3.16.3 computes
// the required weight as:
//
//	totalWeight - floor((totalWeight - 1) / 3)
func VerifyStaticPBFTFinality(
	sth model.SignedTreeHead,
	result model.STHAnchorResult,
	config TrustConfig,
) error {
	if result.EvidenceStage != model.AnchorEvidenceStageRaw {
		return fmt.Errorf("%w: PBFT finality requires immutable raw BCOS evidence", ErrInvalidProof)
	}
	if err := ValidateProofAgainstTrustConfig(sth, result, config); err != nil {
		return err
	}
	canonical, err := canonicalTrustConfig(config)
	if err != nil {
		return err
	}
	proof, err := UnmarshalProof(result.Proof)
	if err != nil {
		return err
	}
	if proof.Block.BlockNumber < canonical.TrustedCheckpoint.BlockNumber {
		return fmt.Errorf(
			"%w: block %d precedes trusted checkpoint %d",
			ErrInvalidProof,
			proof.Block.BlockNumber,
			canonical.TrustedCheckpoint.BlockNumber,
		)
	}
	if canonical.ValidatorTransitionPolicy != ValidatorPolicyStatic {
		return fmt.Errorf("%w: static finality requires validator_transition_policy=%s", ErrInvalidProof, ValidatorPolicyStatic)
	}
	if len(proof.ValidatorHistory) != 0 {
		return fmt.Errorf("%w: static validator policy rejects transition history", ErrInvalidProof)
	}
	if proof.Block.BlockNumber == canonical.TrustedCheckpoint.BlockNumber &&
		!bytes.Equal(proof.Block.BlockHash, canonical.TrustedCheckpoint.BlockHash) {
		return fmt.Errorf("%w: block at trusted checkpoint height has a different hash", ErrInvalidProof)
	}

	validators, err := validatorStateFromConfig(canonical)
	if err != nil {
		return err
	}
	if err := verifyValidatorHeader(validators, proof.Block.Fields); err != nil {
		return err
	}
	return verifyFinalityAgainstState(canonical, validators, proof.Block, proof.Finality)
}

type validatorState struct {
	ordered []ValidatorDescriptor
	byNode  map[string]ValidatorDescriptor
	total   uint64
}

func validatorStateFromConfig(config TrustConfig) (validatorState, error) {
	if config.ValidatorQuorumPolicy != QuorumPolicyPBFTV2 {
		return validatorState{}, fmt.Errorf("%w: unsupported PBFT quorum policy %q", ErrInvalidProof, config.ValidatorQuorumPolicy)
	}
	state := validatorState{
		ordered: append([]ValidatorDescriptor(nil), config.Validators...),
		byNode:  make(map[string]ValidatorDescriptor, len(config.Validators)),
	}
	for index := range state.ordered {
		state.ordered[index].PublicKey = append([]byte(nil), state.ordered[index].PublicKey...)
		validator := state.ordered[index]
		nodeID, err := canonicalNodeIDForPublicKey(validator.PublicKey)
		if err != nil || validator.NodeID != nodeID || validator.VoteWeight == 0 {
			return validatorState{}, fmt.Errorf("%w: validator %q is not canonical", ErrInvalidProof, validator.NodeID)
		}
		if _, duplicate := state.byNode[nodeID]; duplicate {
			return validatorState{}, fmt.Errorf("%w: duplicate trusted validator %q", ErrInvalidProof, nodeID)
		}
		var carry uint64
		state.total, carry = bits.Add64(state.total, validator.VoteWeight, 0)
		if carry != 0 {
			return validatorState{}, fmt.Errorf("%w: trusted validator weight sum overflows", ErrInvalidProof)
		}
		state.byNode[nodeID] = validator
	}
	if state.total == 0 || state.total > math.MaxInt64 {
		return validatorState{}, fmt.Errorf("%w: trusted validator total weight is outside [1, 2^63-1]", ErrInvalidProof)
	}
	return state, nil
}

func verifyValidatorHeader(state validatorState, header NativeBlockHeaderFields) error {
	if len(header.SealerList) != len(state.ordered) || len(header.ConsensusWeights) != len(state.ordered) {
		return fmt.Errorf("%w: block validator membership/weight count differs from trusted set", ErrInvalidProof)
	}
	if header.Sealer < 0 || uint64(header.Sealer) >= uint64(len(header.SealerList)) {
		return fmt.Errorf("%w: block sealer index is outside the trusted validator set", ErrInvalidProof)
	}
	for index, validator := range state.ordered {
		rawNodeID := header.SealerList[index]
		if len(rawNodeID) != bcosConsensusPublicKeyBytes ||
			!bytes.Equal(rawNodeID, validator.PublicKey[1:]) ||
			header.ConsensusWeights[index] <= 0 ||
			uint64(header.ConsensusWeights[index]) != validator.VoteWeight {
			return fmt.Errorf("%w: block validator %d does not exactly match trusted order and weight", ErrInvalidProof, index)
		}
	}
	return nil
}

func verifyFinalityAgainstState(config TrustConfig, state validatorState, block BlockEvidence, finality FinalityEvidence) error {
	if len(finality.Signatures) == 0 {
		return fmt.Errorf("%w: PBFT finality has no signatures", ErrInvalidProof)
	}
	seen := make(map[string]struct{}, len(finality.Signatures))
	var signedWeight uint64
	for index, commit := range finality.Signatures {
		if _, duplicate := seen[commit.ValidatorNodeID]; duplicate {
			return fmt.Errorf("%w: duplicate PBFT signer %q", ErrInvalidProof, commit.ValidatorNodeID)
		}
		seen[commit.ValidatorNodeID] = struct{}{}
		validator, member := state.byNode[commit.ValidatorNodeID]
		if !member {
			return fmt.Errorf("%w: PBFT signer %q is not in the active trusted set", ErrInvalidProof, commit.ValidatorNodeID)
		}
		if err := VerifyPBFTCommitSignature(
			config.CryptoMode,
			config.SM2UserID,
			validator.PublicKey,
			block.BlockHash,
			commit.Signature,
		); err != nil {
			return fmt.Errorf("%w: PBFT signature %d for %q: %v", ErrInvalidProof, index, commit.ValidatorNodeID, err)
		}
		var carry uint64
		signedWeight, carry = bits.Add64(signedWeight, validator.VoteWeight, 0)
		if carry != 0 {
			return fmt.Errorf("%w: PBFT signed weight overflows", ErrInvalidProof)
		}
	}

	requiredWeight := state.total - (state.total-1)/3
	if signedWeight < requiredWeight {
		return fmt.Errorf(
			"%w: PBFT quorum has weight %d, requires %d of trusted total %d",
			ErrInvalidProof,
			signedWeight,
			requiredWeight,
			state.total,
		)
	}
	return nil
}

func canonicalNodeIDForPublicKey(publicKey []byte) (string, error) {
	if len(publicKey) != bcosConsensusPublicKeyBytes+1 || publicKey[0] != 0x04 {
		return "", fmt.Errorf("expected canonical 65-byte uncompressed public key")
	}
	return canonicalNodeID(publicKey[1:]), nil
}

func canonicalNodeID(rawPublicKey []byte) string {
	return "0x" + hex.EncodeToString(rawPublicKey)
}

// VerifyPBFTCommitSignature independently verifies one native PBFT commit
// signature against an explicitly selected chain cryptographic mode. It does
// not authenticate validator membership; callers must bind publicKey to their
// local validator trust policy.
func VerifyPBFTCommitSignature(
	mode CryptoMode,
	sm2UserID string,
	publicKey []byte,
	blockHash []byte,
	signature []byte,
) error {
	if len(blockHash) != identifierBytes {
		return fmt.Errorf("block hash is not %d bytes", identifierBytes)
	}
	switch mode {
	case CryptoModeStandard:
		if sm2UserID != "" {
			return fmt.Errorf("standard mode must not set an SM2 user ID")
		}
		if len(signature) != bcosStandardSignatureBytes || signature[64] > 3 {
			return fmt.Errorf("standard signature must be 65-byte [R || S || recovery-id<=3]")
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:64])
		order := crypto.S256().Params().N
		halfOrder := new(big.Int).Rsh(new(big.Int).Set(order), 1)
		if r.Sign() <= 0 || s.Sign() <= 0 ||
			r.Cmp(order) >= 0 || s.Cmp(order) >= 0 ||
			s.Cmp(halfOrder) > 0 {
			return fmt.Errorf("standard signature has non-canonical R/S values")
		}
		recovered, err := crypto.SigToPub(blockHash, signature)
		if err != nil {
			return fmt.Errorf("recover secp256k1 signer: %v", err)
		}
		if !bytes.Equal(crypto.FromECDSAPub(recovered), publicKey) {
			return fmt.Errorf("secp256k1 signer does not match pinned validator")
		}
		return nil
	case CryptoModeGuomi:
		if sm2UserID != cryptosuite.SM2DefaultUserID {
			return fmt.Errorf("Guomi mode requires fixed SM2 user ID %q", cryptosuite.SM2DefaultUserID)
		}
		if len(signature) != bcosGuomiSignatureBytes {
			return fmt.Errorf("Guomi signature must be 64-byte [R || S]")
		}
		public, err := gmsm2.NewPublicKey(publicKey)
		if err != nil {
			return fmt.Errorf("parse SM2 validator public key: %v", err)
		}
		digest, err := gmsm2.CalculateSM2Hash(public, blockHash, []byte(sm2UserID))
		if err != nil {
			return fmt.Errorf("calculate SM2 block-hash digest: %v", err)
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if !gmsm2.Verify(public, digest, r, s) {
			return fmt.Errorf("invalid SM2 block-hash signature")
		}
		return nil
	default:
		return fmt.Errorf("unsupported crypto mode %q", mode)
	}
}
