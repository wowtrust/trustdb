package fiscobcos

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"

	gmsm2 "github.com/emmansun/gmsm/sm2"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/wowtrust/trustdb/internal/model"
)

const (
	bcosConsensusPublicKeyBytes = 64
	bcosStandardSignatureBytes  = 65
	bcosGuomiSignatureBytes     = 64
)

// VerifyStaticPBFTFinality verifies the persisted block commit proof against
// the verifier-local static validator checkpoint. It performs no RPC, DNS,
// certificate, provider, or other network access.
//
// QuorumPolicyPBFTV1 deliberately admits only unit-weight validator sets.
// FISCO BCOS v3.16.3 computes the required weight as:
//
//	totalWeight - floor((totalWeight - 1) / 3)
//
// With unit weights this is the policy's pinned 2f+1 membership threshold.
// Weighted or changed header membership is rejected until a versioned local
// trust profile can authenticate those weights and transitions.
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
	if proof.Block.BlockNumber == canonical.TrustedCheckpoint.BlockNumber &&
		!bytes.Equal(proof.Block.BlockHash, canonical.TrustedCheckpoint.BlockHash) {
		return fmt.Errorf("%w: block at trusted checkpoint height has a different hash", ErrInvalidProof)
	}

	validators, err := staticValidatorSet(canonical, proof.Block.Fields)
	if err != nil {
		return err
	}
	if proof.Block.Fields.Sealer < 0 ||
		uint64(proof.Block.Fields.Sealer) >= uint64(len(proof.Block.Fields.SealerList)) {
		return fmt.Errorf("%w: block sealer index is outside the trusted validator set", ErrInvalidProof)
	}

	seen := make(map[string]struct{}, len(proof.Finality.Signatures))
	var signedWeight uint64
	for index, commit := range proof.Finality.Signatures {
		if _, duplicate := seen[commit.ValidatorNodeID]; duplicate {
			return fmt.Errorf("%w: duplicate PBFT signer %q", ErrInvalidProof, commit.ValidatorNodeID)
		}
		seen[commit.ValidatorNodeID] = struct{}{}
		validator, member := validators[commit.ValidatorNodeID]
		if !member {
			return fmt.Errorf("%w: PBFT signer %q is not in the trusted static set", ErrInvalidProof, commit.ValidatorNodeID)
		}
		if err := verifyPBFTCommitSignature(
			canonical.CryptoMode,
			validator.PublicKey,
			proof.Block.BlockHash,
			commit.Signature,
		); err != nil {
			return fmt.Errorf("%w: PBFT signature %d for %q: %v", ErrInvalidProof, index, commit.ValidatorNodeID, err)
		}
		signedWeight++
	}

	totalWeight := uint64(len(validators))
	requiredWeight := totalWeight - (totalWeight-1)/3
	if signedWeight < requiredWeight {
		return fmt.Errorf(
			"%w: PBFT quorum has weight %d, requires %d of trusted total %d",
			ErrInvalidProof,
			signedWeight,
			requiredWeight,
			totalWeight,
		)
	}
	return nil
}

func staticValidatorSet(
	config TrustConfig,
	header NativeBlockHeaderFields,
) (map[string]ValidatorDescriptor, error) {
	if config.ValidatorQuorumPolicy != QuorumPolicyPBFTV1 {
		return nil, fmt.Errorf("%w: unsupported PBFT quorum policy %q", ErrInvalidProof, config.ValidatorQuorumPolicy)
	}
	if len(header.SealerList) != len(config.Validators) ||
		len(header.ConsensusWeights) != len(config.Validators) {
		return nil, fmt.Errorf(
			"%w: block validator membership/weight count differs from trusted static set",
			ErrInvalidProof,
		)
	}

	validators := make(map[string]ValidatorDescriptor, len(config.Validators))
	for _, validator := range config.Validators {
		nodeID, err := canonicalNodeIDForPublicKey(validator.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: validator %q public key: %v", ErrInvalidProof, validator.NodeID, err)
		}
		if validator.NodeID != nodeID {
			return nil, fmt.Errorf(
				"%w: validator node_id %q does not encode its pinned public key",
				ErrInvalidProof,
				validator.NodeID,
			)
		}
		validators[nodeID] = validator
	}

	seenHeader := make(map[string]struct{}, len(header.SealerList))
	for index, rawNodeID := range header.SealerList {
		if len(rawNodeID) != bcosConsensusPublicKeyBytes {
			return nil, fmt.Errorf("%w: block validator %d node ID is not 64 bytes", ErrInvalidProof, index)
		}
		nodeID := canonicalNodeID(rawNodeID)
		validator, trusted := validators[nodeID]
		if !trusted || !bytes.Equal(rawNodeID, validator.PublicKey[1:]) {
			return nil, fmt.Errorf("%w: block validator %q is not in the trusted static set", ErrInvalidProof, nodeID)
		}
		if _, duplicate := seenHeader[nodeID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate block validator %q", ErrInvalidProof, nodeID)
		}
		seenHeader[nodeID] = struct{}{}
		if header.ConsensusWeights[index] != 1 {
			return nil, fmt.Errorf(
				"%w: validator %q has unsupported vote weight %d; policy %s requires unit weights",
				ErrInvalidProof,
				nodeID,
				header.ConsensusWeights[index],
				QuorumPolicyPBFTV1,
			)
		}
	}
	if len(seenHeader) != len(validators) {
		return nil, fmt.Errorf("%w: block validator set does not exactly match the trusted static set", ErrInvalidProof)
	}
	return validators, nil
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

func verifyPBFTCommitSignature(
	mode CryptoMode,
	publicKey []byte,
	blockHash []byte,
	signature []byte,
) error {
	if len(blockHash) != identifierBytes {
		return fmt.Errorf("block hash is not %d bytes", identifierBytes)
	}
	switch mode {
	case CryptoModeStandard:
		if len(signature) != bcosStandardSignatureBytes || signature[64] > 3 {
			return fmt.Errorf("standard signature must be 65-byte [R || S || recovery-id<=3]")
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
		if len(signature) != bcosGuomiSignatureBytes {
			return fmt.Errorf("Guomi signature must be 64-byte [R || S]")
		}
		public, err := gmsm2.NewPublicKey(publicKey)
		if err != nil {
			return fmt.Errorf("parse SM2 validator public key: %v", err)
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if !gmsm2.Verify(public, blockHash, r, s) {
			return fmt.Errorf("invalid SM2 block-hash signature")
		}
		return nil
	default:
		return fmt.Errorf("unsupported crypto mode %q", mode)
	}
}
