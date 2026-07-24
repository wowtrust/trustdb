package fiscobcos

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	gmsm2 "github.com/emmansun/gmsm/sm2"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
)

type finalityFixtureKey struct {
	private   []byte
	publicKey []byte
	nodeID    string
}

func TestVerifyStaticPBFTFinalityFourValidatorStandardAndGuomi(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		mode  CryptoMode
		suite cryptosuite.ID
	}{
		{name: "standard", mode: CryptoModeStandard, suite: cryptosuite.CNSMV1},
		{name: "guomi", mode: CryptoModeGuomi, suite: cryptosuite.INTLV1},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			sth, result, trust, _ := validStaticFinalityFixture(t, test.mode, test.suite)
			if err := VerifyStaticPBFTFinality(sth, result, trust); err != nil {
				t.Fatalf("VerifyStaticPBFTFinality() error = %v", err)
			}
		})
	}
}

func TestVerifyStaticPBFTFinalityRejectsMutations(t *testing.T) {
	t.Parallel()

	sth, result, trust, keys := validStaticFinalityFixture(
		t,
		CryptoModeStandard,
		cryptosuite.INTLV1,
	)
	base := mustFinalityProof(t, result)

	tests := []struct {
		name   string
		mutate func(*AnchorProof, *TrustConfig)
		match  string
	}{
		{
			name: "insufficient quorum",
			mutate: func(proof *AnchorProof, _ *TrustConfig) {
				proof.Finality.Signatures = proof.Finality.Signatures[:2]
			},
			match: "requires 3",
		},
		{
			name: "nonmember signer",
			mutate: func(proof *AnchorProof, _ *TrustConfig) {
				proof.Finality.Signatures[0].ValidatorNodeID = "0x" + strings.Repeat("ff", 64)
			},
			match: "not in the trusted static set",
		},
		{
			name: "wrong signature",
			mutate: func(proof *AnchorProof, _ *TrustConfig) {
				proof.Finality.Signatures[0].Signature[0] ^= 0xff
			},
			match: "PBFT signature",
		},
		{
			name: "membership transition",
			mutate: func(proof *AnchorProof, _ *TrustConfig) {
				proof.Block.Fields.SealerList[3] = bytes.Repeat([]byte{0xff}, 64)
				rebuildFinalityBlock(t, proof, keys[:3])
			},
			match: "not in the trusted static set",
		},
		{
			name: "weighted membership",
			mutate: func(proof *AnchorProof, _ *TrustConfig) {
				proof.Block.Fields.ConsensusWeights[0] = 2
				rebuildFinalityBlock(t, proof, keys)
			},
			match: "requires unit weights",
		},
		{
			name: "invalid sealer index",
			mutate: func(proof *AnchorProof, _ *TrustConfig) {
				proof.Block.Fields.Sealer = 4
				rebuildFinalityBlock(t, proof, keys)
			},
			match: "sealer index",
		},
		{
			name: "block before checkpoint",
			mutate: func(proof *AnchorProof, config *TrustConfig) {
				config.TrustedCheckpoint.BlockNumber = proof.Block.BlockNumber + 1
				config.TrustedCheckpoint.BlockHash = bytes.Repeat([]byte{0xa5}, 32)
				rebindFinalityContext(t, proof, *config)
			},
			match: "precedes trusted checkpoint",
		},
		{
			name: "wrong hash at checkpoint height",
			mutate: func(proof *AnchorProof, config *TrustConfig) {
				config.TrustedCheckpoint.BlockNumber = proof.Block.BlockNumber
				config.TrustedCheckpoint.BlockHash = bytes.Repeat([]byte{0xa6}, 32)
				rebindFinalityContext(t, proof, *config)
			},
			match: "different hash",
		},
		{
			name: "wrong local checkpoint",
			mutate: func(_ *AnchorProof, config *TrustConfig) {
				config.TrustedCheckpoint.BlockHash[0] ^= 0xff
			},
			match: "does not match local trust config",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			proof := cloneAnchorProofForMutation(t, base)
			config := cloneTrustConfig(trust)
			test.mutate(&proof, &config)
			candidate := resultWithFinalityProof(t, result, proof)
			err := VerifyStaticPBFTFinality(sth, candidate, config)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("VerifyStaticPBFTFinality() error = %v, want containing %q", err, test.match)
			}
		})
	}
}

func TestVerifyStaticPBFTFinalityRejectsDuplicateSigner(t *testing.T) {
	t.Parallel()

	_, result, _, _ := validStaticFinalityFixture(
		t,
		CryptoModeStandard,
		cryptosuite.INTLV1,
	)
	proof := mustFinalityProof(t, result)
	proof.Finality.Signatures[1].ValidatorNodeID =
		proof.Finality.Signatures[0].ValidatorNodeID
	if err := ValidateProofStructure(proof); err == nil ||
		!strings.Contains(err.Error(), "duplicate finality signer") {
		t.Fatalf("ValidateProofStructure() error = %v", err)
	}
}

func validStaticFinalityFixture(
	t *testing.T,
	mode CryptoMode,
	suite cryptosuite.ID,
) (model.SignedTreeHead, model.STHAnchorResult, TrustConfig, []finalityFixtureKey) {
	t.Helper()
	sth, result, trust := validReceiptInclusionFixture(t, mode, suite)
	proof := mustFinalityProof(t, result)

	params, err := ParametersForMode(mode)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]finalityFixtureKey, 4)
	trust.Validators = make([]ValidatorDescriptor, 4)
	proof.Block.Fields.SealerList = make([][]byte, 4)
	proof.Block.Fields.ConsensusWeights = []int64{1, 1, 1, 1}
	for index := range keys {
		privateKey := make([]byte, 32)
		privateKey[31] = byte(index + 1)
		var rawPublic []byte
		switch mode {
		case CryptoModeStandard:
			private, err := ethcrypto.ToECDSA(privateKey)
			if err != nil {
				t.Fatal(err)
			}
			rawPublic = ethcrypto.FromECDSAPub(&private.PublicKey)[1:]
		case CryptoModeGuomi:
			private, err := gmsm2.NewPrivateKey(privateKey)
			if err != nil {
				t.Fatal(err)
			}
			rawPublic = elliptic.Marshal(private.Curve, private.X, private.Y)[1:]
		default:
			t.Fatal("unsupported fixture mode")
		}
		nodeID := "0x" + hex.EncodeToString(rawPublic)
		publicKey := append([]byte{0x04}, rawPublic...)
		keys[index] = finalityFixtureKey{
			private:   privateKey,
			publicKey: publicKey,
			nodeID:    nodeID,
		}
		trust.Validators[index] = ValidatorDescriptor{
			NodeID:            nodeID,
			Algorithm:         params.ChainSignatureAlgorithm,
			PublicKeyEncoding: params.PublicKeyEncoding,
			PublicKey:         publicKey,
		}
		proof.Block.Fields.SealerList[index] = append([]byte(nil), rawPublic...)
	}
	rebindFinalityContext(t, &proof, trust)
	rebuildFinalityBlock(t, &proof, keys)
	return sth, resultWithFinalityProof(t, result, proof), trust, keys
}

func rebuildFinalityBlock(t *testing.T, proof *AnchorProof, signers []finalityFixtureKey) {
	t.Helper()
	rawHeader, err := MarshalNativeBlockHeaderPreimage(proof.Block.Fields)
	if err != nil {
		t.Fatal(err)
	}
	blockHash, err := HashNativeEvidence(proof.ChainHashAlgorithm, rawHeader)
	if err != nil {
		t.Fatal(err)
	}
	proof.Block.RawCanonicalHeader = rawHeader
	proof.Block.BlockHash = blockHash
	proof.Finality.Signatures = make([]CommitSignature, len(signers))
	for index, signer := range signers {
		var signature []byte
		switch proof.CryptoMode {
		case CryptoModeStandard:
			private, err := ethcrypto.ToECDSA(signer.private)
			if err != nil {
				t.Fatal(err)
			}
			signature, err = ethcrypto.Sign(blockHash, private)
			if err != nil {
				t.Fatal(err)
			}
		case CryptoModeGuomi:
			private, err := gmsm2.NewPrivateKey(signer.private)
			if err != nil {
				t.Fatal(err)
			}
			r, s, err := gmsm2.Sign(rand.Reader, &private.PrivateKey, blockHash)
			if err != nil {
				t.Fatal(err)
			}
			signature = make([]byte, 64)
			r.FillBytes(signature[:32])
			s.FillBytes(signature[32:])
		default:
			t.Fatal("unsupported fixture mode")
		}
		proof.Finality.Signatures[index] = CommitSignature{
			ValidatorNodeID: signer.nodeID,
			Signature:       signature,
		}
	}
}

func rebindFinalityContext(t *testing.T, proof *AnchorProof, trust TrustConfig) {
	t.Helper()
	contextID, err := ChainContextID(trust)
	if err != nil {
		t.Fatal(err)
	}
	proof.TrustedCheckpoint = trust.TrustedCheckpoint
	proof.ChainContextID = contextID
}

func mustFinalityProof(t *testing.T, result model.STHAnchorResult) AnchorProof {
	t.Helper()
	proof, err := UnmarshalProof(result.Proof)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func resultWithFinalityProof(
	t *testing.T,
	template model.STHAnchorResult,
	proof AnchorProof,
) model.STHAnchorResult {
	t.Helper()
	encoded, err := MarshalProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	template.Proof = encoded
	return template
}
