package fiscobcos

import (
	"bytes"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	gmsm2 "github.com/emmansun/gmsm/sm2"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
)

func TestVerifyAuthenticatedPBFTFinalityAddValidatorStandardAndGuomi(t *testing.T) {
	t.Parallel()
	for _, mode := range []CryptoMode{CryptoModeStandard, CryptoModeGuomi} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			sth, result, trust, _, _ := validValidatorTransitionFixture(t, mode)
			if err := VerifyReceiptInclusion(sth, result, trust); err != nil {
				t.Fatalf("VerifyReceiptInclusion() error = %v", err)
			}
			if err := VerifyAuthenticatedPBFTFinality(sth, result, trust); err != nil {
				t.Fatalf("VerifyAuthenticatedPBFTFinality() error = %v", err)
			}
			if err := VerifyExactAnchorBinding(sth, result, trust); err != nil {
				t.Fatalf("VerifyExactAnchorBinding() error = %v", err)
			}
		})
	}
}

func TestVerifyAuthenticatedPBFTFinalityRejectsTransitionTampering(t *testing.T) {
	t.Parallel()
	sth, result, trust, oldKeys, allKeys := validValidatorTransitionFixture(t, CryptoModeStandard)
	base := mustFinalityProof(t, result)

	tests := []struct {
		name   string
		mutate func(*AnchorProof, *TrustConfig)
		match  string
	}{
		{
			name: "skipped parent",
			mutate: func(proof *AnchorProof, _ *TrustConfig) {
				proof.Block.Fields.ParentInfo[0].BlockHash[0] ^= 0xff
				rebuildFinalityBlock(t, proof, allKeys)
			},
			match: "skipped, reordered, or has the wrong parent",
		},
		{
			name: "omitted transition block contents",
			mutate: func(proof *AnchorProof, _ *TrustConfig) {
				proof.ValidatorHistory[0].Transactions = nil
				proof.ValidatorHistory[0].Receipts = nil
			},
			match: "lacks a complete transaction/receipt list",
		},
		{
			name: "forged new validator",
			mutate: func(proof *AnchorProof, _ *TrustConfig) {
				proof.Block.Fields.SealerList[4] = bytes.Repeat([]byte{0xff}, 64)
				rebuildFinalityBlock(t, proof, oldKeys[:3])
			},
			match: "not the exact result",
		},
		{
			name: "new committee quorum missing",
			mutate: func(proof *AnchorProof, _ *TrustConfig) {
				proof.Finality.Signatures = nil
				rebuildFinalityBlock(t, proof, oldKeys[:3])
			},
			match: "requires 5",
		},
		{
			name: "successful receipt returns nonzero",
			mutate: func(proof *AnchorProof, config *TrustConfig) {
				proof.ValidatorHistory[0].Receipts[0].Fields.Output[31] = 1
				rebuildTransitionSource(t, proof, config, allKeys)
			},
			match: "not the exact result",
		},
		{
			name: "rpbft mutation selector",
			mutate: func(proof *AnchorProof, config *TrustConfig) {
				selector, err := ABISelectorForMode(config.CryptoMode, addSealerRPBFT)
				if err != nil {
					t.Fatal(err)
				}
				copy(proof.ValidatorHistory[0].Transactions[0].Fields.Input[:4], selector)
				rebuildTransitionSource(t, proof, config, allKeys)
			},
			match: "RPBFT validator mutation",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			proof := cloneAnchorProofForMutation(t, base)
			config := cloneTrustConfig(trust)
			test.mutate(&proof, &config)
			candidate := resultWithFinalityProof(t, result, proof)
			err := VerifyAuthenticatedPBFTFinality(sth, candidate, config)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("VerifyAuthenticatedPBFTFinality() error = %v, want containing %q", err, test.match)
			}
		})
	}
}

func TestStaticPolicyRejectsTransitionEvidence(t *testing.T) {
	t.Parallel()
	sth, result, trust, _, _ := validValidatorTransitionFixture(t, CryptoModeStandard)
	proof := mustFinalityProof(t, result)
	trust.ValidatorTransitionPolicy = ValidatorPolicyStatic
	rebindFinalityContext(t, &proof, trust)
	result = resultWithFinalityProof(t, result, proof)
	if err := VerifyStaticPBFTFinality(sth, result, trust); err == nil ||
		!strings.Contains(err.Error(), "rejects transition history") {
		t.Fatalf("VerifyStaticPBFTFinality() error = %v", err)
	}
	if err := VerifyAuthenticatedPBFTFinality(sth, result, trust); err == nil ||
		!strings.Contains(err.Error(), "does not authorize validator transitions") {
		t.Fatalf("VerifyAuthenticatedPBFTFinality() error = %v", err)
	}
}

func TestAdvanceTrustConfigCheckpointIsExplicitAndMonotonic(t *testing.T) {
	t.Parallel()
	_, result, trust, _, _ := validValidatorTransitionFixture(t, CryptoModeStandard)
	proof := mustFinalityProof(t, result)
	oldDigest, err := TrustConfigDigest(trust)
	if err != nil {
		t.Fatal(err)
	}
	next, err := AdvanceTrustConfigCheckpoint(trust, proof)
	if err != nil {
		t.Fatalf("AdvanceTrustConfigCheckpoint() error = %v", err)
	}
	if next.CheckpointGeneration != trust.CheckpointGeneration+1 ||
		next.TrustedCheckpoint.BlockNumber != proof.Block.BlockNumber ||
		!bytes.Equal(next.TrustedCheckpoint.BlockHash, proof.Block.BlockHash) ||
		!bytes.Equal(next.PreviousConfigDigest, oldDigest) ||
		len(next.Validators) != 5 || next.Validators[4].VoteWeight != 2 {
		t.Fatalf("advanced config = %+v", next)
	}
	if _, err := AdvanceTrustConfigCheckpoint(next, proof); err == nil {
		t.Fatal("advanced config accepted replayed/rollback transition evidence")
	}
}

func TestTrustConfigRejectsValidatorTotalWeightOverflow(t *testing.T) {
	t.Parallel()

	_, _, trust, _ := validStaticFinalityFixture(t, CryptoModeStandard, cryptosuite.INTLV1)
	trust.Validators[0].VoteWeight = uint64(^uint64(0) >> 1)
	trust.Validators[1].VoteWeight = uint64(^uint64(0) >> 1)
	if _, err := MarshalTrustConfig(trust); err == nil || !strings.Contains(err.Error(), "total validator vote weight") {
		t.Fatalf("MarshalTrustConfig() error = %v", err)
	}
}

func TestVerifyAuthenticatedPBFTFinalitySupportsRemoveWeightAndRotation(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name          string
		inputs        func(*testing.T, TrustConfig, []finalityFixtureKey, []finalityFixtureKey) [][]byte
		targetKeys    func([]finalityFixtureKey, []finalityFixtureKey) []finalityFixtureKey
		targetWeights []int64
		signers       func([]finalityFixtureKey, []finalityFixtureKey) []finalityFixtureKey
	}{
		{
			name: "remove validator",
			inputs: func(t *testing.T, config TrustConfig, oldKeys, _ []finalityFixtureKey) [][]byte {
				return [][]byte{encodeStringCall(t, config.CryptoMode, removeNodeSignature, oldKeys[3].nodeID[2:])}
			},
			targetKeys:    func(oldKeys, _ []finalityFixtureKey) []finalityFixtureKey { return oldKeys[:3] },
			targetWeights: []int64{1, 1, 1},
			signers:       func(oldKeys, _ []finalityFixtureKey) []finalityFixtureKey { return oldKeys[:3] },
		},
		{
			name: "demote validator to observer",
			inputs: func(t *testing.T, config TrustConfig, oldKeys, _ []finalityFixtureKey) [][]byte {
				return [][]byte{encodeStringCall(t, config.CryptoMode, addObserverSignature, oldKeys[3].nodeID[2:])}
			},
			targetKeys:    func(oldKeys, _ []finalityFixtureKey) []finalityFixtureKey { return oldKeys[:3] },
			targetWeights: []int64{1, 1, 1},
			signers:       func(oldKeys, _ []finalityFixtureKey) []finalityFixtureKey { return oldKeys[:3] },
		},
		{
			name: "increase validator weight",
			inputs: func(t *testing.T, config TrustConfig, oldKeys, _ []finalityFixtureKey) [][]byte {
				return [][]byte{encodeStringUint256Call(t, config.CryptoMode, setWeightSignature, oldKeys[0].nodeID[2:], 4)}
			},
			targetKeys:    func(oldKeys, _ []finalityFixtureKey) []finalityFixtureKey { return oldKeys },
			targetWeights: []int64{4, 1, 1, 1},
			signers:       func(oldKeys, _ []finalityFixtureKey) []finalityFixtureKey { return oldKeys[:2] },
		},
		{
			name: "remove and add in transaction order",
			inputs: func(t *testing.T, config TrustConfig, oldKeys, allKeys []finalityFixtureKey) [][]byte {
				return [][]byte{
					encodeStringCall(t, config.CryptoMode, removeNodeSignature, oldKeys[3].nodeID[2:]),
					encodeStringUint256Call(t, config.CryptoMode, addSealerSignature, allKeys[4].nodeID[2:], 1),
				}
			},
			targetKeys: func(oldKeys, allKeys []finalityFixtureKey) []finalityFixtureKey {
				return append(append([]finalityFixtureKey(nil), oldKeys[:3]...), allKeys[4])
			},
			targetWeights: []int64{1, 1, 1, 1},
			signers:       func(oldKeys, _ []finalityFixtureKey) []finalityFixtureKey { return oldKeys[:3] },
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			sth, result, trust, oldKeys, allKeys := validValidatorTransitionFixture(t, CryptoModeStandard)
			proof := mustFinalityProof(t, result)
			rewriteTransitionBlock(
				t,
				&proof,
				&trust,
				test.inputs(t, trust, oldKeys, allKeys),
				test.targetKeys(oldKeys, allKeys),
				test.targetWeights,
				test.signers(oldKeys, allKeys),
			)
			candidate := resultWithFinalityProof(t, result, proof)
			if err := VerifyAuthenticatedPBFTFinality(sth, candidate, trust); err != nil {
				t.Fatalf("VerifyAuthenticatedPBFTFinality() error = %v", err)
			}
		})
	}
}

func TestVerifyAuthenticatedPBFTFinalityLongChainAndReordering(t *testing.T) {
	t.Parallel()

	const historyBlocks = 64
	sth, result, trust, keys := validStaticFinalityFixture(t, CryptoModeStandard, cryptosuite.INTLV1)
	proof := mustFinalityProof(t, result)
	trust.ValidatorTransitionPolicy = ValidatorPolicyTransitions
	if proof.Block.BlockNumber <= historyBlocks {
		t.Fatalf("target block %d is too low for the long-chain fixture", proof.Block.BlockNumber)
	}
	checkpointNumber := proof.Block.BlockNumber - historyBlocks
	parentHash := bytes.Repeat([]byte{0x41}, identifierBytes)
	history := make([]ValidatorHistoryBlock, historyBlocks)
	for index := uint64(0); index < historyBlocks; index++ {
		blockNumber := checkpointNumber + index
		fields := NativeBlockHeaderFields{
			Version: proof.Block.Fields.Version,
			ParentInfo: []NativeParentInfo{{
				BlockNumber: int64(blockNumber - 1),
				BlockHash:   append([]byte(nil), parentHash...),
			}},
			TransactionsRoot: append([]byte(nil), proof.Block.Fields.TransactionsRoot...),
			ReceiptsRoot:     append([]byte(nil), proof.Block.Fields.ReceiptsRoot...),
			StateRoot:        bytes.Repeat([]byte{byte(index + 1)}, identifierBytes),
			BlockNumber:      int64(blockNumber),
			GasUsed:          proof.Block.Fields.GasUsed,
			Timestamp:        proof.Block.Fields.Timestamp - int64(historyBlocks-index),
			Sealer:           int64(index % uint64(len(keys))),
			SealerList:       cloneByteSlices(proof.Block.Fields.SealerList),
			ConsensusWeights: append([]int64(nil), proof.Block.Fields.ConsensusWeights...),
		}
		raw, err := MarshalNativeBlockHeaderPreimage(fields)
		if err != nil {
			t.Fatal(err)
		}
		blockHash, err := HashNativeEvidence(proof.ChainHashAlgorithm, raw)
		if err != nil {
			t.Fatal(err)
		}
		item := ValidatorHistoryBlock{Block: BlockEvidence{
			Fields: fields, RawCanonicalHeader: raw, BlockHash: blockHash, BlockNumber: blockNumber,
		}}
		if index != 0 {
			temporary := AnchorProof{CryptoMode: proof.CryptoMode, ChainHashAlgorithm: proof.ChainHashAlgorithm, Block: item.Block}
			rebuildFinalityBlock(t, &temporary, keys[:3])
			item.Block = temporary.Block
			item.Finality = temporary.Finality
		}
		history[index] = item
		parentHash = blockHash
	}
	trust.TrustedCheckpoint = BlockCheckpoint{
		BlockNumber: checkpointNumber,
		BlockHash:   append([]byte(nil), history[0].Block.BlockHash...),
	}
	proof.ValidatorHistory = history
	proof.Block.Fields.ParentInfo = []NativeParentInfo{{
		BlockNumber: int64(proof.Block.BlockNumber - 1),
		BlockHash:   append([]byte(nil), history[len(history)-1].Block.BlockHash...),
	}}
	rebindFinalityContext(t, &proof, trust)
	rebuildFinalityBlock(t, &proof, keys[:3])
	candidate := resultWithFinalityProof(t, result, proof)
	if len(candidate.Proof) >= MaxProofBytes {
		t.Fatalf("long-chain proof size = %d, limit = %d", len(candidate.Proof), MaxProofBytes)
	}
	if err := VerifyAuthenticatedPBFTFinality(sth, candidate, trust); err != nil {
		t.Fatalf("VerifyAuthenticatedPBFTFinality() error = %v", err)
	}

	reordered := cloneAnchorProofForMutation(t, proof)
	reordered.ValidatorHistory[10], reordered.ValidatorHistory[11] =
		reordered.ValidatorHistory[11], reordered.ValidatorHistory[10]
	err := VerifyAuthenticatedPBFTFinality(sth, resultWithFinalityProof(t, result, reordered), trust)
	if err == nil || !strings.Contains(err.Error(), "skipped, reordered, or has the wrong parent") {
		t.Fatalf("reordered history error = %v", err)
	}
}

func TestVerifyAuthenticatedPBFTFinalityAuthorizesTransitionWithOldCommittee(t *testing.T) {
	t.Parallel()

	sth, result, trust, oldKeys, allKeys := validValidatorTransitionFixture(t, CryptoModeStandard)
	proof := mustFinalityProof(t, result)
	source := proof.ValidatorHistory[0]
	checkpointNumber := source.Block.BlockNumber - 1
	checkpointFields := NativeBlockHeaderFields{
		Version: proof.Block.Fields.Version,
		ParentInfo: []NativeParentInfo{{
			BlockNumber: int64(checkpointNumber - 1),
			BlockHash:   bytes.Repeat([]byte{0x31}, identifierBytes),
		}},
		TransactionsRoot: bytes.Repeat([]byte{0x32}, identifierBytes),
		ReceiptsRoot:     bytes.Repeat([]byte{0x33}, identifierBytes),
		StateRoot:        bytes.Repeat([]byte{0x34}, identifierBytes),
		BlockNumber:      int64(checkpointNumber),
		GasUsed:          "0",
		Timestamp:        source.Block.Fields.Timestamp - 1,
		Sealer:           0,
		SealerList:       cloneByteSlices(source.Block.Fields.SealerList),
		ConsensusWeights: append([]int64(nil), source.Block.Fields.ConsensusWeights...),
	}
	checkpointRaw, err := MarshalNativeBlockHeaderPreimage(checkpointFields)
	if err != nil {
		t.Fatal(err)
	}
	checkpointHash, err := HashNativeEvidence(proof.ChainHashAlgorithm, checkpointRaw)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := ValidatorHistoryBlock{Block: BlockEvidence{
		Fields: checkpointFields, RawCanonicalHeader: checkpointRaw,
		BlockHash: checkpointHash, BlockNumber: checkpointNumber,
	}}
	source.Block.Fields.ParentInfo = []NativeParentInfo{{
		BlockNumber: int64(checkpointNumber), BlockHash: append([]byte(nil), checkpointHash...),
	}}
	temporary := AnchorProof{
		CryptoMode: proof.CryptoMode, ChainHashAlgorithm: proof.ChainHashAlgorithm,
		Block: source.Block,
	}
	rebuildFinalityBlock(t, &temporary, oldKeys[:3])
	source.Block = temporary.Block
	source.Finality = temporary.Finality
	trust.TrustedCheckpoint = BlockCheckpoint{BlockNumber: checkpointNumber, BlockHash: checkpointHash}
	proof.ValidatorHistory = []ValidatorHistoryBlock{checkpoint, source}
	proof.Block.Fields.ParentInfo = []NativeParentInfo{{
		BlockNumber: int64(source.Block.BlockNumber), BlockHash: append([]byte(nil), source.Block.BlockHash...),
	}}
	rebindFinalityContext(t, &proof, trust)
	rebuildFinalityBlock(t, &proof, allKeys)
	candidate := resultWithFinalityProof(t, result, proof)
	if err := VerifyAuthenticatedPBFTFinality(sth, candidate, trust); err != nil {
		t.Fatalf("VerifyAuthenticatedPBFTFinality() error = %v", err)
	}

	forged := cloneAnchorProofForMutation(t, proof)
	temporary = AnchorProof{
		CryptoMode: forged.CryptoMode, ChainHashAlgorithm: forged.ChainHashAlgorithm,
		Block: forged.ValidatorHistory[1].Block,
	}
	rebuildFinalityBlock(t, &temporary, allKeys[4:])
	forged.ValidatorHistory[1].Finality = temporary.Finality
	err = VerifyAuthenticatedPBFTFinality(sth, resultWithFinalityProof(t, result, forged), trust)
	if err == nil || !strings.Contains(err.Error(), "is not in the active trusted set") {
		t.Fatalf("new committee self-authorization error = %v", err)
	}
}

func validValidatorTransitionFixture(
	t *testing.T,
	mode CryptoMode,
) (model.SignedTreeHead, model.STHAnchorResult, TrustConfig, []finalityFixtureKey, []finalityFixtureKey) {
	t.Helper()
	sth, result, trust, oldKeys := validStaticFinalityFixture(t, mode, cryptosuite.INTLV1)
	proof := mustFinalityProof(t, result)
	trust.ValidatorTransitionPolicy = ValidatorPolicyTransitions

	newKey := finalityKey(t, mode, 9)
	allKeys := append(append([]finalityFixtureKey(nil), oldKeys...), newKey)
	transitionInput := encodeStringUint256Call(t, mode, addSealerSignature, newKey.nodeID[2:], 2)
	transactionFields := NativeTransactionFields{
		Version: 0, ChainID: trust.ChainID, GroupID: trust.GroupID,
		BlockLimit: 5000, Nonce: "validator-transition-1",
		To: append([]byte(nil), consensusPrecompileAddress...), Input: transitionInput,
	}
	transactionPreimage, err := MarshalNativeTransactionHashPreimage(transactionFields)
	if err != nil {
		t.Fatal(err)
	}
	transactionHash, err := HashNativeEvidence(trust.ChainHashAlgorithm, transactionPreimage)
	if err != nil {
		t.Fatal(err)
	}
	receiptFields := NativeReceiptFields{
		Version: 0, GasUsed: "1000", Status: ReceiptStatusOK,
		Output: make([]byte, 32), BlockNumber: int64(proof.Block.BlockNumber - 1),
	}
	receiptPreimage, _, err := MarshalNativeReceiptPreimage(receiptFields)
	if err != nil {
		t.Fatal(err)
	}
	receiptHash, err := HashNativeEvidence(trust.ChainHashAlgorithm, receiptPreimage)
	if err != nil {
		t.Fatal(err)
	}

	checkpointFields := NativeBlockHeaderFields{
		Version: 0,
		ParentInfo: []NativeParentInfo{{
			BlockNumber: int64(proof.Block.BlockNumber - 2),
			BlockHash:   bytes.Repeat([]byte{0x55}, 32),
		}},
		TransactionsRoot: append([]byte(nil), transactionHash...),
		ReceiptsRoot:     append([]byte(nil), receiptHash...),
		StateRoot:        bytes.Repeat([]byte{0x66}, 32),
		BlockNumber:      int64(proof.Block.BlockNumber - 1),
		GasUsed:          "1000",
		Timestamp:        proof.Block.Fields.Timestamp - 1,
		Sealer:           0,
		SealerList:       cloneByteSlices(proof.Block.Fields.SealerList),
		ConsensusWeights: append([]int64(nil), proof.Block.Fields.ConsensusWeights...),
	}
	checkpointRaw, err := MarshalNativeBlockHeaderPreimage(checkpointFields)
	if err != nil {
		t.Fatal(err)
	}
	checkpointHash, err := HashNativeEvidence(trust.ChainHashAlgorithm, checkpointRaw)
	if err != nil {
		t.Fatal(err)
	}
	trust.TrustedCheckpoint = BlockCheckpoint{
		BlockNumber: proof.Block.BlockNumber - 1,
		BlockHash:   append([]byte(nil), checkpointHash...),
	}
	proof.ValidatorHistory = []ValidatorHistoryBlock{{
		Block: BlockEvidence{
			Fields: checkpointFields, RawCanonicalHeader: checkpointRaw,
			BlockHash: checkpointHash, BlockNumber: proof.Block.BlockNumber - 1,
		},
		Transactions: []TransitionTransactionEvidence{{
			Fields: transactionFields, RawHashPreimage: transactionPreimage,
			TransactionHash: transactionHash,
		}},
		Receipts: []TransitionReceiptEvidence{{
			Fields: receiptFields, RawCanonicalReceipt: receiptPreimage,
			ReceiptHash: receiptHash,
		}},
	}}
	proof.Block.Fields.ParentInfo = []NativeParentInfo{{
		BlockNumber: int64(proof.Block.BlockNumber - 1), BlockHash: checkpointHash,
	}}
	proof.Block.Fields.SealerList = append(proof.Block.Fields.SealerList, append([]byte(nil), newKey.publicKey[1:]...))
	proof.Block.Fields.ConsensusWeights = append(proof.Block.Fields.ConsensusWeights, 2)
	rebindFinalityContext(t, &proof, trust)
	rebuildFinalityBlock(t, &proof, allKeys)
	return sth, resultWithFinalityProof(t, result, proof), trust, oldKeys, allKeys
}

func rebuildTransitionSource(t *testing.T, proof *AnchorProof, trust *TrustConfig, targetSigners []finalityFixtureKey) {
	t.Helper()
	source := &proof.ValidatorHistory[0]
	transactionPreimage, err := MarshalNativeTransactionHashPreimage(source.Transactions[0].Fields)
	if err != nil {
		t.Fatal(err)
	}
	source.Transactions[0].RawHashPreimage = transactionPreimage
	source.Transactions[0].TransactionHash, err = HashNativeEvidence(proof.ChainHashAlgorithm, transactionPreimage)
	if err != nil {
		t.Fatal(err)
	}
	receiptPreimage, _, err := MarshalNativeReceiptPreimage(source.Receipts[0].Fields)
	if err != nil {
		t.Fatal(err)
	}
	source.Receipts[0].RawCanonicalReceipt = receiptPreimage
	source.Receipts[0].ReceiptHash, err = HashNativeEvidence(proof.ChainHashAlgorithm, receiptPreimage)
	if err != nil {
		t.Fatal(err)
	}
	source.Block.Fields.TransactionsRoot = append([]byte(nil), source.Transactions[0].TransactionHash...)
	source.Block.Fields.ReceiptsRoot = append([]byte(nil), source.Receipts[0].ReceiptHash...)
	source.Block.RawCanonicalHeader, err = MarshalNativeBlockHeaderPreimage(source.Block.Fields)
	if err != nil {
		t.Fatal(err)
	}
	source.Block.BlockHash, err = HashNativeEvidence(proof.ChainHashAlgorithm, source.Block.RawCanonicalHeader)
	if err != nil {
		t.Fatal(err)
	}
	trust.TrustedCheckpoint.BlockHash = append([]byte(nil), source.Block.BlockHash...)
	proof.Block.Fields.ParentInfo[0].BlockHash = append([]byte(nil), source.Block.BlockHash...)
	rebindFinalityContext(t, proof, *trust)
	rebuildFinalityBlock(t, proof, targetSigners)
}

func rewriteTransitionBlock(
	t *testing.T,
	proof *AnchorProof,
	trust *TrustConfig,
	inputs [][]byte,
	targetKeys []finalityFixtureKey,
	targetWeights []int64,
	targetSigners []finalityFixtureKey,
) {
	t.Helper()
	if len(inputs) == 0 || len(targetKeys) != len(targetWeights) {
		t.Fatal("invalid transition rewrite fixture")
	}
	source := &proof.ValidatorHistory[0]
	baseTransaction := source.Transactions[0].Fields
	baseReceipt := source.Receipts[0].Fields
	source.Transactions = make([]TransitionTransactionEvidence, len(inputs))
	source.Receipts = make([]TransitionReceiptEvidence, len(inputs))
	for index, input := range inputs {
		transaction := baseTransaction
		transaction.Nonce = fmt.Sprintf("validator-transition-%d", index+1)
		transaction.Input = append([]byte(nil), input...)
		preimage, err := MarshalNativeTransactionHashPreimage(transaction)
		if err != nil {
			t.Fatal(err)
		}
		hash, err := HashNativeEvidence(proof.ChainHashAlgorithm, preimage)
		if err != nil {
			t.Fatal(err)
		}
		source.Transactions[index] = TransitionTransactionEvidence{
			Fields: transaction, RawHashPreimage: preimage, TransactionHash: hash,
		}

		receipt := baseReceipt
		receipt.Output = append([]byte(nil), baseReceipt.Output...)
		receiptPreimage, _, err := MarshalNativeReceiptPreimage(receipt)
		if err != nil {
			t.Fatal(err)
		}
		receiptHash, err := HashNativeEvidence(proof.ChainHashAlgorithm, receiptPreimage)
		if err != nil {
			t.Fatal(err)
		}
		source.Receipts[index] = TransitionReceiptEvidence{
			Fields: receipt, RawCanonicalReceipt: receiptPreimage, ReceiptHash: receiptHash,
		}
	}
	transactionHashes := make([][]byte, len(source.Transactions))
	receiptHashes := make([][]byte, len(source.Receipts))
	for index := range source.Transactions {
		transactionHashes[index] = source.Transactions[index].TransactionHash
		receiptHashes[index] = source.Receipts[index].ReceiptHash
	}
	var err error
	source.Block.Fields.TransactionsRoot, err = buildBCOSMerkleRoot(transactionHashes, proof.ChainHashAlgorithm)
	if err != nil {
		t.Fatal(err)
	}
	source.Block.Fields.ReceiptsRoot, err = buildBCOSMerkleRoot(receiptHashes, proof.ChainHashAlgorithm)
	if err != nil {
		t.Fatal(err)
	}
	source.Block.RawCanonicalHeader, err = MarshalNativeBlockHeaderPreimage(source.Block.Fields)
	if err != nil {
		t.Fatal(err)
	}
	source.Block.BlockHash, err = HashNativeEvidence(proof.ChainHashAlgorithm, source.Block.RawCanonicalHeader)
	if err != nil {
		t.Fatal(err)
	}
	trust.TrustedCheckpoint.BlockHash = append([]byte(nil), source.Block.BlockHash...)
	proof.Block.Fields.ParentInfo[0].BlockHash = append([]byte(nil), source.Block.BlockHash...)
	proof.Block.Fields.SealerList = make([][]byte, len(targetKeys))
	for index, key := range targetKeys {
		proof.Block.Fields.SealerList[index] = append([]byte(nil), key.publicKey[1:]...)
	}
	proof.Block.Fields.ConsensusWeights = append([]int64(nil), targetWeights...)
	rebindFinalityContext(t, proof, *trust)
	rebuildFinalityBlock(t, proof, targetSigners)
}

func finalityKey(t *testing.T, mode CryptoMode, scalar byte) finalityFixtureKey {
	t.Helper()
	privateKey := make([]byte, 32)
	privateKey[31] = scalar
	var publicKey []byte
	switch mode {
	case CryptoModeStandard:
		private, err := ethcrypto.ToECDSA(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		publicKey = ethcrypto.FromECDSAPub(&private.PublicKey)
	case CryptoModeGuomi:
		private, err := gmsm2.NewPrivateKey(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		publicKey = elliptic.Marshal(private.Curve, private.X, private.Y)
	default:
		t.Fatal("unsupported mode")
	}
	return finalityFixtureKey{
		private: privateKey, publicKey: publicKey,
		nodeID: "0x" + hex.EncodeToString(publicKey[1:]),
	}
}

func encodeStringUint256Call(t *testing.T, mode CryptoMode, signature, value string, weight uint64) []byte {
	t.Helper()
	selector, err := ABISelectorForMode(mode, signature)
	if err != nil {
		t.Fatal(err)
	}
	padded := (len(value) + 31) &^ 31
	out := make([]byte, 4+64+32+padded)
	copy(out, selector)
	binary.BigEndian.PutUint64(out[4+24:4+32], 64)
	binary.BigEndian.PutUint64(out[4+32+24:4+64], weight)
	binary.BigEndian.PutUint64(out[4+64+24:4+96], uint64(len(value)))
	copy(out[4+96:], value)
	return out
}

func encodeStringCall(t *testing.T, mode CryptoMode, signature, value string) []byte {
	t.Helper()
	selector, err := ABISelectorForMode(mode, signature)
	if err != nil {
		t.Fatal(err)
	}
	padded := (len(value) + 31) &^ 31
	out := make([]byte, 4+32+32+padded)
	copy(out, selector)
	binary.BigEndian.PutUint64(out[4+24:4+32], 32)
	binary.BigEndian.PutUint64(out[4+32+24:4+64], uint64(len(value)))
	copy(out[4+64:], value)
	return out
}
