package fiscobcos

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"strings"

	"github.com/wowtrust/trustdb/internal/model"
)

var consensusPrecompileAddress = func() []byte {
	address := make([]byte, 20)
	address[18] = 0x10
	address[19] = 0x03
	return address
}()

const (
	addSealerSignature   = "addSealer(string,uint256)"
	addObserverSignature = "addObserver(string)"
	removeNodeSignature  = "remove(string)"
	setWeightSignature   = "setWeight(string,uint256)"
	addSealerRPBFT       = "addSealer(string,uint256,uint256)"
	setTermWeightRPBFT   = "setTermWeight(string,uint256)"
)

// VerifyAuthenticatedPBFTFinality verifies a contiguous validator history
// from a verifier-local checkpoint to the anchored block. It never reads the
// network and never adopts trust material merely because it appears in the
// evidence file.
func VerifyAuthenticatedPBFTFinality(
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
	proof, err := UnmarshalProof(result.Proof)
	if err != nil {
		return err
	}
	_, err = verifyValidatorHistory(config, proof)
	return err
}

// AdvanceTrustConfigCheckpoint verifies the carried transition history using
// the current local TrustConfig, then returns a new configuration whose
// generation and previous digest form an explicit audit chain. Callers are
// responsible for atomically replacing the local file after checking the
// expected old digest.
func AdvanceTrustConfigCheckpoint(config TrustConfig, proof AnchorProof) (TrustConfig, error) {
	canonical, err := canonicalTrustConfig(config)
	if err != nil {
		return TrustConfig{}, err
	}
	if err := validateProofChainContext(proof, canonical); err != nil {
		return TrustConfig{}, err
	}
	state, err := verifyValidatorHistory(canonical, proof)
	if err != nil {
		return TrustConfig{}, err
	}
	if proof.Block.BlockNumber <= canonical.TrustedCheckpoint.BlockNumber {
		return TrustConfig{}, fmt.Errorf("%w: checkpoint advancement must increase block height", ErrInvalidTrustConfig)
	}
	previousDigest, err := TrustConfigDigest(canonical)
	if err != nil {
		return TrustConfig{}, err
	}
	next := cloneTrustConfig(canonical)
	next.TrustedCheckpoint = BlockCheckpoint{
		BlockNumber: proof.Block.BlockNumber,
		BlockHash:   append([]byte(nil), proof.Block.BlockHash...),
	}
	next.CheckpointGeneration++
	next.PreviousConfigDigest = previousDigest
	next.Validators = append([]ValidatorDescriptor(nil), state.ordered...)
	for index := range next.Validators {
		next.Validators[index].PublicKey = append([]byte(nil), state.ordered[index].PublicKey...)
	}
	return canonicalTrustConfig(next)
}

func validateProofChainContext(proof AnchorProof, config TrustConfig) error {
	if err := ValidateProofStructure(proof); err != nil {
		return err
	}
	if proof.CryptoMode != config.CryptoMode ||
		proof.ProtocolHashAlgorithm != config.ProtocolHashAlgorithm ||
		proof.ChainHashAlgorithm != config.ChainHashAlgorithm ||
		proof.ChainSignatureAlgorithm != config.ChainSignatureAlgorithm ||
		proof.ChainID != config.ChainID || proof.GroupID != config.GroupID ||
		!bytes.Equal(proof.GenesisHash, config.GenesisHash) ||
		proof.TrustedCheckpoint.BlockNumber != config.TrustedCheckpoint.BlockNumber ||
		!bytes.Equal(proof.TrustedCheckpoint.BlockHash, config.TrustedCheckpoint.BlockHash) ||
		!sameContractBinding(proof.Contract, config.Contract) {
		return fmt.Errorf("%w: transition evidence does not match local chain context", ErrInvalidProof)
	}
	wantContext, err := ChainContextID(config)
	if err != nil {
		return err
	}
	if !bytes.Equal(proof.ChainContextID, wantContext) {
		return fmt.Errorf("%w: transition evidence chain context mismatch", ErrInvalidProof)
	}
	return nil
}

func verifyValidatorHistory(config TrustConfig, proof AnchorProof) (validatorState, error) {
	canonical, err := canonicalTrustConfig(config)
	if err != nil {
		return validatorState{}, err
	}
	if canonical.ValidatorTransitionPolicy != ValidatorPolicyTransitions {
		return validatorState{}, fmt.Errorf("%w: local trust config does not authorize validator transitions", ErrInvalidProof)
	}
	if proof.Block.BlockNumber < canonical.TrustedCheckpoint.BlockNumber {
		return validatorState{}, fmt.Errorf("%w: target block precedes trusted checkpoint", ErrInvalidProof)
	}
	state, err := validatorStateFromConfig(canonical)
	if err != nil {
		return validatorState{}, err
	}
	if proof.Block.BlockNumber == canonical.TrustedCheckpoint.BlockNumber {
		if len(proof.ValidatorHistory) != 0 ||
			!bytes.Equal(proof.Block.BlockHash, canonical.TrustedCheckpoint.BlockHash) {
			return validatorState{}, fmt.Errorf("%w: checkpoint-height proof is inconsistent", ErrInvalidProof)
		}
		if err := verifyValidatorHeader(state, proof.Block.Fields); err != nil {
			return validatorState{}, err
		}
		if err := verifyFinalityAgainstState(canonical, state, proof.Block, proof.Finality); err != nil {
			return validatorState{}, err
		}
		return state, nil
	}
	delta := proof.Block.BlockNumber - canonical.TrustedCheckpoint.BlockNumber
	if delta > MaxValidatorHistoryBlocks || uint64(len(proof.ValidatorHistory)) != delta {
		return validatorState{}, fmt.Errorf("%w: validator history has %d blocks, want %d", ErrInvalidProof, len(proof.ValidatorHistory), delta)
	}
	checkpoint := proof.ValidatorHistory[0]
	if checkpoint.Block.BlockNumber != canonical.TrustedCheckpoint.BlockNumber ||
		!bytes.Equal(checkpoint.Block.BlockHash, canonical.TrustedCheckpoint.BlockHash) ||
		len(checkpoint.Finality.Signatures) != 0 {
		return validatorState{}, fmt.Errorf("%w: validator history does not start at the exact local checkpoint", ErrInvalidProof)
	}
	if err := verifyValidatorHeader(state, checkpoint.Block.Fields); err != nil {
		return validatorState{}, err
	}

	current := checkpoint
	for index := uint64(1); index <= delta; index++ {
		var nextBlock BlockEvidence
		var nextFinality FinalityEvidence
		if index == delta {
			nextBlock = proof.Block
			nextFinality = proof.Finality
		} else {
			nextBlock = proof.ValidatorHistory[index].Block
			nextFinality = proof.ValidatorHistory[index].Finality
		}
		if nextBlock.BlockNumber != current.Block.BlockNumber+1 ||
			!hasExactParent(nextBlock.Fields, current.Block) {
			return validatorState{}, fmt.Errorf("%w: validator history block %d is skipped, reordered, or has the wrong parent", ErrInvalidProof, nextBlock.BlockNumber)
		}
		state, err = deriveNextValidatorState(canonical, state, current, nextBlock.Fields)
		if err != nil {
			return validatorState{}, fmt.Errorf("%w: transition from block %d: %v", ErrInvalidProof, current.Block.BlockNumber, err)
		}
		if err := verifyValidatorHeader(state, nextBlock.Fields); err != nil {
			return validatorState{}, err
		}
		if err := verifyFinalityAgainstState(canonical, state, nextBlock, nextFinality); err != nil {
			return validatorState{}, err
		}
		if index < delta {
			current = proof.ValidatorHistory[index]
		}
	}
	return state, nil
}

// ValidatorHeadersHaveSameSet compares validator membership and vote weights
// without treating header order as trust. Promoting an existing observer can
// legitimately insert a sealer at an order not derivable from the active-only
// local checkpoint.
func ValidatorHeadersHaveSameSet(left, right NativeBlockHeaderFields) bool {
	leftState, ok := validatorSetFromHeader(left)
	if !ok {
		return false
	}
	rightState, ok := validatorSetFromHeader(right)
	if !ok || len(leftState) != len(rightState) {
		return false
	}
	for nodeID, weight := range leftState {
		if rightState[nodeID] != weight {
			return false
		}
	}
	return true
}

func validatorSetFromHeader(header NativeBlockHeaderFields) (map[string]uint64, bool) {
	if len(header.SealerList) == 0 || len(header.SealerList) != len(header.ConsensusWeights) {
		return nil, false
	}
	result := make(map[string]uint64, len(header.SealerList))
	for index, rawNodeID := range header.SealerList {
		if len(rawNodeID) != bcosConsensusPublicKeyBytes || header.ConsensusWeights[index] <= 0 {
			return nil, false
		}
		nodeID := canonicalNodeID(rawNodeID)
		if _, duplicate := result[nodeID]; duplicate {
			return nil, false
		}
		result[nodeID] = uint64(header.ConsensusWeights[index])
	}
	return result, true
}

func hasExactParent(fields NativeBlockHeaderFields, parent BlockEvidence) bool {
	return len(fields.ParentInfo) == 1 && fields.ParentInfo[0].BlockNumber >= 0 &&
		uint64(fields.ParentInfo[0].BlockNumber) == parent.BlockNumber &&
		bytes.Equal(fields.ParentInfo[0].BlockHash, parent.BlockHash)
}

func deriveNextValidatorState(
	config TrustConfig,
	current validatorState,
	evidence ValidatorHistoryBlock,
	nextHeader NativeBlockHeaderFields,
) (validatorState, error) {
	if headerMatchesValidatorSet(current, nextHeader) {
		if len(evidence.Transactions) == 0 && len(evidence.Receipts) == 0 {
			return stateOrderedByHeader(current, nextHeader)
		}
	}
	if len(evidence.Transactions) == 0 || len(evidence.Transactions) != len(evidence.Receipts) {
		return validatorState{}, fmt.Errorf("validator change lacks a complete transaction/receipt list")
	}
	if err := verifyTransitionBlockRoots(config.ChainHashAlgorithm, evidence); err != nil {
		return validatorState{}, err
	}
	derived := cloneValidatorState(current)
	for index := range evidence.Transactions {
		transaction := evidence.Transactions[index]
		receipt := evidence.Receipts[index]
		if !bytes.Equal(transaction.Fields.To, consensusPrecompileAddress) || receipt.Fields.Status != ReceiptStatusOK {
			continue
		}
		if len(receipt.Fields.Output) != 32 {
			return validatorState{}, fmt.Errorf("consensus precompile receipt %d has a non-canonical return value", index)
		}
		if !bytes.Equal(receipt.Fields.Output, make([]byte, 32)) {
			continue
		}
		if err := applyConsensusMutation(config, &derived, transaction.Fields.Input); err != nil {
			return validatorState{}, fmt.Errorf("consensus precompile transaction %d: %v", index, err)
		}
	}
	if !headerMatchesValidatorSet(derived, nextHeader) {
		return validatorState{}, fmt.Errorf("next header validator set is not the exact result of successful consensus mutations")
	}
	return stateOrderedByHeader(derived, nextHeader)
}

func verifyTransitionBlockRoots(hashAlgorithm string, evidence ValidatorHistoryBlock) error {
	transactionHashes := make([][]byte, len(evidence.Transactions))
	receiptHashes := make([][]byte, len(evidence.Receipts))
	for index := range evidence.Transactions {
		transactionHashes[index] = evidence.Transactions[index].TransactionHash
		receiptHashes[index] = evidence.Receipts[index].ReceiptHash
	}
	transactionRoot, err := buildBCOSMerkleRoot(transactionHashes, hashAlgorithm)
	if err != nil || !bytes.Equal(transactionRoot, evidence.Block.Fields.TransactionsRoot) {
		return fmt.Errorf("transition transaction root mismatch")
	}
	receiptRoot, err := buildBCOSMerkleRoot(receiptHashes, hashAlgorithm)
	if err != nil || !bytes.Equal(receiptRoot, evidence.Block.Fields.ReceiptsRoot) {
		return fmt.Errorf("transition receipt root mismatch")
	}
	return nil
}

func buildBCOSMerkleRoot(leaves [][]byte, hashAlgorithm string) ([]byte, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("empty BCOS Merkle tree")
	}
	level := make([][]byte, len(leaves))
	for index, leaf := range leaves {
		if len(leaf) != identifierBytes {
			return nil, fmt.Errorf("invalid BCOS Merkle leaf %d", index)
		}
		level[index] = append([]byte(nil), leaf...)
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for index := 0; index < len(level); index += 2 {
			preimage := append([]byte(nil), level[index]...)
			if index+1 < len(level) {
				preimage = append(preimage, level[index+1]...)
			}
			digest, err := HashNativeEvidence(hashAlgorithm, preimage)
			if err != nil {
				return nil, err
			}
			next = append(next, digest)
		}
		level = next
	}
	return level[0], nil
}

func applyConsensusMutation(config TrustConfig, state *validatorState, input []byte) error {
	if len(input) < 4 {
		return fmt.Errorf("missing ABI selector")
	}
	type operation int
	const (
		opAddSealer operation = iota + 1
		opAddObserver
		opRemove
		opSetWeight
	)
	selectors := make(map[string]operation, 4)
	for signature, op := range map[string]operation{
		addSealerSignature: opAddSealer, addObserverSignature: opAddObserver,
		removeNodeSignature: opRemove, setWeightSignature: opSetWeight,
	} {
		selector, err := ABISelectorForMode(config.CryptoMode, signature)
		if err != nil {
			return err
		}
		selectors[string(selector)] = op
	}
	for _, unsupported := range []string{addSealerRPBFT, setTermWeightRPBFT} {
		selector, err := ABISelectorForMode(config.CryptoMode, unsupported)
		if err != nil {
			return err
		}
		if bytes.Equal(input[:4], selector) {
			return fmt.Errorf("RPBFT validator mutation %s is unsupported", unsupported)
		}
	}
	op, supported := selectors[string(input[:4])]
	if !supported {
		return fmt.Errorf("unsupported consensus precompile selector 0x%s", hex.EncodeToString(input[:4]))
	}
	var nodeID string
	var weight uint64
	var err error
	switch op {
	case opAddObserver, opRemove:
		nodeID, err = decodeABIString(input[4:], 1)
	case opAddSealer, opSetWeight:
		nodeID, weight, err = decodeABIStringUint256(input[4:])
	}
	if err != nil {
		return err
	}
	nodeID = strings.ToLower(nodeID)
	publicKeyBody, err := hex.DecodeString(nodeID)
	if err != nil || len(publicKeyBody) != bcosConsensusPublicKeyBytes {
		return fmt.Errorf("validator node ID is not a 128-character hexadecimal public key")
	}
	canonicalID := canonicalNodeID(publicKeyBody)
	switch op {
	case opAddSealer:
		if weight == 0 || weight > uint64(^uint64(0)>>1) {
			return fmt.Errorf("validator vote weight is outside [1, 2^63-1]")
		}
		validator, exists := state.byNode[canonicalID]
		if !exists {
			params, _ := ParametersForMode(config.CryptoMode)
			validator = ValidatorDescriptor{
				NodeID: canonicalID, Algorithm: params.ChainSignatureAlgorithm,
				PublicKeyEncoding: params.PublicKeyEncoding,
				PublicKey:         append([]byte{0x04}, publicKeyBody...), VoteWeight: weight,
			}
			if err := validateValidator(validator, params); err != nil {
				return err
			}
		} else {
			validator.VoteWeight = weight
		}
		state.byNode[canonicalID] = validator
	case opAddObserver, opRemove:
		delete(state.byNode, canonicalID)
	case opSetWeight:
		validator, exists := state.byNode[canonicalID]
		if !exists {
			return fmt.Errorf("successful setWeight targets a non-validator")
		}
		if weight == 0 || weight > uint64(^uint64(0)>>1) {
			return fmt.Errorf("validator vote weight is outside [1, 2^63-1]")
		}
		validator.VoteWeight = weight
		state.byNode[canonicalID] = validator
	}
	return recomputeValidatorTotal(state)
}

func decodeABIString(data []byte, words int) (string, error) {
	if words != 1 || len(data) < 64 || binary.BigEndian.Uint64(data[24:32]) != 32 ||
		!bytes.Equal(data[:24], make([]byte, 24)) {
		return "", fmt.Errorf("non-canonical ABI string arguments")
	}
	return decodeABITailString(data, 32)
}

func decodeABIStringUint256(data []byte) (string, uint64, error) {
	if len(data) < 96 || !bytes.Equal(data[:24], make([]byte, 24)) ||
		binary.BigEndian.Uint64(data[24:32]) != 64 ||
		!bytes.Equal(data[32:56], make([]byte, 24)) {
		return "", 0, fmt.Errorf("non-canonical ABI string,uint256 arguments")
	}
	value, err := decodeABITailString(data, 64)
	if err != nil {
		return "", 0, err
	}
	return value, binary.BigEndian.Uint64(data[56:64]), nil
}

func decodeABITailString(data []byte, offset int) (string, error) {
	if offset < 0 || offset+32 > len(data) || !bytes.Equal(data[offset:offset+24], make([]byte, 24)) {
		return "", fmt.Errorf("non-canonical ABI string offset or length")
	}
	length := binary.BigEndian.Uint64(data[offset+24 : offset+32])
	if length > maxConfigString || length > uint64(len(data)-(offset+32)) {
		return "", fmt.Errorf("ABI string is oversized or truncated")
	}
	padded := (int(length) + 31) &^ 31
	if offset+32+padded != len(data) ||
		!bytes.Equal(data[offset+32+int(length):], make([]byte, padded-int(length))) {
		return "", fmt.Errorf("ABI string has trailing or non-zero padding")
	}
	return string(data[offset+32 : offset+32+int(length)]), nil
}

func headerMatchesValidatorSet(state validatorState, header NativeBlockHeaderFields) bool {
	if len(header.SealerList) != len(state.byNode) || len(header.ConsensusWeights) != len(state.byNode) {
		return false
	}
	seen := make(map[string]struct{}, len(header.SealerList))
	for index, rawNodeID := range header.SealerList {
		if len(rawNodeID) != bcosConsensusPublicKeyBytes || header.ConsensusWeights[index] <= 0 {
			return false
		}
		nodeID := canonicalNodeID(rawNodeID)
		validator, exists := state.byNode[nodeID]
		if !exists || !bytes.Equal(validator.PublicKey[1:], rawNodeID) ||
			validator.VoteWeight != uint64(header.ConsensusWeights[index]) {
			return false
		}
		if _, duplicate := seen[nodeID]; duplicate {
			return false
		}
		seen[nodeID] = struct{}{}
	}
	return len(seen) == len(state.byNode)
}

func stateOrderedByHeader(state validatorState, header NativeBlockHeaderFields) (validatorState, error) {
	if !headerMatchesValidatorSet(state, header) {
		return validatorState{}, fmt.Errorf("header validator set mismatch")
	}
	out := cloneValidatorState(state)
	out.ordered = make([]ValidatorDescriptor, len(header.SealerList))
	for index, rawNodeID := range header.SealerList {
		validator := out.byNode[canonicalNodeID(rawNodeID)]
		validator.PublicKey = append([]byte(nil), validator.PublicKey...)
		out.ordered[index] = validator
	}
	return out, nil
}

func cloneValidatorState(state validatorState) validatorState {
	out := validatorState{byNode: make(map[string]ValidatorDescriptor, len(state.byNode)), total: state.total}
	for nodeID, validator := range state.byNode {
		validator.PublicKey = append([]byte(nil), validator.PublicKey...)
		out.byNode[nodeID] = validator
	}
	out.ordered = append([]ValidatorDescriptor(nil), state.ordered...)
	for index := range out.ordered {
		out.ordered[index].PublicKey = append([]byte(nil), out.ordered[index].PublicKey...)
	}
	return out
}

func recomputeValidatorTotal(state *validatorState) error {
	state.total = 0
	for _, validator := range state.byNode {
		var carry uint64
		state.total, carry = bits.Add64(state.total, validator.VoteWeight, 0)
		if carry != 0 {
			return fmt.Errorf("validator weight sum overflows")
		}
	}
	if state.total == 0 {
		return fmt.Errorf("validator set cannot be empty")
	}
	return nil
}
