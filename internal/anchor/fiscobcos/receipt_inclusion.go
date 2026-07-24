package fiscobcos

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	fiscoecdsa "github.com/FISCO-BCOS/crypto/ecdsa"
	fiscoelliptic "github.com/FISCO-BCOS/crypto/elliptic"
	"github.com/FISCO-BCOS/go-sdk/v3/smcrypto"
	"github.com/FISCO-BCOS/go-sdk/v3/smcrypto/sm3"
	"github.com/FISCO-BCOS/go-sdk/v3/types"
	"github.com/TarsCloud/TarsGo/tars/protocol/codec"
	gmsm2 "github.com/emmansun/gmsm/sm2"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
)

const maxBCOSMerkleGroupWidth = 2

// VerifyReceiptInclusion verifies the BCOS transaction, receipt, binary Merkle
// paths, and TrustDBAnchorV1 event using only the supplied bytes and local
// TrustConfig. It deliberately does not verify or claim PBFT finality.
func VerifyReceiptInclusion(
	sth model.SignedTreeHead,
	result model.STHAnchorResult,
	config TrustConfig,
) error {
	if result.EvidenceStage != model.AnchorEvidenceStageRaw {
		return fmt.Errorf("%w: receipt inclusion requires immutable raw BCOS evidence", ErrInvalidProof)
	}
	if err := ValidateProofAgainstTrustConfig(sth, result, config); err != nil {
		return err
	}
	proof, err := UnmarshalProof(result.Proof)
	if err != nil {
		return err
	}
	payload, err := UnmarshalPayload(proof.CanonicalPayload)
	if err != nil {
		return fmt.Errorf("%w: decode canonical payload: %v", ErrInvalidProof, err)
	}
	attempt := proof.TransactionAttempts[proof.SuccessfulAttemptOrdinal-1]
	if err := verifyCanonicalTransaction(proof.CryptoMode, config.SM2UserID, proof, attempt, payload); err != nil {
		return err
	}
	if err := verifyBCOSMerklePath(
		"transaction",
		attempt.TransactionHash,
		proof.Receipt.TransactionProof,
		proof.Receipt.TransactionIndex,
		proof.Block.Fields.TransactionsRoot,
		proof.ChainHashAlgorithm,
	); err != nil {
		return err
	}
	if err := verifyBCOSMerklePath(
		"receipt",
		proof.Receipt.ReceiptHash,
		proof.Receipt.ReceiptProof,
		proof.Receipt.ReceiptIndex,
		proof.Block.Fields.ReceiptsRoot,
		proof.ChainHashAlgorithm,
	); err != nil {
		return err
	}
	if proof.Receipt.TransactionIndex != proof.Receipt.ReceiptIndex {
		return fmt.Errorf("%w: transaction and receipt indices differ", ErrInvalidProof)
	}
	if err := verifyAnchorEvent(proof.CryptoMode, proof, payload, attempt); err != nil {
		return err
	}
	return nil
}

func verifyCanonicalTransaction(
	mode CryptoMode,
	sm2UserID string,
	proof AnchorProof,
	attempt TransactionAttempt,
	payload AnchorPayload,
) error {
	if err := validateBoundedTARS(attempt.RawCanonicalTransaction); err != nil {
		return err
	}
	var transaction types.Transaction
	if err := transaction.ReadFrom(codec.NewReader(attempt.RawCanonicalTransaction)); err != nil {
		return fmt.Errorf("%w: decode canonical TARS transaction: %v", ErrInvalidProof, err)
	}
	if !bytes.Equal(transaction.Bytes(), attempt.RawCanonicalTransaction) {
		return fmt.Errorf("%w: transaction is not canonical TARS", ErrInvalidProof)
	}
	if transaction.DataHash == nil || transaction.Data.To == nil ||
		transaction.Data.ChainID != proof.ChainID ||
		transaction.Data.GroupID != proof.GroupID ||
		transaction.Data.BlockLimit <= 0 ||
		uint64(transaction.Data.BlockLimit) != attempt.BlockLimit ||
		!bytes.Equal(transaction.Data.To.Bytes(), proof.Contract.Address) ||
		!bytes.Equal(transaction.Data.To.Bytes(), attempt.To) ||
		!bytes.Equal(transaction.Data.Input, attempt.Input) ||
		!bytes.Equal(transaction.Signature, attempt.Signature) {
		return fmt.Errorf("%w: canonical transaction fields do not match evidence", ErrInvalidProof)
	}
	transaction.SMCrypto = mode == CryptoModeGuomi
	declaredHash := append([]byte(nil), transaction.DataHash.Bytes()...)
	computedHash := transaction.Hash().Bytes()
	if !bytes.Equal(declaredHash, computedHash) ||
		!bytes.Equal(computedHash, attempt.TransactionHash) ||
		!bytes.Equal(computedHash, proof.SuccessfulTransactionHash) {
		return fmt.Errorf("%w: transaction consensus hash mismatch", ErrInvalidProof)
	}
	callData, err := PublishCallDataForMode(mode, payload)
	if err != nil || !bytes.Equal(callData, attempt.Input) {
		return fmt.Errorf("%w: transaction input does not exactly publish the bound payload", ErrInvalidProof)
	}
	sender, err := verifyTransactionSignature(mode, sm2UserID, computedHash, attempt.Signature)
	if err != nil {
		return err
	}
	if !bytes.Equal(sender, attempt.Sender) {
		return fmt.Errorf("%w: transaction sender does not match signature", ErrInvalidProof)
	}
	if transaction.Sender != nil && !bytes.Equal(transaction.Sender.Bytes(), sender) {
		return fmt.Errorf("%w: TARS sender does not match signature", ErrInvalidProof)
	}
	return nil
}

func verifyTransactionSignature(
	mode CryptoMode,
	sm2UserID string,
	digest []byte,
	signature []byte,
) ([]byte, error) {
	switch mode {
	case CryptoModeStandard:
		if len(signature) != 65 {
			return nil, fmt.Errorf("%w: standard transaction signature must be 65 bytes", ErrInvalidProof)
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:64])
		if !crypto.ValidateSignatureValues(signature[64], r, s, true) {
			return nil, fmt.Errorf("%w: invalid secp256k1 signature values", ErrInvalidProof)
		}
		publicKey, err := crypto.SigToPub(digest, signature)
		if err != nil {
			return nil, fmt.Errorf("%w: recover secp256k1 signer: %v", ErrInvalidProof, err)
		}
		return crypto.PubkeyToAddress(*publicKey).Bytes(), nil
	case CryptoModeGuomi:
		if len(signature) != 128 {
			return nil, fmt.Errorf("%w: Guomi transaction signature must be 128 bytes", ErrInvalidProof)
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:64])
		curve := fiscoelliptic.Sm2p256v1()
		x := new(big.Int).SetBytes(signature[64:96])
		y := new(big.Int).SetBytes(signature[96:128])
		if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(curve.Params().N) >= 0 ||
			s.Cmp(curve.Params().N) >= 0 || !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("%w: invalid SM2 signature or public key", ErrInvalidProof)
		}
		publicKey := fiscoecdsa.PublicKey{Curve: curve, X: x, Y: y}
		preprocessed, err := smcrypto.SM2PreProcess(
			digest,
			sm2UserID,
			&fiscoecdsa.PrivateKey{PublicKey: publicKey},
		)
		if err != nil {
			return nil, fmt.Errorf("%w: SM2 signature preimage: %v", ErrInvalidProof, err)
		}
		signingDigest := sm3.Hash(preprocessed)
		encodedPublicKey := append([]byte{0x04}, signature[64:128]...)
		gmPublicKey, err := gmsm2.NewPublicKey(encodedPublicKey)
		if err != nil || !gmsm2.Verify(gmPublicKey, signingDigest, r, s) {
			return nil, fmt.Errorf("%w: invalid SM2 transaction signature", ErrInvalidProof)
		}
		publicBytes := signature[64:128]
		addressHash := sm3.Hash(publicBytes)
		return append([]byte(nil), addressHash[12:]...), nil
	default:
		return nil, fmt.Errorf("%w: unsupported transaction crypto mode %q", ErrInvalidProof, mode)
	}
}

func verifyBCOSMerklePath(
	name string,
	leaf []byte,
	path [][]byte,
	index uint64,
	root []byte,
	hashAlgorithm string,
) error {
	if len(leaf) != identifierBytes || len(root) != identifierBytes ||
		len(path) == 0 || len(path) > MaxMerklePathNodes {
		return fmt.Errorf("%w: %s Merkle proof is incomplete", ErrInvalidProof, name)
	}
	// FISCO BCOS emits the root itself for a one-leaf tree.
	if len(path) == 1 {
		if len(path[0]) != identifierBytes || index != 0 ||
			!bytes.Equal(path[0], leaf) || !bytes.Equal(leaf, root) {
			return fmt.Errorf("%w: %s single-leaf Merkle proof mismatch", ErrInvalidProof, name)
		}
		return nil
	}
	current := append([]byte(nil), leaf...)
	var derivedIndex uint64
	level := 0
	for offset := 0; offset < len(path); level++ {
		count, err := decodeBCOSMerkleGroupCount(path[offset])
		if err != nil {
			return fmt.Errorf("%w: %s Merkle proof level %d: %v", ErrInvalidProof, name, level, err)
		}
		offset++
		if count > len(path)-offset {
			return fmt.Errorf("%w: %s Merkle proof level %d is truncated", ErrInvalidProof, name, level)
		}
		group := path[offset : offset+count]
		offset += count
		position := -1
		for i := range group {
			if len(group[i]) != identifierBytes {
				return fmt.Errorf("%w: %s Merkle hash at level %d is not 32 bytes", ErrInvalidProof, name, level)
			}
			if bytes.Equal(group[i], current) {
				if position >= 0 {
					return fmt.Errorf("%w: %s Merkle group contains current hash twice", ErrInvalidProof, name)
				}
				position = i
			}
		}
		if position < 0 {
			return fmt.Errorf("%w: %s Merkle group omits current hash", ErrInvalidProof, name)
		}
		if position == 1 {
			if level >= 64 {
				return fmt.Errorf("%w: %s Merkle index overflows", ErrInvalidProof, name)
			}
			derivedIndex |= uint64(1) << uint(level)
		}
		preimage := make([]byte, 0, len(group)*identifierBytes)
		for _, hash := range group {
			preimage = append(preimage, hash...)
		}
		current, err = HashNativeEvidence(hashAlgorithm, preimage)
		if err != nil {
			return fmt.Errorf("%w: %s Merkle hash: %v", ErrInvalidProof, name, err)
		}
	}
	if derivedIndex != index {
		return fmt.Errorf("%w: %s Merkle index=%d, proof derives %d", ErrInvalidProof, name, index, derivedIndex)
	}
	if !bytes.Equal(current, root) {
		return fmt.Errorf("%w: %s Merkle root mismatch", ErrInvalidProof, name)
	}
	return nil
}

func decodeBCOSMerkleGroupCount(encoded []byte) (int, error) {
	if len(encoded) != 4 {
		return 0, fmt.Errorf("group count is not a canonical uint32")
	}
	count := binary.BigEndian.Uint32(encoded[:4])
	if count == 0 || count > maxBCOSMerkleGroupWidth {
		return 0, fmt.Errorf("group width %d is invalid", count)
	}
	return int(count), nil
}

func verifyAnchorEvent(
	mode CryptoMode,
	proof AnchorProof,
	payload AnchorPayload,
	attempt TransactionAttempt,
) error {
	if proof.Receipt.AnchorLogIndex >= uint64(len(proof.Receipt.Fields.Logs)) {
		return fmt.Errorf("%w: anchor log index is out of range", ErrInvalidProof)
	}
	topic0, err := EventTopicForMode(mode, proof.Contract.EventSignature)
	if err != nil {
		return err
	}
	matches := 0
	var decoded AnchorPublishedEvent
	for index := range proof.Receipt.Fields.Logs {
		log := proof.Receipt.Fields.Logs[index]
		address, err := strictConsensusAddress(log.Address)
		if err != nil {
			return fmt.Errorf("%w: receipt log %d address: %v", ErrInvalidProof, index, err)
		}
		if !bytes.Equal(address, proof.Contract.Address) ||
			len(log.Topics) != 4 ||
			!bytes.Equal(log.Topics[0], topic0) {
			continue
		}
		matches++
		if uint64(index) != proof.Receipt.AnchorLogIndex {
			return fmt.Errorf("%w: matching anchor event has wrong log index", ErrInvalidProof)
		}
		event, err := decodeAnchorEventLog(proof.Contract.Address, log, uint64(index))
		if err != nil {
			return err
		}
		decoded = event
	}
	if matches != 1 {
		return fmt.Errorf("%w: expected exactly one matching anchor event, got %d", ErrInvalidProof, matches)
	}
	canonicalEvent, err := MarshalNativeAnchorEvent(decoded)
	if err != nil || !bytes.Equal(canonicalEvent, proof.Receipt.DecodedAnchorEvent) {
		return fmt.Errorf("%w: decoded anchor event evidence mismatch", ErrInvalidProof)
	}
	if !bytes.Equal(decoded.AnchorID, payload.AnchorID) ||
		!bytes.Equal(decoded.StreamID, payload.StreamID) ||
		decoded.TreeSize != payload.TreeSize ||
		!bytes.Equal(decoded.RootHash, payload.RootHash) ||
		!bytes.Equal(decoded.SignedSTHDigest, payload.SignedSTHDigest) ||
		decoded.PayloadVersion != payload.Version ||
		!bytes.Equal(decoded.Publisher, attempt.Sender) {
		return fmt.Errorf("%w: anchor event does not exactly bind payload and publisher", ErrInvalidProof)
	}
	return nil
}

func decodeAnchorEventLog(contract []byte, log NativeLogFields, index uint64) (AnchorPublishedEvent, error) {
	if len(log.Topics) != 4 || len(log.Data) != 4*identifierBytes {
		return AnchorPublishedEvent{}, fmt.Errorf("%w: anchor event ABI shape is invalid", ErrInvalidProof)
	}
	for i := range log.Topics {
		if len(log.Topics[i]) != identifierBytes {
			return AnchorPublishedEvent{}, fmt.Errorf("%w: anchor event topic %d is not 32 bytes", ErrInvalidProof, i)
		}
	}
	if !zeroPrefix(log.Topics[3], 12) ||
		!zeroPrefix(log.Data[:identifierBytes], 24) ||
		!zeroPrefix(log.Data[3*identifierBytes:], 30) {
		return AnchorPublishedEvent{}, fmt.Errorf("%w: anchor event ABI padding is non-zero", ErrInvalidProof)
	}
	return AnchorPublishedEvent{
		ContractAddress: append([]byte(nil), contract...),
		AnchorID:        append([]byte(nil), log.Topics[1]...),
		StreamID:        append([]byte(nil), log.Topics[2]...),
		TreeSize:        binary.BigEndian.Uint64(log.Data[24:32]),
		RootHash:        append([]byte(nil), log.Data[32:64]...),
		SignedSTHDigest: append([]byte(nil), log.Data[64:96]...),
		Publisher:       append([]byte(nil), log.Topics[3][12:]...),
		PayloadVersion:  binary.BigEndian.Uint16(log.Data[126:128]),
		LogIndex:        index,
	}, nil
}

func strictConsensusAddress(value string) ([]byte, error) {
	if len(value) != 40 || strings.HasPrefix(value, "0x") || strings.ToLower(value) != value {
		return nil, fmt.Errorf("address must be canonical 40-character lowercase hex")
	}
	out, err := hex.DecodeString(value)
	if err != nil || len(out) != 20 {
		return nil, fmt.Errorf("address is invalid hex")
	}
	return out, nil
}

// UnmarshalNativeAnchorEvent decodes and re-encodes the stored event
// projection so alternate CBOR encodings and trailing data are rejected.
func UnmarshalNativeAnchorEvent(data []byte) (AnchorPublishedEvent, error) {
	var stored nativeAnchorEventEvidence
	if err := cborx.UnmarshalLimits(data, &stored, maxDecodedEventBytes, 32, 32); err != nil {
		return AnchorPublishedEvent{}, fmt.Errorf("%w: decode anchor event: %v", ErrInvalidProof, err)
	}
	event := AnchorPublishedEvent{
		ContractAddress: stored.ContractAddress,
		AnchorID:        stored.AnchorID,
		StreamID:        stored.StreamID,
		TreeSize:        stored.TreeSize,
		RootHash:        stored.RootHash,
		SignedSTHDigest: stored.SignedSTHDigest,
		Publisher:       stored.Publisher,
		PayloadVersion:  stored.PayloadVersion,
		LogIndex:        stored.LogIndex,
	}
	canonical, err := MarshalNativeAnchorEvent(event)
	if err != nil || !bytes.Equal(canonical, data) {
		return AnchorPublishedEvent{}, fmt.Errorf("%w: non-canonical anchor event", ErrInvalidProof)
	}
	return event, nil
}
