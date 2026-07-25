package fiscobcos

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/sha3"

	"github.com/wowtrust/trustdb/internal/cborx"
)

const (
	maxNativeEvidenceFieldBytes = 4 << 20
	maxNativeEvidenceItems      = 4096
	// MaxNativeEvidenceItems is the allocation guard used by SDK adapters
	// before materializing RPC-provided repeated fields.
	MaxNativeEvidenceItems      = maxNativeEvidenceItems
	MaxNativeEvidenceFieldBytes = maxNativeEvidenceFieldBytes
)

// NativeReceiptFields mirrors the fields consumed by the official
// bcos-tars-protocol TransactionReceipt Hashable implementation. It is kept
// independent of RPC/SDK structs so JSON serialization can never become a
// consensus preimage by accident.
type NativeReceiptFields struct {
	Version           int32             `cbor:"version" json:"version"`
	GasUsed           string            `cbor:"gas_used" json:"gas_used"`
	ContractAddress   string            `cbor:"contract_address" json:"contract_address"`
	Status            int32             `cbor:"status" json:"status"`
	Output            []byte            `cbor:"output" json:"output"`
	EffectiveGasPrice *string           `cbor:"effective_gas_price,omitempty" json:"effective_gas_price,omitempty"`
	Logs              []NativeLogFields `cbor:"logs" json:"logs"`
	BlockNumber       int64             `cbor:"block_number" json:"block_number"`
}

// NativeTransactionFields is the exact transaction-data projection hashed by
// FISCO BCOS v3.16.3. Validator transition evidence deliberately supports
// version 0 only because the pinned RPC transaction detail omits version 1
// fee fields and therefore cannot reconstruct that hash preimage fail-closed.
type NativeTransactionFields struct {
	Version    int32  `cbor:"version" json:"version"`
	ChainID    string `cbor:"chain_id" json:"chain_id"`
	GroupID    string `cbor:"group_id" json:"group_id"`
	BlockLimit int64  `cbor:"block_limit" json:"block_limit"`
	Nonce      string `cbor:"nonce" json:"nonce"`
	To         []byte `cbor:"to,omitempty" json:"to,omitempty"`
	Input      []byte `cbor:"input" json:"input"`
	ABI        string `cbor:"abi" json:"abi"`
}

type NativeLogFields struct {
	Address string   `cbor:"address" json:"address"`
	Topics  [][]byte `cbor:"topics" json:"topics"`
	Data    []byte   `cbor:"data" json:"data"`
}

type NativeParentInfo struct {
	BlockNumber int64  `cbor:"block_number" json:"block_number"`
	BlockHash   []byte `cbor:"block_hash" json:"block_hash"`
}

// NativeBlockHeaderFields mirrors the fields and order consumed by the
// official bcos-tars-protocol BlockHeader Hashable implementation.
type NativeBlockHeaderFields struct {
	Version          int32              `cbor:"version" json:"version"`
	ParentInfo       []NativeParentInfo `cbor:"parent_info" json:"parent_info"`
	TransactionsRoot []byte             `cbor:"transactions_root" json:"transactions_root"`
	ReceiptsRoot     []byte             `cbor:"receipts_root" json:"receipts_root"`
	StateRoot        []byte             `cbor:"state_root" json:"state_root"`
	BlockNumber      int64              `cbor:"block_number" json:"block_number"`
	GasUsed          string             `cbor:"gas_used" json:"gas_used"`
	Timestamp        int64              `cbor:"timestamp" json:"timestamp"`
	Sealer           int64              `cbor:"sealer" json:"sealer"`
	SealerList       [][]byte           `cbor:"sealer_list" json:"sealer_list"`
	ExtraData        []byte             `cbor:"extra_data" json:"extra_data"`
	ConsensusWeights []int64            `cbor:"consensus_weights" json:"consensus_weights"`
}

type nativeAnchorEventEvidence struct {
	ContractAddress []byte `cbor:"contract_address"`
	AnchorID        []byte `cbor:"anchor_id"`
	StreamID        []byte `cbor:"stream_id"`
	TreeSize        uint64 `cbor:"tree_size"`
	RootHash        []byte `cbor:"root_hash"`
	SignedSTHDigest []byte `cbor:"signed_sth_digest"`
	Publisher       []byte `cbor:"publisher"`
	PayloadVersion  uint16 `cbor:"payload_version"`
	LogIndex        uint64 `cbor:"log_index"`
}

func MarshalNativeAnchorEvent(event AnchorPublishedEvent) ([]byte, error) {
	if len(event.ContractAddress) != 20 ||
		len(event.AnchorID) != identifierBytes ||
		len(event.StreamID) != identifierBytes ||
		event.TreeSize == 0 ||
		len(event.RootHash) != identifierBytes ||
		len(event.SignedSTHDigest) != identifierBytes ||
		len(event.Publisher) != 20 ||
		event.PayloadVersion == 0 {
		return nil, ErrIncompleteChainEvidence
	}
	return cborx.Marshal(nativeAnchorEventEvidence{
		ContractAddress: event.ContractAddress,
		AnchorID:        event.AnchorID,
		StreamID:        event.StreamID,
		TreeSize:        event.TreeSize,
		RootHash:        event.RootHash,
		SignedSTHDigest: event.SignedSTHDigest,
		Publisher:       event.Publisher,
		PayloadVersion:  event.PayloadVersion,
		LogIndex:        event.LogIndex,
	})
}

// MarshalNativeReceiptPreimage reconstructs the field projection hashed by
// FISCO BCOS v3.16.3's bcos-tars-protocol/impl/TarsHashable.h. That pinned
// release hashes field bytes directly; it does not hash
// TransactionReceiptData.writeTo output.
func MarshalNativeReceiptPreimage(fields NativeReceiptFields) ([]byte, [][]byte, error) {
	if fields.Version < 0 || fields.BlockNumber < 0 ||
		len(fields.GasUsed) > maxNativeEvidenceFieldBytes ||
		len(fields.ContractAddress) > maxNativeEvidenceFieldBytes ||
		len(fields.Output) > maxNativeEvidenceFieldBytes ||
		len(fields.Logs) > maxNativeEvidenceItems {
		return nil, nil, ErrIncompleteChainEvidence
	}
	if fields.Version >= 1 && fields.EffectiveGasPrice == nil {
		return nil, nil, fmt.Errorf(
			"%w: receipt version %d lacks effectiveGasPrice",
			ErrIncompleteChainEvidence,
			fields.Version,
		)
	}
	receiptSize := 4 + len(fields.GasUsed) + len(fields.ContractAddress) + 4 +
		len(fields.Output) + 8
	if fields.EffectiveGasPrice != nil {
		if len(*fields.EffectiveGasPrice) > maxNativeEvidenceFieldBytes {
			return nil, nil, ErrIncompleteChainEvidence
		}
		receiptSize += len(*fields.EffectiveGasPrice)
	}
	for _, log := range fields.Logs {
		if len(log.Address) == 0 || len(log.Address) > maxNativeEvidenceFieldBytes ||
			len(log.Data) > maxNativeEvidenceFieldBytes ||
			len(log.Topics) > maxNativeEvidenceItems {
			return nil, nil, ErrIncompleteChainEvidence
		}
		receiptSize += len(log.Address) + len(log.Data) + identifierBytes*len(log.Topics)
		if receiptSize > maxRawReceiptBytes {
			return nil, nil, ErrIncompleteChainEvidence
		}
	}
	out := make([]byte, 0, receiptSize)
	out = appendInt32(out, fields.Version)
	out = append(out, fields.GasUsed...)
	out = append(out, fields.ContractAddress...)
	out = appendInt32(out, fields.Status)
	out = append(out, fields.Output...)
	if fields.Version >= 1 {
		out = append(out, (*fields.EffectiveGasPrice)...)
	}
	logs := make([][]byte, len(fields.Logs))
	for index, log := range fields.Logs {
		canonical := make([]byte, 0, len(log.Address)+len(log.Data)+32*len(log.Topics))
		canonical = append(canonical, log.Address...)
		for _, topic := range log.Topics {
			if len(topic) != identifierBytes {
				return nil, nil, fmt.Errorf(
					"%w: receipt log topic is not 32 bytes",
					ErrIncompleteChainEvidence,
				)
			}
			canonical = append(canonical, topic...)
		}
		canonical = append(canonical, log.Data...)
		logs[index] = canonical
		out = append(out, canonical...)
	}
	out = appendInt64(out, fields.BlockNumber)
	if len(out) > maxRawReceiptBytes {
		return nil, nil, ErrIncompleteChainEvidence
	}
	return out, logs, nil
}

// MarshalNativeTransactionHashPreimage mirrors the v3.16.3 transaction data
// hash implementation for version 0 transactions. It is independent of the
// RPC JSON shape and does not include signatures, import time, or sender,
// which are not part of the consensus transaction hash.
func MarshalNativeTransactionHashPreimage(fields NativeTransactionFields) ([]byte, error) {
	if fields.Version != 0 || fields.BlockLimit <= 0 ||
		len(fields.ChainID) == 0 || len(fields.ChainID) > maxNativeEvidenceFieldBytes ||
		len(fields.GroupID) == 0 || len(fields.GroupID) > maxNativeEvidenceFieldBytes ||
		len(fields.Nonce) > maxNativeEvidenceFieldBytes ||
		len(fields.To) != 0 && len(fields.To) != 20 ||
		len(fields.Input) > maxNativeEvidenceFieldBytes ||
		len(fields.ABI) > maxNativeEvidenceFieldBytes {
		return nil, ErrIncompleteChainEvidence
	}
	size := 4 + len(fields.ChainID) + len(fields.GroupID) + 8 + len(fields.Nonce) +
		2*len(fields.To) + len(fields.Input) + len(fields.ABI)
	if size > maxRawTransactionBytes {
		return nil, ErrIncompleteChainEvidence
	}
	out := make([]byte, 0, size)
	out = appendInt32(out, fields.Version)
	out = append(out, fields.ChainID...)
	out = append(out, fields.GroupID...)
	out = appendInt64(out, fields.BlockLimit)
	out = append(out, fields.Nonce...)
	if len(fields.To) != 0 {
		encoded := make([]byte, hex.EncodedLen(len(fields.To)))
		hex.Encode(encoded, fields.To)
		out = append(out, encoded...)
	}
	out = append(out, fields.Input...)
	out = append(out, fields.ABI...)
	return out, nil
}

func MarshalNativeBlockHeaderPreimage(fields NativeBlockHeaderFields) ([]byte, error) {
	if fields.Version < 0 || fields.BlockNumber < 0 || fields.Timestamp < 0 ||
		fields.Sealer < 0 || len(fields.ParentInfo) > maxNativeEvidenceItems ||
		len(fields.SealerList) > maxNativeEvidenceItems ||
		len(fields.ConsensusWeights) > maxNativeEvidenceItems ||
		len(fields.GasUsed) > maxNativeEvidenceFieldBytes ||
		len(fields.ExtraData) > maxNativeEvidenceFieldBytes {
		return nil, ErrIncompleteChainEvidence
	}
	for _, root := range [][]byte{fields.TransactionsRoot, fields.ReceiptsRoot, fields.StateRoot} {
		if len(root) != identifierBytes {
			return nil, fmt.Errorf("%w: block header root is not 32 bytes", ErrIncompleteChainEvidence)
		}
	}
	headerSize := 4 + len(fields.ParentInfo)*(8+identifierBytes) +
		3*identifierBytes + 8 + len(fields.GasUsed) + 8 + 8 +
		len(fields.ExtraData) + len(fields.ConsensusWeights)*8
	for _, sealer := range fields.SealerList {
		if len(sealer) == 0 || len(sealer) > maxNativeEvidenceFieldBytes {
			return nil, ErrIncompleteChainEvidence
		}
		headerSize += len(sealer)
		if headerSize > maxRawHeaderBytes {
			return nil, ErrIncompleteChainEvidence
		}
	}
	if headerSize > maxRawHeaderBytes {
		return nil, ErrIncompleteChainEvidence
	}
	out := make([]byte, 0, headerSize)
	out = appendInt32(out, fields.Version)
	for _, parent := range fields.ParentInfo {
		if parent.BlockNumber < 0 || len(parent.BlockHash) != identifierBytes {
			return nil, fmt.Errorf("%w: invalid parent block identity", ErrIncompleteChainEvidence)
		}
		out = appendInt64(out, parent.BlockNumber)
		out = append(out, parent.BlockHash...)
	}
	out = append(out, fields.TransactionsRoot...)
	out = append(out, fields.ReceiptsRoot...)
	out = append(out, fields.StateRoot...)
	out = appendInt64(out, fields.BlockNumber)
	out = append(out, fields.GasUsed...)
	out = appendInt64(out, fields.Timestamp)
	out = appendInt64(out, fields.Sealer)
	for _, sealer := range fields.SealerList {
		out = append(out, sealer...)
	}
	out = append(out, fields.ExtraData...)
	for _, weight := range fields.ConsensusWeights {
		if weight < 0 {
			return nil, ErrIncompleteChainEvidence
		}
		out = appendInt64(out, weight)
	}
	if len(out) > maxRawHeaderBytes {
		return nil, ErrIncompleteChainEvidence
	}
	return out, nil
}

func HashNativeEvidence(algorithm string, preimage []byte) ([]byte, error) {
	switch algorithm {
	case HashKeccak256:
		hash := sha3.NewLegacyKeccak256()
		_, _ = hash.Write(preimage)
		return hash.Sum(nil), nil
	case "sm3":
		sum := sm3.Sum(preimage)
		return sum[:], nil
	default:
		return nil, errors.New("unsupported FISCO BCOS native evidence hash")
	}
}

func Uint64ToConsensusInt64(value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, ErrIncompleteChainEvidence
	}
	return int64(value), nil
}

func appendInt32(out []byte, value int32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(value))
	return append(out, encoded[:]...)
}

func appendInt64(out []byte, value int64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	return append(out, encoded[:]...)
}
