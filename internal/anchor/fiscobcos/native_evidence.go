package fiscobcos

import (
	"encoding/binary"
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

// MarshalNativeReceiptPreimage reconstructs the exact byte concatenation
// hashed by FISCO BCOS. Receipt version >= 1 requires effectiveGasPrice;
// callers must fail closed when their SDK cannot prove that field.
func MarshalNativeReceiptPreimage(fields NativeReceiptFields) ([]byte, [][]byte, error) {
	if fields.Version < 0 || fields.BlockNumber < 0 ||
		len(fields.Output) > maxNativeEvidenceFieldBytes ||
		len(fields.Logs) > maxNativeEvidenceItems {
		return nil, nil, ErrIncompleteChainEvidence
	}
	if fields.Version >= 1 && fields.EffectiveGasPrice == nil {
		return nil, nil, fmt.Errorf("%w: receipt version %d lacks effectiveGasPrice", ErrIncompleteChainEvidence, fields.Version)
	}
	out := make([]byte, 0, 128+len(fields.Output))
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
		if len(log.Data) > maxNativeEvidenceFieldBytes || len(log.Topics) > maxNativeEvidenceItems {
			return nil, nil, ErrIncompleteChainEvidence
		}
		canonical := make([]byte, 0, len(log.Address)+len(log.Data)+32*len(log.Topics))
		canonical = append(canonical, log.Address...)
		for _, topic := range log.Topics {
			if len(topic) != 32 {
				return nil, nil, fmt.Errorf("%w: receipt log topic is not 32 bytes", ErrIncompleteChainEvidence)
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

func MarshalNativeBlockHeaderPreimage(fields NativeBlockHeaderFields) ([]byte, error) {
	if fields.Version < 0 || fields.BlockNumber < 0 || fields.Timestamp < 0 ||
		fields.Sealer < 0 || len(fields.ParentInfo) > maxNativeEvidenceItems ||
		len(fields.SealerList) > maxNativeEvidenceItems ||
		len(fields.ConsensusWeights) > maxNativeEvidenceItems ||
		len(fields.ExtraData) > maxNativeEvidenceFieldBytes {
		return nil, ErrIncompleteChainEvidence
	}
	for _, root := range [][]byte{fields.TransactionsRoot, fields.ReceiptsRoot, fields.StateRoot} {
		if len(root) != identifierBytes {
			return nil, fmt.Errorf("%w: block header root is not 32 bytes", ErrIncompleteChainEvidence)
		}
	}
	out := make([]byte, 0, 256+len(fields.ExtraData))
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
		if len(sealer) == 0 || len(sealer) > maxNativeEvidenceFieldBytes {
			return nil, ErrIncompleteChainEvidence
		}
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
