package fiscobcos

import (
	"errors"
	"fmt"
	"math"

	"github.com/TarsCloud/TarsGo/tars/protocol/codec"
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
	Version         int32             `cbor:"version" json:"version"`
	GasUsed         string            `cbor:"gas_used" json:"gas_used"`
	ContractAddress string            `cbor:"contract_address" json:"contract_address"`
	Status          int32             `cbor:"status" json:"status"`
	Output          []byte            `cbor:"output" json:"output"`
	Logs            []NativeLogFields `cbor:"logs" json:"logs"`
	BlockNumber     int64             `cbor:"block_number" json:"block_number"`
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

// MarshalNativeReceiptPreimage reconstructs TransactionReceiptData.writeTo.
// The tags and required/optional rules come from the upstream
// bcos-tars-protocol TransactionReceipt.tars schema. The consensus hash is
// over these TARS bytes, not JSON or an ad-hoc field concatenation.
func MarshalNativeReceiptPreimage(fields NativeReceiptFields) ([]byte, [][]byte, error) {
	if fields.Version < 0 || fields.BlockNumber < 0 ||
		len(fields.Output) > maxNativeEvidenceFieldBytes ||
		len(fields.Logs) > maxNativeEvidenceItems {
		return nil, nil, ErrIncompleteChainEvidence
	}
	out := codec.NewBuffer()
	if err := out.WriteInt32(fields.Version, 1); err != nil {
		return nil, nil, tarsEvidenceError(err)
	}
	if err := out.WriteString(fields.GasUsed, 2); err != nil {
		return nil, nil, tarsEvidenceError(err)
	}
	if fields.ContractAddress != "" {
		if err := out.WriteString(fields.ContractAddress, 3); err != nil {
			return nil, nil, tarsEvidenceError(err)
		}
	}
	if err := out.WriteInt32(fields.Status, 4); err != nil {
		return nil, nil, tarsEvidenceError(err)
	}
	if len(fields.Output) != 0 {
		if err := writeTARSBytes(out, fields.Output, 5); err != nil {
			return nil, nil, err
		}
	}
	logs := make([][]byte, len(fields.Logs))
	if len(fields.Logs) != 0 {
		if err := out.WriteHead(codec.LIST, 6); err != nil {
			return nil, nil, tarsEvidenceError(err)
		}
		if err := out.WriteInt32(int32(len(fields.Logs)), 0); err != nil {
			return nil, nil, tarsEvidenceError(err)
		}
		for index, log := range fields.Logs {
			canonical, err := marshalNativeLogBlock(log)
			if err != nil {
				return nil, nil, err
			}
			logs[index] = canonical
			if err := out.WriteSliceUint8(canonical); err != nil {
				return nil, nil, tarsEvidenceError(err)
			}
		}
	}
	if err := out.WriteInt64(fields.BlockNumber, 7); err != nil {
		return nil, nil, tarsEvidenceError(err)
	}
	if out.Len() > maxRawReceiptBytes {
		return nil, nil, ErrIncompleteChainEvidence
	}
	return append([]byte(nil), out.ToBytes()...), logs, nil
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
	out := codec.NewBuffer()
	if err := out.WriteInt32(fields.Version, 2); err != nil {
		return nil, tarsEvidenceError(err)
	}
	if err := out.WriteHead(codec.LIST, 3); err != nil {
		return nil, tarsEvidenceError(err)
	}
	if err := out.WriteInt32(int32(len(fields.ParentInfo)), 0); err != nil {
		return nil, tarsEvidenceError(err)
	}
	for _, parent := range fields.ParentInfo {
		if parent.BlockNumber < 0 || len(parent.BlockHash) != identifierBytes {
			return nil, fmt.Errorf("%w: invalid parent block identity", ErrIncompleteChainEvidence)
		}
		if err := out.WriteHead(codec.StructBegin, 0); err != nil {
			return nil, tarsEvidenceError(err)
		}
		if err := out.WriteInt64(parent.BlockNumber, 1); err != nil {
			return nil, tarsEvidenceError(err)
		}
		if err := writeTARSBytes(out, parent.BlockHash, 2); err != nil {
			return nil, err
		}
		if err := out.WriteHead(codec.StructEnd, 0); err != nil {
			return nil, tarsEvidenceError(err)
		}
	}
	for index, value := range [][]byte{fields.TransactionsRoot, fields.ReceiptsRoot, fields.StateRoot} {
		if err := writeTARSBytes(out, value, byte(index+4)); err != nil {
			return nil, err
		}
	}
	if err := out.WriteInt64(fields.BlockNumber, 7); err != nil {
		return nil, tarsEvidenceError(err)
	}
	if err := out.WriteString(fields.GasUsed, 8); err != nil {
		return nil, tarsEvidenceError(err)
	}
	if err := out.WriteInt64(fields.Timestamp, 9); err != nil {
		return nil, tarsEvidenceError(err)
	}
	if err := out.WriteInt64(fields.Sealer, 10); err != nil {
		return nil, tarsEvidenceError(err)
	}
	if err := writeTARSBytesList(out, fields.SealerList, 11); err != nil {
		return nil, err
	}
	for _, sealer := range fields.SealerList {
		if len(sealer) == 0 || len(sealer) > maxNativeEvidenceFieldBytes {
			return nil, ErrIncompleteChainEvidence
		}
	}
	if err := writeTARSBytes(out, fields.ExtraData, 12); err != nil {
		return nil, err
	}
	if err := out.WriteHead(codec.LIST, 13); err != nil {
		return nil, tarsEvidenceError(err)
	}
	if err := out.WriteInt32(int32(len(fields.ConsensusWeights)), 0); err != nil {
		return nil, tarsEvidenceError(err)
	}
	for _, weight := range fields.ConsensusWeights {
		if weight < 0 {
			return nil, ErrIncompleteChainEvidence
		}
		if err := out.WriteInt64(weight, 0); err != nil {
			return nil, tarsEvidenceError(err)
		}
	}
	if out.Len() > maxRawHeaderBytes {
		return nil, ErrIncompleteChainEvidence
	}
	return append([]byte(nil), out.ToBytes()...), nil
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

func marshalNativeLogBlock(log NativeLogFields) ([]byte, error) {
	if len(log.Data) > maxNativeEvidenceFieldBytes || len(log.Topics) > maxNativeEvidenceItems {
		return nil, ErrIncompleteChainEvidence
	}
	out := codec.NewBuffer()
	if err := out.WriteHead(codec.StructBegin, 0); err != nil {
		return nil, tarsEvidenceError(err)
	}
	if log.Address != "" {
		if err := out.WriteString(log.Address, 1); err != nil {
			return nil, tarsEvidenceError(err)
		}
	}
	if len(log.Topics) != 0 {
		for _, topic := range log.Topics {
			if len(topic) != identifierBytes {
				return nil, fmt.Errorf("%w: receipt log topic is not 32 bytes", ErrIncompleteChainEvidence)
			}
		}
		if err := writeTARSBytesList(out, log.Topics, 2); err != nil {
			return nil, err
		}
	}
	if len(log.Data) != 0 {
		if err := writeTARSBytes(out, log.Data, 3); err != nil {
			return nil, err
		}
	}
	if err := out.WriteHead(codec.StructEnd, 0); err != nil {
		return nil, tarsEvidenceError(err)
	}
	return append([]byte(nil), out.ToBytes()...), nil
}

func writeTARSBytes(out *codec.Buffer, value []byte, tag byte) error {
	if len(value) > maxNativeEvidenceFieldBytes || len(value) > math.MaxInt32 {
		return ErrIncompleteChainEvidence
	}
	if err := out.WriteHead(codec.SimpleList, tag); err != nil {
		return tarsEvidenceError(err)
	}
	if err := out.WriteHead(codec.BYTE, 0); err != nil {
		return tarsEvidenceError(err)
	}
	if err := out.WriteInt32(int32(len(value)), 0); err != nil {
		return tarsEvidenceError(err)
	}
	if err := out.WriteSliceUint8(value); err != nil {
		return tarsEvidenceError(err)
	}
	return nil
}

func writeTARSBytesList(out *codec.Buffer, values [][]byte, tag byte) error {
	if len(values) > maxNativeEvidenceItems {
		return ErrIncompleteChainEvidence
	}
	if err := out.WriteHead(codec.LIST, tag); err != nil {
		return tarsEvidenceError(err)
	}
	if err := out.WriteInt32(int32(len(values)), 0); err != nil {
		return tarsEvidenceError(err)
	}
	for _, value := range values {
		if err := writeTARSBytes(out, value, 0); err != nil {
			return err
		}
	}
	return nil
}

func tarsEvidenceError(err error) error {
	return fmt.Errorf("%w: encode official TARS preimage: %v", ErrIncompleteChainEvidence, err)
}
