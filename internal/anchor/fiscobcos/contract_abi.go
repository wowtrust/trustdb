package fiscobcos

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/sha3"
)

const (
	TrustDBAnchorV1ProtocolVersion = "trustdb-anchor-v1"
	TrustDBAnchorV1EventSignature  = "AnchorPublished(bytes32,bytes32,uint64,bytes32,bytes32,address,uint16)"

	publishSignature   = "publish(bytes32,bytes32,uint64,bytes32,bytes32,uint16)"
	getAnchorSignature = "getAnchor(bytes32)"
)

func PublishCallData(payload AnchorPayload) ([]byte, error) {
	if err := validatePayload(payload); err != nil {
		return nil, err
	}
	out := make([]byte, 4+32*6)
	copy(out[:4], abiSelector(publishSignature))
	copy(out[4:36], payload.AnchorID)
	copy(out[36:68], payload.StreamID)
	binary.BigEndian.PutUint64(out[4+32*2+24:4+32*3], payload.TreeSize)
	copy(out[4+32*3:4+32*4], payload.RootHash)
	copy(out[4+32*4:4+32*5], payload.SignedSTHDigest)
	binary.BigEndian.PutUint16(out[4+32*5+30:4+32*6], payload.Version)
	return out, nil
}

func GetAnchorCallData(anchorID []byte) ([]byte, error) {
	if len(anchorID) != identifierBytes {
		return nil, fmt.Errorf("%w: anchor_id must be %d bytes", ErrInvalidPayload, identifierBytes)
	}
	out := make([]byte, 4+32)
	copy(out[:4], abiSelector(getAnchorSignature))
	copy(out[4:], anchorID)
	return out, nil
}

// DecodeAnchorRecord decodes the static ABI tuple returned by getAnchor.
// Dynamic offsets or trailing data are rejected because TrustDBAnchorV1 has a
// fixed six-word record plus the exists flag.
func DecodeAnchorRecord(data []byte) (AnchorRecord, error) {
	const words = 7
	if len(data) != words*32 {
		return AnchorRecord{}, fmt.Errorf("%w: getAnchor returned %d bytes, want %d", ErrDriverInvalid, len(data), words*32)
	}
	if !zeroPrefix(data[32:2*32], 24) || !zeroPrefix(data[4*32:5*32], 12) || !zeroPrefix(data[6*32:7*32], 31) {
		return AnchorRecord{}, fmt.Errorf("%w: getAnchor integer/address padding is non-zero", ErrDriverInvalid)
	}
	payloadVersionWord := data[5*32 : 6*32]
	if !zeroPrefix(payloadVersionWord, 30) {
		return AnchorRecord{}, fmt.Errorf("%w: getAnchor payload version padding is non-zero", ErrDriverInvalid)
	}
	exists := data[6*32+31]
	if exists > 1 {
		return AnchorRecord{}, fmt.Errorf("%w: getAnchor exists flag is not boolean", ErrDriverInvalid)
	}
	if exists == 0 {
		if !bytes.Equal(data, make([]byte, len(data))) {
			return AnchorRecord{}, fmt.Errorf("%w: absent getAnchor record contains non-zero fields", ErrDriverInvalid)
		}
		return AnchorRecord{}, nil
	}
	return AnchorRecord{
		StreamID:        append([]byte(nil), data[:32]...),
		TreeSize:        binary.BigEndian.Uint64(data[32+24 : 2*32]),
		RootHash:        append([]byte(nil), data[2*32:3*32]...),
		SignedSTHDigest: append([]byte(nil), data[3*32:4*32]...),
		Publisher:       append([]byte(nil), data[4*32+12:5*32]...),
		PayloadVersion:  binary.BigEndian.Uint16(payloadVersionWord[30:]),
		Exists:          exists == 1,
	}, nil
}

func abiSelector(signature string) []byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write([]byte(signature))
	return h.Sum(nil)[:4]
}

func zeroPrefix(data []byte, length int) bool {
	if length < 0 || length > len(data) {
		return false
	}
	return bytes.Equal(data[:length], make([]byte, length))
}
