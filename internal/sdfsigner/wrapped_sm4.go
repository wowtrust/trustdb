package sdfsigner

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/emmansun/gmsm/sm3"

	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/sdk/signerplugin"
)

const (
	WrappedSM4KeySchemaV1  = "trustdb.sdf-wrapped-sm4-key.v1"
	WrappedSM4KeyAlgorithm = "sm4-128-key-with-kek-v1"
	maxWrappedSM4Envelope  = MaxWrappedKeyBytes + 4096
	wrappedSM4ChecksumSize = 32
)

var (
	ErrInvalidWrappedSM4Key      = errors.New("invalid SDF wrapped SM4 key")
	ErrNonCanonicalWrappedSM4Key = errors.New("non-canonical SDF wrapped SM4 key")
)

type wrappedSM4KeyPayload struct {
	SchemaVersion string         `cbor:"schema_version"`
	CryptoSuite   string         `cbor:"crypto_suite"`
	Algorithm     string         `cbor:"algorithm"`
	Device        DeviceIdentity `cbor:"device"`
	KEKID         string         `cbor:"kek_id"`
	KEKIndex      uint32         `cbor:"kek_index"`
	Wrapped       []byte         `cbor:"wrapped"`
}

func NewWrappedSM4Key(device DeviceIdentity, kekID string, kekIndex uint32, wrapped []byte) (WrappedSM4Key, error) {
	if err := validateIdentity(device); err != nil {
		return WrappedSM4Key{}, wrappedSM4Error("device identity is invalid")
	}
	if !validIdentifier(kekID, 256) || kekIndex == 0 {
		return WrappedSM4Key{}, wrappedSM4Error("KEK identity is invalid")
	}
	if len(wrapped) == 0 || len(wrapped) > MaxWrappedKeyBytes {
		return WrappedSM4Key{}, wrappedSM4Error("wrapped key length is invalid")
	}
	value := WrappedSM4Key{
		SchemaVersion: WrappedSM4KeySchemaV1,
		CryptoSuite:   signerplugin.SuiteCNSMV1,
		Algorithm:     WrappedSM4KeyAlgorithm,
		Device:        device,
		KEKID:         kekID,
		KEKIndex:      kekIndex,
		Wrapped:       append([]byte(nil), wrapped...),
	}
	checksum, err := value.calculateChecksum()
	if err != nil {
		return WrappedSM4Key{}, err
	}
	value.ChecksumSM3 = checksum
	if err := value.Validate(); err != nil {
		return WrappedSM4Key{}, err
	}
	return value, nil
}

func (w WrappedSM4Key) Validate() error {
	if w.SchemaVersion != WrappedSM4KeySchemaV1 {
		return wrappedSM4Error("schema_version is unsupported")
	}
	if w.CryptoSuite != signerplugin.SuiteCNSMV1 {
		return wrappedSM4Error("crypto_suite is unsupported")
	}
	if w.Algorithm != WrappedSM4KeyAlgorithm {
		return wrappedSM4Error("algorithm is unsupported")
	}
	if err := validateIdentity(w.Device); err != nil {
		return wrappedSM4Error("device identity is invalid")
	}
	if !validIdentifier(w.KEKID, 256) || w.KEKIndex == 0 {
		return wrappedSM4Error("KEK identity is invalid")
	}
	if len(w.Wrapped) == 0 || len(w.Wrapped) > MaxWrappedKeyBytes {
		return wrappedSM4Error("wrapped key length is invalid")
	}
	if len(w.ChecksumSM3) != wrappedSM4ChecksumSize {
		return wrappedSM4Error("checksum length is invalid")
	}
	checksum, err := w.calculateChecksum()
	if err != nil {
		return err
	}
	if !bytes.Equal(checksum, w.ChecksumSM3) {
		return wrappedSM4Error("checksum does not match")
	}
	return nil
}

func (w WrappedSM4Key) Clone() WrappedSM4Key {
	w.Wrapped = append([]byte(nil), w.Wrapped...)
	w.ChecksumSM3 = append([]byte(nil), w.ChecksumSM3...)
	return w
}

func MarshalWrappedSM4Key(value WrappedSM4Key) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	encoded, err := cborx.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidWrappedSM4Key, err)
	}
	if len(encoded) > maxWrappedSM4Envelope {
		return nil, wrappedSM4Error("encoded envelope is too large")
	}
	return encoded, nil
}

func UnmarshalWrappedSM4Key(encoded []byte) (WrappedSM4Key, error) {
	if len(encoded) == 0 || len(encoded) > maxWrappedSM4Envelope {
		return WrappedSM4Key{}, wrappedSM4Error("encoded envelope length is invalid")
	}
	var value WrappedSM4Key
	if err := cborx.UnmarshalLimit(encoded, &value, maxWrappedSM4Envelope); err != nil {
		return WrappedSM4Key{}, fmt.Errorf("%w: decode: %v", ErrInvalidWrappedSM4Key, err)
	}
	if err := value.Validate(); err != nil {
		return WrappedSM4Key{}, err
	}
	canonical, err := cborx.Marshal(value)
	if err != nil {
		return WrappedSM4Key{}, fmt.Errorf("%w: re-encode: %v", ErrInvalidWrappedSM4Key, err)
	}
	if !bytes.Equal(canonical, encoded) {
		return WrappedSM4Key{}, ErrNonCanonicalWrappedSM4Key
	}
	return value.Clone(), nil
}

func (w WrappedSM4Key) calculateChecksum() ([]byte, error) {
	payload := wrappedSM4KeyPayload{
		SchemaVersion: w.SchemaVersion,
		CryptoSuite:   w.CryptoSuite,
		Algorithm:     w.Algorithm,
		Device:        w.Device,
		KEKID:         w.KEKID,
		KEKIndex:      w.KEKIndex,
		Wrapped:       w.Wrapped,
	}
	encoded, err := cborx.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: encode checksum payload: %v", ErrInvalidWrappedSM4Key, err)
	}
	digest := sm3.Sum(encoded)
	return append([]byte(nil), digest[:]...), nil
}

func wrappedSM4Error(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidWrappedSM4Key, message)
}
