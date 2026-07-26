package sdfsigner

import (
	"bytes"
	"errors"
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/cborx"
)

func TestWrappedSM4KeyDeterministicCBORRoundTrip(t *testing.T) {
	t.Parallel()
	value := testWrappedSM4Key(t)
	first, err := MarshalWrappedSM4Key(value)
	if err != nil {
		t.Fatal(err)
	}
	second, err := MarshalWrappedSM4Key(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("deterministic encoding differs:\n%x\n%x", first, second)
	}
	decoded, err := UnmarshalWrappedSM4Key(first)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != WrappedSM4KeySchemaV1 ||
		decoded.CryptoSuite != value.CryptoSuite ||
		decoded.Algorithm != WrappedSM4KeyAlgorithm ||
		decoded.Device != value.Device ||
		decoded.KEKID != value.KEKID ||
		decoded.KEKIndex != value.KEKIndex ||
		!bytes.Equal(decoded.Wrapped, value.Wrapped) ||
		!bytes.Equal(decoded.ChecksumSM3, value.ChecksumSM3) {
		t.Fatalf("decoded = %+v, want %+v", decoded, value)
	}
	decoded.Wrapped[0] ^= 0xff
	decoded.ChecksumSM3[0] ^= 0xff
	if bytes.Equal(decoded.Wrapped, value.Wrapped) ||
		bytes.Equal(decoded.ChecksumSM3, value.ChecksumSM3) {
		t.Fatal("decoded envelope retained mutable input aliases")
	}
}

func TestWrappedSM4KeyRejectsCorruptionAndBindingChanges(t *testing.T) {
	t.Parallel()
	base := testWrappedSM4Key(t)
	tests := []struct {
		name   string
		mutate func(*WrappedSM4Key)
	}{
		{name: "schema", mutate: func(value *WrappedSM4Key) { value.SchemaVersion = "trustdb.sdf-wrapped-sm4-key.v2" }},
		{name: "suite", mutate: func(value *WrappedSM4Key) { value.CryptoSuite = "INTL_V1" }},
		{name: "algorithm", mutate: func(value *WrappedSM4Key) { value.Algorithm = "sm4-other" }},
		{name: "device", mutate: func(value *WrappedSM4Key) { value.Device.Serial = "replacement" }},
		{name: "kek id", mutate: func(value *WrappedSM4Key) { value.KEKID = "backup-kek-v2" }},
		{name: "kek index", mutate: func(value *WrappedSM4Key) { value.KEKIndex++ }},
		{name: "wrapped blob", mutate: func(value *WrappedSM4Key) { value.Wrapped[0] ^= 0xff }},
		{name: "checksum", mutate: func(value *WrappedSM4Key) { value.ChecksumSM3[0] ^= 0xff }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			value := base.Clone()
			test.mutate(&value)
			if _, err := MarshalWrappedSM4Key(value); !errors.Is(err, ErrInvalidWrappedSM4Key) {
				t.Fatalf("MarshalWrappedSM4Key() error = %v", err)
			}
		})
	}
}

func TestWrappedSM4KeyRejectsUnknownTrailingAndNonCanonicalCBOR(t *testing.T) {
	t.Parallel()
	canonical, err := MarshalWrappedSM4Key(testWrappedSM4Key(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalWrappedSM4Key(append(append([]byte(nil), canonical...), 0xf6)); err == nil {
		t.Fatal("UnmarshalWrappedSM4Key() accepted trailing data")
	}
	var fields map[string]any
	if err := cborx.Unmarshal(canonical, &fields); err != nil {
		t.Fatal(err)
	}
	fields["unknown"] = "rejected"
	unknown, err := cborx.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalWrappedSM4Key(unknown); err == nil {
		t.Fatal("UnmarshalWrappedSM4Key() accepted an unknown field")
	}

	needle := append([]byte{0x69}, []byte("kek_index")...)
	needle = append(needle, 0x0b)
	index := bytes.Index(canonical, needle)
	if index < 0 {
		t.Fatalf("canonical fixture lacks expected kek_index encoding: %x", canonical)
	}
	nonCanonical := make([]byte, 0, len(canonical)+1)
	nonCanonical = append(nonCanonical, canonical[:index+len(needle)-1]...)
	nonCanonical = append(nonCanonical, 0x18, 0x0b)
	nonCanonical = append(nonCanonical, canonical[index+len(needle):]...)
	if _, err := UnmarshalWrappedSM4Key(nonCanonical); !errors.Is(err, ErrNonCanonicalWrappedSM4Key) {
		t.Fatalf("UnmarshalWrappedSM4Key(non-canonical) error = %v", err)
	}
}

func testWrappedSM4Key(t *testing.T) WrappedSM4Key {
	t.Helper()
	value, err := NewWrappedSM4Key(
		DeviceIdentity{
			AdapterID:      "trustdb.fake-sdf",
			AdapterVersion: "1.0.0",
			DeviceID:       "sdf-production",
			Serial:         "serial-1",
			Firmware:       "firmware-1",
		},
		"backup-kek-v1",
		11,
		[]byte{0x53, 0x01, 0x02, 0x03},
	)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
