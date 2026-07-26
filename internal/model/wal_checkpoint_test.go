package model

import (
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
)

// legacyWALCheckpoint pins the pre-suite wire shape so the V3 cutover can
// prove that old readers fail closed instead of silently accepting V3 state.
type legacyWALCheckpoint struct {
	SchemaVersion   string `cbor:"schema_version"`
	SegmentID       uint64 `cbor:"segment_id"`
	LastSequence    uint64 `cbor:"last_sequence"`
	LastOffset      int64  `cbor:"last_offset"`
	BatchID         string `cbor:"batch_id,omitempty"`
	RecordedAtUnixN int64  `cbor:"recorded_at_unix_nano"`
}

func TestContiguousWALCheckpointV3RejectsLegacyDecoder(t *testing.T) {
	want := WALCheckpoint{
		SchemaVersion:   SchemaWALCheckpointContiguous,
		CryptoSuite:     cryptosuite.INTLV1,
		SegmentID:       7,
		LastSequence:    42,
		LastOffset:      8192,
		BatchID:         "batch-42",
		RecordedAtUnixN: 123456,
	}
	data, err := cborx.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var got legacyWALCheckpoint
	if err := cborx.Unmarshal(data, &got); err == nil {
		t.Fatal("legacy decoder accepted V3 checkpoint with crypto_suite")
	}
}
