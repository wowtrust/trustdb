package model

import (
	"testing"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
)

// legacyWALCheckpoint pins the v1 wire shape. A rollback binary can decode a
// v2 checkpoint safely because contiguous coverage is signaled only by the
// schema string, not by a new CBOR field rejected by strict decoders.
type legacyWALCheckpoint struct {
	SchemaVersion   string `cbor:"schema_version"`
	SegmentID       uint64 `cbor:"segment_id"`
	LastSequence    uint64 `cbor:"last_sequence"`
	LastOffset      int64  `cbor:"last_offset"`
	BatchID         string `cbor:"batch_id,omitempty"`
	RecordedAtUnixN int64  `cbor:"recorded_at_unix_nano"`
}

func TestContiguousWALCheckpointKeepsLegacyWireShape(t *testing.T) {
	want := WALCheckpoint{
		SchemaVersion:   SchemaWALCheckpointContiguous,
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
	if err := cborx.Unmarshal(data, &got); err != nil {
		t.Fatalf("legacy decoder rejected v2 checkpoint: %v", err)
	}
	if got.SchemaVersion != want.SchemaVersion || got.SegmentID != want.SegmentID ||
		got.LastSequence != want.LastSequence || got.LastOffset != want.LastOffset ||
		got.BatchID != want.BatchID || got.RecordedAtUnixN != want.RecordedAtUnixN {
		t.Fatalf("legacy decode = %+v, want %+v", got, want)
	}
}
