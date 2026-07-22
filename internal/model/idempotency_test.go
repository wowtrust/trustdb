package model

import (
	"reflect"
	"testing"

	"github.com/wowtrust/trustdb/internal/cborx"
)

func TestIdempotencyDecisionCBORRoundTrip(t *testing.T) {
	t.Parallel()

	want := IdempotencyDecision{
		SchemaVersion: SchemaIdempotencyDecision,
		Identity: IdempotencyIdentity{
			TenantID:       "tenant-a",
			ClientID:       "client-a",
			IdempotencyKey: "request-a",
		},
		ClaimHash: []byte{1, 2, 3},
		Record: ServerRecord{
			SchemaVersion: SchemaServerRecord,
			RecordID:      "record-a",
			TenantID:      "tenant-a",
			ClientID:      "client-a",
			WAL:           WALPosition{SegmentID: 1, Offset: 64, Sequence: 7},
		},
		Accepted: AcceptedReceipt{
			SchemaVersion: SchemaAcceptedReceipt,
			RecordID:      "record-a",
			Status:        "accepted",
			WAL:           WALPosition{SegmentID: 1, Offset: 64, Sequence: 7},
		},
		BatchID: "batch-a",
	}
	data, err := cborx.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var got IdempotencyDecision
	if err := cborx.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}
