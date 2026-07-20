package sdk

import (
	"strconv"
	"testing"

	"github.com/ryan-wong-coder/trustdb/internal/model"
)

func TestRecordPageFromEnvelopeTransfersDecodedRecords(t *testing.T) {
	t.Parallel()

	records := []RecordIndex{{RecordID: "tr1one"}, {RecordID: "tr1two"}}
	page := recordPageFromEnvelope(recordsEnvelope{
		Records:    records,
		Limit:      2,
		Direction:  RecordListDirectionAsc,
		NextCursor: "next",
	})
	if len(page.Records) != 2 || &page.Records[0] != &records[0] {
		t.Fatalf("records were copied: page=%+v", page.Records)
	}
	if page.Limit != 2 || page.Direction != RecordListDirectionAsc || page.NextCursor != "next" {
		t.Fatalf("page metadata = %+v", page)
	}
}

func TestRecordPageFromEnvelopePreservesNonNilEmptyRecords(t *testing.T) {
	t.Parallel()

	page := recordPageFromEnvelope(recordsEnvelope{})
	if page.Records == nil || len(page.Records) != 0 {
		t.Fatalf("records = %#v, want non-nil empty slice", page.Records)
	}
}

func BenchmarkRecordPageFromEnvelope1000(b *testing.B) {
	records := make([]RecordIndex, 1000)
	for index := range records {
		records[index] = RecordIndex{
			SchemaVersion: model.SchemaRecordIndex,
			RecordID:      "tr1record-" + strconv.Itoa(index),
			BatchID:       "batch-benchmark",
			TenantID:      "tenant-benchmark",
			ClientID:      "client-benchmark",
			ProofLevel:    ProofLevelL3,
		}
	}
	env := recordsEnvelope{
		Records:    records,
		Limit:      len(records),
		Direction:  RecordListDirectionDesc,
		NextCursor: "next-page",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkRecordPage = recordPageFromEnvelope(env)
	}
}

var benchmarkRecordPage RecordPage
