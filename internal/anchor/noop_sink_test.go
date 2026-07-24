package anchor

import (
	"context"
	"testing"

	"github.com/wowtrust/trustdb/internal/model"
)

func TestNoopSinkProducesLocalOnlyL4Result(t *testing.T) {
	t.Parallel()
	sth := testSTH(testScheduleKey(NoopSinkName), 3, 0x33)
	result, err := (NoopSink{}).Publish(context.Background(), sth)
	if err != nil {
		t.Fatal(err)
	}
	if result.EvidenceStage != model.AnchorEvidenceStageLocalOnly ||
		model.AnchorResultProvidesOfflineL5(result) {
		t.Fatalf("noop result=%+v, want local-only non-L5 evidence", result)
	}
}
