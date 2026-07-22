package l5coverage

import (
	"testing"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestAdvanceIsMonotonic(t *testing.T) {
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	first, changed, err := Advance(model.L5CoverageCheckpoint{}, false, key, 8, 100)
	if err != nil || !changed || first.CoveredTreeSize != 8 || first.Revision != 1 {
		t.Fatalf("Advance first = %+v changed=%v err=%v", first, changed, err)
	}
	unchanged, changed, err := Advance(first, true, key, 5, 200)
	if err != nil || changed || unchanged != first {
		t.Fatalf("Advance lower = %+v changed=%v err=%v", unchanged, changed, err)
	}
	advanced, changed, err := Advance(first, true, key, 12, 300)
	if err != nil || !changed || advanced.CoveredTreeSize != 12 || advanced.Revision != 2 {
		t.Fatalf("Advance higher = %+v changed=%v err=%v", advanced, changed, err)
	}
}

func TestAdvanceRejectsMismatchedKey(t *testing.T) {
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	current, _, err := Advance(model.L5CoverageCheckpoint{}, false, key, 8, 100)
	if err != nil {
		t.Fatalf("Advance first: %v", err)
	}
	other := key
	other.SinkName = "ots"
	if _, _, err := Advance(current, true, other, 12, 200); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("Advance mismatch = %v", err)
	}
}
