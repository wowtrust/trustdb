package anchor

import (
	"context"
	"testing"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
)

type countingAnchorPageStore struct {
	proofstore.LocalStore
	pageCalls int
}

func (s *countingAnchorPageStore) ListSTHAnchorResultsPage(ctx context.Context, opts model.AnchorListOptions) ([]model.STHAnchorResult, error) {
	s.pageCalls++
	return s.LocalStore.ListSTHAnchorResultsPage(ctx, opts)
}

func TestAPIAnchorsCompositeCursorRetainsSameTreeSinks(t *testing.T) {
	t.Parallel()
	store := &countingAnchorPageStore{LocalStore: newBoundTestLocalStore(t, t.TempDir())}
	writer := proofstore.STHAnchorResultWriter(store)
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	sth := testSTH(key, 7, 0x77)
	for _, tc := range []struct {
		sinkName string
		anchorID string
	}{
		{sinkName: "file", anchorID: "anchor-file-7"},
		{sinkName: "ots", anchorID: "anchor-ots-7"},
	} {
		result := model.STHAnchorResult{
			SchemaVersion:    model.SchemaSTHAnchorResult,
			CryptoSuite:      cryptosuite.INTLV1,
			EvidenceStage:    model.AnchorEvidenceStageOfflineVerified,
			NodeID:           sth.NodeID,
			LogID:            sth.LogID,
			TreeSize:         sth.TreeSize,
			SinkName:         tc.sinkName,
			AnchorID:         tc.anchorID,
			RootHash:         append([]byte(nil), sth.RootHash...),
			STH:              sth,
			PublishedAtUnixN: 700,
		}
		if err := writer.PutSTHAnchorResult(context.Background(), result); err != nil {
			t.Fatalf("PutSTHAnchorResult(%s): %v", tc.sinkName, err)
		}
	}

	api := NewAPI(store)
	first, err := api.Anchors(context.Background(), model.AnchorListOptions{Limit: 1, Direction: model.RecordListDirectionDesc})
	if err != nil || len(first) != 1 {
		t.Fatalf("first page=%+v err=%v", first, err)
	}
	second, err := api.Anchors(context.Background(), model.AnchorListOptions{
		Limit: 1, Direction: model.RecordListDirectionDesc,
		AfterResultKey: anchorschedule.ResultKey(first[0]), HasAfter: true,
	})
	if err != nil || len(second) != 1 {
		t.Fatalf("second page=%+v err=%v", second, err)
	}
	if first[0].TreeSize != second[0].TreeSize || first[0].SinkName == second[0].SinkName {
		t.Fatalf("same-tree sink pagination skipped or duplicated a result: first=%+v second=%+v", first[0], second[0])
	}
	if store.pageCalls != 2 {
		t.Fatalf("bounded pager calls = %d, want one seek per API page", store.pageCalls)
	}
}
