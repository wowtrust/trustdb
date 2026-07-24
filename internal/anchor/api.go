package anchor

import (
	"context"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

// API exposes immutable anchor results to transport layers. It is a thin
// wrapper around a proofstore.Store so tests and CLI code can use an
// in-memory store without pulling in the full Service.
type API struct {
	Store proofstore.Store
}

// NewAPI constructs an API backed by the provided store.
func NewAPI(store proofstore.Store) *API { return &API{Store: store} }

func (a *API) AnchorResult(ctx context.Context, treeSize uint64) (model.STHAnchorResult, bool, error) {
	result, found, err := a.Store.GetSTHAnchorResult(ctx, treeSize)
	if err != nil || !found {
		return result, found, err
	}
	key := anchorschedule.ScheduleKey(anchorschedule.ResultKey(result))
	if err := anchorschedule.ValidateResult(key, result); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "stored anchor result is invalid", err)
	}
	return result, true, nil
}

func (a *API) Anchors(ctx context.Context, opts model.AnchorListOptions) ([]model.STHAnchorResult, error) {
	pager, ok := a.Store.(proofstore.STHAnchorResultPager)
	if !ok {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "proofstore does not support immutable anchor result pagination")
	}
	if opts.Limit <= 0 {
		opts.Limit = 100
	}
	if opts.Limit > 1000 {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "limit must be between 1 and 1000")
	}
	switch opts.Direction {
	case "":
		opts.Direction = model.RecordListDirectionDesc
	case model.RecordListDirectionAsc, model.RecordListDirectionDesc:
	default:
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "direction must be asc or desc")
	}
	if opts.HasAfter {
		if err := anchorschedule.ValidateResultKey(opts.AfterResultKey); err != nil {
			return nil, err
		}
	}
	results, err := pager.ListSTHAnchorResultsPage(ctx, opts)
	if err != nil {
		return nil, err
	}
	for _, result := range results {
		key := anchorschedule.ScheduleKey(anchorschedule.ResultKey(result))
		if err := anchorschedule.ValidateResult(key, result); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "stored anchor result is invalid", err)
		}
	}
	return results, nil
}
