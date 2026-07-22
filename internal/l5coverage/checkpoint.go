// Package l5coverage defines the monotonic state transition used by every
// proofstore backend for the derived L5 coverage projection.
package l5coverage

import (
	"math"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func ValidateCheckpoint(checkpoint model.L5CoverageCheckpoint) error {
	if checkpoint.SchemaVersion != model.SchemaL5Coverage {
		return trusterr.New(trusterr.CodeDataLoss, "unsupported L5 coverage checkpoint schema")
	}
	if err := anchorschedule.ValidateKey(checkpoint.Key); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "invalid L5 coverage checkpoint key", err)
	}
	if checkpoint.CoveredTreeSize == 0 {
		return trusterr.New(trusterr.CodeDataLoss, "L5 coverage checkpoint tree size is required")
	}
	if checkpoint.Revision == 0 {
		return trusterr.New(trusterr.CodeDataLoss, "L5 coverage checkpoint revision is required")
	}
	if checkpoint.UpdatedAtUnixN < 0 {
		return trusterr.New(trusterr.CodeDataLoss, "L5 coverage checkpoint update time is invalid")
	}
	return nil
}

func Advance(current model.L5CoverageCheckpoint, found bool, key model.STHAnchorScheduleKey, coveredTreeSize uint64, updatedAtUnixN int64) (model.L5CoverageCheckpoint, bool, error) {
	if err := anchorschedule.ValidateKey(key); err != nil {
		return model.L5CoverageCheckpoint{}, false, err
	}
	if coveredTreeSize == 0 {
		return model.L5CoverageCheckpoint{}, false, trusterr.New(trusterr.CodeInvalidArgument, "covered_tree_size is required")
	}
	if updatedAtUnixN < 0 {
		return model.L5CoverageCheckpoint{}, false, trusterr.New(trusterr.CodeInvalidArgument, "updated_at_unix_nano must be non-negative")
	}
	if found {
		if err := ValidateCheckpoint(current); err != nil {
			return model.L5CoverageCheckpoint{}, false, err
		}
		if !anchorschedule.SameKey(current.Key, key) {
			return model.L5CoverageCheckpoint{}, false, trusterr.New(trusterr.CodeDataLoss, "L5 coverage checkpoint key mismatch")
		}
		if coveredTreeSize <= current.CoveredTreeSize {
			return current, false, nil
		}
		if current.Revision == math.MaxUint64 {
			return model.L5CoverageCheckpoint{}, false, trusterr.New(trusterr.CodeDataLoss, "L5 coverage checkpoint revision overflow")
		}
	}
	revision := uint64(1)
	if found {
		revision = current.Revision + 1
	}
	next := model.L5CoverageCheckpoint{
		SchemaVersion:   model.SchemaL5Coverage,
		Key:             key,
		CoveredTreeSize: coveredTreeSize,
		Revision:        revision,
		UpdatedAtUnixN:  updatedAtUnixN,
	}
	return next, true, nil
}
