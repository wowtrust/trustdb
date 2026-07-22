package anchor

import (
	"context"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
)

// NoopSinkName is the stable identifier for the NoopSink. It is
// primarily used in tests and for `--anchor-sink=noop` deployments
// where operators want the anchor worker plumbing to run but without
// any external notary.
const NoopSinkName = "noop"

// NoopSink immediately returns a successful STHAnchorResult without
// touching any external system. It is useful in tests, local
// development and as a safety net when the operator wants to disable
// external anchoring but keep the outbox pipeline active (so no batch
// is silently skipped when a real Sink is configured later).
type NoopSink struct{}

// NewNoopSink is a constructor for symmetry with other sinks; callers
// can use NoopSink{} directly but the function makes the
// DI/registration code read uniformly.
func NewNoopSink() *NoopSink { return &NoopSink{} }

func (NoopSink) Name() string { return NoopSinkName }

// Publish never fails and never returns ErrPermanent. The AnchorID is
// derived from the STH tree size so replay produces the same id and the
// outbox stays idempotent.
func (NoopSink) Publish(ctx context.Context, sth model.SignedTreeHead) (model.STHAnchorResult, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorResult{}, err
	}
	return model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		NodeID:           sth.NodeID,
		LogID:            sth.LogID,
		TreeSize:         sth.TreeSize,
		SinkName:         NoopSinkName,
		AnchorID:         DeterministicNoopAnchorID(sth),
		RootHash:         sth.RootHash,
		STH:              sth,
		PublishedAtUnixN: time.Now().UTC().UnixNano(),
	}, nil
}
