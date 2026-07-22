// Package anchor implements the L5 (Anchored) proof layer. It defines a
// generic Sink interface for external notaries (file, Certificate
// Transparency, public blockchains, ...) and a background worker that
// claims the durable coalescing schedule and records immutable results.
//
// The separation is intentional: publication code only coalesces one
// Pending target. All retry, backoff, observability and
// sink-specific quirks live behind the Sink contract, so swapping a
// FileSink for a CtLogSink is a configuration change rather than a
// code change in the batch pipeline.
package anchor

import (
	"context"
	"errors"

	"github.com/wowtrust/trustdb/internal/model"
)

// Sink is the one-method contract every external notary must satisfy.
// Name returns a short stable identifier ("file", "ct", "bitcoin",
// ...) recorded in every STHAnchorResult so that a
// proof verifier can pick the right Sink-specific proof parser.
//
// Publish must return either:
//
//   - (result, nil)    on success; the worker stores the immutable result
//     and atomically completes the matching InFlight generation.
//   - (_, ErrPermanent) wrapped error on a non-retryable failure
//     (e.g. schema rejected, signature algorithm unknown). The worker
//     records a terminal schedule failure and never retries that target.
//   - (_, any other error) on a transient failure. The worker bumps
//     the attempts counter and reschedules the same immutable InFlight target.
//
// Implementations should use errors.Is(err, anchor.ErrPermanent) when
// they need to declare a permanent failure so the worker can
// distinguish the two classes without string matching.
type Sink interface {
	Name() string
	Publish(ctx context.Context, sth model.SignedTreeHead) (model.STHAnchorResult, error)
}

// ErrPermanent is a sentinel wrapped by Sink implementations to signal
// that retrying will not help. The worker only checks it via
// errors.Is, so callers can wrap it freely with fmt.Errorf("%w: ...",
// anchor.ErrPermanent) and preserve their own message.
var ErrPermanent = errors.New("anchor: permanent sink failure")
