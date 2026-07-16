package anchor

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/observability"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
)

// Upgrader-side defaults. The cadence is intentionally far slower
// than the anchor-publisher worker because OTS calendars only fold a
// commitment into a Bitcoin block roughly every block (~10 minutes
// average) and many calendars batch upgrades hourly.
const (
	defaultUpgradePollInterval = 1 * time.Hour
	defaultUpgradeBatchSize    = 64
	defaultUpgradePerCallTO    = 30 * time.Second
)

// UpgraderConfig collects every knob OtsUpgrader respects. Store is
// the only required field; everything else has a sensible default.
type UpgraderConfig struct {
	Store proofstore.Store

	// HTTPOptions overrides the per-calendar HTTP client used for
	// upgrade GETs. Tests inject a fake transport via this field;
	// production leaves it zero so each tick uses a fresh
	// http.Client with the configured timeout.
	HTTPOptions OtsUpgradeOptions

	// Metrics is optional; nil disables observability. Useful for
	// tests that don't want to register a Prometheus collector.
	Metrics *observability.Metrics
	Logger  zerolog.Logger

	// PollInterval is the wall-clock gap between sweeps. Defaults
	// to 1h. Setting this below ~5 minutes is rarely useful — the
	// public OTS calendar pool will simply return the same pending
	// bytes most of the time and you'll waste both their bandwidth
	// and your CPU on JSON re-marshalling.
	PollInterval time.Duration
	// BatchSize caps how many STHAnchorResults a single sweep
	// processes. The store iteration is cheap, but the HTTP
	// timestamps add up; a moderate cap keeps a single sweep
	// bounded so other goroutines on the shared store handle make
	// progress.
	BatchSize int
	// Workers bounds concurrent upgrades for independent STHs.
	Workers int
	// Clock makes UnixNano deterministic in tests; nil => time.Now.
	Clock func() time.Time
}

func (c *UpgraderConfig) applyDefaults() {
	if c.PollInterval <= 0 {
		c.PollInterval = defaultUpgradePollInterval
	}
	if c.BatchSize <= 0 {
		c.BatchSize = defaultUpgradeBatchSize
	}
	if c.Workers <= 0 {
		c.Workers = 4
	}
	if c.HTTPOptions.Timeout <= 0 {
		c.HTTPOptions.Timeout = defaultUpgradePerCallTO
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
}

// OtsUpgrader periodically walks every published OTS STHAnchorResult and
// asks each calendar whether its commitment has been folded into a
// Bitcoin block. When yes, it rewrites STHAnchorResult.Proof in place
// (via proofstore.MarkSTHAnchorPublished) so verification tooling sees
// the upgraded bytes without operator intervention.
//
// The loop is intentionally idempotent: a Calendar marked Upgraded
// (set by UpgradeOtsProof on a successful byte change) is skipped on
// every subsequent sweep, so a fully-attested batch costs zero HTTP
// requests forever after.
type OtsUpgrader struct {
	cfg UpgraderConfig

	// trigger is a 1-buffered channel so a manual Trigger() never
	// blocks and never enqueues more than one extra sweep.
	trigger chan struct{}

	mu      sync.Mutex
	running bool
	stop    chan struct{}
	done    chan struct{}
}

// NewOtsUpgrader builds an OtsUpgrader with defaults applied. Store
// is required; everything else may be zero.
func NewOtsUpgrader(cfg UpgraderConfig) (*OtsUpgrader, error) {
	if cfg.Store == nil {
		return nil, errors.New("ots upgrader: store is required")
	}
	cfg.applyDefaults()
	return &OtsUpgrader{
		cfg:     cfg,
		trigger: make(chan struct{}, 1),
	}, nil
}

// Start launches the worker goroutine. Multiple Start calls are
// no-ops after the first so accidental double-wiring during startup
// cannot double-launch the worker.
func (u *OtsUpgrader) Start(ctx context.Context) {
	u.mu.Lock()
	if u.running {
		u.mu.Unlock()
		return
	}
	u.running = true
	u.stop = make(chan struct{})
	u.done = make(chan struct{})
	u.mu.Unlock()

	go u.run(ctx)
}

// Stop signals the worker to exit and blocks until the in-flight
// sweep completes. Safe to call when the upgrader was never started
// (no-op) or has already stopped (no-op).
func (u *OtsUpgrader) Stop() {
	u.mu.Lock()
	if !u.running {
		u.mu.Unlock()
		return
	}
	close(u.stop)
	done := u.done
	u.running = false
	u.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Trigger wakes the upgrader immediately instead of waiting for the
// next tick. Non-blocking; a second call while a wakeup is pending
// is dropped because consecutive triggers cannot add information.
func (u *OtsUpgrader) Trigger() {
	select {
	case u.trigger <- struct{}{}:
	default:
	}
}

// run owns the timer + select loop. Errors inside tick() are logged
// but never propagate, so a transient store / HTTP failure cannot
// silently kill the upgrader.
func (u *OtsUpgrader) run(ctx context.Context) {
	defer close(u.done)
	// First sweep happens promptly so a server that just started
	// up and inherits a backlog of pending batches makes immediate
	// forward progress instead of idling for PollInterval.
	u.tick(ctx)
	timer := time.NewTimer(u.cfg.PollInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-u.stop:
			return
		case <-timer.C:
			u.tick(ctx)
			timer.Reset(u.cfg.PollInterval)
		case <-u.trigger:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			u.tick(ctx)
			timer.Reset(u.cfg.PollInterval)
		}
	}
}

// TickOnce runs a single sweep synchronously and returns the per-
// outcome counts. Exposed (with the "Tick" name reserved for the
// background loop) so integration tests can drive the worker without
// races.
func (u *OtsUpgrader) TickOnce(ctx context.Context) UpgraderTickStats {
	return u.tick(ctx)
}

// UpgraderTickStats is the per-sweep summary returned by TickOnce.
// All counters are aggregated across every batch the sweep visited;
// per-batch detail lives in the structured logger output.
type UpgraderTickStats struct {
	Visited           int
	Skipped           int
	Changed           int
	Unchanged         int
	Errored           int
	StillPending      int
	CalendarChanged   int
	CalendarUnchanged int
	CalendarErrored   int
}

func (u *OtsUpgrader) tick(ctx context.Context) UpgraderTickStats {
	var stats UpgraderTickStats
	if ctx.Err() != nil {
		return stats
	}
	if u.cfg.Metrics != nil {
		u.cfg.Metrics.OtsUpgradeRuns.Inc()
	}
	items, err := u.cfg.Store.ListPublishedSTHAnchors(ctx, u.cfg.BatchSize)
	if err != nil {
		u.cfg.Logger.Warn().Err(err).Msg("ots-upgrader: list published failed")
		return stats
	}
	treeSizes := make([]uint64, 0, len(items))
	for _, item := range items {
		if item.SinkName == OtsSinkName {
			treeSizes = append(treeSizes, item.TreeSize)
		}
	}
	workers := min(u.cfg.Workers, len(treeSizes))
	if workers > 0 {
		jobs := make(chan uint64)
		results := make(chan UpgraderTickStats, len(treeSizes))
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for treeSize := range jobs {
					local := UpgraderTickStats{Visited: 1}
					u.processOne(ctx, treeSize, &local)
					results <- local
				}
			}()
		}
		for _, treeSize := range treeSizes {
			select {
			case jobs <- treeSize:
			case <-ctx.Done():
				break
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
		for local := range results {
			mergeUpgraderTickStats(&stats, local)
		}
	}
	if u.cfg.Metrics != nil {
		u.cfg.Metrics.OtsPendingBatches.Set(float64(stats.StillPending))
	}
	u.cfg.Logger.Debug().
		Int("visited", stats.Visited).
		Int("changed", stats.Changed).
		Int("skipped", stats.Skipped).
		Int("still_pending", stats.StillPending).
		Msg("ots-upgrader: tick complete")
	return stats
}

func mergeUpgraderTickStats(dst *UpgraderTickStats, src UpgraderTickStats) {
	dst.Visited += src.Visited
	dst.Skipped += src.Skipped
	dst.Changed += src.Changed
	dst.Unchanged += src.Unchanged
	dst.Errored += src.Errored
	dst.StillPending += src.StillPending
	dst.CalendarChanged += src.CalendarChanged
	dst.CalendarUnchanged += src.CalendarUnchanged
	dst.CalendarErrored += src.CalendarErrored
}

// processOne loads the STHAnchorResult, runs the upgrade probe, and
// persists when something changed. errors are logged + reflected in
// stats; the loop keeps going so one bad batch can't stall the rest.
func (u *OtsUpgrader) processOne(ctx context.Context, treeSize uint64, stats *UpgraderTickStats) {
	logger := u.cfg.Logger.With().Uint64("tree_size", treeSize).Logger()
	ar, ok, err := u.cfg.Store.GetSTHAnchorResult(ctx, treeSize)
	if err != nil {
		stats.Errored++
		u.markBatchOutcome("error")
		logger.Warn().Err(err).Msg("ots-upgrader: get anchor result failed")
		return
	}
	if !ok {
		// Outbox says published but the result is missing. The
		// anchor worker already tolerates this race during
		// crash recovery; we simply skip the batch this tick and
		// let the worker restore the result on its own schedule.
		stats.Skipped++
		u.markBatchOutcome("skipped")
		return
	}

	updated, summary, err := UpgradeAnchorResult(ctx, ar, u.cfg.HTTPOptions)
	if err != nil {
		stats.Errored++
		u.markBatchOutcome("error")
		logger.Warn().Err(err).Msg("ots-upgrader: upgrade probe failed")
		return
	}

	for _, c := range summary.Calendars {
		switch {
		case c.Changed:
			stats.CalendarChanged++
			u.markCalendarOutcome("changed")
		case c.Error != "":
			stats.CalendarErrored++
			u.markCalendarOutcome("error")
		default:
			stats.CalendarUnchanged++
			u.markCalendarOutcome("unchanged")
		}
	}

	if !summary.Changed {
		// Re-decode the (unchanged) proof so we can update the
		// pending-batches gauge accurately. Cheap because the
		// envelope is at most a few KB and we already paid the
		// network cost above.
		if proof, decodeErr := decodeOtsProofEnvelope(ar.Proof); decodeErr == nil && !proof.AllUpgraded() {
			stats.StillPending++
		}
		stats.Unchanged++
		u.markBatchOutcome("unchanged")
		return
	}
	if err := u.cfg.Store.MarkSTHAnchorPublished(ctx, updated); err != nil {
		stats.Errored++
		u.markBatchOutcome("error")
		logger.Warn().Err(err).Msg("ots-upgrader: persist upgraded result failed")
		return
	}
	stats.Changed++
	u.markBatchOutcome("changed")
	if proof, decodeErr := decodeOtsProofEnvelope(updated.Proof); decodeErr == nil && !proof.AllUpgraded() {
		stats.StillPending++
	}
	logger.Info().
		Int("calendars_changed", stats.CalendarChanged).
		Msg("ots-upgrader: persisted upgraded proof")
}

// decodeOtsProofEnvelope is a tiny private helper that lets the
// upgrader peek inside an STHAnchorResult.Proof without depending on the
// JSON marshalling subtleties of OtsAnchorProof. Lives next to the
// upgrader because UpgradeAnchorResult already does the analogous
// work for the public path.
func decodeOtsProofEnvelope(b []byte) (*OtsAnchorProof, error) {
	if len(b) == 0 {
		return nil, errors.New("empty proof bytes")
	}
	var p OtsAnchorProof
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// _ = model.STHAnchorOutboxItem is a deliberate import-pin to document
// that the upgrader only cares about a tiny subset (TreeSize +
// SinkName) of STHAnchorOutboxItem and would not break if the wider
// shape changes. Removing it is fine; keeping it makes intent
// explicit during code review.
var _ = model.STHAnchorOutboxItem{}

// markBatchOutcome / markCalendarOutcome guard the metric Inc() calls
// so callers don't have to spell out the nil-guard at every site.
func (u *OtsUpgrader) markBatchOutcome(outcome string) {
	if u.cfg.Metrics == nil {
		return
	}
	u.cfg.Metrics.OtsUpgradeBatches.WithLabelValues(outcome).Inc()
}

func (u *OtsUpgrader) markCalendarOutcome(outcome string) {
	if u.cfg.Metrics == nil {
		return
	}
	u.cfg.Metrics.OtsUpgradeCalendarHits.WithLabelValues(outcome).Inc()
}
