package anchor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/proofstore"
)

// Upgrader-side defaults. The cadence is intentionally far slower
// than the anchor-publisher worker because OTS calendars only fold a
// commitment into a Bitcoin block roughly every block (~10 minutes
// average) and many calendars batch upgrades hourly.
const (
	defaultUpgradePollInterval = 1 * time.Hour
	defaultUpgradeBatchSize    = 64
	defaultUpgradePerCallTO    = 30 * time.Second
	MaxOtsUpgradeBatchSize     = 1000
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

// OtsUpgrader periodically walks every immutable OTS STHAnchorResult and
// asks each calendar whether its commitment has been folded into a
// Bitcoin block. When yes, it rewrites STHAnchorResult.Proof in place
// (via proofstore.STHAnchorResultUpdater) so verification tooling sees
// the upgraded bytes without operator intervention.
//
// The loop is intentionally idempotent: a Calendar marked Upgraded
// (set by UpgradeOtsProof on a successful byte change) is skipped on
// every subsequent sweep, so a fully-attested batch costs zero HTTP
// requests forever after.
type OtsUpgrader struct {
	cfg     UpgraderConfig
	pager   proofstore.STHAnchorResultPager
	reader  proofstore.STHAnchorResultKeyedReader
	updater proofstore.STHAnchorResultUpdater

	// trigger is a 1-buffered channel so a manual Trigger() never
	// blocks and never enqueues more than one extra sweep.
	trigger chan struct{}

	tickMu            sync.Mutex
	backfillCursor    model.STHAnchorResultKey
	hasBackfillCursor bool
	tailTurn          bool

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
	pager, ok := cfg.Store.(proofstore.STHAnchorResultPager)
	if !ok {
		return nil, errors.New("ots upgrader: store does not support immutable anchor result paging")
	}
	reader, ok := cfg.Store.(proofstore.STHAnchorResultKeyedReader)
	if !ok {
		return nil, errors.New("ots upgrader: store does not support keyed immutable anchor result reads")
	}
	updater, ok := cfg.Store.(proofstore.STHAnchorResultUpdater)
	if !ok {
		return nil, errors.New("ots upgrader: store does not support immutable anchor result updates")
	}
	if cfg.BatchSize < 0 || cfg.BatchSize > MaxOtsUpgradeBatchSize {
		return nil, fmt.Errorf("ots upgrader: batch size must be between 0 and %d", MaxOtsUpgradeBatchSize)
	}
	cfg.applyDefaults()
	return &OtsUpgrader{
		cfg:      cfg,
		pager:    pager,
		reader:   reader,
		updater:  updater,
		trigger:  make(chan struct{}, 1),
		tailTurn: true,
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
	stop := make(chan struct{})
	done := make(chan struct{})
	u.running = true
	u.stop = stop
	u.done = done
	u.mu.Unlock()

	go u.run(ctx, stop, done)
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
	if u.stop != nil {
		close(u.stop)
		u.stop = nil
	}
	done := u.done
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
func (u *OtsUpgrader) run(ctx context.Context, stop, done chan struct{}) {
	defer u.finishRun(done)
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
		case <-stop:
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

func (u *OtsUpgrader) finishRun(done chan struct{}) {
	u.mu.Lock()
	if u.done == done {
		u.running = false
		u.stop = nil
		u.done = nil
	}
	u.mu.Unlock()
	close(done)
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
	u.tickMu.Lock()
	defer u.tickMu.Unlock()

	var stats UpgraderTickStats
	if ctx.Err() != nil {
		return stats
	}
	if u.cfg.Metrics != nil {
		u.cfg.Metrics.OtsUpgradeRuns.Inc()
	}
	items, err := u.nextResultPage(ctx)
	if err != nil {
		u.cfg.Logger.Warn().Err(err).Msg("ots-upgrader: list immutable results failed")
		return stats
	}
	otsItems := make([]model.STHAnchorResult, 0, len(items))
	for _, item := range items {
		if item.SinkName == OtsSinkName {
			otsItems = append(otsItems, item)
		}
	}
	workers := min(u.cfg.Workers, len(otsItems))
	if workers > 0 {
		jobs := make(chan model.STHAnchorResult)
		results := make(chan UpgraderTickStats, len(otsItems))
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for item := range jobs {
					local := UpgraderTickStats{Visited: 1}
					u.processOne(ctx, item, &local)
					results <- local
				}
			}()
		}
	feedJobs:
		for _, item := range otsItems {
			select {
			case jobs <- item:
			case <-ctx.Done():
				break feedJobs
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

// nextResultPage reserves part of every sweep for the newest immutable anchor
// results and uses the remainder for a descending historical backfill. The
// tail read keeps newly-created OTS results prompt even after restarts or in a
// namespace with years of file/noop history, while the cursor still makes old
// pending OTS proofs converge without an unbounded scan.
func (u *OtsUpgrader) nextResultPage(ctx context.Context) ([]model.STHAnchorResult, error) {
	if u.cfg.BatchSize == 1 {
		if u.tailTurn || !u.hasBackfillCursor {
			u.tailTurn = false
			items, err := u.pageResults(ctx, model.STHAnchorResultKey{}, false, 1)
			if err != nil || len(items) == 0 {
				return items, err
			}
			if !u.hasBackfillCursor {
				u.backfillCursor = anchorschedule.ResultKey(items[len(items)-1])
				u.hasBackfillCursor = true
			}
			return items, nil
		}
		u.tailTurn = true
		items, err := u.pageResults(ctx, u.backfillCursor, true, 1)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			u.backfillCursor = model.STHAnchorResultKey{}
			u.hasBackfillCursor = false
			return nil, nil
		}
		u.backfillCursor = anchorschedule.ResultKey(items[len(items)-1])
		return items, nil
	}

	tailLimit := (u.cfg.BatchSize + 1) / 2
	backfillLimit := u.cfg.BatchSize - tailLimit
	tail, err := u.pageResults(ctx, model.STHAnchorResultKey{}, false, tailLimit)
	if err != nil || len(tail) == 0 || backfillLimit == 0 {
		return tail, err
	}
	if !u.hasBackfillCursor {
		u.backfillCursor = anchorschedule.ResultKey(tail[len(tail)-1])
		u.hasBackfillCursor = true
	}
	backfill, err := u.pageResults(ctx, u.backfillCursor, true, backfillLimit)
	if err != nil {
		return nil, err
	}
	if len(backfill) == 0 {
		u.backfillCursor = anchorschedule.ResultKey(tail[len(tail)-1])
		backfill, err = u.pageResults(ctx, u.backfillCursor, true, backfillLimit)
		if err != nil {
			return nil, err
		}
	}
	if len(backfill) > 0 {
		u.backfillCursor = anchorschedule.ResultKey(backfill[len(backfill)-1])
	}
	return appendUniqueAnchorResults(tail, backfill), nil
}

func (u *OtsUpgrader) pageResults(ctx context.Context, after model.STHAnchorResultKey, hasAfter bool, limit int) ([]model.STHAnchorResult, error) {
	return u.pager.ListSTHAnchorResultsPage(ctx, model.AnchorListOptions{
		Limit: limit, Direction: model.RecordListDirectionDesc, AfterResultKey: after, HasAfter: hasAfter,
	})
}

func appendUniqueAnchorResults(first, second []model.STHAnchorResult) []model.STHAnchorResult {
	if len(second) == 0 {
		return first
	}
	result := make([]model.STHAnchorResult, 0, len(first)+len(second))
	seen := make(map[model.STHAnchorResultKey]struct{}, len(first)+len(second))
	for _, items := range [...][]model.STHAnchorResult{first, second} {
		for _, item := range items {
			key := anchorschedule.ResultKey(item)
			if _, found := seen[key]; found {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, item)
		}
	}
	return result
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

// processOne upgrades one immutable STHAnchorResult and
// persists when something changed. errors are logged + reflected in
// stats; the loop keeps going so one bad batch can't stall the rest.
func (u *OtsUpgrader) processOne(ctx context.Context, ar model.STHAnchorResult, stats *UpgraderTickStats) {
	logger := u.cfg.Logger.With().Uint64("tree_size", ar.TreeSize).Logger()
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
	persisted, changed, err := PersistOtsAnchorResultUpgrade(ctx, u.reader, u.updater, ar, updated)
	if err != nil {
		stats.Errored++
		u.markBatchOutcome("error")
		logger.Warn().Err(err).Msg("ots-upgrader: persist upgraded result failed")
		return
	}
	if changed {
		stats.Changed++
		u.markBatchOutcome("changed")
	} else {
		stats.Unchanged++
		u.markBatchOutcome("unchanged")
	}
	if proof, decodeErr := decodeOtsProofEnvelope(persisted.Proof); decodeErr == nil && !proof.AllUpgraded() {
		stats.StillPending++
	}
	logger.Info().
		Int("calendars_changed", stats.CalendarChanged).
		Bool("stored", changed).
		Msg("ots-upgrader: converged upgraded proof")
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
