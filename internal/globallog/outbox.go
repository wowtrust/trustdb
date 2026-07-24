package globallog

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/proofstore"
)

const (
	defaultOutboxPollInterval   = 500 * time.Millisecond
	defaultOutboxBatchSize      = 128
	defaultOutboxInitialBackoff = 100 * time.Millisecond
	defaultOutboxMaxBackoff     = time.Minute
	defaultAnchorMaxDelay       = 5 * time.Minute
)

// OutboxConfig wires the durable batch-root -> global-log worker. Batch commit
// only writes GlobalLogOutboxItem; this worker performs the slower append and
// optional durable STH anchor candidate merge outside the batch goroutine.
type OutboxConfig struct {
	Store          proofstore.Store
	Global         *Service
	AnchorKey      *model.STHAnchorScheduleKey
	AnchorMaxDelay time.Duration
	OnAnchorReady  func()
	// OnBatchesPublished runs after the L4 publication marker and record-index
	// promotions are durable. It is intended for lightweight invalidation only.
	OnBatchesPublished func(context.Context, []string)
	Metrics            *observability.Metrics

	Logger         zerolog.Logger
	PollInterval   time.Duration
	BatchSize      int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Clock          func() time.Time
}

func (c *OutboxConfig) applyDefaults() {
	if c.PollInterval <= 0 {
		c.PollInterval = defaultOutboxPollInterval
	}
	if c.BatchSize <= 0 {
		c.BatchSize = defaultOutboxBatchSize
	}
	if c.InitialBackoff <= 0 {
		c.InitialBackoff = defaultOutboxInitialBackoff
	}
	if c.MaxBackoff < c.InitialBackoff {
		c.MaxBackoff = defaultOutboxMaxBackoff
	}
	if c.AnchorKey != nil && c.AnchorMaxDelay <= 0 {
		c.AnchorMaxDelay = defaultAnchorMaxDelay
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
}

type OutboxWorker struct {
	cfg OutboxConfig

	trigger chan struct{}
	mu      sync.Mutex
	running bool
	stop    chan struct{}
	done    chan struct{}
}

func NewOutboxWorker(cfg OutboxConfig) *OutboxWorker {
	cfg.applyDefaults()
	return &OutboxWorker{
		cfg:     cfg,
		trigger: make(chan struct{}, 1),
	}
}

func (w *OutboxWorker) Start(ctx context.Context) {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	w.running = true
	w.stop = stop
	w.done = done
	w.mu.Unlock()
	go w.run(ctx, stop, done)
}

func (w *OutboxWorker) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	if w.stop != nil {
		close(w.stop)
		w.stop = nil
	}
	done := w.done
	w.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (w *OutboxWorker) Trigger() {
	select {
	case w.trigger <- struct{}{}:
	default:
	}
}

func (w *OutboxWorker) run(ctx context.Context, stop, done chan struct{}) {
	defer w.finishRun(done)
	w.tick(ctx)
	timer := time.NewTimer(w.cfg.PollInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-timer.C:
			w.tick(ctx)
			timer.Reset(w.cfg.PollInterval)
		case <-w.trigger:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			w.tick(ctx)
			timer.Reset(w.cfg.PollInterval)
		}
	}
}

func (w *OutboxWorker) finishRun(done chan struct{}) {
	w.mu.Lock()
	if w.done == done {
		w.running = false
		w.stop = nil
		w.done = nil
	}
	w.mu.Unlock()
	close(done)
}

func (w *OutboxWorker) tick(ctx context.Context) {
	if ctx.Err() != nil || w.cfg.Store == nil || w.cfg.Global == nil {
		return
	}
	now := w.cfg.Clock().UTC().UnixNano()
	nodeID, logID := w.cfg.Global.StreamIdentity()
	if w.cfg.AnchorKey != nil {
		if w.cfg.AnchorKey.NodeID != nodeID || w.cfg.AnchorKey.LogID != logID {
			w.cfg.Logger.Error().
				Str("anchor_node_id", w.cfg.AnchorKey.NodeID).
				Str("anchor_log_id", w.cfg.AnchorKey.LogID).
				Str("signer_node_id", nodeID).
				Str("signer_log_id", logID).
				Msg("global log outbox: anchor schedule identity does not match signer")
			return
		}
	}
	items, err := w.cfg.Store.ListPendingGlobalLogForStream(ctx, nodeID, logID, now, w.cfg.BatchSize)
	if err != nil {
		w.cfg.Logger.Warn().Err(err).Msg("global log outbox: list pending failed")
		return
	}
	for i := range items {
		if items[i].BatchRoot.NodeID != nodeID || items[i].BatchRoot.LogID != logID {
			w.cfg.Logger.Error().Str("batch_id", items[i].BatchID).Msg("global log outbox: scoped listing returned a foreign stream item")
			return
		}
	}
	w.processBatch(ctx, items)
}

func (w *OutboxWorker) processBatch(ctx context.Context, items []model.GlobalLogOutboxItem) {
	if len(items) == 0 {
		return
	}
	start := time.Now()
	roots := make([]model.BatchRoot, len(items))
	batchIDs := make([]string, len(items))
	for i := range items {
		roots[i] = items[i].BatchRoot
		batchIDs[i] = items[i].BatchID
	}
	sths, err := w.cfg.Global.AppendBatchRoots(ctx, roots)
	if w.cfg.Metrics != nil {
		w.cfg.Metrics.GlobalLogBatchSize.Observe(float64(len(items)))
		w.cfg.Metrics.GlobalLogBatchLatency.Observe(time.Since(start).Seconds())
	}
	if err != nil {
		for i := range items {
			w.reschedule(ctx, items[i], err)
		}
		return
	}
	if len(sths) != len(items) {
		w.cfg.Logger.Error().Int("items", len(items)).Int("sths", len(sths)).Msg("global log outbox: append returned inconsistent STH count")
		return
	}
	nodeID, logID := w.cfg.Global.StreamIdentity()
	for i := range sths {
		if sths[i].NodeID != nodeID || sths[i].LogID != logID {
			w.cfg.Logger.Error().Str("batch_id", items[i].BatchID).Msg("global log outbox: append returned a foreign stream STH")
			return
		}
	}
	anchorCandidateStored := false
	if w.cfg.AnchorKey != nil {
		marker, ok := w.cfg.Store.(proofstore.GlobalLogPublishedBatchWithAnchorCandidateMarker)
		if !ok {
			w.cfg.Logger.Error().Msg("global log outbox: durable anchor publication is unsupported")
			return
		}
		scheduleStore, ok := w.cfg.Store.(proofstore.STHAnchorScheduleStore)
		if !ok {
			w.cfg.Logger.Error().Msg("global log outbox: durable anchor schedule lookup is unsupported")
			return
		}
		schedule, scheduleFound, err := scheduleStore.GetSTHAnchorSchedule(ctx, *w.cfg.AnchorKey)
		if err != nil {
			w.cfg.Logger.Error().Err(err).Msg("global log outbox: read durable anchor schedule failed")
			return
		}
		coveredTreeSize := uint64(0)
		if scheduleFound {
			if schedule.InFlight != nil {
				coveredTreeSize = schedule.InFlight.Target.TreeSize
			}
			if schedule.Pending != nil && schedule.Pending.Target.TreeSize > coveredTreeSize {
				coveredTreeSize = schedule.Pending.Target.TreeSize
			}
		}
		latestReader, ok := w.cfg.Store.(proofstore.LatestSTHAnchorResultForKeyReader)
		if !ok {
			w.cfg.Logger.Error().Msg("global log outbox: keyed latest anchor lookup is unsupported")
			return
		}
		latest, latestFound, err := latestReader.LatestSTHAnchorResultForKey(ctx, *w.cfg.AnchorKey)
		if err != nil {
			w.cfg.Logger.Error().Err(err).Msg("global log outbox: read latest keyed anchor failed")
			return
		}
		if latestFound && latest.TreeSize > coveredTreeSize {
			coveredTreeSize = latest.TreeSize
		}
		windowStart, target, err := anchorschedule.SelectPublicationTargets(sths, coveredTreeSize)
		if err != nil {
			w.cfg.Logger.Error().Err(err).Msg("global log outbox: canonicalize STH publication batch failed")
			return
		}
		// The first STH in this append opened the fixed, non-sliding anchor
		// window. Covered retry prefixes are skipped so a newly appended suffix
		// gets its own window, while the signed timestamp survives restarts.
		observedAt := time.Unix(0, windowStart.TimestampUnixN).UTC()
		candidate := model.STHAnchorCandidate{
			Key:             *w.cfg.AnchorKey,
			STH:             target,
			ObservedAtUnixN: observedAt.UnixNano(),
			DueAtUnixN:      observedAt.Add(w.cfg.AnchorMaxDelay).UnixNano(),
		}
		if err := marker.MarkGlobalLogPublishedBatchWithAnchorCandidate(ctx, batchIDs, sths, candidate); err != nil {
			w.cfg.Logger.Error().Err(err).Int("count", len(items)).Msg("global log outbox: mark batch published with anchor candidate failed")
			return
		}
		anchorCandidateStored = true
	}
	if !anchorCandidateStored {
		if marker, ok := w.cfg.Store.(proofstore.GlobalLogPublishedBatchMarker); ok {
			if err := marker.MarkGlobalLogPublishedBatch(ctx, batchIDs, sths); err != nil {
				w.cfg.Logger.Error().Err(err).Int("count", len(items)).Msg("global log outbox: mark batch published failed")
				return
			}
		} else {
			for i := range items {
				if err := w.cfg.Store.MarkGlobalLogPublished(ctx, items[i].BatchID, sths[i]); err != nil {
					w.cfg.Logger.Error().Err(err).Str("batch_id", items[i].BatchID).Msg("global log outbox: mark published failed")
					return
				}
			}
		}
	}
	if w.cfg.Metrics != nil {
		w.cfg.Metrics.GlobalLogPublished.Add(float64(len(items)))
	}
	if w.cfg.OnBatchesPublished != nil {
		w.cfg.OnBatchesPublished(ctx, append([]string(nil), batchIDs...))
	}
	if anchorCandidateStored {
		if w.cfg.OnAnchorReady != nil {
			w.cfg.OnAnchorReady()
		}
	}
	for i := range items {
		w.cfg.Logger.Debug().Str("batch_id", items[i].BatchID).Uint64("tree_size", sths[i].TreeSize).Msg("global log outbox: appended")
	}
}

func (w *OutboxWorker) reschedule(ctx context.Context, item model.GlobalLogOutboxItem, cause error) {
	nextAttempts := item.Attempts + 1
	backoff := outboxBackoff(w.cfg.InitialBackoff, w.cfg.MaxBackoff, nextAttempts)
	nextAttempt := w.cfg.Clock().Add(backoff).UTC().UnixNano()
	if err := w.cfg.Store.RescheduleGlobalLog(ctx, item.BatchID, nextAttempts, nextAttempt, cause.Error()); err != nil {
		w.cfg.Logger.Error().Err(err).Str("batch_id", item.BatchID).Msg("global log outbox: reschedule failed")
		return
	}
	w.cfg.Logger.Warn().Err(cause).Str("batch_id", item.BatchID).Int("attempts", nextAttempts).Dur("backoff", backoff).Msg("global log outbox: append failed")
}

func outboxBackoff(initial, max time.Duration, attempts int) time.Duration {
	if attempts <= 1 {
		return initial
	}
	delay := initial
	for i := 1; i < attempts && delay < max; i++ {
		if delay > max/2 {
			return max
		}
		delay *= 2
	}
	if delay > max {
		return max
	}
	return delay
}
