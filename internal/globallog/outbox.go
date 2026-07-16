package globallog

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/observability"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
)

const (
	defaultOutboxPollInterval   = 500 * time.Millisecond
	defaultOutboxBatchSize      = 128
	defaultOutboxInitialBackoff = 100 * time.Millisecond
	defaultOutboxMaxBackoff     = time.Minute
)

// OutboxConfig wires the durable batch-root -> global-log worker. Batch commit
// only writes GlobalLogOutboxItem; this worker performs the slower append and
// optional STH anchor enqueue path outside the batch goroutine.
type OutboxConfig struct {
	Store   proofstore.Store
	Global  *Service
	OnSTH   func(context.Context, model.SignedTreeHead)
	Metrics *observability.Metrics

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
	w.running = true
	w.stop = make(chan struct{})
	w.done = make(chan struct{})
	w.mu.Unlock()
	go w.run(ctx)
}

func (w *OutboxWorker) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	close(w.stop)
	done := w.done
	w.running = false
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

func (w *OutboxWorker) run(ctx context.Context) {
	defer close(w.done)
	w.tick(ctx)
	timer := time.NewTimer(w.cfg.PollInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stop:
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

func (w *OutboxWorker) tick(ctx context.Context) {
	if ctx.Err() != nil || w.cfg.Store == nil || w.cfg.Global == nil {
		return
	}
	now := w.cfg.Clock().UTC().UnixNano()
	items, err := w.cfg.Store.ListPendingGlobalLog(ctx, now, w.cfg.BatchSize)
	if err != nil {
		w.cfg.Logger.Warn().Err(err).Msg("global log outbox: list pending failed")
		return
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
	for i := range items {
		if w.cfg.OnSTH != nil {
			w.cfg.OnSTH(ctx, sths[i])
		}
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

func (w *OutboxWorker) processOne(ctx context.Context, item model.GlobalLogOutboxItem) {
	sth, err := w.cfg.Global.AppendBatchRoot(ctx, item.BatchRoot)
	if err == nil {
		if err := w.cfg.Store.MarkGlobalLogPublished(ctx, item.BatchID, sth); err != nil {
			w.cfg.Logger.Error().Err(err).Str("batch_id", item.BatchID).Msg("global log outbox: mark published failed")
			return
		}
		if w.cfg.OnSTH != nil {
			w.cfg.OnSTH(ctx, sth)
		}
		w.cfg.Logger.Debug().Str("batch_id", item.BatchID).Uint64("tree_size", sth.TreeSize).Msg("global log outbox: appended")
		return
	}

	w.reschedule(ctx, item, err)
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
