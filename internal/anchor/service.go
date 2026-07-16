package anchor

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/observability"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
)

// Default tuning. These are exported via Config so operators can
// override any one without copying the whole struct.
const (
	defaultPollInterval   = 2 * time.Second
	defaultBatchSize      = 64
	defaultWorkers        = 4
	defaultPerCallTimeout = 30 * time.Second
	defaultInitialBackoff = 1 * time.Second
	defaultMaxBackoff     = 5 * time.Minute
)

// Config collects every knob Service respects. The zero value is not
// valid — Sink and Store must be set — but every other field has a
// sane default applied in NewService.
type Config struct {
	Sink  Sink
	Store proofstore.Store

	// Metrics is optional; when nil the service runs without
	// observability which keeps tests from pulling in the full
	// Prometheus registry.
	Metrics *observability.Metrics
	Logger  zerolog.Logger

	// PollInterval is the wall-clock gap between outbox sweeps.
	// Trigger() shortcuts this for commit-time wakeups.
	PollInterval time.Duration
	// BatchSize caps how many items a single sweep processes so a
	// large backlog cannot starve other goroutines on the shared
	// store handle.
	BatchSize int
	// Workers bounds concurrent Sink.Publish calls for independent STHs.
	Workers int
	// PerCallTimeout bounds any single Sink.Publish call. Most
	// sinks return in <1s; the default is deliberately generous to
	// tolerate external notaries that rate-limit heavily.
	PerCallTimeout time.Duration
	// InitialBackoff and MaxBackoff drive exponential retry delay
	// on transient sink failures: delay = min(MaxBackoff,
	// InitialBackoff * 2^attempts).
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	// MaxAttempts, when > 0, caps the retry budget: after this
	// many transient failures the item transitions to Failed. When
	// 0 (the default) the worker retries forever which is usually
	// what you want — a permanently broken sink will declare
	// ErrPermanent itself.
	MaxAttempts int
	// Clock is injected only by tests; production uses time.Now.
	Clock func() time.Time
}

func (c *Config) applyDefaults() {
	if c.PollInterval <= 0 {
		c.PollInterval = defaultPollInterval
	}
	if c.BatchSize <= 0 {
		c.BatchSize = defaultBatchSize
	}
	if c.Workers <= 0 {
		c.Workers = defaultWorkers
	}
	if c.PerCallTimeout <= 0 {
		c.PerCallTimeout = defaultPerCallTimeout
	}
	if c.InitialBackoff <= 0 {
		c.InitialBackoff = defaultInitialBackoff
	}
	if c.MaxBackoff < c.InitialBackoff {
		c.MaxBackoff = defaultMaxBackoff
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
}

// Service drives the anchor outbox: polls pending items, calls the
// configured Sink, and updates the outbox with success/retry/fail.
// Callers own the lifecycle — Start launches a background goroutine
// and Stop cleanly drains it.
type Service struct {
	cfg Config

	// Single-buffer trigger channel: a concurrent Trigger() never
	// blocks and never enqueues more than one extra sweep, so we
	// cannot leak goroutines even under a thundering herd of
	// commits.
	trigger chan struct{}

	mu      sync.Mutex
	running bool
	stop    chan struct{}
	done    chan struct{}
}

// NewService builds a Service with defaults applied. Sink and Store
// are required; a nil for either returns an error so the caller
// cannot accidentally start a worker that would panic on first tick.
func NewService(cfg Config) (*Service, error) {
	if cfg.Sink == nil {
		return nil, errors.New("anchor service: sink is required")
	}
	if cfg.Store == nil {
		return nil, errors.New("anchor service: store is required")
	}
	cfg.applyDefaults()
	return &Service{
		cfg:     cfg,
		trigger: make(chan struct{}, 1),
	}, nil
}

// Start launches the worker goroutine. It is safe to call Start
// multiple times but only the first call takes effect; subsequent
// calls are no-ops so crash-recovery wiring that starts the worker
// from two places cannot double-launch.
func (s *Service) Start(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	s.mu.Unlock()

	go s.run(ctx)
}

// Stop signals the worker to exit and blocks until the current tick
// completes. A ctx cancellation on the Start ctx will also stop the
// worker — Stop is the graceful complement used during normal
// shutdown.
func (s *Service) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	close(s.stop)
	done := s.done
	s.running = false
	s.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Trigger wakes the worker immediately instead of waiting for the
// next tick. It is non-blocking: a second call while the first
// pending wakeup has not been consumed is dropped (the buffered
// channel has capacity 1), because consecutive triggers cannot add
// information — the worker will pick up everything in the next
// sweep regardless.
func (s *Service) Trigger() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

func (s *Service) run(ctx context.Context) {
	defer close(s.done)
	// Fast first sweep so commits that happened before Start (e.g.
	// during crash recovery) get picked up immediately instead of
	// waiting up to PollInterval.
	s.tick(ctx)
	timer := time.NewTimer(s.cfg.PollInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		case <-timer.C:
			s.tick(ctx)
			timer.Reset(s.cfg.PollInterval)
		case <-s.trigger:
			// Stop+drain the timer so the forthcoming Reset
			// doesn't race with an already-fired tick.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			s.tick(ctx)
			timer.Reset(s.cfg.PollInterval)
		}
	}
}

// tick runs a single sweep. Errors are logged but never propagate;
// the worker must keep running so transient store issues do not
// silently stop anchoring.
func (s *Service) tick(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	now := s.cfg.Clock().UTC().UnixNano()
	items, err := s.cfg.Store.ListPendingSTHAnchors(ctx, now, s.cfg.BatchSize)
	if err != nil {
		s.cfg.Logger.Warn().Err(err).Msg("anchor: list pending failed")
		return
	}
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.AnchorPending.Set(float64(len(items)))
	}
	workers := min(s.cfg.Workers, len(items))
	if workers == 0 {
		return
	}
	jobs := make(chan model.STHAnchorOutboxItem)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				if s.cfg.Metrics != nil {
					s.cfg.Metrics.AnchorInFlight.Inc()
				}
				s.processOne(ctx, item)
				if s.cfg.Metrics != nil {
					s.cfg.Metrics.AnchorInFlight.Dec()
				}
			}
		}()
	}
	for _, item := range items {
		select {
		case jobs <- item:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		}
	}
	close(jobs)
	wg.Wait()
}

// processOne publishes a single outbox item and persists the
// resulting state. The method is extracted so tests can drive the
// loop step-by-step via tickOnce.
func (s *Service) processOne(ctx context.Context, item model.STHAnchorOutboxItem) {
	callCtx, cancel := context.WithTimeout(ctx, s.cfg.PerCallTimeout)
	defer cancel()
	start := time.Now()
	result, err := s.cfg.Sink.Publish(callCtx, item.STH)
	latency := time.Since(start).Seconds()
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.AnchorLatency.Observe(latency)
	}

	switch {
	case err == nil:
		result.SinkName = s.cfg.Sink.Name()
		result.TreeSize = item.TreeSize
		if err := s.cfg.Store.MarkSTHAnchorPublished(ctx, result); err != nil {
			s.cfg.Logger.Error().Err(err).Uint64("tree_size", item.TreeSize).Msg("anchor: mark published failed")
			if s.cfg.Metrics != nil {
				s.cfg.Metrics.AnchorAttempts.WithLabelValues(s.cfg.Sink.Name(), "store_error").Inc()
			}
			return
		}
		if s.cfg.Metrics != nil {
			s.cfg.Metrics.AnchorAttempts.WithLabelValues(s.cfg.Sink.Name(), "success").Inc()
			s.cfg.Metrics.AnchorPublished.WithLabelValues(s.cfg.Sink.Name()).Inc()
		}
		s.cfg.Logger.Info().
			Uint64("tree_size", item.TreeSize).
			Str("sink", s.cfg.Sink.Name()).
			Str("anchor_id", result.AnchorID).
			Msg("anchor: published")

	case errors.Is(err, ErrPermanent):
		if err := s.cfg.Store.MarkSTHAnchorFailed(ctx, item.TreeSize, err.Error()); err != nil {
			s.cfg.Logger.Error().Err(err).Uint64("tree_size", item.TreeSize).Msg("anchor: mark failed error")
		}
		if s.cfg.Metrics != nil {
			s.cfg.Metrics.AnchorAttempts.WithLabelValues(s.cfg.Sink.Name(), "permanent").Inc()
		}
		s.cfg.Logger.Error().Err(err).Uint64("tree_size", item.TreeSize).Msg("anchor: permanent failure")

	default:
		nextAttempts := item.Attempts + 1
		// Treat MaxAttempts == 0 as "unlimited". Exceeding the
		// budget promotes a transient failure to Failed so the
		// item stops consuming worker time forever.
		if s.cfg.MaxAttempts > 0 && nextAttempts >= s.cfg.MaxAttempts {
			if mfErr := s.cfg.Store.MarkSTHAnchorFailed(ctx, item.TreeSize, err.Error()); mfErr != nil {
				s.cfg.Logger.Error().Err(mfErr).Uint64("tree_size", item.TreeSize).Msg("anchor: mark failed after max attempts")
			}
			if s.cfg.Metrics != nil {
				s.cfg.Metrics.AnchorAttempts.WithLabelValues(s.cfg.Sink.Name(), "exhausted").Inc()
			}
			s.cfg.Logger.Warn().Err(err).Uint64("tree_size", item.TreeSize).Int("attempts", nextAttempts).Msg("anchor: retry budget exhausted")
			return
		}
		backoff := computeBackoff(s.cfg.InitialBackoff, s.cfg.MaxBackoff, nextAttempts)
		nextAttempt := s.cfg.Clock().Add(backoff).UTC().UnixNano()
		if rErr := s.cfg.Store.RescheduleSTHAnchor(ctx, item.TreeSize, nextAttempts, nextAttempt, err.Error()); rErr != nil {
			s.cfg.Logger.Error().Err(rErr).Uint64("tree_size", item.TreeSize).Msg("anchor: reschedule failed")
		}
		if s.cfg.Metrics != nil {
			s.cfg.Metrics.AnchorAttempts.WithLabelValues(s.cfg.Sink.Name(), "transient").Inc()
		}
		s.cfg.Logger.Warn().Err(err).Uint64("tree_size", item.TreeSize).Int("attempts", nextAttempts).Dur("backoff", backoff).Msg("anchor: transient failure")
	}
}

// computeBackoff returns min(MaxBackoff, Initial * 2^(attempts-1)).
// attempts is the attempt about to be retried (already incremented
// past the failure that triggered this backoff).
func computeBackoff(initial, max time.Duration, attempts int) time.Duration {
	if attempts <= 1 {
		return initial
	}
	delay := initial
	// Bit-shift guards against overflow by stopping once we exceed
	// the cap; 2^30 already dwarfs any reasonable ceiling.
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
