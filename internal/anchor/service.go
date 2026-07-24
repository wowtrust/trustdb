package anchor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rs/zerolog"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/proofstore"
)

const (
	defaultPollInterval   = 2 * time.Second
	defaultPerCallTimeout = 30 * time.Second
	defaultLeaseDuration  = 75 * time.Second
	defaultInitialBackoff = time.Second
	defaultMaxBackoff     = 5 * time.Minute
	minimumLeaseMargin    = time.Second
)

// Config describes one constant-space anchor scheduler worker. The durable
// schedule key is explicit so a tick never scans historical STHs or results.
type Config struct {
	Sink  Sink
	Store proofstore.Store
	Key   model.STHAnchorScheduleKey

	Metrics *observability.Metrics
	Logger  zerolog.Logger

	PollInterval   time.Duration
	PerCallTimeout time.Duration
	LeaseDuration  time.Duration
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	MaxAttempts    int

	Clock         func() time.Time
	NewLeaseToken func() string
}

func (c *Config) applyDefaults() {
	if c.PollInterval <= 0 {
		c.PollInterval = defaultPollInterval
	}
	if c.PerCallTimeout <= 0 {
		c.PerCallTimeout = defaultPerCallTimeout
	}
	minimumLease := minimumSafeLeaseDuration(c.PerCallTimeout)
	if c.LeaseDuration < minimumLease {
		c.LeaseDuration = max(defaultLeaseDuration, minimumLease)
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
	if c.NewLeaseToken == nil {
		c.NewLeaseToken = newLeaseToken
	}
}

func minimumSafeLeaseDuration(perCallTimeout time.Duration) time.Duration {
	margin := max(minimumLeaseMargin, perCallTimeout/10)
	const maxDuration = time.Duration(1<<63 - 1)
	if perCallTimeout > (maxDuration-margin)/2 {
		return maxDuration
	}
	return 2*perCallTimeout + margin
}

// Service claims and publishes at most one immutable InFlight target for one
// stream and sink. Pending targets are coalesced by the proofstore writer.
type Service struct {
	cfg      Config
	schedule proofstore.STHAnchorScheduleStore
	owner    string

	trigger chan struct{}
	mu      sync.Mutex
	running bool
	stop    chan struct{}
	done    chan struct{}
}

func NewService(cfg Config) (*Service, error) {
	if cfg.Sink == nil {
		return nil, errors.New("anchor service: sink is required")
	}
	if cfg.Store == nil {
		return nil, errors.New("anchor service: store is required")
	}
	if cfg.Key.SinkName == "" {
		cfg.Key.SinkName = cfg.Sink.Name()
	}
	if err := anchorschedule.ValidateKey(cfg.Key); err != nil {
		return nil, fmt.Errorf("anchor service: %w", err)
	}
	if cfg.Key.SinkName != cfg.Sink.Name() {
		return nil, errors.New("anchor service: schedule key sink does not match configured sink")
	}
	schedule, ok := cfg.Store.(proofstore.STHAnchorScheduleStore)
	if !ok {
		return nil, errors.New("anchor service: store does not support durable scheduling")
	}
	cfg.applyDefaults()
	return &Service{
		cfg:      cfg,
		schedule: schedule,
		owner:    "anchor-worker-" + cfg.NewLeaseToken(),
		trigger:  make(chan struct{}, 1),
	}, nil
}

func (s *Service) SinkName() string {
	if s == nil || s.cfg.Sink == nil {
		return ""
	}
	return s.cfg.Sink.Name()
}

// Sink returns the configured provider for transport-side capability
// discovery. Callers must continue to use Service for publication scheduling.
func (s *Service) Sink() Sink {
	if s == nil {
		return nil
	}
	return s.cfg.Sink
}

func (s *Service) ScheduleKey() model.STHAnchorScheduleKey {
	if s == nil {
		return model.STHAnchorScheduleKey{}
	}
	return s.cfg.Key
}

func (s *Service) Start(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	s.running = true
	s.stop = stop
	s.done = done
	s.mu.Unlock()
	go s.run(ctx, stop, done)
}

// Stop does not flush Pending. It only waits for the current bounded tick, so
// the persisted fixed deadline remains authoritative across clean restarts.
func (s *Service) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	if s.stop != nil {
		close(s.stop)
		s.stop = nil
	}
	done := s.done
	s.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (s *Service) Trigger() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

func (s *Service) run(ctx context.Context, stop, done chan struct{}) {
	defer s.finishRun(done)
	s.tick(ctx)
	timer := time.NewTimer(s.cfg.PollInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-timer.C:
			s.tick(ctx)
			timer.Reset(s.cfg.PollInterval)
		case <-s.trigger:
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

func (s *Service) finishRun(done chan struct{}) {
	s.mu.Lock()
	if s.done == done {
		s.running = false
		s.stop = nil
		s.done = nil
	}
	s.mu.Unlock()
	close(done)
}

// tick performs one O(1) schedule lookup and at most one external publish.
func (s *Service) tick(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	state, found, err := s.schedule.GetSTHAnchorSchedule(ctx, s.cfg.Key)
	if err != nil {
		s.cfg.Logger.Warn().Err(err).Msg("anchor: read schedule failed")
		return
	}
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.AnchorPending.Set(boolFloat(found && state.Pending != nil))
	}
	if !found {
		return
	}
	now := s.cfg.Clock().UTC()
	token := s.cfg.NewLeaseToken()
	attempt, claimed, err := s.schedule.ClaimSTHAnchorAttempt(
		ctx,
		s.cfg.Key,
		now.UnixNano(),
		now.Add(s.cfg.LeaseDuration).UnixNano(),
		s.owner,
		token,
	)
	if err != nil {
		s.cfg.Logger.Warn().Err(err).Msg("anchor: claim attempt failed")
		return
	}
	if !claimed {
		return
	}
	s.processOne(ctx, attempt)
	s.refreshPendingMetric(ctx)
}

func (s *Service) refreshPendingMetric(ctx context.Context) {
	if s.cfg.Metrics == nil {
		return
	}
	refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.PerCallTimeout)
	defer cancel()
	state, found, err := s.schedule.GetSTHAnchorSchedule(refreshCtx, s.cfg.Key)
	if err != nil {
		s.cfg.Logger.Warn().Err(err).Msg("anchor: refresh pending metric failed")
		return
	}
	s.cfg.Metrics.AnchorPending.Set(boolFloat(found && state.Pending != nil))
}

func (s *Service) processOne(ctx context.Context, attempt model.STHAnchorAttempt) {
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.AnchorInFlight.Inc()
		defer s.cfg.Metrics.AnchorInFlight.Dec()
	}
	callCtx, cancel := context.WithTimeout(ctx, s.cfg.PerCallTimeout)
	start := time.Now()
	result, publishErr := s.cfg.Sink.Publish(callCtx, attempt.Target)
	cancel()
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.AnchorLatency.Observe(time.Since(start).Seconds())
	}

	persistCtx, persistCancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.PerCallTimeout)
	defer persistCancel()
	nextAttempts := attempt.Attempts + 1

	if publishErr == nil {
		boundResult, bindErr := anchorschedule.BindAttemptResult(s.cfg.Key, attempt, result, s.cfg.Clock().UTC().UnixNano())
		if bindErr != nil {
			invalidResultErr := fmt.Errorf("invalid successful sink result: %w", bindErr)
			message := boundedProviderError(invalidResultErr)
			if err := s.schedule.FailSTHAnchorAttempt(persistCtx, s.cfg.Key, attempt.Generation, attempt.LeaseToken, nextAttempts, message); err != nil {
				s.cfg.Logger.Error().Err(err).Uint64("tree_size", attempt.Target.TreeSize).Msg("anchor: persist invalid result failure failed")
			}
			if s.cfg.Metrics != nil {
				s.cfg.Metrics.AnchorAttempts.WithLabelValues(s.cfg.Sink.Name(), "invalid_result").Inc()
			}
			s.cfg.Logger.Error().Err(invalidResultErr).Uint64("tree_size", attempt.Target.TreeSize).Int("attempts", nextAttempts).Msg("anchor: sink returned an invalid successful result")
			return
		}
		result = boundResult
		if err := s.schedule.CompleteSTHAnchorAttempt(persistCtx, s.cfg.Key, attempt.Generation, attempt.LeaseToken, result); err != nil {
			s.cfg.Logger.Error().Err(err).Uint64("tree_size", attempt.Target.TreeSize).Msg("anchor: persist completion failed")
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
			Uint64("tree_size", attempt.Target.TreeSize).
			Uint64("generation", attempt.Generation).
			Str("sink", s.cfg.Sink.Name()).
			Str("anchor_id", result.AnchorID).
			Msg("anchor: published")
		return
	}

	message := boundedProviderError(publishErr)
	if errors.Is(publishErr, ErrPermanent) || s.cfg.MaxAttempts > 0 && nextAttempts >= s.cfg.MaxAttempts {
		if err := s.schedule.FailSTHAnchorAttempt(persistCtx, s.cfg.Key, attempt.Generation, attempt.LeaseToken, nextAttempts, message); err != nil {
			s.cfg.Logger.Error().Err(err).Uint64("tree_size", attempt.Target.TreeSize).Msg("anchor: persist terminal failure failed")
		}
		outcome := "permanent"
		if !errors.Is(publishErr, ErrPermanent) {
			outcome = "exhausted"
		}
		if s.cfg.Metrics != nil {
			s.cfg.Metrics.AnchorAttempts.WithLabelValues(s.cfg.Sink.Name(), outcome).Inc()
		}
		s.cfg.Logger.Error().Err(publishErr).Uint64("tree_size", attempt.Target.TreeSize).Int("attempts", nextAttempts).Msg("anchor: terminal failure")
		return
	}

	backoff := computeBackoff(s.cfg.InitialBackoff, s.cfg.MaxBackoff, nextAttempts)
	nextAttempt := s.cfg.Clock().Add(backoff).UTC().UnixNano()
	if err := s.schedule.RescheduleSTHAnchorAttempt(persistCtx, s.cfg.Key, attempt.Generation, attempt.LeaseToken, nextAttempts, nextAttempt, message); err != nil {
		s.cfg.Logger.Error().Err(err).Uint64("tree_size", attempt.Target.TreeSize).Msg("anchor: persist retry failed")
	}
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.AnchorAttempts.WithLabelValues(s.cfg.Sink.Name(), "transient").Inc()
	}
	s.cfg.Logger.Warn().Err(publishErr).Uint64("tree_size", attempt.Target.TreeSize).Int("attempts", nextAttempts).Dur("backoff", backoff).Msg("anchor: transient failure")
}

func boundedProviderError(err error) string {
	message := err.Error()
	if strings.TrimSpace(message) == "" {
		message = "anchor provider returned an unspecified error"
	}
	if len(message) <= anchorschedule.MaxLastErrorBytes {
		return message
	}
	message = message[:anchorschedule.MaxLastErrorBytes]
	for !utf8.ValidString(message) {
		message = message[:len(message)-1]
	}
	return message
}

func newLeaseToken() string {
	var token [16]byte
	if _, err := rand.Read(token[:]); err == nil {
		return hex.EncodeToString(token[:])
	}
	return fmt.Sprintf("%x", time.Now().UTC().UnixNano())
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func computeBackoff(initial, maxDelay time.Duration, attempts int) time.Duration {
	if attempts <= 1 {
		return initial
	}
	delay := initial
	for i := 1; i < attempts && delay < maxDelay; i++ {
		if delay > maxDelay/2 {
			return maxDelay
		}
		delay *= 2
	}
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}
