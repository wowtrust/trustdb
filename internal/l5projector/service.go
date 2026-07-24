// Package l5projector materializes the proof-level projection implied by a
// covering STH anchor. Proof generation remains authoritative and independent
// of this asynchronous convenience index.
package l5projector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const (
	defaultPageSize     = 128
	defaultPollInterval = 2 * time.Second
)

type Store interface {
	proofstore.STHAnchorResultKeyedReader
	proofstore.L5CoverageCheckpointStore
	proofstore.BatchProofLevelPromoter
	ListGlobalLeavesRange(context.Context, uint64, int) ([]model.GlobalLogLeaf, error)
}

type Config struct {
	Store        Store
	Key          model.STHAnchorScheduleKey
	PageSize     int
	PollInterval time.Duration
	Clock        func() time.Time
	Logger       zerolog.Logger
	// OnBatchesPromoted runs only after the whole page and its continuous
	// checkpoint are durable. It is intended for lightweight invalidation.
	OnBatchesPromoted func(context.Context, []string)
}

type Service struct {
	cfg     Config
	trigger chan struct{}
	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
}

func New(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "L5 coverage store is required")
	}
	if err := anchorschedule.ValidateKey(cfg.Key); err != nil {
		return nil, err
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = defaultPageSize
	}
	if cfg.PageSize > 1000 {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "L5 coverage page size must not exceed 1000")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Service{cfg: cfg, trigger: make(chan struct{}, 1)}, nil
}

// ProjectPage promotes one bounded continuous page. The checkpoint advances
// only after every referenced batch is durable; replay after a crash is safe
// because proof-level promotion is monotonic and idempotent.
func (s *Service) ProjectPage(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "project L5 coverage canceled", err)
	}
	result, found, err := s.cfg.Store.LatestSTHAnchorResultForKey(ctx, s.cfg.Key)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	if err := anchorschedule.ValidateResult(s.cfg.Key, result); err != nil {
		return false, trusterr.Wrap(trusterr.CodeDataLoss, "latest L5 anchor result is invalid", err)
	}
	if !model.AnchorResultProvidesOfflineL5(result) {
		return false, nil
	}
	checkpoint, checkpointFound, err := s.cfg.Store.GetL5CoverageCheckpoint(ctx, s.cfg.Key)
	if err != nil {
		return false, err
	}
	start := uint64(0)
	if checkpointFound {
		start = checkpoint.CoveredTreeSize
	}
	if start > result.TreeSize {
		return false, trusterr.New(trusterr.CodeDataLoss, "L5 coverage checkpoint exceeds latest anchor tree size")
	}
	if start == result.TreeSize {
		return false, nil
	}
	remaining := result.TreeSize - start
	count := s.cfg.PageSize
	if remaining < uint64(count) {
		count = int(remaining)
	}
	leaves, err := s.cfg.Store.ListGlobalLeavesRange(ctx, start, count)
	if err != nil {
		return false, err
	}
	if len(leaves) != count {
		return false, trusterr.New(trusterr.CodeDataLoss, "L5 coverage page contains a missing Global Log leaf")
	}
	batchIDs := make([]string, 0, len(leaves))
	for i, leaf := range leaves {
		wantIndex := start + uint64(i)
		if leaf.LeafIndex != wantIndex {
			return false, trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("L5 coverage leaf index %d does not match expected %d", leaf.LeafIndex, wantIndex))
		}
		if leaf.NodeID != s.cfg.Key.NodeID || leaf.LogID != s.cfg.Key.LogID {
			return false, trusterr.New(trusterr.CodeDataLoss, "L5 coverage leaf belongs to another Global Log")
		}
		if leaf.BatchID == "" {
			return false, trusterr.New(trusterr.CodeDataLoss, "L5 coverage leaf has an empty batch_id")
		}
		if err := s.cfg.Store.PromoteBatchProofLevel(ctx, leaf.BatchID, "L5"); err != nil {
			return false, err
		}
		batchIDs = append(batchIDs, leaf.BatchID)
	}
	end := start + uint64(count)
	if _, err := s.cfg.Store.AdvanceL5CoverageCheckpoint(ctx, s.cfg.Key, end, s.cfg.Clock().UTC().UnixNano()); err != nil {
		return false, err
	}
	if s.cfg.OnBatchesPromoted != nil {
		s.cfg.OnBatchesPromoted(ctx, batchIDs)
	}
	return true, nil
}

func (s *Service) Start(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.running = true
	s.cancel = cancel
	s.done = make(chan struct{})
	done := s.done
	s.mu.Unlock()
	go s.run(runCtx, done)
}

// Stop cancels the current page and never forces a final projection pass.
// The last fully committed continuous checkpoint is resumed on next start.
func (s *Service) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	cancel := s.cancel
	done := s.done
	s.running = false
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
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

func (s *Service) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	s.projectAvailable(ctx)
	timer := time.NewTimer(s.cfg.PollInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.projectAvailable(ctx)
			timer.Reset(s.cfg.PollInterval)
		case <-s.trigger:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			s.projectAvailable(ctx)
			timer.Reset(s.cfg.PollInterval)
		}
	}
}

func (s *Service) projectAvailable(ctx context.Context) {
	for ctx.Err() == nil {
		progressed, err := s.ProjectPage(ctx)
		if err != nil {
			if ctx.Err() == nil {
				s.cfg.Logger.Warn().Err(err).Msg("L5 coverage projection failed")
			}
			return
		}
		if !progressed {
			return
		}
	}
}
