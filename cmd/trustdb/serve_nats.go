package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	trustconfig "github.com/wowtrust/trustdb/internal/config"
	"github.com/wowtrust/trustdb/internal/natsingress"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/submission"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

// serveNATSIngress owns the optional NATS transport lifecycle without owning
// the shared TrustDB submission service. The worker must be started only after
// WAL replay has made the submission pipeline ready.
type serveNATSIngress struct {
	runtime *natsingress.Runtime
	cancel  context.CancelFunc
	done    chan struct{}
	runErr  error
}

func startServeNATSIngress(ctx context.Context, cfg trustconfig.NATS, submitter submission.Submitter, metrics *observability.Metrics, logger zerolog.Logger) (*serveNATSIngress, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	runtime, err := natsingress.Open(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("start optional NATS ingress: %w", err)
	}
	cleanup := func() {
		timeout, parseErr := time.ParseDuration(cfg.DrainTimeout)
		if parseErr != nil || timeout <= 0 {
			timeout = 5 * time.Second
		}
		closeCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		_ = runtime.Close(closeCtx)
	}

	sink, err := natsingress.NewJetStreamOutcomeSink(runtime, cfg)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("build optional NATS outcome sink: %w", err)
	}
	workerOptions := []natsingress.WorkerOption{
		natsingress.WithWorkerErrorHandler(func(err error) {
			logger.Warn().Err(err).Msg("NATS ingress worker delivery error")
		}),
	}
	if metrics != nil {
		workerOptions = append(workerOptions, natsingress.WithWorkerObserver(serveNATSObserver{metrics: metrics}))
	}
	worker, err := natsingress.NewWorker(
		runtime.Consumer(),
		submitter,
		sink,
		cfg,
		workerOptions...,
	)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("build optional NATS ingress worker: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	service := &serveNATSIngress{
		runtime: runtime,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	go func() {
		defer close(service.done)
		service.runErr = worker.Run(runCtx)
		if errors.Is(service.runErr, context.Canceled) && runCtx.Err() != nil {
			service.runErr = nil
		}
	}()

	logger.Info().
		Str("stream", cfg.Stream).
		Str("consumer", cfg.Durable).
		Str("result_stream", cfg.ResultStream).
		Str("dead_letter_stream", cfg.DLQStream).
		Int("workers", worker.Workers()).
		Int("fetch_batch_per_worker", worker.PerWorkerBatch()).
		Msg("optional NATS ingress started")
	return service, nil
}

type serveNATSObserver struct {
	metrics *observability.Metrics
}

func (o serveNATSObserver) DeliveryStarted() {
	o.metrics.NATSIngressInFlight.Inc()
}

func (o serveNATSObserver) DeliveryFinished() {
	o.metrics.NATSIngressInFlight.Dec()
}

func (o serveNATSObserver) DeliveryAction(action string) {
	o.metrics.NATSIngressDeliveries.WithLabelValues(action).Inc()
}

func (o serveNATSObserver) OutcomeStoreRetry(kind string) {
	o.metrics.NATSIngressOutcomeStoreRetries.WithLabelValues(kind).Inc()
}

func (o serveNATSObserver) WorkerError(stage string) {
	o.metrics.NATSIngressErrors.WithLabelValues(stage).Inc()
}

func (s *serveNATSIngress) Done() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.done
}

func (s *serveNATSIngress) Err() error {
	if s == nil {
		return nil
	}
	select {
	case <-s.done:
		return s.runErr
	default:
		return nil
	}
}

// Close stops new pulls, waits for buffered callbacks to leave incomplete
// deliveries unacknowledged, then drains and closes the NATS connection.
func (s *serveNATSIngress) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.cancel()
	select {
	case <-s.done:
	case <-ctx.Done():
		return errors.Join(ctx.Err(), s.runtime.Close(ctx))
	}
	return s.runtime.Close(ctx)
}

func waitForServeStop(ctx context.Context, errCh <-chan error, natsIngress *serveNATSIngress) error {
	var natsDone <-chan struct{}
	if natsIngress != nil {
		natsDone = natsIngress.Done()
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	case <-natsDone:
		if ctx.Err() != nil {
			return nil
		}
		if err := natsIngress.Err(); err != nil {
			return trusterr.Wrap(trusterr.CodeInternal, "optional NATS ingress stopped unexpectedly", err)
		}
		return trusterr.New(trusterr.CodeInternal, "optional NATS ingress stopped unexpectedly")
	}
}
