package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	prommodel "github.com/prometheus/common/model"
	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"github.com/wowtrust/trustdb/sdk"
)

func newBenchCommand(rt *runtimeConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Benchmark ingest and proof/query paths against a TrustDB server",
	}
	cmd.AddCommand(newBenchIngestCommand(rt))
	cmd.AddCommand(newBenchMatrixCommand(rt))
	cmd.AddCommand(newBenchCompareCommand(rt))
	return cmd
}

func newBenchIngestCommand(rt *runtimeConfig) *cobra.Command {
	var cfg benchIngestConfig
	cmd := &cobra.Command{
		Use:   "ingest",
		Short: "Generate synthetic claims and measure ingest, proof, and query performance",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg.Endpoint = strings.TrimSpace(cfg.Endpoint)
			cfg.Transport = strings.ToLower(strings.TrimSpace(cfg.Transport))
			cfg.PrivateKeyPath = stringOrConfig(cmd, rt, "private-key", cfg.PrivateKeyPath, "keys.client_private")
			cfg.Identity = sdk.Identity{
				TenantID: stringValue(cmd, rt, "tenant", "tenant"),
				ClientID: stringValue(cmd, rt, "client", "client"),
				KeyID:    stringValue(cmd, rt, "key-id", "key_id"),
			}
			if cfg.Endpoint == "" {
				return usageError("bench ingest requires --server")
			}
			if cfg.Transport == "" {
				cfg.Transport = "http"
			}
			if cfg.Transport != "http" && cfg.Transport != "grpc" {
				return usageError("bench ingest --transport must be http or grpc")
			}
			if cfg.PrivateKeyPath == "" {
				return usageError("bench ingest requires --private-key")
			}
			if cfg.Identity.ClientID == "" || cfg.Identity.KeyID == "" {
				return usageError("bench ingest requires --client and --key-id")
			}
			if cfg.Count <= 0 {
				return usageError("bench ingest --count must be > 0")
			}
			if cfg.Concurrency <= 0 {
				return usageError("bench ingest --concurrency must be > 0")
			}
			if cfg.PayloadBytes <= 0 {
				return usageError("bench ingest --payload-bytes must be > 0")
			}
			if cfg.Samples < 0 {
				return usageError("bench ingest --samples must be >= 0")
			}
			if cfg.ProofLevel == "" {
				cfg.ProofLevel = sdk.ProofLevelL4
			}
			switch cfg.ProofLevel {
			case sdk.ProofLevelL3, sdk.ProofLevelL4, sdk.ProofLevelL5:
			default:
				return usageError("bench ingest --proof-level must be L3, L4, or L5")
			}
			cfg.MaxProofLevel = strings.ToUpper(strings.TrimSpace(cfg.MaxProofLevel))
			switch cfg.MaxProofLevel {
			case "", sdk.ProofLevelL3, sdk.ProofLevelL4, sdk.ProofLevelL5:
			default:
				return usageError("bench ingest --max-proof-level must be L3, L4, or L5")
			}
			if cfg.ProofTimeout <= 0 {
				return usageError("bench ingest --proof-timeout must be > 0")
			}
			if cfg.ProgressEvery < 0 {
				return usageError("bench ingest --progress-every must be >= 0")
			}
			if cfg.EventType == "" {
				cfg.EventType = "bench.synthetic"
			}
			if cfg.Source == "" {
				cfg.Source = "trustdb-bench"
			}
			if cfg.OutputFormat == "" {
				cfg.OutputFormat = "json"
			}
			if cfg.OutputFormat != "json" && cfg.OutputFormat != "text" {
				return usageError("bench ingest --output must be json or text")
			}
			cfg.ReportFile = strings.TrimSpace(cfg.ReportFile)

			signer, descriptor, err := readSigner(cmd.Context(), cfg.PrivateKeyPath)
			if err != nil {
				return err
			}
			if err := requireKeyID(cfg.Identity.KeyID, descriptor); err != nil {
				return err
			}
			cfg.Signer = signer
			cfg.CryptoProvider, err = trustcrypto.ProviderForSuite(descriptor.CryptoSuite)
			if err != nil {
				return err
			}

			client, err := newBenchSDKClient(cfg.Transport, cfg.Endpoint, cfg.Concurrency)
			if err != nil {
				return err
			}
			defer client.Close()

			ctx := cmd.Context()
			result, err := runBenchIngest(ctx, rt, client, cfg)
			if err != nil {
				return err
			}
			return emitBenchIngestResult(rt, cfg, result)
		},
	}
	cmd.Flags().StringVar(&cfg.Endpoint, "server", "", "TrustDB server HTTP base URL or gRPC target")
	cmd.Flags().StringVar(&cfg.Transport, "transport", "http", "transport: http or grpc")
	addCommonIdentityFlags(cmd)
	cmd.Flags().StringVar(&cfg.PrivateKeyPath, "private-key", "", "client signer descriptor")
	cmd.Flags().IntVar(&cfg.Count, "count", 1000, "number of synthetic claims to submit")
	cmd.Flags().IntVar(&cfg.Concurrency, "concurrency", 16, "number of concurrent submit workers")
	cmd.Flags().IntVar(&cfg.PayloadBytes, "payload-bytes", 1024, "payload size in bytes per synthetic claim")
	cmd.Flags().IntVar(&cfg.ProgressEvery, "progress-every", 1000, "log progress every N completed submits; 0 disables progress logs")
	cmd.Flags().IntVar(&cfg.Samples, "samples", 8, "number of successful records to sample for record/proof queries after ingest")
	cmd.Flags().StringVar(&cfg.ProofLevel, "proof-level", sdk.ProofLevelL4, "target proof level to wait for in samples: L3, L4, or L5")
	cmd.Flags().DurationVar(&cfg.ProofTimeout, "proof-timeout", 45*time.Second, "maximum wait per sampled record for target proof level")
	cmd.Flags().DurationVar(&cfg.Settle, "settle", 3*time.Second, "extra settle time before final metric snapshot")
	cmd.Flags().StringVar(&cfg.EventType, "event-type", "bench.synthetic", "metadata.event_type for synthetic claims")
	cmd.Flags().StringVar(&cfg.Source, "source", "trustdb-bench", "metadata.source for synthetic claims")
	cmd.Flags().StringVar(&cfg.SemanticProfile, "semantic-profile", "", "semantic profile label to record in the report")
	cmd.Flags().StringVar(&cfg.DurabilityProfile, "durability-profile", "", "durability profile label to record in the report")
	cmd.Flags().StringVar(&cfg.ProofMode, "proof-mode", "", "server proof materialization mode label to record in the report")
	cmd.Flags().StringVar(&cfg.RecordIndexMode, "record-index-mode", "", "server record index mode label to record in the report")
	cmd.Flags().StringVar(&cfg.MaxProofLevel, "max-proof-level", "", "highest enabled proof level label to record in the report")
	cmd.Flags().StringVar(&cfg.OutputFormat, "output", "json", "output format: json or text")
	cmd.Flags().StringVar(&cfg.ReportFile, "report-file", "", "optional JSON report path to persist the ingest benchmark result")
	return cmd
}

type benchIngestConfig struct {
	Endpoint          string
	Transport         string
	PrivateKeyPath    string
	Identity          sdk.Identity
	Signer            trustcrypto.Signer
	CryptoProvider    trustcrypto.Provider
	Count             int
	Concurrency       int
	PayloadBytes      int
	ProgressEvery     int
	Samples           int
	ProofLevel        string
	ProofTimeout      time.Duration
	Settle            time.Duration
	EventType         string
	Source            string
	SemanticProfile   string
	DurabilityProfile string
	ProofMode         string
	RecordIndexMode   string
	MaxProofLevel     string
	OutputFormat      string
	ReportFile        string
}

type benchIngestResult struct {
	SchemaVersion                 string              `json:"schema_version"`
	Endpoint                      string              `json:"endpoint"`
	Transport                     string              `json:"transport"`
	SemanticProfile               string              `json:"semantic_profile,omitempty"`
	DurabilityProfile             string              `json:"durability_profile,omitempty"`
	ProofMode                     string              `json:"proof_mode,omitempty"`
	RecordIndexMode               string              `json:"record_index_mode,omitempty"`
	MaxProofLevel                 string              `json:"max_proof_level,omitempty"`
	Count                         int                 `json:"count"`
	Concurrency                   int                 `json:"concurrency"`
	PayloadBytes                  int                 `json:"payload_bytes"`
	StartedAt                     time.Time           `json:"started_at"`
	FinishedAt                    time.Time           `json:"finished_at"`
	DurationSeconds               float64             `json:"duration_seconds"`
	SubmitDurationSeconds         float64             `json:"submit_duration_seconds,omitempty"`
	SubmitThroughputPerSec        float64             `json:"submit_throughput_per_sec,omitempty"`
	QueryDurationSeconds          float64             `json:"query_duration_seconds,omitempty"`
	ImmediateQueryDurationSeconds float64             `json:"immediate_query_duration_seconds,omitempty"`
	PostProofQueryDurationSeconds float64             `json:"post_proof_query_duration_seconds,omitempty"`
	ProofWaitDurationSeconds      float64             `json:"proof_wait_duration_seconds,omitempty"`
	SettleDurationSeconds         float64             `json:"settle_duration_seconds,omitempty"`
	Submitted                     int                 `json:"submitted"`
	Failed                        int                 `json:"failed"`
	BatchErrors                   int                 `json:"batch_errors"`
	ThroughputPerSec              float64             `json:"throughput_per_sec"`
	SubmitLatency                 benchLatencySummary `json:"submit_latency"`
	QuerySamples                  benchQuerySummary   `json:"query_samples"`
	ImmediateQuerySamples         benchQuerySummary   `json:"immediate_query_samples"`
	PostProofQuerySamples         benchQuerySummary   `json:"post_proof_query_samples"`
	ProofSamples                  benchProofSummary   `json:"proof_samples"`
	Metrics                       []benchMetricDelta  `json:"metrics"`
	ErrorSamples                  []string            `json:"error_samples,omitempty"`
	Records                       []benchRecordSample `json:"records,omitempty"`
}

type benchLatencySummary struct {
	Count int64   `json:"count"`
	AvgMs float64 `json:"avg_ms"`
	MinMs float64 `json:"min_ms"`
	P50Ms float64 `json:"p50_ms"`
	P95Ms float64 `json:"p95_ms"`
	P99Ms float64 `json:"p99_ms"`
	MaxMs float64 `json:"max_ms"`
}

type benchQuerySummary struct {
	Samples int                 `json:"samples"`
	Ready   int                 `json:"ready"`
	Failed  int                 `json:"failed"`
	Latency benchLatencySummary `json:"latency"`
}

type benchProofSummary struct {
	Samples     int                 `json:"samples"`
	TargetLevel string              `json:"target_level"`
	Ready       int                 `json:"ready"`
	Disabled    int                 `json:"disabled,omitempty"`
	Timeouts    int                 `json:"timeouts"`
	Failed      int                 `json:"failed"`
	Latency     benchLatencySummary `json:"latency"`
}

type benchMetricDelta struct {
	Name   string  `json:"name"`
	Before float64 `json:"before"`
	After  float64 `json:"after"`
	Delta  float64 `json:"delta"`
}

type benchRecordSample struct {
	RecordID string `json:"record_id"`
	BatchID  string `json:"batch_id,omitempty"`
}

type benchSubmitOutcome struct {
	RecordID   string
	Latency    time.Duration
	Err        error
	BatchError string
}

func runBenchIngest(ctx context.Context, rt *runtimeConfig, client *sdk.Client, cfg benchIngestConfig) (benchIngestResult, error) {
	if status := client.CheckHealth(ctx); !status.OK {
		return benchIngestResult{}, &sdk.Error{Op: "bench health", URL: cfg.Endpoint, StatusCode: status.StatusCode, Message: status.Error}
	}

	beforeMetrics, err := fetchBenchMetrics(ctx, client)
	if err != nil {
		rt.logger.Warn().Err(err).Msg("bench could not snapshot initial metrics")
	}

	started := time.Now().UTC()
	submitStats := newBenchLatencyHistogram()
	immediateQueryStats := newBenchLatencyHistogram()
	postProofQueryStats := newBenchLatencyHistogram()
	proofStats := newBenchLatencyHistogram()
	jobCh := make(chan int)
	outcomeCh := make(chan benchSubmitOutcome, cfg.Concurrency)
	sampleMu := sync.Mutex{}
	samples := make([]benchRecordSample, 0, cfg.Samples)
	errorSamples := make([]string, 0, 5)
	var completed atomic.Int64
	var wg sync.WaitGroup
	payloadPool := sync.Pool{
		New: func() any {
			return make([]byte, cfg.PayloadBytes)
		},
	}
	runID := strconv.FormatInt(time.Now().UTC().UnixNano(), 36)

	for worker := 0; worker < cfg.Concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seq := range jobCh {
				if ctx.Err() != nil {
					return
				}
				start := time.Now()
				buf := payloadPool.Get().([]byte)
				if cap(buf) < cfg.PayloadBytes {
					buf = make([]byte, cfg.PayloadBytes)
				}
				buf = buf[:cfg.PayloadBytes]
				fillBenchPayload(buf, seq)
				result, err := submitBenchFile(ctx, client, buf, cfg, sdk.FileClaimOptions{
					ProducedAt:     time.Now().UTC(),
					Nonce:          benchNonce(seq),
					IdempotencyKey: fmt.Sprintf("bench-%s-%d", runID, seq),
					MediaType:      "application/octet-stream",
					StorageURI:     fmt.Sprintf("bench://%s/%d.bin", runID, seq),
					EventType:      cfg.EventType,
					Source:         cfg.Source,
					CustomMetadata: map[string]string{"bench_seq": strconv.Itoa(seq)},
				})
				payloadPool.Put(buf)
				outcome := benchSubmitOutcome{Latency: time.Since(start), Err: err}
				if err == nil {
					outcome.RecordID = result.RecordID
					outcome.BatchError = strings.TrimSpace(result.BatchError)
				}
				select {
				case outcomeCh <- outcome:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		for i := 0; i < cfg.Count; i++ {
			select {
			case jobCh <- i:
			case <-ctx.Done():
				close(jobCh)
				return
			}
		}
		close(jobCh)
	}()
	go func() {
		wg.Wait()
		close(outcomeCh)
	}()

	submitted := 0
	failed := 0
	batchErrors := 0
	for outcome := range outcomeCh {
		completedNow := completed.Add(1)
		if outcome.Err != nil {
			failed++
			if len(errorSamples) < cap(errorSamples) {
				errorSamples = append(errorSamples, outcome.Err.Error())
			}
		} else {
			submitted++
			submitStats.Observe(outcome.Latency)
			if outcome.BatchError != "" {
				batchErrors++
				if len(errorSamples) < cap(errorSamples) {
					errorSamples = append(errorSamples, outcome.BatchError)
				}
			}
			sampleMu.Lock()
			if len(samples) < cfg.Samples {
				samples = append(samples, benchRecordSample{RecordID: outcome.RecordID})
			}
			sampleMu.Unlock()
		}
		if cfg.ProgressEvery > 0 && completedNow%int64(cfg.ProgressEvery) == 0 {
			rt.logger.Info().
				Int64("completed", completedNow).
				Int("submitted", submitted).
				Int("failed", failed).
				Msg("bench ingest progress")
		}
	}
	submitFinished := time.Now().UTC()
	submitDuration := submitFinished.Sub(started)

	immediateQueryReady := 0
	immediateQueryFailed := 0
	postProofQueryReady := 0
	postProofQueryFailed := 0
	postProofQuerySamples := 0
	proofReady := 0
	proofFailed := 0
	proofTimeouts := 0
	proofDisabled := 0
	var immediateQueryDuration time.Duration
	var postProofQueryDuration time.Duration
	var proofWaitDuration time.Duration
	for i := range samples {
		recordStart := time.Now()
		record, err := client.GetRecord(ctx, samples[i].RecordID)
		recordElapsed := time.Since(recordStart)
		immediateQueryDuration += recordElapsed
		if err != nil {
			immediateQueryFailed++
			if len(errorSamples) < cap(errorSamples) {
				errorSamples = append(errorSamples, fmt.Sprintf("immediate query %s: %v", samples[i].RecordID, err))
			}
		} else {
			immediateQueryReady++
			immediateQueryStats.Observe(recordElapsed)
			samples[i].BatchID = record.BatchID
		}

		if cfg.ProofLevel == "" {
			continue
		}
		if cfg.MaxProofLevel != "" && benchProofLevelRank(cfg.ProofLevel) > benchProofLevelRank(cfg.MaxProofLevel) {
			proofDisabled++
			continue
		}
		proofStart := time.Now()
		waitErr := waitForBenchProofLevel(ctx, client, samples[i].RecordID, cfg.ProofLevel, cfg.ProofTimeout)
		proofElapsed := time.Since(proofStart)
		proofWaitDuration += proofElapsed
		switch {
		case waitErr == nil:
			proofReady++
			proofStats.Observe(proofElapsed)
			postProofQuerySamples++
			recordStart := time.Now()
			record, err := client.GetRecord(ctx, samples[i].RecordID)
			recordElapsed := time.Since(recordStart)
			postProofQueryDuration += recordElapsed
			if err != nil {
				postProofQueryFailed++
				if len(errorSamples) < cap(errorSamples) {
					errorSamples = append(errorSamples, fmt.Sprintf("post-proof query %s: %v", samples[i].RecordID, err))
				}
			} else {
				postProofQueryReady++
				postProofQueryStats.Observe(recordElapsed)
				samples[i].BatchID = record.BatchID
			}
		case errors.Is(waitErr, errBenchProofTimeout):
			proofTimeouts++
			if len(errorSamples) < cap(errorSamples) {
				errorSamples = append(errorSamples, fmt.Sprintf("proof timeout %s", samples[i].RecordID))
			}
		default:
			proofFailed++
			if len(errorSamples) < cap(errorSamples) {
				errorSamples = append(errorSamples, fmt.Sprintf("proof wait %s: %v", samples[i].RecordID, waitErr))
			}
		}
	}

	var settleDuration time.Duration
	if cfg.Settle > 0 {
		settleStart := time.Now()
		select {
		case <-time.After(cfg.Settle):
			settleDuration = time.Since(settleStart)
		case <-ctx.Done():
			return benchIngestResult{}, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "bench ingest canceled during settle", ctx.Err())
		}
	}

	afterMetrics, err := fetchBenchMetrics(ctx, client)
	if err != nil {
		rt.logger.Warn().Err(err).Msg("bench could not snapshot final metrics")
	}

	finished := time.Now().UTC()
	duration := finished.Sub(started)
	result := benchIngestResult{
		SchemaVersion:                 benchIngestReportSchema,
		Endpoint:                      cfg.Endpoint,
		Transport:                     cfg.Transport,
		SemanticProfile:               cfg.SemanticProfile,
		DurabilityProfile:             cfg.DurabilityProfile,
		ProofMode:                     cfg.ProofMode,
		RecordIndexMode:               cfg.RecordIndexMode,
		MaxProofLevel:                 cfg.MaxProofLevel,
		Count:                         cfg.Count,
		Concurrency:                   cfg.Concurrency,
		PayloadBytes:                  cfg.PayloadBytes,
		StartedAt:                     started,
		FinishedAt:                    finished,
		DurationSeconds:               duration.Seconds(),
		SubmitDurationSeconds:         submitDuration.Seconds(),
		QueryDurationSeconds:          immediateQueryDuration.Seconds(),
		ImmediateQueryDurationSeconds: immediateQueryDuration.Seconds(),
		PostProofQueryDurationSeconds: postProofQueryDuration.Seconds(),
		ProofWaitDurationSeconds:      proofWaitDuration.Seconds(),
		SettleDurationSeconds:         settleDuration.Seconds(),
		Submitted:                     submitted,
		Failed:                        failed,
		BatchErrors:                   batchErrors,
		SubmitLatency:                 submitStats.Summary(),
		QuerySamples:                  benchQuerySummary{Samples: len(samples), Ready: immediateQueryReady, Failed: immediateQueryFailed, Latency: immediateQueryStats.Summary()},
		ImmediateQuerySamples:         benchQuerySummary{Samples: len(samples), Ready: immediateQueryReady, Failed: immediateQueryFailed, Latency: immediateQueryStats.Summary()},
		PostProofQuerySamples:         benchQuerySummary{Samples: postProofQuerySamples, Ready: postProofQueryReady, Failed: postProofQueryFailed, Latency: postProofQueryStats.Summary()},
		ProofSamples:                  benchProofSummary{Samples: len(samples), TargetLevel: cfg.ProofLevel, Ready: proofReady, Disabled: proofDisabled, Timeouts: proofTimeouts, Failed: proofFailed, Latency: proofStats.Summary()},
		Metrics:                       diffBenchMetrics(beforeMetrics, afterMetrics),
		ErrorSamples:                  errorSamples,
		Records:                       samples,
	}
	if duration > 0 {
		result.ThroughputPerSec = float64(submitted) / duration.Seconds()
	}
	if submitDuration > 0 {
		result.SubmitThroughputPerSec = float64(submitted) / submitDuration.Seconds()
	}
	return result, nil
}

func submitBenchFile(ctx context.Context, client *sdk.Client, raw []byte, cfg benchIngestConfig, opts sdk.FileClaimOptions) (sdk.SubmitResult, error) {
	if cfg.Signer == nil {
		return client.SubmitFile(ctx, bytes.NewReader(raw), cfg.Identity, opts)
	}
	if cfg.CryptoProvider == nil {
		return sdk.SubmitResult{}, errors.New("bench: descriptor signer has no crypto provider")
	}
	hashAlg := opts.HashAlg
	if hashAlg == "" {
		hashAlg = model.DefaultHashAlg
	}
	contentHash, err := trustcrypto.HashBytesWithProvider(cfg.CryptoProvider, hashAlg, raw)
	if err != nil {
		return sdk.SubmitResult{}, err
	}
	claimValue, err := claim.NewFileClaim(
		cfg.Identity.TenantID,
		cfg.Identity.ClientID,
		cfg.Identity.KeyID,
		opts.ProducedAt,
		opts.Nonce,
		opts.IdempotencyKey,
		model.Content{
			HashAlg:       hashAlg,
			ContentHash:   contentHash,
			ContentLength: int64(len(raw)),
			MediaType:     opts.MediaType,
			StorageURI:    opts.StorageURI,
		},
		model.Metadata{
			EventType: opts.EventType,
			Source:    opts.Source,
			Custom:    opts.CustomMetadata,
		},
	)
	if err != nil {
		return sdk.SubmitResult{}, err
	}
	signed, err := claim.SignWithProvider(ctx, cfg.CryptoProvider, claimValue, cfg.Signer)
	if err != nil {
		return sdk.SubmitResult{}, err
	}
	return client.SubmitSignedClaim(ctx, signed)
}

func newBenchSDKClient(transport, endpoint string, concurrency int) (*sdk.Client, error) {
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "http":
		return sdk.NewClient(endpoint, sdk.WithHTTPClient(sdk.NewHTTPClientForConcurrency(concurrency)))
	case "grpc":
		return sdk.NewGRPCClient(endpoint)
	default:
		return nil, usageError("bench ingest --transport must be http or grpc")
	}
}

var errBenchProofTimeout = errors.New("bench proof timeout")

func waitForBenchProofLevel(ctx context.Context, client *sdk.Client, recordID, level string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "bench proof wait canceled", ctx.Err())
		}
		proof, err := client.ExportSingleProof(ctx, recordID)
		if err == nil && benchProofReachedLevel(proof, level) {
			return nil
		}
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			return trusterr.Wrap(trusterr.CodeDeadlineExceeded, "bench proof wait canceled", ctx.Err())
		}
	}
	return errBenchProofTimeout
}

func benchProofReachedLevel(proof sdk.SingleProof, level string) bool {
	switch level {
	case sdk.ProofLevelL3:
		return proof.ProofBundle.RecordID != ""
	case sdk.ProofLevelL4:
		return proof.ProofBundle.RecordID != "" && proof.GlobalProof != nil
	case sdk.ProofLevelL5:
		return proof.ProofBundle.RecordID != "" && proof.GlobalProof != nil && proof.AnchorResult != nil
	default:
		return false
	}
}

func benchProofLevelRank(level string) int {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case sdk.ProofLevelL3:
		return 3
	case sdk.ProofLevelL4:
		return 4
	case sdk.ProofLevelL5:
		return 5
	default:
		return 0
	}
}

func fillBenchPayload(buf []byte, seq int) {
	seed := uint64(seq+1) * 0x9e3779b97f4a7c15
	for i := range buf {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		buf[i] = byte(seed >> 56)
	}
}

func benchNonce(seq int) []byte {
	nonce := make([]byte, 16)
	binary.BigEndian.PutUint64(nonce[:8], uint64(seq+1))
	binary.BigEndian.PutUint64(nonce[8:], ^uint64(seq+1))
	return nonce
}

var benchMetricPrefixes = []string{
	"trustdb_ingest_requests_total",
	"trustdb_ingest_rejected_total",
	"trustdb_wal_append_latency_seconds",
	"trustdb_wal_fsync_latency_seconds",
	"trustdb_batch_commit_latency_seconds",
	"trustdb_batch_stage_latency_seconds",
	"trustdb_batch_size_records",
	"trustdb_merkle_build_latency_seconds",
	"trustdb_materializer_",
	"trustdb_materialized_records_total",
	"trustdb_batch_tree_tiles",
	"trustdb_global_log_",
	"trustdb_anchor_",
	"trustdb_semantic_profile_info",
	"trustdb_anchor_published_total",
	"trustdb_anchor_attempts_total",
	"trustdb_anchor_pending_total",
	"trustdb_queue_depth",
	"trustdb_wal_checkpoint_last_sequence",
	"trustdb_wal_replay_records_total",
	"trustdb_wal_active_segment_id",
	"trustdb_wal_segments_total",
	"trustdb_wal_bytes_pruned_total",
	"trustdb_pebble_",
	"go_goroutines",
	"go_memstats_alloc_bytes",
	"go_memstats_heap_alloc_bytes",
	"go_memstats_heap_inuse_bytes",
}

func fetchBenchMetrics(ctx context.Context, client *sdk.Client) (map[string]float64, error) {
	raw, err := client.MetricsRaw(ctx)
	if err != nil {
		return nil, err
	}
	return parseBenchMetrics(raw)
}

func parseBenchMetrics(raw string) (map[string]float64, error) {
	parser := expfmt.NewTextParser(prommodel.UTF8Validation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(raw))
	if err != nil {
		return nil, err
	}
	out := make(map[string]float64)
	for name, family := range families {
		if !benchMetricWanted(name) {
			continue
		}
		for _, metric := range family.GetMetric() {
			labels := benchMetricLabels(metric.GetLabel())
			switch family.GetType() {
			case dto.MetricType_COUNTER:
				out[benchMetricKey(name, labels)] = metric.GetCounter().GetValue()
			case dto.MetricType_GAUGE:
				out[benchMetricKey(name, labels)] = metric.GetGauge().GetValue()
			case dto.MetricType_UNTYPED:
				out[benchMetricKey(name, labels)] = metric.GetUntyped().GetValue()
			case dto.MetricType_HISTOGRAM:
				h := metric.GetHistogram()
				out[benchMetricKey(name+"_count", labels)] = float64(h.GetSampleCount())
				out[benchMetricKey(name+"_sum", labels)] = h.GetSampleSum()
			case dto.MetricType_SUMMARY:
				s := metric.GetSummary()
				out[benchMetricKey(name+"_count", labels)] = float64(s.GetSampleCount())
				out[benchMetricKey(name+"_sum", labels)] = s.GetSampleSum()
			}
		}
	}
	return out, nil
}

func benchMetricWanted(name string) bool {
	for _, prefix := range benchMetricPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func benchMetricLabels(labels []*dto.LabelPair) string {
	if len(labels) == 0 {
		return ""
	}
	parts := make([]string, 0, len(labels))
	for _, label := range labels {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, label.GetName(), label.GetValue()))
	}
	sort.Strings(parts)
	return "{" + strings.Join(parts, ",") + "}"
}

func benchMetricKey(name, labels string) string {
	return name + labels
}

func diffBenchMetrics(before, after map[string]float64) []benchMetricDelta {
	if len(before) == 0 && len(after) == 0 {
		return nil
	}
	keys := make([]string, 0, len(before)+len(after))
	seen := make(map[string]struct{}, len(before)+len(after))
	for k := range before {
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	for k := range after {
		if _, ok := seen[k]; ok {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]benchMetricDelta, 0, len(keys))
	for _, key := range keys {
		b := before[key]
		a := after[key]
		out = append(out, benchMetricDelta{Name: key, Before: b, After: a, Delta: a - b})
	}
	return out
}

type benchLatencyHistogram struct {
	count     int64
	sum       time.Duration
	min       time.Duration
	max       time.Duration
	bounds    []time.Duration
	bucketHit []int64
}

func newBenchLatencyHistogram() *benchLatencyHistogram {
	bounds := []time.Duration{
		100 * time.Microsecond,
		250 * time.Microsecond,
		500 * time.Microsecond,
		1 * time.Millisecond,
		2 * time.Millisecond,
		5 * time.Millisecond,
		10 * time.Millisecond,
		20 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		200 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
		2 * time.Second,
		5 * time.Second,
		10 * time.Second,
		30 * time.Second,
		60 * time.Second,
	}
	return &benchLatencyHistogram{
		min:       time.Duration(math.MaxInt64),
		bounds:    bounds,
		bucketHit: make([]int64, len(bounds)+1),
	}
}

func (h *benchLatencyHistogram) Observe(d time.Duration) {
	if d < 0 {
		d = 0
	}
	h.count++
	h.sum += d
	if d < h.min {
		h.min = d
	}
	if d > h.max {
		h.max = d
	}
	for i, bound := range h.bounds {
		if d <= bound {
			h.bucketHit[i]++
			return
		}
	}
	h.bucketHit[len(h.bucketHit)-1]++
}

func (h *benchLatencyHistogram) Summary() benchLatencySummary {
	if h.count == 0 {
		return benchLatencySummary{}
	}
	return benchLatencySummary{
		Count: h.count,
		AvgMs: durationMillis(time.Duration(int64(h.sum) / h.count)),
		MinMs: durationMillis(h.min),
		P50Ms: durationMillis(h.quantile(0.50)),
		P95Ms: durationMillis(h.quantile(0.95)),
		P99Ms: durationMillis(h.quantile(0.99)),
		MaxMs: durationMillis(h.max),
	}
}

func (h *benchLatencyHistogram) quantile(q float64) time.Duration {
	if h.count == 0 {
		return 0
	}
	target := int64(math.Ceil(float64(h.count) * q))
	if target < 1 {
		target = 1
	}
	var seen int64
	for i, hits := range h.bucketHit {
		seen += hits
		if seen >= target {
			if i < len(h.bounds) {
				return h.bounds[i]
			}
			return h.max
		}
	}
	return h.max
}

func durationMillis(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func writeBenchIngestText(w io.Writer, result benchIngestResult) {
	fmt.Fprintf(w, "endpoint: %s\n", result.Endpoint)
	fmt.Fprintf(w, "transport: %s\n", result.Transport)
	if result.SemanticProfile != "" {
		fmt.Fprintf(w, "semantic_profile: %s\n", result.SemanticProfile)
	}
	if result.DurabilityProfile != "" {
		fmt.Fprintf(w, "durability_profile: %s\n", result.DurabilityProfile)
	}
	if result.ProofMode != "" {
		fmt.Fprintf(w, "proof_mode: %s\n", result.ProofMode)
	}
	if result.RecordIndexMode != "" {
		fmt.Fprintf(w, "record_index_mode: %s\n", result.RecordIndexMode)
	}
	if result.MaxProofLevel != "" {
		fmt.Fprintf(w, "max_proof_level: %s\n", result.MaxProofLevel)
	}
	fmt.Fprintf(w, "count: %d\n", result.Count)
	fmt.Fprintf(w, "concurrency: %d\n", result.Concurrency)
	fmt.Fprintf(w, "payload_bytes: %d\n", result.PayloadBytes)
	fmt.Fprintf(w, "submitted: %d\n", result.Submitted)
	fmt.Fprintf(w, "failed: %d\n", result.Failed)
	fmt.Fprintf(w, "batch_errors: %d\n", result.BatchErrors)
	fmt.Fprintf(w, "duration_seconds: %.3f\n", result.DurationSeconds)
	fmt.Fprintf(w, "throughput_per_sec: %.2f\n", result.ThroughputPerSec)
	fmt.Fprintf(w, "submit_duration_seconds: %.3f\n", result.SubmitDurationSeconds)
	fmt.Fprintf(w, "submit_throughput_per_sec: %.2f\n", result.SubmitThroughputPerSec)
	fmt.Fprintf(w, "query_duration_seconds: %.3f\n", result.QueryDurationSeconds)
	fmt.Fprintf(w, "immediate_query_duration_seconds: %.3f\n", result.ImmediateQueryDurationSeconds)
	fmt.Fprintf(w, "post_proof_query_duration_seconds: %.3f\n", result.PostProofQueryDurationSeconds)
	fmt.Fprintf(w, "proof_wait_duration_seconds: %.3f\n", result.ProofWaitDurationSeconds)
	fmt.Fprintf(w, "settle_duration_seconds: %.3f\n", result.SettleDurationSeconds)
	fmt.Fprintf(w, "submit_latency_ms: avg=%.2f min=%.2f p50=%.2f p95=%.2f p99=%.2f max=%.2f\n",
		result.SubmitLatency.AvgMs,
		result.SubmitLatency.MinMs,
		result.SubmitLatency.P50Ms,
		result.SubmitLatency.P95Ms,
		result.SubmitLatency.P99Ms,
		result.SubmitLatency.MaxMs,
	)
	fmt.Fprintf(w, "immediate_query_samples: total=%d ready=%d failed=%d avg_ms=%.2f p95_ms=%.2f\n",
		result.ImmediateQuerySamples.Samples,
		result.ImmediateQuerySamples.Ready,
		result.ImmediateQuerySamples.Failed,
		result.ImmediateQuerySamples.Latency.AvgMs,
		result.ImmediateQuerySamples.Latency.P95Ms,
	)
	fmt.Fprintf(w, "post_proof_query_samples: total=%d ready=%d failed=%d avg_ms=%.2f p95_ms=%.2f\n",
		result.PostProofQuerySamples.Samples,
		result.PostProofQuerySamples.Ready,
		result.PostProofQuerySamples.Failed,
		result.PostProofQuerySamples.Latency.AvgMs,
		result.PostProofQuerySamples.Latency.P95Ms,
	)
	fmt.Fprintf(w, "proof_samples: total=%d target=%s ready=%d disabled=%d timeouts=%d failed=%d avg_ms=%.2f p95_ms=%.2f\n",
		result.ProofSamples.Samples,
		result.ProofSamples.TargetLevel,
		result.ProofSamples.Ready,
		result.ProofSamples.Disabled,
		result.ProofSamples.Timeouts,
		result.ProofSamples.Failed,
		result.ProofSamples.Latency.AvgMs,
		result.ProofSamples.Latency.P95Ms,
	)
	if len(result.Metrics) > 0 {
		fmt.Fprintln(w, "metrics:")
		for _, metric := range result.Metrics {
			fmt.Fprintf(w, "  %s delta=%.6f after=%.6f\n", metric.Name, metric.Delta, metric.After)
		}
	}
	if len(result.ErrorSamples) > 0 {
		fmt.Fprintln(w, "errors:")
		for _, msg := range result.ErrorSamples {
			fmt.Fprintf(w, "  - %s\n", msg)
		}
	}
}
