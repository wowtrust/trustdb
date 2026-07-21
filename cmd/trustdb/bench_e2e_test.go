//go:build e2e

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/anchor"
	"github.com/ryan-wong-coder/trustdb/internal/app"
	"github.com/ryan-wong-coder/trustdb/internal/batch"
	"github.com/ryan-wong-coder/trustdb/internal/globallog"
	"github.com/ryan-wong-coder/trustdb/internal/grpcapi"
	"github.com/ryan-wong-coder/trustdb/internal/httpapi"
	"github.com/ryan-wong-coder/trustdb/internal/ingest"
	"github.com/ryan-wong-coder/trustdb/internal/observability"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
	"github.com/ryan-wong-coder/trustdb/internal/trustcrypto"
	"github.com/ryan-wong-coder/trustdb/internal/wal"
	"github.com/ryan-wong-coder/trustdb/sdk"
	"google.golang.org/grpc"
)

const (
	trustdbBenchArtifactDirEnv                = "TRUSTDB_BENCH_ARTIFACT_DIR"
	trustdbBenchMinCandidateThroughputEnv     = "TRUSTDB_BENCH_MIN_CANDIDATE_THROUGHPUT"
	trustdbBenchMaxThroughputRegressionPctEnv = "TRUSTDB_BENCH_MAX_THROUGHPUT_REGRESSION_PCT"
	trustdbBenchMaxDurationRegressionPctEnv   = "TRUSTDB_BENCH_MAX_DURATION_REGRESSION_PCT"
	trustdbBenchMaxSubmitP95RegressionPctEnv  = "TRUSTDB_BENCH_MAX_SUBMIT_P95_REGRESSION_PCT"
	trustdbBenchMaxCandidateSubmitP95MsEnv    = "TRUSTDB_BENCH_MAX_CANDIDATE_SUBMIT_P95_MS"
	trustdbBenchMaxCandidateFailedEnv         = "TRUSTDB_BENCH_MAX_CANDIDATE_FAILED"
	trustdbBenchMaxCandidateBatchErrorsEnv    = "TRUSTDB_BENCH_MAX_CANDIDATE_BATCH_ERRORS"
	trustdbBenchMaxCandidateQueryFailedEnv    = "TRUSTDB_BENCH_MAX_CANDIDATE_QUERY_FAILED"
	trustdbBenchMaxCandidateProofTimeoutsEnv  = "TRUSTDB_BENCH_MAX_CANDIDATE_PROOF_TIMEOUTS"
	trustdbBenchMaxCandidateProofFailedEnv    = "TRUSTDB_BENCH_MAX_CANDIDATE_PROOF_FAILED"
)

type benchSmokeGateConfig struct {
	MinCandidateThroughput     float64
	MaxThroughputRegressionPct float64
	MaxDurationRegressionPct   float64
	MaxSubmitP95RegressionPct  float64
	MaxCandidateSubmitP95Ms    float64
	MaxCandidateFailed         int
	MaxCandidateBatchErrors    int
	MaxCandidateQueryFailed    int
	MaxCandidateProofTimeouts  int
	MaxCandidateProofFailed    int
}

func TestBenchIngestCollectsPebbleMetricsOverHTTPAndGRPC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport string
		clientFor func(testing.TB, benchPebbleE2EEnv) *sdk.Client
	}{
		{
			name:      "http",
			transport: "http",
			clientFor: func(tb testing.TB, env benchPebbleE2EEnv) *sdk.Client {
				tb.Helper()
				client, err := sdk.NewClient(env.httpURL)
				if err != nil {
					tb.Fatalf("NewClient: %v", err)
				}
				return client
			},
		},
		{
			name:      "grpc",
			transport: "grpc",
			clientFor: func(tb testing.TB, env benchPebbleE2EEnv) *sdk.Client {
				tb.Helper()
				client, err := sdk.NewGRPCClient(env.grpcTarget)
				if err != nil {
					tb.Fatalf("NewGRPCClient: %v", err)
				}
				return client
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			env := newBenchPebbleE2EEnv(t)
			client := tt.clientFor(t, env)
			defer client.Close()

			result, err := runBenchIngest(context.Background(), &runtimeConfig{logger: silentLogger()}, client, benchIngestConfig{
				Endpoint:      client.BaseURL(),
				Transport:     tt.transport,
				Identity:      env.identity,
				Count:         4,
				Concurrency:   2,
				PayloadBytes:  512,
				ProgressEvery: 0,
				Samples:       2,
				ProofLevel:    sdk.ProofLevelL5,
				ProofTimeout:  10 * time.Second,
				Settle:        250 * time.Millisecond,
				EventType:     "bench.e2e",
				Source:        "bench-pebble-e2e",
			})
			if err != nil {
				t.Fatalf("runBenchIngest: %v", err)
			}
			if result.Submitted != 4 {
				t.Fatalf("submitted = %d, want 4", result.Submitted)
			}
			if result.ProofSamples.Samples == 0 || result.ProofSamples.Ready == 0 {
				t.Fatalf("proof summary = %+v, want samples and ready > 0", result.ProofSamples)
			}
			if len(result.Metrics) == 0 {
				t.Fatalf("metrics diff is empty")
			}

			rawMetrics, err := client.MetricsRaw(context.Background())
			if err != nil {
				t.Fatalf("MetricsRaw: %v", err)
			}
			if !strings.Contains(rawMetrics, "trustdb_pebble_wal_bytes_written_total") {
				t.Fatalf("metrics endpoint missing pebble WAL metric")
			}

			walBytesWritten := mustFindBenchMetric(t, result.Metrics, "trustdb_pebble_wal_bytes_written_total")
			if walBytesWritten.After <= 0 || walBytesWritten.Delta <= 0 {
				t.Fatalf("wal bytes written metric = %+v, want after/delta > 0", walBytesWritten)
			}

			walSize := mustFindBenchMetric(t, result.Metrics, "trustdb_pebble_wal_size_bytes")
			if walSize.After <= 0 {
				t.Fatalf("wal size metric = %+v, want after > 0", walSize)
			}

			if _, ok := findBenchMetric(result.Metrics, "trustdb_pebble_memtable_size_bytes"); !ok {
				t.Fatalf("result metrics missing pebble memtable size entry")
			}
		})
	}
}

func TestBenchMatrixCommandWritesCaseReports(t *testing.T) {
	t.Parallel()

	env := newBenchPebbleE2EEnv(t)
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "client.key")
	if err := writeKey(keyPath, env.identity.PrivateKey); err != nil {
		t.Fatalf("writeKey: %v", err)
	}
	matrixPath := filepath.Join(tmp, "matrix.json")
	if err := os.WriteFile(matrixPath, []byte(`{
  "schema_version": "`+benchMatrixConfigSchema+`",
  "defaults": {
    "proof_level": "L5",
    "proof_timeout": "10s",
    "settle": "250ms",
    "event_type": "bench.matrix.e2e",
    "source": "bench-matrix-e2e"
  },
  "cases": [
    {"name": "small", "count": 2, "concurrency": 1, "payload_bytes": 128, "samples": 1},
    {"name": "medium", "count": 3, "concurrency": 2, "payload_bytes": 256, "samples": 1}
  ]
}`), 0o600); err != nil {
		t.Fatalf("WriteFile(matrix): %v", err)
	}
	reportDir := filepath.Join(tmp, "reports")

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{
		"bench", "matrix",
		"--server", env.httpURL,
		"--transport", "http",
		"--tenant", env.identity.TenantID,
		"--client", env.identity.ClientID,
		"--key-id", env.identity.KeyID,
		"--private-key", keyPath,
		"--matrix-file", matrixPath,
		"--report-dir", reportDir,
		"--output", "json",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("bench matrix execute: %v stderr=%s", err, errOut.String())
	}

	var result benchMatrixResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal(matrix output): %v body=%q", err, out.String())
	}
	if result.SchemaVersion != benchMatrixReportSchema {
		t.Fatalf("schema = %q", result.SchemaVersion)
	}
	if len(result.Cases) != 2 || result.Summary.CaseCount != 2 {
		t.Fatalf("cases/summary = %+v", result)
	}
	if result.Cases[0].ReportFile == "" || result.Cases[1].ReportFile == "" || result.SummaryFile == "" {
		t.Fatalf("report paths missing: %+v", result)
	}
	if _, err := os.Stat(result.Cases[0].ReportFile); err != nil {
		t.Fatalf("stat case report: %v", err)
	}
	if _, err := os.Stat(result.SummaryFile); err != nil {
		t.Fatalf("stat summary report: %v", err)
	}
	if result.Summary.TotalSubmitted != 5 {
		t.Fatalf("total submitted = %d, want 5", result.Summary.TotalSubmitted)
	}
}

func TestBenchCIArtifactFlow(t *testing.T) {
	env := newBenchPebbleE2EEnv(t)
	gate := loadBenchSmokeGateConfig(t)
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "client.key")
	if err := writeKey(keyPath, env.identity.PrivateKey); err != nil {
		t.Fatalf("writeKey: %v", err)
	}

	artifactDir := strings.TrimSpace(os.Getenv(trustdbBenchArtifactDirEnv))
	if artifactDir == "" {
		artifactDir = filepath.Join(tmp, "artifacts")
	}
	if err := ensureDir(artifactDir); err != nil {
		t.Fatalf("ensureDir(%q): %v", artifactDir, err)
	}
	matrixDir := filepath.Join(artifactDir, "matrix")
	if err := ensureDir(matrixDir); err != nil {
		t.Fatalf("ensureDir(%q): %v", matrixDir, err)
	}

	baselinePath := filepath.Join(artifactDir, "baseline.json")
	candidatePath := filepath.Join(artifactDir, "candidate.json")
	comparePath := filepath.Join(artifactDir, "compare.json")
	matrixStdoutPath := filepath.Join(artifactDir, "matrix-result.json")
	matrixPath := filepath.Join(tmp, "ci-matrix.json")
	if err := os.WriteFile(matrixPath, []byte(`{
  "schema_version": "`+benchMatrixConfigSchema+`",
  "defaults": {
    "proof_level": "L5",
    "proof_timeout": "10s",
    "settle": "250ms",
    "event_type": "bench.ci.matrix",
    "source": "bench-ci"
  },
  "cases": [
    {"name": "http-small", "count": 2, "concurrency": 1, "payload_bytes": 128, "samples": 1},
    {"name": "http-medium", "count": 3, "concurrency": 2, "payload_bytes": 256, "samples": 1}
  ]
}`), 0o600); err != nil {
		t.Fatalf("WriteFile(matrix): %v", err)
	}

	if _, _, err := runBenchCLICommand(t, []string{
		"bench", "ingest",
		"--server", env.httpURL,
		"--transport", "http",
		"--tenant", env.identity.TenantID,
		"--client", env.identity.ClientID,
		"--key-id", env.identity.KeyID,
		"--private-key", keyPath,
		"--count", "3",
		"--concurrency", "2",
		"--payload-bytes", "256",
		"--samples", "1",
		"--proof-level", "L5",
		"--proof-timeout", "10s",
		"--settle", "250ms",
		"--event-type", "bench.ci.baseline",
		"--source", "bench-ci",
		"--report-file", baselinePath,
		"--output", "json",
	}); err != nil {
		t.Fatalf("bench ingest baseline: %v", err)
	}

	if _, _, err := runBenchCLICommand(t, []string{
		"bench", "ingest",
		"--server", env.httpURL,
		"--transport", "http",
		"--tenant", env.identity.TenantID,
		"--client", env.identity.ClientID,
		"--key-id", env.identity.KeyID,
		"--private-key", keyPath,
		"--count", "3",
		"--concurrency", "2",
		"--payload-bytes", "256",
		"--samples", "1",
		"--proof-level", "L5",
		"--proof-timeout", "10s",
		"--settle", "250ms",
		"--event-type", "bench.ci.candidate",
		"--source", "bench-ci",
		"--report-file", candidatePath,
		"--output", "json",
	}); err != nil {
		t.Fatalf("bench ingest candidate: %v", err)
	}

	compareArgs := append([]string{
		"bench", "compare",
		"--baseline", baselinePath,
		"--candidate", candidatePath,
		"--output", "json",
	}, gate.CompareArgs()...)
	compareOut, _, err := runBenchCLICommand(t, compareArgs)
	if err != nil {
		t.Fatalf("bench compare: %v", err)
	}
	if err := os.WriteFile(comparePath, compareOut.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile(compare): %v", err)
	}

	matrixOut, _, err := runBenchCLICommand(t, []string{
		"bench", "matrix",
		"--server", env.httpURL,
		"--transport", "http",
		"--tenant", env.identity.TenantID,
		"--client", env.identity.ClientID,
		"--key-id", env.identity.KeyID,
		"--private-key", keyPath,
		"--matrix-file", matrixPath,
		"--report-dir", matrixDir,
		"--output", "json",
	})
	if err != nil {
		t.Fatalf("bench matrix: %v", err)
	}
	if err := os.WriteFile(matrixStdoutPath, matrixOut.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile(matrix stdout): %v", err)
	}

	for _, path := range []string{
		baselinePath,
		candidatePath,
		comparePath,
		matrixStdoutPath,
		filepath.Join(matrixDir, "matrix-summary.json"),
		filepath.Join(matrixDir, "01-http-small.json"),
		filepath.Join(matrixDir, "02-http-medium.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("artifact %q missing: %v", path, err)
		}
	}
}

type benchPebbleE2EEnv struct {
	httpURL    string
	grpcTarget string
	identity   sdk.Identity
}

func newBenchPebbleE2EEnv(t *testing.T) benchPebbleE2EEnv {
	t.Helper()

	clientPub, clientPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key client: %v", err)
	}
	_, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key server: %v", err)
	}

	tmp := t.TempDir()
	writer, _, err := openWALWriterWithOptions(filepath.Join(tmp, "wal"), wal.Options{})
	if err != nil {
		t.Fatalf("openWALWriterWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	reg, metrics := observability.NewRegistry()
	engine := app.LocalEngine{
		ServerID:         "server-bench-pebble-e2e",
		ServerKeyID:      "server-key",
		ClientPublicKey:  clientPub,
		ServerPrivateKey: serverPriv,
		WAL:              writer,
		Idempotency:      app.NewIdempotencyIndex(),
		Now:              func() time.Time { return time.Now().UTC() },
	}
	store, err := proofstore.Open(proofstore.Config{
		Kind: proofstore.BackendPebble,
		Path: filepath.Join(tmp, "pebble"),
	})
	if err != nil {
		t.Fatalf("proofstore.Open(pebble): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if enabled, err := observability.RegisterPebbleMetrics(reg, store); err != nil {
		t.Fatalf("RegisterPebbleMetrics: %v", err)
	} else if !enabled {
		t.Fatalf("RegisterPebbleMetrics enabled = false, want true")
	}

	ingestSvc := ingest.New(engine, ingest.Options{QueueSize: 16, Workers: 2}, metrics)
	t.Cleanup(func() { _ = ingestSvc.Shutdown(context.Background()) })

	anchorSvc, err := anchor.NewService(anchor.Config{
		Sink:         anchor.NewNoopSink(),
		Store:        store,
		Metrics:      metrics,
		PollInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("anchor.NewService: %v", err)
	}
	anchorSvc.Start(context.Background())
	t.Cleanup(anchorSvc.Stop)

	rt := &runtimeConfig{logger: silentLogger()}
	globalSvc, err := globallog.New(globallog.Options{
		Store:      store,
		LogID:      engine.ServerID,
		KeyID:      engine.ServerKeyID,
		PrivateKey: serverPriv,
	})
	if err != nil {
		t.Fatalf("globallog.New: %v", err)
	}
	globalOutbox := globallog.NewOutboxWorker(globallog.OutboxConfig{
		Store:          store,
		Global:         globalSvc,
		PollInterval:   20 * time.Millisecond,
		AnchorOutbox:   true,
		OnAnchorsReady: anchorSvc.Trigger,
	})
	globalOutbox.Start(context.Background())
	t.Cleanup(globalOutbox.Stop)

	batchSvc := batch.New(engine, store, batch.Options{
		QueueSize:        16,
		MaxRecords:       1,
		MaxDelay:         20 * time.Millisecond,
		OnBatchCommitted: newGlobalLogEnqueueHook(rt, store, globalOutbox),
	}, metrics)
	t.Cleanup(func() { _ = batchSvc.Shutdown(context.Background()) })

	metricsHandler := observability.Handler(reg)
	anchorAPI := anchor.NewAPI(store)
	httpServer := httptest.NewServer(httpapi.NewWithGlobalAndAnchors(ingestSvc, metricsHandler, batchSvc, globalSvc, anchorAPI))
	t.Cleanup(httpServer.Close)

	grpcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen grpc: %v", err)
	}
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(grpcapi.MaxMessageBytes),
		grpc.MaxSendMsgSize(grpcapi.MaxMessageBytes),
	)
	grpcapi.RegisterTrustDBServiceServer(grpcServer, grpcapi.NewServer(ingestSvc, batchSvc, globalSvc, anchorAPI, metricsHandler))
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- grpcServer.Serve(grpcListener)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = grpcListener.Close()
		select {
		case err := <-serveErr:
			if err != nil && err != grpc.ErrServerStopped {
				t.Fatalf("grpc serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("grpc server did not stop")
		}
	})

	return benchPebbleE2EEnv{
		httpURL:    httpServer.URL,
		grpcTarget: grpcListener.Addr().String(),
		identity: sdk.Identity{
			TenantID:   "tenant-bench-e2e",
			ClientID:   "client-bench-e2e",
			KeyID:      "client-key",
			PrivateKey: clientPriv,
		},
	}
}

func mustFindBenchMetric(t *testing.T, metrics []benchMetricDelta, name string) benchMetricDelta {
	t.Helper()
	metric, ok := findBenchMetric(metrics, name)
	if !ok {
		t.Fatalf("metric %q not found in %+v", name, metrics)
	}
	return metric
}

func findBenchMetric(metrics []benchMetricDelta, name string) (benchMetricDelta, bool) {
	for _, metric := range metrics {
		if metric.Name == name {
			return metric, true
		}
	}
	return benchMetricDelta{}, false
}

func runBenchCLICommand(t *testing.T, args []string) (*bytes.Buffer, *bytes.Buffer, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return &out, &errOut, err
}

func loadBenchSmokeGateConfig(t testing.TB) benchSmokeGateConfig {
	t.Helper()
	return benchSmokeGateConfig{
		MinCandidateThroughput:     benchEnvFloat(t, trustdbBenchMinCandidateThroughputEnv, 1),
		MaxThroughputRegressionPct: benchEnvFloat(t, trustdbBenchMaxThroughputRegressionPctEnv, 80),
		// Default is looser than bench-smoke CI (which sets TRUSTDB_BENCH_MAX_DURATION_REGRESSION_PCT)
		// so shared e2e runners are less likely to flake on wall-clock variance.
		MaxDurationRegressionPct:  benchEnvFloat(t, trustdbBenchMaxDurationRegressionPctEnv, 500),
		MaxSubmitP95RegressionPct: benchEnvFloat(t, trustdbBenchMaxSubmitP95RegressionPctEnv, 0),
		MaxCandidateSubmitP95Ms:   benchEnvFloat(t, trustdbBenchMaxCandidateSubmitP95MsEnv, 0),
		MaxCandidateFailed:        benchEnvInt(t, trustdbBenchMaxCandidateFailedEnv, 0),
		MaxCandidateBatchErrors:   benchEnvInt(t, trustdbBenchMaxCandidateBatchErrorsEnv, 0),
		// Immediate query samples intentionally happen before proof waiting and
		// can race async record-index visibility on busy CI runners. Keep the
		// smoke gate strict for failed submissions/batch errors/post-proof
		// queries, but allow the single immediate sample in this tiny flow to
		// be unavailable without failing unrelated CI jobs.
		MaxCandidateQueryFailed:   benchEnvInt(t, trustdbBenchMaxCandidateQueryFailedEnv, 1),
		MaxCandidateProofTimeouts: benchEnvInt(t, trustdbBenchMaxCandidateProofTimeoutsEnv, 0),
		MaxCandidateProofFailed:   benchEnvInt(t, trustdbBenchMaxCandidateProofFailedEnv, 0),
	}
}

func (cfg benchSmokeGateConfig) CompareArgs() []string {
	args := []string{
		"--min-candidate-throughput", strconv.FormatFloat(cfg.MinCandidateThroughput, 'f', -1, 64),
		"--max-throughput-regression-pct", strconv.FormatFloat(cfg.MaxThroughputRegressionPct, 'f', -1, 64),
		"--max-duration-regression-pct", strconv.FormatFloat(cfg.MaxDurationRegressionPct, 'f', -1, 64),
		"--max-candidate-failed", strconv.Itoa(cfg.MaxCandidateFailed),
		"--max-candidate-batch-errors", strconv.Itoa(cfg.MaxCandidateBatchErrors),
		"--max-candidate-query-failed", strconv.Itoa(cfg.MaxCandidateQueryFailed),
		"--max-candidate-proof-timeouts", strconv.Itoa(cfg.MaxCandidateProofTimeouts),
		"--max-candidate-proof-failed", strconv.Itoa(cfg.MaxCandidateProofFailed),
	}
	if cfg.MaxSubmitP95RegressionPct > 0 {
		args = append(args, "--max-submit-p95-regression-pct", strconv.FormatFloat(cfg.MaxSubmitP95RegressionPct, 'f', -1, 64))
	}
	if cfg.MaxCandidateSubmitP95Ms > 0 {
		args = append(args, "--max-candidate-submit-p95-ms", strconv.FormatFloat(cfg.MaxCandidateSubmitP95Ms, 'f', -1, 64))
	}
	return args
}

func TestBenchSmokeGateCompareArgsSkipsDisabledSubmitP95Regression(t *testing.T) {
	t.Parallel()

	args := benchSmokeGateConfig{
		MinCandidateThroughput:     1,
		MaxThroughputRegressionPct: 80,
		MaxDurationRegressionPct:   200,
	}.CompareArgs()

	if hasArg(args, "--max-submit-p95-regression-pct") {
		t.Fatalf("CompareArgs() included disabled submit p95 regression gate: %v", args)
	}

	args = benchSmokeGateConfig{MaxSubmitP95RegressionPct: 25}.CompareArgs()
	if !hasArg(args, "--max-submit-p95-regression-pct") {
		t.Fatalf("CompareArgs() missing enabled submit p95 regression gate: %v", args)
	}
}

func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func benchEnvFloat(t testing.TB, name string, fallback float64) float64 {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		t.Fatalf("ParseFloat(%s=%q): %v", name, raw, err)
	}
	return value
}

func benchEnvInt(t testing.TB, name string, fallback int) int {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("Atoi(%s=%q): %v", name, raw, err)
	}
	return value
}
