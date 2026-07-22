package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/sdk"
)

func TestReadBenchMatrixFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	validPath := filepath.Join(tmp, "matrix.json")
	if err := os.WriteFile(validPath, []byte(`{"cases":[{"name":"smoke","count":4}]}`), 0o600); err != nil {
		t.Fatalf("WriteFile(valid matrix): %v", err)
	}

	matrix, err := readBenchMatrixFile(validPath)
	if err != nil {
		t.Fatalf("readBenchMatrixFile(valid): %v", err)
	}
	if matrix.SchemaVersion != benchMatrixConfigSchema {
		t.Fatalf("schema fallback = %q, want %q", matrix.SchemaVersion, benchMatrixConfigSchema)
	}
	if len(matrix.Cases) != 1 || matrix.Cases[0].Name != "smoke" {
		t.Fatalf("matrix cases = %+v", matrix.Cases)
	}

	invalidSchemaPath := filepath.Join(tmp, "invalid-schema.json")
	if err := os.WriteFile(invalidSchemaPath, []byte(`{"schema_version":"trustdb.bench.matrix.config.v0","cases":[{"name":"oops"}]}`), 0o600); err != nil {
		t.Fatalf("WriteFile(invalid schema): %v", err)
	}
	if _, err := readBenchMatrixFile(invalidSchemaPath); err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("readBenchMatrixFile(invalid schema) error = %v, want schema_version failure", err)
	}

	emptyCasesPath := filepath.Join(tmp, "empty.json")
	if err := os.WriteFile(emptyCasesPath, []byte(`{"schema_version":"`+benchMatrixConfigSchema+`","cases":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile(empty cases): %v", err)
	}
	if _, err := readBenchMatrixFile(emptyCasesPath); err == nil || !strings.Contains(err.Error(), "at least one case") {
		t.Fatalf("readBenchMatrixFile(empty cases) error = %v, want empty case failure", err)
	}
}

func TestResolveBenchMatrixCase(t *testing.T) {
	t.Parallel()

	base := benchIngestConfig{
		Count:         100,
		Concurrency:   8,
		PayloadBytes:  512,
		ProgressEvery: 10,
		Samples:       4,
		ProofLevel:    sdk.ProofLevelL4,
		ProofTimeout:  30 * time.Second,
		Settle:        2 * time.Second,
		EventType:     "bench.synthetic",
		Source:        "bench-base",
	}
	defaults := benchMatrixDefaults{
		Count:         intPtr(200),
		Concurrency:   intPtr(16),
		ProgressEvery: intPtr(5),
		ProofLevel:    sdk.ProofLevelL5,
		ProofTimeout:  "45s",
		Settle:        "4s",
		EventType:     "bench.defaults",
	}
	item := benchMatrixCaseDef{
		Name:         "grpc heavy",
		Count:        intPtr(300),
		PayloadBytes: intPtr(2048),
		Samples:      intPtr(6),
		Source:       "bench-case",
	}

	got, name, err := resolveBenchMatrixCase(base, defaults, item, 0)
	if err != nil {
		t.Fatalf("resolveBenchMatrixCase() error = %v", err)
	}
	if name != "grpc heavy" {
		t.Fatalf("name = %q", name)
	}
	if got.Count != 300 || got.Concurrency != 16 || got.PayloadBytes != 2048 {
		t.Fatalf("resolved counts = %+v", got)
	}
	if got.ProgressEvery != 5 || got.Samples != 6 {
		t.Fatalf("resolved progress/samples = %+v", got)
	}
	if got.ProofLevel != sdk.ProofLevelL5 || got.EventType != "bench.defaults" || got.Source != "bench-case" {
		t.Fatalf("resolved strings = %+v", got)
	}
	if got.ProofTimeout != 45*time.Second || got.Settle != 4*time.Second {
		t.Fatalf("resolved durations = %+v", got)
	}

	if _, _, err := resolveBenchMatrixCase(base, benchMatrixDefaults{}, benchMatrixCaseDef{ProofTimeout: "nope"}, 1); err == nil || !strings.Contains(err.Error(), "proof_timeout") {
		t.Fatalf("invalid proof_timeout error = %v", err)
	}
	if _, _, err := resolveBenchMatrixCase(base, benchMatrixDefaults{}, benchMatrixCaseDef{ProofLevel: "L9"}, 1); err == nil || !strings.Contains(err.Error(), "proof_level") {
		t.Fatalf("invalid proof_level error = %v", err)
	}
	if _, _, err := resolveBenchMatrixCase(base, benchMatrixDefaults{}, benchMatrixCaseDef{MaxProofLevel: "L9"}, 1); err == nil || !strings.Contains(err.Error(), "max_proof_level") {
		t.Fatalf("invalid max_proof_level error = %v", err)
	}
}

func TestRunBenchMatrixWritesReportsAndSummary(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	cfg := benchMatrixConfig{
		MatrixFile: filepath.Join(tmp, "matrix.json"),
		ReportDir:  filepath.Join(tmp, "reports"),
		Base: benchIngestConfig{
			Endpoint:      "http://127.0.0.1:8080",
			Transport:     "http",
			Count:         10,
			Concurrency:   2,
			PayloadBytes:  256,
			ProgressEvery: 0,
			Samples:       2,
			ProofLevel:    sdk.ProofLevelL4,
			ProofTimeout:  10 * time.Second,
			Settle:        time.Second,
			EventType:     "bench.synthetic",
			Source:        "bench-test",
		},
	}
	matrix := benchMatrixFile{
		SchemaVersion: benchMatrixConfigSchema,
		Defaults: benchMatrixDefaults{
			ProofLevel: sdk.ProofLevelL5,
		},
		Cases: []benchMatrixCaseDef{
			{Name: "small http", Count: intPtr(4)},
			{Name: "large grpc", Count: intPtr(6), Concurrency: intPtr(3), PayloadBytes: intPtr(1024)},
		},
	}

	var seen []benchIngestConfig
	result, err := runBenchMatrix(context.Background(), &runtimeConfig{}, cfg, matrix, func(_ context.Context, caseCfg benchIngestConfig) (benchIngestResult, error) {
		seen = append(seen, caseCfg)
		return benchIngestResult{
			SchemaVersion:          benchIngestReportSchema,
			Endpoint:               caseCfg.Endpoint,
			Transport:              caseCfg.Transport,
			Count:                  caseCfg.Count,
			Concurrency:            caseCfg.Concurrency,
			PayloadBytes:           caseCfg.PayloadBytes,
			Submitted:              caseCfg.Count,
			Failed:                 caseCfg.Concurrency - 1,
			ThroughputPerSec:       float64(caseCfg.Count * caseCfg.Concurrency),
			SubmitThroughputPerSec: float64(caseCfg.Count * caseCfg.Concurrency * 2),
			SubmitLatency:          benchLatencySummary{P95Ms: float64(caseCfg.PayloadBytes) / 10},
			ImmediateQuerySamples:  benchQuerySummary{Samples: caseCfg.Samples, Failed: caseCfg.Concurrency - 1},
			PostProofQuerySamples:  benchQuerySummary{Samples: caseCfg.Samples, Ready: caseCfg.Samples},
			ProofSamples:           benchProofSummary{Samples: caseCfg.Samples, TargetLevel: caseCfg.ProofLevel, Ready: caseCfg.Samples, Timeouts: caseCfg.Concurrency - 1},
		}, nil
	})
	if err != nil {
		t.Fatalf("runBenchMatrix() error = %v", err)
	}

	if len(seen) != 2 {
		t.Fatalf("runner cases = %d, want 2", len(seen))
	}
	if seen[0].Count != 4 || seen[0].Concurrency != 2 || seen[0].ProofLevel != sdk.ProofLevelL5 {
		t.Fatalf("seen[0] = %+v", seen[0])
	}
	if seen[1].Count != 6 || seen[1].Concurrency != 3 || seen[1].PayloadBytes != 1024 {
		t.Fatalf("seen[1] = %+v", seen[1])
	}

	if result.SchemaVersion != benchMatrixReportSchema {
		t.Fatalf("schema = %q", result.SchemaVersion)
	}
	if result.Summary.CaseCount != 2 || result.Summary.TotalSubmitted != 10 || result.Summary.TotalFailed != 3 {
		t.Fatalf("summary counts = %+v", result.Summary)
	}
	if result.Summary.TotalImmediateQueryFailed != 3 || result.Summary.TotalPostProofQueryFailed != 0 || result.Summary.TotalProofTimeouts != 3 {
		t.Fatalf("summary split query/proof counts = %+v", result.Summary)
	}
	if result.Summary.FastestCaseName != "large grpc" || result.Summary.FastestThroughputPerSec != 18 {
		t.Fatalf("summary fastest = %+v", result.Summary)
	}
	if result.Summary.FastestSubmitCaseName != "large grpc" || result.Summary.FastestSubmitThroughputPerSec != 36 {
		t.Fatalf("summary fastest submit = %+v", result.Summary)
	}
	if result.Summary.SlowestSubmitP95CaseName != "large grpc" || result.Summary.SlowestSubmitP95Ms != 102.4 {
		t.Fatalf("summary slowest = %+v", result.Summary)
	}
	if result.SummaryFile == "" {
		t.Fatalf("summary file missing: %+v", result)
	}
	if len(result.Cases) != 2 || result.Cases[0].ReportFile == "" || result.Cases[1].ReportFile == "" {
		t.Fatalf("case report files missing: %+v", result.Cases)
	}

	loadedCase, err := readBenchIngestReportFile(result.Cases[0].ReportFile)
	if err != nil {
		t.Fatalf("readBenchIngestReportFile(case): %v", err)
	}
	if loadedCase.Count != 4 || loadedCase.ProofSamples.TargetLevel != sdk.ProofLevelL5 {
		t.Fatalf("loaded case report = %+v", loadedCase)
	}

	data, err := os.ReadFile(result.SummaryFile)
	if err != nil {
		t.Fatalf("ReadFile(summary): %v", err)
	}
	var persisted benchMatrixResult
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatalf("json.Unmarshal(summary): %v", err)
	}
	if persisted.Summary.TotalSubmitted != result.Summary.TotalSubmitted || len(persisted.Cases) != 2 {
		t.Fatalf("persisted summary = %+v", persisted)
	}
}

func TestWriteBenchMatrixText(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	writeBenchMatrixText(&out, benchMatrixResult{
		MatrixFile:      "matrix.json",
		Endpoint:        "http://127.0.0.1:8080",
		Transport:       "grpc",
		ReportDir:       "reports",
		SummaryFile:     "reports/matrix-summary.json",
		DurationSeconds: 1.25,
		Cases: []benchMatrixCaseResult{
			{
				Name:         "small",
				Count:        4,
				Concurrency:  2,
				PayloadBytes: 256,
				ReportFile:   "reports/01-small.json",
				Result: benchIngestResult{
					Submitted:        4,
					Failed:           0,
					ThroughputPerSec: 8.5,
					SubmitLatency:    benchLatencySummary{P95Ms: 12},
					ImmediateQuerySamples: benchQuerySummary{
						Samples: 2,
						Failed:  1,
					},
					PostProofQuerySamples: benchQuerySummary{
						Samples: 1,
						Ready:   1,
					},
					ProofSamples: benchProofSummary{Timeouts: 1},
				},
			},
		},
		Summary: benchMatrixSummary{
			CaseCount:                 1,
			TotalSubmitted:            4,
			TotalImmediateQueryFailed: 1,
			TotalProofTimeouts:        1,
			AverageThroughputPerSec:   8.5,
			FastestCaseName:           "small",
			FastestThroughputPerSec:   8.5,
			SlowestSubmitP95CaseName:  "small",
			SlowestSubmitP95Ms:        12,
		},
	})
	text := out.String()
	for _, want := range []string{
		"matrix_file: matrix.json",
		"transport: grpc",
		"small count=4 concurrency=2 payload_bytes=256 submitted=4 failed=0 throughput_per_sec=8.50 submit_p95_ms=12.00 immediate_query_failed=1 post_proof_query_failed=0 proof_disabled=0 proof_timeouts=1 report_file=reports/01-small.json",
		"total_immediate_query_failed: 1",
		"total_post_proof_query_failed: 0",
		"total_proof_disabled: 0",
		"average_throughput_per_sec: 8.50",
		"fastest_case: small (8.50/s)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("writeBenchMatrixText() missing %q in %q", want, text)
		}
	}
}

func TestSanitizeBenchCaseName(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"HTTP small":     "http-small",
		"  grpc__L5  ":   "grpc-l5",
		"***":            "case",
		"mix/UP down#42": "mix-up-down-42",
	}
	for input, want := range tests {
		if got := sanitizeBenchCaseName(input); got != want {
			t.Fatalf("sanitizeBenchCaseName(%q) = %q, want %q", input, got, want)
		}
	}
}

func intPtr(v int) *int {
	return &v
}
