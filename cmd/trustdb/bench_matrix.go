package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/sdk"
)

const (
	benchMatrixConfigSchema = "trustdb.bench.matrix.config.v1"
	benchMatrixReportSchema = "trustdb.bench.matrix.report.v1"
)

type benchMatrixConfig struct {
	MatrixFile   string
	ReportDir    string
	OutputFormat string
	Base         benchIngestConfig
}

type benchMatrixFile struct {
	SchemaVersion string               `json:"schema_version"`
	Defaults      benchMatrixDefaults  `json:"defaults,omitempty"`
	Cases         []benchMatrixCaseDef `json:"cases"`
}

type benchMatrixDefaults struct {
	Count             *int   `json:"count,omitempty"`
	Concurrency       *int   `json:"concurrency,omitempty"`
	PayloadBytes      *int   `json:"payload_bytes,omitempty"`
	ProgressEvery     *int   `json:"progress_every,omitempty"`
	Samples           *int   `json:"samples,omitempty"`
	ProofLevel        string `json:"proof_level,omitempty"`
	ProofTimeout      string `json:"proof_timeout,omitempty"`
	Settle            string `json:"settle,omitempty"`
	EventType         string `json:"event_type,omitempty"`
	Source            string `json:"source,omitempty"`
	SemanticProfile   string `json:"semantic_profile,omitempty"`
	DurabilityProfile string `json:"durability_profile,omitempty"`
	ProofMode         string `json:"proof_mode,omitempty"`
	RecordIndexMode   string `json:"record_index_mode,omitempty"`
	MaxProofLevel     string `json:"max_proof_level,omitempty"`
}

type benchMatrixCaseDef struct {
	Name              string `json:"name,omitempty"`
	Count             *int   `json:"count,omitempty"`
	Concurrency       *int   `json:"concurrency,omitempty"`
	PayloadBytes      *int   `json:"payload_bytes,omitempty"`
	ProgressEvery     *int   `json:"progress_every,omitempty"`
	Samples           *int   `json:"samples,omitempty"`
	ProofLevel        string `json:"proof_level,omitempty"`
	ProofTimeout      string `json:"proof_timeout,omitempty"`
	Settle            string `json:"settle,omitempty"`
	EventType         string `json:"event_type,omitempty"`
	Source            string `json:"source,omitempty"`
	SemanticProfile   string `json:"semantic_profile,omitempty"`
	DurabilityProfile string `json:"durability_profile,omitempty"`
	ProofMode         string `json:"proof_mode,omitempty"`
	RecordIndexMode   string `json:"record_index_mode,omitempty"`
	MaxProofLevel     string `json:"max_proof_level,omitempty"`
}

type benchMatrixResult struct {
	SchemaVersion   string                  `json:"schema_version"`
	MatrixFile      string                  `json:"matrix_file"`
	Endpoint        string                  `json:"endpoint"`
	Transport       string                  `json:"transport"`
	ReportDir       string                  `json:"report_dir,omitempty"`
	SummaryFile     string                  `json:"summary_file,omitempty"`
	StartedAt       time.Time               `json:"started_at"`
	FinishedAt      time.Time               `json:"finished_at"`
	DurationSeconds float64                 `json:"duration_seconds"`
	Cases           []benchMatrixCaseResult `json:"cases"`
	Summary         benchMatrixSummary      `json:"summary"`
}

type benchMatrixCaseResult struct {
	Name         string            `json:"name"`
	Count        int               `json:"count"`
	Concurrency  int               `json:"concurrency"`
	PayloadBytes int               `json:"payload_bytes"`
	ReportFile   string            `json:"report_file,omitempty"`
	Result       benchIngestResult `json:"result"`
}

type benchMatrixSummary struct {
	CaseCount                     int     `json:"case_count"`
	TotalSubmitted                int     `json:"total_submitted"`
	TotalFailed                   int     `json:"total_failed"`
	TotalImmediateQueryFailed     int     `json:"total_immediate_query_failed"`
	TotalPostProofQueryFailed     int     `json:"total_post_proof_query_failed"`
	TotalProofTimeouts            int     `json:"total_proof_timeouts"`
	TotalProofDisabled            int     `json:"total_proof_disabled"`
	TotalProofFailed              int     `json:"total_proof_failed"`
	AverageThroughputPerSec       float64 `json:"average_throughput_per_sec"`
	AverageSubmitThroughputPerSec float64 `json:"average_submit_throughput_per_sec"`
	FastestCaseName               string  `json:"fastest_case_name,omitempty"`
	FastestThroughputPerSec       float64 `json:"fastest_throughput_per_sec,omitempty"`
	FastestSubmitCaseName         string  `json:"fastest_submit_case_name,omitempty"`
	FastestSubmitThroughputPerSec float64 `json:"fastest_submit_throughput_per_sec,omitempty"`
	SlowestSubmitP95CaseName      string  `json:"slowest_submit_p95_case_name,omitempty"`
	SlowestSubmitP95Ms            float64 `json:"slowest_submit_p95_ms,omitempty"`
}

type benchMatrixCaseRun func(context.Context, benchIngestConfig) (benchIngestResult, error)

func maxBenchMatrixConcurrency(base benchIngestConfig, matrix benchMatrixFile) int {
	maxConcurrency := base.Concurrency
	if matrix.Defaults.Concurrency != nil && *matrix.Defaults.Concurrency > maxConcurrency {
		maxConcurrency = *matrix.Defaults.Concurrency
	}
	for _, item := range matrix.Cases {
		if item.Concurrency != nil && *item.Concurrency > maxConcurrency {
			maxConcurrency = *item.Concurrency
		}
	}
	return maxConcurrency
}

func newBenchMatrixCommand(rt *runtimeConfig) *cobra.Command {
	var cfg benchMatrixConfig
	cfg.Base.Transport = "http"
	cfg.Base.Count = 1000
	cfg.Base.Concurrency = 16
	cfg.Base.PayloadBytes = 1024
	cfg.Base.Samples = 8
	cfg.Base.ProofLevel = sdk.ProofLevelL4
	cfg.Base.ProofTimeout = 45 * time.Second
	cfg.Base.Settle = 3 * time.Second
	cfg.Base.EventType = "bench.synthetic"
	cfg.Base.Source = "trustdb-bench"
	cfg.Base.OutputFormat = "text"

	cmd := &cobra.Command{
		Use:   "matrix",
		Short: "Run multiple ingest benchmark cases from a JSON matrix file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg.MatrixFile = strings.TrimSpace(cfg.MatrixFile)
			cfg.ReportDir = strings.TrimSpace(cfg.ReportDir)
			cfg.OutputFormat = strings.ToLower(strings.TrimSpace(cfg.OutputFormat))
			cfg.Base.Endpoint = strings.TrimSpace(cfg.Base.Endpoint)
			cfg.Base.Transport = strings.ToLower(strings.TrimSpace(cfg.Base.Transport))
			cfg.Base.PrivateKeyPath = stringOrConfig(cmd, rt, "private-key", cfg.Base.PrivateKeyPath, "keys.client_private")
			cfg.Base.Identity = sdk.Identity{
				TenantID: stringValue(cmd, rt, "tenant", "tenant"),
				ClientID: stringValue(cmd, rt, "client", "client"),
				KeyID:    stringValue(cmd, rt, "key-id", "key_id"),
			}
			if cfg.MatrixFile == "" {
				return usageError("bench matrix requires --matrix-file")
			}
			if cfg.Base.Endpoint == "" {
				return usageError("bench matrix requires --server")
			}
			if cfg.Base.Transport == "" {
				cfg.Base.Transport = "http"
			}
			if cfg.Base.Transport != "http" && cfg.Base.Transport != "grpc" {
				return usageError("bench matrix --transport must be http or grpc")
			}
			if cfg.Base.PrivateKeyPath == "" {
				return usageError("bench matrix requires --private-key")
			}
			if cfg.Base.Identity.ClientID == "" || cfg.Base.Identity.KeyID == "" {
				return usageError("bench matrix requires --client and --key-id")
			}
			if cfg.OutputFormat == "" {
				cfg.OutputFormat = "text"
			}
			if cfg.OutputFormat != "text" && cfg.OutputFormat != "json" {
				return usageError("bench matrix --output must be json or text")
			}
			if cfg.Base.Count <= 0 || cfg.Base.Concurrency <= 0 || cfg.Base.PayloadBytes <= 0 {
				return usageError("bench matrix base count/concurrency/payload-bytes must be > 0")
			}
			if cfg.Base.Samples < 0 {
				return usageError("bench matrix --samples must be >= 0")
			}
			if cfg.Base.ProofTimeout <= 0 {
				return usageError("bench matrix --proof-timeout must be > 0")
			}
			if cfg.Base.ProgressEvery < 0 {
				return usageError("bench matrix --progress-every must be >= 0")
			}
			if cfg.Base.EventType == "" {
				cfg.Base.EventType = "bench.synthetic"
			}
			if cfg.Base.Source == "" {
				cfg.Base.Source = "trustdb-bench"
			}

			signer, descriptor, err := readSigner(cmd.Context(), cfg.Base.PrivateKeyPath)
			if err != nil {
				return err
			}
			if err := requireKeyID(cfg.Base.Identity.KeyID, descriptor); err != nil {
				return err
			}
			cfg.Base.Signer = signer
			cfg.Base.CryptoProvider, err = trustcrypto.ProviderForSuite(descriptor.CryptoSuite)
			if err != nil {
				return err
			}

			matrix, err := readBenchMatrixFile(cfg.MatrixFile)
			if err != nil {
				return err
			}
			client, err := newBenchSDKClient(cfg.Base.Transport, cfg.Base.Endpoint, maxBenchMatrixConcurrency(cfg.Base, matrix))
			if err != nil {
				return err
			}
			defer client.Close()

			result, err := runBenchMatrix(
				cmd.Context(),
				rt,
				cfg,
				matrix,
				func(ctx context.Context, caseCfg benchIngestConfig) (benchIngestResult, error) {
					return runBenchIngest(ctx, rt, client, caseCfg)
				},
			)
			if err != nil {
				return err
			}
			return emitBenchMatrixResult(rt, cfg, result)
		},
	}
	cmd.Flags().StringVar(&cfg.Base.Endpoint, "server", "", "TrustDB server HTTP base URL or gRPC target")
	cmd.Flags().StringVar(&cfg.Base.Transport, "transport", cfg.Base.Transport, "transport: http or grpc")
	addCommonIdentityFlags(cmd)
	cmd.Flags().StringVar(&cfg.Base.PrivateKeyPath, "private-key", "", "client signer descriptor")
	cmd.Flags().StringVar(&cfg.MatrixFile, "matrix-file", "", "JSON matrix file describing benchmark cases")
	cmd.Flags().StringVar(&cfg.ReportDir, "report-dir", "", "optional directory to persist per-case and summary JSON reports")
	cmd.Flags().StringVar(&cfg.OutputFormat, "output", "text", "output format: text or json")
	cmd.Flags().IntVar(&cfg.Base.Count, "count", cfg.Base.Count, "default number of synthetic claims to submit when a matrix case omits count")
	cmd.Flags().IntVar(&cfg.Base.Concurrency, "concurrency", cfg.Base.Concurrency, "default concurrent submit workers when a matrix case omits concurrency")
	cmd.Flags().IntVar(&cfg.Base.PayloadBytes, "payload-bytes", cfg.Base.PayloadBytes, "default payload size in bytes when a matrix case omits payload_bytes")
	cmd.Flags().IntVar(&cfg.Base.ProgressEvery, "progress-every", 0, "default progress log cadence when a matrix case omits progress_every; 0 disables progress logs")
	cmd.Flags().IntVar(&cfg.Base.Samples, "samples", cfg.Base.Samples, "default number of successful records to sample when a matrix case omits samples")
	cmd.Flags().StringVar(&cfg.Base.ProofLevel, "proof-level", cfg.Base.ProofLevel, "default target proof level when a matrix case omits proof_level")
	cmd.Flags().DurationVar(&cfg.Base.ProofTimeout, "proof-timeout", cfg.Base.ProofTimeout, "default maximum wait per sampled record for proof readiness")
	cmd.Flags().DurationVar(&cfg.Base.Settle, "settle", cfg.Base.Settle, "default extra settle time before final metric snapshot")
	cmd.Flags().StringVar(&cfg.Base.EventType, "event-type", cfg.Base.EventType, "default metadata.event_type for synthetic claims")
	cmd.Flags().StringVar(&cfg.Base.Source, "source", cfg.Base.Source, "default metadata.source for synthetic claims")
	cmd.Flags().StringVar(&cfg.Base.SemanticProfile, "semantic-profile", "", "semantic profile label recorded in child ingest reports")
	cmd.Flags().StringVar(&cfg.Base.DurabilityProfile, "durability-profile", "", "durability profile label recorded in child ingest reports")
	cmd.Flags().StringVar(&cfg.Base.ProofMode, "proof-mode", "", "server proof materialization mode label recorded in child ingest reports")
	cmd.Flags().StringVar(&cfg.Base.RecordIndexMode, "record-index-mode", "", "server record index mode label recorded in child ingest reports")
	cmd.Flags().StringVar(&cfg.Base.MaxProofLevel, "max-proof-level", "", "highest enabled proof level label recorded in child ingest reports")
	return cmd
}

func readBenchMatrixFile(path string) (benchMatrixFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return benchMatrixFile{}, err
	}
	var matrix benchMatrixFile
	if err := json.Unmarshal(data, &matrix); err != nil {
		return benchMatrixFile{}, err
	}
	if matrix.SchemaVersion == "" {
		matrix.SchemaVersion = benchMatrixConfigSchema
	}
	if matrix.SchemaVersion != benchMatrixConfigSchema {
		return benchMatrixFile{}, usageError("bench matrix file schema_version must be " + benchMatrixConfigSchema)
	}
	if len(matrix.Cases) == 0 {
		return benchMatrixFile{}, usageError("bench matrix file must contain at least one case")
	}
	return matrix, nil
}

func runBenchMatrix(ctx context.Context, rt *runtimeConfig, cfg benchMatrixConfig, matrix benchMatrixFile, runner benchMatrixCaseRun) (benchMatrixResult, error) {
	started := time.Now().UTC()
	result := benchMatrixResult{
		SchemaVersion: benchMatrixReportSchema,
		MatrixFile:    cfg.MatrixFile,
		Endpoint:      cfg.Base.Endpoint,
		Transport:     cfg.Base.Transport,
		ReportDir:     cfg.ReportDir,
		StartedAt:     started,
		Cases:         make([]benchMatrixCaseResult, 0, len(matrix.Cases)),
	}
	if cfg.ReportDir != "" {
		if err := ensureDir(cfg.ReportDir); err != nil {
			return benchMatrixResult{}, err
		}
	}
	for i, item := range matrix.Cases {
		caseCfg, caseName, err := resolveBenchMatrixCase(cfg.Base, matrix.Defaults, item, i)
		if err != nil {
			return benchMatrixResult{}, err
		}
		benchResult, err := runner(ctx, caseCfg)
		if err != nil {
			return benchMatrixResult{}, err
		}
		caseResult := benchMatrixCaseResult{
			Name:         caseName,
			Count:        caseCfg.Count,
			Concurrency:  caseCfg.Concurrency,
			PayloadBytes: caseCfg.PayloadBytes,
			Result:       benchResult,
		}
		if cfg.ReportDir != "" {
			reportPath := filepath.Join(cfg.ReportDir, fmt.Sprintf("%02d-%s.json", i+1, sanitizeBenchCaseName(caseName)))
			if err := writeJSONFile(reportPath, benchResult); err != nil {
				return benchMatrixResult{}, err
			}
			caseResult.ReportFile = reportPath
		}
		result.Cases = append(result.Cases, caseResult)
	}
	result.FinishedAt = time.Now().UTC()
	result.DurationSeconds = result.FinishedAt.Sub(started).Seconds()
	result.Summary = buildBenchMatrixSummary(result.Cases)
	if cfg.ReportDir != "" {
		result.SummaryFile = filepath.Join(cfg.ReportDir, "matrix-summary.json")
		if err := writeJSONFile(result.SummaryFile, result); err != nil {
			return benchMatrixResult{}, err
		}
	}
	return result, nil
}

func resolveBenchMatrixCase(base benchIngestConfig, defaults benchMatrixDefaults, item benchMatrixCaseDef, index int) (benchIngestConfig, string, error) {
	cfg := base
	cfg.Count = firstBenchMatrixInt(item.Count, defaults.Count, base.Count)
	cfg.Concurrency = firstBenchMatrixInt(item.Concurrency, defaults.Concurrency, base.Concurrency)
	cfg.PayloadBytes = firstBenchMatrixInt(item.PayloadBytes, defaults.PayloadBytes, base.PayloadBytes)
	cfg.ProgressEvery = firstBenchMatrixInt(item.ProgressEvery, defaults.ProgressEvery, base.ProgressEvery)
	cfg.Samples = firstBenchMatrixInt(item.Samples, defaults.Samples, base.Samples)
	cfg.ProofLevel = firstBenchMatrixString(item.ProofLevel, defaults.ProofLevel, base.ProofLevel)
	cfg.EventType = firstBenchMatrixString(item.EventType, defaults.EventType, base.EventType)
	cfg.Source = firstBenchMatrixString(item.Source, defaults.Source, base.Source)
	cfg.SemanticProfile = firstBenchMatrixString(item.SemanticProfile, defaults.SemanticProfile, base.SemanticProfile)
	cfg.DurabilityProfile = firstBenchMatrixString(item.DurabilityProfile, defaults.DurabilityProfile, base.DurabilityProfile)
	cfg.ProofMode = firstBenchMatrixString(item.ProofMode, defaults.ProofMode, base.ProofMode)
	cfg.RecordIndexMode = firstBenchMatrixString(item.RecordIndexMode, defaults.RecordIndexMode, base.RecordIndexMode)
	cfg.MaxProofLevel = firstBenchMatrixString(item.MaxProofLevel, defaults.MaxProofLevel, base.MaxProofLevel)

	proofTimeout, err := resolveBenchMatrixDuration("proof_timeout", item.ProofTimeout, defaults.ProofTimeout, base.ProofTimeout)
	if err != nil {
		return benchIngestConfig{}, "", err
	}
	cfg.ProofTimeout = proofTimeout
	settle, err := resolveBenchMatrixDuration("settle", item.Settle, defaults.Settle, base.Settle)
	if err != nil {
		return benchIngestConfig{}, "", err
	}
	cfg.Settle = settle

	if cfg.Count <= 0 {
		return benchIngestConfig{}, "", usageError("bench matrix case count must be > 0")
	}
	if cfg.Concurrency <= 0 {
		return benchIngestConfig{}, "", usageError("bench matrix case concurrency must be > 0")
	}
	if cfg.PayloadBytes <= 0 {
		return benchIngestConfig{}, "", usageError("bench matrix case payload_bytes must be > 0")
	}
	if cfg.Samples < 0 {
		return benchIngestConfig{}, "", usageError("bench matrix case samples must be >= 0")
	}
	if cfg.ProgressEvery < 0 {
		return benchIngestConfig{}, "", usageError("bench matrix case progress_every must be >= 0")
	}
	switch cfg.ProofLevel {
	case sdk.ProofLevelL3, sdk.ProofLevelL4, sdk.ProofLevelL5:
	default:
		return benchIngestConfig{}, "", usageError("bench matrix case proof_level must be L3, L4, or L5")
	}
	cfg.MaxProofLevel = strings.ToUpper(strings.TrimSpace(cfg.MaxProofLevel))
	switch cfg.MaxProofLevel {
	case "", sdk.ProofLevelL3, sdk.ProofLevelL4, sdk.ProofLevelL5:
	default:
		return benchIngestConfig{}, "", usageError("bench matrix case max_proof_level must be L3, L4, or L5")
	}
	if cfg.ProofTimeout <= 0 {
		return benchIngestConfig{}, "", usageError("bench matrix case proof_timeout must be > 0")
	}
	name := strings.TrimSpace(item.Name)
	if name == "" {
		name = fmt.Sprintf("case-%02d", index+1)
	}
	return cfg, name, nil
}

func buildBenchMatrixSummary(cases []benchMatrixCaseResult) benchMatrixSummary {
	summary := benchMatrixSummary{CaseCount: len(cases)}
	if len(cases) == 0 {
		return summary
	}
	var throughputSum float64
	var submitThroughputSum float64
	for i, item := range cases {
		result := normalizeBenchIngestResult(item.Result)
		summary.TotalSubmitted += result.Submitted
		summary.TotalFailed += result.Failed
		summary.TotalImmediateQueryFailed += result.ImmediateQuerySamples.Failed
		summary.TotalPostProofQueryFailed += result.PostProofQuerySamples.Failed
		summary.TotalProofTimeouts += result.ProofSamples.Timeouts
		summary.TotalProofDisabled += result.ProofSamples.Disabled
		summary.TotalProofFailed += result.ProofSamples.Failed
		throughputSum += result.ThroughputPerSec
		submitThroughputSum += result.SubmitThroughputPerSec
		if i == 0 || result.ThroughputPerSec > summary.FastestThroughputPerSec {
			summary.FastestThroughputPerSec = result.ThroughputPerSec
			summary.FastestCaseName = item.Name
		}
		if i == 0 || result.SubmitThroughputPerSec > summary.FastestSubmitThroughputPerSec {
			summary.FastestSubmitThroughputPerSec = result.SubmitThroughputPerSec
			summary.FastestSubmitCaseName = item.Name
		}
		if summary.SlowestSubmitP95CaseName == "" || result.SubmitLatency.P95Ms > summary.SlowestSubmitP95Ms {
			summary.SlowestSubmitP95CaseName = item.Name
			summary.SlowestSubmitP95Ms = result.SubmitLatency.P95Ms
		}
	}
	summary.AverageThroughputPerSec = throughputSum / float64(len(cases))
	summary.AverageSubmitThroughputPerSec = submitThroughputSum / float64(len(cases))
	return summary
}

func emitBenchMatrixResult(rt *runtimeConfig, cfg benchMatrixConfig, result benchMatrixResult) error {
	if cfg.OutputFormat == "text" {
		writeBenchMatrixText(rt.out, result)
		return nil
	}
	return rt.writeJSON(result)
}

func writeBenchMatrixText(w io.Writer, result benchMatrixResult) {
	fmt.Fprintf(w, "matrix_file: %s\n", result.MatrixFile)
	fmt.Fprintf(w, "endpoint: %s\n", result.Endpoint)
	fmt.Fprintf(w, "transport: %s\n", result.Transport)
	if result.ReportDir != "" {
		fmt.Fprintf(w, "report_dir: %s\n", result.ReportDir)
	}
	if result.SummaryFile != "" {
		fmt.Fprintf(w, "summary_file: %s\n", result.SummaryFile)
	}
	fmt.Fprintf(w, "duration_seconds: %.3f\n", result.DurationSeconds)
	fmt.Fprintln(w, "cases:")
	for _, item := range result.Cases {
		caseResult := normalizeBenchIngestResult(item.Result)
		line := fmt.Sprintf(
			"  %s count=%d concurrency=%d payload_bytes=%d submitted=%d failed=%d throughput_per_sec=%.2f submit_p95_ms=%.2f immediate_query_failed=%d post_proof_query_failed=%d proof_disabled=%d proof_timeouts=%d",
			item.Name,
			item.Count,
			item.Concurrency,
			item.PayloadBytes,
			caseResult.Submitted,
			caseResult.Failed,
			caseResult.ThroughputPerSec,
			caseResult.SubmitLatency.P95Ms,
			caseResult.ImmediateQuerySamples.Failed,
			caseResult.PostProofQuerySamples.Failed,
			caseResult.ProofSamples.Disabled,
			caseResult.ProofSamples.Timeouts,
		)
		if item.ReportFile != "" {
			line += " report_file=" + item.ReportFile
		}
		line += fmt.Sprintf(" submit_throughput_per_sec=%.2f", caseResult.SubmitThroughputPerSec)
		if caseResult.SemanticProfile != "" {
			line += " semantic_profile=" + caseResult.SemanticProfile
		}
		if caseResult.MaxProofLevel != "" {
			line += " max_proof_level=" + caseResult.MaxProofLevel
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w, "summary:")
	fmt.Fprintf(w, "  case_count: %d\n", result.Summary.CaseCount)
	fmt.Fprintf(w, "  total_submitted: %d\n", result.Summary.TotalSubmitted)
	fmt.Fprintf(w, "  total_failed: %d\n", result.Summary.TotalFailed)
	fmt.Fprintf(w, "  total_immediate_query_failed: %d\n", result.Summary.TotalImmediateQueryFailed)
	fmt.Fprintf(w, "  total_post_proof_query_failed: %d\n", result.Summary.TotalPostProofQueryFailed)
	fmt.Fprintf(w, "  total_proof_disabled: %d\n", result.Summary.TotalProofDisabled)
	fmt.Fprintf(w, "  total_proof_timeouts: %d\n", result.Summary.TotalProofTimeouts)
	fmt.Fprintf(w, "  total_proof_failed: %d\n", result.Summary.TotalProofFailed)
	fmt.Fprintf(w, "  average_throughput_per_sec: %.2f\n", result.Summary.AverageThroughputPerSec)
	fmt.Fprintf(w, "  average_submit_throughput_per_sec: %.2f\n", result.Summary.AverageSubmitThroughputPerSec)
	if result.Summary.FastestCaseName != "" {
		fmt.Fprintf(w, "  fastest_case: %s (%.2f/s)\n", result.Summary.FastestCaseName, result.Summary.FastestThroughputPerSec)
	}
	if result.Summary.FastestSubmitCaseName != "" {
		fmt.Fprintf(w, "  fastest_submit_case: %s (%.2f/s)\n", result.Summary.FastestSubmitCaseName, result.Summary.FastestSubmitThroughputPerSec)
	}
	if result.Summary.SlowestSubmitP95CaseName != "" {
		fmt.Fprintf(w, "  slowest_submit_p95_case: %s (%.2f ms)\n", result.Summary.SlowestSubmitP95CaseName, result.Summary.SlowestSubmitP95Ms)
	}
}

func firstBenchMatrixInt(primary, secondary *int, fallback int) int {
	if primary != nil {
		return *primary
	}
	if secondary != nil {
		return *secondary
	}
	return fallback
}

func firstBenchMatrixString(primary, secondary, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return strings.TrimSpace(primary)
	}
	if strings.TrimSpace(secondary) != "" {
		return strings.TrimSpace(secondary)
	}
	return fallback
}

func resolveBenchMatrixDuration(field, primary, secondary string, fallback time.Duration) (time.Duration, error) {
	value := firstBenchMatrixString(primary, secondary, "")
	if value == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, usageError("bench matrix case " + field + " must be a valid duration")
	}
	return d, nil
}

func sanitizeBenchCaseName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "case"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "case"
	}
	return out
}
