package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/sdk"
)

func TestParseBenchMetrics(t *testing.T) {
	t.Parallel()

	raw := `
# HELP trustdb_ingest_requests_total Total ingest requests by result.
# TYPE trustdb_ingest_requests_total counter
trustdb_ingest_requests_total{result="accepted"} 12
# HELP trustdb_pebble_compactions_total Total number of Pebble compactions since the database was opened.
# TYPE trustdb_pebble_compactions_total counter
trustdb_pebble_compactions_total 4
# HELP trustdb_queue_depth Current queue depth by queue name.
# TYPE trustdb_queue_depth gauge
trustdb_queue_depth{queue="ingest"} 3
# HELP trustdb_batch_commit_latency_seconds Batch commit latency in seconds.
# TYPE trustdb_batch_commit_latency_seconds histogram
trustdb_batch_commit_latency_seconds_bucket{le="0.001"} 0
trustdb_batch_commit_latency_seconds_bucket{le="0.01"} 2
trustdb_batch_commit_latency_seconds_bucket{le="+Inf"} 2
trustdb_batch_commit_latency_seconds_sum 0.012
trustdb_batch_commit_latency_seconds_count 2
`
	metrics, err := parseBenchMetrics(raw)
	if err != nil {
		t.Fatalf("parseBenchMetrics() error = %v", err)
	}
	if got := metrics[`trustdb_ingest_requests_total{result="accepted"}`]; got != 12 {
		t.Fatalf("accepted counter = %v", got)
	}
	if got := metrics[`trustdb_queue_depth{queue="ingest"}`]; got != 3 {
		t.Fatalf("queue depth = %v", got)
	}
	if got := metrics[`trustdb_batch_commit_latency_seconds_count`]; got != 2 {
		t.Fatalf("batch count = %v", got)
	}
	if got := metrics[`trustdb_batch_commit_latency_seconds_sum`]; got != 0.012 {
		t.Fatalf("batch sum = %v", got)
	}
	if got := metrics[`trustdb_pebble_compactions_total`]; got != 4 {
		t.Fatalf("pebble compactions = %v", got)
	}
}

func TestRunBenchIngest(t *testing.T) {
	t.Parallel()

	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	client, err := sdk.NewClientWithTransport(&fakeBenchTransport{})
	if err != nil {
		t.Fatalf("NewClientWithTransport() error = %v", err)
	}

	result, err := runBenchIngest(context.Background(), &runtimeConfig{logger: silentLogger()}, client, benchIngestConfig{
		Endpoint:      "bench://fake",
		Transport:     "http",
		Identity:      sdk.Identity{TenantID: "tenant-bench", ClientID: "client-bench", KeyID: "key-bench", PrivateKey: priv},
		Count:         4,
		Concurrency:   2,
		PayloadBytes:  128,
		ProgressEvery: 0,
		Samples:       2,
		ProofLevel:    sdk.ProofLevelL3,
		ProofTimeout:  500 * time.Millisecond,
		Settle:        0,
		EventType:     "bench.synthetic",
		Source:        "bench-test",
	})
	if err != nil {
		t.Fatalf("runBenchIngest() error = %v", err)
	}
	if result.Submitted != 4 || result.Failed != 0 {
		t.Fatalf("submit summary = %+v", result)
	}
	if result.QuerySamples.Ready != 2 || result.ProofSamples.Ready != 2 {
		t.Fatalf("query/proof samples = %+v %+v", result.QuerySamples, result.ProofSamples)
	}
	if result.ImmediateQuerySamples.Ready != 2 || result.PostProofQuerySamples.Ready != 2 {
		t.Fatalf("split query samples = %+v %+v", result.ImmediateQuerySamples, result.PostProofQuerySamples)
	}
	if result.SubmitLatency.Count != 4 {
		t.Fatalf("submit latency count = %+v", result.SubmitLatency)
	}
	if len(result.Metrics) == 0 {
		t.Fatalf("metrics diff should not be empty")
	}
	if result.DurationSeconds < 0 || result.ThroughputPerSec < 0 {
		t.Fatalf("duration/throughput = %v %v", result.DurationSeconds, result.ThroughputPerSec)
	}
}

func TestRunBenchIngestSplitsImmediateAndPostProofQueries(t *testing.T) {
	t.Parallel()

	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	client, err := sdk.NewClientWithTransport(&fakeBenchVisibilityTransport{})
	if err != nil {
		t.Fatalf("NewClientWithTransport() error = %v", err)
	}

	result, err := runBenchIngest(context.Background(), &runtimeConfig{logger: silentLogger()}, client, benchIngestConfig{
		Endpoint:      "bench://fake",
		Transport:     "http",
		Identity:      sdk.Identity{TenantID: "tenant-bench", ClientID: "client-bench", KeyID: "key-bench", PrivateKey: priv},
		Count:         1,
		Concurrency:   1,
		PayloadBytes:  128,
		ProgressEvery: 0,
		Samples:       1,
		ProofLevel:    sdk.ProofLevelL3,
		ProofTimeout:  500 * time.Millisecond,
		Settle:        0,
		EventType:     "bench.synthetic",
		Source:        "bench-test",
	})
	if err != nil {
		t.Fatalf("runBenchIngest() error = %v", err)
	}
	if result.ImmediateQuerySamples.Failed != 1 || result.ImmediateQuerySamples.Ready != 0 {
		t.Fatalf("immediate query samples = %+v", result.ImmediateQuerySamples)
	}
	if result.ProofSamples.Ready != 1 || result.PostProofQuerySamples.Ready != 1 || result.PostProofQuerySamples.Failed != 0 {
		t.Fatalf("proof/post-proof samples = %+v %+v", result.ProofSamples, result.PostProofQuerySamples)
	}
	if result.QuerySamples.Failed != result.ImmediateQuerySamples.Failed {
		t.Fatalf("legacy query samples should alias immediate query: %+v vs %+v", result.QuerySamples, result.ImmediateQuerySamples)
	}
	if len(result.ErrorSamples) == 0 || !strings.Contains(result.ErrorSamples[0], "immediate query") {
		t.Fatalf("error samples = %+v", result.ErrorSamples)
	}
}

func TestRunBenchIngestSeparatesDisabledProofLevel(t *testing.T) {
	t.Parallel()

	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	client, err := sdk.NewClientWithTransport(&fakeBenchTransport{})
	if err != nil {
		t.Fatalf("NewClientWithTransport() error = %v", err)
	}

	result, err := runBenchIngest(context.Background(), &runtimeConfig{logger: silentLogger()}, client, benchIngestConfig{
		Endpoint:      "bench://fake",
		Transport:     "http",
		Identity:      sdk.Identity{TenantID: "tenant-bench", ClientID: "client-bench", KeyID: "key-bench", PrivateKey: priv},
		Count:         1,
		Concurrency:   1,
		PayloadBytes:  128,
		ProgressEvery: 0,
		Samples:       1,
		ProofLevel:    sdk.ProofLevelL4,
		MaxProofLevel: sdk.ProofLevelL3,
		ProofTimeout:  10 * time.Millisecond,
		Settle:        0,
		EventType:     "bench.synthetic",
		Source:        "bench-test",
	})
	if err != nil {
		t.Fatalf("runBenchIngest() error = %v", err)
	}
	if result.ProofSamples.Disabled != 1 || result.ProofSamples.Ready != 0 || result.ProofSamples.Timeouts != 0 {
		t.Fatalf("proof samples = %+v", result.ProofSamples)
	}
	if result.PostProofQuerySamples.Samples != 0 {
		t.Fatalf("post-proof query samples = %+v", result.PostProofQuerySamples)
	}
}

func TestWriteBenchIngestText(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	writeBenchIngestText(&out, benchIngestResult{
		Endpoint:         "http://127.0.0.1:8080",
		Transport:        "http",
		Count:            10,
		Concurrency:      2,
		PayloadBytes:     256,
		Submitted:        10,
		ThroughputPerSec: 100.5,
		SubmitLatency: benchLatencySummary{
			AvgMs: 10,
			MinMs: 1,
			P50Ms: 8,
			P95Ms: 20,
			P99Ms: 25,
			MaxMs: 30,
		},
		QuerySamples: benchQuerySummary{
			Samples: 2,
			Ready:   2,
			Latency: benchLatencySummary{AvgMs: 5, P95Ms: 9},
		},
		ImmediateQuerySamples: benchQuerySummary{
			Samples: 2,
			Ready:   2,
			Latency: benchLatencySummary{AvgMs: 5, P95Ms: 9},
		},
		PostProofQuerySamples: benchQuerySummary{
			Samples: 2,
			Ready:   2,
			Latency: benchLatencySummary{AvgMs: 6, P95Ms: 10},
		},
		ProofSamples: benchProofSummary{
			Samples:     2,
			TargetLevel: sdk.ProofLevelL4,
			Ready:       2,
			Latency:     benchLatencySummary{AvgMs: 40, P95Ms: 50},
		},
		Metrics: []benchMetricDelta{{Name: `trustdb_ingest_requests_total{result="accepted"}`, Delta: 10, After: 10}},
	})
	text := out.String()
	for _, want := range []string{
		"endpoint: http://127.0.0.1:8080",
		"throughput_per_sec: 100.50",
		"immediate_query_samples: total=2 ready=2 failed=0",
		"post_proof_query_samples: total=2 ready=2 failed=0",
		"proof_samples: total=2 target=L4 ready=2",
		`trustdb_ingest_requests_total{result="accepted"} delta=10.000000 after=10.000000`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("writeBenchIngestText() missing %q in %q", want, text)
		}
	}
}

type fakeBenchTransport struct {
	mu           sync.Mutex
	submits      int
	metricsCalls int
}

type fakeBenchVisibilityTransport struct {
	fakeBenchTransport
	recordMu    sync.Mutex
	recordCalls map[string]int
}

func (f *fakeBenchVisibilityTransport) GetRecord(_ context.Context, recordID string) (sdk.RecordIndex, error) {
	f.recordMu.Lock()
	defer f.recordMu.Unlock()
	if f.recordCalls == nil {
		f.recordCalls = make(map[string]int)
	}
	f.recordCalls[recordID]++
	if f.recordCalls[recordID] == 1 {
		return model.RecordIndex{}, &sdk.Error{StatusCode: 404, Code: "NOT_FOUND", Message: "record not visible yet"}
	}
	return model.RecordIndex{RecordID: recordID, BatchID: "batch-bench-1"}, nil
}

func (f *fakeBenchTransport) Endpoint() string { return "bench://fake" }

func (f *fakeBenchTransport) CheckHealth(context.Context) sdk.HealthStatus {
	return sdk.HealthStatus{OK: true, ServerURL: f.Endpoint()}
}

func (f *fakeBenchTransport) SubmitSignedClaim(_ context.Context, signed sdk.SignedClaim) (sdk.SubmitResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submits++
	recordID := fmt.Sprintf("tr-bench-%03d", f.submits)
	return sdk.SubmitResult{
		RecordID:      recordID,
		Status:        "accepted",
		ProofLevel:    sdk.ProofLevelL2,
		BatchEnqueued: true,
		ServerRecord: model.ServerRecord{
			RecordID: recordID,
		},
	}, nil
}

func (f *fakeBenchTransport) GetRecord(_ context.Context, recordID string) (sdk.RecordIndex, error) {
	return model.RecordIndex{RecordID: recordID, BatchID: "batch-bench-1"}, nil
}

func (f *fakeBenchTransport) ListRecords(context.Context, sdk.ListRecordsOptions) (sdk.RecordPage, error) {
	return sdk.RecordPage{}, nil
}

func (f *fakeBenchTransport) ListRootsPage(context.Context, sdk.ListPageOptions) (sdk.RootPage, error) {
	return sdk.RootPage{}, nil
}

func (f *fakeBenchTransport) GetProofBundle(_ context.Context, recordID string) (sdk.ProofBundle, error) {
	return model.ProofBundle{
		SchemaVersion: model.SchemaProofBundle,
		RecordID:      recordID,
		CommittedReceipt: model.CommittedReceipt{
			BatchID: "batch-bench-1",
		},
	}, nil
}

func (f *fakeBenchTransport) ListRoots(context.Context, int) ([]sdk.BatchRoot, error) {
	return nil, nil
}

func (f *fakeBenchTransport) LatestRoot(context.Context) (sdk.BatchRoot, error) {
	return model.BatchRoot{}, nil
}

func (f *fakeBenchTransport) ListSTHs(context.Context, sdk.ListPageOptions) (sdk.TreeHeadPage, error) {
	return sdk.TreeHeadPage{}, nil
}

func (f *fakeBenchTransport) GetGlobalProof(_ context.Context, batchID string) (sdk.GlobalLogProof, error) {
	return model.GlobalLogProof{}, &sdk.Error{StatusCode: 404, Code: "NOT_FOUND", Message: "global proof not found"}
}

func (f *fakeBenchTransport) GetGlobalEvidence(_ context.Context, batchID string) (sdk.GlobalLogEvidence, error) {
	return model.GlobalLogEvidence{}, &sdk.Error{StatusCode: 404, Code: "NOT_FOUND", Message: "global evidence not found"}
}

func (f *fakeBenchTransport) ListGlobalLeaves(context.Context, sdk.ListPageOptions) (sdk.GlobalLeafPage, error) {
	return sdk.GlobalLeafPage{}, nil
}

func (f *fakeBenchTransport) ListAnchors(context.Context, sdk.ListPageOptions) (sdk.AnchorPage, error) {
	return sdk.AnchorPage{}, nil
}

func (f *fakeBenchTransport) GetAnchor(context.Context, uint64) (sdk.AnchorStatus, error) {
	return sdk.AnchorStatus{}, &sdk.Error{StatusCode: 404, Code: "NOT_FOUND", Message: "anchor not found"}
}

func (f *fakeBenchTransport) LatestSTH(context.Context) (sdk.SignedTreeHead, error) {
	return model.SignedTreeHead{}, nil
}

func (f *fakeBenchTransport) GetSTH(context.Context, uint64) (sdk.SignedTreeHead, error) {
	return model.SignedTreeHead{}, nil
}

func (f *fakeBenchTransport) MetricsRaw(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.metricsCalls++
	if f.metricsCalls == 1 {
		return `
# TYPE trustdb_ingest_requests_total counter
trustdb_ingest_requests_total{result="accepted"} 0
# TYPE trustdb_queue_depth gauge
trustdb_queue_depth{queue="ingest"} 0
`, nil
	}
	return `
# TYPE trustdb_ingest_requests_total counter
trustdb_ingest_requests_total{result="accepted"} 4
# TYPE trustdb_queue_depth gauge
trustdb_queue_depth{queue="ingest"} 0
`, nil
}

func (f *fakeBenchTransport) Close() error { return nil }

func TestBenchIngestCommandHelp(t *testing.T) {
	t.Parallel()

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"bench", "ingest", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("help execute error = %v", err)
	}
	if !strings.Contains(out.String(), "Generate synthetic claims") {
		t.Fatalf("help output missing bench ingest description: %q", out.String())
	}
}

func TestBenchNonce(t *testing.T) {
	t.Parallel()

	a := benchNonce(1)
	b := benchNonce(2)
	if len(a) != 16 || len(b) != 16 {
		t.Fatalf("nonce sizes = %d %d", len(a), len(b))
	}
	if bytes.Equal(a, b) {
		t.Fatalf("nonces should differ")
	}
}

func TestBenchMetricWantedIncludesPipelineMetrics(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"trustdb_materializer_in_flight",
		"trustdb_materialized_records_total",
		"trustdb_batch_tree_tiles_count",
		"trustdb_global_log_batch_latency_seconds_sum",
		"trustdb_anchor_in_flight",
	} {
		if !benchMetricWanted(name) {
			t.Fatalf("benchMetricWanted(%q) = false", name)
		}
	}
}

func TestBenchClientUsesSuppliedPrivateKey(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	identity := sdk.Identity{TenantID: "tenant", ClientID: "client", KeyID: "key", PrivateKey: priv}
	client, err := sdk.NewClientWithTransport(&fakeBenchTransport{})
	if err != nil {
		t.Fatalf("NewClientWithTransport() error = %v", err)
	}
	_, err = client.SubmitFile(context.Background(), bytes.NewReader([]byte("payload")), identity, sdk.FileClaimOptions{
		ProducedAt:     time.Now(),
		Nonce:          benchNonce(1),
		IdempotencyKey: "bench-test",
		MediaType:      "application/octet-stream",
		StorageURI:     "bench://test",
		EventType:      "bench.synthetic",
		Source:         "bench-test",
	})
	if err != nil {
		t.Fatalf("SubmitFile() error = %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key length = %d", len(pub))
	}
}
