package observability

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pdb "github.com/cockroachdb/pebble"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsRegisterAndExpose(t *testing.T) {
	t.Parallel()

	reg, metrics := NewRegistry()
	metrics.IngestRequests.WithLabelValues("accepted").Inc()
	metrics.IngestRejected.WithLabelValues("RESOURCE_EXHAUSTED").Add(2)
	metrics.QueueDepth.WithLabelValues("ingest").Set(7)
	metrics.GlobalLogPublished.Add(3)

	expected := `
# HELP trustdb_ingest_rejected_total Total rejected ingest requests by reason.
# TYPE trustdb_ingest_rejected_total counter
trustdb_ingest_rejected_total{reason="RESOURCE_EXHAUSTED"} 2
# HELP trustdb_ingest_requests_total Total ingest requests by result.
# TYPE trustdb_ingest_requests_total counter
trustdb_ingest_requests_total{result="accepted"} 1
# HELP trustdb_queue_depth Current queue depth by queue name.
# TYPE trustdb_queue_depth gauge
trustdb_queue_depth{queue="ingest"} 7
# HELP trustdb_global_log_published_roots_total Total batch roots whose L4 indexes and global-log outbox state are fully published.
# TYPE trustdb_global_log_published_roots_total counter
trustdb_global_log_published_roots_total 3
`
	if err := testutil.GatherAndCompare(
		reg,
		strings.NewReader(expected),
		"trustdb_ingest_requests_total",
		"trustdb_ingest_rejected_total",
		"trustdb_queue_depth",
		"trustdb_global_log_published_roots_total",
	); err != nil {
		t.Fatalf("GatherAndCompare() error = %v", err)
	}

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	Handler(reg).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("metrics handler status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "trustdb_ingest_requests_total") {
		t.Fatalf("metrics handler body missing trustdb metric")
	}
}

func TestWALCheckpointAndReplayMetrics(t *testing.T) {
	t.Parallel()

	reg, metrics := NewRegistry()
	metrics.WALCheckpointLastSequence.Set(42)
	metrics.WALCheckpointCoverageDropped.Add(2)
	metrics.WALCheckpointFailures.Inc()
	metrics.WALReplayRecords.WithLabelValues("skipped").Add(5)
	metrics.WALReplayRecords.WithLabelValues("replayed").Add(2)
	metrics.WALReplayRecords.WithLabelValues("recovered").Add(1)

	expected := `
# HELP trustdb_wal_checkpoint_last_sequence Highest WAL sequence that a committed batch has advanced the checkpoint to.
# TYPE trustdb_wal_checkpoint_last_sequence gauge
trustdb_wal_checkpoint_last_sequence 42
# HELP trustdb_wal_checkpoint_coverage_dropped_total Far-future committed WAL coverage islands discarded from the bounded frontier tracker.
# TYPE trustdb_wal_checkpoint_coverage_dropped_total counter
trustdb_wal_checkpoint_coverage_dropped_total 2
# HELP trustdb_wal_checkpoint_failures_total WAL checkpoint load, merge, and persistence failures.
# TYPE trustdb_wal_checkpoint_failures_total counter
trustdb_wal_checkpoint_failures_total 1
# HELP trustdb_wal_replay_records_total WAL records handled during startup replay, broken down by outcome.
# TYPE trustdb_wal_replay_records_total counter
trustdb_wal_replay_records_total{result="recovered"} 1
trustdb_wal_replay_records_total{result="replayed"} 2
trustdb_wal_replay_records_total{result="skipped"} 5
`
	if err := testutil.GatherAndCompare(
		reg,
		strings.NewReader(expected),
		"trustdb_wal_checkpoint_last_sequence",
		"trustdb_wal_checkpoint_coverage_dropped_total",
		"trustdb_wal_checkpoint_failures_total",
		"trustdb_wal_replay_records_total",
	); err != nil {
		t.Fatalf("GatherAndCompare() error = %v", err)
	}
}

// TestWALSegmentMetrics exercises the segment-rotation metric family. The
// gauges are set directly (they are pushed by serve on rotation/prune) while
// the counter is accumulated as prune removes bytes. We assert registration,
// help text, and a small value matrix to pin down the exposition format.
func TestWALSegmentMetrics(t *testing.T) {
	t.Parallel()

	reg, metrics := NewRegistry()
	metrics.WALActiveSegmentID.Set(7)
	metrics.WALSegmentsTotal.Set(4)
	metrics.WALBytesPrunedTotal.Add(1024)
	metrics.WALBytesPrunedTotal.Add(2048)

	expected := `
# HELP trustdb_wal_active_segment_id Id of the WAL segment the writer is currently appending to.
# TYPE trustdb_wal_active_segment_id gauge
trustdb_wal_active_segment_id 7
# HELP trustdb_wal_bytes_pruned_total Cumulative bytes reclaimed from pruned WAL segments since process start.
# TYPE trustdb_wal_bytes_pruned_total counter
trustdb_wal_bytes_pruned_total 3072
# HELP trustdb_wal_segments_total Number of WAL segment files currently present on disk.
# TYPE trustdb_wal_segments_total gauge
trustdb_wal_segments_total 4
`
	if err := testutil.GatherAndCompare(
		reg,
		strings.NewReader(expected),
		"trustdb_wal_active_segment_id",
		"trustdb_wal_segments_total",
		"trustdb_wal_bytes_pruned_total",
	); err != nil {
		t.Fatalf("GatherAndCompare() error = %v", err)
	}
}

func TestRegisterPebbleMetrics(t *testing.T) {
	t.Parallel()

	metrics := &pdb.Metrics{
		Compact: struct {
			Count             int64
			DefaultCount      int64
			DeleteOnlyCount   int64
			ElisionOnlyCount  int64
			MoveCount         int64
			ReadCount         int64
			RewriteCount      int64
			MultiLevelCount   int64
			CounterLevelCount int64
			EstimatedDebt     uint64
			InProgressBytes   int64
			NumInProgress     int64
			MarkedFiles       int
			Duration          time.Duration
		}{
			Count:           3,
			EstimatedDebt:   4096,
			InProgressBytes: 2048,
			NumInProgress:   1,
			Duration:        2 * time.Second,
		},
		Ingest: struct {
			Count uint64
		}{Count: 5},
		Flush: struct {
			Count              int64
			WriteThroughput    pdb.ThroughputMetric
			NumInProgress      int64
			AsIngestCount      uint64
			AsIngestTableCount uint64
			AsIngestBytes      uint64
		}{
			Count:         7,
			NumInProgress: 1,
		},
		MemTable: struct {
			Size        uint64
			Count       int64
			ZombieSize  uint64
			ZombieCount int64
		}{
			Size:       1024,
			Count:      2,
			ZombieSize: 128,
		},
		Snapshots: struct {
			Count          int
			EarliestSeqNum uint64
			PinnedKeys     uint64
			PinnedSize     uint64
		}{
			Count: 1,
		},
		Table: struct {
			ObsoleteSize      uint64
			ObsoleteCount     int64
			ZombieSize        uint64
			ZombieCount       int64
			BackingTableCount uint64
			BackingTableSize  uint64
		}{
			ObsoleteSize:      64,
			ZombieSize:        32,
			BackingTableCount: 4,
			BackingTableSize:  8192,
		},
		WAL: struct {
			Files                int64
			ObsoleteFiles        int64
			ObsoletePhysicalSize uint64
			Size                 uint64
			PhysicalSize         uint64
			BytesIn              uint64
			BytesWritten         uint64
		}{
			Files:                2,
			ObsoleteFiles:        1,
			ObsoletePhysicalSize: 16,
			Size:                 512,
			PhysicalSize:         768,
			BytesIn:              100,
			BytesWritten:         120,
		},
	}
	metrics.Levels[0].NumFiles = 1
	metrics.Levels[0].Size = 2048
	metrics.Levels[0].Score = 1.5
	metrics.Levels[0].Sublevels = 6

	reg, _ := NewRegistry()
	enabled, err := RegisterPebbleMetrics(reg, fakePebbleMetricsSource{metrics: metrics})
	if err != nil {
		t.Fatalf("RegisterPebbleMetrics() error = %v", err)
	}
	if !enabled {
		t.Fatalf("RegisterPebbleMetrics() enabled = false, want true")
	}

	expected := `
# HELP trustdb_pebble_backing_table_size_bytes Total bytes of Pebble backing SSTables.
# TYPE trustdb_pebble_backing_table_size_bytes gauge
trustdb_pebble_backing_table_size_bytes 8192
# HELP trustdb_pebble_compaction_debt_bytes Estimated Pebble compaction debt in bytes.
# TYPE trustdb_pebble_compaction_debt_bytes gauge
trustdb_pebble_compaction_debt_bytes 4096
# HELP trustdb_pebble_compaction_duration_seconds_total Cumulative duration of Pebble compactions since the database was opened.
# TYPE trustdb_pebble_compaction_duration_seconds_total counter
trustdb_pebble_compaction_duration_seconds_total 2
# HELP trustdb_pebble_compactions_total Total number of Pebble compactions since the database was opened.
# TYPE trustdb_pebble_compactions_total counter
trustdb_pebble_compactions_total 3
# HELP trustdb_pebble_disk_space_usage_bytes Approximate on-disk space used by the Pebble database.
# TYPE trustdb_pebble_disk_space_usage_bytes gauge
trustdb_pebble_disk_space_usage_bytes 4976
# HELP trustdb_pebble_flushes_total Total number of Pebble flushes since the database was opened.
# TYPE trustdb_pebble_flushes_total counter
trustdb_pebble_flushes_total 7
# HELP trustdb_pebble_ingestions_total Total number of Pebble ingestions since the database was opened.
# TYPE trustdb_pebble_ingestions_total counter
trustdb_pebble_ingestions_total 5
# HELP trustdb_pebble_level_files Current number of files in each Pebble LSM level.
# TYPE trustdb_pebble_level_files gauge
trustdb_pebble_level_files{level="L0"} 1
# HELP trustdb_pebble_level_size_bytes Current bytes stored in each Pebble LSM level.
# TYPE trustdb_pebble_level_size_bytes gauge
trustdb_pebble_level_size_bytes{level="L0"} 2048
# HELP trustdb_pebble_read_amplification Approximate Pebble read amplification across the LSM tree.
# TYPE trustdb_pebble_read_amplification gauge
trustdb_pebble_read_amplification 6
# HELP trustdb_pebble_wal_bytes_written_total Physical bytes written to the Pebble WAL since the database was opened.
# TYPE trustdb_pebble_wal_bytes_written_total counter
trustdb_pebble_wal_bytes_written_total 120
`
	src := reg
	if err := testutil.GatherAndCompare(
		src,
		strings.NewReader(expected),
		"trustdb_pebble_backing_table_size_bytes",
		"trustdb_pebble_compaction_debt_bytes",
		"trustdb_pebble_compaction_duration_seconds_total",
		"trustdb_pebble_compactions_total",
		"trustdb_pebble_disk_space_usage_bytes",
		"trustdb_pebble_flushes_total",
		"trustdb_pebble_ingestions_total",
		"trustdb_pebble_level_files",
		"trustdb_pebble_level_size_bytes",
		"trustdb_pebble_read_amplification",
		"trustdb_pebble_wal_bytes_written_total",
	); err != nil {
		t.Fatalf("GatherAndCompare() error = %v", err)
	}
}

func TestRegisterPebbleMetricsSkipsNonPebbleStore(t *testing.T) {
	t.Parallel()

	reg, _ := NewRegistry()
	enabled, err := RegisterPebbleMetrics(reg, struct{}{})
	if err != nil {
		t.Fatalf("RegisterPebbleMetrics() error = %v", err)
	}
	if enabled {
		t.Fatalf("RegisterPebbleMetrics() enabled = true, want false")
	}
}

func TestPebbleUintGaugeClampsCounterUnderflow(t *testing.T) {
	t.Parallel()

	if got := pebbleUintGauge(^uint64(0) - 4095); got != 0 {
		t.Fatalf("pebbleUintGauge(underflow) = %v, want 0", got)
	}
	if got := pebbleUintGauge(4096); got != 4096 {
		t.Fatalf("pebbleUintGauge(4096) = %v, want 4096", got)
	}
}

type fakePebbleMetricsSource struct {
	metrics *pdb.Metrics
}

func (f fakePebbleMetricsSource) PebbleMetrics() *pdb.Metrics {
	return f.metrics
}
