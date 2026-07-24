package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	IngestRequests        *prometheus.CounterVec
	IngestRejected        *prometheus.CounterVec
	WALAppendLatency      *prometheus.HistogramVec
	WALFsyncLatency       *prometheus.HistogramVec
	QueueDepth            *prometheus.GaugeVec
	BatchSizeRecords      prometheus.Histogram
	BatchCommitLatency    prometheus.Histogram
	BatchStageLatency     *prometheus.HistogramVec
	MerkleBuildLatency    prometheus.Histogram
	SemanticProfile       *prometheus.GaugeVec
	MaterializerInFlight  prometheus.Gauge
	MaterializerPrepared  prometheus.Gauge
	MaterializerOldestAge prometheus.Gauge
	MaterializerRetries   prometheus.Counter
	MaterializedRecords   prometheus.Counter
	BatchTreeTiles        prometheus.Histogram
	GlobalLogBatchSize    prometheus.Histogram
	GlobalLogBatchLatency prometheus.Histogram
	GlobalLogPublished    prometheus.Counter
	AnchorPending         prometheus.Gauge
	AnchorInFlight        prometheus.Gauge
	AnchorLatency         prometheus.Histogram
	// AnchorAttempts counts every Sink.Publish call the worker has
	// issued, broken down by sink and outcome (success | transient |
	// permanent). A sudden rise in transient spikes points at sink
	// instability; permanent spikes point at schema/bug issues.
	AnchorAttempts *prometheus.CounterVec
	// AnchorPublished counts only successful Publish calls. It is a
	// convenience counter for rate alerting and is redundant with
	// AnchorAttempts{outcome="success"} but cheaper to query.
	AnchorPublished *prometheus.CounterVec
	// OtsUpgradeRuns counts every upgrader sweep (one per tick).
	// Used to confirm the worker is alive and to compare against
	// the configured interval.
	OtsUpgradeRuns prometheus.Counter
	// OtsUpgradeBatches counts the proof envelopes the upgrader
	// touched per outcome: "changed" (at least one calendar
	// upgraded), "unchanged" (every calendar still pending),
	// "skipped" (already AllUpgraded, nothing to do), "error"
	// (envelope decode / network / store error). The {outcome}
	// label keeps the number of timeseries bounded.
	OtsUpgradeBatches *prometheus.CounterVec
	// OtsUpgradeCalendarHits counts the per-calendar upgrade
	// outcomes across every batch: "changed" / "unchanged" /
	// "error". Lets operators alert when one calendar is silently
	// failing while others succeed.
	OtsUpgradeCalendarHits *prometheus.CounterVec
	// OtsPendingBatches reports the current number of OTS-anchored
	// batches whose proof still has at least one pending calendar.
	// Should drift toward zero as time passes; a stuck non-zero
	// value means the upgrader cannot reach calendars.
	OtsPendingBatches prometheus.Gauge
	// WALCheckpointLastSequence is the highest contiguous WAL sequence for
	// which every earlier record is covered by a committed batch. Alerting on
	// a stalled value flags a batcher that is no longer closing the next gap.
	WALCheckpointLastSequence prometheus.Gauge
	// WALCheckpointCoverageDropped counts far-future committed coverage islands
	// discarded from the bounded in-memory frontier tracker. A non-zero rate
	// means a long-lived gap is forcing startup replay to rebuild distant runs.
	WALCheckpointCoverageDropped prometheus.Counter
	// WALCheckpointFailures counts checkpoint load, merge, and persistence
	// failures. Unlike the service's latest-error snapshot, this counter cannot
	// be erased by a later successful batch and is therefore safe for alerting.
	WALCheckpointFailures prometheus.Counter
	// WALReplayRecords reports what happened to each WAL record during the
	// last startup replay, broken down by outcome (recovered = prepared
	// manifest finalized; replayed = re-enqueued into batcher; skipped =
	// short-circuited because checkpoint or committed manifest covers it).
	WALReplayRecords *prometheus.CounterVec
	// WALActiveSegmentID is the id of the segment the writer is currently
	// appending to. Only populated in directory-mode WAL; stays at 1 for
	// single-file deployments.
	WALActiveSegmentID prometheus.Gauge
	// WALSegmentsTotal counts the segment files currently on disk for
	// the active WAL directory. Combined with WALActiveSegmentID it tells
	// an operator how many retained (pruned-but-still-listed or
	// checkpoint-covered) segments exist.
	WALSegmentsTotal prometheus.Gauge
	// WALBytesPrunedTotal is the cumulative bytes reclaimed by
	// PruneSegmentsBefore since the process started. A stagnant counter
	// after commits keep happening suggests the prune hook is not wired
	// up or the keep-segments window is too generous.
	WALBytesPrunedTotal prometheus.Counter
	// NATSIngressInFlight reports deliveries currently executing the worker
	// state machine. It excludes messages still waiting in JetStream.
	NATSIngressInFlight prometheus.Gauge
	// NATSIngressDeliveries counts successful broker actions using the bounded
	// action labels ack, nak, term_result, and term_rejection.
	NATSIngressDeliveries *prometheus.CounterVec
	// NATSIngressOutcomeStoreRetries counts failed durable outcome writes before
	// the worker retries without acknowledging the original delivery.
	NATSIngressOutcomeStoreRetries *prometheus.CounterVec
	// NATSIngressErrors counts worker errors using bounded lifecycle stages.
	NATSIngressErrors *prometheus.CounterVec
}

func NewRegistry() (*prometheus.Registry, *Metrics) {
	reg := prometheus.NewRegistry()
	metrics := NewMetrics()
	reg.MustRegister(metrics.Collectors()...)
	reg.MustRegister(collectors.NewGoCollector())
	return reg, metrics
}

func NewMetrics() *Metrics {
	return &Metrics{
		IngestRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trustdb_ingest_requests_total",
			Help: "Total ingest requests by result.",
		}, []string{"result"}),
		IngestRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trustdb_ingest_rejected_total",
			Help: "Total rejected ingest requests by reason.",
		}, []string{"reason"}),
		WALAppendLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "trustdb_wal_append_latency_seconds",
			Help:    "WAL append latency in seconds.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 16),
		}, []string{"durability"}),
		WALFsyncLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "trustdb_wal_fsync_latency_seconds",
			Help:    "WAL fsync latency in seconds.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 16),
		}, []string{"durability"}),
		QueueDepth: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "trustdb_queue_depth",
			Help: "Current queue depth by queue name.",
		}, []string{"queue"}),
		BatchSizeRecords: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "trustdb_batch_size_records",
			Help:    "Committed batch size in records.",
			Buckets: []float64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096},
		}),
		BatchCommitLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "trustdb_batch_commit_latency_seconds",
			Help:    "Batch commit latency in seconds.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 16),
		}),
		BatchStageLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "trustdb_batch_stage_latency_seconds",
			Help:    "Batch worker stage latency in seconds.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 18),
		}, []string{"stage"}),
		MerkleBuildLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "trustdb_merkle_build_latency_seconds",
			Help:    "Merkle tree build latency in seconds.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 16),
		}),
		SemanticProfile: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "trustdb_semantic_profile_info",
			Help: "Active semantic and durability performance profile labels for this process.",
		}, []string{"semantic_profile", "durability_profile", "proof_mode", "record_index_mode", "artifact_sync_mode", "global_log"}),
		MaterializerInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trustdb_materializer_in_flight",
			Help: "Current number of proof materialization jobs being processed.",
		}),
		MaterializerPrepared: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trustdb_materializer_prepared_backlog",
			Help: "Current number of due prepared manifests observed by the scanner.",
		}),
		MaterializerOldestAge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trustdb_materializer_oldest_prepared_age_seconds",
			Help: "Age in seconds of the oldest due prepared manifest.",
		}),
		MaterializerRetries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "trustdb_materializer_retries_total",
			Help: "Total materialization attempts scheduled for retry.",
		}),
		MaterializedRecords: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "trustdb_materialized_records_total",
			Help: "Total records whose L3 proof bundles were materialized.",
		}),
		BatchTreeTiles: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "trustdb_batch_tree_tiles",
			Help:    "Number of physical tree tiles written per batch.",
			Buckets: []float64{1, 2, 4, 8, 16, 24, 32, 40, 64, 128},
		}),
		GlobalLogBatchSize: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "trustdb_global_log_batch_size",
			Help:    "Number of roots processed in one global-log outbox batch.",
			Buckets: []float64{1, 2, 4, 8, 16, 32, 64, 128},
		}),
		GlobalLogBatchLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "trustdb_global_log_batch_latency_seconds",
			Help:    "Latency of one global-log outbox batch.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 16),
		}),
		GlobalLogPublished: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "trustdb_global_log_published_roots_total",
			Help: "Total batch roots whose L4 indexes and global-log outbox state are fully published.",
		}),
		AnchorPending: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trustdb_anchor_pending_total",
			Help: "Current pending anchor coalescing windows.",
		}),
		AnchorInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trustdb_anchor_in_flight",
			Help: "Current number of anchor publish calls in flight.",
		}),
		AnchorLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "trustdb_anchor_latency_seconds",
			Help:    "Anchor publish latency in seconds.",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 12),
		}),
		AnchorAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trustdb_anchor_attempts_total",
			Help: "Anchor publish attempts by sink and outcome.",
		}, []string{"sink", "outcome"}),
		AnchorPublished: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trustdb_anchor_published_total",
			Help: "Anchor publish successes by sink.",
		}, []string{"sink"}),
		OtsUpgradeRuns: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "trustdb_anchor_ots_upgrade_runs_total",
			Help: "Number of OTS upgrader sweeps that have run.",
		}),
		OtsUpgradeBatches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trustdb_anchor_ots_upgrade_batches_total",
			Help: "OTS batches touched by the upgrader, by per-batch outcome.",
		}, []string{"outcome"}),
		OtsUpgradeCalendarHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trustdb_anchor_ots_upgrade_calendar_hits_total",
			Help: "Per-calendar OTS upgrade outcomes across every batch.",
		}, []string{"outcome"}),
		OtsPendingBatches: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trustdb_anchor_ots_pending_batches",
			Help: "OTS-anchored batches whose proof still has at least one pending calendar.",
		}),
		WALCheckpointLastSequence: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trustdb_wal_checkpoint_last_sequence",
			Help: "Highest WAL sequence that a committed batch has advanced the checkpoint to.",
		}),
		WALCheckpointCoverageDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "trustdb_wal_checkpoint_coverage_dropped_total",
			Help: "Far-future committed WAL coverage islands discarded from the bounded frontier tracker.",
		}),
		WALCheckpointFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "trustdb_wal_checkpoint_failures_total",
			Help: "WAL checkpoint load, merge, and persistence failures.",
		}),
		WALReplayRecords: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trustdb_wal_replay_records_total",
			Help: "WAL records handled during startup replay, broken down by outcome.",
		}, []string{"result"}),
		WALActiveSegmentID: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trustdb_wal_active_segment_id",
			Help: "Id of the WAL segment the writer is currently appending to.",
		}),
		WALSegmentsTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trustdb_wal_segments_total",
			Help: "Number of WAL segment files currently present on disk.",
		}),
		WALBytesPrunedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "trustdb_wal_bytes_pruned_total",
			Help: "Cumulative bytes reclaimed from pruned WAL segments since process start.",
		}),
		NATSIngressInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trustdb_nats_ingress_in_flight",
			Help: "Current NATS ingress deliveries executing the worker state machine.",
		}),
		NATSIngressDeliveries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trustdb_nats_ingress_deliveries_total",
			Help: "NATS ingress deliveries by successful broker action.",
		}, []string{"action"}),
		NATSIngressOutcomeStoreRetries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trustdb_nats_ingress_outcome_store_retries_total",
			Help: "NATS ingress durable outcome store retries by outcome kind.",
		}, []string{"kind"}),
		NATSIngressErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trustdb_nats_ingress_errors_total",
			Help: "NATS ingress worker errors by bounded lifecycle stage.",
		}, []string{"stage"}),
	}
}

func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.IngestRequests,
		m.IngestRejected,
		m.WALAppendLatency,
		m.WALFsyncLatency,
		m.QueueDepth,
		m.BatchSizeRecords,
		m.BatchCommitLatency,
		m.BatchStageLatency,
		m.MerkleBuildLatency,
		m.SemanticProfile,
		m.MaterializerInFlight,
		m.MaterializerPrepared,
		m.MaterializerOldestAge,
		m.MaterializerRetries,
		m.MaterializedRecords,
		m.BatchTreeTiles,
		m.GlobalLogBatchSize,
		m.GlobalLogBatchLatency,
		m.GlobalLogPublished,
		m.AnchorPending,
		m.AnchorInFlight,
		m.AnchorLatency,
		m.AnchorAttempts,
		m.AnchorPublished,
		m.OtsUpgradeRuns,
		m.OtsUpgradeBatches,
		m.OtsUpgradeCalendarHits,
		m.OtsPendingBatches,
		m.WALCheckpointLastSequence,
		m.WALCheckpointCoverageDropped,
		m.WALCheckpointFailures,
		m.WALReplayRecords,
		m.WALActiveSegmentID,
		m.WALSegmentsTotal,
		m.WALBytesPrunedTotal,
		m.NATSIngressInFlight,
		m.NATSIngressDeliveries,
		m.NATSIngressOutcomeStoreRetries,
		m.NATSIngressErrors,
	}
}

func Handler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
