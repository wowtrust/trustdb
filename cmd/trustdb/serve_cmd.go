package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/adminweb"
	"github.com/wowtrust/trustdb/internal/anchor"
	"github.com/wowtrust/trustdb/internal/app"
	"github.com/wowtrust/trustdb/internal/batch"
	"github.com/wowtrust/trustdb/internal/claim"
	trustconfig "github.com/wowtrust/trustdb/internal/config"
	"github.com/wowtrust/trustdb/internal/globallog"
	"github.com/wowtrust/trustdb/internal/grpcapi"
	"github.com/wowtrust/trustdb/internal/httpapi"
	"github.com/wowtrust/trustdb/internal/idempotency"
	"github.com/wowtrust/trustdb/internal/ingest"
	"github.com/wowtrust/trustdb/internal/l5projector"
	"github.com/wowtrust/trustdb/internal/merkle"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/submission"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"github.com/wowtrust/trustdb/internal/wal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func newServeCommand(rt *runtimeConfig) *cobra.Command {
	var listen, grpcListen, serverKeyPath, walPath, proofDir, clientPubPath, registryPath, registryPubPath string
	var queueSize, workers, batchQueueSize, batchMaxRecords int
	var batchMaterializerWorkers, batchMaterializerQueueSize, batchProofWorkers int
	var walMaxSegmentBytes int64
	var walKeepSegments int
	var walFsyncMode string
	var readTimeoutText, readHeaderTimeoutText, writeTimeoutText, idleTimeoutText, shutdownTimeoutText, batchMaxDelayText, batchMaterializerPollText string
	var walGroupCommitIntervalText string
	var metastoreKind, metastorePath string
	var proofstoreTiKVPDText, proofstoreTiKVKeyspace, proofstoreTiKVNamespace string
	var batchProofMode, proofstoreArtifactSyncMode, proofstoreRecordIndexMode string
	var proofstoreIndexStorageTokens bool
	var anchorSinkKind, anchorPath, anchorMaxDelayText, anchorPollIntervalText string
	var anchorPluginCommand, anchorPluginStartTimeoutText, anchorPluginRPCTimeoutText string
	var anchorPluginArgs []string
	var anchorOtsCalendars []string
	var anchorOtsMinAccepted int
	var anchorOtsTimeoutText string
	var anchorOtsUpgradeEnabled bool
	var anchorOtsUpgradeIntervalText string
	var anchorOtsUpgradeBatchSize int
	var anchorOtsUpgradeTimeoutText string
	var anchorOtsUpgradeWorkers int
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run a local TrustDB HTTP ingest server",
		RunE: func(cmd *cobra.Command, args []string) error {
			listen = stringOrConfig(cmd, rt, "listen", listen, "server.listen")
			grpcListen = stringOrConfig(cmd, rt, "grpc-listen", grpcListen, "server.grpc_listen")
			serverKeyPath = stringOrConfig(cmd, rt, "server-private-key", serverKeyPath, "keys.server_private")
			walPath = stringOrConfig(cmd, rt, "wal", walPath, "wal")
			proofDir = stringOrConfig(cmd, rt, "proof-dir", proofDir, "proof_dir")
			metastoreKind = stringOrConfig(cmd, rt, "metastore", metastoreKind, "metastore")
			metastorePath = stringOrConfig(cmd, rt, "metastore-path", metastorePath, "metastore_path")
			tikvPDAddresses := rt.cfg.Proofstore.TiKVPDAddresses
			if cmd.Flags().Changed("proofstore-tikv-pd-endpoints") {
				tikvPDAddresses = splitCSV(proofstoreTiKVPDText)
			}
			proofstoreTiKVKeyspace = stringOrLiteral(cmd, "proofstore-tikv-keyspace", proofstoreTiKVKeyspace, rt.cfg.Proofstore.TiKVKeyspace)
			proofstoreTiKVNamespace = stringOrLiteral(cmd, "proofstore-tikv-namespace", proofstoreTiKVNamespace, rt.cfg.Proofstore.TiKVNamespace)
			proofstoreRecordIndexMode = stringOrLiteral(cmd, "proofstore-record-index-mode", proofstoreRecordIndexMode, rt.cfg.Proofstore.RecordIndexMode)
			if cmd.Flags().Changed("proofstore-index-storage-tokens") {
				proofstoreIndexStorageTokens, _ = cmd.Flags().GetBool("proofstore-index-storage-tokens")
				if !proofstoreIndexStorageTokens {
					proofstoreRecordIndexMode = "no_storage_tokens"
				} else if strings.TrimSpace(proofstoreRecordIndexMode) == "" {
					proofstoreRecordIndexMode = "full"
				}
			}
			proofstoreArtifactSyncMode = stringOrLiteral(cmd, "proofstore-artifact-sync-mode", proofstoreArtifactSyncMode, rt.cfg.Proofstore.ArtifactSyncMode)
			anchorSinkKind = stringOrConfig(cmd, rt, "anchor-sink", anchorSinkKind, "anchor.sink")
			anchorPath = stringOrConfig(cmd, rt, "anchor-path", anchorPath, "anchor.path")
			anchorPluginCommand = stringOrLiteral(cmd, "anchor-plugin-command", anchorPluginCommand, rt.cfg.Anchor.Plugin.Command)
			if cmd.Flags().Changed("anchor-plugin-arg") {
				anchorPluginArgs, _ = cmd.Flags().GetStringArray("anchor-plugin-arg")
			} else {
				anchorPluginArgs = append([]string(nil), rt.cfg.Anchor.Plugin.Args...)
			}
			anchorPluginStartTimeoutText = stringOrLiteral(cmd, "anchor-plugin-start-timeout", anchorPluginStartTimeoutText, rt.cfg.Anchor.Plugin.StartTimeout)
			anchorPluginRPCTimeoutText = stringOrLiteral(cmd, "anchor-plugin-rpc-timeout", anchorPluginRPCTimeoutText, rt.cfg.Anchor.Plugin.RPCTimeout)
			// OTS sink options: calendars live as a list in viper
			// ("anchor.ots.calendars"), other scalars via the usual
			// stringOrConfig / intValue helpers so env override and
			// YAML config stay consistent with the rest of the flags.
			if cmd.Flags().Changed("anchor-ots-calendars") {
				anchorOtsCalendars, _ = cmd.Flags().GetStringSlice("anchor-ots-calendars")
			} else if vs := rt.viper.GetStringSlice("anchor.ots.calendars"); len(vs) > 0 {
				anchorOtsCalendars = vs
			}
			if cmd.Flags().Changed("anchor-ots-min-accepted") {
				anchorOtsMinAccepted, _ = cmd.Flags().GetInt("anchor-ots-min-accepted")
			} else {
				anchorOtsMinAccepted = rt.viper.GetInt("anchor.ots.min_accepted")
			}
			anchorOtsTimeoutText = stringOrLiteral(cmd, "anchor-ots-timeout", anchorOtsTimeoutText, rt.viper.GetString("anchor.ots.timeout"))
			anchorMaxDelayText = stringOrLiteral(cmd, "anchor-max-delay", anchorMaxDelayText, rt.cfg.Anchor.MaxDelay)
			anchorPollIntervalText = stringOrLiteral(cmd, "anchor-poll-interval", anchorPollIntervalText, rt.cfg.Anchor.PollInterval)
			// OTS upgrader: default enabled (true) so flipping
			// --anchor-sink=ots gives operators automatic
			// pending→attested progression without a second flag.
			// Operators who want to manage upgrades manually can
			// pass --anchor-ots-upgrade-enabled=false or set
			// anchor.ots.upgrade.enabled=false in the config file.
			if cmd.Flags().Changed("anchor-ots-upgrade-enabled") {
				anchorOtsUpgradeEnabled, _ = cmd.Flags().GetBool("anchor-ots-upgrade-enabled")
			} else if rt.viper.IsSet("anchor.ots.upgrade.enabled") {
				anchorOtsUpgradeEnabled = rt.viper.GetBool("anchor.ots.upgrade.enabled")
			} else {
				anchorOtsUpgradeEnabled = true
			}
			anchorOtsUpgradeIntervalText = stringOrLiteral(cmd, "anchor-ots-upgrade-interval", anchorOtsUpgradeIntervalText, rt.viper.GetString("anchor.ots.upgrade.interval"))
			if cmd.Flags().Changed("anchor-ots-upgrade-batch-size") {
				anchorOtsUpgradeBatchSize, _ = cmd.Flags().GetInt("anchor-ots-upgrade-batch-size")
			} else {
				anchorOtsUpgradeBatchSize = rt.viper.GetInt("anchor.ots.upgrade.batch_size")
			}
			anchorOtsUpgradeTimeoutText = stringOrLiteral(cmd, "anchor-ots-upgrade-timeout", anchorOtsUpgradeTimeoutText, rt.viper.GetString("anchor.ots.upgrade.timeout"))
			if cmd.Flags().Changed("anchor-ots-upgrade-workers") {
				anchorOtsUpgradeWorkers, _ = cmd.Flags().GetInt("anchor-ots-upgrade-workers")
			} else {
				anchorOtsUpgradeWorkers = rt.viper.GetInt("anchor.ots.upgrade.workers")
			}
			clientPubPath = stringOrConfig(cmd, rt, "client-public-key", clientPubPath, "keys.client_public")
			registryPath = stringOrConfig(cmd, rt, "key-registry", registryPath, "key_registry")
			registryPubPath = stringOrConfig(cmd, rt, "registry-public-key", registryPubPath, "keys.registry_public")
			if cmd.Flags().Changed("queue-size") {
				queueSize, _ = cmd.Flags().GetInt("queue-size")
			} else {
				queueSize = rt.cfg.Server.QueueSize
			}
			if cmd.Flags().Changed("workers") {
				workers, _ = cmd.Flags().GetInt("workers")
			} else {
				workers = rt.cfg.Server.Workers
			}
			if cmd.Flags().Changed("batch-queue-size") {
				batchQueueSize, _ = cmd.Flags().GetInt("batch-queue-size")
			} else {
				batchQueueSize = rt.cfg.Batch.QueueSize
			}
			if cmd.Flags().Changed("batch-max-records") {
				batchMaxRecords, _ = cmd.Flags().GetInt("batch-max-records")
			} else {
				batchMaxRecords = rt.cfg.Batch.MaxRecords
			}
			if cmd.Flags().Changed("batch-materializer-workers") {
				batchMaterializerWorkers, _ = cmd.Flags().GetInt("batch-materializer-workers")
			} else {
				batchMaterializerWorkers = rt.cfg.Batch.MaterializerWorkers
			}
			if cmd.Flags().Changed("batch-materializer-queue-size") {
				batchMaterializerQueueSize, _ = cmd.Flags().GetInt("batch-materializer-queue-size")
			} else {
				batchMaterializerQueueSize = rt.cfg.Batch.MaterializerQueueSize
			}
			if cmd.Flags().Changed("batch-proof-workers") {
				batchProofWorkers, _ = cmd.Flags().GetInt("batch-proof-workers")
			} else {
				batchProofWorkers = rt.cfg.Batch.ProofWorkers
			}
			readTimeoutText = stringOrLiteral(cmd, "read-timeout", readTimeoutText, rt.cfg.Server.ReadTimeout)
			readHeaderTimeoutText = stringOrLiteral(cmd, "read-header-timeout", readHeaderTimeoutText, rt.cfg.Server.ReadHeaderTimeout)
			writeTimeoutText = stringOrLiteral(cmd, "write-timeout", writeTimeoutText, rt.cfg.Server.WriteTimeout)
			idleTimeoutText = stringOrLiteral(cmd, "idle-timeout", idleTimeoutText, rt.cfg.Server.IdleTimeout)
			shutdownTimeoutText = stringOrLiteral(cmd, "shutdown-timeout", shutdownTimeoutText, rt.cfg.Server.ShutdownTimeout)
			batchMaxDelayText = stringOrLiteral(cmd, "batch-max-delay", batchMaxDelayText, rt.cfg.Batch.MaxDelay)
			batchMaterializerPollText = stringOrLiteral(cmd, "batch-materializer-poll-interval", batchMaterializerPollText, rt.cfg.Batch.MaterializerPollInterval)
			batchProofMode = stringOrLiteral(cmd, "batch-proof-mode", batchProofMode, rt.cfg.Batch.ProofMode)
			if serverKeyPath == "" {
				return usageError("serve requires server-private-key")
			}
			if clientPubPath == "" && registryPath == "" {
				return usageError("serve requires either client-public-key or key-registry")
			}
			readTimeout, err := parseNonNegativeDurationFlag("read-timeout", readTimeoutText)
			if err != nil {
				return err
			}
			readHeaderTimeout, err := parseNonNegativeDurationFlag("read-header-timeout", readHeaderTimeoutText)
			if err != nil {
				return err
			}
			writeTimeout, err := parseNonNegativeDurationFlag("write-timeout", writeTimeoutText)
			if err != nil {
				return err
			}
			idleTimeout, err := parseNonNegativeDurationFlag("idle-timeout", idleTimeoutText)
			if err != nil {
				return err
			}
			shutdownTimeout, err := parseNonNegativeDurationFlag("shutdown-timeout", shutdownTimeoutText)
			if err != nil {
				return err
			}
			batchMaxDelay, err := parsePositiveDurationFlag("batch-max-delay", batchMaxDelayText)
			if err != nil {
				return err
			}
			batchMaterializerPollInterval, err := parsePositiveDurationFlag("batch-materializer-poll-interval", batchMaterializerPollText)
			if err != nil {
				return err
			}
			anchorPollInterval, err := parsePositiveDurationFlag("anchor-poll-interval", anchorPollIntervalText)
			if err != nil {
				return err
			}
			anchorMaxDelay, err := parsePositiveDurationFlag("anchor-max-delay", anchorMaxDelayText)
			if err != nil {
				return err
			}
			if batchMaterializerWorkers <= 0 {
				return usageError("batch-materializer-workers must be greater than 0")
			}
			if batchMaterializerQueueSize <= 0 {
				return usageError("batch-materializer-queue-size must be greater than 0")
			}
			if batchProofWorkers < 0 {
				return usageError("batch-proof-workers must be zero or greater")
			}
			serverSigner, serverKey, err := readSigner(cmd.Context(), serverKeyPath)
			if err != nil {
				return err
			}
			clientPub, clientKeys, err := resolveClientKeys(clientPubPath, registryPath, registryPubPath, cmd.Flags().Changed("key-registry"))
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("wal-max-segment-bytes") {
				walMaxSegmentBytes, _ = cmd.Flags().GetInt64("wal-max-segment-bytes")
			}
			if cmd.Flags().Changed("wal-keep-segments") {
				walKeepSegments, _ = cmd.Flags().GetInt("wal-keep-segments")
			}
			walFsyncMode = stringOrLiteral(cmd, "wal-fsync-mode", walFsyncMode, rt.viper.GetString("wal.fsync_mode"))
			if strings.TrimSpace(walFsyncMode) == "" {
				walFsyncMode = wal.FsyncGroup
			}
			switch strings.ToLower(strings.TrimSpace(walFsyncMode)) {
			case wal.FsyncStrict, wal.FsyncGroup, wal.FsyncBatch:
			default:
				return trusterr.New(trusterr.CodeInvalidArgument, "wal fsync mode must be strict, group, or batch")
			}
			walGroupCommitIntervalText = stringOrLiteral(cmd, "wal-group-commit-interval", walGroupCommitIntervalText, rt.viper.GetString("wal.group_commit_interval"))
			if strings.TrimSpace(walGroupCommitIntervalText) == "" {
				walGroupCommitIntervalText = "10ms"
			}
			walGroupCommitInterval, err := parseWALGroupCommitInterval(walFsyncMode, walGroupCommitIntervalText)
			if err != nil {
				return err
			}
			batchProofMode = normalizeSemanticProofMode(batchProofMode)
			proofstoreRecordIndexMode = normalizeSemanticRecordIndexMode(proofstoreRecordIndexMode)
			proofstoreArtifactSyncMode = normalizeSemanticArtifactSyncMode(proofstoreArtifactSyncMode)
			if err := validateSemanticModes(batchProofMode, proofstoreRecordIndexMode, proofstoreArtifactSyncMode); err != nil {
				return err
			}
			reg, metrics := observability.NewRegistry()
			walOpts := wal.Options{
				MaxSegmentBytes:     walMaxSegmentBytes,
				FsyncMode:           walFsyncMode,
				GroupCommitInterval: walGroupCommitInterval,
				OnRotate: func(_, to uint64) {
					metrics.WALActiveSegmentID.Set(float64(to))
					// The count gauge is refreshed on rotate rather than
					// read live so prometheus scrapes remain cheap; a
					// fresh segment becoming active implies +1 file.
					if err := refreshWALSegmentsTotal(metrics, walPath); err != nil {
						rt.logger.Warn().Err(err).Str("wal", walPath).Msg("wal segment metric refresh failed")
					}
				},
				OnAppend: func(mode string, d time.Duration) {
					metrics.WALAppendLatency.WithLabelValues(mode).Observe(d.Seconds())
				},
				OnFsync: func(mode string, d time.Duration) {
					metrics.WALFsyncLatency.WithLabelValues(mode).Observe(d.Seconds())
				},
				OnFsyncError: func(mode string, err error) {
					rt.logger.Error().Err(err).Str("fsync_mode", mode).Str("wal", walPath).Msg("wal fsync failed")
				},
			}
			writer, walMode, err := openWALWriterWithOptions(walPath, walOpts)
			if err != nil {
				return err
			}
			defer func() {
				if err := writer.Close(); err != nil {
					rt.logger.Error().Err(err).Str("wal", walPath).Msg("wal close failed")
				}
			}()
			rt.logger.Info().
				Str("wal", walPath).
				Str("mode", walMode).
				Str("fsync_mode", walFsyncMode).
				Str("durability_profile", walDurabilityProfile(walFsyncMode)).
				Dur("group_commit_interval", walGroupCommitInterval).
				Int64("max_segment_bytes", walMaxSegmentBytes).
				Int("keep_segments", walKeepSegments).
				Msg("wal opened")
			// Seed the startup values of the segment gauges so dashboards
			// see the true on-disk count and active segment immediately,
			// not after the first rotate/prune.
			metrics.WALActiveSegmentID.Set(float64(writer.ActiveSegmentID()))
			if walMode == "directory" {
				if err := refreshWALSegmentsTotal(metrics, walPath); err != nil {
					rt.logger.Warn().Err(err).Str("wal", walPath).Msg("wal segment metric refresh failed")
				}
			} else {
				metrics.WALSegmentsTotal.Set(1)
			}

			idempotency := app.NewIdempotencyIndex()
			nodeID := stringValue(cmd, rt, "server-id", "server_id")
			walID, err := filepath.Abs(filepath.Clean(walPath))
			if err != nil {
				return trusterr.Wrap(trusterr.CodeInvalidArgument, "resolve wal identity", err)
			}
			logID := strings.TrimSpace(rt.cfg.GlobalLog.LogID)
			if logID == "" {
				logID = nodeID
			}
			serverKeyID := stringValue(cmd, rt, "server-key-id", "server_key_id")
			if err := requireKeyID(serverKeyID, serverKey); err != nil {
				return err
			}
			engine := app.LocalEngine{
				ServerID:        nodeID,
				LogID:           logID,
				ServerKeyID:     serverKeyID,
				ClientPublicKey: clientPub,
				ClientKeys:      clientKeys,
				ServerSigner:    serverSigner,
				ProofWorkers:    batchProofWorkers,
				WAL:             writer,
				Idempotency:     idempotency,
			}
			// Pick the proof store backend from the CLI/config, defaulting
			// to the file backend rooted at --proof-dir so existing
			// deployments continue to work unchanged. When --metastore
			// names a pebble backend without an explicit path we fall
			// back to the proof_dir/pebble sub-directory so the Pebble
			// WAL/manifests do not accidentally collide with the file
			// backend's files living in the same directory.
			metaPath := metastorePath
			if metaPath == "" {
				metaPath = proofDir
			}
			metaKind := metastoreKind
			if metaKind == "" {
				metaKind = string(proofstore.BackendPebble)
			}
			if metaKind == string(proofstore.BackendPebble) && metastorePath == "" {
				metaPath = proofDir + "/pebble"
			}
			logServeRunProfile(rt, metaKind, anchorSinkKind)
			if metaKind == string(proofstore.BackendFile) {
				rt.logger.Warn().Msg("file proofstore is intended for development/small datasets; use --metastore=pebble for production-scale attestations")
			}
			proofStore, err := proofstore.Open(proofstore.Config{
				Kind:                         proofstore.Backend(metaKind),
				Path:                         metaPath,
				TiKVPDAddresses:              tikvPDAddresses,
				TiKVKeyspace:                 proofstoreTiKVKeyspace,
				TiKVNamespace:                proofstoreTiKVNamespace,
				CheckpointNodeID:             nodeID,
				CheckpointWALID:              walID,
				RecordIndexMode:              proofstoreRecordIndexMode,
				ArtifactSyncMode:             proofstoreArtifactSyncMode,
				IndexStorageTokens:           !strings.EqualFold(proofstoreRecordIndexMode, "no_storage_tokens"),
				IndexStorageTokensConfigured: cmd.Flags().Changed("proofstore-index-storage-tokens"),
			})
			if err != nil {
				return err
			}
			defer func() {
				if cerr := proofStore.Close(); cerr != nil {
					rt.logger.Warn().Err(cerr).Msg("proofstore close failed")
				}
			}()
			if manager, ok := proofStore.(proofstore.IdempotencyProjectionManager); ok {
				if err := manager.EnsureIdempotencyProjection(context.Background()); err != nil {
					return trusterr.Wrap(trusterr.CodeDataLoss, "prepare durable idempotency projection", err)
				}
			}
			if reader, ok := proofStore.(proofstore.IdempotencyDecisionReader); ok {
				engine.DurableIdempotency = reader
			}
			engine.DurableRecords = proofStore
			ingestSvc := ingest.New(engine, ingest.Options{QueueSize: queueSize, Workers: workers}, metrics)
			defer ingestSvc.Shutdown(context.Background())
			if enabled, err := observability.RegisterPebbleMetrics(reg, proofStore); err != nil {
				return trusterr.Wrap(trusterr.CodeInternal, "register pebble metrics", err)
			} else if enabled {
				rt.logger.Info().Str("path", metaPath).Msg("pebble proofstore metrics enabled")
			}
			activeSemanticProfile := semanticProfile(walFsyncMode, batchProofMode, proofstoreRecordIndexMode, proofstoreArtifactSyncMode, rt.cfg.GlobalLog.Enabled)
			activeDurabilityProfile := walDurabilityProfile(walFsyncMode)
			metrics.SemanticProfile.WithLabelValues(
				activeSemanticProfile,
				activeDurabilityProfile,
				batchProofMode,
				proofstoreRecordIndexMode,
				proofstoreArtifactSyncMode,
				strings.ToLower(strconv.FormatBool(rt.cfg.GlobalLog.Enabled)),
			).Set(1)
			rt.logger.Info().
				Str("semantic_profile", activeSemanticProfile).
				Str("durability_profile", activeDurabilityProfile).
				Str("proof_mode", batchProofMode).
				Str("record_index_mode", proofstoreRecordIndexMode).
				Str("artifact_sync_mode", proofstoreArtifactSyncMode).
				Bool("global_log_enabled", rt.cfg.GlobalLog.Enabled).
				Msg("semantic performance profile active")
			batchOpts := batch.Options{
				QueueSize:                batchQueueSize,
				MaxRecords:               batchMaxRecords,
				MaxDelay:                 batchMaxDelay,
				ProofMode:                batchProofMode,
				MaterializerWorkers:      batchMaterializerWorkers,
				MaterializerQueueSize:    batchMaterializerQueueSize,
				MaterializerPollInterval: batchMaterializerPollInterval,
				MaterializerNodeID:       nodeID,
				DeferMaterializerScan:    true,
				DeferCheckpointAdvance:   true,
				InitialSeq:               restoreBatchSeq(context.Background(), rt, proofStore),
				LoadBatchItems: func(ctx context.Context, manifest model.BatchManifest) ([]batch.Accepted, error) {
					return loadManifestItemsFromWAL(ctx, walPath, engine, manifest)
				},
			}
			// Only wire automatic prune on directory-mode WALs: single-file
			// deployments have no notion of "older segments to delete" so
			// firing PruneSegmentsBefore against them is both pointless
			// and confusing in the logs.
			if walMode == "directory" {
				pruneGuard, guarded := proofStore.(proofstore.WALCheckpointPruneGuard)
				if proofstore.WALCheckpointPruneSafe(proofStore) && guarded {
					pruneHook := newPruneHook(rt, walPath, walKeepSegments, metrics)
					batchOpts.OnCheckpointAdvanced = func(ctx context.Context, cp model.WALCheckpoint) {
						ran, err := pruneGuard.WithWALCheckpointPruneGuard(ctx, cp, func() error {
							pruneHook(ctx, cp)
							return nil
						})
						if err != nil {
							rt.logger.Warn().Err(err).Msg("wal checkpoint prune guard failed")
						} else if !ran {
							rt.logger.Debug().Msg("wal checkpoint prune skipped: durable checkpoint is no longer current")
						}
					}
				} else {
					rt.logger.Warn().Str("metastore", metaKind).Msg("automatic WAL checkpoint pruning disabled: proofstore cannot durably guard committed artifacts and restart idempotency for this node-local WAL")
				}
			}
			// Build the anchor sink + worker before constructing the batch
			// service so the OnBatchCommitted hook can close over a live
			// service handle. "off" (or empty) disables L5 entirely; the
			// file/noop sinks run the full outbox pipeline so tests and
			// on-prem deployments exercise the same code paths as real
			// external notaries.
			globalLogEnabled := rt.cfg.GlobalLog.Enabled
			if !globalLogEnabled && strings.TrimSpace(anchorSinkKind) != "" && !strings.EqualFold(anchorSinkKind, "off") {
				rt.logger.Warn().Str("anchor_sink", anchorSinkKind).Msg("global log disabled; anchor sink will not be started")
			}
			if !globalLogEnabled {
				anchorSinkKind = "off"
			}
			anchorSvc, anchorAPI, anchorShutdown, err := buildAnchorService(rt, proofStore, metrics, nodeID, logID, anchorSinkKind, anchorPath, proofDir, anchorPollInterval, pluginSinkParams{
				Command:          anchorPluginCommand,
				Args:             anchorPluginArgs,
				StartTimeoutText: anchorPluginStartTimeoutText,
				RPCTimeoutText:   anchorPluginRPCTimeoutText,
			}, otsSinkParams{
				Calendars:   anchorOtsCalendars,
				MinAccepted: anchorOtsMinAccepted,
				TimeoutText: anchorOtsTimeoutText,
			})
			if err != nil {
				return err
			}
			defer anchorShutdown()
			var coverageProjector *l5projector.Service
			if anchorSvc != nil {
				coverageStore, ok := proofStore.(l5projector.Store)
				if !ok {
					return trusterr.New(trusterr.CodeFailedPrecondition, "proofstore does not support recoverable L5 coverage projection")
				}
				coverageProjector, err = l5projector.New(l5projector.Config{
					Store:        coverageStore,
					Key:          anchorSvc.ScheduleKey(),
					PollInterval: anchorPollInterval,
					Logger:       rt.logger,
				})
				if err != nil {
					return trusterr.Wrap(trusterr.CodeInternal, "build L5 coverage projector", err)
				}
				defer coverageProjector.Stop()
			}
			var globalSvc *globallog.Service
			var globalOutbox *globallog.OutboxWorker
			if globalLogEnabled {
				anchorSinkName := ""
				var anchorKey *model.STHAnchorScheduleKey
				var onAnchorReady func()
				if anchorSvc != nil {
					anchorSinkName = anchorSvc.SinkName()
					key := anchorSvc.ScheduleKey()
					anchorKey = &key
					onAnchorReady = anchorSvc.Trigger
				}
				globalSvc, err = globallog.New(globallog.Options{
					Store:          proofStore,
					NodeID:         nodeID,
					LogID:          logID,
					Signer:         serverSigner,
					AnchorSinkName: anchorSinkName,
				})
				if err != nil {
					return trusterr.Wrap(trusterr.CodeInternal, "build global log service", err)
				}
				globalOutbox = globallog.NewOutboxWorker(globallog.OutboxConfig{
					Store:          proofStore,
					Global:         globalSvc,
					AnchorKey:      anchorKey,
					AnchorMaxDelay: anchorMaxDelay,
					OnAnchorReady:  onAnchorReady,
					Metrics:        metrics,
					Logger:         rt.logger,
				})
				defer globalOutbox.Stop()
				batchOpts.OnBatchCommitted = newGlobalLogEnqueueHook(rt, proofStore, globalOutbox)
			}
			batchSvc := batch.New(engine, proofStore, batchOpts, metrics)
			defer batchSvc.Shutdown(context.Background())
			submissionSvc := submission.New(ingestSvc, batchSvc)
			recovered, replayed, skipped, err := replayWALAccepted(context.Background(), walPath, engine, batchSvc, proofStore, metrics)
			if err != nil {
				return err
			}
			batchSvc.StartMaterializerScan()
			rt.logger.Info().
				Int("recovered_batches", recovered).
				Int("replayed", replayed).
				Int("skipped", skipped).
				Msg("wal replay complete")
			if globalLogEnabled {
				if n, err := backfillGlobalLogOutbox(context.Background(), proofStore); err != nil {
					rt.logger.Warn().Err(err).Msg("global log outbox backfill failed")
				} else if n > 0 {
					rt.logger.Info().Int("backfilled", n).Msg("global log outbox backfill complete")
				}
				globalOutbox.Start(context.Background())
				globalOutbox.Trigger()
			}
			if anchorSvc != nil {
				// Start *after* backfill so the worker sees the freshly
				// enqueued items on its first tick.
				anchorSvc.Start(context.Background())
			}
			if coverageProjector != nil {
				coverageProjector.Start(context.Background())
			}
			// OTS upgrader: only meaningful when the anchor sink is
			// the OpenTimestamps one. Enabled by default; the
			// background worker will keep walking published OTS
			// STHAnchorResults until every accepted calendar reaches
			// terminal Bitcoin attestation. Stop it on shutdown
			// before the proofstore so a sweep cannot race the
			// store close.
			otsUpgrader, err := buildOtsUpgrader(rt, proofStore, metrics, anchorSinkKind, otsUpgraderParams{
				Enabled:      anchorOtsUpgradeEnabled,
				IntervalText: anchorOtsUpgradeIntervalText,
				BatchSize:    anchorOtsUpgradeBatchSize,
				TimeoutText:  anchorOtsUpgradeTimeoutText,
				Workers:      anchorOtsUpgradeWorkers,
			})
			if err != nil {
				return err
			}
			if otsUpgrader != nil {
				otsUpgrader.Start(context.Background())
				defer otsUpgrader.Stop()
			}

			serveCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			natsIngress, err := startServeNATSIngress(serveCtx, rt.cfg.NATS, submissionSvc, rt.logger)
			if err != nil {
				return err
			}
			if natsIngress != nil {
				defer func() {
					closeCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
					defer cancel()
					if err := natsIngress.Close(closeCtx); err != nil {
						rt.logger.Warn().Err(err).Msg("optional NATS ingress close failed")
					}
				}()
			}

			metricsHandler := observability.Handler(reg)
			var publicHandler http.Handler
			if anchorAPI != nil {
				publicHandler = httpapi.NewWithSubmitterAndGlobalAndAnchors(submissionSvc, metricsHandler, batchSvc, globalSvc, anchorAPI)
			} else {
				publicHandler = httpapi.NewWithSubmitterAndGlobalAndAnchors(submissionSvc, metricsHandler, batchSvc, globalSvc, nil)
			}
			handler := http.Handler(publicHandler)
			if rt.cfg.Admin.Enabled {
				ah, err := adminweb.New(adminweb.Options{
					Admin:        rt.cfg.Admin,
					Viper:        rt.viper,
					ConfigPath:   rt.configPath,
					EffectiveCfg: rt.cfg,
					Public:       publicHandler,
					Metrics:      metricsHandler,
					Logger:       rt.logger,
				})
				if err != nil {
					return err
				}
				bp := strings.TrimSpace(rt.cfg.Admin.BasePath)
				if bp == "" {
					bp = "/admin"
				}
				handler = adminweb.Mount(bp, publicHandler, ah)
			}
			server := &http.Server{
				Addr:              listen,
				Handler:           handler,
				ReadTimeout:       readTimeout,
				ReadHeaderTimeout: readHeaderTimeout,
				WriteTimeout:      writeTimeout,
				IdleTimeout:       idleTimeout,
			}
			errCh := make(chan error, 2)
			var grpcServer *grpc.Server
			if strings.TrimSpace(grpcListen) != "" {
				listener, err := net.Listen("tcp", grpcListen)
				if err != nil {
					return trusterr.Wrap(trusterr.CodeInvalidArgument, "listen grpc", err)
				}
				defer listener.Close()
				grpcServer = grpc.NewServer(
					grpc.MaxRecvMsgSize(grpcapi.MaxMessageBytes),
					grpc.MaxSendMsgSize(grpcapi.MaxMessageBytes),
				)
				healthSvc := health.NewServer()
				healthSvc.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
				healthpb.RegisterHealthServer(grpcServer, healthSvc)
				defer healthSvc.Shutdown()
				grpcapi.RegisterTrustDBServiceServer(grpcServer, grpcapi.NewServerWithSubmitter(submissionSvc, batchSvc, globalSvc, anchorAPI, metricsHandler))
				defer grpcServer.Stop()
				go func() {
					rt.logger.Info().Str("listen", grpcListen).Msg("starting trustdb grpc server")
					if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
						errCh <- err
					}
				}()
			}

			go func() {
				rt.logger.Info().Str("listen", listen).Msg("starting trustdb server")
				if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errCh <- err
				}
			}()

			runErr := waitForServeStop(serveCtx, errCh, natsIngress)
			stop()

			shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			var shutdownErrs []error
			if err := server.Shutdown(shutdownCtx); err != nil {
				shutdownErrs = append(shutdownErrs, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "http server shutdown", err))
			}
			if grpcServer != nil {
				shutdownGRPCServer(shutdownCtx, grpcServer)
			}
			if err := natsIngress.Close(shutdownCtx); err != nil {
				shutdownErrs = append(shutdownErrs, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "optional NATS ingress shutdown", err))
			}
			if err := ingestSvc.Shutdown(shutdownCtx); err != nil {
				shutdownErrs = append(shutdownErrs, err)
			}
			if err := batchSvc.Shutdown(shutdownCtx); err != nil {
				shutdownErrs = append(shutdownErrs, err)
			}
			rt.logger.Info().Msg("trustdb server stopped")
			return errors.Join(append([]error{runErr}, shutdownErrs...)...)
		},
	}
	addServerFlags(cmd)
	cmd.Flags().StringVar(&listen, "listen", "", "listen address")
	cmd.Flags().StringVar(&grpcListen, "grpc-listen", "", "optional gRPC listen address; empty disables gRPC")
	cmd.Flags().StringVar(&serverKeyPath, "server-private-key", "", "server signer descriptor")
	cmd.Flags().StringVar(&walPath, "wal", "", "wal path")
	cmd.Flags().StringVar(&proofDir, "proof-dir", "", "proof bundle and root directory")
	cmd.Flags().StringVar(&clientPubPath, "client-public-key", "", "client verifier descriptor")
	cmd.Flags().StringVar(&registryPath, "key-registry", "", "key registry path")
	cmd.Flags().StringVar(&registryPubPath, "registry-public-key", "", "registry verifier descriptor")
	cmd.Flags().IntVar(&queueSize, "queue-size", 0, "bounded ingest queue size")
	cmd.Flags().IntVar(&workers, "workers", 0, "ingest worker count")
	cmd.Flags().IntVar(&batchQueueSize, "batch-queue-size", 0, "bounded batch queue size")
	cmd.Flags().IntVar(&batchMaxRecords, "batch-max-records", 0, "records per batch before commit")
	cmd.Flags().IntVar(&batchMaterializerWorkers, "batch-materializer-workers", 0, "bounded async proof materializer worker count")
	cmd.Flags().IntVar(&batchMaterializerQueueSize, "batch-materializer-queue-size", 0, "bounded in-memory async materializer job queue size")
	cmd.Flags().StringVar(&batchMaterializerPollText, "batch-materializer-poll-interval", "", "interval for recovering durable prepared materialization jobs")
	cmd.Flags().IntVar(&batchProofWorkers, "batch-proof-workers", 0, "global per-batch proof/signing workers (0 = auto)")
	cmd.Flags().StringVar(&readTimeoutText, "read-timeout", "", "http read timeout")
	cmd.Flags().StringVar(&readHeaderTimeoutText, "read-header-timeout", "", "http request header read timeout")
	cmd.Flags().StringVar(&writeTimeoutText, "write-timeout", "", "http write timeout")
	cmd.Flags().StringVar(&idleTimeoutText, "idle-timeout", "", "http keep-alive idle timeout")
	cmd.Flags().StringVar(&shutdownTimeoutText, "shutdown-timeout", "", "graceful shutdown timeout")
	cmd.Flags().StringVar(&batchMaxDelayText, "batch-max-delay", "", "maximum delay before committing a partial batch")
	cmd.Flags().StringVar(&batchProofMode, "batch-proof-mode", "", "proof materialization mode: inline (default), async, or on_demand")
	cmd.Flags().Int64Var(&walMaxSegmentBytes, "wal-max-segment-bytes", 0, "rotate WAL directory segments above this byte count (0 disables rotation; only honored in directory mode)")
	cmd.Flags().IntVar(&walKeepSegments, "wal-keep-segments", 0, "after checkpoint advance, keep this many segments older than the checkpoint-covered segment (directory mode; 0 = only retain the active segment + checkpoint-covered one)")
	cmd.Flags().StringVar(&walFsyncMode, "wal-fsync-mode", "", "WAL fsync mode: strict, group (production default), or batch")
	cmd.Flags().StringVar(&walGroupCommitIntervalText, "wal-group-commit-interval", "", "maximum WAL dirty interval in group mode (default 10ms; use strict for fsync before each receipt)")
	cmd.Flags().StringVar(&metastoreKind, "metastore", "", "proof store backend: file (default), pebble, or tikv (shared PD/TiKV cluster)")
	cmd.Flags().StringVar(&metastorePath, "metastore-path", "", "proof store path (defaults to --proof-dir; for tikv, accepts comma-separated PD endpoints)")
	cmd.Flags().StringVar(&proofstoreTiKVPDText, "proofstore-tikv-pd-endpoints", "", "comma-separated TiKV PD endpoints for the tikv proofstore backend")
	cmd.Flags().StringVar(&proofstoreTiKVKeyspace, "proofstore-tikv-keyspace", "", "TiKV keyspace for the tikv proofstore backend")
	cmd.Flags().StringVar(&proofstoreTiKVNamespace, "proofstore-tikv-namespace", "", "application namespace prefix inside the TiKV proofstore backend")
	cmd.Flags().StringVar(&proofstoreArtifactSyncMode, "proofstore-artifact-sync-mode", "", "proof artifact durability mode: chunk (default) or batch")
	cmd.Flags().StringVar(&proofstoreRecordIndexMode, "proofstore-record-index-mode", "", "record secondary index mode: full (default), no_storage_tokens, or time_only")
	cmd.Flags().BoolVar(&proofstoreIndexStorageTokens, "proofstore-index-storage-tokens", true, "write StorageURI/FileName token secondary indexes in the proofstore; disable for high-write ingest profiles")
	cmd.Flags().StringVar(&anchorSinkKind, "anchor-sink", "", "external anchor sink: off (default; no L5 proofs), file, noop, ots (OpenTimestamps), or plugin")
	cmd.Flags().StringVar(&anchorPath, "anchor-path", "", "file anchor sink output path (JSONL). Defaults to <proof-dir>/anchors.jsonl when --anchor-sink=file and this flag is empty")
	cmd.Flags().StringVar(&anchorPluginCommand, "anchor-plugin-command", "", "external anchor plugin executable (required when --anchor-sink=plugin)")
	cmd.Flags().StringArrayVar(&anchorPluginArgs, "anchor-plugin-arg", nil, "argument passed to the external anchor plugin; may be repeated")
	cmd.Flags().StringVar(&anchorPluginStartTimeoutText, "anchor-plugin-start-timeout", "", "maximum time to start and handshake with an external anchor plugin (default 10s)")
	cmd.Flags().StringVar(&anchorPluginRPCTimeoutText, "anchor-plugin-rpc-timeout", "", "per-RPC timeout for an external anchor plugin (default 30s)")
	cmd.Flags().StringVar(&anchorMaxDelayText, "anchor-max-delay", "", "fixed coalescing window before publishing the latest pending STH")
	cmd.Flags().StringVar(&anchorPollIntervalText, "anchor-poll-interval", "", "interval for recovering durable pending anchor jobs")
	cmd.Flags().StringSliceVar(&anchorOtsCalendars, "anchor-ots-calendars", nil, "comma-separated OpenTimestamps calendar URLs. When empty a built-in public pool is used (only honored when --anchor-sink=ots)")
	cmd.Flags().IntVar(&anchorOtsMinAccepted, "anchor-ots-min-accepted", 0, "minimum number of OTS calendars that must accept a submission for success (0 = require majority)")
	cmd.Flags().StringVar(&anchorOtsTimeoutText, "anchor-ots-timeout", "", "per-calendar request timeout for the OpenTimestamps sink (default 20s)")
	cmd.Flags().BoolVar(&anchorOtsUpgradeEnabled, "anchor-ots-upgrade-enabled", true, "run a background worker that upgrades pending OTS proofs to Bitcoin-attested ones (default true; only meaningful with --anchor-sink=ots)")
	cmd.Flags().StringVar(&anchorOtsUpgradeIntervalText, "anchor-ots-upgrade-interval", "", "interval between OTS upgrade sweeps (default 1h; values <5m are usually wasteful against the public calendar pool)")
	cmd.Flags().IntVar(&anchorOtsUpgradeBatchSize, "anchor-ots-upgrade-batch-size", 0, fmt.Sprintf("max number of OTS STHAnchorResults processed per upgrade sweep (default 64, max %d)", anchor.MaxOtsUpgradeBatchSize))
	cmd.Flags().StringVar(&anchorOtsUpgradeTimeoutText, "anchor-ots-upgrade-timeout", "", "per-calendar GET timeout for the OTS upgrader (default 30s)")
	cmd.Flags().IntVar(&anchorOtsUpgradeWorkers, "anchor-ots-upgrade-workers", 0, "bounded concurrent OTS proof upgrade worker count")
	return cmd
}

func shutdownGRPCServer(ctx context.Context, server *grpc.Server) {
	stopped := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-ctx.Done():
		server.Stop()
	}
}

func parseNonNegativeDurationFlag(name, text string) (time.Duration, error) {
	d, err := time.ParseDuration(text)
	if err != nil {
		return 0, trusterr.Wrap(trusterr.CodeInvalidArgument, "parse "+name, err)
	}
	if d < 0 {
		return 0, trusterr.New(trusterr.CodeInvalidArgument, "--"+name+" must be >= 0")
	}
	return d, nil
}

func parsePositiveDurationFlag(name, text string) (time.Duration, error) {
	d, err := time.ParseDuration(text)
	if err != nil {
		return 0, trusterr.Wrap(trusterr.CodeInvalidArgument, "parse "+name, err)
	}
	if d <= 0 {
		return 0, trusterr.New(trusterr.CodeInvalidArgument, "--"+name+" must be > 0")
	}
	return d, nil
}

func parseWALGroupCommitInterval(mode, text string) (time.Duration, error) {
	if strings.EqualFold(strings.TrimSpace(mode), wal.FsyncGroup) {
		return parsePositiveDurationFlag("wal-group-commit-interval", text)
	}
	d, err := time.ParseDuration(text)
	if err != nil {
		return 0, trusterr.Wrap(trusterr.CodeInvalidArgument, "parse wal-group-commit-interval", err)
	}
	// Preserve compatibility for strict and batch profiles, where this
	// setting is inactive, while logging the same normalized value the WAL
	// writer would use if the mode later changed to group.
	if d <= 0 {
		return 10 * time.Millisecond, nil
	}
	return d, nil
}

// otsSinkParams carries the OpenTimestamps-specific options through
// buildAnchorService without bloating its signature for deployments
// that don't use the OTS sink. All fields are optional and validated
// only when --anchor-sink=ots.
type otsSinkParams struct {
	Calendars   []string
	MinAccepted int
	TimeoutText string
}

type pluginSinkParams struct {
	Command          string
	Args             []string
	StartTimeoutText string
	RPCTimeoutText   string
}

func newPluginSinkFromParams(ctx context.Context, plugin pluginSinkParams) (*anchor.PluginSink, error) {
	startTimeout, err := parsePositiveDurationFlag("anchor-plugin-start-timeout", plugin.StartTimeoutText)
	if err != nil {
		return nil, err
	}
	rpcTimeout, err := parsePositiveDurationFlag("anchor-plugin-rpc-timeout", plugin.RPCTimeoutText)
	if err != nil {
		return nil, err
	}
	return anchor.NewPluginSink(ctx, anchor.PluginSinkOptions{
		Command:      plugin.Command,
		Args:         plugin.Args,
		StartTimeout: startTimeout,
		RPCTimeout:   rpcTimeout,
	})
}

// buildAnchorService wires the configured Sink and returns both the
// worker Service and a read-only API suitable for the HTTP layer. The
// shutdown closure is always non-nil so `defer anchorShutdown()` is
// safe even when anchoring is off. Legal sink kinds: "" / "off" (L5
// disabled), "file", "noop", "ots", and "plugin".
func buildAnchorService(rt *runtimeConfig, store proofstore.Store, metrics *observability.Metrics, nodeID, logID, sinkKind, anchorPath, proofDir string, pollInterval time.Duration, plugin pluginSinkParams, ots otsSinkParams) (*anchor.Service, httpapi.AnchorService, func(), error) {
	kind := strings.ToLower(strings.TrimSpace(sinkKind))
	switch kind {
	case "", "off", "disabled", "none":
		return nil, nil, func() {}, nil
	}
	var sink anchor.Sink
	var sinkShutdown func()
	switch kind {
	case "file":
		path := anchorPath
		if path == "" {
			if proofDir == "" {
				return nil, nil, nil, trusterr.New(trusterr.CodeInvalidArgument, "--anchor-sink=file requires --anchor-path or --proof-dir")
			}
			path = filepath.Join(proofDir, "anchors.jsonl")
		}
		fs, err := anchor.NewFileSink(path)
		if err != nil {
			return nil, nil, nil, err
		}
		rt.logger.Info().Str("sink", fs.Name()).Str("path", path).Msg("anchor sink enabled")
		sink = fs
	case "noop":
		rt.logger.Info().Str("sink", anchor.NoopSinkName).Msg("anchor sink enabled (noop)")
		sink = anchor.NewNoopSink()
	case "ots", "opentimestamps":
		os, err := newOtsSinkFromParams(ots)
		if err != nil {
			return nil, nil, nil, err
		}
		rt.logger.Info().
			Str("sink", os.Name()).
			Strs("calendars", os.Calendars()).
			Msg("anchor sink enabled (opentimestamps)")
		sink = os
	case "plugin":
		ps, err := newPluginSinkFromParams(context.Background(), plugin)
		if err != nil {
			return nil, nil, nil, trusterr.Wrap(trusterr.CodeFailedPrecondition, "start anchor plugin", err)
		}
		rt.logger.Info().Str("sink", ps.Name()).Str("command", plugin.Command).Msg("anchor sink enabled (external plugin)")
		sink = ps
		sinkShutdown = func() {
			if err := ps.Close(); err != nil {
				rt.logger.Warn().Err(err).Msg("anchor: close external plugin")
			}
		}
	default:
		return nil, nil, nil, trusterr.New(trusterr.CodeInvalidArgument, "unknown anchor sink: "+sinkKind)
	}
	svc, err := anchor.NewService(anchor.Config{
		Sink:         sink,
		Store:        store,
		Key:          model.STHAnchorScheduleKey{NodeID: nodeID, LogID: logID, SinkName: sink.Name()},
		Metrics:      metrics,
		Logger:       rt.logger,
		PollInterval: pollInterval,
	})
	if err != nil {
		if sinkShutdown != nil {
			sinkShutdown()
		}
		return nil, nil, nil, err
	}
	api := anchor.NewAPI(store)
	return svc, api, func() {
		svc.Stop()
		if sinkShutdown != nil {
			sinkShutdown()
		}
	}, nil
}

// newOtsSinkFromParams constructs an OpenTimestamps sink from
// user-facing flag values. Durations go through parseDurationText so
// yaml strings ("20s") and flag literals share the same error
// surface. An empty Calendars slice is explicitly allowed; the sink
// falls back to anchor.DefaultOtsCalendars in that case. A negative
// MinAccepted is rejected up-front so we don't silently degrade the
// quorum policy.
func newOtsSinkFromParams(p otsSinkParams) (*anchor.OtsSink, error) {
	if p.MinAccepted < 0 {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "--anchor-ots-min-accepted must be >= 0")
	}
	var timeout time.Duration
	if text := strings.TrimSpace(p.TimeoutText); text != "" {
		d, err := time.ParseDuration(text)
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeInvalidArgument, "parse --anchor-ots-timeout", err)
		}
		timeout = d
	}
	return anchor.NewOtsSink(anchor.OtsSinkOptions{
		Calendars:   p.Calendars,
		MinAccepted: p.MinAccepted,
		Timeout:     timeout,
	})
}

// otsUpgraderParams collects the user-facing knobs for the OpenTimestamps
// upgrader. Kept separate from otsSinkParams because the sink and the
// upgrader have independent lifecycles: an operator may want to disable
// the periodic sweep (e.g. running a dedicated cron) while still using
// the sink, and vice versa is a no-op.
type otsUpgraderParams struct {
	Enabled      bool
	IntervalText string
	BatchSize    int
	TimeoutText  string
	Workers      int
}

// buildOtsUpgrader returns nil (with no error) when the upgrader is
// not applicable: any sink other than "ots", or operator-disabled via
// --anchor-ots-upgrade-enabled=false. Returning nil keeps the caller
// site simple (`if upgrader != nil { upgrader.Start(...) }`) and
// avoids fabricating a degenerate worker that walks an empty
// sink-name partition every interval.
func buildOtsUpgrader(rt *runtimeConfig, store proofstore.Store, metrics *observability.Metrics, sinkKind string, p otsUpgraderParams) (*anchor.OtsUpgrader, error) {
	kind := strings.ToLower(strings.TrimSpace(sinkKind))
	if kind != "ots" && kind != "opentimestamps" {
		return nil, nil
	}
	if !p.Enabled {
		rt.logger.Info().Msg("anchor: OTS upgrader disabled by --anchor-ots-upgrade-enabled=false")
		return nil, nil
	}

	var interval time.Duration
	if text := strings.TrimSpace(p.IntervalText); text != "" {
		d, err := time.ParseDuration(text)
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeInvalidArgument, "parse --anchor-ots-upgrade-interval", err)
		}
		if d <= 0 {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "--anchor-ots-upgrade-interval must be > 0")
		}
		interval = d
	}
	if p.BatchSize < 0 {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "--anchor-ots-upgrade-batch-size must be >= 0")
	}
	if p.BatchSize > anchor.MaxOtsUpgradeBatchSize {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, fmt.Sprintf("--anchor-ots-upgrade-batch-size must be <= %d", anchor.MaxOtsUpgradeBatchSize))
	}
	if p.Workers < 0 {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "--anchor-ots-upgrade-workers must be >= 0")
	}
	var timeout time.Duration
	if text := strings.TrimSpace(p.TimeoutText); text != "" {
		d, err := time.ParseDuration(text)
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeInvalidArgument, "parse --anchor-ots-upgrade-timeout", err)
		}
		if d <= 0 {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "--anchor-ots-upgrade-timeout must be > 0")
		}
		timeout = d
	}
	upgrader, err := anchor.NewOtsUpgrader(anchor.UpgraderConfig{
		Store:        store,
		Metrics:      metrics,
		Logger:       rt.logger,
		PollInterval: interval,
		BatchSize:    p.BatchSize,
		Workers:      p.Workers,
		HTTPOptions:  anchor.OtsUpgradeOptions{Timeout: timeout},
	})
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeInternal, "build ots upgrader", err)
	}
	rt.logger.Info().
		Dur("interval", interval).
		Int("batch_size", p.BatchSize).
		Dur("per_calendar_timeout", timeout).
		Msg("anchor: OTS upgrader enabled")
	return upgrader, nil
}

// newGlobalLogEnqueueHook persists a durable append event for every committed
// batch root. The slower global-log append and STH anchor enqueue happen in a
// separate worker so batch commit never waits on transparency-log IO.
func newGlobalLogEnqueueHook(rt *runtimeConfig, store proofstore.Store, worker *globallog.OutboxWorker) func(context.Context, model.BatchRoot) {
	return func(ctx context.Context, root model.BatchRoot) {
		if err := validateGlobalLogOutboxRoot(root); err != nil {
			rt.logger.Error().Err(err).Str("batch_id", root.BatchID).Msg("global log outbox enqueue rejected")
			return
		}
		item := model.GlobalLogOutboxItem{
			SchemaVersion: model.SchemaGlobalLogOutbox,
			BatchID:       root.BatchID,
			BatchRoot:     root,
			Status:        model.AnchorStatePending,
		}
		if err := store.EnqueueGlobalLog(ctx, item); err != nil {
			if trusterr.CodeOf(err) == trusterr.CodeAlreadyExists {
				return
			}
			rt.logger.Warn().Err(err).Str("batch_id", root.BatchID).Msg("global log outbox enqueue failed")
			return
		}
		if worker != nil {
			worker.Trigger()
		}
	}
}

func backfillGlobalLogOutbox(ctx context.Context, store proofstore.Store) (int, error) {
	var enqueued int
	var cursor int64
	const pageSize = 1024
	for {
		roots, err := store.ListRootsAfter(ctx, cursor, pageSize)
		if err != nil {
			return enqueued, err
		}
		if len(roots) == 0 {
			return enqueued, nil
		}
		for _, root := range roots {
			cursor = root.ClosedAtUnixN
			if err := validateGlobalLogOutboxRoot(root); err != nil {
				return enqueued, err
			}
			if _, ok, err := store.GetGlobalLeafByBatchID(ctx, root.BatchID); err != nil {
				return enqueued, err
			} else if ok {
				continue
			}
			if _, ok, err := store.GetGlobalLogOutboxItem(ctx, root.BatchID); err != nil {
				return enqueued, err
			} else if ok {
				continue
			}
			item := model.GlobalLogOutboxItem{
				SchemaVersion: model.SchemaGlobalLogOutbox,
				BatchID:       root.BatchID,
				BatchRoot:     root,
				Status:        model.AnchorStatePending,
			}
			if err := store.EnqueueGlobalLog(ctx, item); err != nil {
				if trusterr.CodeOf(err) == trusterr.CodeAlreadyExists {
					continue
				}
				return enqueued, err
			}
			enqueued++
		}
	}
}

func validateGlobalLogOutboxRoot(root model.BatchRoot) error {
	if strings.TrimSpace(root.NodeID) == "" || strings.TrimSpace(root.LogID) == "" {
		return trusterr.New(trusterr.CodeDataLoss, "global log batch root is missing node_id or log_id")
	}
	return nil
}

// restoreBatchSeq seeds the batch worker's in-memory seq counter
// from the latest persisted BatchRoot, so the "-NNNNNN" suffix on
// batch_id keeps moving forward across server restarts instead of
// resetting to -000001 every time. A fresh deployment (no roots
// yet) and unparsable historical IDs both fall through to 0, which
// is the legacy behaviour. We never fail startup over this — at
// worst we get a duplicated suffix on the first batch, which is
// what we have today, so any error here is strictly an upgrade.
func restoreBatchSeq(ctx context.Context, rt *runtimeConfig, store proofstore.Store) uint64 {
	if store == nil {
		return 0
	}
	root, err := store.LatestRoot(ctx)
	if err != nil {
		if code := trusterr.CodeOf(err); code != trusterr.CodeNotFound {
			rt.logger.Warn().Err(err).Msg("restore batch seq: latest root lookup failed; starting from 0")
		}
		return 0
	}
	seq, ok := batch.ParseBatchSeq(root.BatchID)
	if !ok {
		rt.logger.Warn().Str("batch_id", root.BatchID).Msg("restore batch seq: unparsable batch_id; starting from 0")
		return 0
	}
	rt.logger.Info().Str("batch_id", root.BatchID).Uint64("restored_seq", seq).Msg("batch seq restored from latest root")
	return seq
}

// newPruneHook returns a batch.Service OnCheckpointAdvanced callback that
// deletes WAL segments the committed checkpoint has already covered, with a
// `keepSegments` safety buffer so operators can retain a local audit window.
// The hook updates the segments gauge + bytes-pruned counter so dashboards
// can verify pruning is actually happening. Errors are logged only — they
// never propagate back into the batch pipeline because correctness of the
// committed batch does not depend on prune succeeding.
func newPruneHook(rt *runtimeConfig, walDir string, keepSegments int, metrics *observability.Metrics) func(context.Context, model.WALCheckpoint) {
	return newPruneHookWithPruner(rt, walDir, keepSegments, metrics, wal.PruneSegmentsBefore)
}

type pruneSegmentsFunc func(string, uint64) (int, int64, error)

func newPruneHookWithPruner(rt *runtimeConfig, walDir string, keepSegments int, metrics *observability.Metrics, prune pruneSegmentsFunc) func(context.Context, model.WALCheckpoint) {
	refreshSegments := func() {
		if err := refreshWALSegmentsTotal(metrics, walDir); err != nil {
			rt.logger.Warn().Err(err).Str("wal", walDir).Msg("wal segment metric refresh failed")
		}
	}
	var (
		pruneMu              sync.Mutex
		lastSuccessfulCutoff uint64
	)
	pruneOnce := func(cutoff uint64) (removed int, bytesRemoved int64, skipped bool, err error) {
		pruneMu.Lock()
		defer pruneMu.Unlock()
		if cutoff <= lastSuccessfulCutoff {
			return 0, 0, true, nil
		}
		removed, bytesRemoved, err = prune(walDir, cutoff)
		if err == nil {
			lastSuccessfulCutoff = cutoff
		}
		return removed, bytesRemoved, false, err
	}
	return func(_ context.Context, cp model.WALCheckpoint) {
		if cp.SegmentID <= 1 {
			return
		}
		cutoff := cp.SegmentID
		if keepSegments > 0 {
			if uint64(keepSegments) >= cp.SegmentID {
				return
			}
			cutoff = cp.SegmentID - uint64(keepSegments)
		}
		removed, bytesRemoved, skipped, err := pruneOnce(cutoff)
		if skipped {
			return
		}
		if err != nil {
			rt.logger.Warn().
				Err(err).
				Uint64("cutoff", cutoff).
				Str("wal", walDir).
				Msg("wal segment prune failed")
			return
		}
		// Refresh even when removed == 0. The last event before a scrape
		// might have been a rotate, and an idempotent prune should still
		// converge the gauge to the actual on-disk segment count.
		refreshSegments()
		if removed > 0 {
			if metrics != nil {
				metrics.WALBytesPrunedTotal.Add(float64(bytesRemoved))
			}
			rt.logger.Info().
				Int("segments_removed", removed).
				Int64("bytes_removed", bytesRemoved).
				Uint64("cutoff_segment_id", cutoff).
				Msg("wal segments pruned")
		}
	}
}

func refreshWALSegmentsTotal(metrics *observability.Metrics, walDir string) error {
	if metrics == nil {
		return nil
	}
	segs, err := wal.ListSegments(walDir)
	if err != nil {
		return err
	}
	metrics.WALSegmentsTotal.Set(float64(len(segs)))
	return nil
}

func walDurabilityProfile(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case wal.FsyncStrict:
		return "strict"
	case wal.FsyncBatch:
		return "unsafe_batch"
	default:
		return "bounded_group"
	}
}

func logServeRunProfile(rt *runtimeConfig, metastoreBackend, anchorSink string) {
	canonical := trustconfig.NormalizeRunProfile(rt.cfg.RunProfile)
	if strings.TrimSpace(rt.cfg.RunProfile) == "" {
		rt.logger.Info().Msg("config run_profile is unset — deployment treated as custom; labelled templates live under configs/")
		return
	}
	if canonical == "" {
		return
	}
	if title := trustconfig.RunProfileStartupTitle(canonical); title != "" {
		rt.logger.Info().
			Str("run_profile", canonical).
			Str("run_profile_raw", strings.TrimSpace(rt.cfg.RunProfile)).
			Msg(title)
	}
	for _, w := range trustconfig.RunProfileWarnings(canonical, metastoreBackend, anchorSink) {
		rt.logger.Warn().Str("run_profile", canonical).Msg(w)
	}
}

func semanticProfile(walMode, proofMode, recordIndexMode, artifactSyncMode string, globalLogEnabled bool) string {
	if walDurabilityProfile(walMode) == "unsafe_batch" {
		return "unsafe_high_write"
	}
	if proofMode != batch.ProofModeInline || recordIndexMode != "full" || artifactSyncMode == "batch" || !globalLogEnabled {
		return "bounded_high_write"
	}
	return "safe_default"
}

func normalizeSemanticProofMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", batch.ProofModeInline:
		return batch.ProofModeInline
	case batch.ProofModeAsync:
		return batch.ProofModeAsync
	case batch.ProofModeOnDemand:
		return batch.ProofModeOnDemand
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func normalizeSemanticRecordIndexMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "full":
		return "full"
	case "no_storage_tokens":
		return "no_storage_tokens"
	case "time_only":
		return "time_only"
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func normalizeSemanticArtifactSyncMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "chunk":
		return "chunk"
	case "batch":
		return "batch"
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func validateSemanticModes(proofMode, recordIndexMode, artifactSyncMode string) error {
	switch strings.ToLower(strings.TrimSpace(proofMode)) {
	case batch.ProofModeInline, batch.ProofModeAsync, batch.ProofModeOnDemand:
	default:
		return trusterr.New(trusterr.CodeInvalidArgument, "batch proof mode must be inline, async, or on_demand")
	}
	switch strings.ToLower(strings.TrimSpace(recordIndexMode)) {
	case "full", "no_storage_tokens", "time_only":
	default:
		return trusterr.New(trusterr.CodeInvalidArgument, "proofstore record index mode must be full, no_storage_tokens, or time_only")
	}
	switch strings.ToLower(strings.TrimSpace(artifactSyncMode)) {
	case "chunk", "batch":
	default:
		return trusterr.New(trusterr.CodeInvalidArgument, "proofstore artifact sync mode must be chunk or batch")
	}
	return nil
}

// openWALWriter is the rotate-hook-free variant used by tests and existing
// callers that only care about mode selection. It forwards to the options
// form with just MaxSegmentBytes populated.
func openWALWriter(walPath string, maxSegmentBytes int64) (*wal.Writer, string, error) {
	return openWALWriterWithOptions(walPath, wal.Options{MaxSegmentBytes: maxSegmentBytes})
}

// openWALWriterWithOptions opens the server's segment-rotating WAL directory.
// Regular files fail closed: serve does not automatically adopt or migrate the
// old single-file layout.
func openWALWriterWithOptions(walPath string, opts wal.Options) (*wal.Writer, string, error) {
	if walPath == "" {
		return nil, "", trusterr.New(trusterr.CodeInvalidArgument, "wal path is required")
	}
	info, err := os.Stat(walPath)
	switch {
	case err == nil && info.IsDir():
		w, oerr := wal.OpenDirWriter(walPath, opts)
		return w, "directory", oerr
	case err == nil:
		return nil, "", trusterr.New(trusterr.CodeFailedPrecondition, "server wal path must be a directory: "+walPath)
	case errors.Is(err, os.ErrNotExist):
		w, oerr := wal.OpenDirWriter(walPath, opts)
		return w, "directory", oerr
	default:
		return nil, "", trusterr.Wrap(trusterr.CodeInternal, "stat wal path", err)
	}
}

func scanWALRecords(walPath string, minSegmentID uint64, visit func(wal.Record) error) error {
	info, err := os.Stat(walPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.IsDir() {
		return wal.ScanDirFrom(walPath, minSegmentID, visit)
	}
	return wal.Scan(walPath, visit)
}

func inspectWALSequenceBounds(walPath string) (uint64, uint64, error) {
	info, err := os.Stat(walPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	if info.IsDir() {
		inspection, err := wal.InspectDir(walPath)
		if err != nil {
			return 0, 0, err
		}
		return inspection.FirstSequence, inspection.LastSequence, nil
	}
	inspection, err := wal.Inspect(walPath)
	if err != nil {
		return 0, 0, err
	}
	return inspection.FirstSequence, inspection.LastSequence, nil
}

type preparedReplay struct {
	manifest model.BatchManifest
	items    []batch.Accepted
	index    map[string]int
	seen     map[string]struct{}
	count    int
}

const replayManifestStateCacheLimit = 256

// replayManifestCache bounds startup memory while avoiding one proofstore
// point read per WAL record. It is populated on demand in WAL order rather
// than preloaded from the manifest listing, which prevents a full replay with
// more than one cache window from evicting exactly the manifests needed next.
// Full manifests are retained because a committed state alone does not prove
// that an index points at the current record's leaf.
type replayManifestCache struct {
	manifests map[string]model.BatchManifest
	order     []string
	next      int
}

func newReplayManifestCache() *replayManifestCache {
	return &replayManifestCache{
		manifests: make(map[string]model.BatchManifest, replayManifestStateCacheLimit),
		order:     make([]string, 0, replayManifestStateCacheLimit),
	}
}

func (c *replayManifestCache) remember(manifest model.BatchManifest) {
	if manifest.BatchID == "" {
		return
	}
	if _, exists := c.manifests[manifest.BatchID]; exists {
		c.manifests[manifest.BatchID] = manifest
		return
	}
	if len(c.order) < replayManifestStateCacheLimit {
		c.order = append(c.order, manifest.BatchID)
		c.manifests[manifest.BatchID] = manifest
		return
	}
	evicted := c.order[c.next]
	delete(c.manifests, evicted)
	c.order[c.next] = manifest.BatchID
	c.next = (c.next + 1) % replayManifestStateCacheLimit
	c.manifests[manifest.BatchID] = manifest
}

func (c *replayManifestCache) lookup(ctx context.Context, store proofstore.Store, batchID string) (model.BatchManifest, error) {
	if manifest, ok := c.manifests[batchID]; ok {
		return manifest, nil
	}
	manifest, err := store.GetManifest(ctx, batchID)
	if err != nil {
		return model.BatchManifest{}, err
	}
	c.remember(manifest)
	return manifest, nil
}

func validateCommittedReplayIndex(ctx context.Context, store proofstore.Store, manifests *replayManifestCache, recordID string, idx model.RecordIndex) (model.BatchManifest, error) {
	if idx.RecordID != recordID || idx.BatchID == "" {
		return model.BatchManifest{}, trusterr.New(trusterr.CodeDataLoss, "record index does not identify its committed batch")
	}
	manifest, err := manifests.lookup(ctx, store, idx.BatchID)
	if err != nil {
		return model.BatchManifest{}, trusterr.Wrap(trusterr.CodeDataLoss, "load indexed batch manifest", err)
	}
	if manifest.BatchID != idx.BatchID || manifest.State != model.BatchStateCommitted {
		return model.BatchManifest{}, trusterr.New(trusterr.CodeDataLoss, "record index is not covered by its committed batch manifest")
	}
	if idx.BatchLeafIndex >= uint64(len(manifest.RecordIDs)) || manifest.RecordIDs[idx.BatchLeafIndex] != recordID {
		return model.BatchManifest{}, trusterr.New(trusterr.CodeDataLoss, "record index leaf does not match its committed batch manifest")
	}
	if manifest.TreeSize != uint64(len(manifest.RecordIDs)) {
		return model.BatchManifest{}, trusterr.New(trusterr.CodeDataLoss, "committed batch manifest tree size does not match its record membership")
	}
	return manifest, nil
}

func validateCommittedReplayRecord(ctx context.Context, store proofstore.Store, manifests *replayManifestCache, record wal.Record, item app.ReplayedAccepted, idx model.RecordIndex) (string, model.ProofBundle, error) {
	recordID := item.Record.RecordID
	manifest, err := validateCommittedReplayIndex(ctx, store, manifests, recordID, idx)
	if err != nil {
		return "", model.ProofBundle{}, err
	}
	bundle, err := store.GetBundle(ctx, recordID)
	if err != nil {
		return "", model.ProofBundle{}, trusterr.Wrap(trusterr.CodeDataLoss, "load indexed proof bundle", err)
	}
	if bundle.RecordID != recordID || bundle.ServerRecord.RecordID != recordID ||
		bundle.AcceptedReceipt.RecordID != recordID || bundle.CommittedReceipt.RecordID != recordID {
		return "", model.ProofBundle{}, trusterr.New(trusterr.CodeDataLoss, "proof bundle record identity does not match the wal record")
	}
	if bundle.CommittedReceipt.BatchID != idx.BatchID || bundle.CommittedReceipt.LeafIndex != idx.BatchLeafIndex {
		return "", model.ProofBundle{}, trusterr.New(trusterr.CodeDataLoss, "proof bundle commitment does not match the record index")
	}
	if bundle.BatchProof.LeafIndex != idx.BatchLeafIndex || bundle.BatchProof.TreeSize != manifest.TreeSize ||
		!bytes.Equal(bundle.CommittedReceipt.BatchRoot, manifest.BatchRoot) {
		return "", model.ProofBundle{}, trusterr.New(trusterr.CodeDataLoss, "proof bundle commitment does not match its committed batch manifest")
	}
	if bundle.ServerRecord.WAL != record.Position || bundle.AcceptedReceipt.WAL != record.Position || item.Record.WAL != record.Position || item.Accepted.WAL != record.Position {
		return "", model.ProofBundle{}, trusterr.New(trusterr.CodeDataLoss, "proof bundle wal position does not match the replayed record")
	}
	if bundle.ServerRecord.TenantID != item.Record.TenantID ||
		bundle.ServerRecord.ClientID != item.Record.ClientID ||
		bundle.ServerRecord.KeyID != item.Record.KeyID ||
		bundle.ServerRecord.ReceivedAtUnixN != item.Record.ReceivedAtUnixN ||
		!bytes.Equal(bundle.ServerRecord.ClaimHash, item.Record.ClaimHash) {
		return "", model.ProofBundle{}, trusterr.New(trusterr.CodeDataLoss, "proof bundle server record does not match the replayed claim")
	}
	if err := validateProofBundleClaim(bundle); err != nil {
		return "", model.ProofBundle{}, err
	}
	leafHash, err := merkle.HashLeaf(bundle.ServerRecord)
	if err != nil {
		return "", model.ProofBundle{}, trusterr.Wrap(trusterr.CodeDataLoss, "hash replay proof bundle leaf", err)
	}
	if !bytes.Equal(leafHash, bundle.CommittedReceipt.LeafHash) ||
		!merkle.Verify(leafHash, idx.BatchLeafIndex, manifest.TreeSize, bundle.BatchProof.AuditPath, manifest.BatchRoot) {
		return "", model.ProofBundle{}, trusterr.New(trusterr.CodeDataLoss, "proof bundle merkle path does not match its committed batch manifest")
	}
	return idx.BatchID, bundle, nil
}

func validateTrustedCheckpointBoundaryRecord(ctx context.Context, engine app.LocalEngine, store proofstore.Store, manifests *replayManifestCache, checkpoint model.WALCheckpoint, record wal.Record) error {
	if record.Position.Sequence != checkpoint.LastSequence ||
		record.Position.SegmentID != checkpoint.SegmentID ||
		record.Position.Offset != checkpoint.LastOffset {
		return trusterr.New(trusterr.CodeDataLoss, "contiguous wal checkpoint does not match the retained wal boundary")
	}
	item, err := engine.ReplayAccepted(ctx, record)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "decode contiguous wal checkpoint boundary", err)
	}
	idx, ok, err := store.GetRecordIndex(ctx, item.Record.RecordID)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "load contiguous wal checkpoint boundary index", err)
	}
	if !ok {
		return trusterr.New(trusterr.CodeDataLoss, "contiguous wal checkpoint boundary has no committed record index")
	}
	batchID, bundle, err := validateCommittedReplayRecord(ctx, store, manifests, record, item, idx)
	if err != nil {
		return err
	}
	if checkpoint.BatchID != "" && checkpoint.BatchID != batchID {
		return trusterr.New(trusterr.CodeDataLoss, "contiguous wal checkpoint batch does not match its boundary proof")
	}
	if err := validateDurableReplayDecision(ctx, engine, item, &bundle, batchID, true); err != nil {
		return err
	}
	return nil
}

func validateDurableReplayDecision(ctx context.Context, engine app.LocalEngine, item app.ReplayedAccepted, bundle *model.ProofBundle, batchID string, committed bool) error {
	if engine.DurableIdempotency == nil || item.Signed.Claim.IdempotencyKey == "" {
		return nil
	}
	identity := model.IdempotencyIdentity{
		TenantID:       item.Signed.Claim.TenantID,
		ClientID:       item.Signed.Claim.ClientID,
		IdempotencyKey: item.Signed.Claim.IdempotencyKey,
	}
	decision, found, err := engine.DurableIdempotency.GetIdempotencyDecision(ctx, identity)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "read replay idempotency decision", err)
	}
	if !committed {
		if found {
			return trusterr.New(trusterr.CodeDataLoss, "uncommitted wal record has a durable idempotency decision")
		}
		return nil
	}
	if !found {
		return trusterr.New(trusterr.CodeDataLoss, "committed wal record is missing its durable idempotency decision")
	}
	if bundle == nil {
		return trusterr.New(trusterr.CodeDataLoss, "committed wal record has no persisted proof bundle")
	}
	expected, err := idempotency.BuildDecision(batchID, bundle.SignedClaim, bundle.ServerRecord, bundle.AcceptedReceipt)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "build replay idempotency decision", err)
	}
	if !idempotency.Equivalent(decision, expected) {
		return trusterr.New(trusterr.CodeDataLoss, "committed wal record conflicts with its durable idempotency decision")
	}
	return nil
}

func validateProofBundleClaim(bundle model.ProofBundle) error {
	signed := bundle.SignedClaim
	record := bundle.ServerRecord
	accepted := bundle.AcceptedReceipt
	if signed.SchemaVersion != model.SchemaSignedClaim ||
		signed.Claim.SchemaVersion != model.SchemaClientClaim ||
		record.SchemaVersion != model.SchemaServerRecord ||
		accepted.SchemaVersion != model.SchemaAcceptedReceipt ||
		signed.Signature.KeyID != signed.Claim.KeyID ||
		record.TenantID != signed.Claim.TenantID ||
		record.ClientID != signed.Claim.ClientID ||
		record.KeyID != signed.Claim.KeyID ||
		accepted.ReceivedAtUnixN != record.ReceivedAtUnixN {
		return trusterr.New(trusterr.CodeDataLoss, "checkpointed proof claim metadata does not match its server record")
	}
	claimCBOR, err := claim.Canonical(signed.Claim)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "canonicalize checkpointed proof claim", err)
	}
	claimHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, claimCBOR)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "hash checkpointed proof claim", err)
	}
	signatureHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, signed.Signature.Signature)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "hash checkpointed proof signature", err)
	}
	if claim.RecordID(claimCBOR, signed.Signature) != record.RecordID ||
		!bytes.Equal(claimHash, record.ClaimHash) ||
		!bytes.Equal(signatureHash, record.ClientSignatureHash) {
		return trusterr.New(trusterr.CodeDataLoss, "checkpointed proof claim is not bound to its server record")
	}
	return nil
}

func newPreparedReplay(manifest model.BatchManifest) *preparedReplay {
	p := &preparedReplay{
		manifest: manifest,
		items:    make([]batch.Accepted, len(manifest.RecordIDs)),
		index:    make(map[string]int, len(manifest.RecordIDs)),
		seen:     make(map[string]struct{}, len(manifest.RecordIDs)),
	}
	for i, rid := range manifest.RecordIDs {
		p.index[rid] = i
	}
	return p
}

func (p *preparedReplay) add(item batch.Accepted) {
	rid := item.Record.RecordID
	if _, ok := p.seen[rid]; ok {
		return
	}
	i, ok := p.index[rid]
	if !ok {
		return
	}
	p.items[i] = item
	p.seen[rid] = struct{}{}
	p.count++
}

func (p *preparedReplay) missingRecordID() string {
	for _, rid := range p.manifest.RecordIDs {
		if _, ok := p.seen[rid]; !ok {
			return rid
		}
	}
	return ""
}

func loadManifestItemsFromWAL(ctx context.Context, walPath string, engine app.LocalEngine, manifest model.BatchManifest) ([]batch.Accepted, error) {
	prepared := newPreparedReplay(manifest)
	minSegmentID := manifest.WALRange.From.SegmentID
	if minSegmentID == 0 {
		minSegmentID = 1
	}
	err := scanWALRecords(walPath, minSegmentID, func(record wal.Record) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if manifest.WALRange.From.Sequence > 0 && record.Position.Sequence < manifest.WALRange.From.Sequence {
			return nil
		}
		if manifest.WALRange.To.Sequence > 0 && record.Position.Sequence > manifest.WALRange.To.Sequence {
			return errStopManifestScan
		}
		replayed, err := engine.ReplayAccepted(ctx, record)
		if err != nil {
			return err
		}
		prepared.add(batch.Accepted{
			Signed:   replayed.Signed,
			Record:   replayed.Record,
			Accepted: replayed.Accepted,
		})
		if prepared.count == len(prepared.items) {
			return errStopManifestScan
		}
		return nil
	})
	if errors.Is(err, errStopManifestScan) {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	if missing := prepared.missingRecordID(); missing != "" {
		return nil, trusterr.New(trusterr.CodeDataLoss, "manifest "+manifest.BatchID+" missing WAL record "+missing)
	}
	return prepared.items, nil
}

var errStopManifestScan = errors.New("stop manifest scan")

// replayWALAccepted brings the local proof store back to a consistent state
// after a restart:
//  1. Rebuild every accepted record from the WAL so each record_id maps to a
//     deterministic Signed/Record/Accepted triple. The WAL checkpoint (if
//     present) lets us skip expensive ReplayAccepted work for records that
//     are already covered by a committed batch.
//  2. Finish any manifest that was prepared but never marked committed, which
//     may involve re-writing bundles and the batch root so a crash between
//     those steps converges to the same final artifacts.
//  3. Enqueue records that are not yet covered by any committed manifest into
//     the live batch service so they can be included in a fresh batch.
func replayWALAccepted(ctx context.Context, walPath string, engine app.LocalEngine, batchSvc *batch.Service, store proofstore.Store, metrics *observability.Metrics) (int, int, int, error) {
	// Recovered batches can commit on the live worker while this function is
	// still scanning. Defer checkpoint persistence (and therefore pruning)
	// across the entire scan and prepared-manifest recovery window.
	batchSvc.DeferCheckpointAdvance()
	checkpointSafe := proofstore.WALCheckpointPruneSafe(store)
	checkpoint, foundCheckpoint, err := store.GetCheckpoint(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	if foundCheckpoint && checkpoint.SchemaVersion != "" &&
		checkpoint.SchemaVersion != model.SchemaWALCheckpoint &&
		checkpoint.SchemaVersion != model.SchemaWALCheckpointContiguous {
		return 0, 0, 0, trusterr.New(trusterr.CodeFailedPrecondition, "unsupported wal checkpoint schema: "+checkpoint.SchemaVersion)
	}
	// v1 checkpoints were derived from batch min/max envelopes and could leap
	// across gaps. Only a positive v2 value certifies a skippable committed
	// prefix. A v2 zero marker is valid migration state, but still requires the
	// retained WAL to begin at sequence one.
	trustedCheckpoint := checkpointSafe && foundCheckpoint && checkpoint.SchemaVersion == model.SchemaWALCheckpointContiguous
	hasCheckpoint := trustedCheckpoint && checkpoint.LastSequence > 0
	legacyCheckpoint := checkpointSafe && foundCheckpoint && checkpoint.SchemaVersion != model.SchemaWALCheckpointContiguous
	requireFullPrefix := !hasCheckpoint
	if hasCheckpoint && checkpoint.LastSequence > 0 && (checkpoint.SegmentID == 0 || checkpoint.LastOffset < 0) {
		return 0, 0, 0, trusterr.New(trusterr.CodeDataLoss, "contiguous wal checkpoint has an invalid position")
	}
	// A non-zero legacy marker needs tail validation before replay can enqueue
	// anything. This intentionally rare migration path may inspect the WAL
	// twice; normal no-checkpoint and checkpoint-unsafe startup stay single-pass.
	if legacyCheckpoint && checkpoint.LastSequence > 0 {
		firstSequence, lastSequence, err := inspectWALSequenceBounds(walPath)
		if err != nil {
			return 0, 0, 0, trusterr.Wrap(trusterr.CodeDataLoss, "inspect wal before legacy checkpoint migration", err)
		}
		if firstSequence > 1 {
			return 0, 0, 0, trusterr.New(trusterr.CodeDataLoss, "legacy wal checkpoint cannot be revalidated because the retained wal prefix is missing")
		}
		if firstSequence == 0 {
			return 0, 0, 0, trusterr.New(trusterr.CodeDataLoss, "legacy wal checkpoint cannot be revalidated because the retained wal is empty")
		}
		if checkpoint.LastSequence > lastSequence {
			return 0, 0, 0, trusterr.New(trusterr.CodeDataLoss, "legacy wal checkpoint cannot be revalidated beyond the retained wal tail")
		}
	}
	// In directory mode we can skip entire segments that a committed
	// checkpoint already covers. Legacy single-file WALs still go through
	// the record-level skip below because they cannot skip by segment.
	// Reading the checkpoint before the WAL also means a crash while
	// appending a new segment cannot trick us into scanning deleted files.
	var minSegmentID uint64
	if hasCheckpoint && checkpoint.LastSequence > 0 {
		minSegmentID = checkpoint.SegmentID
	}
	if metrics != nil && hasCheckpoint {
		// Seed the gauge before replay so operators can see the checkpoint
		// position even if no new batches commit after startup.
		metrics.WALCheckpointLastSequence.Set(float64(checkpoint.LastSequence))
	}

	preparedByRecordID := make(map[string]*preparedReplay)
	failedByRecordID := make(map[string]struct{})
	manifestCache := newReplayManifestCache()
	var preparedManifests []*preparedReplay
	var recovered int
	for afterBatchID := ""; ; {
		manifests, err := store.ListManifestsAfter(ctx, afterBatchID, 1024)
		if err != nil {
			return 0, 0, 0, err
		}
		if len(manifests) == 0 {
			break
		}
		for _, manifest := range manifests {
			if manifest.State == model.BatchStateCommitted {
				continue
			}
			if manifest.State == model.BatchStateFailed {
				for _, rid := range manifest.RecordIDs {
					if _, exists := preparedByRecordID[rid]; exists {
						return recovered, 0, 0, trusterr.New(trusterr.CodeFailedPrecondition, "record "+rid+" appears in both failed and prepared manifests")
					}
					if _, exists := failedByRecordID[rid]; exists {
						return recovered, 0, 0, trusterr.New(trusterr.CodeFailedPrecondition, "record "+rid+" appears in more than one failed manifest")
					}
					failedByRecordID[rid] = struct{}{}
				}
				continue
			}
			if manifest.State != model.BatchStatePreparing && manifest.State != model.BatchStatePrepared {
				return recovered, 0, 0, trusterr.New(trusterr.CodeFailedPrecondition, "unknown batch manifest state: "+manifest.State)
			}
			// A prepared manifest whose WAL range is entirely below the
			// checkpoint is stale: a later committed manifest already
			// superseded it and advanced the checkpoint past it. Treat it as
			// committed so we don't attempt to RecoverManifest with items we
			// purposefully skipped above.
			if hasCheckpoint && manifest.WALRange.To.Sequence > 0 && manifest.WALRange.To.Sequence <= checkpoint.LastSequence {
				continue
			}
			prepared := newPreparedReplay(manifest)
			for _, rid := range manifest.RecordIDs {
				if _, exists := failedByRecordID[rid]; exists {
					return recovered, 0, 0, trusterr.New(trusterr.CodeFailedPrecondition, "record "+rid+" appears in both failed and prepared manifests")
				}
				if _, exists := preparedByRecordID[rid]; exists {
					return recovered, 0, 0, trusterr.New(trusterr.CodeFailedPrecondition, "record "+rid+" appears in more than one prepared manifest")
				}
				preparedByRecordID[rid] = prepared
			}
			preparedManifests = append(preparedManifests, prepared)
		}
		afterBatchID = manifests[len(manifests)-1].BatchID
	}

	var replayed int
	var skipped int
	var firstRetainedSequence uint64
	var lastRetainedSequence uint64
	var committedRunFrom model.WALPosition
	var committedRunTo model.WALPosition
	var committedRunBatchID string
	var localRecordIDs map[string]struct{}
	checkpointBoundaryValidated := !hasCheckpoint
	flushCommittedRun := func() error {
		if committedRunFrom.Sequence == 0 {
			return nil
		}
		err := batchSvc.RecordCommittedWALRange(ctx, committedRunFrom, committedRunTo, committedRunBatchID)
		committedRunFrom = model.WALPosition{}
		committedRunTo = model.WALPosition{}
		committedRunBatchID = ""
		return err
	}
	if err := scanWALRecords(walPath, minSegmentID, func(record wal.Record) error {
		if firstRetainedSequence == 0 {
			firstRetainedSequence = record.Position.Sequence
			if requireFullPrefix && firstRetainedSequence != 1 {
				return trusterr.New(trusterr.CodeDataLoss, "wal cannot be fully replayed because the retained prefix is missing")
			}
		}
		lastRetainedSequence = record.Position.Sequence
		// Records at or below the checkpoint are guaranteed to be covered
		// by a committed manifest, so ReplayAccepted (CBOR decode + receipt
		// re-signing) can be skipped. Durable restart idempotency is handled
		// separately from this recovery optimization.
		if hasCheckpoint && record.Position.Sequence <= checkpoint.LastSequence {
			if record.Position.Sequence == checkpoint.LastSequence {
				if err := validateTrustedCheckpointBoundaryRecord(ctx, engine, store, manifestCache, checkpoint, record); err != nil {
					return err
				}
				checkpointBoundaryValidated = true
			}
			skipped++
			return nil
		}
		if !checkpointBoundaryValidated {
			return trusterr.New(trusterr.CodeDataLoss, "contiguous wal checkpoint boundary is missing from the retained wal")
		}
		item, err := engine.ReplayAccepted(ctx, record)
		if err != nil {
			return err
		}
		accepted := batch.Accepted{Signed: item.Signed, Record: item.Record, Accepted: item.Accepted}
		idempotencyKey := app.IdempotencyKey(item.Signed.Claim.TenantID, item.Signed.Claim.ClientID, item.Signed.Claim.IdempotencyKey)
		if idempotencyKey == "" {
			if localRecordIDs == nil {
				localRecordIDs = make(map[string]struct{})
			}
			if _, exists := localRecordIDs[item.Record.RecordID]; exists {
				return trusterr.New(trusterr.CodeDataLoss, "record id appears at conflicting local wal positions")
			}
			localRecordIDs[item.Record.RecordID] = struct{}{}
			idempotencyKey = app.RecordIDKey(item.Record.RecordID)
		}
		if engine.Idempotency != nil {
			if !engine.Idempotency.Restore(idempotencyKey, item.Record, item.Accepted, item.Record.ClaimHash) {
				return trusterr.New(trusterr.CodeDataLoss, "wal idempotency key maps to conflicting accepted records")
			}
		}
		if prepared := preparedByRecordID[item.Record.RecordID]; prepared != nil {
			if err := flushCommittedRun(); err != nil {
				return err
			}
			if err := validateDurableReplayDecision(ctx, engine, item, nil, "", false); err != nil {
				return err
			}
			prepared.add(accepted)
			return nil
		}
		if _, failed := failedByRecordID[item.Record.RecordID]; failed {
			if err := flushCommittedRun(); err != nil {
				return err
			}
			if err := validateDurableReplayDecision(ctx, engine, item, nil, "", false); err != nil {
				return err
			}
			skipped++
			return nil
		}
		if idx, ok, err := store.GetRecordIndex(ctx, item.Record.RecordID); err != nil {
			return err
		} else if ok {
			if idx.RecordID != item.Record.RecordID || idx.BatchID == "" {
				return trusterr.New(trusterr.CodeDataLoss, "record index does not identify its committed batch")
			}
			batchID := idx.BatchID
			var committedBundle *model.ProofBundle
			if checkpointSafe || engine.DurableIdempotency != nil {
				validatedBatchID, bundle, validateErr := validateCommittedReplayRecord(ctx, store, manifestCache, record, item, idx)
				batchID, err = validatedBatchID, validateErr
				if err != nil {
					return err
				}
				committedBundle = &bundle
			} else if _, err := validateCommittedReplayIndex(ctx, store, manifestCache, item.Record.RecordID, idx); err != nil {
				return err
			}
			if err := validateDurableReplayDecision(ctx, engine, item, committedBundle, batchID, true); err != nil {
				return err
			}
			if engine.Idempotency != nil {
				engine.Idempotency.ForgetCommitted(idempotencyKey, item.Record.RecordID)
			}
			if !checkpointSafe {
				skipped++
				return nil
			}
			if committedRunFrom.Sequence == 0 {
				committedRunFrom = record.Position
				committedRunTo = record.Position
				committedRunBatchID = batchID
			} else if committedRunTo.Sequence != ^uint64(0) && record.Position.Sequence == committedRunTo.Sequence+1 {
				committedRunTo = record.Position
				committedRunBatchID = batchID
			} else {
				if record.Position.Sequence <= committedRunTo.Sequence {
					return trusterr.New(trusterr.CodeDataLoss, "wal replay sequence is not strictly increasing")
				}
				if err := flushCommittedRun(); err != nil {
					return err
				}
				committedRunFrom = record.Position
				committedRunTo = record.Position
				committedRunBatchID = batchID
			}
			skipped++
			return nil
		}
		if err := flushCommittedRun(); err != nil {
			return err
		}
		if err := validateDurableReplayDecision(ctx, engine, item, nil, "", false); err != nil {
			return err
		}
		if err := batchSvc.EnqueueRecovered(ctx, accepted); err != nil {
			return err
		}
		replayed++
		return nil
	}); err != nil {
		return recovered, replayed, skipped, err
	}
	if err := flushCommittedRun(); err != nil {
		return recovered, replayed, skipped, err
	}
	if !checkpointBoundaryValidated {
		return recovered, replayed, skipped, trusterr.New(trusterr.CodeDataLoss, "contiguous wal checkpoint boundary is missing from the retained wal")
	}
	if requireFullPrefix && firstRetainedSequence == 0 && foundCheckpoint && checkpoint.LastSequence > 0 {
		return recovered, replayed, skipped, trusterr.New(trusterr.CodeDataLoss, "wal cannot be fully replayed because the retained wal is empty")
	}
	if legacyCheckpoint && checkpoint.LastSequence > lastRetainedSequence {
		return recovered, replayed, skipped, trusterr.New(trusterr.CodeDataLoss, "legacy wal checkpoint cannot be revalidated beyond the retained wal tail")
	}

	for _, prepared := range preparedManifests {
		if prepared.count != len(prepared.manifest.RecordIDs) {
			return recovered, replayed, skipped, trusterr.New(trusterr.CodeFailedPrecondition, "prepared manifest "+prepared.manifest.BatchID+" references missing record "+prepared.missingRecordID())
		}
		if err := batchSvc.RecoverManifest(ctx, prepared.manifest, prepared.items); err != nil {
			return recovered, replayed, skipped, err
		}
		skipped += len(prepared.manifest.RecordIDs)
		recovered++
	}
	// Checkpoint persistence is best-effort. A failed flush remains dirty in
	// the service and is retried by the next committed batch; replayed records
	// are still correct and the unpruned WAL remains the recovery source.
	if err := batchSvc.StartCheckpointAdvance(ctx); err != nil && legacyCheckpoint {
		return recovered, replayed, skipped, trusterr.Wrap(trusterr.CodeDataLoss, "persist migrated wal checkpoint", err)
	}
	if metrics != nil {
		if skipped > 0 {
			metrics.WALReplayRecords.WithLabelValues("skipped").Add(float64(skipped))
		}
		if replayed > 0 {
			metrics.WALReplayRecords.WithLabelValues("replayed").Add(float64(replayed))
		}
		if recovered > 0 {
			metrics.WALReplayRecords.WithLabelValues("recovered").Add(float64(recovered))
		}
	}
	return recovered, replayed, skipped, nil
}

func stringOrLiteral(cmd *cobra.Command, flagName, flagValue, fallback string) string {
	if cmd.Flags().Changed(flagName) {
		return flagValue
	}
	return fallback
}

func splitCSV(text string) []string {
	parts := strings.Split(text, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
