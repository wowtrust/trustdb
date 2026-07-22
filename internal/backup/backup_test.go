package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/globallog"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestBackupCreateVerifyRestoreRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	src := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "src")}
	bundle := model.ProofBundle{
		SchemaVersion: model.SchemaProofBundle,
		RecordID:      "record-1",
		CommittedReceipt: model.CommittedReceipt{
			BatchID:   "batch-1",
			BatchRoot: repeatByte(0x44, 32),
		},
		BatchProof: model.BatchProof{TreeSize: 1},
	}
	if err := src.PutBundle(ctx, bundle); err != nil {
		t.Fatalf("PutBundle: %v", err)
	}
	if err := src.PutManifest(ctx, model.BatchManifest{
		SchemaVersion: model.SchemaBatchManifest,
		BatchID:       "batch-1",
		State:         model.BatchStateCommitted,
		TreeSize:      1,
		BatchRoot:     repeatByte(0x44, 32),
		RecordIDs:     []string{"record-1"},
		ClosedAtUnixN: 1,
	}); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	root := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       "batch-1",
		BatchRoot:     repeatByte(0x44, 32),
		TreeSize:      1,
		ClosedAtUnixN: 1,
	}
	if err := src.PutRoot(ctx, root); err != nil {
		t.Fatalf("PutRoot: %v", err)
	}
	if err := src.EnqueueGlobalLog(ctx, model.GlobalLogOutboxItem{
		SchemaVersion: model.SchemaGlobalLogOutbox,
		BatchID:       root.BatchID,
		BatchRoot:     root,
		Status:        model.AnchorStatePending,
	}); err != nil {
		t.Fatalf("EnqueueGlobalLog: %v", err)
	}

	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	globalSvc, err := globallog.New(globallog.Options{
		Store:      src,
		NodeID:     "node-1",
		LogID:      "backup-test",
		KeyID:      "backup-key",
		PrivateKey: priv,
		Clock:      func() time.Time { return time.Unix(10, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("globallog.New: %v", err)
	}
	sth, err := globalSvc.AppendBatchRoot(ctx, root)
	if err != nil {
		t.Fatalf("AppendBatchRoot: %v", err)
	}
	if _, err := globalSvc.CompactHistory(ctx, 1); err != nil {
		t.Fatalf("CompactHistory: %v", err)
	}
	resultWriter := any(src).(proofstore.STHAnchorResultWriter)
	if err := resultWriter.PutSTHAnchorResult(ctx, model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		NodeID:           sth.NodeID,
		LogID:            sth.LogID,
		TreeSize:         sth.TreeSize,
		SinkName:         "noop",
		AnchorID:         "noop-sth-1",
		RootHash:         sth.RootHash,
		STH:              sth,
		PublishedAtUnixN: 11,
	}); err != nil {
		t.Fatalf("PutSTHAnchorResult: %v", err)
	}
	if err := src.PutCheckpoint(ctx, model.WALCheckpoint{
		SchemaVersion:   model.SchemaWALCheckpoint,
		LastSequence:    42,
		RecordedAtUnixN: 12,
	}); err != nil {
		t.Fatalf("PutCheckpoint: %v", err)
	}

	path := filepath.Join(t.TempDir(), "trustdb.tdbackup")
	report, err := Create(ctx, src, path, Options{Compression: "gzip"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if report.SchemaVersion != SchemaManifest || report.BackupID == "" || len(report.Entries) == 0 {
		t.Fatalf("missing v4 manifest metadata: %+v", report)
	}
	if report.Bundles != 1 || report.Roots != 1 || report.GlobalLeaves != 1 || report.GlobalNodes == 0 || !report.GlobalState || report.STHs != 1 || report.GlobalOutboxes != 1 || report.AnchorResults != 1 {
		t.Fatalf("unexpected create report: %+v", report)
	}
	verified, err := Verify(ctx, path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.AnchorResults != 1 || verified.GlobalTiles != 1 {
		t.Fatalf("unexpected verify report: %+v", verified)
	}

	dst := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "dst")}
	checkpoint := filepath.Join(t.TempDir(), "restore.checkpoint.json")
	restored, err := RestoreWithOptions(ctx, dst, path, RestoreOptions{Resume: true, CheckpointPath: checkpoint})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if restored.Bundles != 1 || restored.GlobalLeaves != 1 || restored.GlobalNodes == 0 || !restored.GlobalState || restored.GlobalOutboxes != 1 || restored.AnchorResults != 1 {
		t.Fatalf("unexpected restore report: %+v", restored)
	}
	if _, err := os.Stat(checkpoint); err != nil {
		t.Fatalf("restore checkpoint not written: %v", err)
	}
	gotBundle, err := dst.GetBundle(ctx, "record-1")
	if err != nil {
		t.Fatalf("GetBundle restored: %v", err)
	}
	if gotBundle.RecordID != "record-1" {
		t.Fatalf("restored bundle = %+v", gotBundle)
	}
	if latest, err := dst.LatestRoot(ctx); err != nil || latest.BatchID != root.BatchID {
		t.Fatalf("LatestRoot restored latest=%+v err=%v", latest, err)
	}
	if _, ok, err := dst.GetSTHAnchorResult(ctx, 1); err != nil || !ok {
		t.Fatalf("GetSTHAnchorResult restored ok=%v err=%v", ok, err)
	}
	if _, ok, err := dst.GetGlobalLogState(ctx); err != nil || !ok {
		t.Fatalf("GetGlobalLogState restored ok=%v err=%v", ok, err)
	}
	if latest, ok, err := dst.LatestSignedTreeHead(ctx); err != nil || !ok || latest.TreeSize != sth.TreeSize {
		t.Fatalf("LatestSignedTreeHead restored latest=%+v ok=%v err=%v", latest, ok, err)
	}
	if _, ok, err := dst.GetGlobalLogOutboxItem(ctx, root.BatchID); err != nil || !ok {
		t.Fatalf("GetGlobalLogOutboxItem restored ok=%v err=%v", ok, err)
	}
	if checkpoint, ok, err := dst.GetCheckpoint(ctx); err != nil || ok {
		t.Fatalf("GetCheckpoint restored checkpoint=%+v ok=%v err=%v, want absent node-local state", checkpoint, ok, err)
	}
}

func TestBackupRoundTripPreservesAnchorScheduleAndIndependentResult(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "src")}
	scheduler, ok := any(src).(proofstore.STHAnchorScheduleStore)
	if !ok {
		t.Fatal("LocalStore does not implement STHAnchorScheduleStore")
	}
	resultWriter, ok := any(src).(proofstore.STHAnchorResultWriter)
	if !ok {
		t.Fatal("LocalStore does not implement STHAnchorResultWriter")
	}
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	firstSTH := backupScheduleSTH(key, 1, 0x11)
	if _, err := scheduler.UpsertSTHAnchorCandidate(ctx, model.STHAnchorCandidate{
		Key: key, STH: firstSTH, ObservedAtUnixN: 100, DueAtUnixN: 100,
	}); err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate first: %v", err)
	}
	firstAttempt, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, key, 100, 150, "worker-1", "lease-1")
	if err != nil || !claimed {
		t.Fatalf("ClaimSTHAnchorAttempt first claimed=%v err=%v", claimed, err)
	}
	firstResult := backupScheduleResult(key, firstSTH, "anchor-1", 110)
	if err := scheduler.CompleteSTHAnchorAttempt(ctx, key, firstAttempt.Generation, "lease-1", firstResult); err != nil {
		t.Fatalf("CompleteSTHAnchorAttempt first: %v", err)
	}

	inFlightSTH := backupScheduleSTH(key, 3, 0x33)
	if _, err := scheduler.UpsertSTHAnchorCandidate(ctx, model.STHAnchorCandidate{
		Key: key, STH: inFlightSTH, ObservedAtUnixN: 200, DueAtUnixN: 200,
	}); err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate in-flight: %v", err)
	}
	inFlightAttempt, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, key, 200, 250, "worker-2", "lease-2")
	if err != nil || !claimed {
		t.Fatalf("ClaimSTHAnchorAttempt in-flight claimed=%v err=%v", claimed, err)
	}
	if err := scheduler.RescheduleSTHAnchorAttempt(ctx, key, inFlightAttempt.Generation, "lease-2", 2, 300, "temporary outage"); err != nil {
		t.Fatalf("RescheduleSTHAnchorAttempt: %v", err)
	}
	if _, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, key, 300, 350, "worker-3", "lease-3"); err != nil || !claimed {
		t.Fatalf("ClaimSTHAnchorAttempt retry claimed=%v err=%v", claimed, err)
	}
	pendingSTH := backupScheduleSTH(key, 5, 0x55)
	if _, err := scheduler.UpsertSTHAnchorCandidate(ctx, model.STHAnchorCandidate{
		Key: key, STH: pendingSTH, ObservedAtUnixN: 310, DueAtUnixN: 410,
	}); err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate pending: %v", err)
	}
	// Exercise the backup capability directly: successful immutable results
	// must not depend on a legacy per-STH outbox entry being present.
	if err := resultWriter.PutSTHAnchorResult(ctx, firstResult); err != nil {
		t.Fatalf("PutSTHAnchorResult idempotent: %v", err)
	}
	secondSinkKey := key
	secondSinkKey.SinkName = "ots"
	secondSinkResult := backupScheduleResult(secondSinkKey, firstSTH, "anchor-1-ots", 111)
	if err := resultWriter.PutSTHAnchorResult(ctx, secondSinkResult); err != nil {
		t.Fatalf("PutSTHAnchorResult second sink: %v", err)
	}
	coverage := any(src).(proofstore.L5CoverageCheckpointStore)
	if _, err := coverage.AdvanceL5CoverageCheckpoint(ctx, key, 1, 120); err != nil {
		t.Fatalf("AdvanceL5CoverageCheckpoint: %v", err)
	}

	path := filepath.Join(t.TempDir(), "anchor-schedule.tdbackup")
	report, err := Create(ctx, src, path, Options{Compression: "none"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if report.AnchorResults != 2 || report.AnchorSchedules != 1 {
		t.Fatalf("backup report = %+v", report)
	}

	dst := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "dst")}
	restored, err := Restore(ctx, dst, path)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if restored.AnchorResults != 2 || restored.AnchorSchedules != 1 {
		t.Fatalf("restore report = %+v", restored)
	}
	restoredScheduler := any(dst).(proofstore.STHAnchorScheduleStore)
	schedule, found, err := restoredScheduler.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found {
		t.Fatalf("GetSTHAnchorSchedule found=%v err=%v", found, err)
	}
	if schedule.InFlight == nil || schedule.InFlight.Target.TreeSize != 3 || schedule.InFlight.Attempts != 2 || schedule.InFlight.NextAttemptUnixN != 300 || schedule.InFlight.LastAttemptUnixN != 300 || schedule.InFlight.LastErrorMessage != "temporary outage" {
		t.Fatalf("restored in-flight = %+v", schedule.InFlight)
	}
	if schedule.InFlight.LeaseOwner != "" || schedule.InFlight.LeaseToken != "" || schedule.InFlight.LeaseUntilUnixN != 0 {
		t.Fatalf("restored stale lease = %+v", schedule.InFlight)
	}
	if schedule.Pending == nil || schedule.Pending.Target.TreeSize != 5 || schedule.Pending.OpenedAtUnixN != 310 || schedule.Pending.DueAtUnixN != 410 {
		t.Fatalf("restored pending = %+v", schedule.Pending)
	}
	if result, found, err := dst.GetSTHAnchorResult(ctx, 1); err != nil || !found || result.AnchorID != "anchor-1" {
		t.Fatalf("restored independent result = %+v found=%v err=%v", result, found, err)
	}
	keyedReader := any(dst).(proofstore.STHAnchorResultKeyedReader)
	for _, tc := range []struct {
		key      model.STHAnchorScheduleKey
		anchorID string
	}{{key, "anchor-1"}, {secondSinkKey, "anchor-1-ots"}} {
		resultKey := model.STHAnchorResultKey{NodeID: tc.key.NodeID, LogID: tc.key.LogID, SinkName: tc.key.SinkName, TreeSize: 1}
		result, found, err := keyedReader.GetSTHAnchorResultForKey(ctx, resultKey)
		if err != nil || !found || result.AnchorID != tc.anchorID {
			t.Fatalf("restored keyed result %s = %+v found=%v err=%v", tc.key.SinkName, result, found, err)
		}
	}
	restoredCoverage := any(dst).(proofstore.L5CoverageCheckpointStore)
	if checkpoint, found, err := restoredCoverage.GetL5CoverageCheckpoint(ctx, key); err != nil || found {
		t.Fatalf("restored derived L5 checkpoint=%+v found=%v err=%v, want absent", checkpoint, found, err)
	}
}

func TestRestoreRejectsLegacySchemaBeforeApplyingEntries(t *testing.T) {
	t.Parallel()
	for _, schema := range []string{"trustdb.backup.v2", "trustdb.backup.v3"} {
		schema := schema
		t.Run(schema, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "legacy.tdbackup")
			f, err := os.Create(path)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			tw := tar.NewWriter(f)
			legacy := Manifest{
				SchemaVersion: schema,
				BackupID:      "legacy-backup",
				CreatedAt:     time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
				Compression:   "none",
			}
			var ordinal int64
			root := model.BatchRoot{SchemaVersion: model.SchemaBatchRoot, BatchID: "must-not-restore", BatchRoot: repeatByte(0x42, 32), TreeSize: 1, ClosedAtUnixN: 1}
			if err := writeCBORTracked(tw, &legacy, &ordinal, "roots/must-not-restore.tdroot", "batch_root", root); err != nil {
				t.Fatalf("write root: %v", err)
			}
			if err := writeJSONTracked(tw, &legacy, &ordinal, "manifest.json", "manifest", legacy); err != nil {
				t.Fatalf("write manifest: %v", err)
			}
			if err := writeJSONTracked(tw, &legacy, &ordinal, "summary.json", "summary", legacy); err != nil {
				t.Fatalf("write summary: %v", err)
			}
			if err := tw.Close(); err != nil {
				t.Fatalf("tar Close: %v", err)
			}
			if err := f.Close(); err != nil {
				t.Fatalf("file Close: %v", err)
			}

			if _, err := Verify(ctx, path); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition || !strings.Contains(err.Error(), schema) {
				t.Fatalf("Verify %s error=%v", schema, err)
			}
			dst := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "dst")}
			if _, err := Restore(ctx, dst, path); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition || !strings.Contains(err.Error(), schema) {
				t.Fatalf("Restore %s error=%v", schema, err)
			}
			if _, err := dst.LatestRoot(ctx); trusterr.CodeOf(err) != trusterr.CodeNotFound {
				t.Fatalf("LatestRoot after rejected restore error=%v", err)
			}
		})
	}
}

func TestBackupRootPaginationPreservesTimestampTies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "src")}
	const rootCount = scanPageSize + 1
	const closedAtUnixN = int64(100)

	for i := 0; i < rootCount; i++ {
		batchID := fmt.Sprintf("batch-%04d", i)
		if err := src.PutRoot(ctx, model.BatchRoot{
			SchemaVersion: model.SchemaBatchRoot,
			BatchID:       batchID,
			BatchRoot:     repeatByte(byte(i), 32),
			TreeSize:      1,
			ClosedAtUnixN: closedAtUnixN,
		}); err != nil {
			t.Fatalf("PutRoot(%q): %v", batchID, err)
		}
	}

	path := filepath.Join(t.TempDir(), "timestamp-ties.tdbackup")
	report, err := Create(ctx, src, path, Options{Compression: "none"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if report.Roots != rootCount {
		t.Fatalf("Create Roots = %d, want %d", report.Roots, rootCount)
	}
	verified, err := Verify(ctx, path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Roots != rootCount {
		t.Fatalf("Verify Roots = %d, want %d", verified.Roots, rootCount)
	}

	dst := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "dst")}
	restored, err := Restore(ctx, dst, path)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if restored.Roots != rootCount {
		t.Fatalf("Restore Roots = %d, want %d", restored.Roots, rootCount)
	}
	restoredRootCount := 0
	afterClosedAtUnixN := int64(0)
	afterBatchID := ""
	for {
		roots, err := dst.ListRootsPage(ctx, model.RootListOptions{
			Limit:              scanPageSize,
			Direction:          model.RecordListDirectionAsc,
			AfterClosedAtUnixN: afterClosedAtUnixN,
			AfterBatchID:       afterBatchID,
		})
		if err != nil {
			t.Fatalf("ListRootsPage: %v", err)
		}
		if len(roots) == 0 {
			break
		}
		restoredRootCount += len(roots)
		lastRoot := roots[len(roots)-1]
		afterClosedAtUnixN = lastRoot.ClosedAtUnixN
		afterBatchID = lastRoot.BatchID
	}
	if restoredRootCount != rootCount {
		t.Fatalf("restored root count = %d, want %d", restoredRootCount, rootCount)
	}
}

func TestBackupCreateRejectsMissingManifestBundle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "src")}
	if err := src.PutManifest(ctx, model.BatchManifest{
		SchemaVersion: model.SchemaBatchManifest,
		BatchID:       "batch-missing-bundle",
		State:         model.BatchStateCommitted,
		TreeSize:      1,
		BatchRoot:     repeatByte(0x44, 32),
		RecordIDs:     []string{"record-missing"},
		ClosedAtUnixN: 1,
	}); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "incomplete.tdbackup")
	_, err := Create(ctx, src, path, Options{Compression: "none"})
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("Create error = %v, code = %s, want %s", err, trusterr.CodeOf(err), trusterr.CodeDataLoss)
	}
	if !strings.Contains(err.Error(), "batch-missing-bundle") || !strings.Contains(err.Error(), "record-missing") {
		t.Fatalf("Create error = %q, want batch and record identifiers", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("backup target stat error = %v, want not exist", statErr)
	}
	temporaryFiles, globErr := filepath.Glob(filepath.Join(dir, ".incomplete.tdbackup.*.tmp"))
	if globErr != nil {
		t.Fatalf("Glob temporary files: %v", globErr)
	}
	if len(temporaryFiles) != 0 {
		t.Fatalf("temporary backup files remain: %v", temporaryFiles)
	}
}

func TestBackupRoundTripPreservesGlobalOutboxStatuses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "src")}
	items := []model.GlobalLogOutboxItem{
		{BatchID: "batch-pending", Status: model.AnchorStatePending, EnqueuedAtUnixN: 1},
		{BatchID: "batch-published", Status: model.AnchorStatePublished, EnqueuedAtUnixN: 2, CompletedAtUnixN: 3},
	}
	for _, item := range items {
		if err := src.EnqueueGlobalLog(ctx, item); err != nil {
			t.Fatalf("EnqueueGlobalLog(%q): %v", item.BatchID, err)
		}
	}
	path := filepath.Join(t.TempDir(), "global-outboxes.tdbackup")
	report, err := Create(ctx, src, path, Options{Compression: "none"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if report.GlobalOutboxes != len(items) {
		t.Fatalf("GlobalOutboxes = %d, want %d", report.GlobalOutboxes, len(items))
	}
	dst := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "dst")}
	if _, err := Restore(ctx, dst, path); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	for _, want := range items {
		got, ok, err := dst.GetGlobalLogOutboxItem(ctx, want.BatchID)
		if err != nil || !ok || got.Status != want.Status {
			t.Fatalf("restored outbox %q = %+v ok=%v err=%v", want.BatchID, got, ok, err)
		}
	}
	pending, err := dst.ListPendingGlobalLog(ctx, 100, 10)
	if err != nil || len(pending) != 1 || pending[0].BatchID != "batch-pending" {
		t.Fatalf("restored pending = %+v err=%v", pending, err)
	}
}

func TestCreateRejectsDirectoryTarget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "src")}
	path := filepath.Join(t.TempDir(), "trustdb.tdbackup")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}

	if _, err := Create(ctx, store, path, Options{}); err == nil {
		t.Fatalf("Create() error = nil, want directory target error")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(target) error = %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("target directory was replaced")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", matches)
	}
}

func TestWriteRestoreCheckpointRejectsDirectoryTarget(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "restore-checkpoint.json")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}

	err := writeRestoreCheckpoint(path, RestoreCheckpoint{SchemaVersion: SchemaRestoreCheckpoint})
	if err == nil {
		t.Fatalf("writeRestoreCheckpoint() error = nil, want directory target error")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(target) error = %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("target directory was replaced")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", matches)
	}
}

func TestRestoreRejectsInvalidResumeCheckpoint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	src := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "src")}
	backupPath := filepath.Join(t.TempDir(), "trustdb.tdbackup")
	if _, err := Create(ctx, src, backupPath, Options{Compression: "none"}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	checkpointPath := filepath.Join(t.TempDir(), "restore.checkpoint.json")
	if err := os.WriteFile(checkpointPath, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("WriteFile(checkpoint) error = %v", err)
	}

	dst := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "dst")}
	_, err := RestoreWithOptions(ctx, dst, backupPath, RestoreOptions{
		Resume:         true,
		CheckpointPath: checkpointPath,
	})
	if err == nil {
		t.Fatalf("RestoreWithOptions() error = nil, want invalid checkpoint error")
	}
}

func TestReadRestoreCheckpointRejectsOversizedFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "restore.checkpoint.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), int(maxRestoreCheckpointBytes)+1), 0o600); err != nil {
		t.Fatalf("WriteFile(checkpoint) error = %v", err)
	}

	if _, err := readRestoreCheckpoint(path); err == nil {
		t.Fatalf("readRestoreCheckpoint() error = nil, want oversized checkpoint error")
	}
}

func TestCreateDoesNotReplaceTargetOnFailure(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	src := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "src")}
	path := filepath.Join(t.TempDir(), "trustdb.tdbackup")
	original := []byte("existing backup content")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("WriteFile(original): %v", err)
	}

	if _, err := Create(ctx, src, path, Options{Compression: "none"}); err == nil {
		t.Fatal("Create() error = nil, want canceled context error")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(target): %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("target backup was replaced on failure: got %q want %q", got, original)
	}
}

func TestCreateUsesCollisionResistantArchiveNames(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	src := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "src")}
	ids := []string{"rec/1", "rec_2F1"}
	for _, id := range ids {
		if err := src.PutBundle(ctx, model.ProofBundle{
			SchemaVersion: model.SchemaProofBundle,
			RecordID:      id,
			CommittedReceipt: model.CommittedReceipt{
				BatchID:   "batch/collide",
				BatchRoot: repeatByte(0x11, 32),
			},
			BatchProof: model.BatchProof{TreeSize: 2},
		}); err != nil {
			t.Fatalf("PutBundle(%q): %v", id, err)
		}
	}
	if err := src.PutManifest(ctx, model.BatchManifest{
		SchemaVersion: model.SchemaBatchManifest,
		BatchID:       "batch/collide",
		State:         model.BatchStateCommitted,
		TreeSize:      2,
		BatchRoot:     repeatByte(0x11, 32),
		RecordIDs:     ids,
		ClosedAtUnixN: 1,
	}); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}

	path := filepath.Join(t.TempDir(), "trustdb.tdbackup")
	report, err := Create(ctx, src, path, Options{Compression: "none"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	names := make(map[string]struct{})
	for _, entry := range report.Entries {
		if entry.Type != "proof_bundle" {
			continue
		}
		if _, ok := names[entry.Name]; ok {
			t.Fatalf("duplicate proof bundle archive entry name: %q", entry.Name)
		}
		names[entry.Name] = struct{}{}
	}
	if len(names) != len(ids) {
		t.Fatalf("proof bundle entry names = %v, want %d entries", names, len(ids))
	}
}

func TestSafeNameAvoidsPathSegmentCollisions(t *testing.T) {
	t.Parallel()

	if safeName("rec/1") == safeName("rec_2F1") {
		t.Fatalf("safeName still collides for escaped slash spelling")
	}
	if safeName("") == safeName("_") {
		t.Fatalf("safeName still collides for empty string and underscore")
	}
	if got := safeName(".."); got == ".." {
		t.Fatalf("safeName(%q) = %q, want encoded non-path segment", "..", got)
	}
	const plain = "batch-1_2.3"
	if got := safeName(plain); got != plain {
		t.Fatalf("safeName(%q) = %q, want unchanged", plain, got)
	}
}

func TestVerifyRejectsEntryHashMismatch(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "bad.tdbackup")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	tw := tar.NewWriter(f)
	data := []byte(fmt.Sprintf("{\"schema_version\":%q}\n", SchemaManifest))
	if err := tw.WriteHeader(&tar.Header{
		Name: "summary.json",
		Mode: 0o600,
		Size: int64(len(data)),
		PAXRecords: map[string]string{
			paxBackupID: "bad-backup",
			paxOrdinal:  "1",
			paxSHA256:   hex.EncodeToString(repeatByte(0, 32)),
			paxType:     "summary",
		},
	}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file Close: %v", err)
	}
	if _, err := Verify(context.Background(), path); err == nil {
		t.Fatal("Verify() error = nil, want sha256 mismatch")
	}
}

func TestVerifyRejectsTrailingJSONData(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "trailing-json.tdbackup")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	tw := tar.NewWriter(f)
	manifestJSON := fmt.Sprintf("{\"schema_version\":%q}", SchemaManifest)
	data := []byte(manifestJSON + manifestJSON)
	sum := sha256.Sum256(data)
	if err := tw.WriteHeader(&tar.Header{
		Name: "summary.json",
		Mode: 0o600,
		Size: int64(len(data)),
		PAXRecords: map[string]string{
			paxBackupID: "bad-backup",
			paxOrdinal:  "1",
			paxSHA256:   hex.EncodeToString(sum[:]),
			paxType:     "summary",
		},
	}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file Close: %v", err)
	}
	if _, err := Verify(context.Background(), path); err == nil {
		t.Fatal("Verify() error = nil, want trailing JSON error")
	}
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func backupScheduleSTH(key model.STHAnchorScheduleKey, treeSize uint64, seed byte) model.SignedTreeHead {
	return model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       treeSize,
		RootHash:       repeatByte(seed, 32),
		TimestampUnixN: int64(treeSize),
		NodeID:         key.NodeID,
		LogID:          key.LogID,
		Signature: model.Signature{
			Alg:       model.DefaultSignatureAlg,
			KeyID:     "server-key",
			Signature: repeatByte(seed, 64),
		},
	}
}

func backupScheduleResult(key model.STHAnchorScheduleKey, sth model.SignedTreeHead, anchorID string, publishedAt int64) model.STHAnchorResult {
	return model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		NodeID:           key.NodeID,
		LogID:            key.LogID,
		TreeSize:         sth.TreeSize,
		SinkName:         key.SinkName,
		AnchorID:         anchorID,
		RootHash:         append([]byte(nil), sth.RootHash...),
		STH:              sth,
		Proof:            []byte("anchor-proof"),
		PublishedAtUnixN: publishedAt,
	}
}
