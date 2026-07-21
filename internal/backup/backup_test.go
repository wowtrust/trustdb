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
	"testing"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/globallog"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
	"github.com/ryan-wong-coder/trustdb/internal/trustcrypto"
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
	if err := src.EnqueueSTHAnchor(ctx, model.STHAnchorOutboxItem{
		SchemaVersion: model.SchemaSTHAnchorOutbox,
		TreeSize:      sth.TreeSize,
		Status:        model.AnchorStatePending,
		SinkName:      "noop",
		STH:           sth,
	}); err != nil {
		t.Fatalf("EnqueueSTHAnchor: %v", err)
	}
	if err := src.MarkSTHAnchorPublished(ctx, model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		TreeSize:         sth.TreeSize,
		SinkName:         "noop",
		AnchorID:         "noop-sth-1",
		RootHash:         sth.RootHash,
		STH:              sth,
		PublishedAtUnixN: 11,
	}); err != nil {
		t.Fatalf("MarkSTHAnchorPublished: %v", err)
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
		t.Fatalf("missing v2 manifest metadata: %+v", report)
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

func TestBackupRoundTripPreservesSTHAnchorStatuses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "src")}
	if err := src.EnqueueSTHAnchor(ctx, model.STHAnchorOutboxItem{TreeSize: 1, Status: model.AnchorStatePending, EnqueuedAtUnixN: 1}); err != nil {
		t.Fatalf("EnqueueSTHAnchor pending: %v", err)
	}
	if err := src.EnqueueSTHAnchor(ctx, model.STHAnchorOutboxItem{TreeSize: 2, Status: model.AnchorStatePending, EnqueuedAtUnixN: 2}); err != nil {
		t.Fatalf("EnqueueSTHAnchor published: %v", err)
	}
	if err := src.MarkSTHAnchorPublished(ctx, model.STHAnchorResult{TreeSize: 2, AnchorID: "anchor-2", PublishedAtUnixN: 3}); err != nil {
		t.Fatalf("MarkSTHAnchorPublished: %v", err)
	}
	if err := src.EnqueueSTHAnchor(ctx, model.STHAnchorOutboxItem{TreeSize: 3, Status: model.AnchorStatePending, EnqueuedAtUnixN: 4}); err != nil {
		t.Fatalf("EnqueueSTHAnchor failed: %v", err)
	}
	if err := src.MarkSTHAnchorFailed(ctx, 3, "permanent"); err != nil {
		t.Fatalf("MarkSTHAnchorFailed: %v", err)
	}

	path := filepath.Join(t.TempDir(), "anchor-outboxes.tdbackup")
	report, err := Create(ctx, src, path, Options{Compression: "none"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if report.AnchorOutboxes != 3 || report.AnchorResults != 1 {
		t.Fatalf("backup report = %+v", report)
	}
	dst := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "dst")}
	if _, err := Restore(ctx, dst, path); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	wantStatuses := map[uint64]string{1: model.AnchorStatePending, 2: model.AnchorStatePublished, 3: model.AnchorStateFailed}
	for treeSize, wantStatus := range wantStatuses {
		got, ok, err := dst.GetSTHAnchorOutboxItem(ctx, treeSize)
		if err != nil || !ok || got.Status != wantStatus {
			t.Fatalf("restored anchor %d = %+v ok=%v err=%v", treeSize, got, ok, err)
		}
	}
	if result, ok, err := dst.GetSTHAnchorResult(ctx, 2); err != nil || !ok || result.AnchorID != "anchor-2" {
		t.Fatalf("restored anchor result = %+v ok=%v err=%v", result, ok, err)
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
	data := []byte(`{"schema_version":"trustdb.backup.v2"}` + "\n")
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
	data := []byte(`{"schema_version":"trustdb.backup.v2"}{"schema_version":"trustdb.backup.v2"}`)
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
