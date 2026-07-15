package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	if report.Bundles != 1 || report.Roots != 1 || report.GlobalLeaves != 1 || report.GlobalNodes == 0 || !report.GlobalState || report.STHs != 1 || report.GlobalOutboxes != 1 || report.AnchorResults != 1 || !report.Checkpoint {
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
	if _, ok, err := dst.GetSTHAnchorResult(ctx, 1); err != nil || !ok {
		t.Fatalf("GetSTHAnchorResult restored ok=%v err=%v", ok, err)
	}
	if _, ok, err := dst.GetGlobalLogState(ctx); err != nil || !ok {
		t.Fatalf("GetGlobalLogState restored ok=%v err=%v", ok, err)
	}
	if _, ok, err := dst.GetGlobalLogOutboxItem(ctx, root.BatchID); err != nil || !ok {
		t.Fatalf("GetGlobalLogOutboxItem restored ok=%v err=%v", ok, err)
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
