package proofstore

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

func TestWALCheckpointPruneSafetyFailsClosedForFileAndUnknownStores(t *testing.T) {
	t.Parallel()
	if WALCheckpointPruneSafe(LocalStore{Root: t.TempDir()}) {
		t.Fatal("LocalStore reported crash-safe WAL checkpoint pruning")
	}
	if WALCheckpointPruneSafe(struct{}{}) {
		t.Fatal("unknown store reported crash-safe WAL checkpoint pruning")
	}
}

func TestLocalStoreBundleRoundTrip(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	bundle := model.ProofBundle{
		SchemaVersion: model.SchemaProofBundle,
		RecordID:      "tr1proof",
	}
	if err := store.PutBundle(context.Background(), bundle); err != nil {
		t.Fatalf("PutBundle() error = %v", err)
	}
	got, err := store.GetBundle(context.Background(), bundle.RecordID)
	if err != nil {
		t.Fatalf("GetBundle() error = %v", err)
	}
	if got.RecordID != bundle.RecordID || got.SchemaVersion != model.SchemaProofBundle {
		t.Fatalf("GetBundle() = %+v", got)
	}
}

func TestReadStoredFileLimitBoundsFileSize(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	primary := filepath.Join(dir, "primary")
	data := bytes.Repeat([]byte{0x42}, 32)
	if err := os.WriteFile(primary, data, 0o600); err != nil {
		t.Fatalf("WriteFile(primary) error = %v", err)
	}
	got, err := readStoredFileLimit(primary, int64(len(data)))
	if err != nil {
		t.Fatalf("readStoredFileLimit(exact boundary) error = %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("readStoredFileLimit() = %x, want %x", got, data)
	}

	if err := os.WriteFile(primary, append(data, 0x43), 0o600); err != nil {
		t.Fatalf("WriteFile(oversized primary) error = %v", err)
	}
	if _, err := readStoredFileLimit(primary, int64(len(data))); err == nil {
		t.Fatal("readStoredFileLimit(oversized primary) error = nil")
	}
}

func TestWriteCBORAtomicRejectsDirectoryTarget(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "bundle.tdproof")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}

	err := writeCBORAtomic(path, model.ProofBundle{RecordID: "record-1"})
	if err == nil {
		t.Fatalf("writeCBORAtomic() error = nil, want directory target error")
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

func TestLocalStoreBundleIDsDoNotCollideAfterEscaping(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	slashBundle := model.ProofBundle{
		SchemaVersion: "slash",
		RecordID:      "rec/1",
	}
	underscoreBundle := model.ProofBundle{
		SchemaVersion: "underscore",
		RecordID:      "rec_1",
	}
	if err := store.PutBundle(context.Background(), slashBundle); err != nil {
		t.Fatalf("PutBundle(slash) error = %v", err)
	}
	if err := store.PutBundle(context.Background(), underscoreBundle); err != nil {
		t.Fatalf("PutBundle(underscore) error = %v", err)
	}
	gotSlash, err := store.GetBundle(context.Background(), slashBundle.RecordID)
	if err != nil {
		t.Fatalf("GetBundle(slash) error = %v", err)
	}
	gotUnderscore, err := store.GetBundle(context.Background(), underscoreBundle.RecordID)
	if err != nil {
		t.Fatalf("GetBundle(underscore) error = %v", err)
	}
	if gotSlash.SchemaVersion != slashBundle.SchemaVersion || gotUnderscore.SchemaVersion != underscoreBundle.SchemaVersion {
		t.Fatalf("bundles collided: slash=%+v underscore=%+v", gotSlash, gotUnderscore)
	}
}

func TestLocalStoreListRecordIndexesRejectsSymlinkOutsideRoot(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	outside := t.TempDir()
	idx := model.RecordIndex{
		SchemaVersion:   model.SchemaRecordIndex,
		RecordID:        "outside-record",
		TenantID:        "tenant-a",
		ReceivedAtUnixN: 1,
	}
	if err := writeCBORAtomic(filepath.Join(outside, "outside.tdrecord"), idx); err != nil {
		t.Fatalf("write outside record: %v", err)
	}
	linkDir := filepath.Join(store.Root, "records", "by-tenant", "tenant-a")
	if err := os.MkdirAll(filepath.Dir(linkDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	indexes, err := store.ListRecordIndexes(context.Background(), model.RecordListOptions{TenantID: "tenant-a"})
	if err == nil {
		t.Fatalf("ListRecordIndexes() indexes=%+v error=nil, want symlink escape error", indexes)
	}
	if len(indexes) != 0 {
		t.Fatalf("ListRecordIndexes() returned outside indexes: %+v", indexes)
	}
}

func TestSafeFileNameAvoidsLegacyCollisions(t *testing.T) {
	t.Parallel()

	if safeFileName("rec/1") == safeFileName("rec_1") {
		t.Fatalf("safeFileName still collides for slash and underscore")
	}
	if safeFileName("") == safeFileName("_") {
		t.Fatalf("safeFileName still collides for empty string and underscore")
	}
	if got := safeFileName(".."); got == ".." {
		t.Fatalf("safeFileName(%q) = %q, want encoded non-path segment", "..", got)
	}
	const plain = "tr1_record-1.2"
	if got := safeFileName(plain); got != plain {
		t.Fatalf("safeFileName(%q) = %q, want unchanged", plain, got)
	}
}

func TestLocalStoreRecordPagesOrderEncodedIDsByRawValue(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	for _, recordID := range []string{"rec_1", "rec/1", "rec-1"} {
		if err := store.PutRecordIndex(ctx, model.RecordIndex{
			SchemaVersion:   model.SchemaRecordIndex,
			RecordID:        recordID,
			ReceivedAtUnixN: 100,
		}); err != nil {
			t.Fatalf("PutRecordIndex(%q): %v", recordID, err)
		}
	}

	first, err := store.ListRecordIndexes(ctx, model.RecordListOptions{Limit: 2, Direction: model.RecordListDirectionAsc})
	if err != nil {
		t.Fatalf("ListRecordIndexes(first): %v", err)
	}
	if len(first) != 2 || first[0].RecordID != "rec-1" || first[1].RecordID != "rec/1" {
		t.Fatalf("first page = %#v", first)
	}
	next, err := store.ListRecordIndexes(ctx, model.RecordListOptions{
		Limit:                2,
		Direction:            model.RecordListDirectionAsc,
		AfterReceivedAtUnixN: first[1].ReceivedAtUnixN,
		AfterRecordID:        first[1].RecordID,
	})
	if err != nil {
		t.Fatalf("ListRecordIndexes(next): %v", err)
	}
	if len(next) != 1 || next[0].RecordID != "rec_1" {
		t.Fatalf("next page = %#v", next)
	}
}

func TestLocalStoreRecordPageStopsReadingAtLimit(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	var oldest model.RecordIndex
	for i := range 101 {
		idx := model.RecordIndex{
			SchemaVersion:   model.SchemaRecordIndex,
			RecordID:        fmt.Sprintf("record-%03d", i),
			ReceivedAtUnixN: int64(i + 1),
		}
		if i == 0 {
			oldest = idx
		}
		if err := store.PutRecordIndex(ctx, idx); err != nil {
			t.Fatalf("PutRecordIndex(%d): %v", i, err)
		}
	}
	oldestPath := filepath.Join(store.recordByTimeDir(), store.recordIndexName(oldest))
	if err := os.WriteFile(oldestPath, []byte("not-cbor"), 0o600); err != nil {
		t.Fatalf("corrupt oldest index: %v", err)
	}

	page, err := store.ListRecordIndexes(ctx, model.RecordListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListRecordIndexes(limit=100): %v", err)
	}
	if len(page) != 100 || page[0].ReceivedAtUnixN != 101 || page[99].ReceivedAtUnixN != 2 {
		t.Fatalf("page bounds: len=%d first=%d last=%d", len(page), page[0].ReceivedAtUnixN, page[len(page)-1].ReceivedAtUnixN)
	}
	if _, err := store.ListRecordIndexes(ctx, model.RecordListOptions{Limit: 101}); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("ListRecordIndexes(limit=101) error = %v, code = %s", err, trusterr.CodeOf(err))
	}
}

func TestLocalStoreRootRoundTrip(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	roots := []model.BatchRoot{
		{SchemaVersion: model.SchemaBatchRoot, BatchID: "batch-a", BatchRoot: bytes.Repeat([]byte{1}, 32), TreeSize: 1, ClosedAtUnixN: 100},
		{SchemaVersion: model.SchemaBatchRoot, BatchID: "batch-b", BatchRoot: bytes.Repeat([]byte{2}, 32), TreeSize: 2, ClosedAtUnixN: 200},
	}
	for _, root := range roots {
		if err := store.PutRoot(context.Background(), root); err != nil {
			t.Fatalf("PutRoot() error = %v", err)
		}
	}
	listed, err := store.ListRoots(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListRoots() error = %v", err)
	}
	if len(listed) != 2 || listed[0].BatchID != "batch-b" || listed[1].BatchID != "batch-a" {
		t.Fatalf("ListRoots() = %+v", listed)
	}
	latest, err := store.LatestRoot(context.Background())
	if err != nil {
		t.Fatalf("LatestRoot() error = %v", err)
	}
	if latest.BatchID != "batch-b" {
		t.Fatalf("LatestRoot() = %+v", latest)
	}
}

func TestLocalStoreRootPagesOrderEncodedIDsByRawValue(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	for _, batchID := range []string{"batch_1", "batch/1", "batch-1"} {
		if err := store.PutRoot(ctx, model.BatchRoot{
			SchemaVersion: model.SchemaBatchRoot,
			BatchID:       batchID,
			BatchRoot:     bytes.Repeat([]byte{1}, 32),
			TreeSize:      1,
			ClosedAtUnixN: 100,
		}); err != nil {
			t.Fatalf("PutRoot(%q): %v", batchID, err)
		}
	}

	first, err := store.ListRootsPage(ctx, model.RootListOptions{Limit: 2, Direction: model.RecordListDirectionAsc})
	if err != nil {
		t.Fatalf("ListRootsPage(first): %v", err)
	}
	if len(first) != 2 || first[0].BatchID != "batch-1" || first[1].BatchID != "batch/1" {
		t.Fatalf("first page = %#v", first)
	}
	next, err := store.ListRootsPage(ctx, model.RootListOptions{
		Limit:              2,
		Direction:          model.RecordListDirectionAsc,
		AfterClosedAtUnixN: first[1].ClosedAtUnixN,
		AfterBatchID:       first[1].BatchID,
	})
	if err != nil {
		t.Fatalf("ListRootsPage(next): %v", err)
	}
	if len(next) != 1 || next[0].BatchID != "batch_1" {
		t.Fatalf("next page = %#v", next)
	}
}

func TestLocalStoreRootReadersSkipFilesOutsideRequestedRange(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	var oldest model.BatchRoot
	for i := range 101 {
		root := model.BatchRoot{
			SchemaVersion: model.SchemaBatchRoot,
			BatchID:       fmt.Sprintf("batch-%03d", i),
			BatchRoot:     bytes.Repeat([]byte{1}, 32),
			TreeSize:      1,
			ClosedAtUnixN: int64(i + 1),
		}
		if i == 0 {
			oldest = root
		}
		if err := store.PutRoot(ctx, root); err != nil {
			t.Fatalf("PutRoot(%d): %v", i, err)
		}
	}
	oldestName := fmt.Sprintf("%0*d_%s.tdroot", localPositionWidth, oldest.ClosedAtUnixN, safeFileName(oldest.BatchID))
	if err := os.WriteFile(filepath.Join(store.rootDir(), oldestName), []byte("not-cbor"), 0o600); err != nil {
		t.Fatalf("corrupt oldest root: %v", err)
	}

	page, err := store.ListRootsPage(ctx, model.RootListOptions{Limit: 100, Direction: model.RecordListDirectionDesc})
	if err != nil {
		t.Fatalf("ListRootsPage: %v", err)
	}
	if len(page) != 100 || page[0].ClosedAtUnixN != 101 || page[99].ClosedAtUnixN != 2 {
		t.Fatalf("page bounds: len=%d first=%d last=%d", len(page), page[0].ClosedAtUnixN, page[len(page)-1].ClosedAtUnixN)
	}
	after, err := store.ListRootsAfter(ctx, 1, 100)
	if err != nil {
		t.Fatalf("ListRootsAfter: %v", err)
	}
	if len(after) != 100 || after[0].ClosedAtUnixN != 2 || after[99].ClosedAtUnixN != 101 {
		t.Fatalf("after bounds: len=%d first=%d last=%d", len(after), after[0].ClosedAtUnixN, after[len(after)-1].ClosedAtUnixN)
	}
}

func TestLocalStoreMissingBundle(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	_, err := store.GetBundle(context.Background(), "missing")
	if trusterr.CodeOf(err) != trusterr.CodeNotFound {
		t.Fatalf("GetBundle() code = %s err=%v", trusterr.CodeOf(err), err)
	}
}

func TestLocalStoreManifestRoundTrip(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	prepared := model.BatchManifest{
		SchemaVersion:   model.SchemaBatchManifest,
		BatchID:         "batch-a",
		State:           model.BatchStatePrepared,
		TreeAlg:         model.DefaultMerkleTreeAlg,
		TreeSize:        2,
		BatchRoot:       bytes.Repeat([]byte{9}, 32),
		RecordIDs:       []string{"rec-1", "rec-2"},
		WALRange:        model.WALRange{From: model.WALPosition{SegmentID: 1, Sequence: 1}, To: model.WALPosition{SegmentID: 1, Sequence: 2}},
		ClosedAtUnixN:   123,
		PreparedAtUnixN: 123,
	}
	if err := store.PutManifest(context.Background(), prepared); err != nil {
		t.Fatalf("PutManifest() error = %v", err)
	}
	got, err := store.GetManifest(context.Background(), prepared.BatchID)
	if err != nil {
		t.Fatalf("GetManifest() error = %v", err)
	}
	if got.State != model.BatchStatePrepared || got.TreeSize != 2 || len(got.RecordIDs) != 2 {
		t.Fatalf("GetManifest() = %+v", got)
	}
	committed := prepared
	committed.State = model.BatchStateCommitted
	committed.CommittedAtUnixN = 200
	if err := store.PutManifest(context.Background(), committed); err != nil {
		t.Fatalf("PutManifest(committed) error = %v", err)
	}
	list, err := store.ListManifests(context.Background())
	if err != nil {
		t.Fatalf("ListManifests() error = %v", err)
	}
	if len(list) != 1 || list[0].State != model.BatchStateCommitted {
		t.Fatalf("ListManifests() = %+v", list)
	}
}

func TestLocalStoreManifestPagesOrderEncodedIDsByRawValue(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	for _, batchID := range []string{"batch_1", "batch/1", "batch-1"} {
		if err := store.PutManifest(ctx, model.BatchManifest{
			SchemaVersion: model.SchemaBatchManifest,
			BatchID:       batchID,
			State:         model.BatchStateCommitted,
		}); err != nil {
			t.Fatalf("PutManifest(%q): %v", batchID, err)
		}
	}

	first, err := store.ListManifestsAfter(ctx, "", 2)
	if err != nil {
		t.Fatalf("ListManifestsAfter(first): %v", err)
	}
	if len(first) != 2 || first[0].BatchID != "batch-1" || first[1].BatchID != "batch/1" {
		t.Fatalf("first page = %#v", first)
	}
	next, err := store.ListManifestsAfter(ctx, first[1].BatchID, 2)
	if err != nil {
		t.Fatalf("ListManifestsAfter(next): %v", err)
	}
	if len(next) != 1 || next[0].BatchID != "batch_1" {
		t.Fatalf("next page = %#v", next)
	}
}

func TestLocalStoreManifestPageSkipsFilesBeforeCursor(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	for i := range 101 {
		batchID := fmt.Sprintf("batch-%03d", i)
		if err := store.PutManifest(ctx, model.BatchManifest{
			SchemaVersion: model.SchemaBatchManifest,
			BatchID:       batchID,
			State:         model.BatchStateCommitted,
		}); err != nil {
			t.Fatalf("PutManifest(%s): %v", batchID, err)
		}
	}
	if err := os.WriteFile(store.manifestPath("batch-000"), []byte("not-cbor"), 0o600); err != nil {
		t.Fatalf("corrupt oldest manifest: %v", err)
	}

	page, err := store.ListManifestsAfter(ctx, "batch-000", 100)
	if err != nil {
		t.Fatalf("ListManifestsAfter: %v", err)
	}
	if len(page) != 100 || page[0].BatchID != "batch-001" || page[99].BatchID != "batch-100" {
		t.Fatalf("page bounds: len=%d first=%s last=%s", len(page), page[0].BatchID, page[len(page)-1].BatchID)
	}
}

func TestLocalStoreManifestListRejectsFilenameMismatch(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	ctx := context.Background()
	manifest := model.BatchManifest{
		SchemaVersion: model.SchemaBatchManifest,
		BatchID:       "batch-a",
		State:         model.BatchStateCommitted,
	}
	if err := store.PutManifest(ctx, manifest); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	if err := os.Rename(store.manifestPath("batch-a"), store.manifestPath("batch-b")); err != nil {
		t.Fatalf("rename manifest: %v", err)
	}

	_, err := store.ListManifestsAfter(ctx, "", 1)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("ListManifestsAfter code = %s, err=%v", trusterr.CodeOf(err), err)
	}
}

func TestLocalStoreMissingManifest(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	_, err := store.GetManifest(context.Background(), "missing")
	if trusterr.CodeOf(err) != trusterr.CodeNotFound {
		t.Fatalf("GetManifest() code = %s err=%v", trusterr.CodeOf(err), err)
	}
}

func TestLocalStoreRejectsInvalidManifestState(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	err := store.PutManifest(context.Background(), model.BatchManifest{BatchID: "b", State: "pending"})
	if trusterr.CodeOf(err) != trusterr.CodeInvalidArgument {
		t.Fatalf("PutManifest() code = %s err=%v", trusterr.CodeOf(err), err)
	}
}

func TestLocalStoreCheckpointRoundTrip(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	cp := model.WALCheckpoint{
		SegmentID:    1,
		LastSequence: 42,
		LastOffset:   4096,
		BatchID:      "batch-a",
	}
	if err := store.PutCheckpoint(context.Background(), cp); err != nil {
		t.Fatalf("PutCheckpoint() error = %v", err)
	}
	got, found, err := store.GetCheckpoint(context.Background())
	if err != nil {
		t.Fatalf("GetCheckpoint() error = %v", err)
	}
	if !found {
		t.Fatalf("GetCheckpoint() found = false after put")
	}
	if got.SchemaVersion != model.SchemaWALCheckpoint {
		t.Fatalf("GetCheckpoint() SchemaVersion = %q, want %q", got.SchemaVersion, model.SchemaWALCheckpoint)
	}
	if got.LastSequence != 42 || got.LastOffset != 4096 || got.SegmentID != 1 || got.BatchID != "batch-a" {
		t.Fatalf("GetCheckpoint() = %+v", got)
	}
	if got.RecordedAtUnixN == 0 {
		t.Fatalf("GetCheckpoint() RecordedAtUnixN = 0, want auto-filled")
	}

	// Overwriting with a newer checkpoint must be observable.
	newer := model.WALCheckpoint{SegmentID: 1, LastSequence: 100, LastOffset: 8192, BatchID: "batch-b"}
	if err := store.PutCheckpoint(context.Background(), newer); err != nil {
		t.Fatalf("PutCheckpoint(newer) error = %v", err)
	}
	got2, _, err := store.GetCheckpoint(context.Background())
	if err != nil {
		t.Fatalf("GetCheckpoint() second error = %v", err)
	}
	if got2.LastSequence != 100 || got2.BatchID != "batch-b" {
		t.Fatalf("GetCheckpoint() after overwrite = %+v", got2)
	}
}

func TestLocalStoreMissingCheckpoint(t *testing.T) {
	t.Parallel()

	store := LocalStore{Root: t.TempDir()}
	_, found, err := store.GetCheckpoint(context.Background())
	if err != nil {
		t.Fatalf("GetCheckpoint() error = %v, want nil for missing checkpoint", err)
	}
	if found {
		t.Fatalf("GetCheckpoint() found = true for empty store")
	}
}
