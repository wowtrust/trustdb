package wal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
)

func TestEnsureDurableDirectorySyncsBoundaryAndNewParentsInOrder(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := filepath.Join(root, "one", "two", "three")
	ops := defaultWALFileOps()
	var events []string
	ops.mkdir = func(path string, perm os.FileMode) error {
		events = append(events, "mkdir "+path)
		return os.Mkdir(path, perm)
	}
	ops.syncDir = func(path string) error {
		events = append(events, "sync "+path)
		return nil
	}
	if err := ensureDurableDirectory(target, 0o755, ops); err != nil {
		t.Fatalf("ensureDurableDirectory() error = %v", err)
	}
	want := []string{
		"sync " + filepath.Dir(root),
		"mkdir " + filepath.Join(root, "one"),
		"sync " + root,
		"mkdir " + filepath.Join(root, "one", "two"),
		"sync " + filepath.Join(root, "one"),
		"mkdir " + target,
		"sync " + filepath.Join(root, "one", "two"),
	}
	if strings.Join(events, "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s\nwant:\n%s", strings.Join(events, "\n"), strings.Join(want, "\n"))
	}

	events = nil
	if err := ensureDurableDirectory(target, 0o755, ops); err != nil {
		t.Fatalf("second ensureDurableDirectory() error = %v", err)
	}
	want = []string{"sync " + filepath.Dir(target)}
	if strings.Join(events, "\n") != strings.Join(want, "\n") {
		t.Fatalf("existing-directory events:\n%s\nwant:\n%s", strings.Join(events, "\n"), strings.Join(want, "\n"))
	}
}

func TestEnsureDurableDirectoryPropagatesExistingBoundarySyncFailure(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("injected existing-boundary sync failure")
	target := t.TempDir()
	ops := defaultWALFileOps()
	ops.syncDir = func(string) error { return sentinel }
	if err := ensureDurableDirectory(target, 0o755, ops); !errors.Is(err, sentinel) {
		t.Fatalf("ensureDurableDirectory() error = %v, want boundary sync failure", err)
	}
}

func TestEnsureDurableDirectoryCleansUpAfterSyncFailure(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("injected parent sync failure")
	root := t.TempDir()
	target := filepath.Join(root, "one", "two")
	ops := defaultWALFileOps()
	var (
		events    []string
		syncCalls int
	)
	ops.mkdir = func(path string, perm os.FileMode) error {
		events = append(events, "mkdir "+path)
		return os.Mkdir(path, perm)
	}
	ops.remove = func(path string) error {
		events = append(events, "remove "+path)
		return os.Remove(path)
	}
	ops.syncDir = func(path string) error {
		events = append(events, "sync "+path)
		if filepath.Clean(path) == filepath.Clean(root) {
			syncCalls++
		}
		if filepath.Clean(path) == filepath.Clean(root) && syncCalls == 1 {
			return sentinel
		}
		return nil
	}
	err := ensureDurableDirectory(target, 0o755, ops)
	if !errors.Is(err, sentinel) {
		t.Fatalf("ensureDurableDirectory() error = %v, want sentinel", err)
	}
	want := []string{
		"sync " + filepath.Dir(root),
		"mkdir " + filepath.Join(root, "one"),
		"sync " + root,
		"remove " + filepath.Join(root, "one"),
		"sync " + root,
	}
	if strings.Join(events, "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s\nwant:\n%s", strings.Join(events, "\n"), strings.Join(want, "\n"))
	}
	if _, statErr := os.Stat(filepath.Join(root, "one")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unpublished directory still exists: %v", statErr)
	}
}

func TestEnsureDurableDirectoryRetriesParentSyncWhenCleanupFails(t *testing.T) {
	t.Parallel()

	syncErr := errors.New("injected first parent sync failure")
	removeErr := errors.New("injected cleanup removal failure")
	root := t.TempDir()
	target := filepath.Join(root, "new")
	ops := defaultWALFileOps()
	var syncCalls atomic.Int64
	ops.syncDir = func(path string) error {
		if filepath.Clean(path) == filepath.Clean(root) {
			if syncCalls.Add(1) == 1 {
				return syncErr
			}
		}
		return syncDirectory(path)
	}
	ops.remove = func(string) error { return removeErr }
	err := ensureDurableDirectory(target, 0o755, ops)
	if !errors.Is(err, syncErr) || !errors.Is(err, removeErr) {
		t.Fatalf("ensureDurableDirectory() error = %v, want sync and cleanup causes", err)
	}
	if got := syncCalls.Load(); got != 2 {
		t.Fatalf("parent sync calls = %d, want retry after failed cleanup", got)
	}
	if info, statErr := os.Stat(target); statErr != nil || !info.IsDir() {
		t.Fatalf("cleanup-owned directory = (%v, %v), want retained directory", info, statErr)
	}
}

func TestEnsureDurableDirectoryRetriesParentSyncAfterConcurrentCreation(t *testing.T) {
	t.Parallel()

	syncErr := errors.New("injected first parent sync failure")
	root := t.TempDir()
	target := filepath.Join(root, "concurrent")
	ops := defaultWALFileOps()
	var syncCalls atomic.Int64
	ops.mkdir = func(path string, perm os.FileMode) error {
		if err := os.Mkdir(path, perm); err != nil {
			return err
		}
		return os.ErrExist
	}
	ops.syncDir = func(path string) error {
		if filepath.Clean(path) == filepath.Clean(root) {
			if syncCalls.Add(1) == 1 {
				return syncErr
			}
		}
		return syncDirectory(path)
	}
	err := ensureDurableDirectory(target, 0o755, ops)
	if !errors.Is(err, syncErr) {
		t.Fatalf("ensureDurableDirectory() error = %v, want first sync failure", err)
	}
	if got := syncCalls.Load(); got != 2 {
		t.Fatalf("parent sync calls = %d, want retry after concurrent creation", got)
	}
	if info, statErr := os.Stat(target); statErr != nil || !info.IsDir() {
		t.Fatalf("concurrently created directory = (%v, %v), want retained directory", info, statErr)
	}
}

func TestWriterStartupPublishesFileAndRetriesExistingDirectoryBarrier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		open func(string, walFileOps) (*Writer, error)
	}{
		{
			name: "directory mode",
			open: func(root string, ops walFileOps) (*Writer, error) {
				return openDirWriterWithOps(filepath.Join(root, "wal"), Options{FsyncMode: FsyncBatch}, ops)
			},
		},
		{
			name: "single file",
			open: func(root string, ops walFileOps) (*Writer, error) {
				return openWriterWithOptionsAndOps(filepath.Join(root, "wal", "records.wal"), 1, Options{FsyncMode: FsyncBatch}, ops)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			ops := defaultWALFileOps()
			var events []string
			ops.openFile = func(path string, flags int, perm os.FileMode) (*os.File, error) {
				events = append(events, "open "+path)
				return os.OpenFile(path, flags, perm)
			}
			ops.syncFile = func(file *os.File) error {
				events = append(events, "sync-file "+file.Name())
				return file.Sync()
			}
			ops.syncDir = func(path string) error {
				events = append(events, "sync-dir "+path)
				return syncDirectory(path)
			}

			writer, err := test.open(root, ops)
			if err != nil {
				t.Fatalf("first open error = %v", err)
			}
			if len(events) < 3 {
				t.Fatalf("startup events = %v", events)
			}
			last := events[len(events)-3:]
			if !strings.HasPrefix(last[0], "open ") || !strings.HasPrefix(last[1], "sync-file ") || !strings.HasPrefix(last[2], "sync-dir ") {
				t.Fatalf("publication tail = %v", last)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("first Close() error = %v", err)
			}

			events = nil
			writer, err = test.open(root, ops)
			if err != nil {
				t.Fatalf("existing open error = %v", err)
			}
			defer writer.Close()
			if len(events) < 4 || !strings.HasPrefix(events[0], "sync-dir ") {
				t.Fatalf("existing-directory publication events = %v", events)
			}
			last = events[len(events)-3:]
			if !strings.HasPrefix(last[0], "open ") || !strings.HasPrefix(last[1], "sync-file ") || !strings.HasPrefix(last[2], "sync-dir ") {
				t.Fatalf("existing-file publication tail = %v", last)
			}
		})
	}
}

func TestWriterStartupDirectorySyncFailureClosesFile(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("injected directory sync failure")
	tests := []struct {
		name string
		open func(string, walFileOps) (*Writer, error)
	}{
		{
			name: "directory mode",
			open: func(root string, ops walFileOps) (*Writer, error) {
				return openDirWriterWithOps(root, Options{}, ops)
			},
		},
		{
			name: "single file",
			open: func(root string, ops walFileOps) (*Writer, error) {
				return openWriterWithOptionsAndOps(filepath.Join(root, "records.wal"), 1, Options{}, ops)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			ops := defaultWALFileOps()
			var opened *os.File
			ops.openFile = func(path string, flags int, perm os.FileMode) (*os.File, error) {
				file, err := os.OpenFile(path, flags, perm)
				opened = file
				return file, err
			}
			ops.syncDir = func(path string) error {
				if filepath.Clean(path) == filepath.Clean(root) {
					return sentinel
				}
				return syncDirectory(path)
			}
			writer, err := test.open(root, ops)
			if writer != nil || !errors.Is(err, sentinel) {
				t.Fatalf("open = (%v, %v), want nil writer and sentinel", writer, err)
			}
			if opened == nil {
				t.Fatal("WAL file was never opened")
			}
			if _, err := opened.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("opened file Stat() error = %v, want closed", err)
			}
			if !strings.Contains(err.Error(), "sync containing directory") {
				t.Fatalf("error lacks directory-sync context: %v", err)
			}
		})
	}
}

func TestRotationDirectorySyncFailureIsSticky(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("injected rotation directory sync failure")
	dir := t.TempDir()
	ops := defaultWALFileOps()
	var (
		failDirectory atomic.Bool
		syncCalls     atomic.Int64
		openCalls     atomic.Int64
		closeCalls    atomic.Int64
		rotateCalls   atomic.Int64
		reported      atomic.Int64
	)
	ops.openFile = func(path string, flags int, perm os.FileMode) (*os.File, error) {
		openCalls.Add(1)
		return os.OpenFile(path, flags, perm)
	}
	ops.syncFile = func(file *os.File) error {
		syncCalls.Add(1)
		return file.Sync()
	}
	ops.syncDir = func(path string) error {
		if failDirectory.Load() {
			return sentinel
		}
		return syncDirectory(path)
	}
	ops.closeFile = func(file *os.File) error {
		closeCalls.Add(1)
		return file.Close()
	}
	writer, err := openDirWriterWithOps(dir, Options{
		FsyncMode:       FsyncBatch,
		MaxSegmentBytes: 1,
		OnRotate:        func(uint64, uint64) { rotateCalls.Add(1) },
		OnFsyncError: func(string, error) {
			reported.Add(1)
		},
	}, ops)
	if err != nil {
		t.Fatalf("openDirWriterWithOps() error = %v", err)
	}
	appendTestRecord(t, writer, "first")
	writer.mu.Lock()
	wantSequence := writer.sequence
	wantOffset := writer.offset
	wantHash := writer.prevHash
	writer.mu.Unlock()

	failDirectory.Store(true)
	_, _, err = writer.Append(context.Background(), []byte("force rotation"))
	if !errors.Is(err, sentinel) {
		t.Fatalf("rotating Append() error = %v, want sentinel", err)
	}
	writer.mu.Lock()
	file := writer.file
	gotSegment := writer.segmentID
	gotSequence := writer.sequence
	gotOffset := writer.offset
	gotHash := writer.prevHash
	writer.mu.Unlock()
	if file != nil || gotSegment != 1 || gotSequence != wantSequence || gotOffset != wantOffset || gotHash != wantHash {
		t.Fatalf("failed rotation published state: file=%v segment=%d sequence=%d offset=%d", file, gotSegment, gotSequence, gotOffset)
	}
	if got := rotateCalls.Load(); got != 0 {
		t.Fatalf("OnRotate calls = %d, want 0", got)
	}
	if got := reported.Load(); got != 1 {
		t.Fatalf("OnFsyncError calls = %d, want 1", got)
	}
	info, statErr := os.Stat(filepath.Join(dir, segmentName(2)))
	if statErr != nil || info.Size() != 0 {
		t.Fatalf("unpublished segment = (%v, %v), want empty file", info, statErr)
	}

	wantOpenCalls := openCalls.Load()
	wantSyncCalls := syncCalls.Load()
	wantCloseCalls := closeCalls.Load()
	if _, _, err := writer.Append(context.Background(), []byte("must stay rejected")); !errors.Is(err, sentinel) {
		t.Fatalf("second Append() error = %v, want sticky sentinel", err)
	}
	if err := writer.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("Close() error = %v, want sticky sentinel", err)
	}
	if openCalls.Load() != wantOpenCalls || syncCalls.Load() != wantSyncCalls || closeCalls.Load() != wantCloseCalls {
		t.Fatalf("sticky rejection performed I/O: open %d/%d sync %d/%d close %d/%d", openCalls.Load(), wantOpenCalls, syncCalls.Load(), wantSyncCalls, closeCalls.Load(), wantCloseCalls)
	}
}

func TestRotationPreservesDirectorySyncAndCleanupCloseErrors(t *testing.T) {
	t.Parallel()

	directoryErr := errors.New("injected rotation directory sync failure")
	cleanupErr := errors.New("injected unpublished file close failure")
	dir := t.TempDir()
	ops := defaultWALFileOps()
	var failDirectory atomic.Bool
	var closeCalls atomic.Int64
	ops.syncDir = func(path string) error {
		if failDirectory.Load() {
			return directoryErr
		}
		return syncDirectory(path)
	}
	ops.closeFile = func(file *os.File) error {
		call := closeCalls.Add(1)
		if err := file.Close(); err != nil {
			return err
		}
		if call == 2 {
			return cleanupErr
		}
		return nil
	}
	writer, err := openDirWriterWithOps(dir, Options{FsyncMode: FsyncBatch, MaxSegmentBytes: 1}, ops)
	if err != nil {
		t.Fatalf("openDirWriterWithOps() error = %v", err)
	}
	appendTestRecord(t, writer, "first")
	failDirectory.Store(true)
	_, _, err = writer.Append(context.Background(), []byte("force rotation"))
	if !errors.Is(err, directoryErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("Append() error = %v, want directory and cleanup causes", err)
	}
	if strings.Index(err.Error(), directoryErr.Error()) > strings.Index(err.Error(), cleanupErr.Error()) {
		t.Fatalf("primary directory-sync cause did not remain first: %v", err)
	}
	if err := writer.Close(); !errors.Is(err, directoryErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("Close() error = %v, want cached directory and cleanup causes", err)
	}
	if got := closeCalls.Load(); got != 2 {
		t.Fatalf("close calls = %d, want old segment plus unpublished new segment", got)
	}
}

func TestOpenDirWriterRecoversEmptyHighestSegmentAtZeroOffset(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writer, err := OpenDirWriter(dir, Options{FsyncMode: FsyncBatch})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	firstPos, firstHash, err := writer.Append(context.Background(), []byte("first"))
	if err != nil {
		t.Fatalf("first Append() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	empty, err := os.OpenFile(filepath.Join(dir, segmentName(2)), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create empty highest segment: %v", err)
	}
	if err := empty.Close(); err != nil {
		t.Fatalf("close empty highest segment: %v", err)
	}

	reopened, err := OpenDirWriter(dir, Options{FsyncMode: FsyncBatch, MaxSegmentBytes: 1})
	if err != nil {
		t.Fatalf("reopen OpenDirWriter() error = %v", err)
	}
	secondPos, _, err := reopened.Append(context.Background(), []byte("second"))
	if err != nil {
		t.Fatalf("second Append() error = %v", err)
	}
	if secondPos.SegmentID != 2 || secondPos.Offset != 0 || secondPos.Sequence != firstPos.Sequence+1 {
		t.Fatalf("second position = %+v, want segment=2 offset=0 sequence=%d", secondPos, firstPos.Sequence+1)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("reopened Close() error = %v", err)
	}
	records, err := ReadAllDir(dir)
	if err != nil {
		t.Fatalf("ReadAllDir() error = %v", err)
	}
	if len(records) != 2 || records[1].PrevHash != firstHash {
		t.Fatalf("recovered records = %+v, want continued two-record hash chain", records)
	}
}

func TestAppendSyncsDirectoryOnlyOnRotation(t *testing.T) {
	t.Parallel()

	ops := defaultWALFileOps()
	var syncDirCalls atomic.Int64
	ops.syncDir = func(path string) error {
		syncDirCalls.Add(1)
		return syncDirectory(path)
	}
	writer, err := openDirWriterWithOps(t.TempDir(), Options{FsyncMode: FsyncBatch}, ops)
	if err != nil {
		t.Fatalf("openDirWriterWithOps() error = %v", err)
	}
	defer writer.Close()
	syncDirCalls.Store(0)
	for i := 0; i < 10; i++ {
		appendTestRecord(t, writer, fmt.Sprintf("ordinary-%d", i))
	}
	if got := syncDirCalls.Load(); got != 0 {
		t.Fatalf("ordinary appends directory sync calls = %d, want 0", got)
	}
	writer.mu.Lock()
	writer.maxBytes = writer.offset + 1
	writer.mu.Unlock()
	appendTestRecord(t, writer, "rotate")
	if got := syncDirCalls.Load(); got != 1 {
		t.Fatalf("rotation directory sync calls = %d, want 1", got)
	}
	appendTestRecord(t, writer, "ordinary-after-rotation")
	if got := syncDirCalls.Load(); got != 1 {
		t.Fatalf("post-rotation directory sync calls = %d, want 1", got)
	}
}

func TestPruneSegmentsPersistsOldestFirstAndStopsOnSyncFailure(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("injected prune directory sync failure")
	dir := t.TempDir()
	segments := writeSegmentedWAL(t, dir, 5)
	cutoff := segments[len(segments)-1]
	ops := defaultWALFileOps()
	var (
		events    []string
		syncCalls int
	)
	ops.remove = func(path string) error {
		events = append(events, "remove "+filepath.Base(path))
		return os.Remove(path)
	}
	ops.syncDir = func(path string) error {
		syncCalls++
		events = append(events, "sync")
		if syncCalls == 3 {
			return sentinel
		}
		return syncDirectory(path)
	}
	removed, _, err := pruneSegmentsBeforeWithOps(dir, cutoff, ops)
	if removed != 2 || !errors.Is(err, sentinel) {
		t.Fatalf("prune = removed %d, error %v; want 2 and sentinel", removed, err)
	}
	want := []string{
		"sync",
		"remove " + segmentName(segments[0]),
		"sync",
		"remove " + segmentName(segments[1]),
		"sync",
	}
	if strings.Join(events, "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s\nwant:\n%s", strings.Join(events, "\n"), strings.Join(want, "\n"))
	}
	afterFailure, err := ListSegments(dir)
	if err != nil {
		t.Fatalf("ListSegments() after failure error = %v", err)
	}
	if len(afterFailure) != 3 || afterFailure[0] != segments[2] {
		t.Fatalf("segments after failure = %v, want contiguous suffix starting at %d", afterFailure, segments[2])
	}

	removed, _, err = PruneSegmentsBefore(dir, cutoff)
	if err != nil {
		t.Fatalf("retry PruneSegmentsBefore() error = %v", err)
	}
	if removed != 2 {
		t.Fatalf("retry removed = %d, want 2", removed)
	}
	afterRetry, err := ListSegments(dir)
	if err != nil {
		t.Fatalf("ListSegments() after retry error = %v", err)
	}
	if len(afterRetry) != 1 || afterRetry[0] != cutoff {
		t.Fatalf("segments after retry = %v, want [%d]", afterRetry, cutoff)
	}
}

func TestPrunedSuffixSupportsEveryRecoveryAPI(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	segments := writeSegmentedWAL(t, dir, 6)
	cutoff := segments[3]
	if _, _, err := PruneSegmentsBefore(dir, cutoff); err != nil {
		t.Fatalf("PruneSegmentsBefore() error = %v", err)
	}

	records, err := ReadAllDir(dir)
	if err != nil {
		t.Fatalf("ReadAllDir() after prune error = %v", err)
	}
	if len(records) != 3 || records[0].Position.Sequence != 4 || records[2].Position.Sequence != 6 {
		t.Fatalf("ReadAllDir() after prune positions = %+v", recordPositions(records))
	}
	var scanned []Record
	if err := ScanDirFrom(dir, 0, func(record Record) error {
		scanned = append(scanned, record)
		return nil
	}); err != nil {
		t.Fatalf("ScanDirFrom(0) after prune error = %v", err)
	}
	if len(scanned) != len(records) {
		t.Fatalf("ScanDirFrom(0) records = %d, want %d", len(scanned), len(records))
	}
	inspection, err := InspectDir(dir)
	if err != nil {
		t.Fatalf("InspectDir() after prune error = %v", err)
	}
	if inspection.TotalRecords != len(records) || inspection.FirstSequence != 4 || inspection.LastSequence != 6 {
		t.Fatalf("InspectDir() after prune = %+v", inspection)
	}
	tailPath := filepath.Join(dir, segmentName(segments[len(segments)-1]))
	beforeRepair, err := os.ReadFile(tailPath)
	if err != nil {
		t.Fatalf("read tail before repair: %v", err)
	}
	repair, err := RepairDir(dir)
	if err != nil {
		t.Fatalf("RepairDir() after prune error = %v", err)
	}
	if repair.TailRepair.Repaired {
		t.Fatalf("RepairDir() unexpectedly repaired valid suffix: %+v", repair.TailRepair)
	}
	afterRepair, err := os.ReadFile(tailPath)
	if err != nil {
		t.Fatalf("read tail after repair: %v", err)
	}
	if !bytes.Equal(afterRepair, beforeRepair) {
		t.Fatal("RepairDir() mutated valid retained tail")
	}

	writer, err := OpenDirWriter(dir, Options{FsyncMode: FsyncBatch, MaxSegmentBytes: 500})
	if err != nil {
		t.Fatalf("OpenDirWriter() after prune error = %v", err)
	}
	position, _, err := writer.Append(context.Background(), bytes.Repeat([]byte{'z'}, 200))
	if err != nil {
		t.Fatalf("Append() after prune error = %v", err)
	}
	if position.Sequence != 7 {
		t.Fatalf("Append() after prune sequence = %d, want 7", position.Sequence)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() after prune error = %v", err)
	}
}

func TestPrunedSuffixSkipsLeadingEmptySegmentBeforeBoundarySeed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writer, err := OpenDirWriter(dir, Options{FsyncMode: FsyncBatch})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	_, firstHash, err := writer.Append(context.Background(), []byte("first"))
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, segmentName(2)), nil, 0o600); err != nil {
		t.Fatalf("create empty segment 2: %v", err)
	}
	encoded, _ := encodeRecord(3, 2, time.Unix(2, 0).UnixNano(), firstHash, []byte("third-segment-record"))
	if err := os.WriteFile(filepath.Join(dir, segmentName(3)), encoded, 0o600); err != nil {
		t.Fatalf("create segment 3: %v", err)
	}
	if _, _, err := PruneSegmentsBefore(dir, 2); err != nil {
		t.Fatalf("PruneSegmentsBefore() error = %v", err)
	}

	records, err := ReadAllDir(dir)
	if err != nil || len(records) != 1 || records[0].Position.SegmentID != 3 {
		t.Fatalf("ReadAllDir() = (%+v, %v), want segment 3 record", records, err)
	}
	if err := ScanDirFrom(dir, 0, nil); err != nil {
		t.Fatalf("ScanDirFrom() error = %v", err)
	}
	if _, err := InspectDir(dir); err != nil {
		t.Fatalf("InspectDir() error = %v", err)
	}
	if repair, err := RepairDir(dir); err != nil || repair.TailRepair.Repaired {
		t.Fatalf("RepairDir() = (%+v, %v), want no-op", repair, err)
	}
	reopened, err := OpenDirWriter(dir, Options{FsyncMode: FsyncBatch})
	if err != nil {
		t.Fatalf("OpenDirWriter() after empty boundary error = %v", err)
	}
	defer reopened.Close()
	position, _, err := reopened.Append(context.Background(), []byte("continued"))
	if err != nil || position.Sequence != 3 || position.SegmentID != 3 {
		t.Fatalf("continued Append() = (%+v, %v), want sequence 3 in segment 3", position, err)
	}
}

func TestRecoveryAPIsRejectInternalSegmentGap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	segments := writeSegmentedWAL(t, dir, 4)
	if err := os.Remove(filepath.Join(dir, segmentName(segments[1]))); err != nil {
		t.Fatalf("remove middle segment: %v", err)
	}
	if err := syncDirectory(dir); err != nil {
		t.Fatalf("sync middle-segment removal: %v", err)
	}
	tests := []struct {
		name string
		run  func() error
	}{
		{name: "open writer", run: func() error {
			writer, err := OpenDirWriter(dir, Options{})
			if writer != nil {
				_ = writer.Close()
			}
			return err
		}},
		{name: "read", run: func() error { _, err := ReadAllDir(dir); return err }},
		{name: "scan", run: func() error { return ScanDirFrom(dir, 0, nil) }},
		{name: "inspect", run: func() error { _, err := InspectDir(dir); return err }},
		{name: "repair", run: func() error { _, err := RepairDir(dir); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); err == nil {
				t.Fatal("error = nil, want internal-gap rejection")
			}
		})
	}
}

func TestSegmentNamedSymlinkIsRejectedWithoutMutatingTarget(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside.wal")
	want := []byte("outside data must not be repaired")
	if err := os.WriteFile(target, want, 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	link := filepath.Join(dir, segmentName(1))
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := ListSegments(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("ListSegments() error = %v, want non-regular rejection", err)
	}
	if writer, err := OpenDirWriter(dir, Options{}); err == nil {
		_ = writer.Close()
		t.Fatal("OpenDirWriter() accepted segment-named symlink")
	}
	if _, err := RepairDir(dir); err == nil {
		t.Fatal("RepairDir() accepted segment-named symlink")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read symlink target after rejection: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("symlink target changed to %q", got)
	}
}

func TestListSegmentsRejectsReservedAndNonCanonicalNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		filename string
		want     string
	}{
		{name: "reserved zero", filename: segmentName(0), want: "reserved id 0"},
		{name: "non-canonical", filename: "1.wal", want: "not canonically named"},
		{name: "numeric overflow", filename: "18446744073709551616.wal", want: "invalid numeric id"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, test.filename), nil, 0o600); err != nil {
				t.Fatalf("write segment entry: %v", err)
			}
			if _, err := ListSegments(dir); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ListSegments() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRepairDirRejectsGapBeforeTailWithoutMutation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writer, err := OpenDirWriter(dir, Options{FsyncMode: FsyncBatch})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	_, firstHash, err := writer.Append(context.Background(), []byte("first"))
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	tailPath := filepath.Join(dir, segmentName(3))
	tail, _ := encodeRecord(3, 2, time.Unix(2, 0).UnixNano(), firstHash, []byte("tail"))
	tail = append(tail, []byte("torn-tail")...)
	if err := os.WriteFile(tailPath, tail, 0o600); err != nil {
		t.Fatalf("write gapped tail: %v", err)
	}
	before := map[string][]byte{}
	for _, id := range []uint64{1, 3} {
		path := filepath.Join(dir, segmentName(id))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read segment %d before repair: %v", id, err)
		}
		before[path] = data
	}
	if _, err := RepairDir(dir); err == nil || !strings.Contains(err.Error(), "segment id gap") {
		t.Fatalf("RepairDir() error = %v, want preflight segment gap", err)
	}
	for path, want := range before {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s after repair: %v", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("RepairDir() mutated %s before rejecting tail gap", path)
		}
	}
}

func TestRepairDirTruncatesTornFirstHeaderAtRetainedBoundary(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tailPath := filepath.Join(dir, segmentName(7))
	partialHeader := bytes.Repeat([]byte{0xff}, headerSize-1)
	if err := os.WriteFile(tailPath, partialHeader, 0o600); err != nil {
		t.Fatalf("write partial retained tail: %v", err)
	}
	if _, err := ReadAllDir(dir); err == nil {
		t.Fatal("ReadAllDir() accepted partial first header before repair")
	}
	if writer, err := OpenDirWriter(dir, Options{}); err == nil {
		_ = writer.Close()
		t.Fatal("OpenDirWriter() accepted partial first header before repair")
	}

	result, err := RepairDir(dir)
	if err != nil {
		t.Fatalf("RepairDir() error = %v", err)
	}
	if !result.TailRepair.Repaired || result.TailRepair.TruncatedBytes != int64(len(partialHeader)) {
		t.Fatalf("RepairDir() result = %+v, want complete tail truncation", result.TailRepair)
	}
	info, err := os.Stat(tailPath)
	if err != nil || info.Size() != 0 {
		t.Fatalf("repaired tail = (%v, %v), want zero bytes", info, err)
	}
	reopened, err := OpenDirWriter(dir, Options{FsyncMode: FsyncBatch})
	if err != nil {
		t.Fatalf("OpenDirWriter() after repair error = %v", err)
	}
	position, _, err := reopened.Append(context.Background(), []byte("recovered"))
	if err != nil {
		t.Fatalf("Append() after repair error = %v", err)
	}
	if position.SegmentID != 7 || position.Offset != 0 || position.Sequence != 1 {
		t.Fatalf("Append() after repair position = %+v, want segment 7 offset 0 sequence 1", position)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("Close() after repair error = %v", err)
	}
}

func TestRepairBoundaryDoesNotSuppressOperationalPeekErrors(t *testing.T) {
	t.Parallel()

	chain := segmentChainState{trustBoundary: true}
	if _, err := chain.repairStartPrev(t.TempDir()); err == nil || errors.Is(err, errRepairableFirstHeader) {
		t.Fatalf("repairStartPrev(directory) error = %v, want propagated operational read error", err)
	}
}

func TestRecordReaderDoesNotClassifyOperationalIOAsRepairable(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("injected reader I/O failure")
	if _, _, err := readOne(iotest.ErrReader(sentinel), 0, [32]byte{}); !errors.Is(err, sentinel) || errors.Is(err, errTornRecord) || errors.Is(err, errCorruptRecord) {
		t.Fatalf("readOne() error = %v, want unclassified operational sentinel", err)
	}
}

func TestDirectoryTailRepairsWithinFilePositionViolations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		secondSegment uint64
		secondSeq     uint64
	}{
		{name: "segment id changes", secondSegment: 2, secondSeq: 2},
		{name: "sequence repeats", secondSegment: 1, secondSeq: 1},
		{name: "sequence jumps", secondSegment: 1, secondSeq: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			first, firstHash := encodeRecord(1, 1, 1, [32]byte{}, []byte("first"))
			second, _ := encodeRecord(test.secondSegment, test.secondSeq, 2, firstHash, []byte("second"))
			path := filepath.Join(dir, segmentName(1))
			if err := os.WriteFile(path, append(first, second...), 0o600); err != nil {
				t.Fatalf("write semantic fixture: %v", err)
			}
			if _, err := ReadAllDir(dir); err == nil {
				t.Fatal("ReadAllDir() accepted position violation")
			}
			visits := 0
			if err := ScanDirFrom(dir, 0, func(Record) error { visits++; return nil }); err == nil {
				t.Fatal("ScanDirFrom() accepted position violation")
			}
			if visits != 1 {
				t.Fatalf("ScanDirFrom() visits = %d, want only the valid prefix", visits)
			}
			if _, err := InspectDir(dir); err == nil {
				t.Fatal("InspectDir() accepted position violation")
			}
			if writer, err := OpenDirWriter(dir, Options{}); err == nil {
				_ = writer.Close()
				t.Fatal("OpenDirWriter() accepted position violation")
			}

			repair, err := RepairDir(dir)
			if err != nil {
				t.Fatalf("RepairDir() error = %v", err)
			}
			if !repair.TailRepair.Repaired || repair.TailRepair.ValidBytes != int64(len(first)) {
				t.Fatalf("RepairDir() result = %+v, want truncation to valid first record", repair.TailRepair)
			}
			records, err := ReadAllDir(dir)
			if err != nil || len(records) != 1 || !bytes.Equal(records[0].Payload, []byte("first")) {
				t.Fatalf("records after repair = (%+v, %v)", records, err)
			}
		})
	}
}

func TestCrossSegmentSequenceDiscontinuityIsRejectedBeforeTailMutation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	first, firstHash := encodeRecord(1, 1, 1, [32]byte{}, []byte("first"))
	second, _ := encodeRecord(2, 3, 2, firstHash, []byte("jumped"))
	firstPath := filepath.Join(dir, segmentName(1))
	secondPath := filepath.Join(dir, segmentName(2))
	if err := os.WriteFile(firstPath, first, 0o600); err != nil {
		t.Fatalf("write segment 1: %v", err)
	}
	if err := os.WriteFile(secondPath, second, 0o600); err != nil {
		t.Fatalf("write segment 2: %v", err)
	}
	if _, err := ReadAllDir(dir); err == nil || !strings.Contains(err.Error(), "sequence discontinuity") {
		t.Fatalf("ReadAllDir() error = %v, want sequence discontinuity", err)
	}
	visits := 0
	if err := ScanDirFrom(dir, 0, func(Record) error { visits++; return nil }); err == nil {
		t.Fatal("ScanDirFrom() accepted cross-segment sequence jump")
	}
	if visits != 1 {
		t.Fatalf("ScanDirFrom() visits = %d, want only segment 1", visits)
	}
	before, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatalf("read tail before repair: %v", err)
	}
	if _, err := RepairDir(dir); err == nil || !strings.Contains(err.Error(), "invalid position metadata") {
		t.Fatalf("RepairDir() error = %v, want position preflight rejection", err)
	}
	after, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatalf("read tail after repair: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("RepairDir() mutated cross-segment sequence violation")
	}
}

func TestFreshChainsRequireSequenceOne(t *testing.T) {
	t.Parallel()

	record, _ := encodeRecord(1, 42, 1, [32]byte{}, []byte("wrong start"))
	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, segmentName(1))
		if err := os.WriteFile(path, record, 0o600); err != nil {
			t.Fatalf("write directory fixture: %v", err)
		}
		if _, err := ReadAllDir(dir); err == nil {
			t.Fatal("ReadAllDir() accepted sequence 42 fresh chain")
		}
		visits := 0
		if err := ScanDirFrom(dir, 0, func(Record) error { visits++; return nil }); err == nil || visits != 0 {
			t.Fatalf("ScanDirFrom() = error %v visits %d, want rejection before visit", err, visits)
		}
		before, _ := os.ReadFile(path)
		if _, err := RepairDir(dir); err == nil {
			t.Fatal("RepairDir() accepted sequence 42 fresh chain")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(after, before) {
			t.Fatal("RepairDir() mutated invalid fresh-chain sequence")
		}
	})

	t.Run("single file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "records.wal")
		if err := os.WriteFile(path, record, 0o600); err != nil {
			t.Fatalf("write single-file fixture: %v", err)
		}
		if _, err := ReadAll(path); err == nil {
			t.Fatal("ReadAll() accepted sequence 42 fresh chain")
		}
		visits := 0
		if err := Scan(path, func(Record) error { visits++; return nil }); err == nil || visits != 0 {
			t.Fatalf("Scan() = error %v visits %d, want rejection before visit", err, visits)
		}
		if _, err := Inspect(path); err == nil {
			t.Fatal("Inspect() accepted sequence 42 fresh chain")
		}
		if writer, err := OpenWriter(path, 1); err == nil {
			_ = writer.Close()
			t.Fatal("OpenWriter() accepted sequence 42 fresh chain")
		}
		before, _ := os.ReadFile(path)
		if _, err := Repair(path); err == nil {
			t.Fatal("Repair() accepted sequence 42 fresh chain")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(after, before) {
			t.Fatal("Repair() mutated invalid fresh-chain sequence")
		}
	})
}

func TestStrictRecoveryRejectsExactPayloadAndTrailerEOF(t *testing.T) {
	t.Parallel()

	payload := []byte("payload")
	encoded, _ := encodeRecord(1, 1, 1, [32]byte{}, payload)
	tests := []struct {
		name string
		cut  int
	}{
		{name: "payload starts at EOF", cut: headerSize},
		{name: "trailer starts at EOF", cut: headerSize + len(payload)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "records.wal")
			if err := os.WriteFile(path, encoded[:test.cut], 0o600); err != nil {
				t.Fatalf("write exact-EOF fixture: %v", err)
			}
			if _, err := ReadAll(path); err == nil {
				t.Fatal("ReadAll() accepted exact EOF inside record")
			}
			if err := Scan(path, nil); err == nil {
				t.Fatal("Scan() accepted exact EOF inside record")
			}
			if _, err := Inspect(path); err == nil {
				t.Fatal("Inspect() accepted exact EOF inside record")
			}
			if writer, err := OpenWriter(path, 1); err == nil {
				_ = writer.Close()
				t.Fatal("OpenWriter() accepted exact EOF inside record")
			}
			result, err := Repair(path)
			if err != nil {
				t.Fatalf("Repair() error = %v", err)
			}
			if !result.Repaired || result.TruncatedBytes != int64(test.cut) {
				t.Fatalf("Repair() result = %+v, want full truncation", result)
			}
			writer, err := OpenWriterWithOptions(path, 1, Options{FsyncMode: FsyncBatch})
			if err != nil {
				t.Fatalf("OpenWriter() after repair error = %v", err)
			}
			position, _, err := writer.Append(context.Background(), []byte("recovered"))
			if err != nil {
				t.Fatalf("Append() after repair error = %v", err)
			}
			if position.Offset != 0 || position.Sequence != 1 {
				t.Fatalf("Append() after repair position = %+v, want offset 0 sequence 1", position)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("Close() after repair error = %v", err)
			}
		})
	}
}

func TestRepairRefusesUnknownInitialEncodingWithoutMutation(t *testing.T) {
	t.Parallel()

	valid, _ := encodeRecord(1, 1, 1, [32]byte{}, []byte("record"))
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "bad magic", mutate: func(data []byte) { data[0] ^= 0xff }},
		{name: "future version", mutate: func(data []byte) { data[5]++ }},
		{name: "unknown type", mutate: func(data []byte) { data[7]++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "records.wal")
			fixture := append([]byte(nil), valid...)
			test.mutate(fixture)
			if err := os.WriteFile(path, fixture, 0o600); err != nil {
				t.Fatalf("write encoding fixture: %v", err)
			}
			if _, err := Repair(path); err == nil {
				t.Fatal("Repair() accepted unknown initial encoding")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read after Repair(): %v", err)
			}
			if !bytes.Equal(after, fixture) {
				t.Fatal("Repair() mutated unknown initial encoding")
			}
		})
	}
}

func TestWriterRejectsSequenceAndSegmentIDExhaustion(t *testing.T) {
	t.Parallel()

	t.Run("sequence", func(t *testing.T) {
		dir := t.TempDir()
		prev := [32]byte{1}
		record, _ := encodeRecord(7, ^uint64(0), 1, prev, []byte("last sequence"))
		path := filepath.Join(dir, segmentName(7))
		if err := os.WriteFile(path, record, 0o600); err != nil {
			t.Fatalf("write exhausted sequence fixture: %v", err)
		}
		writer, err := OpenDirWriter(dir, Options{FsyncMode: FsyncBatch})
		if err != nil {
			t.Fatalf("OpenDirWriter() error = %v", err)
		}
		before, _ := os.ReadFile(path)
		if _, _, err := writer.Append(context.Background(), []byte("must fail")); err == nil || !strings.Contains(err.Error(), "sequence exhausted") {
			t.Fatalf("Append() error = %v, want sequence exhaustion", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(after, before) {
			t.Fatal("sequence-exhausted Append() mutated WAL")
		}
	})

	t.Run("segment id", func(t *testing.T) {
		dir := t.TempDir()
		writer, err := OpenDirWriter(dir, Options{InitialSegmentID: ^uint64(0), MaxSegmentBytes: 1, FsyncMode: FsyncBatch})
		if err != nil {
			t.Fatalf("OpenDirWriter() error = %v", err)
		}
		appendTestRecord(t, writer, "first")
		if _, _, err := writer.Append(context.Background(), []byte("must rotate")); err == nil || !strings.Contains(err.Error(), "segment id exhausted") {
			t.Fatalf("rotating Append() error = %v, want segment exhaustion", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		segments, err := ListSegments(dir)
		if err != nil || len(segments) != 1 || segments[0] != ^uint64(0) {
			t.Fatalf("segments = (%v, %v), want only max segment id", segments, err)
		}
	})

	t.Run("offset addition", func(t *testing.T) {
		dir := t.TempDir()
		const maxInt64 = int64(^uint64(0) >> 1)
		writer, err := OpenDirWriter(dir, Options{MaxSegmentBytes: maxInt64, FsyncMode: FsyncBatch})
		if err != nil {
			t.Fatalf("OpenDirWriter() error = %v", err)
		}
		// Simulate an active segment at the largest representable offset.
		// The size comparison must rotate instead of wrapping the sum.
		writer.offset = maxInt64
		position, _, err := writer.Append(context.Background(), []byte("rotate before overflow"))
		if err != nil {
			t.Fatalf("Append() error = %v", err)
		}
		if position.SegmentID != 2 || position.Offset != 0 {
			t.Fatalf("Append() position = %+v, want segment 2 offset 0", position)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
}

func TestEmptyPayloadRecordIsRejectedAndTailRepairable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "records.wal")
	record, _ := encodeRecord(1, 1, 1, [32]byte{}, nil)
	if err := os.WriteFile(path, record, 0o600); err != nil {
		t.Fatalf("write empty-payload record: %v", err)
	}
	if _, err := ReadAll(path); err == nil {
		t.Fatal("ReadAll() accepted empty-payload record")
	}
	result, err := Repair(path)
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	if !result.Repaired || result.ValidBytes != 0 {
		t.Fatalf("Repair() result = %+v, want complete truncation", result)
	}
}

func TestWriterPayloadLengthMatchesRecoveryLimit(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		length int
		ok     bool
	}{
		{name: "empty", length: 0},
		{name: "maximum", length: maxPayloadBytes, ok: true},
		{name: "too large", length: maxPayloadBytes + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validatePayloadLength(test.length)
			if test.ok && err != nil {
				t.Fatalf("validatePayloadLength(%d) error = %v", test.length, err)
			}
			if !test.ok && err == nil {
				t.Fatalf("validatePayloadLength(%d) error = nil", test.length)
			}
		})
	}
}

func TestRepairSynchronizesCleanAndTruncatedFiles(t *testing.T) {
	t.Parallel()

	t.Run("clean file sync failure", func(t *testing.T) {
		path := writeSingleFileWAL(t)
		sentinel := errors.New("injected clean repair sync failure")
		ops := defaultWALFileOps()
		var syncCalls, truncateCalls, closeCalls atomic.Int64
		ops.truncateFile = func(file *os.File, size int64) error {
			truncateCalls.Add(1)
			return file.Truncate(size)
		}
		ops.syncFile = func(*os.File) error {
			syncCalls.Add(1)
			return sentinel
		}
		ops.closeFile = func(file *os.File) error {
			closeCalls.Add(1)
			return file.Close()
		}
		if _, err := repairWithOps(path, ops); !errors.Is(err, sentinel) {
			t.Fatalf("repairWithOps() error = %v, want sentinel", err)
		}
		if syncCalls.Load() != 1 || truncateCalls.Load() != 0 || closeCalls.Load() != 1 {
			t.Fatalf("calls sync/truncate/close = %d/%d/%d, want 1/0/1", syncCalls.Load(), truncateCalls.Load(), closeCalls.Load())
		}
	})

	t.Run("retry after post-truncate sync failure", func(t *testing.T) {
		path := writeSingleFileWAL(t)
		appendGarbage(t, path)
		sentinel := errors.New("injected post-truncate sync failure")
		ops := defaultWALFileOps()
		var truncateCalls atomic.Int64
		ops.truncateFile = func(file *os.File, size int64) error {
			truncateCalls.Add(1)
			return file.Truncate(size)
		}
		ops.syncFile = func(*os.File) error { return sentinel }
		if _, err := repairWithOps(path, ops); !errors.Is(err, sentinel) {
			t.Fatalf("first repairWithOps() error = %v, want sentinel", err)
		}
		if truncateCalls.Load() != 1 {
			t.Fatalf("first repair truncate calls = %d, want 1", truncateCalls.Load())
		}

		retryOps := defaultWALFileOps()
		var retrySyncs atomic.Int64
		retryOps.syncFile = func(file *os.File) error {
			retrySyncs.Add(1)
			return file.Sync()
		}
		result, err := repairWithOps(path, retryOps)
		if err != nil {
			t.Fatalf("retry repairWithOps() error = %v", err)
		}
		if result.Repaired || retrySyncs.Load() != 1 {
			t.Fatalf("retry result = %+v, sync calls = %d; want clean result and one barrier", result, retrySyncs.Load())
		}
	})

	t.Run("truncate and close failures preserve both causes", func(t *testing.T) {
		path := writeSingleFileWAL(t)
		appendGarbage(t, path)
		truncateErr := errors.New("injected truncate failure")
		closeErr := errors.New("injected repair close failure")
		ops := defaultWALFileOps()
		var syncCalls atomic.Int64
		ops.truncateFile = func(*os.File, int64) error { return truncateErr }
		ops.syncFile = func(*os.File) error {
			syncCalls.Add(1)
			return nil
		}
		ops.closeFile = func(file *os.File) error {
			if err := file.Close(); err != nil {
				return errors.Join(closeErr, err)
			}
			return closeErr
		}
		_, err := repairWithOps(path, ops)
		if !errors.Is(err, truncateErr) || !errors.Is(err, closeErr) {
			t.Fatalf("repairWithOps() error = %v, want truncate and close causes", err)
		}
		if syncCalls.Load() != 0 {
			t.Fatalf("sync calls after failed truncate = %d, want 0", syncCalls.Load())
		}
		if strings.Index(err.Error(), truncateErr.Error()) > strings.Index(err.Error(), closeErr.Error()) {
			t.Fatalf("primary truncate cause did not remain first: %v", err)
		}
	})
}

func writeSegmentedWAL(t *testing.T, dir string, count int) []uint64 {
	t.Helper()
	writer, err := OpenDirWriter(dir, Options{FsyncMode: FsyncBatch, MaxSegmentBytes: 500})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	for i := 0; i < count; i++ {
		payload := bytes.Repeat([]byte{byte('a' + i)}, 200)
		if _, _, err := writer.Append(context.Background(), payload); err != nil {
			t.Fatalf("Append(%d) error = %v", i, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	segments, err := ListSegments(dir)
	if err != nil {
		t.Fatalf("ListSegments() error = %v", err)
	}
	if len(segments) != count {
		t.Fatalf("segments = %v, want %d one-record segments", segments, count)
	}
	return segments
}

func writeSingleFileWAL(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "records.wal")
	writer, err := OpenWriterWithOptions(path, 1, Options{FsyncMode: FsyncBatch})
	if err != nil {
		t.Fatalf("OpenWriterWithOptions() error = %v", err)
	}
	if _, _, err := writer.Append(context.Background(), []byte("valid record")); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return path
}

func appendGarbage(t *testing.T, path string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open append garbage: %v", err)
	}
	if _, err := file.Write([]byte("garbage")); err != nil {
		_ = file.Close()
		t.Fatalf("append garbage: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close garbage file: %v", err)
	}
}

func recordPositions(records []Record) []string {
	out := make([]string, len(records))
	for i, record := range records {
		out[i] = fmt.Sprintf("%d/%d/%d", record.Position.SegmentID, record.Position.Offset, record.Position.Sequence)
	}
	return out
}
