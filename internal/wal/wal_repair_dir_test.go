package wal

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/wowtrust/trustdb/internal/trusterr"
)

// TestRepairDirNoOpWhenClean runs RepairDir on a healthy multi-segment WAL
// and verifies that nothing is truncated and the summary reflects the
// original record counts.
func TestRepairDirNoOpWhenClean(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := OpenDirWriter(dir, Options{MaxSegmentBytes: 500})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	for i := 0; i < 6; i++ {
		if _, _, err := w.Append(context.Background(), bytes.Repeat([]byte{byte('a' + i)}, 180)); err != nil {
			t.Fatalf("Append(%d) error = %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	idsBefore, err := ListSegments(dir)
	if err != nil {
		t.Fatalf("ListSegments() error = %v", err)
	}
	if len(idsBefore) < 2 {
		t.Fatalf("expected at least 2 segments, got %d", len(idsBefore))
	}

	result, err := RepairDir(dir)
	if err != nil {
		t.Fatalf("RepairDir() error = %v", err)
	}
	if result.TailRepair.Repaired {
		t.Fatalf("expected tail repair to be a no-op, got %+v", result.TailRepair)
	}
	if result.TailRepair.TruncatedBytes != 0 {
		t.Fatalf("expected 0 truncated bytes, got %d", result.TailRepair.TruncatedBytes)
	}
	if got, want := len(result.Segments), len(idsBefore); got != want {
		t.Fatalf("Segments len = %d, want %d", got, want)
	}
	if result.ActiveSegmentID != idsBefore[len(idsBefore)-1] {
		t.Fatalf("ActiveSegmentID = %d, want %d", result.ActiveSegmentID, idsBefore[len(idsBefore)-1])
	}
}

// TestRepairDirTruncatesTailGarbage appends junk bytes to the tail segment
// and verifies that RepairDir truncates to the last valid record boundary
// while leaving every earlier segment untouched.
func TestRepairDirTruncatesTailGarbage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := OpenDirWriter(dir, Options{MaxSegmentBytes: 500})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	for i := 0; i < 6; i++ {
		if _, _, err := w.Append(context.Background(), bytes.Repeat([]byte{byte('a' + i)}, 180)); err != nil {
			t.Fatalf("Append(%d) error = %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	ids, err := ListSegments(dir)
	if err != nil {
		t.Fatalf("ListSegments() error = %v", err)
	}
	tailID := ids[len(ids)-1]
	tailPath := filepath.Join(dir, segmentName(tailID))
	infoBefore, err := os.Stat(tailPath)
	if err != nil {
		t.Fatalf("stat tail: %v", err)
	}

	// Record the hash of the first (non-tail) segment so we can assert it
	// is not mutated by the repair.
	firstPath := filepath.Join(dir, segmentName(ids[0]))
	firstBefore, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatalf("read first segment: %v", err)
	}

	tailFile, err := os.OpenFile(tailPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open tail: %v", err)
	}
	junk := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 32)
	if _, err := tailFile.Write(junk); err != nil {
		t.Fatalf("write junk: %v", err)
	}
	if err := tailFile.Close(); err != nil {
		t.Fatalf("close tail: %v", err)
	}

	result, err := RepairDir(dir)
	if err != nil {
		t.Fatalf("RepairDir() error = %v", err)
	}
	if !result.TailRepair.Repaired {
		t.Fatalf("expected tail repair to run, got %+v", result.TailRepair)
	}
	if result.TailRepair.TruncatedBytes != int64(len(junk)) {
		t.Fatalf("TruncatedBytes = %d, want %d", result.TailRepair.TruncatedBytes, len(junk))
	}
	if result.TailRepair.OriginalBytes != infoBefore.Size()+int64(len(junk)) {
		t.Fatalf("OriginalBytes = %d, want %d", result.TailRepair.OriginalBytes, infoBefore.Size()+int64(len(junk)))
	}

	// First segment must be byte-identical after repair.
	firstAfter, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatalf("read first segment after: %v", err)
	}
	if !bytes.Equal(firstBefore, firstAfter) {
		t.Fatalf("non-tail segment was mutated by RepairDir")
	}

	// The writer should be able to reopen the directory and continue with
	// a contiguous sequence.
	w2, err := OpenDirWriter(dir, Options{MaxSegmentBytes: 500})
	if err != nil {
		t.Fatalf("OpenDirWriter() after repair error = %v", err)
	}
	pos, _, err := w2.Append(context.Background(), []byte("post-repair"))
	if err != nil {
		t.Fatalf("Append after repair error = %v", err)
	}
	if pos.Sequence == 0 {
		t.Fatalf("Append after repair returned zero sequence: %+v", pos)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("Close w2: %v", err)
	}
}

// TestRepairDirRejectsNonTailCorruption corrupts a non-tail segment and
// verifies that RepairDir refuses to modify anything on disk, returning
// a FAILED_PRECONDITION error.
func TestRepairDirRejectsNonTailCorruption(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := OpenDirWriter(dir, Options{MaxSegmentBytes: 500})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, _, err := w.Append(context.Background(), bytes.Repeat([]byte{byte('a' + i)}, 180)); err != nil {
			t.Fatalf("Append(%d) error = %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	ids, err := ListSegments(dir)
	if err != nil {
		t.Fatalf("ListSegments() error = %v", err)
	}
	if len(ids) < 3 {
		t.Fatalf("expected at least 3 segments for non-tail corruption test, got %d", len(ids))
	}

	// Snapshot every segment's bytes so we can assert no mutation.
	snapshots := make(map[uint64][]byte, len(ids))
	for _, id := range ids {
		data, err := os.ReadFile(filepath.Join(dir, segmentName(id)))
		if err != nil {
			t.Fatalf("read seg %d: %v", id, err)
		}
		snapshots[id] = data
	}

	// Corrupt the middle segment by flipping a byte in the middle of a
	// record (not in the trailing padding, so it breaks validation).
	midID := ids[len(ids)/2]
	midPath := filepath.Join(dir, segmentName(midID))
	data := snapshots[midID]
	if len(data) < 40 {
		t.Fatalf("mid segment too small to corrupt: %d bytes", len(data))
	}
	data = append([]byte(nil), data...)
	data[len(data)/2] ^= 0xFF
	if err := os.WriteFile(midPath, data, 0o644); err != nil {
		t.Fatalf("write corrupt mid: %v", err)
	}
	snapshots[midID] = data

	_, err = RepairDir(dir)
	if err == nil {
		t.Fatalf("RepairDir() = nil, want error")
	}
	if code := trusterr.CodeOf(err); code != trusterr.CodeFailedPrecondition {
		t.Fatalf("CodeOf(err) = %s, want %s", code, trusterr.CodeFailedPrecondition)
	}

	for _, id := range ids {
		got, err := os.ReadFile(filepath.Join(dir, segmentName(id)))
		if err != nil {
			t.Fatalf("read seg %d after: %v", id, err)
		}
		if !bytes.Equal(got, snapshots[id]) {
			t.Fatalf("segment %d was mutated by RepairDir despite error", id)
		}
	}
}

// TestRepairDirEmptyDir asserts that running RepairDir against an empty
// directory is a no-op and returns a zero-valued result without error.
func TestRepairDirEmptyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	result, err := RepairDir(dir)
	if err != nil {
		t.Fatalf("RepairDir() error = %v", err)
	}
	if len(result.Segments) != 0 {
		t.Fatalf("Segments = %v, want empty", result.Segments)
	}
	if result.ActiveSegmentID != 0 {
		t.Fatalf("ActiveSegmentID = %d, want 0", result.ActiveSegmentID)
	}
	if result.TailRepair.Repaired {
		t.Fatalf("TailRepair.Repaired = true, want false")
	}
}

// TestRepairDirMissingDir checks that RepairDir tolerates a non-existent
// path by treating it the same as an empty directory, mirroring the
// lenient semantics of ListSegments.
func TestRepairDirMissingDir(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "does-not-exist")
	result, err := RepairDir(dir)
	if err != nil {
		t.Fatalf("RepairDir() error = %v", err)
	}
	if len(result.Segments) != 0 || result.ActiveSegmentID != 0 {
		t.Fatalf("expected empty result, got %+v", result)
	}
}
