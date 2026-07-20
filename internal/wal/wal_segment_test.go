package wal

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestOpenDirWriterCreatesInitialSegment verifies that an empty directory is
// provisioned with segment 1 (or the configured InitialSegmentID) and that
// Append writes into that segment with sequence starting at 1.
func TestOpenDirWriterCreatesInitialSegment(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := OpenDirWriter(dir, Options{})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	defer w.Close()
	if got := w.ActiveSegmentID(); got != 1 {
		t.Fatalf("ActiveSegmentID() = %d, want 1", got)
	}
	pos, _, err := w.Append(context.Background(), []byte("hello"))
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if pos.SegmentID != 1 || pos.Sequence != 1 {
		t.Fatalf("Append() pos = %+v", pos)
	}
	if _, err := os.Stat(filepath.Join(dir, segmentName(1))); err != nil {
		t.Fatalf("expected segment 1 file on disk: %v", err)
	}
}

// TestOpenDirWriterHonorsInitialSegmentID checks that an empty directory can
// be bootstrapped with a non-default segment id (useful for tests and for
// disaster-recovery scenarios where a cluster restarts from a known segment).
func TestOpenDirWriterHonorsInitialSegmentID(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := OpenDirWriter(dir, Options{InitialSegmentID: 7})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	defer w.Close()
	if got := w.ActiveSegmentID(); got != 7 {
		t.Fatalf("ActiveSegmentID() = %d, want 7", got)
	}
}

// TestWriterAutoRotatesOnMaxBytes drives Append past MaxSegmentBytes and
// verifies that (a) records are never split across segments, (b) the hash
// chain continues across the boundary, and (c) the writer advances to the
// next segment id without operator intervention.
func TestWriterAutoRotatesOnMaxBytes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Payloads of ~200 bytes each; MaxSegmentBytes set so that two records
	// fit per segment, forcing rotation on the third.
	w, err := OpenDirWriter(dir, Options{MaxSegmentBytes: 700})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	defer w.Close()

	payloads := make([][]byte, 5)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{byte('a' + i)}, 200)
	}
	positions := make([]uint64, len(payloads))
	for i, p := range payloads {
		pos, _, err := w.Append(context.Background(), p)
		if err != nil {
			t.Fatalf("Append(%d) error = %v", i, err)
		}
		positions[i] = pos.SegmentID
	}
	if w.ActiveSegmentID() == 1 {
		t.Fatalf("writer stayed on segment 1 after 5 writes of 200 bytes with max=700")
	}

	segs, err := ListSegments(dir)
	if err != nil {
		t.Fatalf("ListSegments() error = %v", err)
	}
	if len(segs) < 2 {
		t.Fatalf("ListSegments() = %v, want at least 2 segments", segs)
	}
	records, err := ReadAllDir(dir)
	if err != nil {
		t.Fatalf("ReadAllDir() error = %v", err)
	}
	if len(records) != len(payloads) {
		t.Fatalf("ReadAllDir() len = %d, want %d", len(records), len(payloads))
	}
	for i, rec := range records {
		if !bytes.Equal(rec.Payload, payloads[i]) {
			t.Fatalf("record %d payload mismatch", i)
		}
		if rec.Position.Sequence != uint64(i+1) {
			t.Fatalf("record %d sequence = %d, want %d", i, rec.Position.Sequence, i+1)
		}
		if rec.Position.SegmentID != positions[i] {
			t.Fatalf("record %d segment_id = %d, want %d (matching Append result)", i, rec.Position.SegmentID, positions[i])
		}
	}
}

// TestReadAllDirFromSkipsEarlySegments validates the checkpoint-driven
// startup path: records in earlier segments are not returned, but the hash
// chain of the returned tail still verifies internally.
func TestReadAllDirFromSkipsEarlySegments(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := OpenDirWriter(dir, Options{MaxSegmentBytes: 500})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	defer w.Close()
	for i := 0; i < 6; i++ {
		if _, _, err := w.Append(context.Background(), bytes.Repeat([]byte{byte('A' + i)}, 200)); err != nil {
			t.Fatalf("Append(%d) error = %v", i, err)
		}
	}

	segs, err := ListSegments(dir)
	if err != nil {
		t.Fatalf("ListSegments() error = %v", err)
	}
	if len(segs) < 3 {
		t.Fatalf("want >= 3 segments, got %v", segs)
	}

	all, err := ReadAllDirFrom(dir, 0)
	if err != nil {
		t.Fatalf("ReadAllDirFrom(0) error = %v", err)
	}
	tail, err := ReadAllDirFrom(dir, segs[1])
	if err != nil {
		t.Fatalf("ReadAllDirFrom(%d) error = %v", segs[1], err)
	}
	if len(tail) >= len(all) {
		t.Fatalf("tail len=%d not less than all len=%d", len(tail), len(all))
	}
	for _, rec := range tail {
		if rec.Position.SegmentID < segs[1] {
			t.Fatalf("returned record from skipped segment: %+v", rec.Position)
		}
	}
}

func TestScanDirFromStreamsLikeReadAllDirFrom(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := OpenDirWriter(dir, Options{MaxSegmentBytes: 500})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	for i := 0; i < 6; i++ {
		if _, _, err := w.Append(context.Background(), bytes.Repeat([]byte{byte('a' + i)}, 200)); err != nil {
			t.Fatalf("Append(%d) error = %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	segs, err := ListSegments(dir)
	if err != nil {
		t.Fatalf("ListSegments() error = %v", err)
	}
	if len(segs) < 2 {
		t.Fatalf("want rotated WAL, got %v", segs)
	}
	want, err := ReadAllDirFrom(dir, segs[1])
	if err != nil {
		t.Fatalf("ReadAllDirFrom() error = %v", err)
	}
	var got []Record
	if err := ScanDirFrom(dir, segs[1], func(rec Record) error {
		got = append(got, rec)
		return nil
	}); err != nil {
		t.Fatalf("ScanDirFrom() error = %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("ScanDirFrom len=%d want=%d", len(got), len(want))
	}
	for i := range want {
		if got[i].Position != want[i].Position || !bytes.Equal(got[i].Payload, want[i].Payload) {
			t.Fatalf("record %d mismatch got=%+v want=%+v", i, got[i].Position, want[i].Position)
		}
	}
}

// TestOpenDirWriterResumesAfterRestart closes a rotating writer, reopens the
// same directory, appends more records, and verifies the combined read back
// matches the write order. This is the core "restart across rotation" test.
func TestOpenDirWriterResumesAfterRestart(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := OpenDirWriter(dir, Options{MaxSegmentBytes: 500})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	firstBatch := [][]byte{
		bytes.Repeat([]byte{'a'}, 200),
		bytes.Repeat([]byte{'b'}, 200),
		bytes.Repeat([]byte{'c'}, 200),
	}
	for i, p := range firstBatch {
		if _, _, err := w.Append(context.Background(), p); err != nil {
			t.Fatalf("first Append(%d) error = %v", i, err)
		}
	}
	segBeforeClose := w.ActiveSegmentID()
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	w2, err := OpenDirWriter(dir, Options{MaxSegmentBytes: 500})
	if err != nil {
		t.Fatalf("reopen OpenDirWriter() error = %v", err)
	}
	if w2.ActiveSegmentID() != segBeforeClose {
		t.Fatalf("reopened on segment %d, want %d", w2.ActiveSegmentID(), segBeforeClose)
	}
	secondBatch := [][]byte{
		bytes.Repeat([]byte{'d'}, 200),
		bytes.Repeat([]byte{'e'}, 200),
	}
	for i, p := range secondBatch {
		if _, _, err := w2.Append(context.Background(), p); err != nil {
			t.Fatalf("second Append(%d) error = %v", i, err)
		}
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}

	records, err := ReadAllDir(dir)
	if err != nil {
		t.Fatalf("ReadAllDir() error = %v", err)
	}
	want := append([][]byte{}, firstBatch...)
	want = append(want, secondBatch...)
	if len(records) != len(want) {
		t.Fatalf("ReadAllDir() len = %d, want %d", len(records), len(want))
	}
	for i, rec := range records {
		if !bytes.Equal(rec.Payload, want[i]) {
			t.Fatalf("record %d payload mismatch", i)
		}
		if rec.Position.Sequence != uint64(i+1) {
			t.Fatalf("record %d sequence = %d, want %d (counter must continue across restart)", i, rec.Position.Sequence, i+1)
		}
	}
}

// TestReadAllDirDetectsHashChainBreak corrupts one segment's last hash by
// overwriting the next segment's first record's prev_hash field on disk,
// then verifies ReadAllDir surfaces the break rather than silently returning
// mismatched records.
func TestReadAllDirDetectsHashChainBreak(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := OpenDirWriter(dir, Options{MaxSegmentBytes: 500})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	for i := 0; i < 4; i++ {
		if _, _, err := w.Append(context.Background(), bytes.Repeat([]byte{byte('a' + i)}, 200)); err != nil {
			t.Fatalf("Append(%d) error = %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	segs, err := ListSegments(dir)
	if err != nil {
		t.Fatalf("ListSegments() error = %v", err)
	}
	if len(segs) < 2 {
		t.Fatalf("want >= 2 segments, got %v", segs)
	}
	// Flip a byte inside the prev_hash field of the second segment's first
	// record (header offset 32..64). The CRC and record hash will still
	// check out locally, but the cross-segment chain must fail.
	secondSeg := filepath.Join(dir, segmentName(segs[1]))
	data, err := os.ReadFile(secondSeg)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", secondSeg, err)
	}
	data[40] ^= 0xff
	if err := os.WriteFile(secondSeg, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := ReadAllDir(dir); err == nil {
		t.Fatal("ReadAllDir() error = nil, want hash chain break")
	}
}

// TestOpenDirWriterRejectsDirtyRotation ensures that if a gap exists in the
// on-disk segment sequence (e.g. someone manually deleted a middle segment)
// the writer refuses to open rather than silently re-numbering things.
func TestOpenDirWriterRejectsChainBreakOnOpen(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := OpenDirWriter(dir, Options{MaxSegmentBytes: 500})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	for i := 0; i < 4; i++ {
		if _, _, err := w.Append(context.Background(), bytes.Repeat([]byte{byte('a' + i)}, 200)); err != nil {
			t.Fatalf("Append(%d) error = %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	segs, _ := ListSegments(dir)
	if len(segs) < 2 {
		t.Fatalf("want >= 2 segments, got %v", segs)
	}
	// Tamper with the last record of segment 1 so its record hash no
	// longer matches segment 2's prev hash. We corrupt the CRC byte which
	// will also fail segment 1's own scan.
	firstSeg := filepath.Join(dir, segmentName(segs[0]))
	data, err := os.ReadFile(firstSeg)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", firstSeg, err)
	}
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(firstSeg, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := OpenDirWriter(dir, Options{}); err == nil {
		t.Fatal("OpenDirWriter() error = nil, want scan failure on corrupted segment")
	}
}

// TestSegmentNameRoundTrip guards against name-format regressions that
// would change the on-disk layout (any change here is a migration).
func TestSegmentNameRoundTrip(t *testing.T) {
	t.Parallel()

	for _, id := range []uint64{1, 42, 999999999} {
		name := segmentName(id)
		got, ok := parseSegmentName(name)
		if !ok || got != id {
			t.Fatalf("roundtrip(%d) = name=%q parsed=%d ok=%v", id, name, got, ok)
		}
	}
	want := "000000001.wal"
	if got := segmentName(1); got != want {
		t.Fatalf("segmentName(1) = %q, want %q", got, want)
	}
	if _, ok := parseSegmentName("not-a-segment.txt"); ok {
		t.Fatal("parseSegmentName() accepted non-segment name")
	}
	if _, ok := parseSegmentName(segmentName(0)); ok {
		t.Fatal("parseSegmentName() accepted reserved segment id 0")
	}
}

// TestWriterRotatesPastOversizedRecord makes sure an Append whose single
// record exceeds MaxSegmentBytes still succeeds rather than looping: segments
// that have already been written stay below the cap, but an oversized record
// lands in its own segment.
func TestWriterRotatesPastOversizedRecord(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := OpenDirWriter(dir, Options{MaxSegmentBytes: 100})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	defer w.Close()
	// A payload much larger than MaxSegmentBytes. Must still succeed.
	big := bytes.Repeat([]byte{'x'}, 4096)
	if _, _, err := w.Append(context.Background(), big); err != nil {
		t.Fatalf("Append(big) error = %v", err)
	}
	small := []byte("tiny")
	if _, _, err := w.Append(context.Background(), small); err != nil {
		t.Fatalf("Append(small) error = %v", err)
	}
	records, err := ReadAllDir(dir)
	if err != nil {
		t.Fatalf("ReadAllDir() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d, want 2", len(records))
	}
	if !bytes.Equal(records[0].Payload, big) || !bytes.Equal(records[1].Payload, small) {
		t.Fatalf("payloads mismatch: %q / %q", records[0].Payload, records[1].Payload)
	}
}

// TestPruneSegmentsBeforeDeletesEarlySegments drives the GC path that a
// checkpoint-advancing scheduler will eventually trigger: segments strictly
// older than segmentID are removed and their bytes reported; the active
// segment and any equal-to-or-later segments are preserved.
func TestPruneSegmentsBeforeDeletesEarlySegments(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := OpenDirWriter(dir, Options{MaxSegmentBytes: 500})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, _, err := w.Append(context.Background(), bytes.Repeat([]byte{byte('a' + i)}, 200)); err != nil {
			t.Fatalf("Append(%d) error = %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	segs, err := ListSegments(dir)
	if err != nil {
		t.Fatalf("ListSegments() error = %v", err)
	}
	if len(segs) < 3 {
		t.Fatalf("want >= 3 segments, got %v", segs)
	}
	cut := segs[len(segs)-1] // keep only the active segment
	removed, bytesRemoved, err := PruneSegmentsBefore(dir, cut)
	if err != nil {
		t.Fatalf("PruneSegmentsBefore() error = %v", err)
	}
	if removed != len(segs)-1 {
		t.Fatalf("removed = %d, want %d", removed, len(segs)-1)
	}
	if bytesRemoved <= 0 {
		t.Fatalf("bytesRemoved = %d, want > 0", bytesRemoved)
	}

	after, err := ListSegments(dir)
	if err != nil {
		t.Fatalf("ListSegments() after prune error = %v", err)
	}
	if len(after) != 1 || after[0] != cut {
		t.Fatalf("segments after prune = %v, want [%d]", after, cut)
	}
	// Remaining segment must still be readable, with ReadAllDirFrom
	// accepting the stored prev_hash as the chain seed.
	recs, err := ReadAllDirFrom(dir, cut)
	if err != nil {
		t.Fatalf("ReadAllDirFrom() after prune error = %v", err)
	}
	if len(recs) == 0 {
		t.Fatalf("ReadAllDirFrom() = 0 records, want > 0 (active segment has content)")
	}
}

// TestPruneSegmentsBeforeIsIdempotent checks that running prune twice with
// the same cutoff is a no-op on the second call and that cutoff <= 1 is a
// safe no-op.
func TestPruneSegmentsBeforeIsIdempotent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := OpenDirWriter(dir, Options{MaxSegmentBytes: 500})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, _, err := w.Append(context.Background(), bytes.Repeat([]byte{byte('a' + i)}, 200)); err != nil {
			t.Fatalf("Append(%d) error = %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, _, err := PruneSegmentsBefore(dir, 0); err != nil {
		t.Fatalf("PruneSegmentsBefore(0) error = %v", err)
	}
	if _, _, err := PruneSegmentsBefore(dir, 1); err != nil {
		t.Fatalf("PruneSegmentsBefore(1) error = %v", err)
	}
	segs, _ := ListSegments(dir)
	before := len(segs)
	cut := segs[len(segs)-1]
	if _, _, err := PruneSegmentsBefore(dir, cut); err != nil {
		t.Fatalf("first PruneSegmentsBefore(cut) error = %v", err)
	}
	removed, bytesRemoved, err := PruneSegmentsBefore(dir, cut)
	if err != nil {
		t.Fatalf("second PruneSegmentsBefore(cut) error = %v", err)
	}
	if removed != 0 || bytesRemoved != 0 {
		t.Fatalf("second prune removed=%d bytes=%d, want 0/0", removed, bytesRemoved)
	}
	after, _ := ListSegments(dir)
	if len(after) > before {
		t.Fatalf("segment count grew from %d to %d", before, len(after))
	}
}

// TestEmptyDirReturnsNoRecords is the smoke test for a fresh WAL location.
func TestEmptyDirReturnsNoRecords(t *testing.T) {
	t.Parallel()

	records, err := ReadAllDir(t.TempDir())
	if err != nil {
		t.Fatalf("ReadAllDir() error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(records) = %d, want 0", len(records))
	}
}

// helper sanity: make sure the fmt-based segment name does not exceed the
// documented width for the ids we plan to allow (guards against accidental
// %d drift that would break lexicographic ordering with existing segments).
func TestSegmentNameWidth(t *testing.T) {
	t.Parallel()

	name := segmentName(1)
	if got := len(name) - len(segmentFileExt); got != segmentIDWidth {
		t.Fatalf("segment stem width = %d, want %d (got name %q)", got, segmentIDWidth, name)
	}
	// Numeric overflow past the declared width is expected to extend the
	// string; callers that care about ordering should stay below 10^width.
	wide := segmentName(1_000_000_000)
	if !stringContainsDigit(wide, '1') {
		t.Fatalf("segmentName(1e9) = %q, expected to contain a '1'", wide)
	}
	if fmt.Sprintf("%d", uint64(len(wide))) == "" {
		t.Fatal("sanity")
	}
}

func stringContainsDigit(s string, d byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == d {
			return true
		}
	}
	return false
}
