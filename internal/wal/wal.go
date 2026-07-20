package wal

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

const (
	magic                  uint32 = 0x54445731
	version                uint16 = 1
	typeAccepted           uint16 = 1
	headerSize                    = 4 + 2 + 2 + 8 + 8 + 8 + 32 + 4
	crcSize                       = 4
	recordHashSize                = 32
	maxPayloadBytes               = 64 << 20
	maxReusableRecordBytes        = 1 << 20
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

const (
	FsyncStrict = "strict"
	FsyncGroup  = "group"
	FsyncBatch  = "batch"
)

// Options controls the behaviour of a directory-mode Writer. A zero Options
// is safe to use in tests: it disables auto-rotation and keeps everything in
// a single segment.
type Options struct {
	// MaxSegmentBytes, when > 0, makes Append rotate the active segment as
	// soon as appending the next record would push the segment past this
	// byte count. Records are never split across segment boundaries.
	MaxSegmentBytes int64
	// InitialSegmentID is used when the directory has no segment files
	// yet. It defaults to 1 if zero. Existing segments always win: a
	// directory with 000000004.wal present reopens as segment 4 (or rolls
	// forward from it) regardless of this value.
	InitialSegmentID uint64
	// OnRotate is invoked after a successful segment rotation inside
	// Append with the id of the segment that was just closed (from) and
	// the id of the new active segment (to). The callback runs while the
	// writer lock is held, so it must stay lightweight — updating a gauge
	// or dispatching a background task is fine; blocking on IO is not.
	// Callers targeting single-file WALs (OpenWriter) do not need this
	// field because rotation never happens there.
	OnRotate func(from, to uint64)
	// FsyncMode controls when Append waits for durable storage:
	// strict = fsync every record; group = fsync at most once per interval;
	// batch = rely on rotation/close/checkpoint boundaries.
	FsyncMode string
	// GroupCommitInterval is used when FsyncMode is group. A zero value
	// defaults to 10ms to keep latency bounded while avoiding per-record sync.
	GroupCommitInterval time.Duration
	OnAppend            func(string, time.Duration)
	OnFsync             func(string, time.Duration)
}

// segmentFileExt is the on-disk suffix for each WAL segment. Segments are
// named "<zero-padded-segment-id><segmentFileExt>"; see segmentName for the
// exact layout.
const segmentFileExt = ".wal"

// segmentIDWidth keeps lexicographic order aligned with numeric order for
// up to ~10^9 segments (enough for years of workload even with 1 MiB
// segments).
const segmentIDWidth = 9

type Writer struct {
	mu         sync.Mutex
	file       *os.File
	dir        string // empty in legacy single-file mode
	maxBytes   int64
	segmentID  uint64
	sequence   uint64
	offset     int64
	prevHash   [32]byte
	rotateHook func(from, to uint64) // test hook; nil in production
	fsyncMode  string
	groupEvery time.Duration
	lastSync   time.Time
	appendHook func(string, time.Duration)
	fsyncHook  func(string, time.Duration)
	recordBuf  []byte
}

type Record struct {
	Position   model.WALPosition
	UnixNano   int64
	Payload    []byte
	PrevHash   [32]byte
	RecordHash [32]byte
}

type InspectResult struct {
	Path          string `json:"path"`
	Records       int    `json:"records"`
	ValidBytes    int64  `json:"valid_bytes"`
	FirstSequence uint64 `json:"first_sequence"`
	LastSequence  uint64 `json:"last_sequence"`
	SegmentID     uint64 `json:"segment_id"`
	LastHash      []byte `json:"last_hash"`
}

type RepairResult struct {
	Path           string `json:"path"`
	Records        int    `json:"records"`
	ValidBytes     int64  `json:"valid_bytes"`
	OriginalBytes  int64  `json:"original_bytes"`
	TruncatedBytes int64  `json:"truncated_bytes"`
	Repaired       bool   `json:"repaired"`
}

// OpenDirWriter opens a WAL in directory mode. The directory may be empty
// (a fresh WAL) or already contain segment files; in the latter case the
// writer reopens the highest-numbered segment and continues appending to it,
// preserving sequence counters and the cross-segment hash chain. Setting
// opts.MaxSegmentBytes > 0 enables automatic segment rotation on Append.
func OpenDirWriter(dir string, opts Options) (*Writer, error) {
	if dir == "" {
		return nil, errors.New("wal: directory path is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("wal: create dir: %w", err)
	}
	segments, err := ListSegments(dir)
	if err != nil {
		return nil, err
	}
	var (
		activeSeg uint64
		sequence  uint64
		offset    int64
		prev      [32]byte
	)
	if len(segments) == 0 {
		activeSeg = opts.InitialSegmentID
		if activeSeg == 0 {
			activeSeg = 1
		}
	} else {
		// Replay every segment so the writer starts with the exact
		// sequence/prev-hash state the next Append would need. The prev
		// hash threads across segments, which is also where any chain
		// break is diagnosed.
		var (
			last      scanState
			chainPrev [32]byte
			prevSeg   uint64
		)
		for i, seg := range segments {
			state, err := scanFileFrom(filepath.Join(dir, segmentName(seg)), false, false, chainPrev)
			if err != nil {
				return nil, fmt.Errorf("wal: scan segment %d: %w", seg, err)
			}
			if state.records == 0 {
				continue
			}
			if state.segmentID != seg {
				return nil, fmt.Errorf("wal: segment %d file reports segment_id %d", seg, state.segmentID)
			}
			if i > 0 && last.records > 0 && state.firstPrev != last.lastHash {
				return nil, fmt.Errorf("wal: hash chain break between segments %d and %d", prevSeg, seg)
			}
			chainPrev = state.lastHash
			prevSeg = seg
			last = state
		}
		activeSeg = segments[len(segments)-1]
		sequence = last.lastSequence
		offset = last.validBytes
		prev = last.lastHash
	}
	path := filepath.Join(dir, segmentName(activeSeg))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("wal: open segment %d: %w", activeSeg, err)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("wal: seek end: %w", err)
	}
	return &Writer{
		file:       f,
		dir:        dir,
		maxBytes:   opts.MaxSegmentBytes,
		segmentID:  activeSeg,
		sequence:   sequence,
		offset:     offset,
		prevHash:   prev,
		rotateHook: opts.OnRotate,
		fsyncMode:  normalizeFsyncMode(opts.FsyncMode),
		groupEvery: normalizeGroupInterval(opts.GroupCommitInterval),
		appendHook: opts.OnAppend,
		fsyncHook:  opts.OnFsync,
	}, nil
}

// ActiveSegmentID returns the segment id the writer is currently appending
// to. Exposed mainly for tests and metrics.
func (w *Writer) ActiveSegmentID() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.segmentID
}

func OpenWriter(path string, segmentID uint64) (*Writer, error) {
	return OpenWriterWithOptions(path, segmentID, Options{FsyncMode: FsyncStrict})
}

func OpenWriterWithOptions(path string, segmentID uint64, opts Options) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("wal: create dir: %w", err)
	}
	state, err := scanFile(path, false, false)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("wal: scan existing log: %w", err)
	}
	if state.records > 0 && state.segmentID != segmentID {
		return nil, fmt.Errorf("wal: segment id mismatch: existing %d requested %d", state.segmentID, segmentID)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("wal: open writer: %w", err)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("wal: seek end: %w", err)
	}
	return &Writer{
		file:       f,
		segmentID:  segmentID,
		sequence:   state.lastSequence,
		offset:     state.validBytes,
		prevHash:   state.lastHash,
		fsyncMode:  normalizeFsyncMode(opts.FsyncMode),
		groupEvery: normalizeGroupInterval(opts.GroupCommitInterval),
		appendHook: opts.OnAppend,
		fsyncHook:  opts.OnFsync,
	}, nil
}

func (w *Writer) Append(ctx context.Context, payload []byte) (model.WALPosition, [32]byte, error) {
	return w.AppendAt(ctx, payload, time.Now().UTC())
}

func (w *Writer) AppendAt(ctx context.Context, payload []byte, at time.Time) (model.WALPosition, [32]byte, error) {
	if len(payload) == 0 {
		return model.WALPosition{}, [32]byte{}, errors.New("wal: empty payload")
	}
	if err := ctx.Err(); err != nil {
		return model.WALPosition{}, [32]byte{}, err
	}

	start := time.Now()
	defer func() {
		if w.appendHook != nil {
			w.appendHook(w.fsyncMode, time.Since(start))
		}
	}()

	w.mu.Lock()
	defer w.mu.Unlock()

	// Auto-rotate before writing, never in the middle, so a single record
	// is always entirely contained in one segment. A segment that does not
	// yet hold any record is never rotated away even if the configured
	// maxBytes is smaller than the record we're about to write; that way
	// an oversized record still makes forward progress instead of looping
	// forever between rotations.
	nextSeq := w.sequence + 1
	encoded, recordHash := encodeRecordInto(w.recordBuf, w.segmentID, nextSeq, at.UTC().UnixNano(), w.prevHash, payload)
	if w.dir != "" && w.maxBytes > 0 && w.offset > 0 && w.offset+int64(len(encoded)) > w.maxBytes {
		if err := w.rotateLocked(); err != nil {
			return model.WALPosition{}, [32]byte{}, err
		}
		nextSeq = w.sequence + 1
		encoded, recordHash = encodeRecordInto(encoded[:0], w.segmentID, nextSeq, at.UTC().UnixNano(), w.prevHash, payload)
	}
	if cap(encoded) <= maxReusableRecordBytes {
		w.recordBuf = encoded[:0]
	} else {
		w.recordBuf = nil
	}
	pos := model.WALPosition{
		SegmentID: w.segmentID,
		Offset:    w.offset,
		Sequence:  nextSeq,
	}
	n, err := w.file.Write(encoded)
	if err != nil {
		return model.WALPosition{}, [32]byte{}, fmt.Errorf("wal: write: %w", err)
	}
	if n != len(encoded) {
		return model.WALPosition{}, [32]byte{}, io.ErrShortWrite
	}
	if err := w.syncAfterAppendLocked(); err != nil {
		return model.WALPosition{}, [32]byte{}, fmt.Errorf("wal: sync: %w", err)
	}
	w.sequence = pos.Sequence
	w.offset += int64(n)
	w.prevHash = recordHash
	return pos, recordHash, nil
}

// rotateLocked closes the active segment and opens the next one. The caller
// must hold w.mu. The hash chain and sequence counter continue across the
// boundary so the first record of segment N+1 references the last record of
// segment N via its prev_hash, keeping verification symmetric with the
// single-file layout.
func (w *Writer) rotateLocked() error {
	if w.dir == "" {
		return errors.New("wal: rotation requires directory mode")
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("wal: sync before rotate: %w", err)
	}
	w.lastSync = time.Now().UTC()
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("wal: close before rotate: %w", err)
	}
	from := w.segmentID
	nextSeg := w.segmentID + 1
	path := filepath.Join(w.dir, segmentName(nextSeg))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("wal: open rotated segment %d: %w", nextSeg, err)
	}
	w.file = f
	w.segmentID = nextSeg
	w.offset = 0
	if w.rotateHook != nil {
		w.rotateHook(from, nextSeg)
	}
	return nil
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	syncErr := w.file.Sync()
	err := w.file.Close()
	w.file = nil
	if syncErr != nil {
		return syncErr
	}
	return err
}

func (w *Writer) syncAfterAppendLocked() error {
	switch w.fsyncMode {
	case FsyncBatch:
		return nil
	case FsyncGroup:
		now := time.Now().UTC()
		if !w.lastSync.IsZero() && now.Sub(w.lastSync) < w.groupEvery {
			return nil
		}
		start := time.Now()
		if err := w.file.Sync(); err != nil {
			return err
		}
		w.observeFsync(time.Since(start))
		w.lastSync = now
		return nil
	default:
		start := time.Now()
		if err := w.file.Sync(); err != nil {
			return err
		}
		w.observeFsync(time.Since(start))
		w.lastSync = time.Now().UTC()
		return nil
	}
}

func (w *Writer) observeFsync(duration time.Duration) {
	if w.fsyncHook != nil {
		w.fsyncHook(w.fsyncMode, duration)
	}
}

func normalizeFsyncMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", FsyncStrict:
		return FsyncStrict
	case FsyncGroup:
		return FsyncGroup
	case FsyncBatch:
		return FsyncBatch
	default:
		return FsyncStrict
	}
}

func normalizeGroupInterval(d time.Duration) time.Duration {
	if d <= 0 {
		return 10 * time.Millisecond
	}
	return d
}

func ReadAll(path string) ([]Record, error) {
	state, err := scanFile(path, false, true)
	if err != nil {
		return nil, err
	}
	return state.recordsList, nil
}

// Scan streams every valid record in a legacy single-file WAL to visit.
// Unlike ReadAll it never builds a []Record, so startup recovery can keep
// memory proportional to the active recovery window rather than the WAL size.
func Scan(path string, visit func(Record) error) error {
	_, err := scanFileVisit(path, false, [32]byte{}, visit)
	return err
}

// ListSegments returns the segment ids found in dir, in ascending order.
// Non-segment files are ignored; a missing directory is treated as empty
// rather than an error to keep callers tolerant of first-boot states.
func ListSegments(dir string) ([]uint64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("wal: read dir: %w", err)
	}
	ids := make([]uint64, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		id, ok := parseSegmentName(entry.Name())
		if !ok {
			continue
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

// ReadAllDir reads every WAL record in dir, verifying the hash chain across
// segment boundaries. Equivalent to ReadAllDirFrom(dir, 0).
func ReadAllDir(dir string) ([]Record, error) {
	return ReadAllDirFrom(dir, 0)
}

// ReadAllDirFrom reads records from segments whose id >= minSegmentID. When
// minSegmentID is 0, every segment is included. The hash chain is verified
// within each returned segment but callers that skip earlier segments
// (e.g. because a checkpoint covers them) only verify the returned suffix;
// earlier segments remain on disk for offline inspection.
func ReadAllDirFrom(dir string, minSegmentID uint64) ([]Record, error) {
	segments, err := ListSegments(dir)
	if err != nil {
		return nil, err
	}
	var (
		out         []Record
		havePrev    bool
		expectPrev  [32]byte
		prevSegment uint64
	)
	// When minSegmentID elides a prefix we cannot verify the link to the
	// skipped tail, but the callers that skip (typically checkpoint-aware
	// replay) have already committed to trusting those earlier segments:
	// a committed batch wrote a WAL checkpoint past them, which in turn
	// requires a manifest that lists the record ids. For the first
	// included segment we therefore seed startPrev with its own stored
	// prev_hash (i.e. accept the link back to the skipped tail without
	// verifying it) and from that point on verify the chain normally.
	for _, seg := range segments {
		if seg < minSegmentID {
			continue
		}
		var startPrev [32]byte
		switch {
		case havePrev:
			startPrev = expectPrev
		case minSegmentID > 0 && seg > 1:
			// Only trust the on-disk prev when we actually skipped something;
			// a fresh-boot read of segment 1 still demands a zero prev.
			peek, err := peekFirstPrev(filepath.Join(dir, segmentName(seg)))
			if err != nil {
				return nil, fmt.Errorf("wal: peek segment %d: %w", seg, err)
			}
			startPrev = peek
		}
		state, err := scanFileFrom(filepath.Join(dir, segmentName(seg)), false, true, startPrev)
		if err != nil {
			return nil, fmt.Errorf("wal: scan segment %d: %w", seg, err)
		}
		if state.records == 0 {
			continue
		}
		if state.segmentID != seg {
			return nil, fmt.Errorf("wal: segment %d file reports segment_id %d", seg, state.segmentID)
		}
		if havePrev && state.firstPrev != expectPrev {
			return nil, fmt.Errorf("wal: hash chain break between segments %d and %d", prevSegment, seg)
		}
		out = append(out, state.recordsList...)
		expectPrev = state.lastHash
		havePrev = true
		prevSegment = seg
	}
	return out, nil
}

// ScanDirFrom streams records from directory-mode WAL segments whose id is
// >= minSegmentID. It verifies the same hash-chain invariants as
// ReadAllDirFrom, but invokes visit record-by-record instead of collecting a
// slice. A nil visit performs validation only.
func ScanDirFrom(dir string, minSegmentID uint64, visit func(Record) error) error {
	segments, err := ListSegments(dir)
	if err != nil {
		return err
	}
	var (
		havePrev    bool
		expectPrev  [32]byte
		prevSegment uint64
	)
	for _, seg := range segments {
		if seg < minSegmentID {
			continue
		}
		var startPrev [32]byte
		switch {
		case havePrev:
			startPrev = expectPrev
		case minSegmentID > 0 && seg > 1:
			peek, err := peekFirstPrev(filepath.Join(dir, segmentName(seg)))
			if err != nil {
				return fmt.Errorf("wal: peek segment %d: %w", seg, err)
			}
			startPrev = peek
		}
		state, err := scanFileVisit(filepath.Join(dir, segmentName(seg)), false, startPrev, visit)
		if err != nil {
			return fmt.Errorf("wal: scan segment %d: %w", seg, err)
		}
		if state.records == 0 {
			continue
		}
		if state.segmentID != seg {
			return fmt.Errorf("wal: segment %d file reports segment_id %d", seg, state.segmentID)
		}
		if havePrev && state.firstPrev != expectPrev {
			return fmt.Errorf("wal: hash chain break between segments %d and %d", prevSegment, seg)
		}
		expectPrev = state.lastHash
		havePrev = true
		prevSegment = seg
	}
	return nil
}

// PruneSegmentsBefore removes every segment file in dir whose id is strictly
// less than segmentID and returns how many files were removed plus their
// total size in bytes. It is safe to call with segmentID <= 1 (no-op) or
// against a directory that holds no segments. Callers are expected to only
// prune segments that a committed WAL checkpoint already covers: the
// function does not re-check the checkpoint itself, because prune is an
// idempotent best-effort GC and the data is also backed by committed
// manifests + bundles in the proof store.
func PruneSegmentsBefore(dir string, segmentID uint64) (int, int64, error) {
	if segmentID <= 1 {
		return 0, 0, nil
	}
	segments, err := ListSegments(dir)
	if err != nil {
		return 0, 0, err
	}
	var removed int
	var bytesRemoved int64
	for _, seg := range segments {
		if seg >= segmentID {
			break
		}
		path := filepath.Join(dir, segmentName(seg))
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return removed, bytesRemoved, fmt.Errorf("wal: stat segment %d: %w", seg, err)
		}
		if err := os.Remove(path); err != nil {
			return removed, bytesRemoved, fmt.Errorf("wal: remove segment %d: %w", seg, err)
		}
		removed++
		bytesRemoved += info.Size()
	}
	return removed, bytesRemoved, nil
}

// peekFirstPrev reads just enough of a segment file to recover the prev_hash
// field of its first record, without verifying anything else. Used by
// ReadAllDirFrom when the leading segments are intentionally skipped and we
// need a starting point for the visible tail's chain verification.
func peekFirstPrev(path string) ([32]byte, error) {
	var out [32]byte
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(f, header); err != nil {
		return out, fmt.Errorf("wal: read first header: %w", err)
	}
	if binary.BigEndian.Uint32(header[0:4]) != magic {
		return out, fmt.Errorf("wal: bad magic at segment start")
	}
	copy(out[:], header[32:64])
	return out, nil
}

func segmentName(id uint64) string {
	return fmt.Sprintf("%0*d%s", segmentIDWidth, id, segmentFileExt)
}

func parseSegmentName(name string) (uint64, bool) {
	if !strings.HasSuffix(name, segmentFileExt) {
		return 0, false
	}
	stem := strings.TrimSuffix(name, segmentFileExt)
	if stem == "" {
		return 0, false
	}
	id, err := strconv.ParseUint(stem, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

func Inspect(path string) (InspectResult, error) {
	state, err := scanFile(path, false, false)
	if err != nil {
		return InspectResult{}, err
	}
	return InspectResult{
		Path:          path,
		Records:       state.records,
		ValidBytes:    state.validBytes,
		FirstSequence: state.firstSequence,
		LastSequence:  state.lastSequence,
		SegmentID:     state.segmentID,
		LastHash:      state.lastHash[:],
	}, nil
}

// DirInspectResult aggregates Inspect stats across all segments of a
// directory-mode WAL plus a per-segment breakdown for operators that need
// to see exactly where a chain broke.
type DirInspectResult struct {
	Path            string          `json:"path"`
	Segments        []InspectResult `json:"segments"`
	TotalRecords    int             `json:"total_records"`
	TotalValidBytes int64           `json:"total_valid_bytes"`
	FirstSequence   uint64          `json:"first_sequence"`
	LastSequence    uint64          `json:"last_sequence"`
	ActiveSegmentID uint64          `json:"active_segment_id"`
	LastHash        []byte          `json:"last_hash"`
}

// InspectDir produces a DirInspectResult by scanning every segment in the
// directory with cross-segment hash chain verification. This is the CLI's
// view of `wal inspect` for directory layouts.
func InspectDir(dir string) (DirInspectResult, error) {
	ids, err := ListSegments(dir)
	if err != nil {
		return DirInspectResult{}, err
	}
	out := DirInspectResult{Path: dir}
	if len(ids) == 0 {
		return out, nil
	}
	var prev [32]byte
	for _, id := range ids {
		segPath := filepath.Join(dir, segmentName(id))
		state, err := scanFileFrom(segPath, false, false, prev)
		if err != nil {
			return out, err
		}
		res := InspectResult{
			Path:          segPath,
			Records:       state.records,
			ValidBytes:    state.validBytes,
			FirstSequence: state.firstSequence,
			LastSequence:  state.lastSequence,
			SegmentID:     id,
			LastHash:      append([]byte(nil), state.lastHash[:]...),
		}
		out.Segments = append(out.Segments, res)
		out.TotalRecords += state.records
		out.TotalValidBytes += state.validBytes
		if out.FirstSequence == 0 {
			out.FirstSequence = state.firstSequence
		}
		if state.lastSequence > out.LastSequence {
			out.LastSequence = state.lastSequence
		}
		if state.records > 0 {
			prev = state.lastHash
		}
		out.ActiveSegmentID = id
	}
	out.LastHash = append([]byte(nil), prev[:]...)
	return out, nil
}

func Repair(path string) (RepairResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return RepairResult{}, fmt.Errorf("wal: stat: %w", err)
	}
	return repairFile(path, info.Size(), [32]byte{})
}

// repairFile is the shared tail-tolerant repair routine used by both
// single-file Repair and the tail-segment branch of RepairDir. startPrev
// lets directory-mode pass in the hash chain state that was stitched across
// earlier segments so the tail segment is scanned from the correct seed
// rather than always assuming a zero prev_hash.
func repairFile(path string, originalBytes int64, startPrev [32]byte) (RepairResult, error) {
	state, scanErr := scanFileFrom(path, true, false, startPrev)
	truncated := originalBytes - state.validBytes
	if scanErr == nil && truncated == 0 {
		return RepairResult{
			Path:          path,
			Records:       state.records,
			ValidBytes:    state.validBytes,
			OriginalBytes: originalBytes,
		}, nil
	}
	if err := os.Truncate(path, state.validBytes); err != nil {
		return RepairResult{}, fmt.Errorf("wal: truncate: %w", err)
	}
	return RepairResult{
		Path:           path,
		Records:        state.records,
		ValidBytes:     state.validBytes,
		OriginalBytes:  originalBytes,
		TruncatedBytes: truncated,
		Repaired:       truncated > 0,
	}, nil
}

// trusterrNonTailBreak produces a FAILED_PRECONDITION error when a
// non-tail segment fails hash-chain or record validation. The disk is
// left untouched so the operator can inspect or restore manually.
func trusterrNonTailBreak(id uint64, path string, cause error) error {
	return trusterr.Wrap(
		trusterr.CodeFailedPrecondition,
		fmt.Sprintf("wal: non-tail segment %d (%s) is corrupt; refusing to repair because truncation would cascade into later segments", id, path),
		cause,
	)
}

// DirRepairResult reports the outcome of running RepairDir against a
// directory-mode WAL. Every segment's on-disk state is surfaced in
// Segments (same shape as single-file Inspect) so an operator can see at
// a glance which segments were healthy and how many records survived the
// truncation applied to the tail segment.
type DirRepairResult struct {
	Path            string          `json:"path"`
	Segments        []InspectResult `json:"segments"`
	TailRepair      RepairResult    `json:"tail_repair"`
	ActiveSegmentID uint64          `json:"active_segment_id"`
}

// RepairDir fixes a directory-mode WAL by truncating only the trailing
// segment at the first invalid record it finds, while refusing to touch
// any non-tail segment that already has a chain break. Multi-segment
// repair is deliberately conservative: a bad record in a segment that is
// not the active one means later segments reference a hash that no longer
// exists, so truncating earlier segments would cascade-invalidate
// everything past them. Operators who hit that case should restore from
// backup or investigate manually.
func RepairDir(dir string) (DirRepairResult, error) {
	ids, err := ListSegments(dir)
	if err != nil {
		return DirRepairResult{}, err
	}
	out := DirRepairResult{Path: dir}
	if len(ids) == 0 {
		return out, nil
	}

	var prev [32]byte
	// Verify every segment strictly except the last. Any error here is a
	// non-tail chain break and we bail out before touching disk.
	for _, id := range ids[:len(ids)-1] {
		segPath := filepath.Join(dir, segmentName(id))
		state, scanErr := scanFileFrom(segPath, false, false, prev)
		if scanErr != nil {
			return out, trusterrNonTailBreak(id, segPath, scanErr)
		}
		out.Segments = append(out.Segments, InspectResult{
			Path:          segPath,
			Records:       state.records,
			ValidBytes:    state.validBytes,
			FirstSequence: state.firstSequence,
			LastSequence:  state.lastSequence,
			SegmentID:     id,
			LastHash:      append([]byte(nil), state.lastHash[:]...),
		})
		if state.records > 0 {
			prev = state.lastHash
		}
	}

	tailID := ids[len(ids)-1]
	tailPath := filepath.Join(dir, segmentName(tailID))
	info, err := os.Stat(tailPath)
	if err != nil {
		return out, fmt.Errorf("wal: stat tail segment: %w", err)
	}
	tail, err := repairFile(tailPath, info.Size(), prev)
	if err != nil {
		return out, err
	}
	out.TailRepair = tail

	// Re-scan the tail after truncation so the Segments slice reflects the
	// post-repair state; the scan now always succeeds because the tail was
	// truncated exactly at the first invalid record boundary.
	tailState, scanErr := scanFileFrom(tailPath, false, false, prev)
	if scanErr != nil {
		return out, fmt.Errorf("wal: verify tail after repair: %w", scanErr)
	}
	out.Segments = append(out.Segments, InspectResult{
		Path:          tailPath,
		Records:       tailState.records,
		ValidBytes:    tailState.validBytes,
		FirstSequence: tailState.firstSequence,
		LastSequence:  tailState.lastSequence,
		SegmentID:     tailID,
		LastHash:      append([]byte(nil), tailState.lastHash[:]...),
	})
	out.ActiveSegmentID = tailID
	return out, nil
}

type scanState struct {
	records       int
	recordsList   []Record
	validBytes    int64
	firstSequence uint64
	lastSequence  uint64
	segmentID     uint64
	firstPrev     [32]byte // prev-hash expected by the first record in this segment; used to stitch chains
	lastHash      [32]byte
}

func scanFile(path string, tolerateTail, collect bool) (scanState, error) {
	return scanFileFrom(path, tolerateTail, collect, [32]byte{})
}

// scanFileFrom is like scanFile but lets the caller seed the expected
// prev_hash for the first record. Directory-mode reads use this to stitch
// the hash chain across segment boundaries without calling into the
// single-file entry point.
func scanFileFrom(path string, tolerateTail, collect bool, startPrev [32]byte) (scanState, error) {
	var records []Record
	state, err := scanFileVisit(path, tolerateTail, startPrev, func(rec Record) error {
		if collect {
			records = append(records, rec)
		}
		return nil
	})
	if collect {
		state.recordsList = records
	}
	return state, err
}

func scanFileVisit(path string, tolerateTail bool, startPrev [32]byte, visit func(Record) error) (scanState, error) {
	f, err := os.Open(path)
	if err != nil {
		return scanState{}, fmt.Errorf("wal: open reader: %w", err)
	}
	defer f.Close()

	var state scanState
	prev := startPrev
	var offset int64
	for {
		rec, n, err := readOne(f, offset, prev)
		if errors.Is(err, io.EOF) {
			return state, nil
		}
		if err != nil {
			if tolerateTail {
				return state, nil
			}
			return scanState{}, err
		}
		if state.records == 0 {
			state.firstSequence = rec.Position.Sequence
			state.segmentID = rec.Position.SegmentID
			state.firstPrev = rec.PrevHash
		}
		state.records++
		if visit != nil {
			if err := visit(rec); err != nil {
				return scanState{}, err
			}
		}
		state.validBytes = offset + n
		state.lastSequence = rec.Position.Sequence
		state.lastHash = rec.RecordHash
		prev = rec.RecordHash
		offset += n
	}
}

func encodeRecord(segmentID, sequence uint64, unixNano int64, prevHash [32]byte, payload []byte) ([]byte, [32]byte) {
	return encodeRecordInto(nil, segmentID, sequence, unixNano, prevHash, payload)
}

func encodeRecordInto(buf []byte, segmentID, sequence uint64, unixNano int64, prevHash [32]byte, payload []byte) ([]byte, [32]byte) {
	total := headerSize + len(payload) + crcSize + recordHashSize
	if cap(buf) < total {
		buf = make([]byte, total)
	} else {
		buf = buf[:total]
	}
	binary.BigEndian.PutUint32(buf[0:4], magic)
	binary.BigEndian.PutUint16(buf[4:6], version)
	binary.BigEndian.PutUint16(buf[6:8], typeAccepted)
	binary.BigEndian.PutUint64(buf[8:16], segmentID)
	binary.BigEndian.PutUint64(buf[16:24], sequence)
	binary.BigEndian.PutUint64(buf[24:32], uint64(unixNano))
	copy(buf[32:64], prevHash[:])
	binary.BigEndian.PutUint32(buf[64:68], uint32(len(payload)))
	copy(buf[68:68+len(payload)], payload)
	crcOffset := 68 + len(payload)
	crc := crc32.Checksum(buf[:crcOffset], crcTable)
	binary.BigEndian.PutUint32(buf[crcOffset:crcOffset+4], crc)
	sum := sha256.Sum256(buf[:crcOffset+4])
	copy(buf[crcOffset+4:], sum[:])
	return buf, sum
}

func readOne(r io.Reader, offset int64, expectedPrev [32]byte) (Record, int64, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(r, header); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return Record{}, 0, fmt.Errorf("wal: truncated header at offset %d", offset)
		}
		return Record{}, 0, err
	}
	if binary.BigEndian.Uint32(header[0:4]) != magic {
		return Record{}, 0, fmt.Errorf("wal: bad magic at offset %d", offset)
	}
	if binary.BigEndian.Uint16(header[4:6]) != version {
		return Record{}, 0, fmt.Errorf("wal: unsupported version at offset %d", offset)
	}
	if binary.BigEndian.Uint16(header[6:8]) != typeAccepted {
		return Record{}, 0, fmt.Errorf("wal: unsupported record type at offset %d", offset)
	}
	var prev [32]byte
	copy(prev[:], header[32:64])
	if prev != expectedPrev {
		return Record{}, 0, fmt.Errorf("wal: hash chain mismatch at offset %d", offset)
	}
	payloadLen := binary.BigEndian.Uint32(header[64:68])
	if payloadLen > maxPayloadBytes {
		return Record{}, 0, fmt.Errorf("wal: payload too large at offset %d: %d > %d", offset, payloadLen, maxPayloadBytes)
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Record{}, 0, fmt.Errorf("wal: truncated payload at offset %d: %w", offset, err)
	}
	trailer := make([]byte, crcSize+recordHashSize)
	if _, err := io.ReadFull(r, trailer); err != nil {
		return Record{}, 0, fmt.Errorf("wal: truncated trailer at offset %d: %w", offset, err)
	}
	wantCRC := binary.BigEndian.Uint32(trailer[:4])
	crc := crc32.New(crcTable)
	_, _ = crc.Write(header)
	_, _ = crc.Write(payload)
	gotCRC := crc.Sum32()
	if gotCRC != wantCRC {
		return Record{}, 0, fmt.Errorf("wal: crc mismatch at offset %d", offset)
	}
	h := sha256.New()
	_, _ = h.Write(header)
	_, _ = h.Write(payload)
	_, _ = h.Write(trailer[:4])
	var gotHash [32]byte
	copy(gotHash[:], h.Sum(nil))
	var storedHash [32]byte
	copy(storedHash[:], trailer[4:])
	if gotHash != storedHash {
		return Record{}, 0, fmt.Errorf("wal: record hash mismatch at offset %d", offset)
	}
	sequence := binary.BigEndian.Uint64(header[16:24])
	segmentID := binary.BigEndian.Uint64(header[8:16])
	unixNano := int64(binary.BigEndian.Uint64(header[24:32]))
	return Record{
		Position: model.WALPosition{
			SegmentID: segmentID,
			Offset:    offset,
			Sequence:  sequence,
		},
		UnixNano:   unixNano,
		Payload:    payload,
		PrevHash:   prev,
		RecordHash: storedHash,
	}, int64(headerSize + len(payload) + crcSize + recordHashSize), nil
}
