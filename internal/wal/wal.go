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

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
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

var (
	errRepairableFirstHeader = errors.New("wal: repairable first record header")
	errTornRecord            = errors.New("wal: torn record")
	errCorruptRecord         = errors.New("wal: corrupt record")
	errBadRecordMagic        = errors.New("wal: bad record magic")
	errUnsupportedRecord     = errors.New("wal: unsupported record encoding")
)

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
	// strict = fsync every record; group = coalesce fsyncs while bounding
	// the dirty interval; batch = rely on rotation and close boundaries.
	FsyncMode string
	// GroupCommitInterval is used when FsyncMode is group. A zero value
	// defaults to 10ms to keep latency bounded while avoiding per-record sync.
	GroupCommitInterval time.Duration
	OnAppend            func(string, time.Duration)
	// OnFsync reports successful WAL durability operations. A rotation's new
	// file and directory publication is reported as one combined operation.
	// In group mode it may run from the background timer, so callbacks must
	// be safe for concurrent use.
	// Fsync callbacks must signal an owner goroutine rather than call Close
	// directly because Close waits for background callbacks to finish.
	OnFsync func(string, time.Duration)
	// OnFsyncError reports fsync failures, including failures from the
	// asynchronous group-commit timer that cannot be returned by Append. It
	// may run from that timer and must be safe for concurrent use.
	OnFsyncError func(string, error)
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
	mu              sync.Mutex
	file            *os.File
	dir             string // empty in legacy single-file mode
	maxBytes        int64
	segmentID       uint64
	sequence        uint64
	offset          int64
	prevHash        [32]byte
	rotateHook      func(from, to uint64) // test hook; nil in production
	fsyncMode       string
	groupEvery      time.Duration
	lastSync        time.Time
	dirty           bool
	groupTimer      timerStopper
	groupTimerGen   uint64
	backgroundHooks sync.WaitGroup
	stickyErr       error
	closed          bool
	closeErr        error
	closeDone       chan struct{}
	afterFunc       func(time.Duration, func()) timerStopper
	openFile        func(string, int, os.FileMode) (*os.File, error)
	syncFile        func(*os.File) error
	syncDir         func(string) error
	closeFile       func(*os.File) error
	appendHook      func(string, time.Duration)
	fsyncHook       func(string, time.Duration)
	fsyncErrorHook  func(string, error)
	recordBuf       []byte
}

type timerStopper interface {
	Stop() bool
}

type fsyncObservation struct {
	attempted bool
	duration  time.Duration
	err       error
}

func defaultAfterFunc(delay time.Duration, callback func()) timerStopper {
	return time.AfterFunc(delay, callback)
}

func defaultSyncFile(file *os.File) error {
	return file.Sync()
}

func defaultCloseFile(file *os.File) error {
	return file.Close()
}

type walFileOps struct {
	stat         func(string) (os.FileInfo, error)
	mkdir        func(string, os.FileMode) error
	openFile     func(string, int, os.FileMode) (*os.File, error)
	remove       func(string) error
	truncateFile func(*os.File, int64) error
	syncFile     func(*os.File) error
	syncDir      func(string) error
	closeFile    func(*os.File) error
}

func defaultWALFileOps() walFileOps {
	return walFileOps{
		stat:     os.Stat,
		mkdir:    os.Mkdir,
		openFile: os.OpenFile,
		remove:   os.Remove,
		truncateFile: func(file *os.File, size int64) error {
			return file.Truncate(size)
		},
		syncFile:  defaultSyncFile,
		syncDir:   syncDirectory,
		closeFile: defaultCloseFile,
	}
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

// ensureDurableDirectory creates missing path components from the first
// existing ancestor downward. Each child is published in its parent before
// the next level is created, so a successful return never relies on
// os.MkdirAll's in-memory namespace state alone.
func ensureDurableDirectory(path string, perm os.FileMode, ops walFileOps) error {
	clean := filepath.Clean(path)
	missing := make([]string, 0, 4)
	var boundary string
	for current := clean; ; current = filepath.Dir(current) {
		info, err := ops.stat(current)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("wal: path component %q is not a directory", current)
			}
			boundary = current
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("wal: stat directory %q: %w", current, err)
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("wal: no existing parent for directory %q", clean)
		}
	}
	// Re-publish the first visible boundary before relying on it. This heals
	// a retry after a prior mkdir succeeded but both its publication barrier
	// and cleanup failed, leaving a directory that is visible in memory but
	// not yet guaranteed durable in its parent.
	boundaryParent := filepath.Dir(boundary)
	if boundaryParent != boundary {
		if err := ops.syncDir(boundaryParent); err != nil {
			return fmt.Errorf("wal: sync parent directory %q for existing boundary %q: %w", boundaryParent, boundary, err)
		}
	}

	for i := len(missing) - 1; i >= 0; i-- {
		component := missing[i]
		created := false
		err := ops.mkdir(component, perm)
		switch {
		case err == nil:
			created = true
		case errors.Is(err, os.ErrExist):
			info, statErr := ops.stat(component)
			if statErr != nil {
				return fmt.Errorf("wal: stat concurrently created directory %q: %w", component, statErr)
			}
			if !info.IsDir() {
				return fmt.Errorf("wal: concurrently created path %q is not a directory", component)
			}
		default:
			return fmt.Errorf("wal: create directory %q: %w", component, err)
		}

		parent := filepath.Dir(component)
		if err := ops.syncDir(parent); err != nil {
			primary := fmt.Errorf("wal: sync parent directory %q after creating %q: %w", parent, component, err)
			if !created {
				if retryErr := ops.syncDir(parent); retryErr != nil {
					return errors.Join(primary, fmt.Errorf("wal: retry sync parent directory %q after concurrent creation: %w", parent, retryErr))
				}
				return primary
			}
			var cleanupErrs []error
			if err := ops.remove(component); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("wal: remove unpublished directory %q: %w", component, err))
			}
			if err := ops.syncDir(parent); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("wal: sync parent directory %q after cleanup: %w", parent, err))
			}
			return errors.Join(append([]error{primary}, cleanupErrs...)...)
		}
	}
	return nil
}

func syncWALFileAndDirectory(file *os.File, path string, ops walFileOps) error {
	if err := ops.syncFile(file); err != nil {
		return fmt.Errorf("wal: sync file %q before publishing: %w", path, err)
	}
	parent := filepath.Dir(path)
	if err := ops.syncDir(parent); err != nil {
		return fmt.Errorf("wal: sync containing directory %q for %q: %w", parent, path, err)
	}
	return nil
}

func closeAfterOpenError(file *os.File, operation string, cause error, ops walFileOps) error {
	if err := ops.closeFile(file); err != nil {
		return errors.Join(cause, fmt.Errorf("wal: close file after %s: %w", operation, err))
	}
	return cause
}

type segmentChainState struct {
	trustBoundary bool
	haveSegment   bool
	lastSegment   uint64
	havePrev      bool
	expectPrev    [32]byte
	prevSegment   uint64
	lastSequence  uint64
}

func (chain *segmentChainState) startPrev(path string) ([32]byte, error) {
	if chain.havePrev || !chain.trustBoundary {
		return chain.expectPrev, nil
	}
	header, present, err := peekFirstHeaderIfPresent(path)
	if err != nil {
		return [32]byte{}, err
	}
	if !present {
		return [32]byte{}, nil
	}
	return header.prevHash, nil
}

// repairStartPrev keeps normal reads strict while allowing the active tail
// repair path to truncate a torn first header at a trusted retained-suffix
// boundary. A complete valid header still supplies its stored boundary hash.
func (chain *segmentChainState) repairStartPrev(path string) ([32]byte, error) {
	prev, err := chain.startPrev(path)
	if err != nil && chain.trustBoundary && !chain.havePrev && errors.Is(err, errRepairableFirstHeader) {
		return [32]byte{}, nil
	}
	return prev, err
}

func (chain *segmentChainState) validateNextSegment(segmentID uint64) error {
	if chain.haveSegment && segmentID != chain.lastSegment+1 {
		return fmt.Errorf("wal: segment id gap between %d and %d", chain.lastSegment, segmentID)
	}
	return nil
}

func (chain *segmentChainState) validateFirstRecord(segmentID uint64, record Record) error {
	return chain.validateFirstPosition(segmentID, record.Position.SegmentID, record.Position.Sequence, record.PrevHash)
}

func (chain *segmentChainState) validateFirstPosition(segmentID, recordSegmentID, sequence uint64, prevHash [32]byte) error {
	if recordSegmentID != segmentID {
		return fmt.Errorf("wal: segment %d file reports segment_id %d", segmentID, recordSegmentID)
	}
	if sequence == 0 {
		return fmt.Errorf("wal: segment %d starts with zero sequence", segmentID)
	}
	if chain.havePrev {
		if chain.lastSequence == ^uint64(0) || sequence != chain.lastSequence+1 {
			return fmt.Errorf("wal: sequence discontinuity between segments %d and %d: got %d after %d", chain.prevSegment, segmentID, sequence, chain.lastSequence)
		}
	} else if (!chain.trustBoundary || prevHash == [32]byte{}) && sequence != 1 {
		return fmt.Errorf("wal: first segment %d starts at sequence %d, want 1", segmentID, sequence)
	}
	return nil
}

func (chain *segmentChainState) accept(segmentID uint64, state scanState) error {
	if err := chain.validateNextSegment(segmentID); err != nil {
		return err
	}
	chain.haveSegment = true
	chain.lastSegment = segmentID
	if state.records == 0 {
		return nil
	}
	if err := chain.validateFirstPosition(segmentID, state.segmentID, state.firstSequence, state.firstPrev); err != nil {
		return err
	}
	if chain.havePrev && state.firstPrev != chain.expectPrev {
		return fmt.Errorf("wal: hash chain break between segments %d and %d", chain.prevSegment, segmentID)
	}
	chain.havePrev = true
	chain.expectPrev = state.lastHash
	chain.prevSegment = segmentID
	chain.lastSequence = state.lastSequence
	return nil
}

// OpenDirWriter opens a WAL in directory mode. The directory may be empty
// (a fresh WAL) or already contain segment files; in the latter case the
// writer reopens the highest-numbered segment and continues appending to it,
// preserving sequence counters and the cross-segment hash chain. Setting
// opts.MaxSegmentBytes > 0 enables automatic segment rotation on Append.
func OpenDirWriter(dir string, opts Options) (*Writer, error) {
	return openDirWriterWithOps(dir, opts, defaultWALFileOps())
}

func openDirWriterWithOps(dir string, opts Options, ops walFileOps) (*Writer, error) {
	if dir == "" {
		return nil, errors.New("wal: directory path is required")
	}
	if err := ensureDurableDirectory(dir, 0o755, ops); err != nil {
		return nil, fmt.Errorf("wal: create dir: %w", err)
	}
	segments, err := ListSegments(dir)
	if err != nil {
		return nil, err
	}
	var (
		activeSeg uint64
		sequence  uint64
		prev      [32]byte
		create    bool
	)
	if len(segments) == 0 {
		create = true
		activeSeg = opts.InitialSegmentID
		if activeSeg == 0 {
			activeSeg = 1
		}
	} else {
		// Replay every segment so the writer starts with the exact
		// sequence/prev-hash state the next Append would need. The prev
		// hash threads across segments, which is also where any chain
		// break is diagnosed.
		var last scanState
		chain := segmentChainState{trustBoundary: segments[0] > 1}
		for _, seg := range segments {
			segmentPath := filepath.Join(dir, segmentName(seg))
			if err := chain.validateNextSegment(seg); err != nil {
				return nil, err
			}
			startPrev, err := chain.startPrev(segmentPath)
			if err != nil {
				return nil, fmt.Errorf("wal: seed segment %d: %w", seg, err)
			}
			state, err := scanFileFrom(segmentPath, false, false, startPrev)
			if err != nil {
				return nil, fmt.Errorf("wal: scan segment %d: %w", seg, err)
			}
			if err := chain.accept(seg, state); err != nil {
				return nil, err
			}
			if state.records > 0 {
				last = state
			}
		}
		activeSeg = segments[len(segments)-1]
		sequence = last.lastSequence
		prev = last.lastHash
	}
	path := filepath.Join(dir, segmentName(activeSeg))
	flags := os.O_RDWR | os.O_APPEND
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := ops.openFile(path, flags, 0o600)
	if err != nil {
		return nil, fmt.Errorf("wal: open segment %d: %w", activeSeg, err)
	}
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		cause := fmt.Errorf("wal: seek end of segment %d: %w", activeSeg, err)
		return nil, closeAfterOpenError(f, "seek", cause, ops)
	}
	if err := syncWALFileAndDirectory(f, path, ops); err != nil {
		cause := fmt.Errorf("wal: publish segment %d: %w", activeSeg, err)
		return nil, closeAfterOpenError(f, "publication", cause, ops)
	}
	return &Writer{
		file:           f,
		dir:            dir,
		maxBytes:       opts.MaxSegmentBytes,
		segmentID:      activeSeg,
		sequence:       sequence,
		offset:         offset,
		prevHash:       prev,
		rotateHook:     opts.OnRotate,
		fsyncMode:      normalizeFsyncMode(opts.FsyncMode),
		groupEvery:     normalizeGroupInterval(opts.GroupCommitInterval),
		afterFunc:      defaultAfterFunc,
		openFile:       ops.openFile,
		syncFile:       ops.syncFile,
		syncDir:        ops.syncDir,
		closeFile:      ops.closeFile,
		appendHook:     opts.OnAppend,
		fsyncHook:      opts.OnFsync,
		fsyncErrorHook: opts.OnFsyncError,
		closeDone:      make(chan struct{}),
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
	return openWriterWithOptionsAndOps(path, segmentID, opts, defaultWALFileOps())
}

func openWriterWithOptionsAndOps(path string, segmentID uint64, opts Options, ops walFileOps) (*Writer, error) {
	if segmentID == 0 {
		return nil, errors.New("wal: segment id must be greater than zero")
	}
	if err := ensureDurableDirectory(filepath.Dir(path), 0o755, ops); err != nil {
		return nil, fmt.Errorf("wal: create dir: %w", err)
	}
	state, err := scanFile(path, false, false)
	create := errors.Is(err, os.ErrNotExist)
	if err != nil && !create {
		return nil, fmt.Errorf("wal: scan existing log: %w", err)
	}
	if err := validateSingleFileStart(state); err != nil {
		return nil, err
	}
	if state.records > 0 && state.segmentID != segmentID {
		return nil, fmt.Errorf("wal: segment id mismatch: existing %d requested %d", state.segmentID, segmentID)
	}
	flags := os.O_RDWR | os.O_APPEND
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := ops.openFile(path, flags, 0o600)
	if err != nil {
		return nil, fmt.Errorf("wal: open writer: %w", err)
	}
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		cause := fmt.Errorf("wal: seek end: %w", err)
		return nil, closeAfterOpenError(f, "seek", cause, ops)
	}
	if err := syncWALFileAndDirectory(f, path, ops); err != nil {
		cause := fmt.Errorf("wal: publish writer file: %w", err)
		return nil, closeAfterOpenError(f, "publication", cause, ops)
	}
	return &Writer{
		file:           f,
		segmentID:      segmentID,
		sequence:       state.lastSequence,
		offset:         offset,
		prevHash:       state.lastHash,
		fsyncMode:      normalizeFsyncMode(opts.FsyncMode),
		groupEvery:     normalizeGroupInterval(opts.GroupCommitInterval),
		afterFunc:      defaultAfterFunc,
		openFile:       ops.openFile,
		syncFile:       ops.syncFile,
		syncDir:        ops.syncDir,
		closeFile:      ops.closeFile,
		appendHook:     opts.OnAppend,
		fsyncHook:      opts.OnFsync,
		fsyncErrorHook: opts.OnFsyncError,
		closeDone:      make(chan struct{}),
	}, nil
}

func (w *Writer) Append(ctx context.Context, payload []byte) (model.WALPosition, [32]byte, error) {
	return w.AppendAt(ctx, payload, time.Now().UTC())
}

func (w *Writer) AppendAt(ctx context.Context, payload []byte, at time.Time) (model.WALPosition, [32]byte, error) {
	if err := validatePayloadLength(len(payload)); err != nil {
		return model.WALPosition{}, [32]byte{}, err
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

	var (
		fsyncs     [3]fsyncObservation
		fsyncCount int
	)
	w.mu.Lock()
	defer func() {
		w.mu.Unlock()
		w.observeFsyncs(fsyncs[:fsyncCount])
	}()
	if w.closed {
		return model.WALPosition{}, [32]byte{}, errors.New("wal: writer is closed")
	}
	if w.stickyErr != nil {
		return model.WALPosition{}, [32]byte{}, w.stickyErr
	}
	if w.file == nil {
		return model.WALPosition{}, [32]byte{}, errors.New("wal: writer is closed")
	}
	if w.sequence == ^uint64(0) {
		return model.WALPosition{}, [32]byte{}, errors.New("wal: sequence exhausted")
	}

	// Auto-rotate before writing, never in the middle, so a single record
	// is always entirely contained in one segment. A segment that does not
	// yet hold any record is never rotated away even if the configured
	// maxBytes is smaller than the record we're about to write; that way
	// an oversized record still makes forward progress instead of looping
	// forever between rotations.
	nextSeq := w.sequence + 1
	encoded, recordHash := encodeRecordInto(w.recordBuf, w.segmentID, nextSeq, at.UTC().UnixNano(), w.prevHash, payload)
	if w.dir != "" && w.maxBytes > 0 && w.offset > 0 && w.offset > w.maxBytes-int64(len(encoded)) {
		beforeRotate, publish, err := w.rotateLocked()
		for _, fsync := range [...]fsyncObservation{beforeRotate, publish} {
			if fsync.attempted {
				fsyncs[fsyncCount] = fsync
				fsyncCount++
			}
		}
		if err != nil {
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
		if n > 0 {
			w.dirty = true
		}
		return model.WALPosition{}, [32]byte{}, w.poisonLocked(fmt.Errorf("wal: write: %w", err))
	}
	if n != len(encoded) {
		if n > 0 {
			w.dirty = true
		}
		return model.WALPosition{}, [32]byte{}, w.poisonLocked(fmt.Errorf("wal: write: %w", io.ErrShortWrite))
	}
	w.dirty = true
	fsync := w.syncAfterAppendLocked()
	if fsync.attempted {
		fsyncs[fsyncCount] = fsync
		fsyncCount++
	}
	if fsync.err != nil {
		return model.WALPosition{}, [32]byte{}, fsync.err
	}
	w.sequence = pos.Sequence
	w.offset += int64(n)
	w.prevHash = recordHash
	return pos, recordHash, nil
}

func validatePayloadLength(length int) error {
	if length == 0 {
		return errors.New("wal: empty payload")
	}
	if length > maxPayloadBytes {
		return fmt.Errorf("wal: payload too large: %d > %d", length, maxPayloadBytes)
	}
	return nil
}

// rotateLocked closes the active segment and opens the next one. The caller
// must hold w.mu. The hash chain and sequence counter continue across the
// boundary so the first record of segment N+1 references the last record of
// segment N via its prev_hash, keeping verification symmetric with the
// single-file layout.
func (w *Writer) rotateLocked() (fsyncObservation, fsyncObservation, error) {
	if w.dir == "" {
		return fsyncObservation{}, fsyncObservation{}, errors.New("wal: rotation requires directory mode")
	}
	if w.segmentID == ^uint64(0) {
		return fsyncObservation{}, fsyncObservation{}, errors.New("wal: segment id exhausted")
	}
	w.cancelGroupTimerLocked()
	beforeRotate := w.syncCurrentLocked("sync before rotate")
	if beforeRotate.err != nil {
		return beforeRotate, fsyncObservation{}, beforeRotate.err
	}
	err := w.closeFile(w.file)
	w.file = nil
	if err != nil {
		return beforeRotate, fsyncObservation{}, w.poisonLocked(fmt.Errorf("wal: close before rotate: %w", err))
	}
	from := w.segmentID
	nextSeg := w.segmentID + 1
	path := filepath.Join(w.dir, segmentName(nextSeg))
	f, err := w.openFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND|os.O_EXCL, 0o600)
	if err != nil {
		return beforeRotate, fsyncObservation{}, w.poisonLocked(fmt.Errorf("wal: open rotated segment %d: %w", nextSeg, err))
	}
	start := time.Now()
	publish := fsyncObservation{attempted: true}
	if err := syncWALFileAndDirectory(f, path, walFileOps{syncFile: w.syncFile, syncDir: w.syncDir}); err != nil {
		primary := fmt.Errorf("wal: publish rotated segment %d: %w", nextSeg, err)
		if closeErr := w.closeFile(f); closeErr != nil {
			primary = errors.Join(primary, fmt.Errorf("wal: close unpublished segment %d: %w", nextSeg, closeErr))
		}
		publish.duration = time.Since(start)
		publish.err = w.poisonLocked(primary)
		return beforeRotate, publish, publish.err
	}
	publish.duration = time.Since(start)
	w.file = f
	w.segmentID = nextSeg
	w.offset = 0
	if w.rotateHook != nil {
		w.rotateHook(from, nextSeg)
	}
	return beforeRotate, publish, nil
}

func (w *Writer) Close() error {
	w.mu.Lock()
	if w.closeDone == nil {
		w.closeDone = make(chan struct{})
	}
	if w.closed {
		done := w.closeDone
		w.mu.Unlock()
		<-done
		w.mu.Lock()
		err := w.closeErr
		w.mu.Unlock()
		return err
	}
	w.closed = true
	w.cancelGroupTimerLocked()

	var (
		closeErrors []error
		fsync       fsyncObservation
	)
	if w.stickyErr != nil {
		closeErrors = append(closeErrors, w.stickyErr)
	}
	if w.file != nil {
		start := time.Now()
		err := w.syncFile(w.file)
		fsync = fsyncObservation{
			attempted: true,
			duration:  time.Since(start),
		}
		if err != nil {
			fsync.err = fmt.Errorf("wal: final sync: %w", err)
			closeErrors = append(closeErrors, fsync.err)
		} else {
			w.dirty = false
			w.lastSync = time.Now()
		}
		if err := w.closeFile(w.file); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("wal: close: %w", err))
		}
		w.file = nil
	}
	w.closeErr = errors.Join(closeErrors...)
	closeErr := w.closeErr
	done := w.closeDone
	w.mu.Unlock()
	w.observeFsyncs([]fsyncObservation{fsync})
	w.backgroundHooks.Wait()
	close(done)
	return closeErr
}

func (w *Writer) syncAfterAppendLocked() fsyncObservation {
	switch w.fsyncMode {
	case FsyncBatch:
		return fsyncObservation{}
	case FsyncGroup:
		now := time.Now()
		if !w.lastSync.IsZero() {
			deadline := w.lastSync.Add(w.groupEvery)
			if now.Before(deadline) {
				w.armGroupTimerLocked(deadline.Sub(now))
				return fsyncObservation{}
			}
		}
		w.cancelGroupTimerLocked()
		return w.syncCurrentLocked("sync")
	default:
		w.cancelGroupTimerLocked()
		return w.syncCurrentLocked("sync")
	}
}

func (w *Writer) syncCurrentLocked(operation string) fsyncObservation {
	start := time.Now()
	err := w.syncFile(w.file)
	observation := fsyncObservation{
		attempted: true,
		duration:  time.Since(start),
	}
	if err != nil {
		observation.err = w.poisonLocked(fmt.Errorf("wal: %s: %w", operation, err))
		return observation
	}
	w.dirty = false
	w.lastSync = time.Now()
	return observation
}

func (w *Writer) armGroupTimerLocked(delay time.Duration) {
	if w.groupTimer != nil || !w.dirty || w.stickyErr != nil || w.closed {
		return
	}
	w.groupTimerGen++
	generation := w.groupTimerGen
	segmentID := w.segmentID
	w.groupTimer = w.afterFunc(delay, func() {
		w.flushGroupTimer(generation, segmentID)
	})
}

func (w *Writer) cancelGroupTimerLocked() {
	if w.groupTimer != nil {
		w.groupTimer.Stop()
		w.groupTimer = nil
	}
	w.groupTimerGen++
}

func (w *Writer) flushGroupTimer(generation, segmentID uint64) {
	w.mu.Lock()
	if w.closed || w.file == nil || w.fsyncMode != FsyncGroup ||
		w.groupTimer == nil || w.groupTimerGen != generation || w.segmentID != segmentID {
		w.mu.Unlock()
		return
	}
	w.groupTimer = nil
	w.groupTimerGen++
	if !w.dirty || w.stickyErr != nil {
		w.mu.Unlock()
		return
	}
	fsync := w.syncCurrentLocked("background group sync")
	w.backgroundHooks.Add(1)
	w.mu.Unlock()
	defer w.backgroundHooks.Done()
	w.observeFsyncs([]fsyncObservation{fsync})
}

func (w *Writer) poisonLocked(err error) error {
	if w.stickyErr == nil {
		w.stickyErr = err
	}
	return w.stickyErr
}

func (w *Writer) observeFsyncs(observations []fsyncObservation) {
	for _, observation := range observations {
		if !observation.attempted {
			continue
		}
		if observation.err != nil {
			if w.fsyncErrorHook != nil {
				w.fsyncErrorHook(w.fsyncMode, observation.err)
			}
			continue
		}
		if w.fsyncHook != nil {
			w.fsyncHook(w.fsyncMode, observation.duration)
		}
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
	if err := validateSingleFileStart(state); err != nil {
		return nil, err
	}
	return state.recordsList, nil
}

// Scan streams every valid record in a legacy single-file WAL to visit.
// Unlike ReadAll it never builds a []Record, so startup recovery can keep
// memory proportional to the active recovery window rather than the WAL size.
func Scan(path string, visit func(Record) error) error {
	first := true
	_, err := scanFileVisit(path, false, [32]byte{}, func(record Record) error {
		if first {
			first = false
			if record.Position.Sequence != 1 {
				return fmt.Errorf("wal: first record starts at sequence %d, want 1", record.Position.Sequence)
			}
		}
		if visit != nil {
			return visit(record)
		}
		return nil
	})
	return err
}

func validateSingleFileStart(state scanState) error {
	if state.records > 0 && state.firstSequence != 1 {
		return fmt.Errorf("wal: first record starts at sequence %d, want 1", state.firstSequence)
	}
	return nil
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
		id, ok := parseSegmentName(entry.Name())
		if !ok {
			if strings.HasSuffix(entry.Name(), segmentFileExt) {
				stem := strings.TrimSuffix(entry.Name(), segmentFileExt)
				if isDecimalSegmentStem(stem) {
					parsed, parseErr := strconv.ParseUint(stem, 10, 64)
					if parseErr != nil {
						return nil, fmt.Errorf("wal: segment entry %q has invalid numeric id: %w", entry.Name(), parseErr)
					}
					if parsed == 0 {
						return nil, fmt.Errorf("wal: segment entry %q uses reserved id 0", entry.Name())
					}
				}
			}
			continue
		}
		if entry.Name() != segmentName(id) {
			return nil, fmt.Errorf("wal: segment %d entry %q is not canonically named %q", id, entry.Name(), segmentName(id))
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("wal: inspect segment entry %q: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("wal: segment %d entry %q is not a regular file", id, entry.Name())
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

// ReadAllDir reads every currently retained WAL record in dir, verifying the
// hash chain across segment boundaries. Equivalent to ReadAllDirFrom(dir, 0).
func ReadAllDir(dir string) ([]Record, error) {
	return ReadAllDirFrom(dir, 0)
}

// ReadAllDirFrom reads records from segments whose id >= minSegmentID. When
// minSegmentID is 0, every retained segment is included. When the first
// on-disk id is greater than 1, or minSegmentID skips files, the first
// non-empty record's link to the absent prefix is trusted once. Every later
// segment id and hash link remains strict.
func ReadAllDirFrom(dir string, minSegmentID uint64) ([]Record, error) {
	segments, err := ListSegments(dir)
	if err != nil {
		return nil, err
	}
	var out []Record
	chain := segmentChainState{trustBoundary: len(segments) > 0 && segments[0] > 1}
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
			chain.trustBoundary = true
			continue
		}
		segmentPath := filepath.Join(dir, segmentName(seg))
		if err := chain.validateNextSegment(seg); err != nil {
			return nil, err
		}
		startPrev, err := chain.startPrev(segmentPath)
		if err != nil {
			return nil, fmt.Errorf("wal: seed segment %d: %w", seg, err)
		}
		state, err := scanFileFrom(segmentPath, false, true, startPrev)
		if err != nil {
			return nil, fmt.Errorf("wal: scan segment %d: %w", seg, err)
		}
		if err := chain.accept(seg, state); err != nil {
			return nil, err
		}
		if state.records == 0 {
			continue
		}
		out = append(out, state.recordsList...)
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
	chain := segmentChainState{trustBoundary: len(segments) > 0 && segments[0] > 1}
	for _, seg := range segments {
		if seg < minSegmentID {
			chain.trustBoundary = true
			continue
		}
		segmentPath := filepath.Join(dir, segmentName(seg))
		if err := chain.validateNextSegment(seg); err != nil {
			return err
		}
		startPrev, err := chain.startPrev(segmentPath)
		if err != nil {
			return fmt.Errorf("wal: seed segment %d: %w", seg, err)
		}
		segmentVisit := visit
		if visit != nil {
			first := true
			segmentVisit = func(record Record) error {
				if first {
					first = false
					if err := chain.validateFirstRecord(seg, record); err != nil {
						return err
					}
				}
				return visit(record)
			}
		}
		state, err := scanFileVisit(segmentPath, false, startPrev, segmentVisit)
		if err != nil {
			return fmt.Errorf("wal: scan segment %d: %w", seg, err)
		}
		if err := chain.accept(seg, state); err != nil {
			return err
		}
	}
	return nil
}

// PruneSegmentsBefore removes every segment file in dir whose id is strictly
// less than segmentID and returns how many files were removed plus their
// total size in bytes. It is safe to call with segmentID <= 1 (no-op) or
// against a directory that holds no segments. Callers are expected to only
// prune segments that a committed WAL checkpoint already covers: the
// function does not re-check the checkpoint itself. Pruning is idempotent,
// but it returns success only after each oldest-first removal has crossed a
// directory metadata barrier.
func PruneSegmentsBefore(dir string, segmentID uint64) (int, int64, error) {
	return pruneSegmentsBeforeWithOps(dir, segmentID, defaultWALFileOps())
}

func pruneSegmentsBeforeWithOps(dir string, segmentID uint64, ops walFileOps) (int, int64, error) {
	if segmentID <= 1 {
		return 0, 0, nil
	}
	segments, err := ListSegments(dir)
	if err != nil {
		return 0, 0, err
	}
	if len(segments) == 0 {
		info, statErr := ops.stat(dir)
		if errors.Is(statErr, os.ErrNotExist) {
			return 0, 0, nil
		}
		if statErr != nil {
			return 0, 0, fmt.Errorf("wal: stat directory before pruning: %w", statErr)
		}
		if !info.IsDir() {
			return 0, 0, fmt.Errorf("wal: prune path %q is not a directory", dir)
		}
	}
	// Heal a prior failed attempt before issuing another unlink. Without
	// this barrier, a retry could observe an already-removed entry in the
	// page cache and then return without ever making that deletion durable.
	if err := ops.syncDir(dir); err != nil {
		return 0, 0, fmt.Errorf("wal: sync directory before pruning: %w", err)
	}
	if len(segments) == 0 {
		return 0, 0, nil
	}
	var removed int
	var bytesRemoved int64
	for _, seg := range segments {
		if seg >= segmentID {
			break
		}
		path := filepath.Join(dir, segmentName(seg))
		info, err := ops.stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return removed, bytesRemoved, fmt.Errorf("wal: stat segment %d: %w", seg, err)
		}
		if err := ops.remove(path); err != nil {
			return removed, bytesRemoved, fmt.Errorf("wal: remove segment %d: %w", seg, err)
		}
		removed++
		bytesRemoved += info.Size()
		// Persist each oldest-first deletion independently. A single final
		// sync would allow a crash to retain an arbitrary subset and create
		// an internal chain gap.
		if err := ops.syncDir(dir); err != nil {
			return removed, bytesRemoved, fmt.Errorf("wal: sync directory after removing segment %d: %w", seg, err)
		}
	}
	return removed, bytesRemoved, nil
}

type firstRecordHeader struct {
	segmentID uint64
	sequence  uint64
	prevHash  [32]byte
}

// peekFirstHeaderIfPresent reads the fixed header of a segment's first
// record. An empty segment reports present=false so a retained suffix can
// skip leading crash-created empty segments before trusting one boundary.
func peekFirstHeaderIfPresent(path string) (firstRecordHeader, bool, error) {
	var out firstRecordHeader
	f, err := os.Open(path)
	if err != nil {
		return out, false, err
	}
	defer func() { _ = f.Close() }()
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(f, header); err != nil {
		if errors.Is(err, io.EOF) {
			return out, false, nil
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return out, false, fmt.Errorf("%w: truncated header: %v", errRepairableFirstHeader, err)
		}
		return out, false, fmt.Errorf("wal: read first header: %w", err)
	}
	if binary.BigEndian.Uint32(header[0:4]) != magic {
		return out, false, fmt.Errorf("%w at segment start", errBadRecordMagic)
	}
	out.segmentID = binary.BigEndian.Uint64(header[8:16])
	out.sequence = binary.BigEndian.Uint64(header[16:24])
	copy(out.prevHash[:], header[32:64])
	return out, true, nil
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
	if err != nil || id == 0 {
		return 0, false
	}
	return id, true
}

func isDecimalSegmentStem(stem string) bool {
	if stem == "" {
		return false
	}
	for i := 0; i < len(stem); i++ {
		if stem[i] < '0' || stem[i] > '9' {
			return false
		}
	}
	return true
}

func Inspect(path string) (InspectResult, error) {
	state, err := scanFile(path, false, false)
	if err != nil {
		return InspectResult{}, err
	}
	if err := validateSingleFileStart(state); err != nil {
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
	chain := segmentChainState{trustBoundary: ids[0] > 1}
	for _, id := range ids {
		segPath := filepath.Join(dir, segmentName(id))
		if err := chain.validateNextSegment(id); err != nil {
			return out, err
		}
		startPrev, err := chain.startPrev(segPath)
		if err != nil {
			return out, fmt.Errorf("wal: seed segment %d: %w", id, err)
		}
		state, err := scanFileFrom(segPath, false, false, startPrev)
		if err != nil {
			return out, err
		}
		if err := chain.accept(id, state); err != nil {
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
		out.ActiveSegmentID = id
	}
	out.LastHash = append([]byte(nil), chain.expectPrev[:]...)
	return out, nil
}

func Repair(path string) (RepairResult, error) {
	return repairWithOps(path, defaultWALFileOps())
}

func repairWithOps(path string, ops walFileOps) (RepairResult, error) {
	info, err := ops.stat(path)
	if err != nil {
		return RepairResult{}, fmt.Errorf("wal: stat: %w", err)
	}
	header, present, peekErr := peekFirstHeaderIfPresent(path)
	if peekErr != nil && !errors.Is(peekErr, errRepairableFirstHeader) {
		return RepairResult{}, peekErr
	}
	if present && (header.segmentID == 0 || header.sequence != 1) {
		return RepairResult{}, fmt.Errorf("wal: first record has segment_id %d sequence %d, want nonzero segment and sequence 1", header.segmentID, header.sequence)
	}
	return repairFileWithOps(path, info.Size(), [32]byte{}, ops)
}

// repairFileWithOps is the shared tail-tolerant repair routine used by both
// single-file Repair and the tail-segment branch of RepairDir. startPrev
// lets directory-mode pass in the hash chain state that was stitched across
// earlier segments so the tail segment is scanned from the correct seed
// rather than always assuming a zero prev_hash.
func repairFileWithOps(path string, originalBytes int64, startPrev [32]byte, ops walFileOps) (RepairResult, error) {
	state, scanErr := scanFileFrom(path, true, false, startPrev)
	if scanErr != nil {
		return RepairResult{}, scanErr
	}
	if state.validBytes > originalBytes {
		return RepairResult{}, fmt.Errorf("wal: repair file grew during scan: valid bytes %d exceed original bytes %d", state.validBytes, originalBytes)
	}
	truncated := originalBytes - state.validBytes
	result := RepairResult{
		Path:           path,
		Records:        state.records,
		ValidBytes:     state.validBytes,
		OriginalBytes:  originalBytes,
		TruncatedBytes: truncated,
		Repaired:       truncated > 0,
	}
	file, err := ops.openFile(path, os.O_RDWR, 0)
	if err != nil {
		return RepairResult{}, fmt.Errorf("wal: open for repair: %w", err)
	}
	var operationErr error
	if truncated > 0 {
		if err := ops.truncateFile(file, state.validBytes); err != nil {
			operationErr = fmt.Errorf("wal: truncate repair file: %w", err)
		}
	}
	if operationErr == nil {
		if err := ops.syncFile(file); err != nil {
			operationErr = fmt.Errorf("wal: sync repair file: %w", err)
		}
	}
	if err := ops.closeFile(file); err != nil {
		operationErr = errors.Join(operationErr, fmt.Errorf("wal: close repair file: %w", err))
	}
	if operationErr != nil {
		return RepairResult{}, operationErr
	}
	return result, nil
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
	return repairDirWithOps(dir, defaultWALFileOps())
}

func repairDirWithOps(dir string, ops walFileOps) (DirRepairResult, error) {
	ids, err := ListSegments(dir)
	if err != nil {
		return DirRepairResult{}, err
	}
	out := DirRepairResult{Path: dir}
	if len(ids) == 0 {
		return out, nil
	}

	chain := segmentChainState{trustBoundary: ids[0] > 1}
	// Verify every segment strictly except the last. Any error here is a
	// non-tail chain break and we bail out before touching disk.
	for _, id := range ids[:len(ids)-1] {
		segPath := filepath.Join(dir, segmentName(id))
		if err := chain.validateNextSegment(id); err != nil {
			return out, trusterrNonTailBreak(id, segPath, err)
		}
		startPrev, seedErr := chain.startPrev(segPath)
		if seedErr != nil {
			return out, trusterrNonTailBreak(id, segPath, seedErr)
		}
		state, scanErr := scanFileFrom(segPath, false, false, startPrev)
		if scanErr != nil {
			return out, trusterrNonTailBreak(id, segPath, scanErr)
		}
		if chainErr := chain.accept(id, state); chainErr != nil {
			return out, trusterrNonTailBreak(id, segPath, chainErr)
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
	}

	tailID := ids[len(ids)-1]
	tailPath := filepath.Join(dir, segmentName(tailID))
	if err := chain.validateNextSegment(tailID); err != nil {
		return out, trusterrNonTailBreak(tailID, tailPath, err)
	}
	if header, present, peekErr := peekFirstHeaderIfPresent(tailPath); peekErr == nil && present {
		if err := chain.validateFirstPosition(tailID, header.segmentID, header.sequence, header.prevHash); err != nil {
			return out, trusterr.Wrap(
				trusterr.CodeFailedPrecondition,
				fmt.Sprintf("wal: tail segment %d (%s) has invalid position metadata; refusing to mutate it", tailID, tailPath),
				err,
			)
		}
	}
	startPrev, err := chain.repairStartPrev(tailPath)
	if err != nil {
		return out, fmt.Errorf("wal: seed tail segment %d: %w", tailID, err)
	}
	info, err := ops.stat(tailPath)
	if err != nil {
		return out, fmt.Errorf("wal: stat tail segment: %w", err)
	}
	tail, err := repairFileWithOps(tailPath, info.Size(), startPrev, ops)
	if err != nil {
		return out, err
	}
	out.TailRepair = tail

	// Re-scan the tail after truncation so the Segments slice reflects the
	// post-repair state; the scan now always succeeds because the tail was
	// truncated exactly at the first invalid record boundary.
	tailState, scanErr := scanFileFrom(tailPath, false, false, startPrev)
	if scanErr != nil {
		return out, fmt.Errorf("wal: verify tail after repair: %w", scanErr)
	}
	if err := chain.accept(tailID, tailState); err != nil {
		return out, fmt.Errorf("wal: verify tail chain after repair: %w", err)
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
	var frame recordReadFrame
	prev := startPrev
	var offset int64
	for {
		rec, n, err := readOneWithFrame(f, offset, prev, &frame)
		if errors.Is(err, io.EOF) {
			return state, nil
		}
		if err != nil {
			if tolerateTail && (errors.Is(err, errTornRecord) || errors.Is(err, errCorruptRecord) || (state.records > 0 && errors.Is(err, errBadRecordMagic))) {
				return state, nil
			}
			return scanState{}, err
		}
		if rec.Position.SegmentID == 0 || rec.Position.Sequence == 0 {
			if tolerateTail {
				return state, nil
			}
			return scanState{}, fmt.Errorf("wal: zero segment_id or sequence at offset %d", offset)
		}
		if state.records == 0 {
			state.firstSequence = rec.Position.Sequence
			state.segmentID = rec.Position.SegmentID
			state.firstPrev = rec.PrevHash
		} else {
			if rec.Position.SegmentID != state.segmentID {
				if tolerateTail {
					return state, nil
				}
				return scanState{}, fmt.Errorf("wal: segment_id changed from %d to %d at offset %d", state.segmentID, rec.Position.SegmentID, offset)
			}
			if state.lastSequence == ^uint64(0) || rec.Position.Sequence != state.lastSequence+1 {
				if tolerateTail {
					return state, nil
				}
				return scanState{}, fmt.Errorf("wal: sequence discontinuity at offset %d: got %d after %d", offset, rec.Position.Sequence, state.lastSequence)
			}
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

type recordReadFrame struct {
	header  [headerSize]byte
	trailer [crcSize + recordHashSize]byte
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
	var frame recordReadFrame
	return readOneWithFrame(r, offset, expectedPrev, &frame)
}

func readOneWithFrame(r io.Reader, offset int64, expectedPrev [32]byte, frame *recordReadFrame) (Record, int64, error) {
	header := frame.header[:]
	if _, err := io.ReadFull(r, header); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return Record{}, 0, fmt.Errorf("%w: truncated header at offset %d", errTornRecord, offset)
		}
		return Record{}, 0, err
	}
	if binary.BigEndian.Uint32(header[0:4]) != magic {
		return Record{}, 0, fmt.Errorf("%w at offset %d", errBadRecordMagic, offset)
	}
	if binary.BigEndian.Uint16(header[4:6]) != version {
		return Record{}, 0, fmt.Errorf("%w: version at offset %d", errUnsupportedRecord, offset)
	}
	if binary.BigEndian.Uint16(header[6:8]) != typeAccepted {
		return Record{}, 0, fmt.Errorf("%w: record type at offset %d", errUnsupportedRecord, offset)
	}
	var prev [32]byte
	copy(prev[:], header[32:64])
	if prev != expectedPrev {
		return Record{}, 0, fmt.Errorf("%w: hash chain mismatch at offset %d", errCorruptRecord, offset)
	}
	payloadLen := binary.BigEndian.Uint32(header[64:68])
	if payloadLen == 0 {
		return Record{}, 0, fmt.Errorf("%w: empty payload at offset %d", errCorruptRecord, offset)
	}
	if payloadLen > maxPayloadBytes {
		return Record{}, 0, fmt.Errorf("%w: payload too large at offset %d: %d > %d", errCorruptRecord, offset, payloadLen, maxPayloadBytes)
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Record{}, 0, fmt.Errorf("%w: truncated payload at offset %d: %v", errTornRecord, offset, err)
		}
		return Record{}, 0, err
	}
	trailer := frame.trailer[:]
	if _, err := io.ReadFull(r, trailer); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Record{}, 0, fmt.Errorf("%w: truncated trailer at offset %d: %v", errTornRecord, offset, err)
		}
		return Record{}, 0, err
	}
	wantCRC := binary.BigEndian.Uint32(trailer[:4])
	crc := crc32.New(crcTable)
	_, _ = crc.Write(header)
	_, _ = crc.Write(payload)
	gotCRC := crc.Sum32()
	if gotCRC != wantCRC {
		return Record{}, 0, fmt.Errorf("%w: crc mismatch at offset %d", errCorruptRecord, offset)
	}
	h := sha256.New()
	_, _ = h.Write(header)
	_, _ = h.Write(payload)
	_, _ = h.Write(trailer[:4])
	var gotHash [recordHashSize]byte
	h.Sum(gotHash[:0])
	var storedHash [32]byte
	copy(storedHash[:], trailer[4:])
	if gotHash != storedHash {
		return Record{}, 0, fmt.Errorf("%w: record hash mismatch at offset %d", errCorruptRecord, offset)
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
