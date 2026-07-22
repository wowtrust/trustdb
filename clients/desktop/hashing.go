package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

// HashJobEvent is the envelope every backend → frontend hashing message
// rides on. The frontend listens on four topics:
//
//   - hash:begin          { job_id, total_files, total_bytes }
//   - hash:file-progress  { job_id, index, path, name, bytes_hashed, bytes_total }
//   - hash:file-done      { job_id, index, info }
//   - hash:done           { job_id, infos }
//   - hash:error          { job_id, index, error }      (index=-1 for job-wide)
//   - hash:cancelled      { job_id }
type HashJobEvent struct {
	JobID       string     `json:"job_id"`
	Index       int        `json:"index,omitempty"`
	Path        string     `json:"path,omitempty"`
	Name        string     `json:"name,omitempty"`
	BytesHashed int64      `json:"bytes_hashed,omitempty"`
	BytesTotal  int64      `json:"bytes_total,omitempty"`
	TotalFiles  int        `json:"total_files,omitempty"`
	TotalBytes  int64      `json:"total_bytes,omitempty"`
	Info        *FileInfo  `json:"info,omitempty"`
	Infos       []FileInfo `json:"infos,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// hashJob tracks one async batch hash so callers can cancel mid-stream.
// We keep these short-lived: a job is born in StartHashing, runs on a
// goroutine, and drops itself from the manager in a defer so the map
// never grows unboundedly.
type hashJob struct {
	id     string
	ctx    context.Context
	cancel context.CancelFunc
}

// hashJobManager is the App's async hashing registry. It is safe for
// concurrent use; a mutex guards the map but the jobs themselves run
// lock-free on goroutines.
type hashJobManager struct {
	mu   sync.Mutex
	jobs map[string]*hashJob
}

func newHashJobManager() *hashJobManager {
	return &hashJobManager{jobs: make(map[string]*hashJob)}
}

func (m *hashJobManager) register(parent context.Context, id string) *hashJob {
	ctx, cancel := context.WithCancel(parent)
	job := &hashJob{id: id, ctx: ctx, cancel: cancel}
	m.mu.Lock()
	m.jobs[id] = job
	m.mu.Unlock()
	return job
}

func (m *hashJobManager) remove(id string) {
	m.mu.Lock()
	if j, ok := m.jobs[id]; ok {
		j.cancel()
		delete(m.jobs, id)
	}
	m.mu.Unlock()
}

// cancel signals the worker to stop at the next progress tick. The
// worker is responsible for cleaning up its file handle and emitting
// hash:cancelled before it exits.
func (m *hashJobManager) cancel(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return false
	}
	j.cancel()
	return true
}

func newJobID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("job-%d", time.Now().UnixNano())
	}
	return "hj-" + hex.EncodeToString(b[:])
}

// progressReader wraps an io.Reader and reports cumulative bytes-read
// to a callback, but only when `interval` has elapsed since the last
// report OR `chunkThreshold` bytes have been read since then. Without
// the throttle a 5 GiB file would emit ~160 k events at 32 KiB reads,
// overwhelming the Wails event bus.
type progressReader struct {
	r              io.Reader
	ctx            context.Context
	total          int64
	read           int64
	lastReport     time.Time
	lastReportRead int64
	interval       time.Duration
	chunkThreshold int64
	onTick         func(read int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	if err := p.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := p.r.Read(b)
	p.read += int64(n)
	now := time.Now()
	if p.onTick != nil {
		// Always emit on EOF even if the throttle says no, so the
		// final "100%" bar is guaranteed to land.
		shouldEmit := errors.Is(err, io.EOF) ||
			now.Sub(p.lastReport) >= p.interval ||
			(p.read-p.lastReportRead) >= p.chunkThreshold
		if shouldEmit {
			p.onTick(p.read)
			p.lastReport = now
			p.lastReportRead = p.read
		}
	}
	return n, err
}

// hashFileStream computes the sha256 of a single file while periodically
// calling onProgress with the running byte count. It respects ctx for
// cancellation and returns a FileInfo ready to be handed to the frontend.
// The function is synchronous but bounded in memory (io.Copy buffers).
func hashFileStream(ctx context.Context, path string, onProgress func(read, total int64)) (FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return FileInfo{}, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return FileInfo{}, err
	}

	pr := &progressReader{
		r:        f,
		ctx:      ctx,
		total:    fi.Size(),
		interval: 150 * time.Millisecond,
		// 8 MiB ~= two screen refreshes on a typical SSD; small
		// enough for the bar to look alive, big enough to not
		// dominate CPU on NVMe.
		chunkThreshold: 8 << 20,
		onTick: func(read int64) {
			if onProgress != nil {
				onProgress(read, fi.Size())
			}
		},
	}
	sum, n, err := trustcrypto.HashReader(model.DefaultHashAlg, pr)
	if err != nil {
		// Surface cancellation with a stable sentinel so callers can
		// tell user-aborted apart from real IO failures.
		if errors.Is(ctx.Err(), context.Canceled) {
			return FileInfo{}, context.Canceled
		}
		return FileInfo{}, err
	}
	return FileInfo{
		Path:        path,
		Name:        filepath.Base(path),
		Size:        n,
		ContentHash: hex.EncodeToString(sum),
		MediaType:   guessMedia(path),
	}, nil
}
