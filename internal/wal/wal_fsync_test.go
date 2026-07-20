package wal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type manualTimer struct {
	mu       sync.Mutex
	callback func()
	stopped  bool
}

func (timer *manualTimer) Stop() bool {
	timer.mu.Lock()
	defer timer.mu.Unlock()
	wasActive := !timer.stopped
	timer.stopped = true
	return wasActive
}

// fire deliberately invokes the callback even after Stop. That models a
// callback that was already dequeued when rotation or Close invalidated it.
func (timer *manualTimer) fire() {
	timer.callback()
}

func (timer *manualTimer) isStopped() bool {
	timer.mu.Lock()
	defer timer.mu.Unlock()
	return timer.stopped
}

type manualTimerFactory struct {
	mu     sync.Mutex
	timers []*manualTimer
	delays []time.Duration
}

func (factory *manualTimerFactory) afterFunc(delay time.Duration, callback func()) timerStopper {
	timer := &manualTimer{callback: callback}
	factory.mu.Lock()
	factory.timers = append(factory.timers, timer)
	factory.delays = append(factory.delays, delay)
	factory.mu.Unlock()
	return timer
}

func (factory *manualTimerFactory) snapshot() ([]*manualTimer, []time.Duration) {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return append([]*manualTimer(nil), factory.timers...), append([]time.Duration(nil), factory.delays...)
}

func openManualGroupWriter(t *testing.T, options Options) (*Writer, *manualTimerFactory, *atomic.Int64) {
	t.Helper()
	options.FsyncMode = FsyncGroup
	if options.GroupCommitInterval == 0 {
		options.GroupCommitInterval = time.Hour
	}
	writer, err := OpenWriterWithOptions(filepath.Join(t.TempDir(), "records.wal"), 1, options)
	if err != nil {
		t.Fatalf("OpenWriterWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	factory := &manualTimerFactory{}
	writer.afterFunc = factory.afterFunc
	calls := &atomic.Int64{}
	writer.syncFile = func(file *os.File) error {
		calls.Add(1)
		return file.Sync()
	}
	return writer, factory, calls
}

func appendTestRecord(t *testing.T, writer *Writer, payload string) {
	t.Helper()
	if _, _, err := writer.Append(context.Background(), []byte(payload)); err != nil {
		t.Fatalf("Append(%q) error = %v", payload, err)
	}
}

func TestGroupFsyncFlushesIdleTailAndCoalescesAppends(t *testing.T) {
	var successfulFsyncs atomic.Int64
	writer, timers, syncCalls := openManualGroupWriter(t, Options{
		OnFsync: func(mode string, _ time.Duration) {
			if mode != FsyncGroup {
				t.Errorf("OnFsync mode = %q, want %q", mode, FsyncGroup)
			}
			successfulFsyncs.Add(1)
		},
	})

	appendTestRecord(t, writer, "first")
	if got := syncCalls.Load(); got != 1 {
		t.Fatalf("sync calls after first append = %d, want 1", got)
	}
	appendTestRecord(t, writer, "second")
	appendTestRecord(t, writer, "third")

	created, delays := timers.snapshot()
	if len(created) != 1 {
		t.Fatalf("timers after coalesced appends = %d, want 1", len(created))
	}
	if delays[0] <= 0 || delays[0] > time.Hour {
		t.Fatalf("group timer delay = %s, want (0, 1h]", delays[0])
	}
	if got := syncCalls.Load(); got != 1 {
		t.Fatalf("sync calls before timer = %d, want 1", got)
	}

	created[0].fire()
	if got := syncCalls.Load(); got != 2 {
		t.Fatalf("sync calls after idle-tail timer = %d, want 2", got)
	}
	if got := successfulFsyncs.Load(); got != 2 {
		t.Fatalf("successful fsync observations = %d, want 2", got)
	}

	appendTestRecord(t, writer, "fourth")
	created, _ = timers.snapshot()
	if len(created) != 2 {
		t.Fatalf("timers after a new dirty interval = %d, want 2", len(created))
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !created[1].isStopped() {
		t.Fatal("Close() did not stop the pending group timer")
	}
	if got := syncCalls.Load(); got != 3 {
		t.Fatalf("sync calls after Close = %d, want 3", got)
	}

	created[1].fire()
	if got := syncCalls.Load(); got != 3 {
		t.Fatalf("stale timer synced a closed writer: calls = %d, want 3", got)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if _, _, err := writer.Append(context.Background(), []byte("after-close")); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Append() after Close error = %v, want closed error", err)
	}
}

func TestGroupFsyncRotationInvalidatesOldTimer(t *testing.T) {
	dir := t.TempDir()
	writer, err := OpenDirWriter(dir, Options{
		FsyncMode:           FsyncGroup,
		GroupCommitInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	timers := &manualTimerFactory{}
	writer.afterFunc = timers.afterFunc
	var syncCalls atomic.Int64
	writer.syncFile = func(file *os.File) error {
		syncCalls.Add(1)
		return file.Sync()
	}

	appendTestRecord(t, writer, "first")
	appendTestRecord(t, writer, "second")
	created, _ := timers.snapshot()
	if len(created) != 1 {
		t.Fatalf("timers before rotation = %d, want 1", len(created))
	}

	writer.mu.Lock()
	writer.maxBytes = writer.offset + 1
	writer.mu.Unlock()
	appendTestRecord(t, writer, "third-forces-rotation")
	created, _ = timers.snapshot()
	if len(created) != 2 {
		t.Fatalf("timers after rotation = %d, want 2", len(created))
	}
	if !created[0].isStopped() {
		t.Fatal("rotation did not stop the old segment timer")
	}
	if got := writer.ActiveSegmentID(); got != 2 {
		t.Fatalf("ActiveSegmentID() = %d, want 2", got)
	}
	if got := syncCalls.Load(); got != 2 {
		t.Fatalf("sync calls after rotation = %d, want 2", got)
	}

	created[0].fire()
	if got := syncCalls.Load(); got != 2 {
		t.Fatalf("stale old-segment timer sync calls = %d, want 2", got)
	}
	created[1].fire()
	if got := syncCalls.Load(); got != 3 {
		t.Fatalf("new-segment timer sync calls = %d, want 3", got)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestGroupFsyncImmediateSyncInvalidatesOldTimer(t *testing.T) {
	writer, timers, syncCalls := openManualGroupWriter(t, Options{})
	appendTestRecord(t, writer, "first")
	appendTestRecord(t, writer, "second")
	created, _ := timers.snapshot()
	if len(created) != 1 {
		t.Fatalf("timers before immediate sync = %d, want 1", len(created))
	}

	writer.mu.Lock()
	writer.lastSync = time.Now().Add(-2 * writer.groupEvery)
	writer.mu.Unlock()
	appendTestRecord(t, writer, "third-after-deadline")
	if !created[0].isStopped() {
		t.Fatal("immediate sync did not stop the pending timer")
	}
	if got := syncCalls.Load(); got != 2 {
		t.Fatalf("sync calls after immediate sync = %d, want 2", got)
	}

	created[0].fire()
	if got := syncCalls.Load(); got != 2 {
		t.Fatalf("stale timer synced after immediate sync: calls = %d, want 2", got)
	}
}

func TestGroupFsyncBackgroundErrorIsSticky(t *testing.T) {
	sentinel := errors.New("injected fsync failure")
	var reported atomic.Int64
	writer, timers, syncCalls := openManualGroupWriter(t, Options{
		OnFsyncError: func(mode string, err error) {
			if mode != FsyncGroup {
				t.Errorf("OnFsyncError mode = %q, want %q", mode, FsyncGroup)
			}
			if !errors.Is(err, sentinel) {
				t.Errorf("OnFsyncError error = %v, want injected failure", err)
			}
			reported.Add(1)
		},
	})
	writer.syncFile = func(file *os.File) error {
		call := syncCalls.Add(1)
		if call == 2 {
			return sentinel
		}
		return file.Sync()
	}

	appendTestRecord(t, writer, "first")
	appendTestRecord(t, writer, "second")
	created, _ := timers.snapshot()
	created[0].fire()
	if got := reported.Load(); got != 1 {
		t.Fatalf("reported fsync failures = %d, want 1", got)
	}

	writer.mu.Lock()
	wantSequence := writer.sequence
	wantOffset := writer.offset
	writer.mu.Unlock()
	if _, _, err := writer.Append(context.Background(), []byte("must-not-write")); !errors.Is(err, sentinel) {
		t.Fatalf("Append() after background failure error = %v, want injected failure", err)
	}
	writer.mu.Lock()
	gotSequence := writer.sequence
	gotOffset := writer.offset
	writer.mu.Unlock()
	if gotSequence != wantSequence || gotOffset != wantOffset {
		t.Fatalf("failed writer advanced from seq/offset %d/%d to %d/%d", wantSequence, wantOffset, gotSequence, gotOffset)
	}
	if got := syncCalls.Load(); got != 2 {
		t.Fatalf("sync calls after rejected append = %d, want 2", got)
	}

	if err := writer.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("Close() error = %v, want sticky injected failure", err)
	}
	if got := syncCalls.Load(); got != 3 {
		t.Fatalf("Close() did not retry final sync: calls = %d, want 3", got)
	}
	if err := writer.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("second Close() error = %v, want cached sticky failure", err)
	}
	if got := syncCalls.Load(); got != 3 {
		t.Fatalf("second Close() repeated IO: sync calls = %d, want 3", got)
	}
}

func TestGroupFsyncRotationOpenFailureClearsClosedFile(t *testing.T) {
	dir := t.TempDir()
	writer, err := OpenDirWriter(dir, Options{
		FsyncMode:           FsyncGroup,
		GroupCommitInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	timers := &manualTimerFactory{}
	writer.afterFunc = timers.afterFunc
	var syncCalls atomic.Int64
	writer.syncFile = func(file *os.File) error {
		syncCalls.Add(1)
		return file.Sync()
	}

	appendTestRecord(t, writer, "first")
	appendTestRecord(t, writer, "second")
	writer.mu.Lock()
	writer.maxBytes = writer.offset + 1
	writer.mu.Unlock()
	if err := os.Mkdir(filepath.Join(dir, segmentName(2)), 0o700); err != nil {
		t.Fatalf("create rotated-segment collision: %v", err)
	}

	if _, _, err := writer.Append(context.Background(), []byte("force-rotation")); err == nil || !strings.Contains(err.Error(), "open rotated segment 2") {
		t.Fatalf("Append() rotation error = %v, want open rotated segment error", err)
	}
	created, _ := timers.snapshot()
	if len(created) != 1 || !created[0].isStopped() {
		t.Fatalf("rotation failure did not invalidate old timer: timers=%d stopped=%v", len(created), len(created) == 1 && created[0].isStopped())
	}
	writer.mu.Lock()
	file := writer.file
	writer.mu.Unlock()
	if file != nil {
		t.Fatal("failed rotation retained the closed old segment descriptor")
	}
	if _, _, err := writer.Append(context.Background(), []byte("queued-append")); err == nil || !strings.Contains(err.Error(), "open rotated segment 2") {
		t.Fatalf("Append() after rotation failure error = %v, want sticky rotation-open failure", err)
	}
	if got := syncCalls.Load(); got != 2 {
		t.Fatalf("sync calls after failed rotation = %d, want 2", got)
	}
	if err := writer.Close(); err == nil || !strings.Contains(err.Error(), "open rotated segment 2") || strings.Contains(err.Error(), "file already closed") {
		t.Fatalf("Close() error = %v, want only the sticky rotation-open failure", err)
	}
	if got := syncCalls.Load(); got != 2 {
		t.Fatalf("Close() retried IO on closed old segment: sync calls = %d, want 2", got)
	}
}

func TestGroupFsyncRotationCloseFailureClearsFileAndStaysSticky(t *testing.T) {
	sentinel := errors.New("injected close failure")
	writer, err := OpenDirWriter(t.TempDir(), Options{
		FsyncMode:           FsyncGroup,
		GroupCommitInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	timers := &manualTimerFactory{}
	writer.afterFunc = timers.afterFunc
	var (
		syncCalls  atomic.Int64
		closeCalls atomic.Int64
	)
	writer.syncFile = func(file *os.File) error {
		syncCalls.Add(1)
		return file.Sync()
	}
	writer.closeFile = func(file *os.File) error {
		closeCalls.Add(1)
		if err := file.Close(); err != nil {
			return err
		}
		return sentinel
	}

	appendTestRecord(t, writer, "first")
	appendTestRecord(t, writer, "second")
	writer.mu.Lock()
	writer.maxBytes = writer.offset + 1
	writer.mu.Unlock()
	if _, _, err := writer.Append(context.Background(), []byte("force-rotation")); !errors.Is(err, sentinel) {
		t.Fatalf("Append() rotation close error = %v, want injected failure", err)
	}
	writer.mu.Lock()
	file := writer.file
	writer.mu.Unlock()
	if file != nil {
		t.Fatal("failed pre-rotation close retained an unusable descriptor")
	}
	if _, _, err := writer.Append(context.Background(), []byte("queued-append")); !errors.Is(err, sentinel) {
		t.Fatalf("Append() after rotation failure error = %v, want sticky injected failure", err)
	}
	if err := writer.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("Close() error = %v, want sticky injected failure", err)
	}
	if got := syncCalls.Load(); got != 2 {
		t.Fatalf("sync calls = %d, want first append plus rotation", got)
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("close calls = %d, want only failed pre-rotation close", got)
	}
}

func TestStrictAndBatchFsyncSemanticsRemainUnchanged(t *testing.T) {
	tests := []struct {
		name                  string
		mode                  string
		wantAppendSyncs       int64
		wantTotalSyncsAtClose int64
	}{
		{name: "strict", mode: FsyncStrict, wantAppendSyncs: 2, wantTotalSyncsAtClose: 3},
		{name: "batch", mode: FsyncBatch, wantAppendSyncs: 0, wantTotalSyncsAtClose: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var observed atomic.Int64
			writer, err := OpenWriterWithOptions(filepath.Join(t.TempDir(), "records.wal"), 1, Options{
				FsyncMode: test.mode,
				OnFsync: func(string, time.Duration) {
					observed.Add(1)
				},
			})
			if err != nil {
				t.Fatalf("OpenWriterWithOptions() error = %v", err)
			}
			t.Cleanup(func() { _ = writer.Close() })
			timers := &manualTimerFactory{}
			writer.afterFunc = timers.afterFunc
			var syncCalls atomic.Int64
			writer.syncFile = func(file *os.File) error {
				syncCalls.Add(1)
				return file.Sync()
			}

			appendTestRecord(t, writer, "first")
			appendTestRecord(t, writer, "second")
			if got := syncCalls.Load(); got != test.wantAppendSyncs {
				t.Fatalf("append sync calls = %d, want %d", got, test.wantAppendSyncs)
			}
			if got := observed.Load(); got != test.wantAppendSyncs {
				t.Fatalf("observed append syncs = %d, want %d", got, test.wantAppendSyncs)
			}
			created, _ := timers.snapshot()
			if len(created) != 0 {
				t.Fatalf("timers = %d, want 0", len(created))
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			if got := syncCalls.Load(); got != test.wantTotalSyncsAtClose {
				t.Fatalf("total sync calls = %d, want %d", got, test.wantTotalSyncsAtClose)
			}
			if got := observed.Load(); got != test.wantTotalSyncsAtClose {
				t.Fatalf("total observed syncs = %d, want %d", got, test.wantTotalSyncsAtClose)
			}
		})
	}
}

func TestCloseReportsFinalFsyncFailureOnce(t *testing.T) {
	sentinel := errors.New("injected final fsync failure")
	var reported atomic.Int64
	writer, err := OpenWriterWithOptions(filepath.Join(t.TempDir(), "records.wal"), 1, Options{
		FsyncMode: FsyncBatch,
		OnFsyncError: func(mode string, err error) {
			if mode != FsyncBatch || !errors.Is(err, sentinel) {
				t.Errorf("OnFsyncError(%q, %v), want batch injected failure", mode, err)
			}
			reported.Add(1)
		},
	})
	if err != nil {
		t.Fatalf("OpenWriterWithOptions() error = %v", err)
	}
	appendTestRecord(t, writer, "dirty-batch-record")
	writer.syncFile = func(*os.File) error { return sentinel }

	if err := writer.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("Close() error = %v, want injected failure", err)
	}
	if got := reported.Load(); got != 1 {
		t.Fatalf("reported final fsync failures = %d, want 1", got)
	}
	if err := writer.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("second Close() error = %v, want cached injected failure", err)
	}
	if got := reported.Load(); got != 1 {
		t.Fatalf("second Close() repeated error hook: calls = %d, want 1", got)
	}
}

func TestGroupFsyncTimerSerializesWithClose(t *testing.T) {
	writer, timers, syncCalls := openManualGroupWriter(t, Options{})
	entered := make(chan struct{})
	release := make(chan struct{})
	writer.syncFile = func(file *os.File) error {
		call := syncCalls.Add(1)
		if call == 2 {
			close(entered)
			<-release
		}
		return file.Sync()
	}
	appendTestRecord(t, writer, "first")
	appendTestRecord(t, writer, "second")
	created, _ := timers.snapshot()

	timerDone := make(chan struct{})
	go func() {
		created[0].fire()
		close(timerDone)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timer callback did not enter fsync")
	}
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- writer.Close()
	}()
	close(release)
	select {
	case <-timerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timer callback deadlocked with Close")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close() deadlocked with timer callback")
	}
	if got := syncCalls.Load(); got != 3 {
		t.Fatalf("serialized timer and Close sync calls = %d, want 3", got)
	}
}

func TestCloseWaitsForBackgroundFsyncHook(t *testing.T) {
	var hookCalls atomic.Int64
	hookEntered := make(chan struct{})
	releaseHook := make(chan struct{})
	closeSyncObserved := make(chan struct{})
	writer, timers, syncCalls := openManualGroupWriter(t, Options{
		OnFsync: func(_ string, _ time.Duration) {
			if hookCalls.Add(1) == 2 {
				close(hookEntered)
				<-releaseHook
			}
		},
	})
	writer.syncFile = func(file *os.File) error {
		if syncCalls.Add(1) == 3 {
			close(closeSyncObserved)
		}
		return file.Sync()
	}
	appendTestRecord(t, writer, "first")
	appendTestRecord(t, writer, "second")
	created, _ := timers.snapshot()

	timerDone := make(chan struct{})
	go func() {
		created[0].fire()
		close(timerDone)
	}()
	select {
	case <-hookEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("background fsync hook did not start")
	}
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- writer.Close()
	}()
	select {
	case <-closeSyncObserved:
	case <-time.After(2 * time.Second):
		t.Fatal("Close() did not reach its final fsync")
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Close() returned before background hook completed: %v", err)
	default:
	}

	close(releaseHook)
	select {
	case <-timerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("background fsync hook did not finish")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close() did not return after background hook completed")
	}
}
