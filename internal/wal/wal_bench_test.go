package wal

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestEncodeRecordIntoReusesBuffer(t *testing.T) {
	payload := bytes.Repeat([]byte{1}, 1024)
	prevHash := [32]byte{1, 2, 3}
	want, wantHash := encodeRecord(7, 11, 123, prevHash, payload)
	buf := make([]byte, 0, len(want))

	allocs := testing.AllocsPerRun(100, func() {
		got, gotHash := encodeRecordInto(buf, 7, 11, 123, prevHash, payload)
		if !bytes.Equal(got, want) {
			t.Fatal("reused encoding differs from owned encoding")
		}
		if gotHash != wantHash {
			t.Fatal("reused record hash differs from owned record hash")
		}
	})
	if allocs != 0 {
		t.Fatalf("encodeRecordInto allocations = %.2f, want 0 with sufficient capacity", allocs)
	}
}

func TestWriterDoesNotRetainOversizedRecordBuffer(t *testing.T) {
	w, err := OpenDirWriter(t.TempDir(), Options{FsyncMode: FsyncBatch})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	payload := make([]byte, maxReusableRecordBytes)
	if _, _, err := w.Append(context.Background(), payload); err != nil {
		t.Fatal(err)
	}
	if w.recordBuf != nil {
		t.Fatalf("retained oversized record buffer with capacity %d", cap(w.recordBuf))
	}
}

func BenchmarkWALAppendGroup(b *testing.B) {
	w, err := OpenDirWriter(b.TempDir(), Options{
		FsyncMode:           FsyncGroup,
		GroupCommitInterval: time.Hour,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = w.Close() })
	payload := bytes.Repeat([]byte{1}, 1024)
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := w.Append(ctx, payload); err != nil {
			b.Fatal(err)
		}
	}
}
