package app

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ryan-wong-coder/trustdb/internal/model"
)

func TestIdempotencyIndexRememberFirstStores(t *testing.T) {
	t.Parallel()

	idx := NewIdempotencyIndex()
	hash := []byte{0x01, 0x02}
	built := 0
	record, accepted, loaded, conflict, err := idx.Remember("k", hash, func() (model.ServerRecord, model.AcceptedReceipt, error) {
		built++
		return model.ServerRecord{RecordID: "r1"}, model.AcceptedReceipt{RecordID: "r1"}, nil
	})
	if err != nil {
		t.Fatalf("Remember() error = %v", err)
	}
	if loaded {
		t.Fatalf("first Remember() loaded = true, want false")
	}
	if conflict {
		t.Fatalf("first Remember() conflict = true, want false")
	}
	if record.RecordID != "r1" || accepted.RecordID != "r1" {
		t.Fatalf("first Remember() record = %+v accepted = %+v", record, accepted)
	}
	if built != 1 {
		t.Fatalf("build ran %d times, want 1", built)
	}
	if idx.Size() != 1 {
		t.Fatalf("Size() = %d, want 1", idx.Size())
	}
}

func TestIdempotencyIndexRememberReturnsStoredEntry(t *testing.T) {
	t.Parallel()

	idx := NewIdempotencyIndex()
	hash := []byte{0x01, 0x02}
	_, _, _, _, err := idx.Remember("k", hash, func() (model.ServerRecord, model.AcceptedReceipt, error) {
		return model.ServerRecord{RecordID: "r1"}, model.AcceptedReceipt{RecordID: "r1"}, nil
	})
	if err != nil {
		t.Fatalf("seed Remember() error = %v", err)
	}
	built := 0
	record, accepted, loaded, conflict, err := idx.Remember("k", hash, func() (model.ServerRecord, model.AcceptedReceipt, error) {
		built++
		return model.ServerRecord{RecordID: "r2"}, model.AcceptedReceipt{RecordID: "r2"}, nil
	})
	if err != nil {
		t.Fatalf("replay Remember() error = %v", err)
	}
	if !loaded {
		t.Fatalf("replay Remember() loaded = false, want true")
	}
	if conflict {
		t.Fatalf("replay Remember() conflict = true")
	}
	if built != 0 {
		t.Fatalf("build ran %d times, want 0 when key already stored", built)
	}
	if record.RecordID != "r1" || accepted.RecordID != "r1" {
		t.Fatalf("replay Remember() returned %+v %+v, want stored entry", record, accepted)
	}
}

func TestIdempotencyIndexRememberDetectsConflict(t *testing.T) {
	t.Parallel()

	idx := NewIdempotencyIndex()
	_, _, _, _, err := idx.Remember("k", []byte{0x01}, func() (model.ServerRecord, model.AcceptedReceipt, error) {
		return model.ServerRecord{RecordID: "r1"}, model.AcceptedReceipt{RecordID: "r1"}, nil
	})
	if err != nil {
		t.Fatalf("seed Remember() error = %v", err)
	}
	_, _, loaded, conflict, err := idx.Remember("k", []byte{0x02}, func() (model.ServerRecord, model.AcceptedReceipt, error) {
		t.Fatalf("build must not run when the claim hash differs")
		return model.ServerRecord{}, model.AcceptedReceipt{}, nil
	})
	if err != nil {
		t.Fatalf("conflicting Remember() error = %v", err)
	}
	if loaded {
		t.Fatalf("conflicting Remember() loaded = true, want false")
	}
	if !conflict {
		t.Fatalf("conflicting Remember() conflict = false, want true")
	}
}

func TestIdempotencyIndexRememberEmptyKeyBypasses(t *testing.T) {
	t.Parallel()

	idx := NewIdempotencyIndex()
	built := 0
	_, _, loaded, conflict, err := idx.Remember("", []byte{0x01}, func() (model.ServerRecord, model.AcceptedReceipt, error) {
		built++
		return model.ServerRecord{RecordID: "r-empty"}, model.AcceptedReceipt{RecordID: "r-empty"}, nil
	})
	if err != nil {
		t.Fatalf("Remember() error = %v", err)
	}
	if loaded || conflict {
		t.Fatalf("empty key Remember() loaded=%v conflict=%v", loaded, conflict)
	}
	if built != 1 {
		t.Fatalf("build ran %d times, want 1", built)
	}
	if idx.Size() != 0 {
		t.Fatalf("empty key must not be stored, Size() = %d", idx.Size())
	}
}

func TestIdempotencyIndexRememberConcurrentSerializesBuild(t *testing.T) {
	t.Parallel()

	idx := NewIdempotencyIndex()
	const concurrency = 16
	hash := []byte{0xaa}

	var builds atomic.Int32
	start := make(chan struct{})
	block := make(chan struct{})

	var wg sync.WaitGroup
	results := make([]string, concurrency)
	loadedCounts := make([]bool, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx2 int) {
			defer wg.Done()
			<-start
			record, _, loaded, _, err := idx.Remember("k", hash, func() (model.ServerRecord, model.AcceptedReceipt, error) {
				builds.Add(1)
				<-block
				return model.ServerRecord{RecordID: fmt.Sprintf("r-%d", idx2)}, model.AcceptedReceipt{RecordID: fmt.Sprintf("r-%d", idx2)}, nil
			})
			if err != nil {
				t.Errorf("Remember() error = %v", err)
				return
			}
			results[idx2] = record.RecordID
			loadedCounts[idx2] = loaded
		}(i)
	}

	close(start)
	// Wait until at least one goroutine is inside build so the per-key
	// mutex has been claimed before releasing build.
	for builds.Load() == 0 {
	}
	close(block)
	wg.Wait()

	if got := builds.Load(); got != 1 {
		t.Fatalf("build ran %d times, want exactly 1 under concurrency", got)
	}

	// All concurrent callers should observe the same stored RecordID.
	first := ""
	for _, id := range results {
		if id == "" {
			t.Fatalf("unexpected empty result: %v", results)
		}
		if first == "" {
			first = id
			continue
		}
		if id != first {
			t.Fatalf("concurrent Remember() returned mismatched ids: first=%s got=%s", first, id)
		}
	}
	loadedSeen := 0
	for _, l := range loadedCounts {
		if l {
			loadedSeen++
		}
	}
	if loadedSeen != concurrency-1 {
		t.Fatalf("loaded count = %d, want %d (only the first caller should not be loaded)", loadedSeen, concurrency-1)
	}
	if idx.Size() != 1 {
		t.Fatalf("Size() = %d, want 1", idx.Size())
	}
}

func TestIdempotencyIndexRememberedInstallsEntry(t *testing.T) {
	t.Parallel()

	idx := NewIdempotencyIndex()
	idx.Remembered("k", model.ServerRecord{RecordID: "r-replay"}, model.AcceptedReceipt{RecordID: "r-replay"}, []byte{0x09})
	if idx.Size() != 1 {
		t.Fatalf("Size() = %d, want 1 after Remembered", idx.Size())
	}
	record, accepted, loaded, conflict, err := idx.Remember("k", []byte{0x09}, func() (model.ServerRecord, model.AcceptedReceipt, error) {
		t.Fatalf("build must not run after Remembered seeded the entry")
		return model.ServerRecord{}, model.AcceptedReceipt{}, nil
	})
	if err != nil || conflict {
		t.Fatalf("Remember() err=%v conflict=%v", err, conflict)
	}
	if !loaded {
		t.Fatalf("Remember() loaded = false, want true")
	}
	if record.RecordID != "r-replay" || accepted.RecordID != "r-replay" {
		t.Fatalf("Remember() = %+v %+v", record, accepted)
	}

	idx.Remembered("", model.ServerRecord{RecordID: "x"}, model.AcceptedReceipt{RecordID: "x"}, nil)
	if idx.Size() != 1 {
		t.Fatalf("Remembered() with empty key must be a no-op, Size() = %d", idx.Size())
	}
}

func TestIdempotencyIndexRestoreRejectsConflictingWALPosition(t *testing.T) {
	t.Parallel()

	idx := NewIdempotencyIndex()
	firstRecord := model.ServerRecord{RecordID: "r-replay", WAL: model.WALPosition{SegmentID: 1, Offset: 10, Sequence: 1}}
	firstAccepted := model.AcceptedReceipt{RecordID: "r-replay", WAL: firstRecord.WAL}
	if !idx.Restore("k", firstRecord, firstAccepted, []byte{0x09}) {
		t.Fatal("first Restore() = false, want true")
	}
	if !idx.Restore("k", firstRecord, firstAccepted, []byte{0x09}) {
		t.Fatal("identical Restore() = false, want true")
	}
	duplicate := firstRecord
	duplicate.WAL = model.WALPosition{SegmentID: 1, Offset: 20, Sequence: 2}
	duplicateAccepted := firstAccepted
	duplicateAccepted.WAL = duplicate.WAL
	if idx.Restore("k", duplicate, duplicateAccepted, []byte{0x09}) {
		t.Fatal("conflicting WAL Restore() = true, want false")
	}
	if idx.Restore("k", firstRecord, firstAccepted, []byte{0x0a}) {
		t.Fatal("conflicting claim Restore() = true, want false")
	}
	if idx.Size() != 1 {
		t.Fatalf("Size() = %d, want 1", idx.Size())
	}
}

func TestIdempotencyKeyFormat(t *testing.T) {
	t.Parallel()

	if IdempotencyKey("tenant", "client", "") != "" {
		t.Fatalf("empty idempotency key must produce empty composite key")
	}
	if got := IdempotencyKey("tenant", "client", "k1"); got != "tenant\x00client\x00k1" {
		t.Fatalf("IdempotencyKey() = %q", got)
	}
	// Different components must not collide even when concatenation could
	// otherwise overlap (e.g. "ab" + "cd" vs "abc" + "d").
	a := IdempotencyKey("ab", "cd", "k")
	b := IdempotencyKey("abc", "d", "k")
	if a == b {
		t.Fatalf("IdempotencyKey() collided: %q == %q", a, b)
	}
}
