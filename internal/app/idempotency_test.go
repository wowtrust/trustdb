package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

type durableReaderStub struct {
	decision model.IdempotencyDecision
	found    bool
	err      error
	calls    atomic.Int32
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
}

type durableRecordReaderStub struct {
	bundle model.ProofBundle
	err    error
	calls  atomic.Int32
}

func (s *durableRecordReaderStub) GetBundle(context.Context, string) (model.ProofBundle, error) {
	s.calls.Add(1)
	return s.bundle, s.err
}

func (s *durableReaderStub) GetIdempotencyDecision(context.Context, model.IdempotencyIdentity) (model.IdempotencyDecision, bool, error) {
	s.calls.Add(1)
	if s.entered != nil {
		s.once.Do(func() { close(s.entered) })
	}
	if s.release != nil {
		<-s.release
	}
	return s.decision, s.found, s.err
}

func testDurableDecision() model.IdempotencyDecision {
	identity := model.IdempotencyIdentity{TenantID: "tenant", ClientID: "client", IdempotencyKey: "key"}
	position := model.WALPosition{SegmentID: 1, Offset: 7, Sequence: 3}
	claimHash := bytes.Repeat([]byte{1}, 32)
	return model.IdempotencyDecision{
		SchemaVersion: model.SchemaIdempotencyDecision,
		Identity:      identity,
		ClaimHash:     claimHash,
		BatchID:       "batch-1",
		Record: model.ServerRecord{
			SchemaVersion:       model.SchemaServerRecord,
			RecordID:            "record-1",
			TenantID:            identity.TenantID,
			ClientID:            identity.ClientID,
			KeyID:               "client-key",
			ClaimHash:           claimHash,
			ClientSignatureHash: bytes.Repeat([]byte{2}, 32),
			ReceivedAtUnixN:     10,
			WAL:                 position,
		},
		Accepted: model.AcceptedReceipt{
			SchemaVersion:   model.SchemaAcceptedReceipt,
			RecordID:        "record-1",
			Status:          "accepted",
			ServerID:        "server-1",
			ReceivedAtUnixN: 10,
			WAL:             position,
			ServerSig: model.Signature{
				Alg:       model.DefaultSignatureAlg,
				KeyID:     "server-key",
				Signature: bytes.Repeat([]byte{3}, 64),
			},
		},
	}
}

func TestIdempotencyIndexRememberDurableCachesExactDecision(t *testing.T) {
	t.Parallel()
	decision := testDurableDecision()
	reader := &durableReaderStub{decision: decision, found: true}
	idx := NewIdempotencyIndex()
	build := func() (model.ServerRecord, model.AcceptedReceipt, error) {
		t.Fatal("build ran for a durable hit")
		return model.ServerRecord{}, model.AcceptedReceipt{}, nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		record, accepted, loaded, conflict, err := idx.RememberDurable(
			context.Background(),
			IdempotencyKey("tenant", "client", "key"),
			decision.Identity,
			decision.ClaimHash,
			reader,
			build,
		)
		if err != nil || !loaded || conflict || record.RecordID != decision.Record.RecordID || accepted.RecordID != decision.Accepted.RecordID {
			t.Fatalf("RememberDurable(attempt %d) = record=%+v accepted=%+v loaded=%v conflict=%v err=%v", attempt, record, accepted, loaded, conflict, err)
		}
	}
	if got := reader.calls.Load(); got != 1 {
		t.Fatalf("durable reads = %d, want 1", got)
	}
	if _, _, loaded, conflict, err := idx.RememberDurable(
		context.Background(),
		IdempotencyKey("tenant", "client", "key"),
		decision.Identity,
		bytes.Repeat([]byte{9}, 32),
		reader,
		build,
	); err != nil || loaded || !conflict {
		t.Fatalf("conflicting RememberDurable() loaded=%v conflict=%v err=%v", loaded, conflict, err)
	}
}

func TestIdempotencyIndexRememberDurableRecordUsesPointLookup(t *testing.T) {
	idx := NewIdempotencyIndex()
	claimHash := []byte{1, 2, 3}
	reader := &durableRecordReaderStub{bundle: model.ProofBundle{
		RecordID:        "record-1",
		ServerRecord:    model.ServerRecord{RecordID: "record-1", ClaimHash: claimHash},
		AcceptedReceipt: model.AcceptedReceipt{RecordID: "record-1"},
	}}
	builds := 0
	build := func() (model.ServerRecord, model.AcceptedReceipt, error) {
		builds++
		return model.ServerRecord{RecordID: "new"}, model.AcceptedReceipt{RecordID: "new"}, nil
	}

	record, accepted, loaded, conflict, err := idx.RememberDurableRecord(
		context.Background(), RecordIDKey("record-1"), "record-1", claimHash, reader, build,
	)
	if err != nil || !loaded || conflict || record.RecordID != "record-1" || accepted.RecordID != "record-1" {
		t.Fatalf("RememberDurableRecord() = record:%+v accepted:%+v loaded:%v conflict:%v err:%v", record, accepted, loaded, conflict, err)
	}
	if builds != 0 || reader.calls.Load() != 1 {
		t.Fatalf("cold lookup counts = builds:%d reads:%d", builds, reader.calls.Load())
	}
	_, _, loaded, conflict, err = idx.RememberDurableRecord(
		context.Background(), RecordIDKey("record-1"), "record-1", claimHash, reader, build,
	)
	if err != nil || !loaded || conflict || reader.calls.Load() != 1 {
		t.Fatalf("cached lookup = loaded:%v conflict:%v reads:%d err:%v", loaded, conflict, reader.calls.Load(), err)
	}
}

func TestIdempotencyIndexRememberDurableRecordBuildsOnNotFoundAndRejectsMismatch(t *testing.T) {
	notFound := &durableRecordReaderStub{err: trusterr.New(trusterr.CodeNotFound, "missing")}
	idx := NewIdempotencyIndex()
	record, _, loaded, conflict, err := idx.RememberDurableRecord(
		context.Background(), RecordIDKey("new"), "new", []byte{1}, notFound,
		func() (model.ServerRecord, model.AcceptedReceipt, error) {
			return model.ServerRecord{RecordID: "new"}, model.AcceptedReceipt{RecordID: "new"}, nil
		},
	)
	if err != nil || loaded || conflict || record.RecordID != "new" {
		t.Fatalf("not-found lookup = record:%+v loaded:%v conflict:%v err:%v", record, loaded, conflict, err)
	}

	mismatch := &durableRecordReaderStub{bundle: model.ProofBundle{
		RecordID:        "other",
		ServerRecord:    model.ServerRecord{RecordID: "other", ClaimHash: []byte{1}},
		AcceptedReceipt: model.AcceptedReceipt{RecordID: "other"},
	}}
	_, _, _, _, err = NewIdempotencyIndex().RememberDurableRecord(
		context.Background(), RecordIDKey("expected"), "expected", []byte{1}, mismatch,
		func() (model.ServerRecord, model.AcceptedReceipt, error) {
			return model.ServerRecord{}, model.AcceptedReceipt{}, nil
		},
	)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("mismatched durable record code = %s, err=%v", trusterr.CodeOf(err), err)
	}
}

func TestIdempotencyIndexConcurrentColdDurableHitReadsOnce(t *testing.T) {
	t.Parallel()
	decision := testDurableDecision()
	reader := &durableReaderStub{
		decision: decision,
		found:    true,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	idx := NewIdempotencyIndex()
	const concurrency = 16
	start := make(chan struct{})
	errs := make(chan error, concurrency)
	var wg sync.WaitGroup
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, loaded, conflict, err := idx.RememberDurable(
				context.Background(),
				IdempotencyKey("tenant", "client", "key"),
				decision.Identity,
				decision.ClaimHash,
				reader,
				func() (model.ServerRecord, model.AcceptedReceipt, error) {
					return model.ServerRecord{}, model.AcceptedReceipt{}, errors.New("unexpected build")
				},
			)
			if err == nil && (!loaded || conflict) {
				err = fmt.Errorf("loaded=%v conflict=%v", loaded, conflict)
			}
			errs <- err
		}()
	}
	close(start)
	<-reader.entered
	close(reader.release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent RememberDurable() error = %v", err)
		}
	}
	if got := reader.calls.Load(); got != 1 {
		t.Fatalf("durable reads = %d, want 1", got)
	}
}

func TestIdempotencyIndexDurableReadErrorAndEmptyKey(t *testing.T) {
	t.Parallel()
	decision := testDurableDecision()
	reader := &durableReaderStub{err: errors.New("unavailable")}
	idx := NewIdempotencyIndex()
	if _, _, _, _, err := idx.RememberDurable(
		context.Background(),
		IdempotencyKey("tenant", "client", "key"),
		decision.Identity,
		decision.ClaimHash,
		reader,
		func() (model.ServerRecord, model.AcceptedReceipt, error) {
			return model.ServerRecord{}, model.AcceptedReceipt{}, nil
		},
	); err == nil {
		t.Fatal("RememberDurable(read error) error = nil")
	}
	reader.err = nil
	built := 0
	if _, _, loaded, conflict, err := idx.RememberDurable(
		context.Background(), "", model.IdempotencyIdentity{}, nil, reader,
		func() (model.ServerRecord, model.AcceptedReceipt, error) {
			built++
			return model.ServerRecord{RecordID: "unkeyed"}, model.AcceptedReceipt{RecordID: "unkeyed"}, nil
		},
	); err != nil || loaded || conflict || built != 1 {
		t.Fatalf("empty-key RememberDurable() loaded=%v conflict=%v built=%d err=%v", loaded, conflict, built, err)
	}
	if got := reader.calls.Load(); got != 1 {
		t.Fatalf("empty key performed durable read: calls=%d", got)
	}
}

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
	if RecordIDKey("") != "" {
		t.Fatalf("RecordIDKey(empty) = %q", RecordIDKey(""))
	}
	if got := RecordIDKey("tr1record"); got == "" || got == IdempotencyKey("tenant", "client", "tr1record") {
		t.Fatalf("RecordIDKey() = %q, want non-empty disjoint key", got)
	}
}
