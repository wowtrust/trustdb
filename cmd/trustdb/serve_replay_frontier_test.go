package main

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/app"
	"github.com/wowtrust/trustdb/internal/batch"
	durableidempotency "github.com/wowtrust/trustdb/internal/idempotency"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
	pebblestore "github.com/wowtrust/trustdb/internal/proofstore/pebble"
	"github.com/wowtrust/trustdb/internal/receipt"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"github.com/wowtrust/trustdb/internal/wal"
)

type replayDecisionReader struct {
	decision model.IdempotencyDecision
	found    bool
}

func (r replayDecisionReader) GetIdempotencyDecision(context.Context, model.IdempotencyIdentity) (model.IdempotencyDecision, bool, error) {
	return r.decision, r.found, nil
}

func TestReplayDurableDecisionCrossChecksCommitState(t *testing.T) {
	env := newIdempotencyEnv(t)
	defer env.writer.Close()
	signed := env.signClaim(t, "replay-cross-check", []byte("payload"), 1)
	record, accepted, _, err := env.engine.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	item := app.ReplayedAccepted{Signed: signed, Record: record, Accepted: accepted}
	decision, err := durableidempotency.BuildDecision("batch-a", signed, record, accepted)
	if err != nil {
		t.Fatalf("BuildDecision() error = %v", err)
	}
	bundle := &model.ProofBundle{
		RecordID:        record.RecordID,
		SignedClaim:     signed,
		ServerRecord:    record,
		AcceptedReceipt: accepted,
	}

	tests := []struct {
		name      string
		reader    replayDecisionReader
		batchID   string
		committed bool
	}{
		{name: "missing committed decision", reader: replayDecisionReader{}, batchID: "batch-a", committed: true},
		{name: "decision on uncommitted wal", reader: replayDecisionReader{decision: decision, found: true}},
		{name: "conflicting committed batch", reader: replayDecisionReader{decision: func() model.IdempotencyDecision {
			conflict := decision
			conflict.BatchID = "batch-b"
			return conflict
		}(), found: true}, batchID: "batch-a", committed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine := env.engine
			engine.DurableIdempotency = test.reader
			var committedBundle *model.ProofBundle
			if test.committed {
				committedBundle = bundle
			}
			if err := validateDurableReplayDecision(context.Background(), engine, item, committedBundle, test.batchID, test.committed); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
				t.Fatalf("validateDurableReplayDecision() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
			}
		})
	}
}

func TestReplayDurableDecisionUsesPersistedReceiptAcrossServerKeyRotation(t *testing.T) {
	env := newIdempotencyEnv(t)
	defer env.writer.Close()
	signed := env.signClaim(t, "rotated-server-key", []byte("payload"), 1)
	record, accepted, _, err := env.engine.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	decision, err := durableidempotency.BuildDecision("batch-a", signed, record, accepted)
	if err != nil {
		t.Fatalf("BuildDecision() error = %v", err)
	}
	bundle := &model.ProofBundle{
		RecordID:        record.RecordID,
		SignedClaim:     signed,
		ServerRecord:    record,
		AcceptedReceipt: accepted,
	}
	_, rotatedPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(rotated server) error = %v", err)
	}
	rotatedAccepted, err := receipt.SignAccepted(accepted, "rotated-server-key", rotatedPrivate)
	if err != nil {
		t.Fatalf("SignAccepted(rotated server) error = %v", err)
	}
	engine := env.engine
	engine.DurableIdempotency = replayDecisionReader{decision: decision, found: true}
	item := app.ReplayedAccepted{Signed: signed, Record: record, Accepted: rotatedAccepted}
	if err := validateDurableReplayDecision(context.Background(), engine, item, bundle, "batch-a", true); err != nil {
		t.Fatalf("validateDurableReplayDecision() after server key rotation error = %v", err)
	}
}

func TestPebbleCheckpointedRestartUsesDurableIdempotencyWithoutWALAppend(t *testing.T) {
	env := newIdempotencyEnv(t)
	signed := env.signClaim(t, "durable-restart-key", []byte("original payload"), 1)
	wantRecord, wantAccepted, idempotent, err := env.engine.Submit(context.Background(), signed)
	if err != nil || idempotent {
		t.Fatalf("Submit(original) record=%+v accepted=%+v idempotent=%v err=%v", wantRecord, wantAccepted, idempotent, err)
	}

	storePath := filepath.Join(env.dir, "pebble")
	store, err := pebblestore.Open(storePath)
	if err != nil {
		t.Fatalf("pebble.Open() error = %v", err)
	}
	svc := batch.New(env.engine, store, batch.Options{QueueSize: 1, MaxRecords: 1, MaxDelay: time.Hour}, nil)
	if err := svc.Enqueue(context.Background(), signed, wantRecord, wantAccepted); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	waitForReplayProof(t, svc, wantRecord.RecordID)
	waitForDurableCheckpoint(t, store, wantRecord.WAL.Sequence)
	if err := svc.Shutdown(context.Background()); err != nil {
		t.Fatalf("batch Shutdown() error = %v", err)
	}
	env.closeWAL(t)
	if err := store.Close(); err != nil {
		t.Fatalf("pebble Close() error = %v", err)
	}

	reopenedWAL := env.reopen(t)
	defer reopenedWAL.Close()
	store, err = pebblestore.Open(storePath)
	if err != nil {
		t.Fatalf("pebble reopen error = %v", err)
	}
	defer store.Close()
	restarted := env.engine
	_, rotatedPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(rotated restart server) error = %v", err)
	}
	restarted.ServerKeyID = "rotated-server-key"
	restarted.ServerPrivateKey = rotatedPrivate
	restarted.WAL = reopenedWAL
	restarted.Idempotency = app.NewIdempotencyIndex()
	restarted.DurableIdempotency = store
	replaySvc := batch.New(restarted, store, batch.Options{QueueSize: 1, MaxRecords: 1, MaxDelay: time.Hour}, nil)
	defer replaySvc.Shutdown(context.Background())

	recovered, replayed, skipped, err := replayWALAccepted(context.Background(), env.walPath, restarted, replaySvc, store, nil)
	if err != nil {
		t.Fatalf("replayWALAccepted() error = %v", err)
	}
	if recovered != 0 || replayed != 0 || skipped != 1 || restarted.Idempotency.Size() != 0 {
		t.Fatalf("checkpoint replay recovered=%d replayed=%d skipped=%d idempotency=%d, want 0/0/1/0", recovered, replayed, skipped, restarted.Idempotency.Size())
	}

	gotRecord, gotAccepted, idempotent, err := restarted.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("Submit(identical restart retry) error = %v", err)
	}
	if !idempotent || !reflect.DeepEqual(gotRecord, wantRecord) || !reflect.DeepEqual(gotAccepted, wantAccepted) {
		t.Fatalf("durable retry record=%+v accepted=%+v idempotent=%v, want original response", gotRecord, gotAccepted, idempotent)
	}
	conflicting := env.signClaim(t, "durable-restart-key", []byte("different payload"), 2)
	if _, _, _, err := restarted.Submit(context.Background(), conflicting); trusterr.CodeOf(err) != trusterr.CodeAlreadyExists {
		t.Fatalf("Submit(conflicting restart retry) code=%s err=%v, want AlreadyExists", trusterr.CodeOf(err), err)
	}
	if got := walRecordCount(t, env.walPath); got != 1 {
		t.Fatalf("WAL records after durable restart retries = %d, want 1", got)
	}
}

func waitForDurableCheckpoint(t *testing.T, store interface {
	GetCheckpoint(context.Context) (model.WALCheckpoint, bool, error)
}, wantSequence uint64) model.WALCheckpoint {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		checkpoint, found, err := store.GetCheckpoint(context.Background())
		if err == nil && found && checkpoint.LastSequence >= wantSequence {
			return checkpoint
		}
		time.Sleep(5 * time.Millisecond)
	}
	checkpoint, found, err := store.GetCheckpoint(context.Background())
	t.Fatalf("GetCheckpoint() = %+v found=%v err=%v, want sequence %d", checkpoint, found, err, wantSequence)
	return model.WALCheckpoint{}
}

type replayCheckpointStore struct {
	proofstore.LocalStore

	mu       sync.Mutex
	puts     []model.WALCheckpoint
	failPuts int
}

func (*replayCheckpointStore) WALCheckpointPruneSafe() bool { return true }

type checkpointSafeLocalStore struct {
	proofstore.LocalStore
}

func (checkpointSafeLocalStore) WALCheckpointPruneSafe() bool { return true }

type checkpointUnsafeLocalStore struct {
	proofstore.LocalStore
}

func (checkpointUnsafeLocalStore) WALCheckpointPruneSafe() bool { return false }

type replayBundleCountingStore struct {
	proofstore.LocalStore
	getBundleCalls int
}

func (*replayBundleCountingStore) WALCheckpointPruneSafe() bool { return false }

func (s *replayBundleCountingStore) GetBundle(ctx context.Context, recordID string) (model.ProofBundle, error) {
	s.getBundleCalls++
	return s.LocalStore.GetBundle(ctx, recordID)
}

func (s *replayCheckpointStore) PutCheckpoint(ctx context.Context, cp model.WALCheckpoint) error {
	s.mu.Lock()
	if s.failPuts > 0 {
		s.failPuts--
		s.mu.Unlock()
		return trusterr.New(trusterr.CodeInternal, "injected checkpoint write failure")
	}
	s.mu.Unlock()
	if err := s.LocalStore.PutCheckpoint(ctx, cp); err != nil {
		return err
	}
	s.mu.Lock()
	s.puts = append(s.puts, cp)
	s.mu.Unlock()
	return nil
}

func (s *replayCheckpointStore) checkpoints() []model.WALCheckpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.WALCheckpoint(nil), s.puts...)
}

type blockingReplayBatchEngine struct {
	base    app.LocalEngine
	entered chan struct{}
	release chan struct{}
}

func (e blockingReplayBatchEngine) CommitBatch(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) ([]model.ProofBundle, error) {
	select {
	case e.entered <- struct{}{}:
	default:
	}
	<-e.release
	return e.base.CommitBatch(batchID, closedAt, signed, records, accepted)
}

func TestReplayFlushesCommittedCoverageOnceAfterScan(t *testing.T) {
	env := newRecoveryEnv(t, 3)
	env.writeBundles(t, len(env.bundles))
	env.writeRoot(t)
	env.writeCommittedManifest(t)

	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	restarted.Idempotency = app.NewIdempotencyIndex()
	store := &replayCheckpointStore{LocalStore: env.store}
	var hooks []model.WALCheckpoint
	svc := batch.New(restarted, store, batch.Options{
		QueueSize:  len(env.items),
		MaxRecords: len(env.items),
		MaxDelay:   time.Hour,
		OnCheckpointAdvanced: func(_ context.Context, cp model.WALCheckpoint) {
			if got := restarted.Idempotency.Size(); got != len(env.items) {
				t.Fatalf("checkpoint hook observed idempotency size %d, want %d after full scan", got, len(env.items))
			}
			hooks = append(hooks, cp)
		},
	}, nil)
	defer svc.Shutdown(context.Background())

	recovered, replayed, skipped, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, nil)
	if err != nil {
		t.Fatalf("replayWALAccepted() error = %v", err)
	}
	if recovered != 0 || replayed != 0 || skipped != len(env.items) {
		t.Fatalf("replayWALAccepted() recovered=%d replayed=%d skipped=%d", recovered, replayed, skipped)
	}
	want := env.items[len(env.items)-1].Record.WAL
	puts := store.checkpoints()
	if len(puts) != 1 || puts[0].LastSequence != want.Sequence {
		t.Fatalf("checkpoint puts = %+v, want one flush at sequence %d", puts, want.Sequence)
	}
	if len(hooks) != 1 || hooks[0].LastSequence != want.Sequence {
		t.Fatalf("checkpoint hooks = %+v, want one callback at sequence %d", hooks, want.Sequence)
	}
}

func TestReplayCheckpointStopsBeforeUncommittedGap(t *testing.T) {
	env := newRecoveryEnv(t, 3)
	writeCommittedRecoverySubset(t, env, "batch-sparse-committed", 0, 2)

	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	restarted.Idempotency = app.NewIdempotencyIndex()
	entered := make(chan struct{}, 1)
	release := make(chan struct{}, 1)
	engine := blockingReplayBatchEngine{base: restarted, entered: entered, release: release}
	store := checkpointSafeLocalStore{LocalStore: env.store}
	svc := batch.New(engine, store, batch.Options{
		QueueSize:  len(env.items),
		MaxRecords: 1,
		MaxDelay:   time.Hour,
	}, nil)
	defer func() {
		select {
		case release <- struct{}{}:
		default:
		}
		_ = svc.Shutdown(context.Background())
	}()

	recovered, replayed, skipped, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, nil)
	if err != nil {
		t.Fatalf("replayWALAccepted() error = %v", err)
	}
	if recovered != 0 || replayed != 1 || skipped != 2 {
		t.Fatalf("replayWALAccepted() recovered=%d replayed=%d skipped=%d, want 0/1/2", recovered, replayed, skipped)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("replayed gap record did not reach the blocked batch engine")
	}
	cp, found, err := env.store.GetCheckpoint(context.Background())
	if err != nil || !found || cp.LastSequence != 1 {
		t.Fatalf("checkpoint while sequence 2 is blocked = %+v found=%v err=%v, want sequence 1", cp, found, err)
	}

	release <- struct{}{}
	wantEnd := env.items[2].Record.WAL
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cp, found, err = env.store.GetCheckpoint(context.Background())
		if err == nil && found && cp.LastSequence == wantEnd.Sequence {
			break
		}
		if err == nil && found && cp.LastSequence > wantEnd.Sequence {
			t.Fatalf("checkpoint leapt past expected frontier: %+v", cp)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil || !found || cp.LastSequence != wantEnd.Sequence {
		t.Fatalf("checkpoint after closing gap = %+v found=%v err=%v", cp, found, err)
	}
	if cp.SegmentID != wantEnd.SegmentID || cp.LastOffset != wantEnd.Offset || cp.BatchID != "batch-sparse-committed" {
		t.Fatalf("checkpoint endpoint metadata = %+v, want WAL=%+v batch=batch-sparse-committed", cp, wantEnd)
	}
}

func TestReplayDoesNotTreatOrphanRecordIndexAsCommitted(t *testing.T) {
	env := newRecoveryEnv(t, 1)
	idx := model.RecordIndexFromBundle(env.bundles[0])
	idx.BatchID = "missing-committed-manifest"
	if err := env.store.PutRecordIndex(context.Background(), idx); err != nil {
		t.Fatalf("PutRecordIndex() error = %v", err)
	}

	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	svc := batch.New(restarted, env.store, batch.Options{QueueSize: 1, MaxRecords: 1, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())

	_, _, _, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, env.store, nil)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("replayWALAccepted() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
	if _, found, getErr := env.store.GetCheckpoint(context.Background()); getErr != nil || found {
		t.Fatalf("GetCheckpoint() found=%v err=%v after orphan index", found, getErr)
	}
}

func TestReplayMigratesLegacyCheckpointFromCompleteWAL(t *testing.T) {
	env := newRecoveryEnv(t, 3)
	env.writeBundles(t, len(env.bundles))
	env.writeRoot(t)
	env.writeCommittedManifest(t)
	top := env.items[len(env.items)-1].Record.WAL
	if err := env.store.PutCheckpoint(context.Background(), model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpoint,
		SegmentID:     top.SegmentID,
		LastSequence:  top.Sequence,
		LastOffset:    top.Offset,
		BatchID:       env.batchID,
	}); err != nil {
		t.Fatalf("PutCheckpoint(legacy) error = %v", err)
	}

	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	restarted.Idempotency = app.NewIdempotencyIndex()
	store := &replayCheckpointStore{LocalStore: env.store}
	svc := batch.New(restarted, store, batch.Options{QueueSize: 3, MaxRecords: 3, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())

	recovered, replayed, skipped, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, nil)
	if err != nil {
		t.Fatalf("replayWALAccepted() error = %v", err)
	}
	if recovered != 0 || replayed != 0 || skipped != 3 {
		t.Fatalf("replayWALAccepted() recovered=%d replayed=%d skipped=%d, want 0/0/3", recovered, replayed, skipped)
	}
	if got := restarted.Idempotency.Size(); got != 3 {
		t.Fatalf("legacy replay idempotency size = %d, want 3 (full WAL was decoded)", got)
	}
	puts := store.checkpoints()
	if len(puts) != 1 || puts[0].SchemaVersion != model.SchemaWALCheckpointContiguous || puts[0].LastSequence != 3 {
		t.Fatalf("legacy migration puts = %+v, want one v2 sequence-3 checkpoint", puts)
	}
}

func TestReplayRejectsLegacyCheckpointBeyondWALTail(t *testing.T) {
	env := newRecoveryEnv(t, 3)
	env.writeBundles(t, len(env.bundles))
	env.writeRoot(t)
	env.writeCommittedManifest(t)
	if err := env.store.PutCheckpoint(context.Background(), model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpoint,
		SegmentID:     1,
		LastSequence:  10,
		LastOffset:    10_000,
	}); err != nil {
		t.Fatalf("PutCheckpoint(legacy) error = %v", err)
	}
	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	restarted.Idempotency = app.NewIdempotencyIndex()
	store := &replayCheckpointStore{LocalStore: env.store}
	svc := batch.New(restarted, store, batch.Options{QueueSize: 3, MaxRecords: 3, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())

	_, _, _, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, nil)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("replayWALAccepted() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
	if puts := store.checkpoints(); len(puts) != 0 {
		t.Fatalf("checkpoint writes after missing tail = %+v, want none", puts)
	}
	if restarted.Idempotency.Size() != 0 {
		t.Fatalf("legacy tail preflight replayed %d records before failing", restarted.Idempotency.Size())
	}
	cp, found, getErr := env.store.GetCheckpoint(context.Background())
	if getErr != nil || !found || cp.SchemaVersion != model.SchemaWALCheckpoint || cp.LastSequence != 10 {
		t.Fatalf("legacy checkpoint changed after failed validation: %+v found=%v err=%v", cp, found, getErr)
	}
}

func TestReplayFailsWhenLegacyCheckpointMigrationCannotPersist(t *testing.T) {
	env := newRecoveryEnv(t, 1)
	env.writeBundles(t, 1)
	env.writeRoot(t)
	env.writeCommittedManifest(t)
	pos := env.items[0].Record.WAL
	if err := env.store.PutCheckpoint(context.Background(), model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpoint,
		SegmentID:     pos.SegmentID,
		LastSequence:  pos.Sequence,
		LastOffset:    pos.Offset,
		BatchID:       env.batchID,
	}); err != nil {
		t.Fatalf("PutCheckpoint(legacy) error = %v", err)
	}
	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	store := &replayCheckpointStore{LocalStore: env.store, failPuts: 1}
	svc := batch.New(restarted, store, batch.Options{QueueSize: 1, MaxRecords: 1, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())

	_, _, _, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, nil)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("replayWALAccepted() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
	cp, found, getErr := env.store.GetCheckpoint(context.Background())
	if getErr != nil || !found || cp.SchemaVersion != model.SchemaWALCheckpoint {
		t.Fatalf("legacy checkpoint after failed migration = %+v found=%v err=%v", cp, found, getErr)
	}
}

func TestReplayRejectsLegacyCheckpointWithPrunedPrefix(t *testing.T) {
	walDir := filepath.Join(t.TempDir(), "wal")
	writer, err := wal.OpenDirWriter(walDir, wal.Options{MaxSegmentBytes: 128})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	var positions []model.WALPosition
	for i := 0; i < 5; i++ {
		pos, _, appendErr := writer.Append(context.Background(), make([]byte, 256))
		if appendErr != nil {
			t.Fatalf("Append(%d) error = %v", i, appendErr)
		}
		positions = append(positions, pos)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	cutoff := positions[2].SegmentID
	if removed, _, err := wal.PruneSegmentsBefore(walDir, cutoff); err != nil || removed == 0 {
		t.Fatalf("PruneSegmentsBefore(%d) removed=%d err=%v", cutoff, removed, err)
	}

	local := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "proofs")}
	if err := local.PutCheckpoint(context.Background(), model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpoint,
		SegmentID:     positions[len(positions)-1].SegmentID,
		LastSequence:  positions[len(positions)-1].Sequence,
		LastOffset:    positions[len(positions)-1].Offset,
	}); err != nil {
		t.Fatalf("PutCheckpoint(legacy) error = %v", err)
	}
	store := &replayCheckpointStore{LocalStore: local}
	svc := batch.New(app.LocalEngine{}, store, batch.Options{QueueSize: 1, MaxRecords: 1, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())

	_, _, _, err = replayWALAccepted(context.Background(), walDir, app.LocalEngine{}, svc, store, nil)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("replayWALAccepted() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
	if puts := store.checkpoints(); len(puts) != 0 {
		t.Fatalf("checkpoint writes after missing prefix = %+v, want none", puts)
	}

	unsafeLocal := checkpointUnsafeLocalStore{LocalStore: proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "unsafe-proofs")}}
	if err := unsafeLocal.PutCheckpoint(context.Background(), model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpoint,
		SegmentID:     positions[len(positions)-1].SegmentID,
		LastSequence:  positions[len(positions)-1].Sequence,
		LastOffset:    positions[len(positions)-1].Offset,
	}); err != nil {
		t.Fatalf("PutCheckpoint(unsafe legacy) error = %v", err)
	}
	unsafeSvc := batch.New(app.LocalEngine{}, unsafeLocal, batch.Options{}, nil)
	defer unsafeSvc.Shutdown(context.Background())
	_, _, _, err = replayWALAccepted(context.Background(), walDir, app.LocalEngine{}, unsafeSvc, unsafeLocal, nil)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("unsafe-store replay code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
}

func TestReplayLegacyEmptyWALMigrationSafety(t *testing.T) {
	t.Run("nonzero fails closed", func(t *testing.T) {
		local := proofstore.LocalStore{Root: t.TempDir()}
		if err := local.PutCheckpoint(context.Background(), model.WALCheckpoint{SchemaVersion: model.SchemaWALCheckpoint, LastSequence: 4}); err != nil {
			t.Fatalf("PutCheckpoint() error = %v", err)
		}
		store := &replayCheckpointStore{LocalStore: local}
		svc := batch.New(app.LocalEngine{}, store, batch.Options{}, nil)
		defer svc.Shutdown(context.Background())
		_, _, _, err := replayWALAccepted(context.Background(), filepath.Join(t.TempDir(), "missing.wal"), app.LocalEngine{}, svc, store, nil)
		if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
			t.Fatalf("replayWALAccepted() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
		}
		if puts := store.checkpoints(); len(puts) != 0 {
			t.Fatalf("nonzero empty migration writes = %+v, want none", puts)
		}
	})

	t.Run("zero migrates without pruning", func(t *testing.T) {
		local := proofstore.LocalStore{Root: t.TempDir()}
		if err := local.PutCheckpoint(context.Background(), model.WALCheckpoint{SchemaVersion: model.SchemaWALCheckpoint}); err != nil {
			t.Fatalf("PutCheckpoint() error = %v", err)
		}
		store := &replayCheckpointStore{LocalStore: local}
		var hooks int
		svc := batch.New(app.LocalEngine{}, store, batch.Options{OnCheckpointAdvanced: func(context.Context, model.WALCheckpoint) { hooks++ }}, nil)
		defer svc.Shutdown(context.Background())
		if _, _, _, err := replayWALAccepted(context.Background(), filepath.Join(t.TempDir(), "missing.wal"), app.LocalEngine{}, svc, store, nil); err != nil {
			t.Fatalf("replayWALAccepted() error = %v", err)
		}
		puts := store.checkpoints()
		if len(puts) != 1 || puts[0].SchemaVersion != model.SchemaWALCheckpointContiguous || puts[0].LastSequence != 0 {
			t.Fatalf("zero empty migration writes = %+v, want one v2 zero", puts)
		}
		if hooks != 0 {
			t.Fatalf("zero migration hooks = %d, want 0", hooks)
		}
	})
}

func TestReplayIgnoresCheckpointFromUnsafeFileStore(t *testing.T) {
	env := newRecoveryEnv(t, 2)
	env.writeBundles(t, len(env.bundles))
	env.writeRoot(t)
	env.writeCommittedManifest(t)
	top := env.items[len(env.items)-1].Record.WAL
	if err := env.store.PutCheckpoint(context.Background(), model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpointContiguous,
		SegmentID:     top.SegmentID,
		LastSequence:  top.Sequence,
		LastOffset:    top.Offset,
	}); err != nil {
		t.Fatalf("PutCheckpoint(v2) error = %v", err)
	}
	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	restarted.Idempotency = app.NewIdempotencyIndex()
	unsafeStore := checkpointUnsafeLocalStore{LocalStore: env.store}
	svc := batch.New(restarted, unsafeStore, batch.Options{QueueSize: 2, MaxRecords: 2, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())

	_, replayed, skipped, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, unsafeStore, nil)
	if err != nil {
		t.Fatalf("replayWALAccepted() error = %v", err)
	}
	if replayed != 0 || skipped != 2 || restarted.Idempotency.Size() != 2 {
		t.Fatalf("unsafe-store replay replayed=%d skipped=%d idempotency=%d, want 0/2/2", replayed, skipped, restarted.Idempotency.Size())
	}
}

func TestReplayUnsafeSharedStoreAcceptsCommittedProofFromAnotherNodeWAL(t *testing.T) {
	env := newRecoveryEnv(t, 1)
	remoteRecord := env.items[0].Record
	remoteRecord.WAL = model.WALPosition{SegmentID: 9, Offset: 900, Sequence: 77}
	remoteAccepted := env.items[0].Accepted
	remoteAccepted.WAL = remoteRecord.WAL
	const remoteBatchID = "batch-remote-node"
	remoteBundles, err := env.engine.CommitBatch(
		remoteBatchID,
		env.closedAt,
		[]model.SignedClaim{env.items[0].Signed},
		[]model.ServerRecord{remoteRecord},
		[]model.AcceptedReceipt{remoteAccepted},
	)
	if err != nil {
		t.Fatalf("CommitBatch(remote) error = %v", err)
	}
	store := &replayBundleCountingStore{LocalStore: env.store}
	if err := store.PutBundle(context.Background(), remoteBundles[0]); err != nil {
		t.Fatalf("PutBundle(remote) error = %v", err)
	}
	if err := store.PutRoot(context.Background(), model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       remoteBatchID,
		BatchRoot:     remoteBundles[0].CommittedReceipt.BatchRoot,
		TreeSize:      1,
		ClosedAtUnixN: remoteBundles[0].CommittedReceipt.ClosedAtUnixN,
	}); err != nil {
		t.Fatalf("PutRoot(remote) error = %v", err)
	}
	if err := store.PutManifest(context.Background(), model.BatchManifest{
		SchemaVersion:    model.SchemaBatchManifest,
		BatchID:          remoteBatchID,
		State:            model.BatchStateCommitted,
		TreeAlg:          model.DefaultMerkleTreeAlg,
		TreeSize:         1,
		BatchRoot:        remoteBundles[0].CommittedReceipt.BatchRoot,
		RecordIDs:        []string{remoteRecord.RecordID},
		WALRange:         model.WALRange{From: remoteRecord.WAL, To: remoteRecord.WAL},
		ClosedAtUnixN:    env.closedAt.UnixNano(),
		CommittedAtUnixN: env.closedAt.Add(time.Nanosecond).UnixNano(),
	}); err != nil {
		t.Fatalf("PutManifest(remote) error = %v", err)
	}

	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	restarted.Idempotency = app.NewIdempotencyIndex()
	svc := batch.New(restarted, store, batch.Options{QueueSize: 1, MaxRecords: 1, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())

	recovered, replayed, skipped, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, nil)
	if err != nil {
		t.Fatalf("replayWALAccepted() error = %v", err)
	}
	if recovered != 0 || replayed != 0 || skipped != 1 {
		t.Fatalf("replayWALAccepted() recovered=%d replayed=%d skipped=%d, want 0/0/1", recovered, replayed, skipped)
	}
	if store.getBundleCalls != 0 {
		t.Fatalf("unsafe shared-store replay GetBundle calls = %d, want 0", store.getBundleCalls)
	}
}

func TestReplayRejectsZeroTrustedCheckpointWithPrunedPrefix(t *testing.T) {
	walDir := filepath.Join(t.TempDir(), "wal")
	writer, err := wal.OpenDirWriter(walDir, wal.Options{MaxSegmentBytes: 128})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	var positions []model.WALPosition
	for i := 0; i < 4; i++ {
		pos, _, appendErr := writer.Append(context.Background(), make([]byte, 256))
		if appendErr != nil {
			t.Fatalf("Append(%d) error = %v", i, appendErr)
		}
		positions = append(positions, pos)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if removed, _, err := wal.PruneSegmentsBefore(walDir, positions[2].SegmentID); err != nil || removed == 0 {
		t.Fatalf("PruneSegmentsBefore(%d) removed=%d err=%v", positions[2].SegmentID, removed, err)
	}

	local := proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "proofs")}
	if err := local.PutCheckpoint(context.Background(), model.WALCheckpoint{SchemaVersion: model.SchemaWALCheckpointContiguous}); err != nil {
		t.Fatalf("PutCheckpoint(v2 zero) error = %v", err)
	}
	store := checkpointSafeLocalStore{LocalStore: local}
	svc := batch.New(app.LocalEngine{}, store, batch.Options{}, nil)
	defer svc.Shutdown(context.Background())
	_, _, _, err = replayWALAccepted(context.Background(), walDir, app.LocalEngine{}, svc, store, nil)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("replayWALAccepted() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
	cp, found, getErr := local.GetCheckpoint(context.Background())
	if getErr != nil || !found || cp.SchemaVersion != model.SchemaWALCheckpointContiguous || cp.LastSequence != 0 {
		t.Fatalf("zero checkpoint changed after missing-prefix failure: %+v found=%v err=%v", cp, found, getErr)
	}
}

func TestReplayRejectsCorruptTrustedCheckpointProof(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.ProofBundle)
	}{
		{
			name: "signed claim idempotency key",
			mutate: func(bundle *model.ProofBundle) {
				bundle.SignedClaim.Claim.IdempotencyKey = "tampered-idempotency-key"
			},
		},
		{
			name: "server record claim hash",
			mutate: func(bundle *model.ProofBundle) {
				bundle.ServerRecord.ClaimHash = append([]byte(nil), bundle.ServerRecord.ClaimHash...)
				bundle.ServerRecord.ClaimHash[0] ^= 0xff
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := newRecoveryEnv(t, 1)
			corrupt := env.bundles[0]
			test.mutate(&corrupt)
			if err := env.store.PutBundle(context.Background(), corrupt); err != nil {
				t.Fatalf("PutBundle(corrupt) error = %v", err)
			}
			env.writeRoot(t)
			env.writeCommittedManifest(t)
			pos := env.items[0].Record.WAL
			if err := env.store.PutCheckpoint(context.Background(), model.WALCheckpoint{
				SchemaVersion: model.SchemaWALCheckpointContiguous,
				SegmentID:     pos.SegmentID,
				LastSequence:  pos.Sequence,
				LastOffset:    pos.Offset,
				BatchID:       env.batchID,
			}); err != nil {
				t.Fatalf("PutCheckpoint(v2) error = %v", err)
			}
			before, err := wal.Inspect(env.walPath)
			if err != nil {
				t.Fatalf("Inspect(before) error = %v", err)
			}

			restarted, reopened := env.restartedEngine(t)
			defer reopened.Close()
			restarted.Idempotency = app.NewIdempotencyIndex()
			store := checkpointSafeLocalStore{LocalStore: env.store}
			svc := batch.New(restarted, store, batch.Options{QueueSize: 1, MaxRecords: 1, MaxDelay: time.Hour}, nil)
			defer svc.Shutdown(context.Background())
			_, _, _, err = replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, nil)
			if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
				t.Fatalf("replayWALAccepted() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
			}
			after, inspectErr := wal.Inspect(env.walPath)
			if inspectErr != nil {
				t.Fatalf("Inspect(after) error = %v", inspectErr)
			}
			if after.LastSequence != before.LastSequence {
				t.Fatalf("WAL last sequence after failed replay = %d, want %d", after.LastSequence, before.LastSequence)
			}
		})
	}
}

func TestReplayRejectsCorruptClaimBeforeFirstSafeCheckpoint(t *testing.T) {
	env := newRecoveryEnv(t, 1)
	corrupt := env.bundles[0]
	corrupt.SignedClaim.Claim.IdempotencyKey = "tampered-before-checkpoint"
	if err := env.store.PutBundle(context.Background(), corrupt); err != nil {
		t.Fatalf("PutBundle(corrupt) error = %v", err)
	}
	env.writeRoot(t)
	env.writeCommittedManifest(t)

	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	store := checkpointSafeLocalStore{LocalStore: env.store}
	var hooks int
	svc := batch.New(restarted, store, batch.Options{
		QueueSize:  1,
		MaxRecords: 1,
		MaxDelay:   time.Hour,
		OnCheckpointAdvanced: func(context.Context, model.WALCheckpoint) {
			hooks++
		},
	}, nil)
	defer svc.Shutdown(context.Background())

	_, _, _, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, nil)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("replayWALAccepted() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
	if cp, found, getErr := env.store.GetCheckpoint(context.Background()); getErr != nil || found {
		t.Fatalf("checkpoint after corrupt full replay = %+v found=%v err=%v, want none", cp, found, getErr)
	}
	if hooks != 0 {
		t.Fatalf("checkpoint hooks after corrupt full replay = %d, want 0", hooks)
	}
}

func TestReplayRejectsTrustedCheckpointAgainstReplacedWAL(t *testing.T) {
	original := newRecoveryEnv(t, 1)
	original.writeBundles(t, 1)
	original.writeRoot(t)
	original.writeCommittedManifest(t)
	pos := original.items[0].Record.WAL
	if err := original.store.PutCheckpoint(context.Background(), model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpointContiguous,
		SegmentID:     pos.SegmentID,
		LastSequence:  pos.Sequence,
		LastOffset:    pos.Offset,
		BatchID:       original.batchID,
	}); err != nil {
		t.Fatalf("PutCheckpoint(v2) error = %v", err)
	}

	replacement := newRecoveryEnv(t, 1)
	restarted, reopened := replacement.restartedEngine(t)
	defer reopened.Close()
	store := checkpointSafeLocalStore{LocalStore: original.store}
	svc := batch.New(restarted, store, batch.Options{QueueSize: 1, MaxRecords: 1, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())
	_, _, _, err := replayWALAccepted(context.Background(), replacement.walPath, restarted, svc, store, nil)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("replayWALAccepted() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
}

func TestReplayRejectsTrustedNonzeroCheckpointWithEmptyWAL(t *testing.T) {
	local := proofstore.LocalStore{Root: t.TempDir()}
	if err := local.PutCheckpoint(context.Background(), model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpointContiguous,
		SegmentID:     1,
		LastSequence:  1,
		LastOffset:    0,
		BatchID:       "missing-boundary",
	}); err != nil {
		t.Fatalf("PutCheckpoint(v2) error = %v", err)
	}
	store := checkpointSafeLocalStore{LocalStore: local}
	svc := batch.New(app.LocalEngine{}, store, batch.Options{}, nil)
	defer svc.Shutdown(context.Background())
	_, _, _, err := replayWALAccepted(context.Background(), filepath.Join(t.TempDir(), "missing.wal"), app.LocalEngine{}, svc, store, nil)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("replayWALAccepted() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
}

func TestReplayRejectsWrongCommittedManifestMember(t *testing.T) {
	env := newRecoveryEnv(t, 1)
	env.writeBundles(t, 1)
	committed := env.manifest
	committed.State = model.BatchStateCommitted
	committed.RecordIDs[0] = "different-record"
	if err := env.store.PutManifest(context.Background(), committed); err != nil {
		t.Fatalf("PutManifest(corrupt) error = %v", err)
	}
	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	store := checkpointSafeLocalStore{LocalStore: env.store}
	svc := batch.New(restarted, store, batch.Options{QueueSize: 1, MaxRecords: 1, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())

	_, _, _, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, nil)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("replayWALAccepted() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
}

func TestReplayRejectsCommittedManifestWithWrongRoot(t *testing.T) {
	env := newRecoveryEnv(t, 1)
	env.writeBundles(t, 1)
	env.writeRoot(t)
	committed := env.manifest
	committed.State = model.BatchStateCommitted
	committed.BatchRoot = append([]byte(nil), committed.BatchRoot...)
	committed.BatchRoot[0] ^= 0xff
	if err := env.store.PutManifest(context.Background(), committed); err != nil {
		t.Fatalf("PutManifest(corrupt root) error = %v", err)
	}
	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	store := checkpointSafeLocalStore{LocalStore: env.store}
	var hooks int
	svc := batch.New(restarted, store, batch.Options{
		QueueSize:  1,
		MaxRecords: 1,
		MaxDelay:   time.Hour,
		OnCheckpointAdvanced: func(context.Context, model.WALCheckpoint) {
			hooks++
		},
	}, nil)
	defer svc.Shutdown(context.Background())

	_, _, _, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, nil)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("replayWALAccepted() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
	if cp, found, getErr := env.store.GetCheckpoint(context.Background()); getErr != nil || found {
		t.Fatalf("checkpoint after corrupt manifest root = %+v found=%v err=%v, want none", cp, found, getErr)
	}
	if hooks != 0 {
		t.Fatalf("checkpoint hooks after corrupt manifest root = %d, want 0", hooks)
	}
}

func TestReplayRejectsCommittedBundleWithWrongAuditPath(t *testing.T) {
	env := newRecoveryEnv(t, 2)
	corrupt := env.bundles[0]
	if len(corrupt.BatchProof.AuditPath) == 0 || len(corrupt.BatchProof.AuditPath[0]) == 0 {
		t.Fatal("two-record fixture has no audit path")
	}
	corrupt.BatchProof.AuditPath[0] = append([]byte(nil), corrupt.BatchProof.AuditPath[0]...)
	corrupt.BatchProof.AuditPath[0][0] ^= 0xff
	if err := env.store.PutBundle(context.Background(), corrupt); err != nil {
		t.Fatalf("PutBundle(corrupt audit path) error = %v", err)
	}
	if err := env.store.PutBundle(context.Background(), env.bundles[1]); err != nil {
		t.Fatalf("PutBundle(second) error = %v", err)
	}
	env.writeRoot(t)
	env.writeCommittedManifest(t)
	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	store := checkpointSafeLocalStore{LocalStore: env.store}
	var hooks int
	svc := batch.New(restarted, store, batch.Options{
		QueueSize:  2,
		MaxRecords: 2,
		MaxDelay:   time.Hour,
		OnCheckpointAdvanced: func(context.Context, model.WALCheckpoint) {
			hooks++
		},
	}, nil)
	defer svc.Shutdown(context.Background())

	_, _, _, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, nil)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("replayWALAccepted() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
	if cp, found, getErr := env.store.GetCheckpoint(context.Background()); getErr != nil || found {
		t.Fatalf("checkpoint after corrupt audit path = %+v found=%v err=%v, want none", cp, found, getErr)
	}
	if hooks != 0 {
		t.Fatalf("checkpoint hooks after corrupt audit path = %d, want 0", hooks)
	}
}

func TestReplayRejectsCommittedBundleWithWrongWAL(t *testing.T) {
	env := newRecoveryEnv(t, 1)
	corrupt := env.bundles[0]
	corrupt.ServerRecord.WAL.Offset++
	if err := env.store.PutBundle(context.Background(), corrupt); err != nil {
		t.Fatalf("PutBundle(corrupt) error = %v", err)
	}
	env.writeCommittedManifest(t)
	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	store := checkpointSafeLocalStore{LocalStore: env.store}
	svc := batch.New(restarted, store, batch.Options{QueueSize: 1, MaxRecords: 1, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())

	_, _, _, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, nil)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("replayWALAccepted() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
}

func TestReplayRejectsDuplicateRecordIDAtDifferentWALPosition(t *testing.T) {
	env := newRecoveryEnv(t, 1)
	env.writeBundles(t, 1)
	env.writeRoot(t)
	env.writeCommittedManifest(t)
	writer, err := wal.OpenWriter(env.walPath, 1)
	if err != nil {
		t.Fatalf("OpenWriter() error = %v", err)
	}
	duplicateEngine := env.engine
	duplicateEngine.WAL = writer
	duplicateEngine.Idempotency = nil
	duplicate, _, _, err := duplicateEngine.Submit(context.Background(), env.items[0].Signed)
	if err != nil {
		t.Fatalf("duplicate Submit() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if duplicate.RecordID != env.items[0].Record.RecordID || duplicate.WAL.Sequence != 2 {
		t.Fatalf("duplicate record = %+v, want same id at sequence 2", duplicate)
	}

	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	store := &replayCheckpointStore{LocalStore: env.store}
	svc := batch.New(restarted, store, batch.Options{QueueSize: 2, MaxRecords: 2, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())
	_, _, _, err = replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, nil)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("replayWALAccepted() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
	if puts := store.checkpoints(); len(puts) != 0 {
		t.Fatalf("duplicate-position checkpoint writes = %+v, want none", puts)
	}
}

func writeCommittedRecoverySubset(t *testing.T, env *recoveryEnv, batchID string, indexes ...int) {
	t.Helper()
	signed := make([]model.SignedClaim, 0, len(indexes))
	records := make([]model.ServerRecord, 0, len(indexes))
	accepted := make([]model.AcceptedReceipt, 0, len(indexes))
	recordIDs := make([]string, 0, len(indexes))
	for _, index := range indexes {
		item := env.items[index]
		signed = append(signed, item.Signed)
		records = append(records, item.Record)
		accepted = append(accepted, item.Accepted)
		recordIDs = append(recordIDs, item.Record.RecordID)
	}
	bundles, err := env.engine.CommitBatch(batchID, env.closedAt, signed, records, accepted)
	if err != nil {
		t.Fatalf("CommitBatch(%q) error = %v", batchID, err)
	}
	for i := range bundles {
		if err := env.store.PutBundle(context.Background(), bundles[i]); err != nil {
			t.Fatalf("PutBundle(%q, %d) error = %v", batchID, i, err)
		}
	}
	root := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       batchID,
		BatchRoot:     bundles[0].CommittedReceipt.BatchRoot,
		TreeSize:      uint64(len(bundles)),
		ClosedAtUnixN: bundles[0].CommittedReceipt.ClosedAtUnixN,
	}
	if err := env.store.PutRoot(context.Background(), root); err != nil {
		t.Fatalf("PutRoot(%q) error = %v", batchID, err)
	}
	manifest := model.BatchManifest{
		SchemaVersion:    model.SchemaBatchManifest,
		BatchID:          batchID,
		State:            model.BatchStateCommitted,
		TreeAlg:          model.DefaultMerkleTreeAlg,
		TreeSize:         uint64(len(bundles)),
		BatchRoot:        bundles[0].CommittedReceipt.BatchRoot,
		RecordIDs:        recordIDs,
		WALRange:         model.WALRange{From: records[0].WAL, To: records[len(records)-1].WAL},
		ClosedAtUnixN:    env.closedAt.UnixNano(),
		CommittedAtUnixN: env.closedAt.Add(time.Nanosecond).UnixNano(),
	}
	if err := env.store.PutManifest(context.Background(), manifest); err != nil {
		t.Fatalf("PutManifest(%q) error = %v", batchID, err)
	}
}
