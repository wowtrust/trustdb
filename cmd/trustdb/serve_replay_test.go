package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/wowtrust/trustdb/internal/app"
	"github.com/wowtrust/trustdb/internal/batch"
	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"github.com/wowtrust/trustdb/internal/wal"
)

func TestReplayWALAcceptedRestoresUnbatchedRecord(t *testing.T) {
	t.Parallel()

	clientPub, clientPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate client key error = %v", err)
	}
	_, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate server key error = %v", err)
	}
	raw := []byte("wal replay payload")
	contentHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, raw)
	if err != nil {
		t.Fatalf("HashBytes() error = %v", err)
	}
	c, err := claim.NewFileClaim(
		"tenant-replay",
		"client-replay",
		"client-key",
		time.Unix(100, 0),
		bytes.Repeat([]byte{1}, 16),
		"idem-replay",
		model.Content{HashAlg: model.DefaultHashAlg, ContentHash: contentHash, ContentLength: int64(len(raw))},
		model.Metadata{EventType: "file.snapshot"},
	)
	if err != nil {
		t.Fatalf("NewFileClaim() error = %v", err)
	}
	signed, err := claim.Sign(c, clientPriv)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	dir := t.TempDir()
	walPath := filepath.Join(dir, "trustdb.wal")
	writer, err := wal.OpenWriter(walPath, 1)
	if err != nil {
		t.Fatalf("OpenWriter() error = %v", err)
	}
	engine := app.LocalEngine{
		ServerID:         "server-replay",
		ServerKeyID:      "server-key",
		ClientPublicKey:  clientPub,
		ServerPrivateKey: serverPriv,
		WAL:              writer,
		Now:              func() time.Time { return time.Unix(200, 123) },
	}
	wantRecord, wantAccepted, _, err := engine.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := wal.OpenWriter(walPath, 1)
	if err != nil {
		t.Fatalf("reopen WAL error = %v", err)
	}
	defer reopened.Close()
	restartedEngine := app.LocalEngine{
		ServerID:         "server-replay",
		ServerKeyID:      "server-key",
		ClientPublicKey:  clientPub,
		ServerPrivateKey: serverPriv,
		WAL:              reopened,
		Now:              func() time.Time { return time.Unix(300, 0) },
	}
	store := proofstore.LocalStore{Root: filepath.Join(dir, "proofs")}
	batchSvc := batch.New(
		restartedEngine,
		store,
		batch.Options{QueueSize: 1, MaxRecords: 1, MaxDelay: time.Hour},
		nil,
	)
	defer batchSvc.Shutdown(context.Background())

	recovered, replayed, skipped, err := replayWALAccepted(context.Background(), walPath, restartedEngine, batchSvc, store, nil)
	if err != nil {
		t.Fatalf("replayWALAccepted() error = %v", err)
	}
	if recovered != 0 || replayed != 1 || skipped != 0 {
		t.Fatalf("replayWALAccepted() recovered=%d replayed=%d skipped=%d, want 0/1/0", recovered, replayed, skipped)
	}
	got := waitForReplayProof(t, batchSvc, wantRecord.RecordID)
	if !reflect.DeepEqual(got.ServerRecord, wantRecord) {
		t.Fatalf("replayed ServerRecord mismatch\n got: %+v\nwant: %+v", got.ServerRecord, wantRecord)
	}
	if !reflect.DeepEqual(got.AcceptedReceipt, wantAccepted) {
		t.Fatalf("replayed AcceptedReceipt mismatch\n got: %+v\nwant: %+v", got.AcceptedReceipt, wantAccepted)
	}
}

func waitForReplayProof(t *testing.T, svc *batch.Service, recordID string) model.ProofBundle {
	t.Helper()

	const timeout = 10 * time.Second
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		got, err := svc.Proof(context.Background(), recordID)
		if err == nil {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	got, err := svc.Proof(context.Background(), recordID)
	t.Fatalf("Proof(%q) after %s = %+v err=%v lastErr=%v", recordID, timeout, got, err, svc.LastError())
	return model.ProofBundle{}
}

// TestReplayRecoversPreparedManifestWithoutBundles covers the crash point
// where the batch worker persisted a prepared manifest and died before any
// bundle reached disk. Recovery must finish the batch and end with a fully
// committed manifest plus all bundles and the root.
func TestReplayRecoversPreparedManifestWithoutBundles(t *testing.T) {
	t.Parallel()

	env := newRecoveryEnv(t, 2)
	env.writePreparedManifest(t)

	recovered, replayed, skipped := env.runReplay(t)
	if recovered != 1 || replayed != 0 || skipped != 2 {
		t.Fatalf("runReplay() recovered=%d replayed=%d skipped=%d, want 1/0/2", recovered, replayed, skipped)
	}
	env.assertCommittedBatch(t)
	env.assertReplayIdempotent(t)
}

func TestReplayRecoversPreparingManifest(t *testing.T) {
	t.Parallel()

	env := newRecoveryEnv(t, 2)
	env.manifest.State = model.BatchStatePreparing
	env.manifest.PreparedAtUnixN = 0
	if err := env.store.PutManifest(context.Background(), env.manifest); err != nil {
		t.Fatal(err)
	}

	recovered, replayed, skipped := env.runReplay(t)
	if recovered != 1 || replayed != 0 || skipped != 2 {
		t.Fatalf("runReplay() recovered=%d replayed=%d skipped=%d, want 1/0/2", recovered, replayed, skipped)
	}
	env.assertCommittedBatch(t)
}

func TestReplayKeepsFailedManifestTerminal(t *testing.T) {
	t.Parallel()

	env := newRecoveryEnv(t, 2)
	// Async proof modes persist L2 record indexes before materialization. Even
	// with those indexes present, a terminal failed manifest is not committed
	// coverage and must never advance the WAL checkpoint.
	env.writeBundles(t, len(env.bundles))
	env.manifest.State = model.BatchStateFailed
	env.manifest.MaterializeLastError = "deterministic data loss"
	if err := env.store.PutManifest(context.Background(), env.manifest); err != nil {
		t.Fatal(err)
	}

	recovered, replayed, skipped := env.runReplay(t)
	if recovered != 0 || replayed != 0 || skipped != 2 {
		t.Fatalf("runReplay() recovered=%d replayed=%d skipped=%d, want 0/0/2", recovered, replayed, skipped)
	}
	manifest, err := env.store.GetManifest(context.Background(), env.batchID)
	if err != nil || manifest.State != model.BatchStateFailed {
		t.Fatalf("manifest=%+v err=%v", manifest, err)
	}
	if cp, found, err := env.store.GetCheckpoint(context.Background()); err != nil || found {
		t.Fatalf("failed manifest checkpoint=%+v found=%v err=%v, want none", cp, found, err)
	}
}

// TestReplayRecoversPartiallyWrittenBundles covers the crash point after a
// prepared manifest and a subset of bundles have been written but neither the
// root nor the committed manifest were flushed.
func TestReplayRecoversPartiallyWrittenBundles(t *testing.T) {
	t.Parallel()

	env := newRecoveryEnv(t, 3)
	env.writePreparedManifest(t)
	env.writeBundles(t, 1)

	recovered, replayed, skipped := env.runReplay(t)
	if recovered != 1 || replayed != 0 || skipped != 3 {
		t.Fatalf("runReplay() recovered=%d replayed=%d skipped=%d, want 1/0/3", recovered, replayed, skipped)
	}
	env.assertCommittedBatch(t)
	env.assertReplayIdempotent(t)
}

// TestReplayRecoversMissingRoot covers the crash point where all bundles were
// written but the batch root file never hit disk before the process exited.
func TestReplayRecoversMissingRoot(t *testing.T) {
	t.Parallel()

	env := newRecoveryEnv(t, 2)
	env.writePreparedManifest(t)
	env.writeBundles(t, len(env.bundles))

	recovered, replayed, skipped := env.runReplay(t)
	if recovered != 1 || replayed != 0 || skipped != 2 {
		t.Fatalf("runReplay() recovered=%d replayed=%d skipped=%d, want 1/0/2", recovered, replayed, skipped)
	}
	env.assertCommittedBatch(t)
	env.assertReplayIdempotent(t)
}

// TestReplayIsIdempotentForCommittedBatches covers the case where a batch was
// already fully committed before the restart and must not be re-enqueued or
// rewritten.
func TestReplayIsIdempotentForCommittedBatches(t *testing.T) {
	t.Parallel()

	env := newRecoveryEnv(t, 2)
	env.writePreparedManifest(t)
	env.writeBundles(t, len(env.bundles))
	env.writeRoot(t)
	env.writeCommittedManifest(t)

	recovered, replayed, skipped := env.runReplay(t)
	if recovered != 0 || replayed != 0 || skipped != 2 {
		t.Fatalf("runReplay() recovered=%d replayed=%d skipped=%d, want 0/0/2", recovered, replayed, skipped)
	}
	env.assertCommittedBatch(t)
	env.assertReplayIdempotent(t)
}

// recoveryEnv bundles a WAL + proof store that is prepopulated with a fixed
// set of submitted claims but nothing yet committed. Individual tests decide
// which crash point to simulate by calling the write* helpers before running
// replayWALAccepted against the snapshot.
type recoveryEnv struct {
	dir       string
	walPath   string
	store     proofstore.LocalStore
	engine    app.LocalEngine
	closedAt  time.Time
	batchID   string
	items     []batch.Accepted
	bundles   []model.ProofBundle
	manifest  model.BatchManifest
	root      model.BatchRoot
	serverPub ed25519.PublicKey
}

func newRecoveryEnv(t *testing.T, numClaims int) *recoveryEnv {
	t.Helper()

	clientPub, clientPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate client key error = %v", err)
	}
	serverPub, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate server key error = %v", err)
	}

	dir := t.TempDir()
	walPath := filepath.Join(dir, "trustdb.wal")
	writer, err := wal.OpenWriter(walPath, 1)
	if err != nil {
		t.Fatalf("OpenWriter() error = %v", err)
	}
	engine := app.LocalEngine{
		ServerID:         "server-recovery",
		ServerKeyID:      "server-key",
		ClientPublicKey:  clientPub,
		ServerPrivateKey: serverPriv,
		WAL:              writer,
		Now:              func() time.Time { return time.Unix(400, 500) },
	}

	items := make([]batch.Accepted, 0, numClaims)
	for i := 0; i < numClaims; i++ {
		raw := []byte(fmt.Sprintf("recovery payload %d", i))
		contentHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, raw)
		if err != nil {
			t.Fatalf("HashBytes() error = %v", err)
		}
		c, err := claim.NewFileClaim(
			"tenant-recovery",
			"client-recovery",
			"client-key",
			time.Unix(int64(100+i), 0),
			bytes.Repeat([]byte{byte(i + 1)}, 16),
			fmt.Sprintf("idem-recovery-%d", i),
			model.Content{HashAlg: model.DefaultHashAlg, ContentHash: contentHash, ContentLength: int64(len(raw))},
			model.Metadata{EventType: "file.snapshot"},
		)
		if err != nil {
			t.Fatalf("NewFileClaim() error = %v", err)
		}
		signed, err := claim.Sign(c, clientPriv)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		record, accepted, _, err := engine.Submit(context.Background(), signed)
		if err != nil {
			t.Fatalf("Submit() error = %v", err)
		}
		items = append(items, batch.Accepted{Signed: signed, Record: record, Accepted: accepted})
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	closedAt := time.Unix(1000, 777).UTC()
	batchID := "batch-recovery-1"

	signed := make([]model.SignedClaim, len(items))
	records := make([]model.ServerRecord, len(items))
	accepted := make([]model.AcceptedReceipt, len(items))
	recordIDs := make([]string, len(items))
	for i := range items {
		signed[i] = items[i].Signed
		records[i] = items[i].Record
		accepted[i] = items[i].Accepted
		recordIDs[i] = items[i].Record.RecordID
	}
	bundles, err := engine.CommitBatch(batchID, closedAt, signed, records, accepted)
	if err != nil {
		t.Fatalf("CommitBatch() error = %v", err)
	}

	manifest := model.BatchManifest{
		SchemaVersion:   model.SchemaBatchManifest,
		BatchID:         batchID,
		State:           model.BatchStatePrepared,
		TreeAlg:         model.DefaultMerkleTreeAlg,
		TreeSize:        uint64(len(bundles)),
		BatchRoot:       bundles[0].CommittedReceipt.BatchRoot,
		RecordIDs:       recordIDs,
		WALRange:        model.WALRange{From: items[0].Record.WAL, To: items[len(items)-1].Record.WAL},
		ClosedAtUnixN:   closedAt.UnixNano(),
		PreparedAtUnixN: closedAt.UnixNano(),
	}
	root := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       batchID,
		BatchRoot:     bundles[0].CommittedReceipt.BatchRoot,
		TreeSize:      uint64(len(bundles)),
		ClosedAtUnixN: bundles[0].CommittedReceipt.ClosedAtUnixN,
	}

	return &recoveryEnv{
		dir:       dir,
		walPath:   walPath,
		store:     proofstore.LocalStore{Root: filepath.Join(dir, "proofs")},
		engine:    engine,
		closedAt:  closedAt,
		batchID:   batchID,
		items:     items,
		bundles:   bundles,
		manifest:  manifest,
		root:      root,
		serverPub: serverPub,
	}
}

func (e *recoveryEnv) writePreparedManifest(t *testing.T) {
	t.Helper()
	if err := e.store.PutManifest(context.Background(), e.manifest); err != nil {
		t.Fatalf("PutManifest(prepared) error = %v", err)
	}
}

func (e *recoveryEnv) writeCommittedManifest(t *testing.T) {
	t.Helper()
	committed := e.manifest
	committed.State = model.BatchStateCommitted
	committed.CommittedAtUnixN = e.closedAt.UnixNano() + 1
	if err := e.store.PutManifest(context.Background(), committed); err != nil {
		t.Fatalf("PutManifest(committed) error = %v", err)
	}
}

func (e *recoveryEnv) writeBundles(t *testing.T, count int) {
	t.Helper()
	for i := 0; i < count && i < len(e.bundles); i++ {
		if err := e.store.PutBundle(context.Background(), e.bundles[i]); err != nil {
			t.Fatalf("PutBundle(%d) error = %v", i, err)
		}
	}
}

func (e *recoveryEnv) writeRoot(t *testing.T) {
	t.Helper()
	if err := e.store.PutRoot(context.Background(), e.root); err != nil {
		t.Fatalf("PutRoot() error = %v", err)
	}
}

func (e *recoveryEnv) restartedEngine(t *testing.T) (app.LocalEngine, *wal.Writer) {
	t.Helper()
	reopened, err := wal.OpenWriter(e.walPath, 1)
	if err != nil {
		t.Fatalf("reopen WAL error = %v", err)
	}
	restarted := e.engine
	restarted.WAL = reopened
	restarted.Now = func() time.Time { return time.Unix(9999, 0) }
	return restarted, reopened
}

func (e *recoveryEnv) runReplay(t *testing.T) (int, int, int) {
	t.Helper()
	restartedEngine, reopened := e.restartedEngine(t)
	defer reopened.Close()

	svc := batch.New(
		restartedEngine,
		e.store,
		batch.Options{QueueSize: len(e.items), MaxRecords: len(e.items), MaxDelay: time.Hour},
		nil,
	)
	defer svc.Shutdown(context.Background())

	recovered, replayed, skipped, err := replayWALAccepted(context.Background(), e.walPath, restartedEngine, svc, e.store, nil)
	if err != nil {
		t.Fatalf("replayWALAccepted() error = %v", err)
	}
	return recovered, replayed, skipped
}

// assertCommittedBatch validates that the store matches the deterministic
// outputs produced by a successful batch commit.
func (e *recoveryEnv) assertCommittedBatch(t *testing.T) {
	t.Helper()

	manifest, err := e.store.GetManifest(context.Background(), e.batchID)
	if err != nil {
		t.Fatalf("GetManifest() error = %v", err)
	}
	if manifest.State != model.BatchStateCommitted {
		t.Fatalf("manifest state = %s, want %s", manifest.State, model.BatchStateCommitted)
	}
	if !bytes.Equal(manifest.BatchRoot, e.manifest.BatchRoot) {
		t.Fatalf("manifest BatchRoot mismatch\n got: %x\nwant: %x", manifest.BatchRoot, e.manifest.BatchRoot)
	}
	if manifest.TreeSize != uint64(len(e.bundles)) {
		t.Fatalf("manifest TreeSize = %d, want %d", manifest.TreeSize, len(e.bundles))
	}

	for i, want := range e.bundles {
		got, err := e.store.GetBundle(context.Background(), want.RecordID)
		if err != nil {
			t.Fatalf("GetBundle(%d) error = %v", i, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("bundle %d mismatch\n got: %+v\nwant: %+v", i, got, want)
		}
	}

	root, err := e.store.LatestRoot(context.Background())
	if err != nil {
		t.Fatalf("LatestRoot() error = %v", err)
	}
	if !bytes.Equal(root.BatchRoot, e.root.BatchRoot) || root.TreeSize != e.root.TreeSize {
		t.Fatalf("LatestRoot() = %+v want %+v", root, e.root)
	}
}

// assertReplayIdempotent runs replayWALAccepted a second time against the
// already-healed store and verifies nothing changes on disk and nothing is
// re-enqueued to the batch service.
func (e *recoveryEnv) assertReplayIdempotent(t *testing.T) {
	t.Helper()

	before, err := snapshotStore(e.store.Root)
	if err != nil {
		t.Fatalf("snapshotStore(before) error = %v", err)
	}
	recovered, replayed, skipped := e.runReplay(t)
	if recovered != 0 || replayed != 0 || skipped != len(e.items) {
		t.Fatalf("second runReplay() recovered=%d replayed=%d skipped=%d, want 0/0/%d", recovered, replayed, skipped, len(e.items))
	}
	after, err := snapshotStore(e.store.Root)
	if err != nil {
		t.Fatalf("snapshotStore(after) error = %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("store mutated between replays\nbefore: %+v\nafter: %+v", before, after)
	}

	// Confirm a committed manifest still reports the right record set so
	// future ingests never attempt to resubmit these records.
	manifest, err := e.store.GetManifest(context.Background(), e.batchID)
	if err != nil {
		t.Fatalf("GetManifest() error = %v", err)
	}
	if manifest.State != model.BatchStateCommitted {
		t.Fatalf("manifest state after idempotent replay = %s", manifest.State)
	}
}

// snapshotStore returns a filename -> byte contents map of the proof store so
// tests can detect any unexpected mutation across replays.
func snapshotStore(root string) (map[string][]byte, error) {
	out := make(map[string][]byte)
	err := walkStore(root, func(path string, data []byte) {
		rel, _ := filepath.Rel(root, path)
		out[filepath.ToSlash(rel)] = data
	})
	return out, err
}

func walkStore(root string, visit func(string, []byte)) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		visit(path, data)
		return nil
	})
}

// idempotencyEnv wires a live LocalEngine with a real WAL + idempotency
// index so tests can exercise the ingest path end-to-end without going
// through the HTTP layer.
type idempotencyEnv struct {
	dir       string
	walPath   string
	writer    *wal.Writer
	engine    app.LocalEngine
	clientPub ed25519.PublicKey
	clientKey ed25519.PrivateKey
}

func newIdempotencyEnv(t *testing.T) *idempotencyEnv {
	t.Helper()
	clientPub, clientPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate client key error = %v", err)
	}
	_, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate server key error = %v", err)
	}
	dir := t.TempDir()
	walPath := filepath.Join(dir, "trustdb.wal")
	writer, err := wal.OpenWriter(walPath, 1)
	if err != nil {
		t.Fatalf("OpenWriter() error = %v", err)
	}
	engine := app.LocalEngine{
		ServerID:         "server-idem",
		ServerKeyID:      "server-key",
		ClientPublicKey:  clientPub,
		ServerPrivateKey: serverPriv,
		WAL:              writer,
		Idempotency:      app.NewIdempotencyIndex(),
		Now:              func() time.Time { return time.Unix(500, 0) },
	}
	return &idempotencyEnv{
		dir:       dir,
		walPath:   walPath,
		writer:    writer,
		engine:    engine,
		clientPub: clientPub,
		clientKey: clientPriv,
	}
}

func (e *idempotencyEnv) signClaim(t *testing.T, idemKey string, payload []byte, nonce byte) model.SignedClaim {
	t.Helper()
	contentHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, payload)
	if err != nil {
		t.Fatalf("HashBytes() error = %v", err)
	}
	c, err := claim.NewFileClaim(
		"tenant-idem",
		"client-idem",
		"client-key",
		time.Unix(100, 0),
		bytes.Repeat([]byte{nonce}, 16),
		idemKey,
		model.Content{HashAlg: model.DefaultHashAlg, ContentHash: contentHash, ContentLength: int64(len(payload))},
		model.Metadata{EventType: "file.snapshot"},
	)
	if err != nil {
		t.Fatalf("NewFileClaim() error = %v", err)
	}
	signed, err := claim.Sign(c, e.clientKey)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return signed
}

func (e *idempotencyEnv) closeWAL(t *testing.T) {
	t.Helper()
	if err := e.writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func (e *idempotencyEnv) reopen(t *testing.T) *wal.Writer {
	t.Helper()
	reopened, err := wal.OpenWriter(e.walPath, 1)
	if err != nil {
		t.Fatalf("reopen WAL error = %v", err)
	}
	return reopened
}

func walRecordCount(t *testing.T, path string) int {
	t.Helper()
	records, err := wal.ReadAll(path)
	if err != nil {
		t.Fatalf("wal.ReadAll() error = %v", err)
	}
	return len(records)
}

// TestIdempotentSubmitReturnsOriginalRecord verifies that resubmitting the
// exact same signed claim returns the original record/accepted pair without
// appending a second WAL record.
func TestIdempotentSubmitReturnsOriginalRecord(t *testing.T) {
	t.Parallel()

	env := newIdempotencyEnv(t)
	defer env.writer.Close()

	signed := env.signClaim(t, "idem-same", []byte("same payload"), 1)
	first, firstAccepted, firstIdem, err := env.engine.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("first Submit() error = %v", err)
	}
	if firstIdem {
		t.Fatalf("first Submit() idempotent = true, want false")
	}

	second, secondAccepted, secondIdem, err := env.engine.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("second Submit() error = %v", err)
	}
	if !secondIdem {
		t.Fatalf("second Submit() idempotent = false, want true")
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("second Submit() ServerRecord diverged\n got: %+v\nwant: %+v", second, first)
	}
	if !reflect.DeepEqual(firstAccepted, secondAccepted) {
		t.Fatalf("second Submit() AcceptedReceipt diverged\n got: %+v\nwant: %+v", secondAccepted, firstAccepted)
	}
	env.closeWAL(t)
	if got := walRecordCount(t, env.walPath); got != 1 {
		t.Fatalf("WAL records after idempotent replay = %d, want 1", got)
	}
}

// TestIdempotencyKeyConflictRejectsDifferentClaim verifies that reusing the
// same (tenant, client, idempotency_key) for a claim with different content
// surfaces ALREADY_EXISTS instead of silently writing a second record.
func TestIdempotencyKeyConflictRejectsDifferentClaim(t *testing.T) {
	t.Parallel()

	env := newIdempotencyEnv(t)
	defer env.writer.Close()

	signedA := env.signClaim(t, "idem-conflict", []byte("payload A"), 1)
	if _, _, _, err := env.engine.Submit(context.Background(), signedA); err != nil {
		t.Fatalf("first Submit() error = %v", err)
	}

	signedB := env.signClaim(t, "idem-conflict", []byte("payload B"), 2)
	_, _, _, err := env.engine.Submit(context.Background(), signedB)
	if err == nil {
		t.Fatalf("second Submit() error = nil, want ALREADY_EXISTS")
	}
	if code := trusterr.CodeOf(err); code != trusterr.CodeAlreadyExists {
		t.Fatalf("second Submit() code = %s, want %s err=%v", code, trusterr.CodeAlreadyExists, err)
	}

	env.closeWAL(t)
	if got := walRecordCount(t, env.walPath); got != 1 {
		t.Fatalf("WAL records after conflict = %d, want 1 (only first claim persisted)", got)
	}
}

// TestReplayRebuildsIdempotencyIndex verifies that after a restart the WAL
// replay repopulates the idempotency index so that a client that retries the
// same claim across a crash still observes its first record rather than
// writing a duplicate WAL entry.
func TestReplayRebuildsIdempotencyIndex(t *testing.T) {
	t.Parallel()

	env := newIdempotencyEnv(t)
	signed := env.signClaim(t, "idem-restart", []byte("restart payload"), 1)
	original, originalAccepted, _, err := env.engine.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("first Submit() error = %v", err)
	}
	env.closeWAL(t)

	reopened := env.reopen(t)
	defer reopened.Close()
	restarted := env.engine
	restarted.WAL = reopened
	restarted.Idempotency = app.NewIdempotencyIndex()
	restarted.Now = func() time.Time { return time.Unix(9000, 0) }

	store := proofstore.LocalStore{Root: filepath.Join(env.dir, "proofs")}
	batchSvc := batch.New(
		restarted,
		store,
		batch.Options{QueueSize: 4, MaxRecords: 4, MaxDelay: time.Hour},
		nil,
	)
	defer batchSvc.Shutdown(context.Background())

	recovered, replayed, skipped, err := replayWALAccepted(context.Background(), env.walPath, restarted, batchSvc, store, nil)
	if err != nil {
		t.Fatalf("replayWALAccepted() error = %v", err)
	}
	if recovered != 0 || replayed != 1 || skipped != 0 {
		t.Fatalf("replayWALAccepted() recovered=%d replayed=%d skipped=%d, want 0/1/0", recovered, replayed, skipped)
	}

	// Resubmit the exact same claim post-restart. The index must short-
	// circuit to the original record without touching the WAL or creating a
	// new batch entry.
	replayed2, replayedAccepted, idem, err := restarted.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("restarted Submit() error = %v", err)
	}
	if !idem {
		t.Fatalf("restarted Submit() idempotent = false, want true after WAL replay")
	}
	if !reflect.DeepEqual(replayed2, original) {
		t.Fatalf("restarted Submit() record diverged\n got: %+v\nwant: %+v", replayed2, original)
	}
	if !reflect.DeepEqual(replayedAccepted, originalAccepted) {
		t.Fatalf("restarted Submit() accepted diverged\n got: %+v\nwant: %+v", replayedAccepted, originalAccepted)
	}

	if err := reopened.Close(); err != nil {
		t.Fatalf("close reopened WAL error = %v", err)
	}
	if got := walRecordCount(t, env.walPath); got != 1 {
		t.Fatalf("WAL records after restart replay = %d, want 1", got)
	}
}

func TestEmptyIdempotencyKeyExactRetrySurvivesRestart(t *testing.T) {
	t.Parallel()

	env := newIdempotencyEnv(t)
	seed := env.signClaim(t, "temporary-key", []byte("duplicate-empty-idempotency"), 7)
	seed.Claim.IdempotencyKey = ""
	signed, err := claim.Sign(seed.Claim, env.clientKey)
	if err != nil {
		t.Fatalf("Sign(empty idempotency) error = %v", err)
	}
	first, firstAccepted, firstIdempotent, err := env.engine.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("Submit(first) error = %v", err)
	}
	if firstIdempotent {
		t.Fatal("Submit(first) idempotent = true")
	}
	second, secondAccepted, secondIdempotent, err := env.engine.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("Submit(second) error = %v", err)
	}
	if !secondIdempotent || !reflect.DeepEqual(second, first) || !reflect.DeepEqual(secondAccepted, firstAccepted) {
		t.Fatalf("exact retry = record:%+v accepted:%+v idempotent:%v", second, secondAccepted, secondIdempotent)
	}

	distinctSeed := env.signClaim(t, "temporary-key-2", []byte("distinct-empty-idempotency"), 8)
	distinctSeed.Claim.IdempotencyKey = ""
	distinctSigned, err := claim.Sign(distinctSeed.Claim, env.clientKey)
	if err != nil {
		t.Fatalf("Sign(distinct empty idempotency) error = %v", err)
	}
	distinct, _, distinctIdempotent, err := env.engine.Submit(context.Background(), distinctSigned)
	if err != nil {
		t.Fatalf("Submit(distinct) error = %v", err)
	}
	if distinctIdempotent || distinct.RecordID == first.RecordID || distinct.WAL == first.WAL {
		t.Fatalf("distinct claim = %+v idempotent=%v", distinct, distinctIdempotent)
	}
	if got := walRecordCount(t, env.walPath); got != 2 {
		t.Fatalf("WAL records before restart = %d, want 2", got)
	}
	env.closeWAL(t)

	reopened := env.reopen(t)
	defer reopened.Close()
	restarted := env.engine
	restarted.WAL = reopened
	restarted.Idempotency = app.NewIdempotencyIndex()
	store := proofstore.LocalStore{Root: filepath.Join(env.dir, "proofs")}
	restarted.DurableRecords = store
	svc := batch.New(restarted, store, batch.Options{QueueSize: 3, MaxRecords: 3, MaxDelay: time.Hour}, nil)
	defer svc.Shutdown(context.Background())

	if _, _, _, err = replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, nil); err != nil {
		t.Fatalf("replayWALAccepted() error = %v", err)
	}
	replayed, replayedAccepted, replayedIdempotent, err := restarted.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("restarted Submit() error = %v", err)
	}
	if !replayedIdempotent || !reflect.DeepEqual(replayed, first) || !reflect.DeepEqual(replayedAccepted, firstAccepted) {
		t.Fatalf("restarted retry = record:%+v accepted:%+v idempotent:%v", replayed, replayedAccepted, replayedIdempotent)
	}
	if got := walRecordCount(t, env.walPath); got != 2 {
		t.Fatalf("WAL records after restart retry = %d, want 2", got)
	}
}

// TestReplaySkipsRecordsBelowCheckpoint verifies that when a WAL checkpoint
// covers every record in the WAL, replay short-circuits: no ReplayAccepted
// invocations happen, no records are enqueued, and the skipped counter
// reflects the full WAL. Built-in stores do not enable this path until a
// durable keyed idempotency projection is available.
func TestReplaySkipsRecordsBelowCheckpoint(t *testing.T) {
	t.Parallel()

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
		BatchID:       env.batchID,
	}); err != nil {
		t.Fatalf("PutCheckpoint() error = %v", err)
	}

	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	store := checkpointSafeLocalStore{LocalStore: env.store}

	svc := batch.New(
		restarted,
		store,
		batch.Options{QueueSize: len(env.items), MaxRecords: len(env.items), MaxDelay: time.Hour},
		nil,
	)
	defer svc.Shutdown(context.Background())

	_, metrics := observability.NewRegistry()
	recovered, replayed, skipped, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, metrics)
	if err != nil {
		t.Fatalf("replayWALAccepted() error = %v", err)
	}
	if recovered != 0 || replayed != 0 || skipped != len(env.items) {
		t.Fatalf("replayWALAccepted() recovered=%d replayed=%d skipped=%d, want 0/0/%d", recovered, replayed, skipped, len(env.items))
	}
	if got := testutil.ToFloat64(metrics.WALReplayRecords.WithLabelValues("skipped")); int(got) != len(env.items) {
		t.Fatalf("wal_replay_records_total{result=skipped} = %v, want %d", got, len(env.items))
	}
	if got := testutil.ToFloat64(metrics.WALReplayRecords.WithLabelValues("replayed")); got != 0 {
		t.Fatalf("wal_replay_records_total{result=replayed} = %v, want 0", got)
	}
	if got := testutil.ToFloat64(metrics.WALReplayRecords.WithLabelValues("recovered")); got != 0 {
		t.Fatalf("wal_replay_records_total{result=recovered} = %v, want 0", got)
	}
	if got := testutil.ToFloat64(metrics.WALCheckpointLastSequence); uint64(got) != top.Sequence {
		t.Fatalf("wal_checkpoint_last_sequence = %v, want %d", got, top.Sequence)
	}

	env.assertCommittedBatch(t)
}

// TestReplayRecordsMetricsOnRecoveredPath exercises the crash-during-commit
// recovery path and verifies the replay counter+gauge combination is emitted
// so operators can distinguish recovered vs. replayed vs. skipped records.
func TestReplayRecordsMetricsOnRecoveredPath(t *testing.T) {
	t.Parallel()

	env := newRecoveryEnv(t, 2)
	env.writePreparedManifest(t)
	env.writeBundles(t, len(env.bundles))

	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()

	svc := batch.New(
		restarted,
		env.store,
		batch.Options{QueueSize: len(env.items), MaxRecords: len(env.items), MaxDelay: time.Hour},
		nil,
	)
	defer svc.Shutdown(context.Background())

	_, metrics := observability.NewRegistry()
	recovered, replayed, skipped, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, env.store, metrics)
	if err != nil {
		t.Fatalf("replayWALAccepted() error = %v", err)
	}
	if recovered != 1 || replayed != 0 || skipped != 2 {
		t.Fatalf("replayWALAccepted() recovered=%d replayed=%d skipped=%d, want 1/0/2", recovered, replayed, skipped)
	}
	if got := testutil.ToFloat64(metrics.WALReplayRecords.WithLabelValues("recovered")); int(got) != 1 {
		t.Fatalf("wal_replay_records_total{result=recovered} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.WALReplayRecords.WithLabelValues("skipped")); int(got) != 2 {
		t.Fatalf("wal_replay_records_total{result=skipped} = %v, want 2", got)
	}
	// No checkpoint existed prior to replay and no commit ran through the
	// batch pipeline (recovery path doesn't go through persistBatch), so the
	// gauge should remain at its zero default.
	if got := testutil.ToFloat64(metrics.WALCheckpointLastSequence); got != 0 {
		t.Fatalf("wal_checkpoint_last_sequence = %v, want 0 (no checkpoint seeded)", got)
	}
}

// TestReplaySkipsStalePreparedManifestBelowCheckpoint covers the recovery
// path where a prepared manifest survived from a previous crash but its WAL
// range was already superseded by a newer committed batch that advanced the
// checkpoint past it. Replay must treat the manifest as stale instead of
// calling RecoverManifest (which would fail because the records were skipped
// during WAL scan).
func TestReplaySkipsStalePreparedManifestBelowCheckpoint(t *testing.T) {
	t.Parallel()

	env := newRecoveryEnv(t, 2)
	env.writePreparedManifest(t)
	writeCommittedRecoverySubset(t, env, "newer-batch-that-already-committed", 0, 1)

	top := env.items[len(env.items)-1].Record.WAL
	if err := env.store.PutCheckpoint(context.Background(), model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpointContiguous,
		SegmentID:     top.SegmentID,
		LastSequence:  top.Sequence,
		LastOffset:    top.Offset,
		BatchID:       "newer-batch-that-already-committed",
	}); err != nil {
		t.Fatalf("PutCheckpoint() error = %v", err)
	}

	restarted, reopened := env.restartedEngine(t)
	defer reopened.Close()
	store := checkpointSafeLocalStore{LocalStore: env.store}

	svc := batch.New(
		restarted,
		store,
		batch.Options{QueueSize: len(env.items), MaxRecords: len(env.items), MaxDelay: time.Hour},
		nil,
	)
	defer svc.Shutdown(context.Background())

	recovered, replayed, skipped, err := replayWALAccepted(context.Background(), env.walPath, restarted, svc, store, nil)
	if err != nil {
		t.Fatalf("replayWALAccepted() error = %v", err)
	}
	if recovered != 0 || replayed != 0 || skipped != len(env.items) {
		t.Fatalf("replayWALAccepted() recovered=%d replayed=%d skipped=%d, want 0/0/%d", recovered, replayed, skipped, len(env.items))
	}

	manifest, err := env.store.GetManifest(context.Background(), env.batchID)
	if err != nil {
		t.Fatalf("GetManifest() error = %v", err)
	}
	if manifest.State != model.BatchStatePrepared {
		t.Fatalf("stale prepared manifest promoted to %s, want prepared", manifest.State)
	}
	bundle, err := env.store.GetBundle(context.Background(), env.bundles[0].RecordID)
	if err != nil || bundle.CommittedReceipt.BatchID != "newer-batch-that-already-committed" {
		t.Fatalf("committed replacement bundle = %+v err=%v", bundle, err)
	}
}

// TestOpenWALWriterModes locks server startup to the segmented directory WAL.
func TestOpenWALWriterModes(t *testing.T) {
	t.Parallel()

	t.Run("existing file is rejected", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		walPath := filepath.Join(dir, "trustdb.wal")
		w, err := wal.OpenWriter(walPath, 1)
		if err != nil {
			t.Fatalf("seed OpenWriter() error = %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("seed Close() error = %v", err)
		}
		got, mode, err := openWALWriter(walPath, 0)
		if err == nil || trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("openWALWriter() = (%v, %q, %v), want failed precondition", got, mode, err)
		}
	})

	t.Run("existing directory selects directory mode", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		walDir := filepath.Join(dir, "segments")
		if err := os.MkdirAll(walDir, 0o755); err != nil {
			t.Fatalf("MkdirAll() error = %v", err)
		}
		got, mode, err := openWALWriter(walDir, 1024)
		if err != nil {
			t.Fatalf("openWALWriter() error = %v", err)
		}
		defer got.Close()
		if mode != "directory" {
			t.Fatalf("mode = %q, want directory", mode)
		}
		if got.ActiveSegmentID() != 1 {
			t.Fatalf("ActiveSegmentID() = %d, want 1 (fresh dir must seed segment 1)", got.ActiveSegmentID())
		}
	})

	t.Run("non-existent .wal path selects directory mode", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		walPath := filepath.Join(dir, "fresh.wal")
		got, mode, err := openWALWriter(walPath, 0)
		if err != nil {
			t.Fatalf("openWALWriter() error = %v", err)
		}
		defer got.Close()
		if mode != "directory" {
			t.Fatalf("mode = %q, want directory", mode)
		}
		info, err := os.Stat(walPath)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		if !info.IsDir() {
			t.Fatalf("Stat() reports regular file; want directory")
		}
	})

	t.Run("non-existent directory-looking path gets promoted", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		walPath := filepath.Join(dir, "wal")
		got, mode, err := openWALWriter(walPath, 0)
		if err != nil {
			t.Fatalf("openWALWriter() error = %v", err)
		}
		defer got.Close()
		if mode != "directory" {
			t.Fatalf("mode = %q, want directory", mode)
		}
		info, err := os.Stat(walPath)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		if !info.IsDir() {
			t.Fatalf("Stat() reports regular file; want directory")
		}
	})
}

// TestReplayDirectoryModeRestoresRecord mirrors
// TestReplayWALAcceptedRestoresUnbatchedRecord but with the directory-mode
// WAL + small MaxSegmentBytes so rotation actually happens. It proves the
// end-to-end replay path works when records live across multiple segments
// and no checkpoint exists yet (so every record must be replayed).
func TestReplayDirectoryModeRestoresRecord(t *testing.T) {
	clientPub, clientPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate client key error = %v", err)
	}
	_, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate server key error = %v", err)
	}

	dir := t.TempDir()
	walDir := filepath.Join(dir, "wal")
	writer, mode, err := openWALWriter(walDir, 256)
	if err != nil {
		t.Fatalf("openWALWriter() error = %v", err)
	}
	if mode != "directory" {
		t.Fatalf("mode = %q, want directory", mode)
	}
	engine := app.LocalEngine{
		ServerID:         "server-dir-replay",
		ServerKeyID:      "server-key",
		ClientPublicKey:  clientPub,
		ServerPrivateKey: serverPriv,
		WAL:              writer,
		Now:              func() time.Time { return time.Unix(200, 123) },
	}

	wantRecords := make([]model.ServerRecord, 0, 4)
	wantAccepted := make([]model.AcceptedReceipt, 0, 4)
	for i := 0; i < 4; i++ {
		raw := bytes.Repeat([]byte{byte('a' + i)}, 120)
		contentHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, raw)
		if err != nil {
			t.Fatalf("HashBytes() error = %v", err)
		}
		c, err := claim.NewFileClaim(
			"tenant-dir",
			"client-dir",
			"client-key",
			time.Unix(int64(100+i), 0),
			bytes.Repeat([]byte{byte(i + 1)}, 16),
			fmt.Sprintf("idem-dir-%d", i),
			model.Content{HashAlg: model.DefaultHashAlg, ContentHash: contentHash, ContentLength: int64(len(raw))},
			model.Metadata{EventType: "file.snapshot"},
		)
		if err != nil {
			t.Fatalf("NewFileClaim() error = %v", err)
		}
		signed, err := claim.Sign(c, clientPriv)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		rec, acc, _, err := engine.Submit(context.Background(), signed)
		if err != nil {
			t.Fatalf("Submit(%d) error = %v", i, err)
		}
		wantRecords = append(wantRecords, rec)
		wantAccepted = append(wantAccepted, acc)
	}
	segs, err := wal.ListSegments(walDir)
	if err != nil {
		t.Fatalf("ListSegments() error = %v", err)
	}
	if len(segs) < 2 {
		t.Fatalf("want >= 2 segments for a meaningful dir-mode test, got %v", segs)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, mode, err := openWALWriter(walDir, 256)
	if err != nil {
		t.Fatalf("reopen openWALWriter() error = %v", err)
	}
	if mode != "directory" {
		t.Fatalf("reopened mode = %q, want directory", mode)
	}
	defer reopened.Close()

	restarted := app.LocalEngine{
		ServerID:         "server-dir-replay",
		ServerKeyID:      "server-key",
		ClientPublicKey:  clientPub,
		ServerPrivateKey: serverPriv,
		WAL:              reopened,
		Idempotency:      app.NewIdempotencyIndex(),
		Now:              func() time.Time { return time.Unix(300, 0) },
	}
	store := proofstore.LocalStore{Root: filepath.Join(dir, "proofs")}
	svc := batch.New(
		restarted,
		store,
		batch.Options{QueueSize: len(wantRecords), MaxRecords: len(wantRecords), MaxDelay: time.Hour},
		nil,
	)
	defer svc.Shutdown(context.Background())

	_, metrics := observability.NewRegistry()
	recovered, replayed, skipped, err := replayWALAccepted(context.Background(), walDir, restarted, svc, store, metrics)
	if err != nil {
		t.Fatalf("replayWALAccepted() error = %v", err)
	}
	if recovered != 0 || replayed != len(wantRecords) || skipped != 0 {
		t.Fatalf("replayWALAccepted() recovered=%d replayed=%d skipped=%d, want 0/%d/0",
			recovered, replayed, skipped, len(wantRecords))
	}
	if size := restarted.Idempotency.Size(); size != len(wantRecords) {
		t.Fatalf("idempotency index size = %d, want %d", size, len(wantRecords))
	}
	for i := range wantRecords {
		got := waitForReplayProof(t, svc, wantRecords[i].RecordID)
		if !reflect.DeepEqual(got.ServerRecord, wantRecords[i]) {
			t.Fatalf("replayed ServerRecord[%d] mismatch\n got: %+v\nwant: %+v",
				i, got.ServerRecord, wantRecords[i])
		}
		if !reflect.DeepEqual(got.AcceptedReceipt, wantAccepted[i]) {
			t.Fatalf("replayed AcceptedReceipt[%d] mismatch\n got: %+v\nwant: %+v",
				i, got.AcceptedReceipt, wantAccepted[i])
		}
	}
}

// TestReplayDirectoryModeSkipsEarlySegments proves the IO optimization:
// when a checkpoint points past the first segment, ReadAllDirFrom must
// avoid reading those files and replay must not see those records at all
// (neither as skipped, since they are skipped at the segment layer, nor as
// replayed). We then also verify PruneSegmentsBefore can safely delete
// those early segments without affecting subsequent replays.
func TestReplayDirectoryModeSkipsEarlySegments(t *testing.T) {
	t.Parallel()

	clientPub, clientPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate client key error = %v", err)
	}
	_, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate server key error = %v", err)
	}

	dir := t.TempDir()
	walDir := filepath.Join(dir, "wal")
	writer, _, err := openWALWriter(walDir, 256)
	if err != nil {
		t.Fatalf("openWALWriter() error = %v", err)
	}
	engine := app.LocalEngine{
		ServerID:         "server-skip-seg",
		ServerKeyID:      "server-key",
		ClientPublicKey:  clientPub,
		ServerPrivateKey: serverPriv,
		WAL:              writer,
		Now:              func() time.Time { return time.Unix(400, 0) },
	}

	const totalRecords = 6
	records := make([]model.ServerRecord, 0, totalRecords)
	signedClaims := make([]model.SignedClaim, 0, totalRecords)
	acceptedReceipts := make([]model.AcceptedReceipt, 0, totalRecords)
	for i := 0; i < totalRecords; i++ {
		raw := bytes.Repeat([]byte{byte('a' + i)}, 120)
		contentHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, raw)
		if err != nil {
			t.Fatalf("HashBytes() error = %v", err)
		}
		c, err := claim.NewFileClaim(
			"tenant-skip",
			"client-skip",
			"client-key",
			time.Unix(int64(500+i), 0),
			bytes.Repeat([]byte{byte(i + 1)}, 16),
			fmt.Sprintf("idem-skip-%d", i),
			model.Content{HashAlg: model.DefaultHashAlg, ContentHash: contentHash, ContentLength: int64(len(raw))},
			model.Metadata{EventType: "file.snapshot"},
		)
		if err != nil {
			t.Fatalf("NewFileClaim() error = %v", err)
		}
		signed, err := claim.Sign(c, clientPriv)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		rec, accepted, _, err := engine.Submit(context.Background(), signed)
		if err != nil {
			t.Fatalf("Submit(%d) error = %v", i, err)
		}
		records = append(records, rec)
		signedClaims = append(signedClaims, signed)
		acceptedReceipts = append(acceptedReceipts, accepted)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Pick the segment id of the last record as the cutoff. Every record
	// strictly before that segment will be skipped by ReadAllDirFrom and
	// thus never touched by replay. Records sharing the last segment are
	// still visible but their sequence ≤ checkpoint.LastSequence so they
	// are counted as skipped inside the replay loop.
	last := records[len(records)-1].WAL
	var belowCutoff, atOrAboveCutoff int
	for _, r := range records {
		if r.WAL.SegmentID < last.SegmentID {
			belowCutoff++
		} else {
			atOrAboveCutoff++
		}
	}
	if belowCutoff == 0 {
		t.Fatalf("want at least one record below cutoff segment; got segments %v",
			segmentsFor(records))
	}

	store := checkpointSafeLocalStore{LocalStore: proofstore.LocalStore{Root: filepath.Join(dir, "proofs")}}
	const checkpointBatchID = "batch-checkpoint-skip"
	closedAt := time.Unix(700, 0).UTC()
	bundles, err := engine.CommitBatch(checkpointBatchID, closedAt, signedClaims, records, acceptedReceipts)
	if err != nil {
		t.Fatalf("CommitBatch() error = %v", err)
	}
	recordIDs := make([]string, len(bundles))
	for i := range bundles {
		recordIDs[i] = bundles[i].RecordID
		if err := store.PutBundle(context.Background(), bundles[i]); err != nil {
			t.Fatalf("PutBundle(%d) error = %v", i, err)
		}
	}
	if err := store.PutManifest(context.Background(), model.BatchManifest{
		SchemaVersion:    model.SchemaBatchManifest,
		BatchID:          checkpointBatchID,
		State:            model.BatchStateCommitted,
		TreeAlg:          model.DefaultMerkleTreeAlg,
		TreeSize:         uint64(len(recordIDs)),
		BatchRoot:        bundles[0].CommittedReceipt.BatchRoot,
		RecordIDs:        recordIDs,
		WALRange:         model.WALRange{From: records[0].WAL, To: records[len(records)-1].WAL},
		ClosedAtUnixN:    closedAt.UnixNano(),
		CommittedAtUnixN: closedAt.Add(time.Nanosecond).UnixNano(),
	}); err != nil {
		t.Fatalf("PutManifest() error = %v", err)
	}
	if err := store.PutCheckpoint(context.Background(), model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpointContiguous,
		SegmentID:     last.SegmentID,
		LastSequence:  last.Sequence,
		LastOffset:    last.Offset,
		BatchID:       checkpointBatchID,
	}); err != nil {
		t.Fatalf("PutCheckpoint() error = %v", err)
	}

	reopened, _, err := openWALWriter(walDir, 256)
	if err != nil {
		t.Fatalf("reopen openWALWriter() error = %v", err)
	}
	defer reopened.Close()
	restarted := app.LocalEngine{
		ServerID:         "server-skip-seg",
		ServerKeyID:      "server-key",
		ClientPublicKey:  clientPub,
		ServerPrivateKey: serverPriv,
		WAL:              reopened,
		Now:              func() time.Time { return time.Unix(600, 0) },
	}
	svc := batch.New(
		restarted,
		store,
		batch.Options{QueueSize: totalRecords, MaxRecords: totalRecords, MaxDelay: time.Hour},
		nil,
	)
	defer svc.Shutdown(context.Background())

	_, metrics := observability.NewRegistry()
	recovered, replayed, skipped, err := replayWALAccepted(context.Background(), walDir, restarted, svc, store, metrics)
	if err != nil {
		t.Fatalf("replayWALAccepted() error = %v", err)
	}
	if recovered != 0 || replayed != 0 || skipped != atOrAboveCutoff {
		t.Fatalf("replayWALAccepted() recovered=%d replayed=%d skipped=%d, want 0/0/%d",
			recovered, replayed, skipped, atOrAboveCutoff)
	}
	// Crucially: records below the cutoff must not appear in any counter,
	// because segment-level skip keeps them out of the replay loop entirely.
	if got := testutil.ToFloat64(metrics.WALReplayRecords.WithLabelValues("skipped")); int(got) != atOrAboveCutoff {
		t.Fatalf("wal_replay_records_total{result=skipped} = %v, want %d", got, atOrAboveCutoff)
	}
	// PruneSegmentsBefore is safe to call with the checkpoint cutoff: it
	// deletes exactly the segments that the checkpoint already covers and
	// leaves the active segment intact.
	removed, bytesRemoved, err := wal.PruneSegmentsBefore(walDir, last.SegmentID)
	if err != nil {
		t.Fatalf("PruneSegmentsBefore() error = %v", err)
	}
	if removed == 0 {
		t.Fatalf("PruneSegmentsBefore() removed 0 segments; want > 0 (cutoff=%d)", last.SegmentID)
	}
	if bytesRemoved <= 0 {
		t.Fatalf("PruneSegmentsBefore() bytesRemoved = %d, want > 0", bytesRemoved)
	}
	after, err := wal.ListSegments(walDir)
	if err != nil {
		t.Fatalf("ListSegments() error = %v", err)
	}
	for _, seg := range after {
		if seg < last.SegmentID {
			t.Fatalf("segment %d survived prune below cutoff %d", seg, last.SegmentID)
		}
	}

	// A second replay after prune must still succeed: the checkpoint still
	// covers the remaining records and ReadAllDirFrom no longer needs to
	// touch the pruned files.
	recovered, replayed, skipped, err = replayWALAccepted(context.Background(), walDir, restarted, svc, store, nil)
	if err != nil {
		t.Fatalf("post-prune replayWALAccepted() error = %v", err)
	}
	if recovered != 0 || replayed != 0 || skipped != atOrAboveCutoff {
		t.Fatalf("post-prune replayWALAccepted() recovered=%d replayed=%d skipped=%d, want 0/0/%d",
			recovered, replayed, skipped, atOrAboveCutoff)
	}
}

func segmentsFor(records []model.ServerRecord) []uint64 {
	out := make([]uint64, 0, len(records))
	for _, r := range records {
		out = append(out, r.WAL.SegmentID)
	}
	return out
}
