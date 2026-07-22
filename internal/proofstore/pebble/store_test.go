package pebble_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
	pebblestore "github.com/wowtrust/trustdb/internal/proofstore/pebble"
	"github.com/wowtrust/trustdb/internal/proofstore/proofstoretest"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

// TestPebbleStoreConformance exercises every Store contract against a
// Pebble-backed implementation so it stays byte-equivalent to the file
// backend under file/pebble switchover.
func TestPebbleStoreConformance(t *testing.T) {
	t.Parallel()
	proofstoretest.RunConformance(t, func(t *testing.T) (proofstore.Store, func()) {
		store, err := pebblestore.Open(t.TempDir())
		if err != nil {
			t.Fatalf("pebble Open: %v", err)
		}
		return store, func() { _ = store.Close() }
	})
}

func TestPebbleEnablesPruningAfterDurableRestartIdempotency(t *testing.T) {
	t.Parallel()
	store, err := pebblestore.Open(t.TempDir())
	if err != nil {
		t.Fatalf("pebble Open: %v", err)
	}
	defer store.Close()
	if !proofstore.WALCheckpointPruneSafe(store) {
		t.Fatal("Pebble store did not enable pruning after durable restart idempotency became ready")
	}
}

func TestPebbleSTHAnchorScheduleSurvivesRestartAndPreservesResult(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	sth := pebbleScheduleSTH(key, 3, 0x33)

	store, err := pebblestore.Open(dir)
	if err != nil {
		t.Fatalf("pebble Open: %v", err)
	}
	scheduler := proofstore.STHAnchorScheduleStore(store)
	if _, err := scheduler.UpsertSTHAnchorCandidate(ctx, model.STHAnchorCandidate{
		Key:             key,
		STH:             sth,
		ObservedAtUnixN: 100,
		DueAtUnixN:      200,
	}); err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate: %v", err)
	}
	firstAttempt, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, key, 200, 250, "worker-1", "lease-1")
	if err != nil || !claimed {
		t.Fatalf("ClaimSTHAnchorAttempt claimed=%v err=%v", claimed, err)
	}
	if err := scheduler.RescheduleSTHAnchorAttempt(ctx, key, firstAttempt.Generation, "lease-1", 1, 300, "retry"); err != nil {
		t.Fatalf("RescheduleSTHAnchorAttempt: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	store, err = pebblestore.Open(dir)
	if err != nil {
		t.Fatalf("pebble reopen: %v", err)
	}
	defer store.Close()
	scheduler = proofstore.STHAnchorScheduleStore(store)
	restored, found, err := scheduler.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || restored.InFlight == nil || restored.InFlight.Attempts != 1 || restored.InFlight.NextAttemptUnixN != 300 {
		t.Fatalf("GetSTHAnchorSchedule after restart found=%v schedule=%+v err=%v", found, restored, err)
	}
	attempt, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, key, 300, 400, "worker-2", "lease-2")
	if err != nil || !claimed {
		t.Fatalf("ClaimSTHAnchorAttempt retry claimed=%v err=%v", claimed, err)
	}
	result := model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		NodeID:           key.NodeID,
		LogID:            key.LogID,
		TreeSize:         attempt.Target.TreeSize,
		SinkName:         key.SinkName,
		AnchorID:         "anchor-3",
		RootHash:         append([]byte(nil), attempt.Target.RootHash...),
		STH:              attempt.Target,
		Proof:            []byte("enriched-proof"),
		PublishedAtUnixN: 310,
	}
	if err := scheduler.CompleteSTHAnchorAttempt(ctx, key, attempt.Generation, "lease-2", result); err != nil {
		t.Fatalf("CompleteSTHAnchorAttempt: %v", err)
	}
	if err := scheduler.CompleteSTHAnchorAttempt(ctx, key, attempt.Generation, "lease-2", result); err != nil {
		t.Fatalf("CompleteSTHAnchorAttempt idempotent retry: %v", err)
	}

	older := result
	older.Proof = []byte("older-proof")
	older.PublishedAtUnixN = 305
	if err := proofstore.STHAnchorResultWriter(store).PutSTHAnchorResult(ctx, older); err != nil {
		t.Fatalf("PutSTHAnchorResult idempotent replacement: %v", err)
	}
	stored, found, err := store.GetSTHAnchorResult(ctx, result.TreeSize)
	if err != nil || !found {
		t.Fatalf("GetSTHAnchorResult found=%v err=%v", found, err)
	}
	if stored.AnchorID != result.AnchorID || !bytes.Equal(stored.Proof, result.Proof) || stored.PublishedAtUnixN != result.PublishedAtUnixN {
		t.Fatalf("stored result was replaced: %+v", stored)
	}
	conflictingAnchorID := result
	conflictingAnchorID.AnchorID = "replacement-anchor"
	if err := proofstore.STHAnchorResultWriter(store).PutSTHAnchorResult(ctx, conflictingAnchorID); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("PutSTHAnchorResult conflicting anchor id error=%v", err)
	}
	conflictingResult := result
	conflictingResult.RootHash = bytes.Repeat([]byte{0x99}, 32)
	conflictingResult.STH.RootHash = append([]byte(nil), conflictingResult.RootHash...)
	if err := proofstore.STHAnchorResultWriter(store).PutSTHAnchorResult(ctx, conflictingResult); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("PutSTHAnchorResult conflicting binding error=%v", err)
	}

	snapshot, found, err := scheduler.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found {
		t.Fatalf("GetSTHAnchorSchedule completed found=%v err=%v", found, err)
	}
	restorer := proofstore.STHAnchorScheduleRestorer(store)
	if err := restorer.PutSTHAnchorSchedule(ctx, snapshot); err != nil {
		t.Fatalf("PutSTHAnchorSchedule idempotent restore: %v", err)
	}
	conflict := snapshot
	conflict.Revision++
	if err := restorer.PutSTHAnchorSchedule(ctx, conflict); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("PutSTHAnchorSchedule conflicting restore error=%v", err)
	}
}

func TestPebbleL5CoverageCheckpointSurvivesRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	store, err := pebblestore.Open(dir)
	if err != nil {
		t.Fatalf("pebble Open: %v", err)
	}
	coverage := proofstore.L5CoverageCheckpointStore(store)
	if _, err := coverage.AdvanceL5CoverageCheckpoint(ctx, key, 17, 100); err != nil {
		t.Fatalf("AdvanceL5CoverageCheckpoint: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	store, err = pebblestore.Open(dir)
	if err != nil {
		t.Fatalf("pebble reopen: %v", err)
	}
	defer store.Close()
	checkpoint, found, err := proofstore.L5CoverageCheckpointStore(store).GetL5CoverageCheckpoint(ctx, key)
	if err != nil || !found || checkpoint.CoveredTreeSize != 17 || checkpoint.Revision != 1 {
		t.Fatalf("restarted checkpoint=%+v found=%v err=%v", checkpoint, found, err)
	}
}

func TestPebbleClaimReconcilesResultBeforeSubmittingPendingWork(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := pebblestore.Open(t.TempDir())
	if err != nil {
		t.Fatalf("pebble Open: %v", err)
	}
	defer store.Close()
	scheduler := proofstore.STHAnchorScheduleStore(store)
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	sth3 := pebbleScheduleSTH(key, 3, 0x33)
	sth5 := pebbleScheduleSTH(key, 5, 0x55)
	if _, err := scheduler.UpsertSTHAnchorCandidate(ctx, model.STHAnchorCandidate{Key: key, STH: sth3, ObservedAtUnixN: 100, DueAtUnixN: 100}); err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate(3): %v", err)
	}
	if _, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, key, 100, 150, "worker-1", "lease-1"); err != nil || !claimed {
		t.Fatalf("ClaimSTHAnchorAttempt(3) claimed=%v err=%v", claimed, err)
	}
	if _, err := scheduler.UpsertSTHAnchorCandidate(ctx, model.STHAnchorCandidate{Key: key, STH: sth5, ObservedAtUnixN: 110, DueAtUnixN: 200}); err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate(5): %v", err)
	}
	result := model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		NodeID:           key.NodeID,
		LogID:            key.LogID,
		TreeSize:         sth3.TreeSize,
		SinkName:         key.SinkName,
		AnchorID:         "anchor-3",
		RootHash:         append([]byte(nil), sth3.RootHash...),
		STH:              sth3,
		Proof:            []byte("proof-3"),
		PublishedAtUnixN: 120,
	}
	if err := proofstore.STHAnchorResultWriter(store).PutSTHAnchorResult(ctx, result); err != nil {
		t.Fatalf("PutSTHAnchorResult: %v", err)
	}
	attempt, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, key, 200, 250, "worker-2", "lease-2")
	if err != nil || !claimed || attempt.Target.TreeSize != sth5.TreeSize {
		t.Fatalf("ClaimSTHAnchorAttempt pending attempt=%+v claimed=%v err=%v", attempt, claimed, err)
	}
	schedule, found, err := scheduler.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || schedule.InFlight == nil || schedule.InFlight.Target.TreeSize != sth5.TreeSize || schedule.Pending != nil {
		t.Fatalf("reconciled schedule found=%v schedule=%+v err=%v", found, schedule, err)
	}
}

func pebbleScheduleSTH(key model.STHAnchorScheduleKey, treeSize uint64, seed byte) model.SignedTreeHead {
	return model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       treeSize,
		RootHash:       bytes.Repeat([]byte{seed}, 32),
		TimestampUnixN: int64(treeSize),
		NodeID:         key.NodeID,
		LogID:          key.LogID,
		Signature: model.Signature{
			Alg:       model.DefaultSignatureAlg,
			KeyID:     "server-key",
			Signature: bytes.Repeat([]byte{seed}, 64),
		},
	}
}
