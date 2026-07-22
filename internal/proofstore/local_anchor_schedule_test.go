package proofstore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestLocalStoreSTHAnchorScheduleUsesEncodedTuplePath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := LocalStore{Root: t.TempDir()}
	key := model.STHAnchorScheduleKey{
		NodeID:   "../node/东京",
		LogID:    "logs/../../global",
		SinkName: "file/provider one",
	}

	want, err := store.UpsertSTHAnchorCandidate(ctx, localScheduleCandidate(key, 1, 0x11, 100, 200))
	if err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate: %v", err)
	}
	path := store.sthAnchorSchedulePath(key)
	rel, err := filepath.Rel(store.sthAnchorScheduleDir(), path)
	if err != nil {
		t.Fatalf("Rel: %v", err)
	}
	if strings.HasPrefix(rel, "..") || filepath.Dir(rel) != "." {
		t.Fatalf("schedule path escaped tuple directory: %q", rel)
	}
	decoded, err := decodeLocalSTHAnchorScheduleFilename(filepath.Base(path))
	if err != nil {
		t.Fatalf("decodeLocalSTHAnchorScheduleFilename: %v", err)
	}
	if !anchorschedule.SameKey(decoded, key) {
		t.Fatalf("decoded key = %+v, want %+v", decoded, key)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat encoded schedule path: %v", err)
	}

	got, found, err := store.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || !reflect.DeepEqual(got, want) {
		t.Fatalf("GetSTHAnchorSchedule got=%+v found=%v err=%v want=%+v", got, found, err, want)
	}
	listed, err := store.ListSTHAnchorSchedules(ctx)
	if err != nil || len(listed) != 1 || !reflect.DeepEqual(listed[0], want) {
		t.Fatalf("ListSTHAnchorSchedules = %+v err=%v", listed, err)
	}
}

func TestLocalStoreCompleteSTHAnchorAttemptPersistsResultBeforeClear(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := LocalStore{Root: t.TempDir()}
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	sth := localScheduleSTH(key, 3, 0x33)
	if _, err := store.UpsertSTHAnchorCandidate(ctx, model.STHAnchorCandidate{
		Key: key, STH: sth, ObservedAtUnixN: 100, DueAtUnixN: 100,
	}); err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate: %v", err)
	}
	attempt, claimed, err := store.ClaimSTHAnchorAttempt(ctx, key, 100, 200, "worker-1", "lease-1")
	if err != nil || !claimed {
		t.Fatalf("ClaimSTHAnchorAttempt claimed=%v err=%v", claimed, err)
	}
	result := localScheduleResult(key, sth, "anchor-3", 110, []byte("original-proof"))

	// Force the durable result publication to fail. The in-flight state must
	// remain intact because schedule clearing is ordered after the result fsync.
	resultPath := store.sthAnchorResultPath(anchorschedule.ResultKey(result))
	if err := os.MkdirAll(resultPath, 0o755); err != nil {
		t.Fatalf("MkdirAll result collision: %v", err)
	}
	if err := store.CompleteSTHAnchorAttempt(ctx, key, attempt.Generation, "lease-1", result); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("CompleteSTHAnchorAttempt result failure = %v", err)
	}
	schedule, found, err := store.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || schedule.InFlight == nil || schedule.InFlight.LeaseToken != "lease-1" {
		t.Fatalf("schedule after result failure = %+v found=%v err=%v", schedule, found, err)
	}
	if err := os.Remove(resultPath); err != nil {
		t.Fatalf("remove result collision: %v", err)
	}

	// Simulate a crash after the result became durable but before the schedule
	// was cleared. Completion must preserve the stored proof and finish safely.
	if err := store.PutSTHAnchorResult(ctx, result); err != nil {
		t.Fatalf("PutSTHAnchorResult: %v", err)
	}
	retry := result
	retry.Proof = []byte("stale-retry-proof")
	retry.PublishedAtUnixN++
	if attempt, claimed, err := store.ClaimSTHAnchorAttempt(ctx, key, 150, 250, "worker-2", "lease-2"); err != nil || claimed {
		t.Fatalf("ClaimSTHAnchorAttempt after durable result attempt=%+v claimed=%v err=%v", attempt, claimed, err)
	}
	completed, found, err := store.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || completed.InFlight != nil {
		t.Fatalf("completed schedule = %+v found=%v err=%v", completed, found, err)
	}
	stored, found, err := store.GetSTHAnchorResult(ctx, result.TreeSize)
	if err != nil || !found || !bytes.Equal(stored.Proof, result.Proof) || stored.PublishedAtUnixN != result.PublishedAtUnixN {
		t.Fatalf("stored result = %+v found=%v err=%v", stored, found, err)
	}
	if err := store.CompleteSTHAnchorAttempt(ctx, key, attempt.Generation, "", retry); err != nil {
		t.Fatalf("CompleteSTHAnchorAttempt idempotent after clear: %v", err)
	}

	conflictSTH := localScheduleSTH(key, result.TreeSize, 0x99)
	conflict := localScheduleResult(key, conflictSTH, "anchor-conflict", 120, []byte("conflict"))
	if err := store.CompleteSTHAnchorAttempt(ctx, key, attempt.Generation, "lease-1", conflict); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("CompleteSTHAnchorAttempt conflicting binding = %v", err)
	}
}

func TestLocalStorePutSTHAnchorScheduleValidatesRestoreSnapshot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	source := LocalStore{Root: filepath.Join(t.TempDir(), "source")}
	if _, err := source.UpsertSTHAnchorCandidate(ctx, localScheduleCandidate(key, 1, 0x11, 100, 100)); err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate: %v", err)
	}
	if _, claimed, err := source.ClaimSTHAnchorAttempt(ctx, key, 100, 200, "worker", "lease"); err != nil || !claimed {
		t.Fatalf("ClaimSTHAnchorAttempt claimed=%v err=%v", claimed, err)
	}
	leased, found, err := source.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found {
		t.Fatalf("GetSTHAnchorSchedule found=%v err=%v", found, err)
	}

	destination := LocalStore{Root: filepath.Join(t.TempDir(), "destination")}
	if err := destination.PutSTHAnchorSchedule(ctx, leased); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("PutSTHAnchorSchedule leased snapshot = %v", err)
	}
	restored, err := anchorschedule.ClearLeaseForRestore(leased)
	if err != nil {
		t.Fatalf("ClearLeaseForRestore: %v", err)
	}
	if err := destination.PutSTHAnchorSchedule(ctx, restored); err != nil {
		t.Fatalf("PutSTHAnchorSchedule: %v", err)
	}
	if err := destination.PutSTHAnchorSchedule(ctx, restored); err != nil {
		t.Fatalf("PutSTHAnchorSchedule idempotent: %v", err)
	}
	conflict := restored
	conflict.Revision++
	if err := destination.PutSTHAnchorSchedule(ctx, conflict); trusterr.CodeOf(err) != trusterr.CodeAlreadyExists {
		t.Fatalf("PutSTHAnchorSchedule conflicting snapshot = %v", err)
	}

	reconciledDestination := LocalStore{Root: filepath.Join(t.TempDir(), "reconciled-destination")}
	result := localScheduleResult(key, restored.InFlight.Target, "anchor-1", 150, []byte("proof"))
	if err := reconciledDestination.PutSTHAnchorResult(ctx, result); err != nil {
		t.Fatalf("PutSTHAnchorResult before schedule restore: %v", err)
	}
	if err := reconciledDestination.PutSTHAnchorSchedule(ctx, restored); err != nil {
		t.Fatalf("PutSTHAnchorSchedule reconcile completed result: %v", err)
	}
	reconciled, found, err := reconciledDestination.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || reconciled.InFlight != nil {
		t.Fatalf("reconciled restored schedule = %+v found=%v err=%v", reconciled, found, err)
	}
}

func TestLocalStoreSTHAnchorCandidateDoesNotScanResultHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := LocalStore{Root: t.TempDir()}
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	firstSTH := localScheduleSTH(key, 1, 0x11)
	if err := store.PutSTHAnchorResult(ctx, localScheduleResult(key, firstSTH, "anchor-1", 100, []byte("proof"))); err != nil {
		t.Fatalf("PutSTHAnchorResult first: %v", err)
	}

	// A malformed historical filename would make a directory-wide result scan
	// fail. Candidate upserts must use the canonical tree-root point lookup.
	malformed := filepath.Join(store.sthAnchorResultDir(), "malformed"+localAnchorResultSuffix)
	if err := os.WriteFile(malformed, []byte("not-cbor"), 0o600); err != nil {
		t.Fatalf("WriteFile malformed history: %v", err)
	}
	if _, err := store.UpsertSTHAnchorCandidate(ctx, localScheduleCandidate(key, 2, 0x22, 200, 300)); err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate with malformed history: %v", err)
	}
}

func TestLocalStoreSTHAnchorTreeRootRejectsConcurrentSplitViewAcrossSinks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := LocalStore{Root: t.TempDir()}
	keys := []model.STHAnchorScheduleKey{
		{NodeID: "node-1", LogID: "log-1", SinkName: "sink-a"},
		{NodeID: "node-1", LogID: "log-1", SinkName: "sink-b"},
	}

	start := make(chan struct{})
	errs := make([]error, len(keys))
	var wg sync.WaitGroup
	for i, key := range keys {
		wg.Add(1)
		go func(i int, key model.STHAnchorScheduleKey) {
			defer wg.Done()
			<-start
			_, errs[i] = store.UpsertSTHAnchorCandidate(ctx, localScheduleCandidate(key, 7, byte(0x70+i), 100, 200))
		}(i, key)
	}
	close(start)
	wg.Wait()

	succeeded, rejected := 0, 0
	for _, err := range errs {
		if err == nil {
			succeeded++
			continue
		}
		switch trusterr.CodeOf(err) {
		case trusterr.CodeDataLoss:
			rejected++
		default:
			t.Fatalf("unexpected concurrent upsert error: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent split view succeeded=%d rejected=%d errors=%v", succeeded, rejected, errs)
	}
}

func TestLocalStoreL5CoverageCheckpointSurvivesRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
	first := LocalStore{Root: root}
	if _, err := first.AdvanceL5CoverageCheckpoint(ctx, key, 17, 100); err != nil {
		t.Fatalf("AdvanceL5CoverageCheckpoint: %v", err)
	}
	restarted := LocalStore{Root: root}
	checkpoint, found, err := restarted.GetL5CoverageCheckpoint(ctx, key)
	if err != nil || !found || checkpoint.CoveredTreeSize != 17 || checkpoint.Revision != 1 {
		t.Fatalf("restarted checkpoint=%+v found=%v err=%v", checkpoint, found, err)
	}
}

func localScheduleCandidate(key model.STHAnchorScheduleKey, treeSize uint64, seed byte, observedAt, dueAt int64) model.STHAnchorCandidate {
	return model.STHAnchorCandidate{
		Key: key, STH: localScheduleSTH(key, treeSize, seed), ObservedAtUnixN: observedAt, DueAtUnixN: dueAt,
	}
}

func localScheduleSTH(key model.STHAnchorScheduleKey, treeSize uint64, seed byte) model.SignedTreeHead {
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

func localScheduleResult(key model.STHAnchorScheduleKey, sth model.SignedTreeHead, anchorID string, publishedAt int64, proof []byte) model.STHAnchorResult {
	return model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		NodeID:           key.NodeID,
		LogID:            key.LogID,
		TreeSize:         sth.TreeSize,
		SinkName:         key.SinkName,
		AnchorID:         anchorID,
		RootHash:         append([]byte(nil), sth.RootHash...),
		STH:              sth,
		Proof:            append([]byte(nil), proof...),
		PublishedAtUnixN: publishedAt,
	}
}
