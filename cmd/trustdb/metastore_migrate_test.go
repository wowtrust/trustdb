package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
)

type seedCounts struct {
	manifests       int
	bundles         int
	roots           int
	globalLeaves    int
	globalNodes     int
	globalState     bool
	sths            int
	globalTiles     int
	anchorResults   int
	anchorSchedules int
}

// seedFileStore populates a file-backed proofstore with a representative
// mixture of manifests, bundles, roots, global log artefacts, immutable STH
// anchor results, scheduler state, and node-local/derived checkpoints so
// migration can verify that only portable data is copied.
// It returns the counts used by the assertions so the test body does not
// have to hard-code magic numbers that would drift whenever the seed changes.
func seedFileStore(t *testing.T, dir string) seedCounts {
	t.Helper()
	ctx := context.Background()
	store, err := proofstore.Open(proofstore.Config{Kind: proofstore.BackendFile, Path: dir})
	if err != nil {
		t.Fatalf("open file proofstore: %v", err)
	}

	// Two manifests: one committed with 2 bundles, one prepared with a
	// single bundle. The committed manifest's bundles also drive the
	// total bundle count.
	committed := model.BatchManifest{
		SchemaVersion:   model.SchemaBatchManifest,
		BatchID:         "batch-1",
		State:           model.BatchStateCommitted,
		RecordIDs:       []string{"rec-1", "rec-2"},
		BatchRoot:       []byte{0x01, 0x02},
		TreeSize:        2,
		ClosedAtUnixN:   100,
		PreparedAtUnixN: 90,
	}
	prepared := model.BatchManifest{
		SchemaVersion:   model.SchemaBatchManifest,
		BatchID:         "batch-2",
		State:           model.BatchStatePrepared,
		RecordIDs:       []string{"rec-3"},
		BatchRoot:       []byte{0x03},
		TreeSize:        1,
		ClosedAtUnixN:   200,
		PreparedAtUnixN: 195,
	}
	if err := store.PutManifest(ctx, committed); err != nil {
		t.Fatalf("PutManifest committed: %v", err)
	}
	if err := store.PutManifest(ctx, prepared); err != nil {
		t.Fatalf("PutManifest prepared: %v", err)
	}

	for _, recID := range []string{"rec-1", "rec-2", "rec-3"} {
		bundle := model.ProofBundle{
			SchemaVersion: model.SchemaProofBundle,
			RecordID:      recID,
		}
		if err := store.PutBundle(ctx, bundle); err != nil {
			t.Fatalf("PutBundle %s: %v", recID, err)
		}
	}

	for i, ts := range []int64{100, 200} {
		root := model.BatchRoot{
			SchemaVersion: model.SchemaBatchRoot,
			BatchID:       []string{"batch-1", "batch-2"}[i],
			BatchRoot:     []byte{byte(i)},
			TreeSize:      uint64(i + 1),
			ClosedAtUnixN: ts,
		}
		if err := store.PutRoot(ctx, root); err != nil {
			t.Fatalf("PutRoot %d: %v", i, err)
		}
	}

	cp := model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpoint,
		SegmentID:     3,
		LastSequence:  42,
		LastOffset:    123,
	}
	if err := store.PutCheckpoint(ctx, cp); err != nil {
		t.Fatalf("PutCheckpoint: %v", err)
	}

	leaf := model.GlobalLogLeaf{
		SchemaVersion:      model.SchemaGlobalLogLeaf,
		BatchID:            "batch-1",
		BatchRoot:          []byte{0x01, 0x02},
		BatchTreeSize:      2,
		BatchClosedAtUnixN: 100,
		LeafIndex:          0,
		LeafHash:           []byte{0xaa},
		AppendedAtUnixN:    300,
	}
	if err := store.PutGlobalLeaf(ctx, leaf); err != nil {
		t.Fatalf("PutGlobalLeaf: %v", err)
	}
	node := model.GlobalLogNode{
		SchemaVersion:  model.SchemaGlobalLogNode,
		Level:          0,
		StartIndex:     0,
		Width:          1,
		Hash:           []byte{0xaa},
		CreatedAtUnixN: 300,
	}
	if err := store.PutGlobalLogNode(ctx, node); err != nil {
		t.Fatalf("PutGlobalLogNode: %v", err)
	}
	if err := store.PutGlobalLogState(ctx, model.GlobalLogState{
		SchemaVersion:  model.SchemaGlobalLogState,
		TreeSize:       1,
		RootHash:       bytes.Repeat([]byte{0xaa}, 32),
		Frontier:       [][]byte{bytes.Repeat([]byte{0xaa}, 32)},
		UpdatedAtUnixN: 300,
	}); err != nil {
		t.Fatalf("PutGlobalLogState: %v", err)
	}
	sth := model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       1,
		RootHash:       bytes.Repeat([]byte{0xaa}, 32),
		TimestampUnixN: 301,
		NodeID:         "node-1",
		LogID:          "test-log",
		Signature:      model.Signature{Alg: model.DefaultSignatureAlg, KeyID: "test", Signature: []byte{1}},
	}
	if err := store.PutSignedTreeHead(ctx, sth); err != nil {
		t.Fatalf("PutSignedTreeHead: %v", err)
	}
	tile := model.GlobalLogTile{
		SchemaVersion:  model.SchemaGlobalLogTile,
		Level:          0,
		StartIndex:     0,
		Width:          1,
		Hashes:         [][]byte{{0xaa}},
		Compressed:     true,
		CreatedAtUnixN: 302,
	}
	if err := store.PutGlobalLogTile(ctx, tile); err != nil {
		t.Fatalf("PutGlobalLogTile: %v", err)
	}
	anchorKey := model.STHAnchorScheduleKey{NodeID: sth.NodeID, LogID: sth.LogID, SinkName: "file"}
	result := model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		NodeID:           anchorKey.NodeID,
		LogID:            anchorKey.LogID,
		TreeSize:         1,
		SinkName:         anchorKey.SinkName,
		AnchorID:         "anchor-1",
		RootHash:         append([]byte(nil), sth.RootHash...),
		STH:              sth,
		Proof:            []byte(`{"ok":true}`),
		PublishedAtUnixN: 304,
	}
	resultWriter := any(store).(proofstore.STHAnchorResultWriter)
	if err := resultWriter.PutSTHAnchorResult(ctx, result); err != nil {
		t.Fatalf("PutSTHAnchorResult: %v", err)
	}

	scheduler := any(store).(proofstore.STHAnchorScheduleStore)
	inFlightSTH := sth
	inFlightSTH.TreeSize = 2
	inFlightSTH.RootHash = bytes.Repeat([]byte{0xbb}, 32)
	inFlightSTH.TimestampUnixN = 400
	if _, err := scheduler.UpsertSTHAnchorCandidate(ctx, model.STHAnchorCandidate{Key: anchorKey, STH: inFlightSTH, ObservedAtUnixN: 400, DueAtUnixN: 400}); err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate in-flight: %v", err)
	}
	attempt, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, anchorKey, 400, 450, "worker-1", "lease-1")
	if err != nil || !claimed {
		t.Fatalf("ClaimSTHAnchorAttempt initial claimed=%v err=%v", claimed, err)
	}
	if err := scheduler.RescheduleSTHAnchorAttempt(ctx, anchorKey, attempt.Generation, "lease-1", 2, 500, "temporary outage"); err != nil {
		t.Fatalf("RescheduleSTHAnchorAttempt: %v", err)
	}
	if _, claimed, err := scheduler.ClaimSTHAnchorAttempt(ctx, anchorKey, 500, 550, "worker-2", "lease-2"); err != nil || !claimed {
		t.Fatalf("ClaimSTHAnchorAttempt retry claimed=%v err=%v", claimed, err)
	}
	pendingSTH := inFlightSTH
	pendingSTH.TreeSize = 3
	pendingSTH.RootHash = bytes.Repeat([]byte{0xcc}, 32)
	pendingSTH.TimestampUnixN = 510
	if _, err := scheduler.UpsertSTHAnchorCandidate(ctx, model.STHAnchorCandidate{Key: anchorKey, STH: pendingSTH, ObservedAtUnixN: 510, DueAtUnixN: 610}); err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate pending: %v", err)
	}
	coverage := any(store).(proofstore.L5CoverageCheckpointStore)
	if _, err := coverage.AdvanceL5CoverageCheckpoint(ctx, anchorKey, 1, 520); err != nil {
		t.Fatalf("AdvanceL5CoverageCheckpoint: %v", err)
	}

	return seedCounts{
		manifests:       2,
		bundles:         3,
		roots:           2,
		globalLeaves:    1,
		globalNodes:     1,
		globalState:     true,
		sths:            1,
		globalTiles:     1,
		anchorResults:   1,
		anchorSchedules: 1,
	}
}

// TestMetastoreMigrateCopiesEverything runs the CLI end-to-end against a
// pre-populated file store and verifies the Pebble destination ends up
// with byte-equivalent portable manifests, bundles, and roots.
func TestMetastoreMigrateCopiesEverything(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	fromDir := filepath.Join(tmp, "file")
	toDir := filepath.Join(tmp, "pebble")
	want := seedFileStore(t, fromDir)

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"metastore", "migrate", "--from", fromDir, "--to", toDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("metastore migrate error = %v stderr=%s", err, errOut.String())
	}
	var report map[string]any
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("migrate output is not json: %q err=%v", out.String(), err)
	}
	if report["manifests"] != float64(want.manifests) {
		t.Fatalf("manifests = %v, want %d", report["manifests"], want.manifests)
	}
	if report["bundles"] != float64(want.bundles) {
		t.Fatalf("bundles = %v, want %d", report["bundles"], want.bundles)
	}
	if report["roots"] != float64(want.roots) {
		t.Fatalf("roots = %v, want %d", report["roots"], want.roots)
	}
	if report["global_leaves"] != float64(want.globalLeaves) {
		t.Fatalf("global_leaves = %v, want %d", report["global_leaves"], want.globalLeaves)
	}
	if report["global_nodes"] != float64(want.globalNodes) {
		t.Fatalf("global_nodes = %v, want %d", report["global_nodes"], want.globalNodes)
	}
	if report["global_state"] != want.globalState {
		t.Fatalf("global_state = %v, want %v", report["global_state"], want.globalState)
	}
	if report["sths"] != float64(want.sths) {
		t.Fatalf("sths = %v, want %d", report["sths"], want.sths)
	}
	if report["global_tiles"] != float64(want.globalTiles) {
		t.Fatalf("global_tiles = %v, want %d", report["global_tiles"], want.globalTiles)
	}
	if report["anchor_results"] != float64(want.anchorResults) {
		t.Fatalf("anchor_results = %v, want %d", report["anchor_results"], want.anchorResults)
	}
	if report["anchor_schedules"] != float64(want.anchorSchedules) {
		t.Fatalf("anchor_schedules = %v, want %d", report["anchor_schedules"], want.anchorSchedules)
	}
	if _, present := report["checkpoint"]; present {
		t.Fatalf("node-local checkpoint unexpectedly appeared in report: %+v", report)
	}

	// Verify destination content.
	ctx := context.Background()
	dst, err := proofstore.Open(proofstore.Config{Kind: proofstore.BackendPebble, Path: toDir})
	if err != nil {
		t.Fatalf("open pebble dst: %v", err)
	}
	defer dst.Close()

	gotManifests, err := dst.ListManifests(ctx)
	if err != nil {
		t.Fatalf("dst ListManifests: %v", err)
	}
	if len(gotManifests) != want.manifests {
		t.Fatalf("dst manifests len = %d, want %d", len(gotManifests), want.manifests)
	}
	gotRoots, err := dst.ListRoots(ctx, 10)
	if err != nil {
		t.Fatalf("dst ListRoots: %v", err)
	}
	if len(gotRoots) != want.roots {
		t.Fatalf("dst roots len = %d, want %d", len(gotRoots), want.roots)
	}
	if gotRoots[0].ClosedAtUnixN != 200 {
		t.Fatalf("dst latest root = %d, want newest-first (200)", gotRoots[0].ClosedAtUnixN)
	}
	if cp, ok, err := dst.GetCheckpoint(ctx); err != nil || ok {
		t.Fatalf("dst GetCheckpoint = %+v ok=%v err=%v, want absent node-local state", cp, ok, err)
	}
	for _, recID := range []string{"rec-1", "rec-2", "rec-3"} {
		bundle, err := dst.GetBundle(ctx, recID)
		if err != nil {
			t.Fatalf("dst GetBundle %s: %v", recID, err)
		}
		if bundle.RecordID != recID {
			t.Fatalf("dst bundle %s = %+v", recID, bundle)
		}
	}
	leaves, err := dst.ListGlobalLeaves(ctx)
	if err != nil {
		t.Fatalf("dst ListGlobalLeaves: %v", err)
	}
	if len(leaves) != want.globalLeaves {
		t.Fatalf("dst global leaves len = %d, want %d", len(leaves), want.globalLeaves)
	}
	if _, ok, err := dst.GetGlobalLogNode(ctx, 0, 0); err != nil || !ok {
		t.Fatalf("dst GetGlobalLogNode ok=%v err=%v", ok, err)
	}
	if _, ok, err := dst.GetGlobalLogState(ctx); err != nil || !ok {
		t.Fatalf("dst GetGlobalLogState ok=%v err=%v", ok, err)
	}
	if _, ok, err := dst.GetSignedTreeHead(ctx, 1); err != nil || !ok {
		t.Fatalf("dst GetSignedTreeHead ok=%v err=%v", ok, err)
	}
	tiles, err := dst.ListGlobalLogTiles(ctx)
	if err != nil {
		t.Fatalf("dst ListGlobalLogTiles: %v", err)
	}
	if len(tiles) != want.globalTiles {
		t.Fatalf("dst global tiles len = %d, want %d", len(tiles), want.globalTiles)
	}
	result, ok, err := dst.GetSTHAnchorResult(ctx, 1)
	if err != nil || !ok || result.AnchorID != "anchor-1" {
		t.Fatalf("dst GetSTHAnchorResult result=%+v ok=%v err=%v", result, ok, err)
	}
	anchorKey := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "test-log", SinkName: "file"}
	scheduler := any(dst).(proofstore.STHAnchorScheduleStore)
	schedule, ok, err := scheduler.GetSTHAnchorSchedule(ctx, anchorKey)
	if err != nil || !ok {
		t.Fatalf("dst GetSTHAnchorSchedule schedule=%+v ok=%v err=%v", schedule, ok, err)
	}
	if schedule.InFlight == nil || schedule.InFlight.Target.TreeSize != 2 || schedule.InFlight.Attempts != 2 || schedule.InFlight.NextAttemptUnixN != 500 || schedule.InFlight.LastAttemptUnixN != 500 || schedule.InFlight.LastErrorMessage != "temporary outage" {
		t.Fatalf("dst in-flight schedule = %+v", schedule.InFlight)
	}
	if schedule.InFlight.LeaseOwner != "" || schedule.InFlight.LeaseToken != "" || schedule.InFlight.LeaseUntilUnixN != 0 {
		t.Fatalf("dst schedule retained process lease = %+v", schedule.InFlight)
	}
	if schedule.Pending == nil || schedule.Pending.Target.TreeSize != 3 || schedule.Pending.OpenedAtUnixN != 510 || schedule.Pending.DueAtUnixN != 610 {
		t.Fatalf("dst pending schedule = %+v", schedule.Pending)
	}
	coverage := any(dst).(proofstore.L5CoverageCheckpointStore)
	if checkpoint, found, err := coverage.GetL5CoverageCheckpoint(ctx, anchorKey); err != nil || found {
		t.Fatalf("dst derived L5 checkpoint=%+v found=%v err=%v, want absent", checkpoint, found, err)
	}
}

func TestMetastoreMigrateResumesAfterManifestOnlyInterruption(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	fromDir := filepath.Join(tmp, "file")
	toDir := filepath.Join(tmp, "pebble")
	_ = seedFileStore(t, fromDir)
	ctx := context.Background()
	src := &proofstore.LocalStore{Root: fromDir}
	manifest, err := src.GetManifest(ctx, "batch-1")
	if err != nil {
		t.Fatalf("source GetManifest() error = %v", err)
	}
	dst, err := proofstore.Open(proofstore.Config{Kind: proofstore.BackendPebble, Path: toDir})
	if err != nil {
		t.Fatalf("open interrupted destination error = %v", err)
	}
	if err := dst.PutManifest(ctx, manifest); err != nil {
		t.Fatalf("seed interrupted manifest error = %v", err)
	}
	if err := dst.Close(); err != nil {
		t.Fatalf("close interrupted destination error = %v", err)
	}

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"metastore", "migrate", "--from", fromDir, "--to", toDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("resumed metastore migrate error = %v stderr=%s", err, errOut.String())
	}
	dst, err = proofstore.Open(proofstore.Config{Kind: proofstore.BackendPebble, Path: toDir})
	if err != nil {
		t.Fatalf("reopen resumed destination error = %v", err)
	}
	defer dst.Close()
	for _, recordID := range manifest.RecordIDs {
		if _, err := dst.GetBundle(ctx, recordID); err != nil {
			t.Fatalf("resumed destination GetBundle(%q) error = %v", recordID, err)
		}
	}
}

// TestMetastoreMigrateIsIdempotent verifies that running migrate twice
// against the same destination results in the destination containing
// each key exactly once and the second run skipping rather than
// overwriting (with --overwrite=false, which is the default).
func TestMetastoreMigrateIsIdempotent(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	fromDir := filepath.Join(tmp, "file")
	toDir := filepath.Join(tmp, "pebble")
	_ = seedFileStore(t, fromDir)

	for run := 0; run < 2; run++ {
		var out, errOut bytes.Buffer
		cmd := newRootCommand(&out, &errOut)
		cmd.SetArgs([]string{"metastore", "migrate", "--from", fromDir, "--to", toDir})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("run %d migrate error = %v stderr=%s", run, err, errOut.String())
		}
		var report map[string]any
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatalf("run %d output is not json: %q err=%v", run, out.String(), err)
		}
		if run == 1 && report["manifests"] != float64(0) {
			t.Fatalf("run 1 should have skipped everything, got manifests=%v skipped=%v",
				report["manifests"], report["skipped"])
		}
		if run == 1 && report["skipped"].(float64) == 0 {
			t.Fatalf("run 1 should have non-zero skipped, got %+v", report)
		}
	}

	ctx := context.Background()
	dst, err := proofstore.Open(proofstore.Config{Kind: proofstore.BackendPebble, Path: toDir})
	if err != nil {
		t.Fatalf("open dst: %v", err)
	}
	defer dst.Close()

	gotRoots, err := dst.ListRoots(ctx, 100)
	if err != nil {
		t.Fatalf("dst ListRoots: %v", err)
	}
	// After two runs, the destination should contain exactly the two
	// original roots, not four — the second run must not duplicate.
	if len(gotRoots) != 2 {
		t.Fatalf("dst roots after idempotent runs = %d, want 2", len(gotRoots))
	}
}

func TestMetastoreMigrateOverwriteReplacesAnchorSchedule(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	fromDir := filepath.Join(tmp, "file")
	toDir := filepath.Join(tmp, "pebble")
	_ = seedFileStore(t, fromDir)
	runMigrate := func(overwrite bool) {
		t.Helper()
		var out, errOut bytes.Buffer
		cmd := newRootCommand(&out, &errOut)
		args := []string{"metastore", "migrate", "--from", fromDir, "--to", toDir}
		if overwrite {
			args = append(args, "--overwrite")
		}
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("metastore migrate overwrite=%v error=%v stderr=%s", overwrite, err, errOut.String())
		}
	}

	runMigrate(false)
	ctx := context.Background()
	dst, err := proofstore.Open(proofstore.Config{Kind: proofstore.BackendPebble, Path: toDir})
	if err != nil {
		t.Fatal(err)
	}
	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "test-log", SinkName: "file"}
	scheduler := any(dst).(proofstore.STHAnchorScheduleStore)
	higher := model.SignedTreeHead{
		SchemaVersion: model.SchemaSignedTreeHead, TreeAlg: model.DefaultMerkleTreeAlg,
		TreeSize: 4, RootHash: bytes.Repeat([]byte{0xdd}, 32), TimestampUnixN: 620,
		NodeID: key.NodeID, LogID: key.LogID,
		Signature: model.Signature{Alg: model.DefaultSignatureAlg, KeyID: "test", Signature: []byte{4}},
	}
	if _, err := scheduler.UpsertSTHAnchorCandidate(ctx, model.STHAnchorCandidate{
		Key: key, STH: higher, ObservedAtUnixN: 620, DueAtUnixN: 720,
	}); err != nil {
		t.Fatalf("mutate destination schedule: %v", err)
	}
	mutated, found, err := scheduler.GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || mutated.Pending == nil || mutated.Pending.Target.TreeSize != 4 {
		t.Fatalf("mutated schedule=%+v found=%v err=%v", mutated, found, err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}

	runMigrate(true)
	dst, err = proofstore.Open(proofstore.Config{Kind: proofstore.BackendPebble, Path: toDir})
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	restored, found, err := any(dst).(proofstore.STHAnchorScheduleStore).GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found {
		t.Fatalf("restored schedule=%+v found=%v err=%v", restored, found, err)
	}
	if restored.Pending == nil || restored.Pending.Target.TreeSize != 3 {
		t.Fatalf("overwrite retained destination scheduler mutation: %+v", restored.Pending)
	}
}
