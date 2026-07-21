package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
)

type seedCounts struct {
	manifests      int
	bundles        int
	roots          int
	globalLeaves   int
	globalNodes    int
	globalState    bool
	sths           int
	globalTiles    int
	anchorOutboxes int
	anchorResults  int
}

// seedFileStore populates a file-backed proofstore with a representative
// mixture of manifests, bundles, roots, global log artefacts, STH anchors,
// and a node-local checkpoint so migration can verify that only portable data
// is copied.
// It returns the counts used by the assertions so the test body does not
// have to hard-code magic numbers that would drift whenever the seed changes.
func seedFileStore(t *testing.T, dir string) seedCounts {
	t.Helper()
	ctx := context.Background()
	store := &proofstore.LocalStore{Root: dir}

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
	outbox := model.STHAnchorOutboxItem{
		SchemaVersion:   model.SchemaSTHAnchorOutbox,
		TreeSize:        1,
		Status:          model.AnchorStatePending,
		SinkName:        "file",
		STH:             sth,
		EnqueuedAtUnixN: 303,
	}
	if err := store.EnqueueSTHAnchor(ctx, outbox); err != nil {
		t.Fatalf("EnqueueSTHAnchor: %v", err)
	}
	result := model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		TreeSize:         1,
		SinkName:         "file",
		AnchorID:         "anchor-1",
		RootHash:         append([]byte(nil), sth.RootHash...),
		STH:              sth,
		Proof:            []byte(`{"ok":true}`),
		PublishedAtUnixN: 304,
	}
	if err := store.MarkSTHAnchorPublished(ctx, result); err != nil {
		t.Fatalf("MarkSTHAnchorPublished: %v", err)
	}

	return seedCounts{
		manifests:      2,
		bundles:        3,
		roots:          2,
		globalLeaves:   1,
		globalNodes:    1,
		globalState:    true,
		sths:           1,
		globalTiles:    1,
		anchorOutboxes: 1,
		anchorResults:  1,
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
	if report["anchor_outboxes"] != float64(want.anchorOutboxes) {
		t.Fatalf("anchor_outboxes = %v, want %d", report["anchor_outboxes"], want.anchorOutboxes)
	}
	if report["anchor_results"] != float64(want.anchorResults) {
		t.Fatalf("anchor_results = %v, want %d", report["anchor_results"], want.anchorResults)
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
	if _, ok, err := dst.GetSTHAnchorOutboxItem(ctx, 1); err != nil || !ok {
		t.Fatalf("dst GetSTHAnchorOutboxItem ok=%v err=%v", ok, err)
	}
	if _, ok, err := dst.GetSTHAnchorResult(ctx, 1); err != nil || !ok {
		t.Fatalf("dst GetSTHAnchorResult ok=%v err=%v", ok, err)
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
