package anchor

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
)

// seedPublishedOtsSTH writes an immutable STHAnchorResult into a
// file-backed proofstore so the upgrader has a realistic input. The
// proof envelope is laid out by the caller via `mutate` so each test
// can dial in mixed pending/upgraded calendars without duplicating
// boilerplate.
func seedPublishedOtsSTH(
	t *testing.T,
	store proofstore.Store,
	treeSize uint64,
	calendarURLs []string,
	mutate func(p *OtsAnchorProof),
) model.STHAnchorResult {
	t.Helper()
	ctx := context.Background()

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i + 1)
	}
	sth := model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       treeSize,
		RootHash:       digest,
		TimestampUnixN: 100,
		Signature:      model.Signature{Alg: model.DefaultSignatureAlg, KeyID: "test", Signature: []byte{1}},
	}
	if err := store.PutSignedTreeHead(ctx, sth); err != nil {
		t.Fatalf("PutSignedTreeHead: %v", err)
	}
	calendars := make([]OtsCalendarTimestamp, 0, len(calendarURLs))
	for _, u := range calendarURLs {
		calendars = append(calendars, OtsCalendarTimestamp{
			URL:          u,
			Accepted:     true,
			RawTimestamp: []byte("pending-" + u),
			StatusCode:   200,
		})
	}
	proof := OtsAnchorProof{
		SchemaVersion: SchemaOtsAnchorProof,
		TreeSize:      treeSize,
		HashAlg:       "sha256",
		Digest:        digest,
		Calendars:     calendars,
		SubmittedAtN:  time.Now().UnixNano(),
	}
	if mutate != nil {
		mutate(&proof)
	}
	bytes, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	ar := model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		TreeSize:         treeSize,
		SinkName:         OtsSinkName,
		AnchorID:         DeterministicOtsAnchorID(sth),
		RootHash:         digest,
		STH:              sth,
		Proof:            bytes,
		PublishedAtUnixN: time.Now().UnixNano(),
	}
	writer, ok := store.(proofstore.STHAnchorResultWriter)
	if !ok {
		t.Fatal("store does not implement STHAnchorResultWriter")
	}
	if err := writer.PutSTHAnchorResult(ctx, ar); err != nil {
		t.Fatalf("PutSTHAnchorResult: %v", err)
	}
	return ar
}

// TestOtsUpgrader_TickPersistsAndShortCircuits is the headline
// scenario: first tick upgrades a pending calendar and writes the
// new bytes to the store; second tick must NOT issue another HTTP
// GET because the calendar is now Upgraded=true. This is what makes
// the worker safe to leave running forever against the public pool.
func TestOtsUpgrader_TickPersistsAndShortCircuits(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	store := &proofstore.LocalStore{Root: filepath.Join(tmp, "ps")}

	upgraded := []byte("upgraded-with-block-header")
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upgraded)
	}))
	defer srv.Close()

	seeded := seedPublishedOtsSTH(t, store, 1, []string{srv.URL}, nil)

	upgrader, err := NewOtsUpgrader(UpgraderConfig{
		Store:        store,
		HTTPOptions:  OtsUpgradeOptions{HTTPClient: srv.Client()},
		PollInterval: time.Hour, // never fires; we drive ticks directly
	})
	if err != nil {
		t.Fatalf("NewOtsUpgrader: %v", err)
	}

	first := upgrader.TickOnce(context.Background())
	if first.Visited != 1 || first.Changed != 1 || first.CalendarChanged != 1 {
		t.Fatalf("first tick stats unexpected: %+v", first)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("first tick hit count = %d, want 1", got)
	}

	got, ok, err := store.GetSTHAnchorResult(context.Background(), seeded.TreeSize)
	if err != nil || !ok {
		t.Fatalf("GetSTHAnchorResult: ok=%v err=%v", ok, err)
	}
	var after OtsAnchorProof
	if err := json.Unmarshal(got.Proof, &after); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(after.Calendars[0].RawTimestamp) != string(upgraded) {
		t.Fatal("upgraded bytes not persisted")
	}
	if !after.Calendars[0].Upgraded {
		t.Fatal("Upgraded flag not persisted")
	}

	second := upgrader.TickOnce(context.Background())
	if second.Visited != 1 || second.Changed != 0 || second.Unchanged != 1 {
		t.Fatalf("second tick stats unexpected: %+v", second)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("second tick must skip HTTP, hit count = %d", got)
	}
}

// TestOtsUpgrader_StillPendingGaugeReflectsState verifies the
// `still_pending` accounting that drives the
// trustdb_anchor_ots_pending_batches gauge. An STH with a mix of
// pending + upgraded calendars must count as still pending; a fully
// upgraded one must not.
func TestOtsUpgrader_StillPendingGaugeReflectsState(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	store := &proofstore.LocalStore{Root: filepath.Join(tmp, "ps")}

	// Calendar that always returns the *same* bytes the seeder put
	// in, so UpgradeOtsProof observes "no change" and the batch
	// remains partially pending across the tick. We close over the
	// reply bytes so the handler doesn't need to know its own URL.
	const replyBody = "still-pending-bytes"
	pending := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(replyBody))
	}))
	defer pending.Close()

	seedPublishedOtsSTH(t, store, 2, []string{pending.URL, "https://already.example"}, func(p *OtsAnchorProof) {
		// Pending calendar: its RawTimestamp matches the server's
		// reply so UpgradeOtsProof sees Changed=false and the
		// calendar stays Accepted=true / Upgraded=false.
		p.Calendars[0].RawTimestamp = []byte(replyBody)
		// Already-attested calendar: Upgraded=true so the upgrader
		// must short-circuit and not issue any HTTP call.
		p.Calendars[1].Upgraded = true
	})

	upgrader, err := NewOtsUpgrader(UpgraderConfig{
		Store:       store,
		HTTPOptions: OtsUpgradeOptions{HTTPClient: pending.Client()},
	})
	if err != nil {
		t.Fatalf("NewOtsUpgrader: %v", err)
	}
	stats := upgrader.TickOnce(context.Background())
	if stats.Unchanged != 1 || stats.Changed != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if stats.StillPending != 1 {
		t.Fatalf("StillPending = %d, want 1", stats.StillPending)
	}
}

// TestOtsUpgrader_IgnoresNonOtsBatches asserts the worker walks the
// immutable result set without trying to "upgrade" file/noop
// STHAnchorResults. Doing so would attempt to JSON-decode an opaque
// proof and pollute the failure counters with permanent errors.
func TestOtsUpgrader_IgnoresNonOtsSTHs(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	store := &proofstore.LocalStore{Root: filepath.Join(tmp, "ps")}
	ctx := context.Background()

	root := make([]byte, 32)
	root[0] = 0x01
	sth := model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       3,
		RootHash:       root,
		TimestampUnixN: 50,
		Signature:      model.Signature{Alg: model.DefaultSignatureAlg, KeyID: "test", Signature: []byte{1}},
	}
	if err := store.PutSignedTreeHead(ctx, sth); err != nil {
		t.Fatalf("PutSignedTreeHead: %v", err)
	}
	if err := store.PutSTHAnchorResult(ctx, model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		TreeSize:         sth.TreeSize,
		SinkName:         "file",
		AnchorID:         "file-id",
		RootHash:         sth.RootHash,
		STH:              sth,
		Proof:            []byte("opaque"),
		PublishedAtUnixN: 100,
	}); err != nil {
		t.Fatalf("PutSTHAnchorResult: %v", err)
	}

	upgrader, err := NewOtsUpgrader(UpgraderConfig{Store: store})
	if err != nil {
		t.Fatalf("NewOtsUpgrader: %v", err)
	}
	stats := upgrader.TickOnce(ctx)
	if stats.Visited != 0 || stats.Errored != 0 {
		t.Fatalf("non-ots STH must be ignored cheaply, got %+v", stats)
	}
}

func TestOtsUpgraderRotatesPastFirstBatch(t *testing.T) {
	t.Parallel()

	store := &proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "ps")}
	hits := make([]atomic.Int32, 3)
	servers := make([]*httptest.Server, 0, 3)
	for i := range 3 {
		index := i
		reply := []byte{byte('a' + i)}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits[index].Add(1)
			_, _ = w.Write(reply)
		}))
		servers = append(servers, server)
		seedPublishedOtsSTH(t, store, uint64(i+10), []string{server.URL}, func(p *OtsAnchorProof) {
			p.Calendars[0].RawTimestamp = append([]byte(nil), reply...)
		})
	}
	defer func() {
		for _, server := range servers {
			server.Close()
		}
	}()

	upgrader, err := NewOtsUpgrader(UpgraderConfig{
		Store: store, BatchSize: 2, Workers: 1,
		HTTPOptions: OtsUpgradeOptions{HTTPClient: servers[0].Client()},
	})
	if err != nil {
		t.Fatal(err)
	}
	first := upgrader.TickOnce(context.Background())
	second := upgrader.TickOnce(context.Background())
	if first.Visited != 2 || second.Visited != 2 {
		t.Fatalf("rotating tick visits first=%+v second=%+v", first, second)
	}
	if got := hits[0].Load(); got != 1 {
		t.Fatalf("oldest OTS result hits=%d, want 1 after historical backfill", got)
	}
	if got := hits[2].Load(); got != 2 {
		t.Fatalf("newest pending OTS result hits=%d, want one prompt probe per tick", got)
	}
}

func TestOtsUpgraderPrioritizesNewestOtsAfterNonOtsHistory(t *testing.T) {
	t.Parallel()
	store := &proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "ps")}
	writer := any(store).(proofstore.STHAnchorResultWriter)
	for treeSize := uint64(1); treeSize <= 20; treeSize++ {
		root := bytes.Repeat([]byte{byte(treeSize)}, 32)
		sth := model.SignedTreeHead{
			SchemaVersion: model.SchemaSignedTreeHead, TreeAlg: model.DefaultMerkleTreeAlg,
			TreeSize: treeSize, RootHash: root, TimestampUnixN: int64(treeSize),
			Signature: model.Signature{Alg: model.DefaultSignatureAlg, KeyID: "file-key", Signature: []byte{1}},
		}
		if err := writer.PutSTHAnchorResult(context.Background(), model.STHAnchorResult{
			SchemaVersion: model.SchemaSTHAnchorResult, TreeSize: treeSize, SinkName: "file",
			AnchorID: "file-anchor-" + time.Unix(int64(treeSize), 0).Format("150405"), RootHash: root,
			STH: sth, Proof: []byte("opaque"), PublishedAtUnixN: int64(treeSize),
		}); err != nil {
			t.Fatalf("PutSTHAnchorResult(file %d): %v", treeSize, err)
		}
	}

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("attested-newest"))
	}))
	defer server.Close()
	seedPublishedOtsSTH(t, store, 21, []string{server.URL}, nil)

	upgrader, err := NewOtsUpgrader(UpgraderConfig{
		Store: store, BatchSize: 4, Workers: 1,
		HTTPOptions: OtsUpgradeOptions{HTTPClient: server.Client()},
	})
	if err != nil {
		t.Fatalf("NewOtsUpgrader: %v", err)
	}
	stats := upgrader.TickOnce(context.Background())
	if stats.Visited != 1 || stats.Changed != 1 || hits.Load() != 1 {
		t.Fatalf("newest OTS result was not prioritized: stats=%+v hits=%d", stats, hits.Load())
	}
}

func TestNewOtsUpgraderRejectsBatchAboveStorePageLimit(t *testing.T) {
	t.Parallel()
	store := &proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "ps")}
	if _, err := NewOtsUpgrader(UpgraderConfig{Store: store, BatchSize: MaxOtsUpgradeBatchSize + 1}); err == nil {
		t.Fatal("NewOtsUpgrader accepted a batch larger than the store page limit")
	}
}

func TestPersistOtsAnchorResultUpgradeMergesConcurrentCalendars(t *testing.T) {
	t.Parallel()
	store := &proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "ps")}
	original := seedPublishedOtsSTH(t, store, 40, []string{"https://calendar-a.example", "https://calendar-b.example"}, nil)
	reader := any(store).(proofstore.STHAnchorResultKeyedReader)
	updater := any(store).(proofstore.STHAnchorResultUpdater)

	upgrade := func(index int, raw string) model.STHAnchorResult {
		candidate := original
		var proof OtsAnchorProof
		if err := json.Unmarshal(candidate.Proof, &proof); err != nil {
			t.Fatalf("decode candidate proof: %v", err)
		}
		proof.Calendars[index].RawTimestamp = []byte(raw)
		proof.Calendars[index].Upgraded = true
		encoded, err := json.Marshal(proof)
		if err != nil {
			t.Fatalf("encode candidate proof: %v", err)
		}
		candidate.Proof = encoded
		return candidate
	}

	first := upgrade(0, "attested-a")
	if _, changed, err := PersistOtsAnchorResultUpgrade(context.Background(), reader, updater, original, first); err != nil || !changed {
		t.Fatalf("persist first upgrade changed=%v err=%v", changed, err)
	}
	second := upgrade(1, "attested-b")
	merged, changed, err := PersistOtsAnchorResultUpgrade(context.Background(), reader, updater, original, second)
	if err != nil || !changed {
		t.Fatalf("persist stale second upgrade changed=%v err=%v", changed, err)
	}
	var proof OtsAnchorProof
	if err := json.Unmarshal(merged.Proof, &proof); err != nil {
		t.Fatalf("decode merged proof: %v", err)
	}
	if !proof.Calendars[0].Upgraded || string(proof.Calendars[0].RawTimestamp) != "attested-a" ||
		!proof.Calendars[1].Upgraded || string(proof.Calendars[1].RawTimestamp) != "attested-b" {
		t.Fatalf("merged calendars = %+v", proof.Calendars)
	}
	stored, found, err := reader.GetSTHAnchorResultForKey(context.Background(), anchorschedule.ResultKey(original))
	if err != nil || !found || !bytes.Equal(stored.Proof, merged.Proof) {
		t.Fatalf("stored merged result found=%v err=%v", found, err)
	}
}

// TestOtsUpgrader_MarkUpgradedAfterChange confirms the persisted
// envelope ends up with both upgraded bytes AND Upgraded=true so the
// next sweep is HTTP-free even after a process restart.
func TestOtsUpgrader_MarkUpgradedAfterChange(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	store := &proofstore.LocalStore{Root: filepath.Join(tmp, "ps")}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("attested-bytes"))
	}))
	defer srv.Close()

	seeded := seedPublishedOtsSTH(t, store, 4, []string{srv.URL}, nil)
	upgrader, _ := NewOtsUpgrader(UpgraderConfig{
		Store:       store,
		HTTPOptions: OtsUpgradeOptions{HTTPClient: srv.Client()},
	})
	upgrader.TickOnce(context.Background())

	got, ok, err := store.GetSTHAnchorResult(context.Background(), seeded.TreeSize)
	if err != nil || !ok {
		t.Fatalf("GetSTHAnchorResult: ok=%v err=%v", ok, err)
	}
	var after OtsAnchorProof
	if err := json.Unmarshal(got.Proof, &after); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !after.AllUpgraded() {
		t.Fatal("AllUpgraded must be true after a single-calendar change")
	}
}

// TestOtsUpgrader_StartStopIsIdempotent guards the lifecycle
// surface. Multiple Start/Stop calls must not panic and Stop on a
// never-started upgrader is a no-op.
func TestOtsUpgrader_StartStopIsIdempotent(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	store := &proofstore.LocalStore{Root: filepath.Join(tmp, "ps")}
	upgrader, _ := NewOtsUpgrader(UpgraderConfig{Store: store, PollInterval: 24 * time.Hour})

	upgrader.Stop() // never started: no-op
	upgrader.Start(context.Background())
	upgrader.Start(context.Background()) // second Start must be no-op
	upgrader.Stop()
	upgrader.Stop()
}

func TestOtsUpgrader_ContextCancellationAllowsRestart(t *testing.T) {
	t.Parallel()
	store := &proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "ps")}
	upgrader, err := NewOtsUpgrader(UpgraderConfig{Store: store, PollInterval: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	upgrader.Start(ctx)
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for {
		upgrader.mu.Lock()
		stopped := !upgrader.running
		upgrader.mu.Unlock()
		if stopped {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("OTS upgrader did not clear running state after context cancellation")
		}
		time.Sleep(time.Millisecond)
	}
	restartCtx, restartCancel := context.WithCancel(context.Background())
	defer restartCancel()
	upgrader.Start(restartCtx)
	upgrader.mu.Lock()
	restarted := upgrader.running
	upgrader.mu.Unlock()
	if !restarted {
		t.Fatal("OTS upgrader did not restart after context cancellation")
	}
	upgrader.Stop()
}

// TestUpgraderTickStatsZeroValueIsSafe documents the contract that
// callers can use the zero-value UpgraderTickStats as a starting
// accumulator without nil checks.
func TestUpgraderTickStatsZeroValueIsSafe(t *testing.T) {
	t.Parallel()
	var s UpgraderTickStats
	if s.Visited != 0 || s.Changed != 0 {
		t.Fatal("zero value should be all zeros")
	}
}
