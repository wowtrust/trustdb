package anchor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
)

// seedPublishedOtsSTH writes an outbox+STHAnchorResult pair into a
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
	if err := store.EnqueueSTHAnchor(ctx, model.STHAnchorOutboxItem{
		SchemaVersion: model.SchemaSTHAnchorOutbox,
		TreeSize:      treeSize,
		SinkName:      OtsSinkName,
		Status:        model.AnchorStatePending,
		STH:           sth,
	}); err != nil {
		t.Fatalf("EnqueueSTHAnchor: %v", err)
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
	if err := store.MarkSTHAnchorPublished(ctx, ar); err != nil {
		t.Fatalf("MarkSTHAnchorPublished: %v", err)
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
// terminal-state outbox without trying to "upgrade" file/noop
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
	if err := store.EnqueueSTHAnchor(ctx, model.STHAnchorOutboxItem{
		SchemaVersion: model.SchemaSTHAnchorOutbox,
		TreeSize:      sth.TreeSize,
		SinkName:      "file",
		Status:        model.AnchorStatePending,
		STH:           sth,
	}); err != nil {
		t.Fatalf("EnqueueSTHAnchor: %v", err)
	}
	if err := store.MarkSTHAnchorPublished(ctx, model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		TreeSize:      sth.TreeSize,
		SinkName:      "file",
		AnchorID:      "file-id",
		RootHash:      sth.RootHash,
		STH:           sth,
		Proof:         []byte("opaque"),
	}); err != nil {
		t.Fatalf("MarkSTHAnchorPublished: %v", err)
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
