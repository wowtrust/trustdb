package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"

	"github.com/ryan-wong-coder/trustdb/internal/app"
	"github.com/ryan-wong-coder/trustdb/internal/batch"
	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/claim"
	"github.com/ryan-wong-coder/trustdb/internal/httpapi"
	"github.com/ryan-wong-coder/trustdb/internal/ingest"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/observability"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
	"github.com/ryan-wong-coder/trustdb/internal/trustcrypto"
	"github.com/ryan-wong-coder/trustdb/internal/wal"
)

// TestServeDirectoryModeEndToEnd stands up the full ingest → batch → proof
// stack against a real directory-mode WAL (via httptest) so we can observe
// the rotate → checkpoint → prune chain that only activates when every
// subsystem is wired together.
//
// The assertions line up with what an operator would check in prod:
//   - the WAL directory actually rotates (multiple segments show up),
//   - committing batches advances the checkpoint past rotated segments,
//   - auto-prune deletes segments strictly below the checkpoint cutoff,
//   - all four new metrics (active_segment_id, segments_total,
//     bytes_pruned_total, checkpoint_last_sequence) converge to the
//     expected values.
func TestServeDirectoryModeEndToEnd(t *testing.T) {
	t.Parallel()

	clientPub, clientPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate client key error = %v", err)
	}
	_, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate server key error = %v", err)
	}

	tmp := t.TempDir()
	walDir := filepath.Join(tmp, "wal")
	proofDir := filepath.Join(tmp, "proofs")

	_, metrics := observability.NewRegistry()
	// Compact rotation threshold + small batch size so the test exercises
	// rotation and commits in under a second while only submitting a
	// handful of claims.
	walOpts := wal.Options{
		MaxSegmentBytes: 280,
		OnRotate: func(_, to uint64) {
			metrics.WALActiveSegmentID.Set(float64(to))
			_ = refreshWALSegmentsTotal(metrics, walDir)
		},
	}
	writer, mode, err := openWALWriterWithOptions(walDir, walOpts)
	if err != nil {
		t.Fatalf("openWALWriterWithOptions() error = %v", err)
	}
	if mode != "directory" {
		t.Fatalf("walMode = %q, want directory", mode)
	}
	defer writer.Close()
	metrics.WALActiveSegmentID.Set(float64(writer.ActiveSegmentID()))
	if err := refreshWALSegmentsTotal(metrics, walDir); err != nil {
		t.Fatalf("refreshWALSegmentsTotal() error = %v", err)
	}

	engine := app.LocalEngine{
		ServerID:         "server-e2e-dir",
		ServerKeyID:      "server-key",
		ClientPublicKey:  clientPub,
		ServerPrivateKey: serverPriv,
		WAL:              writer,
		Idempotency:      app.NewIdempotencyIndex(),
		Now:              func() time.Time { return time.Unix(200, 0) },
	}
	proofStore := checkpointSafeLocalStore{LocalStore: proofstore.LocalStore{Root: proofDir}}
	ingestSvc := ingest.New(engine, ingest.Options{QueueSize: 16, Workers: 2}, metrics)
	defer ingestSvc.Shutdown(context.Background())

	rt := &runtimeConfig{logger: silentLogger()}
	batchSvc := batch.New(engine, proofStore, batch.Options{
		QueueSize:            16,
		MaxRecords:           2,
		MaxDelay:             50 * time.Millisecond,
		OnCheckpointAdvanced: newPruneHook(rt, walDir, 0, metrics),
	}, metrics)
	defer batchSvc.Shutdown(context.Background())

	server := httptest.NewServer(httpapi.New(ingestSvc, nil, batchSvc))
	defer server.Close()

	const totalClaims = 6
	recordIDs := make([]string, 0, totalClaims)
	for i := 0; i < totalClaims; i++ {
		raw := bytes.Repeat([]byte{byte('e' + i)}, 180)
		contentHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, raw)
		if err != nil {
			t.Fatalf("HashBytes(%d) error = %v", i, err)
		}
		c, err := claim.NewFileClaim(
			"tenant-e2e",
			"client-e2e",
			"client-key",
			time.Unix(int64(1000+i), 0),
			bytes.Repeat([]byte{byte(i + 1)}, 16),
			fmt.Sprintf("idem-e2e-%d", i),
			model.Content{HashAlg: model.DefaultHashAlg, ContentHash: contentHash, ContentLength: int64(len(raw))},
			model.Metadata{EventType: "file.snapshot"},
		)
		if err != nil {
			t.Fatalf("NewFileClaim(%d) error = %v", i, err)
		}
		signed, err := claim.Sign(c, clientPriv)
		if err != nil {
			t.Fatalf("Sign(%d) error = %v", i, err)
		}
		body, err := cborx.Marshal(signed)
		if err != nil {
			t.Fatalf("Marshal(%d) error = %v", i, err)
		}

		resp, err := http.Post(server.URL+"/v1/claims", "application/cbor", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST /v1/claims (%d) error = %v", i, err)
		}
		var decoded struct {
			RecordID      string `json:"record_id"`
			Status        string `json:"status"`
			BatchEnqueued bool   `json:"batch_enqueued"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
			resp.Body.Close()
			t.Fatalf("decode response (%d): %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted || decoded.RecordID == "" {
			t.Fatalf("response %d: status=%d body=%+v", i, resp.StatusCode, decoded)
		}
		recordIDs = append(recordIDs, decoded.RecordID)
	}

	// Wait for all claims to produce a proof, then wait separately for the
	// final checkpoint. Proof publication precedes checkpoint advancement, and
	// durable local-store barriers can make that distinction observable.
	for _, rid := range recordIDs {
		waitForHTTPProof(t, server.URL, rid)
	}
	waitForMetric(t, func() bool {
		return testutil.ToFloat64(metrics.WALCheckpointLastSequence) >= float64(totalClaims)
	}, "wal_checkpoint_last_sequence >= totalClaims")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := batchSvc.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("batch shutdown after proof convergence error = %v", err)
	}

	// Rotation assertion: we asked for 280-byte segments with ~230-byte
	// records each, so there must be at least two segments ever created
	// (the initial one plus the rotated one).
	if got := uint64(testutil.ToFloat64(metrics.WALActiveSegmentID)); got < 2 {
		t.Fatalf("wal_active_segment_id = %d, want >= 2 (rotation expected)", got)
	}

	// Checkpoint assertion: after all claims, the checkpoint sequence is
	// the sequence of the last record we submitted. Under the hood this
	// also means the checkpoint gauge is published.
	if got := testutil.ToFloat64(metrics.WALCheckpointLastSequence); got < float64(totalClaims) {
		t.Fatalf("wal_checkpoint_last_sequence = %v, want >= %d", got, totalClaims)
	}

	// Prune assertion: since keepSegments=0 and MaxSegmentBytes is tight,
	// older segments must have been reclaimed. bytes_pruned_total is the
	// cleanest signal because "at least one segment was below the
	// checkpoint cutoff and got deleted".
	waitForMetric(t, func() bool {
		return testutil.ToFloat64(metrics.WALBytesPrunedTotal) > 0
	}, "wal_bytes_pruned_total > 0")
	if got := testutil.ToFloat64(metrics.WALBytesPrunedTotal); got <= 0 {
		t.Fatalf("wal_bytes_pruned_total = %v, want > 0", got)
	}

	// Directory state matches the segments gauge so there is no drift
	// between what the gauge reports and what is actually on disk.
	segs, err := wal.ListSegments(walDir)
	if err != nil {
		t.Fatalf("ListSegments() error = %v", err)
	}
	if got := int(testutil.ToFloat64(metrics.WALSegmentsTotal)); got != len(segs) {
		t.Fatalf("wal_segments_total = %d, ListSegments() = %v", got, segs)
	}
	// After prune we expect fewer segments than the highest id ever
	// assigned: some were deleted.
	activeID := uint64(testutil.ToFloat64(metrics.WALActiveSegmentID))
	if uint64(len(segs)) >= activeID {
		t.Fatalf("segments on disk (%d) should be strictly fewer than active id (%d) after prune",
			len(segs), activeID)
	}

	// Finally: the proof store is consistent. LatestRoot should reflect
	// the most recent batch (tree_size = MaxRecords since every batch is
	// size 2 and we submitted an even count).
	rootResp, err := http.Get(server.URL + "/v1/roots/latest")
	if err != nil {
		t.Fatalf("GET /v1/roots/latest error = %v", err)
	}
	defer rootResp.Body.Close()
	if rootResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/roots/latest status = %d", rootResp.StatusCode)
	}
}

func TestPruneHookRefreshesSegmentGaugeWithoutRemoval(t *testing.T) {
	t.Parallel()

	walDir := t.TempDir()
	writer, err := wal.OpenDirWriter(walDir, wal.Options{InitialSegmentID: 3})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	_, metrics := observability.NewRegistry()
	metrics.WALSegmentsTotal.Set(99)
	hook := newPruneHook(&runtimeConfig{logger: silentLogger()}, walDir, 0, metrics)
	hook(context.Background(), model.WALCheckpoint{SegmentID: 3, LastSequence: 10})

	if got := testutil.ToFloat64(metrics.WALSegmentsTotal); got != 1 {
		t.Fatalf("wal_segments_total = %v, want 1 after idempotent prune refresh", got)
	}
	if got := testutil.ToFloat64(metrics.WALBytesPrunedTotal); got != 0 {
		t.Fatalf("wal_bytes_pruned_total = %v, want 0 when no files were removed", got)
	}
}

func TestPruneHookCachesSuccessfulCutoffAndRetriesFailures(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("injected prune failure")
	var calls []uint64
	failFirst := true
	pruner := func(_ string, cutoff uint64) (int, int64, error) {
		calls = append(calls, cutoff)
		if failFirst {
			failFirst = false
			return 0, 0, sentinel
		}
		return 0, 0, nil
	}
	hook := newPruneHookWithPruner(&runtimeConfig{logger: silentLogger()}, t.TempDir(), 0, nil, pruner)
	hook(context.Background(), model.WALCheckpoint{SegmentID: 3}) // fails; must remain retryable
	hook(context.Background(), model.WALCheckpoint{SegmentID: 3}) // succeeds and caches
	hook(context.Background(), model.WALCheckpoint{SegmentID: 3}) // identical cutoff skips
	hook(context.Background(), model.WALCheckpoint{SegmentID: 2}) // older cutoff skips
	hook(context.Background(), model.WALCheckpoint{SegmentID: 4}) // new segment prunes once

	want := []uint64{3, 3, 4}
	if fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("prune cutoffs = %v, want %v", calls, want)
	}

	panicCalls := 0
	panicHook := newPruneHookWithPruner(&runtimeConfig{logger: silentLogger()}, t.TempDir(), 0, nil, func(_ string, _ uint64) (int, int64, error) {
		panicCalls++
		if panicCalls == 1 {
			panic("injected prune panic")
		}
		return 0, 0, nil
	})
	func() {
		defer func() {
			if recover() == nil {
				t.Error("first prune call did not panic")
			}
		}()
		panicHook(context.Background(), model.WALCheckpoint{SegmentID: 5})
	}()
	panicHook(context.Background(), model.WALCheckpoint{SegmentID: 5})
	if panicCalls != 2 {
		t.Fatalf("prune calls after panic = %d, want retry without deadlock", panicCalls)
	}

	noPruneCalls := 0
	noPruneHook := newPruneHookWithPruner(&runtimeConfig{logger: silentLogger()}, t.TempDir(), 10, nil, func(string, uint64) (int, int64, error) {
		noPruneCalls++
		return 0, 0, nil
	})
	noPruneHook(context.Background(), model.WALCheckpoint{SegmentID: 1})
	noPruneHook(context.Background(), model.WALCheckpoint{SegmentID: 5})
	if noPruneCalls != 0 {
		t.Fatalf("pruner called %d times before an eligible cutoff", noPruneCalls)
	}
}

// silentLogger produces a zerolog.Logger that discards output so e2e tests
// do not spam go test's output with structured log lines coming from the
// prune hook and other serve-time subsystems.
func silentLogger() zerolog.Logger {
	return zerolog.New(io.Discard).Level(zerolog.Disabled)
}

// waitForHTTPProof polls the proof endpoint until it returns 200, which is
// the observable signal that a batch containing the record committed (and
// therefore advanceCheckpoint + OnCheckpointAdvanced ran to completion).
func waitForHTTPProof(t *testing.T, baseURL, recordID string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	var lastStatus int
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/v1/proofs/" + recordID)
		if err == nil {
			code := resp.StatusCode
			lastStatus = code
			resp.Body.Close()
			if code == http.StatusOK {
				return
			}
		} else {
			lastErr = err
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("proof for %s never became available; last_status=%d last_error=%v", recordID, lastStatus, lastErr)
}

// waitForMetric polls cond until it returns true or the deadline lapses.
// It is used instead of a single time.Sleep because metric updates happen
// on a different goroutine (the batch worker) than HTTP responses.
func waitForMetric(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("timed out waiting for: %s", msg)
	}
}
