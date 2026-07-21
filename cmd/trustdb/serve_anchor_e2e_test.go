package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/ryan-wong-coder/trustdb/internal/anchor"
	"github.com/ryan-wong-coder/trustdb/internal/app"
	"github.com/ryan-wong-coder/trustdb/internal/batch"
	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/claim"
	"github.com/ryan-wong-coder/trustdb/internal/globallog"
	"github.com/ryan-wong-coder/trustdb/internal/httpapi"
	"github.com/ryan-wong-coder/trustdb/internal/ingest"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/observability"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
	"github.com/ryan-wong-coder/trustdb/internal/trustcrypto"
	"github.com/ryan-wong-coder/trustdb/internal/wal"
)

// TestServeAnchorEndToEnd drives the full L1→L5 pipeline against a
// file-backed anchor sink so every boundary is exercised with real
// IO: claim accepted → batch committed → outbox enqueued → worker
// publishes → JSONL appended → HTTP exposes the anchor result.
//
// Using a FileSink lets the assertions inspect on-disk artefacts
// directly (number of JSONL lines, anchor_id determinism) in addition
// to the HTTP response, which catches regressions where the sink
// "looks" successful but never actually wrote anything.
func TestServeAnchorEndToEnd(t *testing.T) {
	clientPub, clientPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key client: %v", err)
	}
	_, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key server: %v", err)
	}

	tmp := t.TempDir()
	walDir := filepath.Join(tmp, "wal")
	proofDir := filepath.Join(tmp, "proofs")
	anchorPath := filepath.Join(tmp, "anchors.jsonl")

	_, metrics := observability.NewRegistry()
	writer, mode, err := openWALWriterWithOptions(walDir, wal.Options{})
	if err != nil {
		t.Fatalf("openWALWriterWithOptions: %v", err)
	}
	if mode != "directory" {
		t.Fatalf("walMode = %q, want directory", mode)
	}
	defer writer.Close()

	engine := app.LocalEngine{
		ServerID:         "server-anchor-e2e",
		ServerKeyID:      "server-key",
		ClientPublicKey:  clientPub,
		ServerPrivateKey: serverPriv,
		WAL:              writer,
		Idempotency:      app.NewIdempotencyIndex(),
		Now:              func() time.Time { return time.Unix(300, 0) },
	}
	proofStore := proofstore.LocalStore{Root: proofDir}
	ingestSvc := ingest.New(engine, ingest.Options{QueueSize: 8, Workers: 2}, metrics)
	defer ingestSvc.Shutdown(context.Background())

	sink, err := anchor.NewFileSink(anchorPath)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	anchorSvc, err := anchor.NewService(anchor.Config{
		Sink:    sink,
		Store:   proofStore,
		Metrics: metrics,
		// Tight poll interval so tests don't wait for defaults.
		PollInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	anchorSvc.Start(context.Background())
	defer anchorSvc.Stop()

	rt := &runtimeConfig{logger: silentLogger()}
	globalSvc, err := globallog.New(globallog.Options{
		Store:      proofStore,
		LogID:      engine.ServerID,
		KeyID:      engine.ServerKeyID,
		PrivateKey: serverPriv,
	})
	if err != nil {
		t.Fatalf("globallog.New: %v", err)
	}
	globalOutbox := globallog.NewOutboxWorker(globallog.OutboxConfig{
		Store:          proofStore,
		Global:         globalSvc,
		PollInterval:   20 * time.Millisecond,
		AnchorOutbox:   true,
		OnAnchorsReady: anchorSvc.Trigger,
	})
	globalOutbox.Start(context.Background())
	defer globalOutbox.Stop()
	batchSvc := batch.New(engine, proofStore, batch.Options{
		QueueSize: 8,
		// MaxRecords=1 forces one record per batch, which gives us
		// a deterministic number of batches regardless of parallel
		// test scheduling. Previous runs with MaxRecords=2 +
		// tight MaxDelay were flaky under load because the number
		// of batches drifted with the scheduler.
		MaxRecords:       1,
		MaxDelay:         30 * time.Millisecond,
		OnBatchCommitted: newGlobalLogEnqueueHook(rt, proofStore, globalOutbox),
	}, metrics)
	defer batchSvc.Shutdown(context.Background())

	handler := httpapi.NewWithGlobalAndAnchors(ingestSvc, nil, batchSvc, globalSvc, anchor.NewAPI(proofStore))
	server := httptest.NewServer(handler)
	defer server.Close()

	const totalClaims = 4
	recordIDs := make([]string, 0, totalClaims)
	for i := 0; i < totalClaims; i++ {
		raw := bytes.Repeat([]byte{byte('a' + i)}, 64)
		contentHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, raw)
		if err != nil {
			t.Fatalf("HashBytes(%d): %v", i, err)
		}
		c, err := claim.NewFileClaim(
			"tenant-anchor",
			"client-anchor",
			"client-key",
			time.Unix(int64(2000+i), 0),
			bytes.Repeat([]byte{byte(i + 1)}, 16),
			fmt.Sprintf("idem-anchor-%d", i),
			model.Content{HashAlg: model.DefaultHashAlg, ContentHash: contentHash, ContentLength: int64(len(raw))},
			model.Metadata{EventType: "file.snapshot"},
		)
		if err != nil {
			t.Fatalf("NewFileClaim(%d): %v", i, err)
		}
		signed, err := claim.Sign(c, clientPriv)
		if err != nil {
			t.Fatalf("Sign(%d): %v", i, err)
		}
		body, err := cborx.Marshal(signed)
		if err != nil {
			t.Fatalf("Marshal(%d): %v", i, err)
		}
		resp, err := http.Post(server.URL+"/v1/claims", "application/cbor", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST /v1/claims(%d): %v", i, err)
		}
		var decoded struct {
			RecordID string `json:"record_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
			resp.Body.Close()
			t.Fatalf("decode %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("POST /v1/claims(%d) status = %d", i, resp.StatusCode)
		}
		recordIDs = append(recordIDs, decoded.RecordID)
	}

	// Wait for every record to reach L3 so we know every batch is
	// committed. After that the anchor outbox will only drain — the
	// L3 → L5 hand-off is local.
	for _, rid := range recordIDs {
		waitForHTTPProof(t, server.URL, rid)
	}

	// With MaxRecords=1 we get exactly totalClaims committed
	// batches, deterministic regardless of scheduler pressure. The
	// anchor worker must publish all of them.
	waitForMetric(t, func() bool {
		return testutil.ToFloat64(metrics.AnchorPublished.WithLabelValues(anchor.FileSinkName)) >= float64(totalClaims)
	}, fmt.Sprintf("anchor_published_total >= %d", totalClaims))

	manifests, err := proofStore.ListManifests(context.Background())
	if err != nil {
		t.Fatalf("ListManifests: %v", err)
	}
	var committed int
	for _, m := range manifests {
		if m.State == model.BatchStateCommitted {
			committed++
		}
	}
	if committed != totalClaims {
		t.Fatalf("committed manifests = %d, want %d", committed, totalClaims)
	}

	// File sink wrote exactly one JSONL line per published batch.
	lines := readJSONL(t, anchorPath)
	if len(lines) != totalClaims {
		t.Fatalf("anchors.jsonl lines = %d, want %d (got %+v)", len(lines), totalClaims, lines)
	}
	if !strings.HasPrefix(lines[0].AnchorID, "file-") {
		t.Fatalf("anchor id missing file- prefix: %q", lines[0].AnchorID)
	}

	// HTTP surface exposes the anchor result for each batch.
	for _, m := range manifests {
		if m.State != model.BatchStateCommitted {
			continue
		}
		leaf, ok, err := proofStore.GetGlobalLeafByBatchID(context.Background(), m.BatchID)
		if err != nil || !ok {
			t.Fatalf("GetGlobalLeafByBatchID(%s) ok=%v err=%v", m.BatchID, ok, err)
		}
		treeSize := leaf.LeafIndex + 1
		resp, err := http.Get(fmt.Sprintf("%s/v1/anchors/sth/%d", server.URL, treeSize))
		if err != nil {
			t.Fatalf("GET /v1/anchors/sth/%d: %v", treeSize, err)
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := readBody(resp)
			resp.Body.Close()
			t.Fatalf("GET /v1/anchors/sth/%d status = %d body=%s", treeSize, resp.StatusCode, body)
		}
		var payload struct {
			TreeSize   uint64 `json:"tree_size"`
			Status     string `json:"status"`
			ProofLevel string `json:"proof_level"`
			Result     *struct {
				AnchorID string `json:"anchor_id"`
				SinkName string `json:"sink_name"`
			} `json:"result"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			resp.Body.Close()
			t.Fatalf("decode anchor response: %v", err)
		}
		resp.Body.Close()
		if payload.Status != model.AnchorStatePublished {
			t.Fatalf("/v1/anchors/sth/%d status = %q, want published", treeSize, payload.Status)
		}
		if payload.TreeSize != treeSize {
			t.Fatalf("tree_size = %d, want %d", payload.TreeSize, treeSize)
		}
		if payload.ProofLevel != "L5" {
			t.Fatalf("proof_level = %q, want L5", payload.ProofLevel)
		}
		if payload.Result == nil || payload.Result.SinkName != anchor.FileSinkName {
			t.Fatalf("result = %+v", payload.Result)
		}
	}

	// An unknown STH tree size is 404 so clients can differentiate
	// "anchor not found" from "transport error".
	resp, err := http.Get(server.URL + "/v1/anchors/sth/999999")
	if err != nil {
		t.Fatalf("GET unknown anchor: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown anchor status = %d, want 404", resp.StatusCode)
	}
}

// TestBackfillGlobalLog simulates an operator startup where a committed batch
// root exists in the proofstore but has no durable global-log append event.
// Startup backfill must enqueue the event exactly once; the outbox worker owns
// the later append + STH anchor enqueue.
func TestBackfillGlobalLog(t *testing.T) {
	proofStore := proofstore.LocalStore{Root: t.TempDir()}
	ctx := context.Background()

	rootHash := bytes.Repeat([]byte{7}, 32)
	root := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       "startup-batch",
		TreeSize:      3,
		BatchRoot:     rootHash,
		ClosedAtUnixN: 1,
	}
	if err := proofStore.PutRoot(ctx, root); err != nil {
		t.Fatalf("PutRoot: %v", err)
	}

	_, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key server: %v", err)
	}
	globalSvc, err := globallog.New(globallog.Options{
		Store:      proofStore,
		LogID:      "test-global",
		KeyID:      "test-key",
		PrivateKey: serverPriv,
	})
	if err != nil {
		t.Fatalf("globallog.New: %v", err)
	}
	svc, err := anchor.NewService(anchor.Config{
		Sink:  anchor.NewNoopSink(),
		Store: proofStore,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	n, err := backfillGlobalLogOutbox(ctx, proofStore)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if n != 1 {
		t.Fatalf("backfill enqueued %d, want 1", n)
	}
	outboxItem, ok, err := proofStore.GetGlobalLogOutboxItem(ctx, root.BatchID)
	if err != nil || !ok {
		t.Fatalf("GetGlobalLogOutboxItem ok=%v err=%v", ok, err)
	}
	if outboxItem.Status != model.AnchorStatePending {
		t.Fatalf("status = %q, want pending", outboxItem.Status)
	}

	// Second run: outbox already has the entry, must be 0.
	n, err = backfillGlobalLogOutbox(ctx, proofStore)
	if err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	if n != 0 {
		t.Fatalf("second backfill enqueued %d, want 0", n)
	}

	worker := globallog.NewOutboxWorker(globallog.OutboxConfig{
		Store:          proofStore,
		Global:         globalSvc,
		PollInterval:   10 * time.Millisecond,
		AnchorOutbox:   true,
		OnAnchorsReady: svc.Trigger,
	})
	worker.Start(ctx)
	defer worker.Stop()
	worker.Trigger()
	waitForMetric(t, func() bool {
		item, ok, err := proofStore.GetSTHAnchorOutboxItem(ctx, 1)
		return err == nil && ok && item.Status == model.AnchorStatePending
	}, "sth anchor outbox pending")
}

// readJSONL parses a file of one-JSON-object-per-line into its
// entries. Stops at EOF and fails the test on malformed lines.
func readJSONL(t *testing.T, path string) []anchor.FileAnchorEntry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var entries []anchor.FileAnchorEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry anchor.FileAnchorEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("decode line %q: %v", scanner.Text(), err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return entries
}

func readBody(resp *http.Response) (string, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(resp.Body)
	return buf.String(), err
}
