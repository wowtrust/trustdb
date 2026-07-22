//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/app"
	"github.com/wowtrust/trustdb/internal/batch"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/ingest"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/wal"
)

func TestHTTPIngestWritesWAL(t *testing.T) {
	t.Parallel()

	clientPub, clientPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate client key error = %v", err)
	}
	_, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Generate server key error = %v", err)
	}
	raw := []byte("trustdb http integration payload")
	contentHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, raw)
	if err != nil {
		t.Fatalf("HashBytes() error = %v", err)
	}
	c, err := claim.NewFileClaim(
		"tenant-http",
		"client-http",
		"client-key",
		time.Unix(100, 0),
		bytes.Repeat([]byte{1}, 16),
		"idem-http",
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
	body, err := cborx.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	walPath := filepath.Join(t.TempDir(), "trustdb.wal")
	writer, err := wal.OpenWriter(walPath, 1)
	if err != nil {
		t.Fatalf("OpenWriter() error = %v", err)
	}
	engine := app.LocalEngine{
		ServerID:         "server-http",
		ServerKeyID:      "server-key",
		ClientPublicKey:  clientPub,
		ServerPrivateKey: serverPriv,
		WAL:              writer,
		Now:              func() time.Time { return time.Unix(200, 0) },
	}
	svc := ingest.New(engine, ingest.Options{QueueSize: 8, Workers: 2}, nil)
	batchSvc := batch.New(engine, proofstore.LocalStore{Root: filepath.Join(t.TempDir(), "proofs")}, batch.Options{QueueSize: 8, MaxRecords: 1, MaxDelay: time.Hour}, nil)
	handler := New(svc, nil, batchSvc)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := batchSvc.Shutdown(shutdownCtx); err != nil {
			t.Errorf("Batch Shutdown() error = %v", err)
		}
		if err := svc.Shutdown(shutdownCtx); err != nil {
			t.Errorf("Shutdown() error = %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Errorf("WAL Close() error = %v", err)
		}
	})

	resp, err := http.Post(server.URL+"/v1/claims", "application/cbor", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/claims error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var accepted submitClaimResponse
	if err := json.NewDecoder(resp.Body).Decode(&accepted); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if accepted.RecordID == "" || accepted.Status != "accepted" || accepted.AcceptedReceipt.ServerID != "server-http" {
		t.Fatalf("accepted response = %+v", accepted)
	}
	if !accepted.BatchEnqueued {
		t.Fatalf("accepted response did not enqueue batch: %+v", accepted)
	}
	waitForHTTPStatus(t, server.URL+"/v1/proofs/"+accepted.RecordID, http.StatusOK)
	waitForHTTPStatus(t, server.URL+"/v1/roots/latest", http.StatusOK)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := batchSvc.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Batch Shutdown() error = %v", err)
	}
	if err := svc.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("WAL Close() error = %v", err)
	}
	records, err := wal.ReadAll(walPath)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("WAL records = %d, want 1", len(records))
	}
	var stored model.SignedClaim
	if err := cborx.Unmarshal(records[0].Payload, &stored); err != nil {
		t.Fatalf("decode WAL payload: %v", err)
	}
	if stored.Signature.KeyID != signed.Signature.KeyID || stored.Claim.ClientID != "client-http" {
		t.Fatalf("stored signed claim = %+v", stored)
	}
}

func waitForHTTPStatus(t *testing.T, url string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastStatus int
	var lastBody []byte
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("GET %s error = %v", url, err)
		}
		lastStatus = resp.StatusCode
		lastBody, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if lastStatus == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("GET %s status = %d body=%s, want %d", url, lastStatus, string(lastBody), want)
}
