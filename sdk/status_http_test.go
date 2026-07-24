package sdk

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
)

func TestHTTPStatusSubscriptionSDK(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/records/tr1/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(model.RecordStatus{SchemaVersion: model.SchemaRecordStatus, RecordID: "tr1", Status: model.RecordStatusCommitted, ProofLevel: "L3"})
	})
	mux.HandleFunc("POST /v1/records/status:batchGet", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"statuses": []model.RecordStatus{{SchemaVersion: model.SchemaRecordStatus, RecordID: "tr1", Status: model.RecordStatusCommitted}}, "missing_record_ids": []string{"missing"}})
	})
	mux.HandleFunc("POST /v1/status-subscriptions", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(StatusSubscription{ID: "tss1sdk", TenantID: "tenant", ClientID: "client", KeyID: "key", RecordIDs: []string{"tr1"}})
	})
	mux.HandleFunc("GET /v1/status-subscriptions/tss1sdk/statuses", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"statuses": []model.RecordStatus{{SchemaVersion: model.SchemaRecordStatus, RecordID: "tr1", Status: model.RecordStatusCommitted}}})
	})
	mux.HandleFunc("GET /v1/status-subscriptions/tss1sdk/events", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		notification, _ := json.Marshal(model.StatusRefresh{SchemaVersion: model.SchemaStatusRefresh, SubscriptionID: "tss1sdk", TenantID: "tenant", ClientID: "client", Version: 7, RefreshRequired: true, EmittedAtUnixN: time.Now().UnixNano()})
		_, _ = fmt.Fprintf(w, "event: refresh_required\ndata: %s\n\n", notification)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	})
	mux.HandleFunc("DELETE /v1/status-subscriptions/tss1sdk", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()
	status, err := client.GetRecordStatus(ctx, "tr1")
	if err != nil || status.Status != model.RecordStatusCommitted {
		t.Fatalf("GetRecordStatus() = %+v err=%v", status, err)
	}
	batch, err := client.GetRecordStatuses(ctx, []string{"tr1", "missing"})
	if err != nil || len(batch.Statuses) != 1 || len(batch.MissingRecordIDs) != 1 {
		t.Fatalf("GetRecordStatuses() = %+v err=%v", batch, err)
	}
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	subscription, err := client.CreateStatusSubscription(ctx, CreateStatusSubscriptionOptions{Identity: Identity{TenantID: "tenant", ClientID: "client", KeyID: "key", PrivateKey: privateKey}, RecordIDs: []string{"tr1"}})
	if err != nil || subscription.ID != "tss1sdk" {
		t.Fatalf("CreateStatusSubscription() = %+v err=%v", subscription, err)
	}
	events, errorsCh, err := client.SubscribeStatusRefresh(ctx, subscription.ID)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case notification := <-events:
		if notification.Version != 7 {
			t.Fatalf("SSE notification = %+v", notification)
		}
	case streamErr := <-errorsCh:
		t.Fatalf("SSE error = %v", streamErr)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SSE notification")
	}
	if _, err := client.GetStatusSubscriptionStatuses(ctx, subscription.ID); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteStatusSubscription(ctx, subscription.ID); err != nil {
		t.Fatal(err)
	}
}
