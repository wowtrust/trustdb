package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/wowtrust/trustdb/internal/model"
)

type recordPageResponse struct {
	Records    []model.RecordIndex `json:"records"`
	Limit      int                 `json:"limit"`
	Direction  string              `json:"direction"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

func TestHTTPClientListRecordIndexesMapsServerPage(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/records" {
			t.Fatalf("path = %s, want /v1/records", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("limit") != "2" || q.Get("cursor") != "cur-1" || q.Get("batch_id") != "batch-1" || q.Get("direction") != "desc" {
			t.Fatalf("query = %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(recordPageResponse{
			Records: []model.RecordIndex{{
				SchemaVersion:      model.SchemaRecordIndex,
				RecordID:           "tr1record",
				TenantID:           "tenant-a",
				ClientID:           "client-a",
				KeyID:              "key-a",
				BatchID:            "batch-1",
				BatchLeafIndex:     7,
				BatchClosedAtUnixN: 99,
				ReceivedAtUnixN:    88,
				ContentHash:        []byte{0xab, 0xcd},
				ContentLength:      12,
				MediaType:          "text/plain",
				StorageURI:         "file:///tmp/example.txt",
				EventType:          "file.snapshot",
				Source:             "desktop",
			}},
			Limit:      2,
			Direction:  "desc",
			NextCursor: "cur-2",
		})
	}))
	defer srv.Close()

	client, err := newServerClient(serverTransportHTTP, srv.URL)
	if err != nil {
		t.Fatalf("newServerClient: %v", err)
	}
	page, err := client.listRecordIndexes(context.Background(), RecordPageOptions{
		Limit:  2,
		Offset: 10,
		Cursor: "cur-1",
		Query:  "batch-1",
	})
	if err != nil {
		t.Fatalf("listRecordIndexes: %v", err)
	}
	if page.Source != "server" || !page.HasMore || page.NextCursor != "cur-2" || page.TotalExact {
		t.Fatalf("page metadata = %+v", page)
	}
	if got := page.Items[0]; got.RecordID != "tr1record" || got.ProofLevel != "L3" || got.FileName != "example.txt" || got.ContentHashHex != "abcd" {
		t.Fatalf("item = %+v", got)
	}
}

func TestHTTPClientListRecordIndexesSupportsExactRecordQuery(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/records/tr1exact" {
			t.Fatalf("path = %s, want exact record endpoint", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(model.RecordIndex{
			SchemaVersion:   model.SchemaRecordIndex,
			RecordID:        "tr1exact",
			ReceivedAtUnixN: 123,
			StorageURI:      "trustdb-local://sha256/abc",
		})
	}))
	defer srv.Close()

	client, err := newServerClient(serverTransportHTTP, srv.URL)
	if err != nil {
		t.Fatalf("newServerClient: %v", err)
	}
	page, err := client.listRecordIndexes(context.Background(), RecordPageOptions{Query: "tr1exact"})
	if err != nil {
		t.Fatalf("listRecordIndexes exact: %v", err)
	}
	if page.Total != 1 || page.Source != "server" || !page.TotalExact || page.Items[0].RecordID != "tr1exact" {
		t.Fatalf("page = %+v", page)
	}
}

func TestHTTPClientListRecordIndexesSendsServerSearchFilters(t *testing.T) {
	t.Parallel()

	const hash = "0202020202020202020202020202020202020202020202020202020202020202"
	var (
		mu           sync.Mutex
		sawTextQuery bool
		sawHashQuery bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/records" {
			t.Fatalf("path = %s, want /v1/records", r.URL.Path)
		}
		switch {
		case r.URL.Query().Get("q") == "screenshot" && r.URL.Query().Get("content_hash") == "":
			mu.Lock()
			sawTextQuery = true
			mu.Unlock()
		case r.URL.Query().Get("content_hash") == hash && r.URL.Query().Get("q") == "":
			mu.Lock()
			sawHashQuery = true
			mu.Unlock()
		default:
			t.Fatalf("unexpected query = %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(recordPageResponse{Limit: 50, Direction: "desc"})
	}))
	defer srv.Close()

	client, err := newServerClient(serverTransportHTTP, srv.URL)
	if err != nil {
		t.Fatalf("newServerClient: %v", err)
	}
	if _, err := client.listRecordIndexes(context.Background(), RecordPageOptions{Query: "screenshot"}); err != nil {
		t.Fatalf("listRecordIndexes q: %v", err)
	}
	if _, err := client.listRecordIndexes(context.Background(), RecordPageOptions{Query: hash}); err != nil {
		t.Fatalf("listRecordIndexes hash: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !sawTextQuery || !sawHashQuery {
		t.Fatalf("saw text=%v hash=%v", sawTextQuery, sawHashQuery)
	}
}

func TestHTTPClientListRecordIndexesSendsLevelFilter(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/records" {
			t.Fatalf("path = %s, want /v1/records", r.URL.Path)
		}
		if r.URL.Query().Get("level") != "L4" {
			t.Fatalf("query = %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(recordPageResponse{Limit: 50, Direction: "desc"})
	}))
	defer srv.Close()

	client, err := newServerClient(serverTransportHTTP, srv.URL)
	if err != nil {
		t.Fatalf("newServerClient: %v", err)
	}
	if _, err := client.listRecordIndexes(context.Background(), RecordPageOptions{Level: "L4"}); err != nil {
		t.Fatalf("listRecordIndexes level: %v", err)
	}
}

func TestHTTPClientGetAnchorMapsImmutableResult(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/anchors/sth/7" {
			t.Fatalf("path = %s, want /v1/anchors/sth/7", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tree_size":   7,
			"status":      model.AnchorStatePublished,
			"proof_level": "L5",
			"result": &model.STHAnchorResult{
				SchemaVersion: model.SchemaSTHAnchorResult,
				TreeSize:      7,
				SinkName:      "ots",
				AnchorID:      "anchor-7",
			},
		})
	}))
	defer srv.Close()

	client, err := newServerClient(serverTransportHTTP, srv.URL)
	if err != nil {
		t.Fatalf("newServerClient: %v", err)
	}
	got, err := client.getAnchor(context.Background(), 7)
	if err != nil {
		t.Fatalf("getAnchor: %v", err)
	}
	if got.TreeSize != 7 || got.Status != model.AnchorStatePublished || got.Result == nil || got.Result.AnchorID != "anchor-7" {
		t.Fatalf("anchor = %+v", got)
	}
}

func TestNormalizeGRPCTargetStripsHTTPStyleURL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "host port", endpoint: "127.0.0.1:9090", want: "127.0.0.1:9090"},
		{name: "http url", endpoint: "http://127.0.0.1:9090", want: "127.0.0.1:9090"},
		{name: "grpc url", endpoint: "grpc://trustdb.example:9090/", want: "trustdb.example:9090"},
		{name: "resolver target", endpoint: "dns:///trustdb.example:9090", want: "dns:///trustdb.example:9090"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeGRPCTarget(tc.endpoint)
			if err != nil {
				t.Fatalf("normalizeGRPCTarget: %v", err)
			}
			if got != tc.want {
				t.Fatalf("target = %q, want %q", got, tc.want)
			}
		})
	}
}
