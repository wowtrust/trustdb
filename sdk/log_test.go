package sdk

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func TestBuildSignedLogClaimDefaultsTraceAndVerifies(t *testing.T) {
	t.Parallel()

	pub, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	parents := []string{"tr1parent"}
	custom := map[string]string{"tenant_stream": "billing"}
	signed, err := BuildSignedLogClaimBytes([]byte(`{"level":"info","msg":"paid"}`), Identity{
		TenantID:   "tenant-1",
		ClientID:   "client-1",
		KeyID:      "client-key-1",
		PrivateKey: priv,
	}, LogClaimOptions{
		ProducedAt:     time.Unix(20, 0),
		Nonce:          bytes.Repeat([]byte{0x24}, 16),
		IdempotencyKey: "idem-log-1",
		Source:         "billing-api",
		TraceID:        "trace-1",
		Parents:        parents,
		CustomMetadata: custom,
	})
	if err != nil {
		t.Fatalf("BuildSignedLogClaimBytes: %v", err)
	}
	parents[0] = "mutated"
	custom["tenant_stream"] = "mutated"

	recordID, err := VerifySignedClaim(signed, pub)
	if err != nil {
		t.Fatalf("VerifySignedClaim: %v", err)
	}
	if recordID == "" {
		t.Fatal("record id is empty")
	}
	if got := signed.Claim.Metadata.EventType; got != DefaultLogEventType {
		t.Fatalf("event type = %q", got)
	}
	if got := signed.Claim.Content.MediaType; got != DefaultLogMediaType {
		t.Fatalf("media type = %q", got)
	}
	if got := signed.Claim.Metadata.TraceID; got != "trace-1" {
		t.Fatalf("trace id = %q", got)
	}
	if got := signed.Claim.Metadata.Parents[0]; got != "tr1parent" {
		t.Fatalf("parent = %q", got)
	}
	if got := signed.Claim.Metadata.Custom["tenant_stream"]; got != "billing" {
		t.Fatalf("custom tenant_stream = %q", got)
	}
}

func TestBuildSignedLogClaimBytesMatchesReaderPath(t *testing.T) {
	t.Parallel()

	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	raw := []byte(`{"level":"info","msg":"equivalent"}`)
	id := Identity{TenantID: "tenant-1", ClientID: "client-1", KeyID: "key-1", PrivateKey: privateKey}
	opts := LogClaimOptions{
		ProducedAt:     time.Unix(20, 0),
		Nonce:          bytes.Repeat([]byte{0x24}, 16),
		IdempotencyKey: "idem-log-equivalent",
		Source:         "sdk-test",
		Parents:        []string{"tr1parent"},
		CustomMetadata: map[string]string{"environment": "test"},
	}
	fromBytes, err := BuildSignedLogClaimBytes(raw, id, opts)
	if err != nil {
		t.Fatalf("BuildSignedLogClaimBytes: %v", err)
	}
	fromReader, err := BuildSignedLogClaim(bytes.NewReader(raw), id, opts)
	if err != nil {
		t.Fatalf("BuildSignedLogClaim: %v", err)
	}
	if !reflect.DeepEqual(fromBytes, fromReader) {
		t.Fatalf("byte and reader claims differ:\nbytes=%+v\nreader=%+v", fromBytes, fromReader)
	}
	contentHash := append([]byte(nil), fromBytes.Claim.Content.ContentHash...)
	raw[0] ^= 0xff
	if !bytes.Equal(fromBytes.Claim.Content.ContentHash, contentHash) {
		t.Fatal("signed claim content hash changed after input mutation")
	}
}

func TestMergedLogClaimOptionsBuildOwnsCallerData(t *testing.T) {
	t.Parallel()

	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	defaults := LogClaimOptions{
		EventType:      "payment.audit",
		Parents:        []string{"tr1default"},
		CustomMetadata: map[string]string{"service": "billing"},
	}
	override := LogClaimOptions{
		ProducedAt:     time.Unix(20, 0),
		Nonce:          bytes.Repeat([]byte{0x24}, 16),
		IdempotencyKey: "idem-log-owned",
		CustomMetadata: map[string]string{"environment": "production"},
	}
	signed, err := BuildSignedLogClaimBytes(
		[]byte(`{"level":"info"}`),
		Identity{TenantID: "tenant-1", ClientID: "client-1", KeyID: "key-1", PrivateKey: privateKey},
		mergeLogClaimOptions(defaults, override),
	)
	if err != nil {
		t.Fatalf("BuildSignedLogClaimBytes: %v", err)
	}
	defaults.Parents[0] = "mutated"
	defaults.CustomMetadata["service"] = "mutated"
	override.Nonce[0] = 0xff
	override.CustomMetadata["environment"] = "mutated"

	if got := signed.Claim.Nonce[0]; got != 0x24 {
		t.Fatalf("nonce[0] = %#x, want 0x24", got)
	}
	if got := signed.Claim.Metadata.Parents[0]; got != "tr1default" {
		t.Fatalf("parent = %q", got)
	}
	if got := signed.Claim.Metadata.Custom["service"]; got != "billing" {
		t.Fatalf("service = %q", got)
	}
	if got := signed.Claim.Metadata.Custom["environment"]; got != "production" {
		t.Fatalf("environment = %q", got)
	}
}

func TestBuildSignedLogClaimDefaultCustomMetadataRemainsNonNil(t *testing.T) {
	t.Parallel()

	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	signed, err := BuildSignedLogClaimBytes(
		[]byte(`{"level":"info"}`),
		Identity{TenantID: "tenant-1", ClientID: "client-1", KeyID: "key-1", PrivateKey: privateKey},
		LogClaimOptions{
			ProducedAt:     time.Unix(20, 0),
			Nonce:          bytes.Repeat([]byte{0x24}, 16),
			IdempotencyKey: "idem-log-writable-metadata",
		},
	)
	if err != nil {
		t.Fatalf("BuildSignedLogClaimBytes: %v", err)
	}
	if signed.Claim.Metadata.Custom == nil {
		t.Fatal("custom metadata map is nil")
	}
}

func BenchmarkBuildSignedLogClaimBytesDefault(b *testing.B) {
	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		b.Fatal(err)
	}
	id := Identity{
		TenantID:   "tenant-benchmark",
		ClientID:   "client-benchmark",
		KeyID:      "key-benchmark",
		PrivateKey: privateKey,
	}
	opts := LogClaimOptions{
		ProducedAt:     time.Unix(20, 0),
		Nonce:          bytes.Repeat([]byte{0x24}, 16),
		IdempotencyKey: "idem-log-benchmark",
		Source:         "sdk-benchmark",
	}
	raw := []byte(`{"level":"info","msg":"paid"}`)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := BuildSignedLogClaimBytes(raw, id, opts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuildMergedSignedLogClaimBytesDefault(b *testing.B) {
	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		b.Fatal(err)
	}
	id := Identity{
		TenantID:   "tenant-benchmark",
		ClientID:   "client-benchmark",
		KeyID:      "key-benchmark",
		PrivateKey: privateKey,
	}
	defaults := LogClaimOptions{EventType: "payment.audit", Source: "billing-api"}
	override := LogClaimOptions{
		ProducedAt:     time.Unix(20, 0),
		Nonce:          bytes.Repeat([]byte{0x24}, 16),
		IdempotencyKey: "idem-log-benchmark",
	}
	raw := []byte(`{"level":"info","msg":"paid"}`)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		opts := mergeLogClaimOptions(defaults, override)
		if _, err := BuildSignedLogClaimBytes(raw, id, opts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMergeLogClaimOptionsDefault(b *testing.B) {
	defaults := LogClaimOptions{EventType: "payment.audit", Source: "billing-api"}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkLogClaimOptions = mergeLogClaimOptions(defaults, LogClaimOptions{})
	}
}

var benchmarkLogClaimOptions LogClaimOptions

func TestNewJSONLogEntry(t *testing.T) {
	t.Parallel()

	entry, err := NewJSONLogEntry(map[string]any{
		"level": "info",
		"msg":   "accepted",
	}, LogClaimOptions{CustomMetadata: map[string]string{"log_id": "json-1"}})
	if err != nil {
		t.Fatalf("NewJSONLogEntry: %v", err)
	}
	if !bytes.Contains(entry.Body, []byte(`"level":"info"`)) {
		t.Fatalf("body = %s", entry.Body)
	}
	if got := entry.Options.CustomMetadata["log_id"]; got != "json-1" {
		t.Fatalf("log_id = %q", got)
	}
}

func TestClientSubmitLogBatchPreservesOrder(t *testing.T) {
	t.Parallel()

	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/claims/batch" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		var batch submitClaimsBatchRequestEnvelope
		if err := cborx.DecodeReaderLimit(r.Body, &batch, 1<<20); err != nil {
			t.Fatalf("DecodeReaderLimit: %v", err)
		}
		results := make([]submitClaimsBatchItemEnvelope, len(batch.Claims))
		for index, signed := range batch.Claims {
			logID := signed.Claim.Metadata.Custom["log_id"]
			if signed.Claim.Metadata.EventType != "payment.audit" {
				t.Fatalf("event type = %q", signed.Claim.Metadata.EventType)
			}
			if signed.Claim.IdempotencyKey == "" {
				t.Fatal("idempotency key is empty")
			}
			results[index] = submitClaimsBatchItemEnvelope{
				Index: index,
				Result: &submitClaimEnvelope{
					RecordID:      "tr1" + logID,
					Status:        "accepted",
					ProofLevel:    ProofLevelL2,
					BatchEnqueued: true,
					ServerRecord: ServerRecord{
						SchemaVersion: model.SchemaServerRecord,
						RecordID:      "tr1" + logID,
					},
					AcceptedReceipt: AcceptedReceipt{
						SchemaVersion: model.SchemaAcceptedReceipt,
						RecordID:      "tr1" + logID,
						Status:        "accepted",
					},
				},
			}
		}
		writeJSONForTest(t, w, http.StatusAccepted, submitClaimsBatchEnvelope{Results: results, Submitted: len(results)})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, WithHTTPClient(NewHTTPClientForConcurrency(2)))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	entries := []LogEntry{
		{Body: []byte(`{"n":1}`), Options: LogClaimOptions{CustomMetadata: map[string]string{"log_id": "one"}}},
		{Body: []byte(`{"n":2}`), Options: LogClaimOptions{CustomMetadata: map[string]string{"log_id": "two"}}},
		{Body: []byte(`{"n":3}`), Options: LogClaimOptions{CustomMetadata: map[string]string{"log_id": "three"}}},
	}
	result, err := client.SubmitLogBatch(context.Background(), entries, Identity{
		TenantID:   "tenant-1",
		ClientID:   "client-1",
		KeyID:      "client-key-1",
		PrivateKey: priv,
	}, LogSubmitOptions{
		Claim:       LogClaimOptions{EventType: "payment.audit", Source: "billing-api"},
		Concurrency: 2,
	})
	if err != nil {
		t.Fatalf("SubmitLogBatch: %v", err)
	}
	if result.Submitted != 3 || result.Failed != 0 {
		t.Fatalf("result = %+v", result)
	}
	want := []string{"tr1one", "tr1two", "tr1three"}
	for i, recordID := range want {
		if got := result.Results[i].Result.RecordID; got != recordID {
			t.Fatalf("result[%d].record_id = %q", i, got)
		}
	}
}

func TestClientSubmitLogBatchReportsPartialFailure(t *testing.T) {
	t.Parallel()

	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/claims/batch" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		var batch submitClaimsBatchRequestEnvelope
		if err := cborx.DecodeReaderLimit(r.Body, &batch, 1<<20); err != nil {
			t.Fatalf("DecodeReaderLimit: %v", err)
		}
		results := make([]submitClaimsBatchItemEnvelope, len(batch.Claims))
		submitted := 0
		failed := 0
		for index, signed := range batch.Claims {
			logID := signed.Claim.Metadata.Custom["log_id"]
			results[index] = submitClaimsBatchItemEnvelope{Index: index}
			if logID == "bad" {
				results[index].Error = &submitClaimErrorEnvelope{Code: "UNAVAILABLE", Message: "downstream unavailable"}
				failed++
				continue
			}
			results[index].Result = &submitClaimEnvelope{
				RecordID:   "tr1" + logID,
				Status:     "accepted",
				ProofLevel: ProofLevelL2,
			}
			submitted++
		}
		writeJSONForTest(t, w, http.StatusMultiStatus, submitClaimsBatchEnvelope{Results: results, Submitted: submitted, Failed: failed})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, WithHTTPClient(NewHTTPClientForConcurrency(2)))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	result, err := client.SubmitLogBatch(context.Background(), []LogEntry{
		{Body: []byte(`{"n":1}`), Options: LogClaimOptions{CustomMetadata: map[string]string{"log_id": "ok"}}},
		{Body: []byte(`{"n":2}`), Options: LogClaimOptions{CustomMetadata: map[string]string{"log_id": "bad"}}},
	}, Identity{
		TenantID:   "tenant-1",
		ClientID:   "client-1",
		KeyID:      "client-key-1",
		PrivateKey: priv,
	}, LogSubmitOptions{Concurrency: 2})

	var batchErr *LogBatchError
	if !errors.As(err, &batchErr) {
		t.Fatalf("error = %v", err)
	}
	if batchErr.Submitted != 1 || batchErr.Failed != 1 {
		t.Fatalf("batch error = %+v", batchErr)
	}
	if result.Submitted != 1 || result.Failed != 1 {
		t.Fatalf("result = %+v", result)
	}
	if result.Results[1].Err == nil {
		t.Fatal("failed item error is nil")
	}
}

func TestClientSubmitLogStream(t *testing.T) {
	t.Parallel()

	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var signed SignedClaim
		if err := cborx.DecodeReaderLimit(r.Body, &signed, 1<<20); err != nil {
			t.Fatalf("DecodeReaderLimit: %v", err)
		}
		logID := signed.Claim.Metadata.Custom["log_id"]
		writeJSONForTest(t, w, http.StatusAccepted, submitClaimEnvelope{
			RecordID:   "tr1" + logID,
			Status:     "accepted",
			ProofLevel: ProofLevelL2,
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, WithHTTPClient(NewHTTPClientForConcurrency(2)))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	entries := make(chan LogEntry)
	out, err := client.SubmitLogStream(context.Background(), entries, Identity{
		TenantID:   "tenant-1",
		ClientID:   "client-1",
		KeyID:      "client-key-1",
		PrivateKey: priv,
	}, LogStreamOptions{
		Claim:       LogClaimOptions{Source: "stream-test"},
		Concurrency: 2,
		QueueSize:   2,
	})
	if err != nil {
		t.Fatalf("SubmitLogStream: %v", err)
	}
	go func() {
		defer close(entries)
		entries <- LogEntry{Body: []byte(`{"n":1}`), Options: LogClaimOptions{CustomMetadata: map[string]string{"log_id": "one"}}}
		entries <- LogEntry{Body: []byte(`{"n":2}`), Options: LogClaimOptions{CustomMetadata: map[string]string{"log_id": "two"}}}
		entries <- LogEntry{Body: []byte(`{"n":3}`), Options: LogClaimOptions{CustomMetadata: map[string]string{"log_id": "three"}}}
	}()

	var recordIDs []string
	for item := range out {
		if item.Err != nil {
			t.Fatalf("stream item error: %v", item.Err)
		}
		recordIDs = append(recordIDs, item.Result.RecordID)
	}
	sort.Strings(recordIDs)
	want := []string{"tr1one", "tr1three", "tr1two"}
	if len(recordIDs) != len(want) {
		t.Fatalf("record ids = %v", recordIDs)
	}
	for i := range want {
		if recordIDs[i] != want[i] {
			t.Fatalf("record ids = %v", recordIDs)
		}
	}
}

func TestClientSubmitLogStreamNilContextDoesNotPanic(t *testing.T) {
	t.Parallel()

	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var signed SignedClaim
		if err := cborx.DecodeReaderLimit(r.Body, &signed, 1<<20); err != nil {
			t.Fatalf("DecodeReaderLimit: %v", err)
		}
		logID := signed.Claim.Metadata.Custom["log_id"]
		writeJSONForTest(t, w, http.StatusAccepted, submitClaimEnvelope{
			RecordID:   "tr1" + logID,
			Status:     "accepted",
			ProofLevel: ProofLevelL2,
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, WithHTTPClient(NewHTTPClientForConcurrency(1)))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	entries := make(chan LogEntry, 1)
	out, err := client.SubmitLogStream(nil, entries, Identity{
		TenantID:   "tenant-1",
		ClientID:   "client-1",
		KeyID:      "client-key-1",
		PrivateKey: priv,
	}, LogStreamOptions{Concurrency: 1, QueueSize: 1})
	if err != nil {
		t.Fatalf("SubmitLogStream: %v", err)
	}
	entries <- LogEntry{Body: []byte(`{"n":1}`), Options: LogClaimOptions{CustomMetadata: map[string]string{"log_id": "nilctx"}}}
	close(entries)

	var got []LogSubmitItemResult
	for item := range out {
		got = append(got, item)
	}
	if len(got) != 1 {
		t.Fatalf("stream results = %+v", got)
	}
	if got[0].Err != nil {
		t.Fatalf("stream item error: %v", got[0].Err)
	}
	if got[0].Result.RecordID != "tr1nilctx" {
		t.Fatalf("stream result = %+v", got[0].Result)
	}
}

func TestClientSubmitLogStreamNativeCancellationUnblocksFullResultBuffer(t *testing.T) {
	secondReceived := make(chan struct{})
	transport := &stubStreamTransport{
		results:        []signedClaimStreamItemResult{{Index: 0}, {Index: 1}},
		secondReceived: secondReceived,
	}
	client, err := NewClientWithTransport(transport)
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	entries := make(chan LogEntry)
	out, err := client.SubmitLogStream(ctx, entries, Identity{}, LogStreamOptions{QueueSize: 1})
	if err != nil {
		t.Fatalf("SubmitLogStream: %v", err)
	}
	close(entries)

	deadline := time.Now().Add(time.Second)
	for len(out) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(out) != 1 {
		t.Fatal("result buffer did not fill")
	}
	select {
	case <-secondReceived:
	case <-time.After(time.Second):
		t.Fatal("native result receiver did not reach the full output buffer")
	}
	cancel()
	time.Sleep(10 * time.Millisecond)

	select {
	case <-out:
	case <-time.After(time.Second):
		t.Fatal("timed out reading buffered result")
	}
	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("stream emitted another result after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("result stream did not close after cancellation")
	}
}

func TestSubmitLogBatchRejectsSharedDefaults(t *testing.T) {
	t.Parallel()

	client, err := NewClientWithTransport(stubTransport{})
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	result, err := client.SubmitLogBatch(context.Background(), []LogEntry{
		{Body: []byte(`{"n":1}`)},
		{Body: []byte(`{"n":2}`)},
	}, Identity{}, LogSubmitOptions{Claim: LogClaimOptions{IdempotencyKey: "same"}})
	if err == nil {
		t.Fatal("expected shared idempotency key error")
	}
	if result.Results == nil || len(result.Results) != 2 {
		t.Fatalf("results = %#v, want two allocated result slots", result.Results)
	}
}

func TestSubmitLogBatchEmptyReturnsNonNilResults(t *testing.T) {
	t.Parallel()

	client, err := NewClientWithTransport(stubTransport{})
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	result, err := client.SubmitLogBatch(context.Background(), nil, Identity{}, LogSubmitOptions{})
	if err != nil {
		t.Fatalf("SubmitLogBatch: %v", err)
	}
	if result.Results == nil || len(result.Results) != 0 {
		t.Fatalf("results = %#v, want non-nil empty slice", result.Results)
	}
}

func TestSubmitLogBatchFallbackTransportPreservesResults(t *testing.T) {
	t.Parallel()

	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	client, err := NewClientWithTransport(stubTransport{})
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	entries := make([]LogEntry, 2)
	for index := range entries {
		entries[index] = LogEntry{
			Body: []byte(`{"level":"info"}`),
			Options: LogClaimOptions{
				ProducedAt:     time.Unix(20, int64(index)),
				Nonce:          bytes.Repeat([]byte{byte(index + 1)}, 16),
				IdempotencyKey: "fallback-" + string(rune('a'+index)),
			},
		}
	}
	result, err := client.SubmitLogBatch(context.Background(), entries, Identity{
		TenantID:   "tenant-test",
		ClientID:   "client-test",
		KeyID:      "key-test",
		PrivateKey: privateKey,
	}, LogSubmitOptions{Concurrency: 2})
	if err != nil {
		t.Fatalf("SubmitLogBatch: %v", err)
	}
	if result.Submitted != len(entries) || result.Failed != 0 || len(result.Results) != len(entries) {
		t.Fatalf("result = %+v", result)
	}
	for index, item := range result.Results {
		if item.Index != index || item.Err != nil || item.Result.SignedClaim.Claim.IdempotencyKey == "" {
			t.Fatalf("result[%d] = %+v", index, item)
		}
	}
}

type stubTransport struct{}

type stubStreamTransport struct {
	stubTransport
	results        []signedClaimStreamItemResult
	secondReceived chan struct{}
}

func (s *stubStreamTransport) SubmitSignedClaimStream(_ context.Context, _ <-chan signedClaimStreamItem) (<-chan signedClaimStreamItemResult, error) {
	out := make(chan signedClaimStreamItemResult)
	go func() {
		defer close(out)
		for index, result := range s.results {
			out <- result
			if index == 1 && s.secondReceived != nil {
				close(s.secondReceived)
			}
		}
	}()
	return out, nil
}

func (stubTransport) Endpoint() string { return "stub" }
func (stubTransport) CheckHealth(context.Context) HealthStatus {
	return HealthStatus{OK: true, ServerURL: "stub"}
}
func (stubTransport) SubmitSignedClaim(context.Context, SignedClaim) (SubmitResult, error) {
	return SubmitResult{}, nil
}
func (stubTransport) GetRecord(context.Context, string) (RecordIndex, error) {
	return RecordIndex{}, nil
}
func (stubTransport) ListRecords(context.Context, ListRecordsOptions) (RecordPage, error) {
	return RecordPage{}, nil
}
func (stubTransport) ListRootsPage(context.Context, ListPageOptions) (RootPage, error) {
	return RootPage{}, nil
}
func (stubTransport) GetProofBundle(context.Context, string) (ProofBundle, error) {
	return ProofBundle{}, nil
}
func (stubTransport) ListRoots(context.Context, int) ([]BatchRoot, error) {
	return nil, nil
}
func (stubTransport) LatestRoot(context.Context) (BatchRoot, error) {
	return BatchRoot{}, nil
}
func (stubTransport) ListSTHs(context.Context, ListPageOptions) (TreeHeadPage, error) {
	return TreeHeadPage{}, nil
}
func (stubTransport) GetGlobalProof(context.Context, string) (GlobalLogProof, error) {
	return GlobalLogProof{}, nil
}
func (stubTransport) ListGlobalLeaves(context.Context, ListPageOptions) (GlobalLeafPage, error) {
	return GlobalLeafPage{}, nil
}
func (stubTransport) ListAnchors(context.Context, ListPageOptions) (AnchorPage, error) {
	return AnchorPage{}, nil
}
func (stubTransport) GetAnchor(context.Context, uint64) (AnchorStatus, error) {
	return AnchorStatus{}, nil
}
func (stubTransport) LatestSTH(context.Context) (SignedTreeHead, error) {
	return SignedTreeHead{}, nil
}
func (stubTransport) GetSTH(context.Context, uint64) (SignedTreeHead, error) {
	return SignedTreeHead{}, nil
}
func (stubTransport) MetricsRaw(context.Context) (string, error) {
	return "", nil
}
