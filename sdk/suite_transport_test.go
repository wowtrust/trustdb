package sdk

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/internal/claim"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/grpcapi"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/submission"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

func TestCNSMV1HTTPSubmitPreservesSuite(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := GenerateCNSMV1SoftwareKey()
	if err != nil {
		t.Fatalf("GenerateCNSMV1SoftwareKey: %v", err)
	}
	identity := mustCNSMV1Identity(t, "tenant-cn", "client-cn", "client-sm2", privateKey)
	signed, err := BuildSignedFileClaim(bytes.NewReader([]byte("CN-SM HTTP")), identity, FileClaimOptions{
		Nonce:          bytes.Repeat([]byte{0x41}, 16),
		IdempotencyKey: "cn-http-1",
		EventType:      "file.snapshot",
	})
	if err != nil {
		t.Fatalf("BuildSignedFileClaim: %v", err)
	}
	descriptor := mustCNSMV1PublicKey(t, "client-sm2", publicKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var decoded SignedClaim
		if err := cborx.DecodeReaderLimit(r.Body, &decoded, 1<<20); err != nil {
			t.Fatalf("DecodeReaderLimit: %v", err)
		}
		if _, err := VerifySignedClaim(decoded, descriptor); err != nil {
			t.Fatalf("VerifySignedClaim: %v", err)
		}
		writeJSONForTest(t, w, http.StatusAccepted, validSubmitClaimEnvelope(decoded))
	}))
	defer server.Close()

	client, err := NewClientForSuite(server.URL, CryptoSuiteCNSMV1)
	if err != nil {
		t.Fatalf("NewClientForSuite: %v", err)
	}
	result, err := client.SubmitSignedClaim(context.Background(), signed)
	if err != nil {
		t.Fatalf("SubmitSignedClaim: %v", err)
	}
	if result.ServerRecord.CryptoSuite != cryptosuite.CNSMV1 ||
		result.AcceptedReceipt.CryptoSuite != cryptosuite.CNSMV1 {
		t.Fatalf("result lost CN suite: %+v", result)
	}
}

func TestClientRejectsRequestSuiteMismatchBeforeNetwork(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer server.Close()
	client, err := NewClientForSuite(server.URL, CryptoSuiteCNSMV1)
	if err != nil {
		t.Fatalf("NewClientForSuite: %v", err)
	}

	_, err = client.SubmitSignedClaim(context.Background(), intlSignedClaimFixture())
	var sdkErr *Error
	if !errors.As(err, &sdkErr) || sdkErr.Code != "FAILED_PRECONDITION" {
		t.Fatalf("SubmitSignedClaim error=%v, want SDK FAILED_PRECONDITION", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("network hits=%d, want 0", hits.Load())
	}
}

func TestClientRejectsIncompleteSubmitContract(t *testing.T) {
	t.Parallel()

	signed := intlSignedClaimFixture()
	valid := validSubmitClaimEnvelope(signed)
	tests := []struct {
		name string
		env  submitClaimEnvelope
	}{
		{name: "empty response"},
		{
			name: "suite without schema",
			env: submitClaimEnvelope{
				RecordID:   "tr1-partial",
				Status:     "accepted",
				ProofLevel: ProofLevelL2,
				ServerRecord: ServerRecord{
					CryptoSuite: cryptosuite.CNSMV1,
					RecordID:    "tr1-partial",
				},
				AcceptedReceipt: AcceptedReceipt{
					CryptoSuite: cryptosuite.CNSMV1,
					RecordID:    "tr1-partial",
					Status:      "accepted",
				},
			},
		},
		{
			name: "inconsistent record ids",
			env: submitClaimEnvelope{
				RecordID:   "tr1-envelope",
				Status:     "accepted",
				ProofLevel: ProofLevelL2,
				ServerRecord: ServerRecord{
					SchemaVersion: model.SchemaServerRecord,
					CryptoSuite:   cryptosuite.INTLV1,
					RecordID:      "tr1-record",
				},
				AcceptedReceipt: AcceptedReceipt{
					SchemaVersion: model.SchemaAcceptedReceipt,
					CryptoSuite:   cryptosuite.INTLV1,
					RecordID:      "tr1-envelope",
					Status:        "accepted",
				},
			},
		},
		{
			name: "schema-only evidence shells",
			env: submitClaimEnvelope{
				RecordID:   valid.RecordID,
				Status:     valid.Status,
				ProofLevel: valid.ProofLevel,
				ServerRecord: ServerRecord{
					SchemaVersion: model.SchemaServerRecord,
					CryptoSuite:   cryptosuite.INTLV1,
					RecordID:      valid.RecordID,
				},
				AcceptedReceipt: AcceptedReceipt{
					SchemaVersion: model.SchemaAcceptedReceipt,
					CryptoSuite:   cryptosuite.INTLV1,
					RecordID:      valid.RecordID,
					Status:        model.RecordStatusAccepted,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeJSONForTest(t, w, http.StatusAccepted, tt.env)
			}))
			defer server.Close()
			client, err := NewClient(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.SubmitSignedClaim(context.Background(), signed)
			var sdkErr *Error
			if !errors.As(err, &sdkErr) || sdkErr.Code != "DATA_LOSS" {
				t.Fatalf("SubmitSignedClaim error=%v, want SDK DATA_LOSS", err)
			}
		})
	}
}

func TestClientRejectsSubmitResultForDifferentSignedClaim(t *testing.T) {
	t.Parallel()

	expected := intlSignedClaimFixture()
	other := expected
	other.Claim.IdempotencyKey = "different-request"
	transport := mismatchedSubmitTransport{
		stubTransport: stubTransport{},
		result:        validSDKSubmitResult(other, ""),
	}
	client, err := NewClientWithTransport(transport)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SubmitSignedClaim(context.Background(), expected)
	var sdkErr *Error
	if !errors.As(err, &sdkErr) || sdkErr.Code != "DATA_LOSS" {
		t.Fatalf("SubmitSignedClaim error=%v, want SDK DATA_LOSS", err)
	}
}

type mismatchedSubmitTransport struct {
	stubTransport
	result SubmitResult
}

func (t mismatchedSubmitTransport) SubmitSignedClaim(context.Context, SignedClaim) (SubmitResult, error) {
	return t.result, nil
}

func TestClientRejectsMismatchedSuiteBoundTransport(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	intl, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClientWithTransportForSuite(intl.transport, CryptoSuiteCNSMV1); err == nil {
		t.Fatal("NewClientWithTransportForSuite accepted an INTL transport for a CN client")
	}
}

func TestLoadBalancedClientDoesNotFailOverAfterSuiteMismatch(t *testing.T) {
	t.Parallel()

	var primaryHits atomic.Int32
	var secondaryHits atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryHits.Add(1)
		writeJSONForTest(t, w, http.StatusAccepted, submitClaimEnvelope{
			RecordID: "tr1-wrong-suite",
			ServerRecord: ServerRecord{
				SchemaVersion: model.SchemaServerRecord,
				CryptoSuite:   cryptosuite.INTLV1,
				RecordID:      "tr1-wrong-suite",
			},
		})
	}))
	defer primary.Close()
	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondaryHits.Add(1)
		writeJSONForTest(t, w, http.StatusAccepted, submitClaimEnvelope{
			RecordID: "tr1-secondary",
			ServerRecord: ServerRecord{
				SchemaVersion: model.SchemaServerRecord,
				CryptoSuite:   cryptosuite.CNSMV1,
				RecordID:      "tr1-secondary",
			},
		})
	}))
	defer secondary.Close()

	_, privateKey, err := GenerateCNSMV1SoftwareKey()
	if err != nil {
		t.Fatalf("GenerateCNSMV1SoftwareKey: %v", err)
	}
	signed, err := BuildSignedFileClaim(bytes.NewReader([]byte("mismatch")), mustCNSMV1Identity(t, "tenant", "client", "sm2", privateKey), FileClaimOptions{
		Nonce:          bytes.Repeat([]byte{0x42}, 16),
		IdempotencyKey: "cn-mismatch-1",
		EventType:      "file.snapshot",
	})
	if err != nil {
		t.Fatalf("BuildSignedFileClaim: %v", err)
	}
	client, err := NewLoadBalancedClientForSuite(
		[]string{primary.URL, secondary.URL},
		CryptoSuiteCNSMV1,
		LoadBalanceOptions{Mode: LoadBalanceFailover},
	)
	if err != nil {
		t.Fatalf("NewLoadBalancedClientForSuite: %v", err)
	}
	_, err = client.SubmitSignedClaim(context.Background(), signed)
	var sdkErr *Error
	if !errors.As(err, &sdkErr) || sdkErr.Code != "FAILED_PRECONDITION" {
		t.Fatalf("SubmitSignedClaim error=%v, want SDK FAILED_PRECONDITION", err)
	}
	if primaryHits.Load() != 1 || secondaryHits.Load() != 0 {
		t.Fatalf("endpoint hits primary=%d secondary=%d, want 1/0", primaryHits.Load(), secondaryHits.Load())
	}
}

func TestCNSMV1LoadBalancedClientRetriesTransientEndpoint(t *testing.T) {
	t.Parallel()

	var primaryHits atomic.Int32
	var secondaryHits atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryHits.Add(1)
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer primary.Close()
	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondaryHits.Add(1)
		var decoded SignedClaim
		if err := cborx.DecodeReaderLimit(r.Body, &decoded, 1<<20); err != nil {
			t.Fatalf("DecodeReaderLimit: %v", err)
		}
		writeJSONForTest(t, w, http.StatusAccepted, validSubmitClaimEnvelope(decoded))
	}))
	defer secondary.Close()

	_, privateKey, err := GenerateCNSMV1SoftwareKey()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewLoadBalancedClientForSuite(
		[]string{primary.URL, secondary.URL},
		CryptoSuiteCNSMV1,
		LoadBalanceOptions{Mode: LoadBalanceFailover},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.SubmitFile(
		context.Background(),
		bytes.NewReader([]byte("retry")),
		mustCNSMV1Identity(t, "tenant", "client", "sm2", privateKey),
		FileClaimOptions{
			Nonce:          bytes.Repeat([]byte{0x44}, 16),
			IdempotencyKey: "cn-retry-1",
			EventType:      "file.snapshot",
		},
	)
	if err != nil {
		t.Fatalf("SubmitFile: %v", err)
	}
	if result.RecordID == "" || primaryHits.Load() != 1 || secondaryHits.Load() != 1 {
		t.Fatalf("result=%+v hits primary=%d secondary=%d", result, primaryHits.Load(), secondaryHits.Load())
	}
}

func TestCNSMV1NativeLogStreamPreservesSuite(t *testing.T) {
	t.Parallel()

	_, privateKey, err := GenerateCNSMV1SoftwareKey()
	if err != nil {
		t.Fatal(err)
	}
	transport := &capturingSuiteStreamTransport{received: make(chan SignedClaim, 2)}
	client, err := NewClientWithTransportForSuite(transport, CryptoSuiteCNSMV1)
	if err != nil {
		t.Fatal(err)
	}
	entries := make(chan LogEntry, 2)
	entries <- LogEntry{Body: []byte(`{"index":0}`), Options: fixedLogClaimOptions("cn-stream-0", 1)}
	entries <- LogEntry{Body: []byte(`{"index":1}`), Options: fixedLogClaimOptions("cn-stream-1", 2)}
	close(entries)
	results, err := client.SubmitLogStream(
		context.Background(),
		entries,
		mustCNSMV1Identity(t, "tenant", "client", "sm2", privateKey),
		LogStreamOptions{QueueSize: 2, Concurrency: 2},
	)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for result := range results {
		if result.Err != nil {
			t.Fatalf("stream result: %v", result.Err)
		}
		count++
	}
	if count != 2 {
		t.Fatalf("stream results=%d, want 2", count)
	}
	for signed := range transport.received {
		if signed.CryptoSuite != cryptosuite.CNSMV1 ||
			signed.Claim.Content.HashAlg != cryptosuite.HashSM3 ||
			signed.Signature.Alg != cryptosuite.SignatureSM2SM3 {
			t.Fatalf("received non-CN stream claim: %+v", signed)
		}
	}
}

func TestCNSMV1GRPCSubmitPreservesSuite(t *testing.T) {
	t.Parallel()

	var received atomic.Int32
	submitter := sdkNATSSubmitterFunc(func(_ context.Context, signed model.SignedClaim) (submission.Outcome, error) {
		if signed.CryptoSuite != cryptosuite.CNSMV1 ||
			signed.Claim.CryptoSuite != cryptosuite.CNSMV1 ||
			signed.Claim.Content.HashAlg != cryptosuite.HashSM3 ||
			signed.Signature.Alg != cryptosuite.SignatureSM2SM3 {
			t.Fatalf("received non-CN claim: %+v", signed)
		}
		received.Add(1)
		result := validSDKSubmitResult(signed, "")
		return submission.Outcome{
			RecordID:        result.RecordID,
			Status:          result.Status,
			ProofLevel:      result.ProofLevel,
			BatchEnqueued:   result.BatchEnqueued,
			ServerRecord:    result.ServerRecord,
			AcceptedReceipt: result.AcceptedReceipt,
		}, nil
	})
	conn := newBufconnConnection(t, grpcapi.NewServerWithSubmitter(submitter, grpcTestBatch{}, nil, nil, nil))
	transport, err := NewGRPCTransportFromConnForSuite("bufnet", conn, CryptoSuiteCNSMV1)
	if err != nil {
		t.Fatalf("NewGRPCTransportFromConnForSuite: %v", err)
	}
	client, err := NewClientWithTransportForSuite(transport, CryptoSuiteCNSMV1)
	if err != nil {
		t.Fatalf("NewClientWithTransportForSuite: %v", err)
	}
	_, privateKey, err := GenerateCNSMV1SoftwareKey()
	if err != nil {
		t.Fatalf("GenerateCNSMV1SoftwareKey: %v", err)
	}
	result, err := client.SubmitFile(
		context.Background(),
		bytes.NewReader([]byte("CN-SM gRPC")),
		mustCNSMV1Identity(t, "tenant-cn", "client-cn", "client-sm2", privateKey),
		FileClaimOptions{
			ProducedAt:     time.Unix(100, 0),
			Nonce:          bytes.Repeat([]byte{0x43}, 16),
			IdempotencyKey: "cn-grpc-1",
			EventType:      "file.snapshot",
		},
	)
	if err != nil {
		t.Fatalf("SubmitFile: %v", err)
	}
	if received.Load() != 1 || result.ServerRecord.CryptoSuite != cryptosuite.CNSMV1 {
		t.Fatalf("received=%d result=%+v", received.Load(), result)
	}
}

type capturingSuiteStreamTransport struct {
	stubTransport
	received chan SignedClaim
}

func (t *capturingSuiteStreamTransport) SubmitSignedClaimStream(
	_ context.Context,
	input <-chan signedClaimStreamItem,
) (<-chan signedClaimStreamItemResult, error) {
	output := make(chan signedClaimStreamItemResult)
	go func() {
		defer close(output)
		defer close(t.received)
		for item := range input {
			t.received <- item.SignedClaim
			output <- signedClaimStreamItemResult{
				Index:  item.Index,
				Result: validSDKSubmitResult(item.SignedClaim, "tr1-cn-stream"),
			}
		}
	}()
	return output, nil
}

func validSDKSubmitResult(signed SignedClaim, _ string) SubmitResult {
	provider, err := trustcrypto.ProviderForSuite(signed.CryptoSuite)
	if err != nil {
		panic(err)
	}
	suite, err := cryptosuite.RequireAvailable(signed.CryptoSuite)
	if err != nil {
		panic(err)
	}
	canonical, err := claim.Canonical(signed.Claim)
	if err != nil {
		panic(err)
	}
	claimHash, err := trustcrypto.HashBytesWithProvider(provider, suite.ClaimHash.Algorithm, canonical)
	if err != nil {
		panic(err)
	}
	signatureHash, err := trustcrypto.HashBytesWithProvider(provider, suite.SignatureHash.Algorithm, signed.Signature.Signature)
	if err != nil {
		panic(err)
	}
	recordID, err := claim.RecordIDWithProvider(provider, canonical, signed.Signature)
	if err != nil {
		panic(err)
	}
	serverSignature := []byte{0x30, 0x01}
	if signed.CryptoSuite == cryptosuite.INTLV1 {
		serverSignature = bytes.Repeat([]byte{0x5a}, 64)
	}
	const receivedAtUnixN = int64(1)
	position := model.WALPosition{SegmentID: 1, Offset: 1, Sequence: 1}
	return SubmitResult{
		RecordID:      recordID,
		Status:        model.RecordStatusAccepted,
		ProofLevel:    ProofLevelL2,
		BatchEnqueued: true,
		ServerRecord: ServerRecord{
			SchemaVersion:       model.SchemaServerRecord,
			CryptoSuite:         signed.CryptoSuite,
			RecordID:            recordID,
			TenantID:            signed.Claim.TenantID,
			ClientID:            signed.Claim.ClientID,
			KeyID:               signed.Claim.KeyID,
			ClaimHash:           claimHash,
			ClientSignatureHash: signatureHash,
			ReceivedAtUnixN:     receivedAtUnixN,
			WAL:                 position,
		},
		AcceptedReceipt: AcceptedReceipt{
			SchemaVersion:   model.SchemaAcceptedReceipt,
			CryptoSuite:     signed.CryptoSuite,
			RecordID:        recordID,
			Status:          model.RecordStatusAccepted,
			ServerID:        "server-test",
			ReceivedAtUnixN: receivedAtUnixN,
			WAL:             position,
			ServerSig: model.Signature{
				Alg:       suite.Signature.Algorithm,
				KeyID:     "server-key-test",
				Signature: serverSignature,
			},
		},
		SignedClaim: signed,
	}
}

func validSubmitClaimEnvelope(signed SignedClaim) submitClaimEnvelope {
	result := validSDKSubmitResult(signed, "")
	return submitClaimEnvelope{
		RecordID:        result.RecordID,
		Status:          result.Status,
		ProofLevel:      result.ProofLevel,
		Idempotent:      result.Idempotent,
		BatchEnqueued:   result.BatchEnqueued,
		BatchError:      result.BatchError,
		ServerRecord:    result.ServerRecord,
		AcceptedReceipt: result.AcceptedReceipt,
	}
}
