package natsingress

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/submission"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestMessageIDAndRoutingKeyAreDeterministicAndScoped(t *testing.T) {
	t.Parallel()

	base := fixtureSignedClaim()
	baseMessageID := mustMessageID(t, base)
	if got, want := mustMessageID(t, base), baseMessageID; got != want {
		t.Fatalf("MessageID is not deterministic: %q != %q", got, want)
	}
	if got, want := RoutingKey(base), RoutingKey(base); got != want {
		t.Fatalf("RoutingKey is not deterministic: %q != %q", got, want)
	}

	exactRetry := base
	if mustMessageID(t, exactRetry) != baseMessageID {
		t.Fatal("MessageID changed across an exact signed request retry")
	}

	resigned := base
	resigned.Signature.Signature = []byte("different-signature")
	resigned.Claim.Nonce = []byte("different-nonce")
	if mustMessageID(t, resigned) == baseMessageID {
		t.Fatal("MessageID did not change with the signed payload")
	}
	if RoutingKey(resigned) != RoutingKey(base) {
		t.Fatal("RoutingKey changed across the same tenant/client identity")
	}

	differentRequest := base
	differentRequest.Claim.IdempotencyKey = "idem-2"
	if mustMessageID(t, differentRequest) == baseMessageID {
		t.Fatal("MessageID did not change with idempotency_key")
	}
	if RoutingKey(differentRequest) != RoutingKey(base) {
		t.Fatal("RoutingKey changed with idempotency_key")
	}

	differentClient := base
	differentClient.Claim.ClientID = "client-b"
	if mustMessageID(t, differentClient) == baseMessageID || RoutingKey(differentClient) == RoutingKey(base) {
		t.Fatal("identity derivation did not change with client_id")
	}
}

func TestRequestCanonicalRoundTripAndGoldenDigest(t *testing.T) {
	t.Parallel()

	want := mustRequest(t)
	data, err := EncodeRequest(want)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	got, err := DecodeRequest(data)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if got.MessageID != want.MessageID || got.SignedClaim.Claim.IdempotencyKey != want.SignedClaim.Claim.IdempotencyKey {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	second, err := EncodeRequest(got)
	if err != nil {
		t.Fatalf("EncodeRequest(second): %v", err)
	}
	if string(second) != string(data) {
		t.Fatal("request encoding is not deterministic")
	}
	digest := sha256.Sum256(data)
	const wantSHA256 = "9e8d6fafd8a56c3e952f13a734c3f7e8a437b10a7cc30a635311c5202259178f"
	if gotDigest := hex.EncodeToString(digest[:]); gotDigest != wantSHA256 {
		t.Fatalf("request CBOR SHA-256 = %s, want %s", gotDigest, wantSHA256)
	}
}

func TestRequestRejectsTamperingUnknownFieldsAndOversize(t *testing.T) {
	t.Parallel()

	request := mustRequest(t)
	last := request.MessageID[len(request.MessageID)-1]
	if last == 'a' {
		request.MessageID = request.MessageID[:len(request.MessageID)-1] + "b"
	} else {
		request.MessageID = request.MessageID[:len(request.MessageID)-1] + "a"
	}
	if _, err := EncodeRequest(request); err == nil || !strings.Contains(err.Error(), "message_id mismatch") {
		t.Fatalf("EncodeRequest tampered error = %v", err)
	}

	request = mustRequest(t)
	request.SchemaVersion = "trustdb.nats-ingress-request.v0"
	if _, err := EncodeRequest(request); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("EncodeRequest schema error = %v", err)
	}

	request = mustRequest(t)
	unknown, err := cborx.Marshal(map[string]any{
		"schema_version": request.SchemaVersion,
		"message_id":     request.MessageID,
		"signed_claim":   request.SignedClaim,
		"unknown":        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRequest(unknown); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("DecodeRequest unknown field error = %v", err)
	}

	if _, err := DecodeRequest(make([]byte, MaxMessageBytes+1)); err == nil || !strings.Contains(err.Error(), "payload too large") {
		t.Fatalf("DecodeRequest oversized error = %v", err)
	}
}

func TestAcceptedResultPreservesSubmissionOutcome(t *testing.T) {
	t.Parallel()

	request := mustRequest(t)
	outcome := fixtureOutcome()
	result, err := NewAcceptedResult(request, outcome)
	if err != nil {
		t.Fatalf("NewAcceptedResult: %v", err)
	}
	data, err := EncodeResult(result)
	if err != nil {
		t.Fatalf("EncodeResult: %v", err)
	}
	got, err := DecodeResult(data)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	if err := got.ValidateFor(request); err != nil {
		t.Fatalf("ValidateFor: %v", err)
	}
	if got.Accepted == nil || got.Error != nil {
		t.Fatalf("decoded result = %+v", got)
	}
	if got.Accepted.RecordID != outcome.RecordID || got.Accepted.BatchEnqueued != outcome.BatchEnqueued || got.Accepted.AcceptedReceipt.RecordID != outcome.AcceptedReceipt.RecordID {
		t.Fatalf("accepted result = %+v, outcome = %+v", got.Accepted, outcome)
	}
}

func TestErrorResultPreservesTrustDBCode(t *testing.T) {
	t.Parallel()

	request := mustRequest(t)
	wantErr := trusterr.Wrap(trusterr.CodeResourceExhausted, "ingress unavailable", errors.New("capacity"))
	result, err := NewErrorResult(request, wantErr)
	if err != nil {
		t.Fatalf("NewErrorResult: %v", err)
	}
	if result.Error == nil || result.Accepted != nil || result.Error.Code != trusterr.CodeResourceExhausted || result.Error.Message != wantErr.Error() {
		t.Fatalf("error result = %+v", result)
	}
	if _, err := NewErrorResult(request, nil); err == nil {
		t.Fatal("NewErrorResult accepted nil error")
	}
}

func TestResultRejectsAmbiguousOrInconsistentPayload(t *testing.T) {
	t.Parallel()

	request := mustRequest(t)
	accepted, err := NewAcceptedResult(request, fixtureOutcome())
	if err != nil {
		t.Fatal(err)
	}
	accepted.Error = &Failure{Code: trusterr.CodeInternal, Message: "ambiguous"}
	if err := accepted.Validate(); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("ambiguous Validate error = %v", err)
	}

	accepted.Error = nil
	accepted.Accepted.ServerRecord.RecordID = "different"
	if err := accepted.Validate(); err == nil || !strings.Contains(err.Error(), "inconsistent record_id") {
		t.Fatalf("record mismatch Validate error = %v", err)
	}

	errorResult, err := NewErrorResult(request, trusterr.New(trusterr.CodeInvalidArgument, "bad claim"))
	if err != nil {
		t.Fatal(err)
	}
	errorResult.MessageID = messageIDPrefix + strings.Repeat("a", 52)
	if err := errorResult.ValidateFor(request); err == nil || !strings.Contains(err.Error(), "does not match request") {
		t.Fatalf("correlation Validate error = %v", err)
	}
}

func TestResultRejectsWrongSchemaUnknownFieldsAndOversize(t *testing.T) {
	t.Parallel()

	request := mustRequest(t)
	result, err := NewErrorResult(request, trusterr.New(trusterr.CodeInvalidArgument, "bad claim"))
	if err != nil {
		t.Fatal(err)
	}
	result.SchemaVersion = "trustdb.nats-ingress-result.v0"
	if _, err := EncodeResult(result); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("EncodeResult schema error = %v", err)
	}

	unknown, err := cborx.Marshal(map[string]any{
		"schema_version": SchemaResult,
		"message_id":     request.MessageID,
		"error": map[string]any{
			"code":    string(trusterr.CodeInvalidArgument),
			"message": "bad claim",
		},
		"unknown": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResult(unknown); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("DecodeResult unknown field error = %v", err)
	}
	if _, err := DecodeResult(make([]byte, MaxMessageBytes+1)); err == nil || !strings.Contains(err.Error(), "payload too large") {
		t.Fatalf("DecodeResult oversized error = %v", err)
	}
}

func fixtureSignedClaim() model.SignedClaim {
	return model.SignedClaim{
		SchemaVersion: model.SchemaSignedClaim,
		Claim: model.ClientClaim{
			SchemaVersion:  model.SchemaClientClaim,
			TenantID:       "tenant-a",
			ClientID:       "client-a",
			IdempotencyKey: "idem-1",
		},
		Signature: model.Signature{
			Alg:       model.DefaultSignatureAlg,
			KeyID:     "key-a",
			Signature: []byte("signature"),
		},
	}
}

func mustRequest(t *testing.T) Request {
	t.Helper()
	request, err := NewRequest(fixtureSignedClaim())
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return request
}

func mustMessageID(t *testing.T, signed model.SignedClaim) string {
	t.Helper()
	messageID, err := MessageID(signed)
	if err != nil {
		t.Fatalf("MessageID: %v", err)
	}
	return messageID
}

func fixtureOutcome() submission.Outcome {
	const recordID = "tr1natscontract"
	return submission.Outcome{
		RecordID:      recordID,
		Status:        "accepted",
		ProofLevel:    "L2",
		BatchEnqueued: true,
		ServerRecord: model.ServerRecord{
			SchemaVersion: model.SchemaServerRecord,
			RecordID:      recordID,
		},
		AcceptedReceipt: model.AcceptedReceipt{
			SchemaVersion: model.SchemaAcceptedReceipt,
			RecordID:      recordID,
			Status:        "accepted",
		},
	}
}
