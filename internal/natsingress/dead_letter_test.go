package natsingress

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestDeadLetterCanonicalRoundTripPreservesCompleteRejection(t *testing.T) {
	t.Parallel()

	rejection := fixtureRejection()
	deadLetter, err := NewDeadLetter(rejection)
	if err != nil {
		t.Fatalf("NewDeadLetter() error = %v", err)
	}
	rejection.Headers.Set("Mutated", "later")
	rejection.Data[0] ^= 0xff

	encoded, err := EncodeDeadLetter(deadLetter)
	if err != nil {
		t.Fatalf("EncodeDeadLetter() error = %v", err)
	}
	decoded, err := DecodeDeadLetter(encoded)
	if err != nil {
		t.Fatalf("DecodeDeadLetter() error = %v", err)
	}
	second, err := EncodeDeadLetter(decoded)
	if err != nil {
		t.Fatalf("EncodeDeadLetter(second) error = %v", err)
	}
	if !bytes.Equal(encoded, second) {
		t.Fatal("dead-letter encoding is not deterministic")
	}
	if decoded.ID == decoded.Headers.Get(HeaderMessageID) {
		t.Fatal("dead-letter trusted the malformed caller message ID as its identity")
	}
	if decoded.Subject != "trustdb.ingress.v1.claims" || decoded.Reply != "reply.subject" || decoded.Stream != "TRUSTDB_INGRESS" || decoded.Consumer != "trustdb-ingress" {
		t.Fatalf("decoded broker identity = %+v", decoded)
	}
	if decoded.StreamSequence != 17 || decoded.ConsumerSequence != 9 || decoded.NumDelivered != 3 {
		t.Fatalf("decoded delivery metadata = %+v", decoded)
	}
	if decoded.Headers.Get("X-Trace") != "trace-a" || !bytes.Equal(decoded.Data, []byte{0xff, 0x01, 0x02, 0x03}) {
		t.Fatalf("decoded raw rejection = headers=%v data=%x", decoded.Headers, decoded.Data)
	}

	digest := sha256.Sum256(encoded)
	const wantSHA256 = "32fb7ceab5489f187b7bdaeeb05cf4ffd7601f54face466f853794b9da33547f"
	if got := hex.EncodeToString(digest[:]); got != wantSHA256 {
		t.Fatalf("dead-letter CBOR SHA-256 = %s, want %s", got, wantSHA256)
	}
}

func TestDeadLetterRejectsTamperingUnknownFieldsAndOversize(t *testing.T) {
	t.Parallel()

	deadLetter, err := NewDeadLetter(fixtureRejection())
	if err != nil {
		t.Fatal(err)
	}
	deadLetter.FormatGeneration = "trustdb.nats-ingress.v2"
	if _, err := EncodeDeadLetter(deadLetter); err == nil || !strings.Contains(err.Error(), "format generation") {
		t.Fatalf("EncodeDeadLetter(format generation) error = %v", err)
	}

	deadLetter, err = NewDeadLetter(fixtureRejection())
	if err != nil {
		t.Fatal(err)
	}
	deadLetter.Data[0] ^= 0xff
	if _, err := EncodeDeadLetter(deadLetter); err == nil || !strings.Contains(err.Error(), "id mismatch") {
		t.Fatalf("EncodeDeadLetter(tampered) error = %v", err)
	}

	deadLetter, err = NewDeadLetter(fixtureRejection())
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := cborx.Marshal(map[string]any{
		"schema_version":     deadLetter.SchemaVersion,
		"format_generation":  deadLetter.FormatGeneration,
		"id":                 deadLetter.ID,
		"subject":            deadLetter.Subject,
		"reply":              deadLetter.Reply,
		"headers":            deadLetter.Headers,
		"data":               deadLetter.Data,
		"stream":             deadLetter.Stream,
		"consumer":           deadLetter.Consumer,
		"stream_sequence":    deadLetter.StreamSequence,
		"consumer_sequence":  deadLetter.ConsumerSequence,
		"num_delivered":      deadLetter.NumDelivered,
		"code":               deadLetter.Code,
		"message":            deadLetter.Message,
		"unrecognized_field": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDeadLetter(unknown); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("DecodeDeadLetter(unknown field) error = %v", err)
	}
	if _, err := DecodeDeadLetter(make([]byte, MaxDeadLetterBytes+1)); err == nil || !strings.Contains(err.Error(), "payload too large") {
		t.Fatalf("DecodeDeadLetter(oversized) error = %v", err)
	}

	rejection := fixtureRejection()
	rejection.Data = make([]byte, MaxMessageBytes+1)
	rejection.ID = rejectionIdentity(rejection.Stream, rejection.StreamSequence, rejection.Subject, rejection.Reply, rejection.Headers, rejection.Data)
	if _, err := NewDeadLetter(rejection); err == nil || !strings.Contains(err.Error(), "raw data too large") {
		t.Fatalf("NewDeadLetter(oversized raw data) error = %v", err)
	}
}

func TestDeadLetterRejectsIncompleteMetadata(t *testing.T) {
	t.Parallel()

	rejection := fixtureRejection()
	rejection.Consumer = ""
	if _, err := NewDeadLetter(rejection); err == nil || !strings.Contains(err.Error(), "incomplete JetStream metadata") {
		t.Fatalf("NewDeadLetter(incomplete metadata) error = %v", err)
	}

	rejection = fixtureRejection()
	rejection.Stream = ""
	rejection.ID = rejectionIdentity("", 0, rejection.Subject, rejection.Reply, rejection.Headers, rejection.Data)
	if _, err := NewDeadLetter(rejection); err == nil || !strings.Contains(err.Error(), "partial JetStream metadata") {
		t.Fatalf("NewDeadLetter(partial metadata) error = %v", err)
	}
}

func fixtureRejection() Rejection {
	headers := nats.Header{
		HeaderContentType: {"application/json"},
		HeaderMessageID:   {"caller-controlled-invalid-id"},
		"X-Trace":         {"trace-a", "trace-b"},
	}
	rejection := Rejection{
		Subject:          "trustdb.ingress.v1.claims",
		Reply:            "reply.subject",
		Headers:          headers,
		Data:             []byte{0xff, 0x01, 0x02, 0x03},
		Stream:           "TRUSTDB_INGRESS",
		Consumer:         "trustdb-ingress",
		StreamSequence:   17,
		ConsumerSequence: 9,
		NumDelivered:     3,
		Code:             trusterr.CodeInvalidArgument,
		Message:          "decode NATS ingress request: malformed CBOR",
	}
	rejection.ID = rejectionIdentity(rejection.Stream, rejection.StreamSequence, rejection.Subject, rejection.Reply, rejection.Headers, rejection.Data)
	return rejection
}
