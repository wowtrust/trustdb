// Package natsingress defines TrustDB's transport-only JetStream ingress wire
// contract. Broker correlation and routing metadata never participates in
// claim, receipt, Merkle, STH, anchor, or offline-proof verification.
package natsingress

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/prooflevel"
	"github.com/wowtrust/trustdb/internal/submission"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const (
	SchemaRequest = "trustdb.nats-ingress-request.v1"
	SchemaResult  = "trustdb.nats-ingress-result.v1"

	ContentType         = "application/vnd.trustdb.nats-ingress+cbor"
	HeaderSchemaVersion = "TrustDB-Schema-Version"
	HeaderMessageID     = "Nats-Msg-Id"

	MaxMessageBytes = 1 << 20
)

const (
	messageIDDomain = "trustdb.nats-message-id.v1"
	routingDomain   = "trustdb.nats-routing-key.v1"
	messageIDPrefix = "tnm1"
	routingPrefix   = "tnr1"
)

var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Request carries exactly one existing SignedClaim. MessageID is derived from
// the complete canonical SignedClaim and must match it during decoding.
type Request struct {
	SchemaVersion string            `cbor:"schema_version" json:"schema_version"`
	MessageID     string            `cbor:"message_id" json:"message_id"`
	SignedClaim   model.SignedClaim `cbor:"signed_claim" json:"signed_claim"`
}

// Result carries exactly one accepted outcome or one coded failure.
type Result struct {
	SchemaVersion string    `cbor:"schema_version" json:"schema_version"`
	MessageID     string    `cbor:"message_id" json:"message_id"`
	Accepted      *Accepted `cbor:"accepted,omitempty" json:"accepted,omitempty"`
	Error         *Failure  `cbor:"error,omitempty" json:"error,omitempty"`
}

// Accepted mirrors the transport-neutral Submission Service outcome.
type Accepted struct {
	RecordID        string                `cbor:"record_id" json:"record_id"`
	Status          string                `cbor:"status" json:"status"`
	ProofLevel      string                `cbor:"proof_level" json:"proof_level"`
	Idempotent      bool                  `cbor:"idempotent" json:"idempotent"`
	BatchEnqueued   bool                  `cbor:"batch_enqueued" json:"batch_enqueued"`
	BatchError      string                `cbor:"batch_error,omitempty" json:"batch_error,omitempty"`
	ServerRecord    model.ServerRecord    `cbor:"server_record" json:"server_record"`
	AcceptedReceipt model.AcceptedReceipt `cbor:"accepted_receipt" json:"accepted_receipt"`
}

// Failure preserves the public TrustDB error code and message.
type Failure struct {
	Code    trusterr.Code `cbor:"code" json:"code"`
	Message string        `cbor:"message" json:"message"`
}

func NewRequest(signed model.SignedClaim) (Request, error) {
	if err := validateSignedClaimIdentity(signed); err != nil {
		return Request{}, err
	}
	messageID, err := MessageID(signed)
	if err != nil {
		return Request{}, err
	}
	return Request{
		SchemaVersion: SchemaRequest,
		MessageID:     messageID,
		SignedClaim:   signed,
	}, nil
}

// MessageID is stable for the exact canonical SignedClaim and is suitable for
// the JetStream Nats-Msg-Id deduplication header. Hashing the complete signed
// payload prevents an unverified message from reserving another payload's
// broker deduplication key. TrustDB's durable semantic idempotency check still
// uses tenant/client/idempotency identity after signature validation.
func MessageID(signed model.SignedClaim) (string, error) {
	canonical, err := cborx.Marshal(signed)
	if err != nil {
		return "", fmt.Errorf("canonicalize signed claim for NATS message_id: %w", err)
	}
	return digestIdentity(messageIDPrefix, messageIDDomain, string(canonical)), nil
}

// RoutingKey is stable for one signed tenant/client identity. A future runtime
// may map it to a configured partition count without trusting caller-supplied
// routing metadata.
func RoutingKey(signed model.SignedClaim) string {
	claim := signed.Claim
	return digestIdentity(routingPrefix, routingDomain, claim.TenantID, claim.ClientID)
}

func NewAcceptedResult(request Request, outcome submission.Outcome) (Result, error) {
	result := Result{
		SchemaVersion: SchemaResult,
		MessageID:     request.MessageID,
		Accepted: &Accepted{
			RecordID:        outcome.RecordID,
			Status:          outcome.Status,
			ProofLevel:      outcome.ProofLevel,
			Idempotent:      outcome.Idempotent,
			BatchEnqueued:   outcome.BatchEnqueued,
			BatchError:      outcome.BatchError,
			ServerRecord:    outcome.ServerRecord,
			AcceptedReceipt: outcome.AcceptedReceipt,
		},
	}
	if err := result.ValidateFor(request); err != nil {
		return Result{}, err
	}
	return result, nil
}

func NewErrorResult(request Request, err error) (Result, error) {
	if err == nil {
		return Result{}, errors.New("nats ingress error result requires a non-nil error")
	}
	result := Result{
		SchemaVersion: SchemaResult,
		MessageID:     request.MessageID,
		Error: &Failure{
			Code:    trusterr.CodeOf(err),
			Message: err.Error(),
		},
	}
	if validateErr := result.ValidateFor(request); validateErr != nil {
		return Result{}, validateErr
	}
	return result, nil
}

func EncodeRequest(request Request) ([]byte, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	return marshalBounded(request)
}

func DecodeRequest(data []byte) (Request, error) {
	var request Request
	if err := cborx.UnmarshalLimit(data, &request, MaxMessageBytes); err != nil {
		return Request{}, fmt.Errorf("decode NATS ingress request: %w", err)
	}
	if err := request.Validate(); err != nil {
		return Request{}, err
	}
	return request, nil
}

func EncodeResult(result Result) ([]byte, error) {
	if err := result.Validate(); err != nil {
		return nil, err
	}
	return marshalBounded(result)
}

func DecodeResult(data []byte) (Result, error) {
	var result Result
	if err := cborx.UnmarshalLimit(data, &result, MaxMessageBytes); err != nil {
		return Result{}, fmt.Errorf("decode NATS ingress result: %w", err)
	}
	if err := result.Validate(); err != nil {
		return Result{}, err
	}
	return result, nil
}

func (r Request) Validate() error {
	if r.SchemaVersion != SchemaRequest {
		return fmt.Errorf("unexpected NATS ingress request schema: %s", r.SchemaVersion)
	}
	if err := validateSignedClaimIdentity(r.SignedClaim); err != nil {
		return err
	}
	want, err := MessageID(r.SignedClaim)
	if err != nil {
		return err
	}
	if r.MessageID != want {
		return fmt.Errorf("NATS ingress message_id mismatch: got %q want %q", r.MessageID, want)
	}
	return nil
}

func validateSignedClaimIdentity(signed model.SignedClaim) error {
	if signed.SchemaVersion != model.SchemaSignedClaim {
		return fmt.Errorf("unexpected signed claim schema: %s", signed.SchemaVersion)
	}
	claim := signed.Claim
	if claim.SchemaVersion != model.SchemaClientClaim {
		return fmt.Errorf("unexpected client claim schema: %s", claim.SchemaVersion)
	}
	if strings.TrimSpace(claim.TenantID) == "" || strings.TrimSpace(claim.ClientID) == "" || strings.TrimSpace(claim.IdempotencyKey) == "" {
		return errors.New("NATS ingress signed claim requires tenant_id, client_id, and idempotency_key")
	}
	return nil
}

func (r Result) Validate() error {
	if r.SchemaVersion != SchemaResult {
		return fmt.Errorf("unexpected NATS ingress result schema: %s", r.SchemaVersion)
	}
	if !validDigestID(r.MessageID, messageIDPrefix) {
		return errors.New("NATS ingress result has invalid message_id")
	}
	if (r.Accepted == nil) == (r.Error == nil) {
		return errors.New("NATS ingress result must contain exactly one of accepted or error")
	}
	if r.Accepted != nil {
		return r.Accepted.validate()
	}
	return r.Error.validate()
}

func (r Result) ValidateFor(request Request) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.MessageID != request.MessageID {
		return fmt.Errorf("NATS ingress result message_id %q does not match request %q", r.MessageID, request.MessageID)
	}
	return nil
}

func (a Accepted) validate() error {
	if a.RecordID == "" || a.RecordID != a.ServerRecord.RecordID || a.RecordID != a.AcceptedReceipt.RecordID {
		return errors.New("NATS ingress accepted result has inconsistent record_id")
	}
	if a.ServerRecord.SchemaVersion != model.SchemaServerRecord {
		return fmt.Errorf("unexpected server record schema: %s", a.ServerRecord.SchemaVersion)
	}
	if a.AcceptedReceipt.SchemaVersion != model.SchemaAcceptedReceipt {
		return fmt.Errorf("unexpected accepted receipt schema: %s", a.AcceptedReceipt.SchemaVersion)
	}
	if a.Status == "" || a.Status != a.AcceptedReceipt.Status {
		return errors.New("NATS ingress accepted result has inconsistent status")
	}
	if a.ProofLevel != prooflevel.L2.String() {
		return fmt.Errorf("NATS ingress accepted result proof_level must be %s", prooflevel.L2.String())
	}
	if a.Idempotent && a.BatchEnqueued {
		return errors.New("NATS ingress idempotent result cannot enqueue a duplicate batch entry")
	}
	if a.Idempotent && a.BatchError != "" {
		return errors.New("NATS ingress idempotent result cannot contain a batch_error")
	}
	if a.BatchEnqueued && a.BatchError != "" {
		return errors.New("NATS ingress accepted result cannot contain batch_error when batch_enqueued is true")
	}
	return nil
}

func (f Failure) validate() error {
	if strings.TrimSpace(f.Message) == "" {
		return errors.New("NATS ingress failure message is required")
	}
	switch f.Code {
	case trusterr.CodeInvalidArgument,
		trusterr.CodeFailedPrecondition,
		trusterr.CodeAlreadyExists,
		trusterr.CodeNotFound,
		trusterr.CodeResourceExhausted,
		trusterr.CodeDeadlineExceeded,
		trusterr.CodeDataLoss,
		trusterr.CodeInternal:
		return nil
	default:
		return fmt.Errorf("unknown NATS ingress failure code: %s", f.Code)
	}
}

func marshalBounded(value any) ([]byte, error) {
	data, err := cborx.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxMessageBytes {
		return nil, fmt.Errorf("NATS ingress message too large: %d > %d", len(data), MaxMessageBytes)
	}
	return data, nil
}

func digestIdentity(prefix, domain string, fields ...string) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	var length [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		h.Write(length[:])
		h.Write([]byte(field))
	}
	return prefix + strings.ToLower(base32NoPadding.EncodeToString(h.Sum(nil)))
}

func validDigestID(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+52 {
		return false
	}
	for _, r := range value[len(prefix):] {
		if (r < 'a' || r > 'z') && (r < '2' || r > '7') {
			return false
		}
	}
	return true
}
