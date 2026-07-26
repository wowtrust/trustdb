// Package idempotency owns the shared durable-decision invariants used by
// ingest, batch publication, and proofstore backends.
package idempotency

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"

	"github.com/wowtrust/trustdb/v2/internal/claim"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

// BuildDecision derives and validates the durable idempotency projection for
// one accepted record that opted into idempotency with a non-empty key.
func BuildDecision(
	batchID string,
	signed model.SignedClaim,
	record model.ServerRecord,
	accepted model.AcceptedReceipt,
) (model.IdempotencyDecision, error) {
	return BuildDecisionWithProvider(trustcrypto.DefaultProvider(), batchID, signed, record, accepted)
}

func BuildDecisionWithProvider(
	provider trustcrypto.Provider,
	batchID string,
	signed model.SignedClaim,
	record model.ServerRecord,
	accepted model.AcceptedReceipt,
) (model.IdempotencyDecision, error) {
	suite, identity, claimHash, err := validateAcceptedResponseWithProvider(provider, signed, record, accepted, true)
	if err != nil {
		return model.IdempotencyDecision{}, err
	}
	decision := model.IdempotencyDecision{
		SchemaVersion: model.SchemaIdempotencyDecision,
		CryptoSuite:   suite.ID,
		Identity:      identity,
		ClaimHash:     append([]byte(nil), claimHash...),
		Record:        cloneRecord(record),
		Accepted:      cloneAccepted(accepted),
		BatchID:       batchID,
	}
	if err := ValidateDecisionForSuite(suite.ID, identity, decision); err != nil {
		return model.IdempotencyDecision{}, err
	}
	return decision, nil
}

// ValidateAcceptedResponseWithProvider verifies that an accepted response is
// completely and exactly bound to the submitted signed claim. It validates
// the durable identity, claim/signature hashes, record ID, WAL/timestamp, and
// receipt signature metadata without treating idempotency as mandatory.
func ValidateAcceptedResponseWithProvider(
	provider trustcrypto.Provider,
	signed model.SignedClaim,
	record model.ServerRecord,
	accepted model.AcceptedReceipt,
) error {
	_, _, _, err := validateAcceptedResponseWithProvider(provider, signed, record, accepted, false)
	return err
}

func validateAcceptedResponseWithProvider(
	provider trustcrypto.Provider,
	signed model.SignedClaim,
	record model.ServerRecord,
	accepted model.AcceptedReceipt,
	requireIdempotency bool,
) (cryptosuite.Suite, model.IdempotencyIdentity, []byte, error) {
	if provider == nil {
		return cryptosuite.Suite{}, model.IdempotencyIdentity{}, nil, errors.New("idempotency: crypto provider is required")
	}
	suite, err := cryptosuite.RequireAvailable(provider.Suite())
	if err != nil {
		return cryptosuite.Suite{}, model.IdempotencyIdentity{}, nil, err
	}
	if signed.SchemaVersion != model.SchemaSignedClaim {
		return cryptosuite.Suite{}, model.IdempotencyIdentity{}, nil, fmt.Errorf("idempotency: unexpected signed claim schema %q", signed.SchemaVersion)
	}
	if signed.Signature.KeyID != signed.Claim.KeyID {
		return cryptosuite.Suite{}, model.IdempotencyIdentity{}, nil, errors.New("idempotency: signature key_id does not match claim key_id")
	}
	if signed.Signature.Alg != suite.Signature.Algorithm ||
		len(signed.Signature.Signature) == 0 ||
		(suite.ID == cryptosuite.INTLV1 && len(signed.Signature.Signature) != ed25519.SignatureSize) {
		return cryptosuite.Suite{}, model.IdempotencyIdentity{}, nil, errors.New("idempotency: valid client signature metadata is required")
	}
	if requireIdempotency && signed.Claim.IdempotencyKey == "" {
		return cryptosuite.Suite{}, model.IdempotencyIdentity{}, nil, errors.New("idempotency: idempotency_key is required")
	}
	claimCBOR, err := claim.Canonical(signed.Claim)
	if err != nil {
		return cryptosuite.Suite{}, model.IdempotencyIdentity{}, nil, fmt.Errorf("idempotency: canonicalize claim: %w", err)
	}
	claimHash, err := trustcrypto.HashBytesWithProvider(provider, suite.ClaimHash.Algorithm, claimCBOR)
	if err != nil {
		return cryptosuite.Suite{}, model.IdempotencyIdentity{}, nil, fmt.Errorf("idempotency: hash claim: %w", err)
	}
	if !bytes.Equal(record.ClaimHash, claimHash) {
		return cryptosuite.Suite{}, model.IdempotencyIdentity{}, nil, errors.New("idempotency: server record claim hash does not match signed claim")
	}
	recordID, err := claim.RecordIDWithProvider(provider, claimCBOR, signed.Signature)
	if err != nil {
		return cryptosuite.Suite{}, model.IdempotencyIdentity{}, nil, fmt.Errorf("idempotency: derive record id: %w", err)
	}
	if record.RecordID != recordID {
		return cryptosuite.Suite{}, model.IdempotencyIdentity{}, nil, errors.New("idempotency: server record id does not match signed claim")
	}
	signatureHash, err := trustcrypto.HashBytesWithProvider(provider, suite.SignatureHash.Algorithm, signed.Signature.Signature)
	if err != nil {
		return cryptosuite.Suite{}, model.IdempotencyIdentity{}, nil, fmt.Errorf("idempotency: hash client signature: %w", err)
	}
	if !bytes.Equal(record.ClientSignatureHash, signatureHash) {
		return cryptosuite.Suite{}, model.IdempotencyIdentity{}, nil, errors.New("idempotency: server record signature hash does not match signed claim")
	}
	if record.KeyID != signed.Claim.KeyID {
		return cryptosuite.Suite{}, model.IdempotencyIdentity{}, nil, errors.New("idempotency: server record key_id does not match signed claim")
	}
	identity := model.IdempotencyIdentity{
		TenantID:       signed.Claim.TenantID,
		ClientID:       signed.Claim.ClientID,
		IdempotencyKey: signed.Claim.IdempotencyKey,
	}
	if err := validateResponseBindings(suite, identity, claimHash, record, accepted); err != nil {
		return cryptosuite.Suite{}, model.IdempotencyIdentity{}, nil, err
	}
	return suite, identity, claimHash, nil
}

// ValidateDecision checks all bindings available from the compact durable
// projection. Signature verification is intentionally outside this helper;
// BuildDecision already derives the projection from a previously verified
// SignedClaim, while readers validate the immutable response relationships.
func ValidateDecision(identity model.IdempotencyIdentity, decision model.IdempotencyDecision) error {
	return ValidateDecisionForSuite(cryptosuite.INTLV1, identity, decision)
}

func ValidateDecisionForSuite(suiteID cryptosuite.ID, identity model.IdempotencyIdentity, decision model.IdempotencyDecision) error {
	suite, err := cryptosuite.RequireKnown(suiteID)
	if err != nil {
		return err
	}
	if identity.TenantID == "" || identity.ClientID == "" || identity.IdempotencyKey == "" {
		return errors.New("idempotency: tenant_id, client_id, and idempotency_key are required")
	}
	if decision.SchemaVersion != model.SchemaIdempotencyDecision {
		return fmt.Errorf("idempotency: unexpected decision schema %q", decision.SchemaVersion)
	}
	if err := cryptosuite.RequireSame(suite.ID, decision.CryptoSuite, decision.Record.CryptoSuite, decision.Accepted.CryptoSuite); err != nil {
		return fmt.Errorf("idempotency: crypto_suite: %w", err)
	}
	if decision.Identity != identity {
		return errors.New("idempotency: decision identity does not match lookup identity")
	}
	if decision.BatchID == "" {
		return errors.New("idempotency: batch_id is required")
	}
	if len(decision.ClaimHash) != suite.ClaimHash.DigestBytes {
		return fmt.Errorf("idempotency: claim_hash length is %d, want %d", len(decision.ClaimHash), suite.ClaimHash.DigestBytes)
	}
	return validateResponseBindings(suite, identity, decision.ClaimHash, decision.Record, decision.Accepted)
}

func validateResponseBindings(
	suite cryptosuite.Suite,
	identity model.IdempotencyIdentity,
	claimHash []byte,
	record model.ServerRecord,
	accepted model.AcceptedReceipt,
) error {
	if record.SchemaVersion != model.SchemaServerRecord {
		return fmt.Errorf("idempotency: unexpected server record schema %q", record.SchemaVersion)
	}
	if record.RecordID == "" {
		return errors.New("idempotency: record_id is required")
	}
	if record.TenantID != identity.TenantID || record.ClientID != identity.ClientID {
		return errors.New("idempotency: server record identity does not match decision identity")
	}
	if record.KeyID == "" {
		return errors.New("idempotency: server record key_id is required")
	}
	if record.ReceivedAtUnixN <= 0 {
		return errors.New("idempotency: server record received_at_unix_n must be positive")
	}
	if !bytes.Equal(record.ClaimHash, claimHash) {
		return errors.New("idempotency: server record claim_hash does not match decision")
	}
	if len(record.ClientSignatureHash) != suite.SignatureHash.DigestBytes {
		return fmt.Errorf("idempotency: client signature hash length is %d, want %d", len(record.ClientSignatureHash), suite.SignatureHash.DigestBytes)
	}
	if err := validateWALPosition(record.WAL); err != nil {
		return err
	}
	if accepted.SchemaVersion != model.SchemaAcceptedReceipt {
		return fmt.Errorf("idempotency: unexpected accepted receipt schema %q", accepted.SchemaVersion)
	}
	if accepted.RecordID != record.RecordID {
		return errors.New("idempotency: accepted receipt record_id does not match server record")
	}
	if accepted.Status != "accepted" {
		return fmt.Errorf("idempotency: unexpected accepted receipt status %q", accepted.Status)
	}
	if accepted.ServerID == "" {
		return errors.New("idempotency: accepted receipt server_id is required")
	}
	if accepted.ReceivedAtUnixN != record.ReceivedAtUnixN {
		return errors.New("idempotency: accepted receipt timestamp does not match server record")
	}
	if accepted.WAL != record.WAL {
		return errors.New("idempotency: accepted receipt WAL position does not match server record")
	}
	if accepted.ServerSig.Alg != suite.Signature.Algorithm ||
		accepted.ServerSig.KeyID == "" ||
		len(accepted.ServerSig.Signature) == 0 ||
		(suite.ID == cryptosuite.INTLV1 && len(accepted.ServerSig.Signature) != ed25519.SignatureSize) {
		return errors.New("idempotency: accepted receipt server signature is required")
	}
	return nil
}

func validateWALPosition(position model.WALPosition) error {
	if position.SegmentID == 0 || position.Offset < 0 || position.Sequence == 0 {
		return errors.New("idempotency: server record has an invalid WAL position")
	}
	return nil
}

// Equivalent reports whether two projections encode exactly the same durable
// decision. It is used to make replay and projection rebuilds idempotent while rejecting
// a second response for the same identity.
func Equivalent(a, b model.IdempotencyDecision) bool {
	return reflect.DeepEqual(a, b)
}

// StorageKey returns a fixed-width, collision-resistant key for an identity.
// Each component is length-delimited before hashing, so arbitrary UTF-8 and
// embedded NUL bytes cannot make distinct identities share a key.
func StorageKey(identity model.IdempotencyIdentity) string {
	key, err := StorageKeyForSuite(cryptosuite.INTLV1, identity)
	if err != nil {
		panic(err)
	}
	return key
}

func StorageKeyForSuite(suiteID cryptosuite.ID, identity model.IdempotencyIdentity) (string, error) {
	suite, err := cryptosuite.RequireKnown(suiteID)
	if err != nil {
		return "", err
	}
	factory, err := trustcrypto.HashFactoryForSuite(suiteID, suite.StorageIntegrityHash.Algorithm)
	if err != nil {
		return "", err
	}
	h := factory.New()
	_, _ = h.Write([]byte(suite.Domains.IdempotencyStorageKey))
	_, _ = h.Write([]byte{0})
	if suite.ID == cryptosuite.CNSMV1 {
		_, _ = h.Write([]byte(suite.ID))
		_, _ = h.Write([]byte{0})
	}
	writeStorageKeyComponent(h, identity.TenantID)
	writeStorageKeyComponent(h, identity.ClientID)
	writeStorageKeyComponent(h, identity.IdempotencyKey)
	return hex.EncodeToString(h.Sum(nil)), nil
}

type byteWriter interface {
	Write([]byte) (int, error)
}

func writeStorageKeyComponent(dst byteWriter, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = dst.Write(size[:])
	_, _ = dst.Write([]byte(value))
}

func cloneRecord(record model.ServerRecord) model.ServerRecord {
	record.ClaimHash = append([]byte(nil), record.ClaimHash...)
	record.ClientSignatureHash = append([]byte(nil), record.ClientSignatureHash...)
	return record
}

func cloneAccepted(accepted model.AcceptedReceipt) model.AcceptedReceipt {
	accepted.ServerSig.Signature = append([]byte(nil), accepted.ServerSig.Signature...)
	return accepted
}
