package idempotency

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/claim"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/receipt"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

func TestBuildDecisionValidatesAndCopiesAcceptedResponse(t *testing.T) {
	t.Parallel()

	signed, record, accepted := validDecisionInputs(t, "request-a")
	decision, err := BuildDecision("batch-a", signed, record, accepted)
	if err != nil {
		t.Fatalf("BuildDecision() error = %v", err)
	}
	wantIdentity := model.IdempotencyIdentity{TenantID: "tenant-a", ClientID: "client-a", IdempotencyKey: "request-a"}
	if decision.Identity != wantIdentity || decision.BatchID != "batch-a" {
		t.Fatalf("BuildDecision() = %+v", decision)
	}
	if err := ValidateDecision(wantIdentity, decision); err != nil {
		t.Fatalf("ValidateDecision() error = %v", err)
	}

	// The persisted projection must not alias transient batch buffers.
	record.ClaimHash[0] ^= 0xff
	accepted.ServerSig.Signature[0] ^= 0xff
	if bytes.Equal(decision.ClaimHash, record.ClaimHash) ||
		bytes.Equal(decision.Accepted.ServerSig.Signature, accepted.ServerSig.Signature) {
		t.Fatal("BuildDecision() retained caller-owned byte slices")
	}
}

func TestBuildDecisionRejectsEmptyIdempotencyKey(t *testing.T) {
	t.Parallel()

	signed, record, accepted := validDecisionInputs(t, "request-before-mutation")
	signed.Claim.IdempotencyKey = ""
	if _, err := BuildDecision("batch-a", signed, record, accepted); err == nil || !strings.Contains(err.Error(), "idempotency_key") {
		t.Fatalf("BuildDecision() error = %v, want missing idempotency_key", err)
	}
}

func TestBuildDecisionRejectsBrokenSignedBindings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*model.SignedClaim, *model.ServerRecord, *model.AcceptedReceipt)
		want   string
	}{
		{name: "claim hash", mutate: func(_ *model.SignedClaim, record *model.ServerRecord, _ *model.AcceptedReceipt) {
			record.ClaimHash[0] ^= 0xff
		}, want: "claim hash"},
		{name: "record id", mutate: func(_ *model.SignedClaim, record *model.ServerRecord, _ *model.AcceptedReceipt) {
			record.RecordID = "different"
		}, want: "record id"},
		{name: "signature hash", mutate: func(_ *model.SignedClaim, record *model.ServerRecord, _ *model.AcceptedReceipt) {
			record.ClientSignatureHash[0] ^= 0xff
		}, want: "signature hash"},
		{name: "key id", mutate: func(_ *model.SignedClaim, record *model.ServerRecord, _ *model.AcceptedReceipt) {
			record.KeyID = "different"
		}, want: "key_id"},
		{name: "signature algorithm", mutate: func(signed *model.SignedClaim, _ *model.ServerRecord, _ *model.AcceptedReceipt) {
			signed.Signature.Alg = "rewritten-algorithm"
		}, want: "signature metadata"},
		{name: "signature length", mutate: func(signed *model.SignedClaim, _ *model.ServerRecord, _ *model.AcceptedReceipt) {
			signed.Signature.Signature = signed.Signature.Signature[:ed25519.SignatureSize-1]
		}, want: "signature metadata"},
		{name: "receipt wal", mutate: func(_ *model.SignedClaim, _ *model.ServerRecord, accepted *model.AcceptedReceipt) {
			accepted.WAL.Sequence++
		}, want: "WAL position"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			signed, record, accepted := validDecisionInputs(t, "request-a")
			tt.mutate(&signed, &record, &accepted)
			if _, err := BuildDecision("batch-a", signed, record, accepted); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("BuildDecision() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestValidateDecisionRejectsLookupIdentityMismatch(t *testing.T) {
	t.Parallel()

	signed, record, accepted := validDecisionInputs(t, "request-a")
	decision, err := BuildDecision("batch-a", signed, record, accepted)
	if err != nil {
		t.Fatalf("BuildDecision() error = %v", err)
	}
	other := decision.Identity
	other.ClientID = "client-b"
	if err := ValidateDecision(other, decision); err == nil || !strings.Contains(err.Error(), "lookup identity") {
		t.Fatalf("ValidateDecision() error = %v, want lookup identity mismatch", err)
	}
}

func TestValidateDecisionForSuiteRequiresSuiteSignatureMetadata(t *testing.T) {
	t.Parallel()

	signed, record, accepted := validDecisionInputs(t, "request-a")
	decision, err := BuildDecision("batch-a", signed, record, accepted)
	if err != nil {
		t.Fatal(err)
	}
	decision.Accepted.ServerSig.Alg = cryptosuite.SignatureEd25519
	if err := ValidateDecisionForSuite(cryptosuite.CNSMV1, decision.Identity, decision); err == nil {
		t.Fatal("ValidateDecisionForSuite(CN_SM_V1) accepted INTL_V1 signature metadata")
	}
	decision.Accepted.ServerSig.Alg = cryptosuite.SignatureSM2SM3
	decision.Accepted.ServerSig.Signature = nil
	if err := ValidateDecisionForSuite(cryptosuite.CNSMV1, decision.Identity, decision); err == nil {
		t.Fatal("ValidateDecisionForSuite(CN_SM_V1) accepted an empty signature")
	}
}

func TestEquivalentDetectsResponseChanges(t *testing.T) {
	t.Parallel()

	signed, record, accepted := validDecisionInputs(t, "request-a")
	decision, err := BuildDecision("batch-a", signed, record, accepted)
	if err != nil {
		t.Fatalf("BuildDecision() error = %v", err)
	}
	identical := decision
	identical.ClaimHash = append([]byte(nil), decision.ClaimHash...)
	identical.Record.ClaimHash = append([]byte(nil), decision.Record.ClaimHash...)
	identical.Accepted.ServerSig.Signature = append([]byte(nil), decision.Accepted.ServerSig.Signature...)
	if !Equivalent(decision, identical) {
		t.Fatal("Equivalent() = false for identical decisions")
	}
	identical.BatchID = "batch-b"
	if Equivalent(decision, identical) {
		t.Fatal("Equivalent() = true after batch_id changed")
	}
}

func TestStorageKeyIsStableAndComponentSafe(t *testing.T) {
	t.Parallel()

	identity := model.IdempotencyIdentity{TenantID: "tenant", ClientID: "client", IdempotencyKey: "key"}
	first := StorageKey(identity)
	if len(first) != sha256HexLength || first != StorageKey(identity) {
		t.Fatalf("StorageKey() = %q", first)
	}
	if first == StorageKey(model.IdempotencyIdentity{TenantID: "tenant\x00client", ClientID: "", IdempotencyKey: "key"}) {
		t.Fatal("StorageKey() collided across component boundaries")
	}
	if first == StorageKey(model.IdempotencyIdentity{TenantID: "tenant", ClientID: "client", IdempotencyKey: "key\x00"}) {
		t.Fatal("StorageKey() ignored embedded NUL")
	}
}

func TestStorageKeyForSuitePinsCanonicalVectors(t *testing.T) {
	t.Parallel()

	identity := model.IdempotencyIdentity{
		TenantID:       "tenant",
		ClientID:       "client",
		IdempotencyKey: "key",
	}
	tests := []struct {
		name    string
		suiteID cryptosuite.ID
		want    string
	}{
		{
			name:    "INTL_V1 SHA-256",
			suiteID: cryptosuite.INTLV1,
			want:    "35f7b4a2c0e49e8c72708eba6245c0fcca7107b13953141630f8b286a5947638",
		},
		{
			name:    "CN_SM_V1 SM3 and suite framing",
			suiteID: cryptosuite.CNSMV1,
			want:    "c9c4fc9a13e82043c97e461201fdba1faf7286edeee33e5fd89b1b9096262645",
		},
	}
	keys := make(map[string]struct{}, len(tests))
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := StorageKeyForSuite(tt.suiteID, identity)
			if err != nil {
				t.Fatalf("StorageKeyForSuite(%s) error = %v", tt.suiteID, err)
			}
			if got != tt.want {
				t.Fatalf("StorageKeyForSuite(%s) = %q, want %q", tt.suiteID, got, tt.want)
			}
		})
		key, err := StorageKeyForSuite(tt.suiteID, identity)
		if err != nil {
			t.Fatalf("StorageKeyForSuite(%s) error = %v", tt.suiteID, err)
		}
		if _, exists := keys[key]; exists {
			t.Fatalf("suite-specific storage key collision for %s", tt.suiteID)
		}
		keys[key] = struct{}{}
	}
	if got := StorageKey(identity); got != tests[0].want {
		t.Fatalf("StorageKey() = %q, want legacy INTL_V1 vector %q", got, tests[0].want)
	}
}

func TestStorageKeyForSuiteRejectsUnknownSuite(t *testing.T) {
	t.Parallel()

	identity := model.IdempotencyIdentity{TenantID: "tenant", ClientID: "client", IdempotencyKey: "key"}
	if _, err := StorageKeyForSuite(cryptosuite.ID("UNKNOWN"), identity); err == nil {
		t.Fatal("StorageKeyForSuite() error = nil for unknown suite")
	}
}

const sha256HexLength = 64

func validDecisionInputs(t *testing.T, idempotencyKey string) (model.SignedClaim, model.ServerRecord, model.AcceptedReceipt) {
	t.Helper()

	clientPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	serverPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	clientClaim := model.ClientClaim{CryptoSuite: "INTL_V1",
		SchemaVersion:   model.SchemaClientClaim,
		TenantID:        "tenant-a",
		ClientID:        "client-a",
		KeyID:           "client-key-a",
		ProducedAtUnixN: time.Unix(10, 0).UnixNano(),
		Nonce:           bytes.Repeat([]byte{3}, 16),
		IdempotencyKey:  idempotencyKey,
		Content: model.Content{
			HashAlg:       model.DefaultHashAlg,
			ContentHash:   bytes.Repeat([]byte{4}, 32),
			ContentLength: 42,
		},
		Metadata:        model.Metadata{EventType: "test"},
		TimeAttestation: model.TimeAttestation{Type: "none"},
	}
	signed, err := claim.Sign(clientClaim, clientPrivate)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	canonical, err := claim.Canonical(clientClaim)
	if err != nil {
		t.Fatalf("Canonical() error = %v", err)
	}
	claimHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, canonical)
	if err != nil {
		t.Fatalf("HashBytes(claim) error = %v", err)
	}
	signatureHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, signed.Signature.Signature)
	if err != nil {
		t.Fatalf("HashBytes(signature) error = %v", err)
	}
	position := model.WALPosition{SegmentID: 1, Offset: 64, Sequence: 7}
	record := model.ServerRecord{CryptoSuite: "INTL_V1",
		SchemaVersion:       model.SchemaServerRecord,
		RecordID:            claim.RecordID(canonical, signed.Signature),
		TenantID:            clientClaim.TenantID,
		ClientID:            clientClaim.ClientID,
		KeyID:               clientClaim.KeyID,
		ClaimHash:           claimHash,
		ClientSignatureHash: signatureHash,
		ReceivedAtUnixN:     time.Unix(20, 0).UnixNano(),
		WAL:                 position,
		Validation: model.Validation{
			PolicyVersion:       model.DefaultValidationPolicy,
			HashAlgAllowed:      true,
			SignatureAlgAllowed: true,
			KeyStatus:           model.KeyStatusValid,
		},
	}
	accepted := model.AcceptedReceipt{CryptoSuite: "INTL_V1",
		SchemaVersion:   model.SchemaAcceptedReceipt,
		RecordID:        record.RecordID,
		Status:          "accepted",
		ServerID:        "server-a",
		ReceivedAtUnixN: record.ReceivedAtUnixN,
		WAL:             position,
	}
	accepted, err = receipt.SignAccepted(accepted, "server-key-a", serverPrivate)
	if err != nil {
		t.Fatalf("SignAccepted() error = %v", err)
	}
	return signed, record, accepted
}
