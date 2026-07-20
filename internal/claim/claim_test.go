package claim

import (
	"bytes"
	"testing"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trustcrypto"
)

func TestSignVerifyAndRecordID(t *testing.T) {
	t.Parallel()

	pub, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	nonce := bytes.Repeat([]byte{1}, 16)
	c, err := NewFileClaim(
		"tenant-a",
		"client-a",
		"key-a",
		time.Unix(100, 5),
		nonce,
		"idem-a",
		model.Content{HashAlg: model.DefaultHashAlg, ContentHash: bytes.Repeat([]byte{2}, 32), ContentLength: 12},
		model.Metadata{EventType: "file.snapshot"},
	)
	if err != nil {
		t.Fatalf("NewFileClaim() error = %v", err)
	}
	signed, err := Sign(c, priv)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	verified, err := Verify(signed, pub)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verified.RecordID == "" {
		t.Fatal("Verify() returned empty record id")
	}
	if verified.RecordID != RecordID(verified.ClaimCBOR, signed.Signature) {
		t.Fatal("record id is not stable")
	}
}

func TestVerifyRejectsTamperedClaim(t *testing.T) {
	t.Parallel()

	pub, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	c, err := NewFileClaim(
		"tenant-a",
		"client-a",
		"key-a",
		time.Unix(100, 5),
		bytes.Repeat([]byte{1}, 16),
		"idem-a",
		model.Content{HashAlg: model.DefaultHashAlg, ContentHash: bytes.Repeat([]byte{2}, 32), ContentLength: 12},
		model.Metadata{EventType: "file.snapshot"},
	)
	if err != nil {
		t.Fatalf("NewFileClaim() error = %v", err)
	}
	signed, err := Sign(c, priv)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	signed.Claim.ClientID = "attacker"
	if _, err := Verify(signed, pub); err == nil {
		t.Fatal("Verify() error = nil, want signature failure")
	}
}

func TestSigningInputReturnsIndependentOwnedBytes(t *testing.T) {
	t.Parallel()

	claimCBOR := []byte{1, 2, 3, 4}
	first := SigningInput(claimCBOR)
	second := SigningInput(claimCBOR)
	first[0] ^= 0xff
	if bytes.Equal(first, second) {
		t.Fatal("SigningInput results alias each other")
	}
	if !bytes.Equal(claimCBOR, []byte{1, 2, 3, 4}) {
		t.Fatalf("claim CBOR mutated: %v", claimCBOR)
	}
}
