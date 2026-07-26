package sdk

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

func TestBuildSignedFileClaimDefaultsAndVerifies(t *testing.T) {
	t.Parallel()

	pub, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	identity, err := NewINTLV1Identity("tenant-1", "client-1", "client-key-1", priv)
	if err != nil {
		t.Fatalf("NewINTLV1Identity: %v", err)
	}
	signed, err := BuildSignedFileClaim(bytes.NewReader([]byte("hello trustdb")), identity, FileClaimOptions{
		ProducedAt:     time.Unix(10, 0),
		Nonce:          bytes.Repeat([]byte{0x42}, 16),
		IdempotencyKey: "idem-1",
		MediaType:      "text/plain",
		StorageURI:     "file:///tmp/hello.txt",
		EventType:      "file.snapshot",
		Source:         "sdk-test",
		CustomMetadata: map[string]string{"file_name": "hello.txt"},
	})
	if err != nil {
		t.Fatalf("BuildSignedFileClaim: %v", err)
	}
	publicKey, err := NewINTLV1PublicKey("client-key-1", pub)
	if err != nil {
		t.Fatalf("NewINTLV1PublicKey: %v", err)
	}
	recordID, err := VerifySignedClaim(signed, publicKey)
	if err != nil {
		t.Fatalf("VerifySignedClaim: %v", err)
	}
	if recordID == "" {
		t.Fatal("record id is empty")
	}
	if signed.SchemaVersion != model.SchemaSignedClaim {
		t.Fatalf("schema = %q", signed.SchemaVersion)
	}
	if got := signed.Claim.Content.ContentLength; got != int64(len("hello trustdb")) {
		t.Fatalf("content length = %d", got)
	}
	if got := signed.Claim.Metadata.Custom["file_name"]; got != "hello.txt" {
		t.Fatalf("metadata file_name = %q", got)
	}
}

func TestBuildSignedFileClaimCNSMV1UsesSM3AndSM2(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := GenerateCNSMV1SoftwareKey()
	if err != nil {
		t.Fatalf("GenerateCNSMV1SoftwareKey: %v", err)
	}
	identity, err := NewCNSMV1Identity("tenant-cn", "client-cn", "client-sm2", privateKey)
	if err != nil {
		t.Fatalf("NewCNSMV1Identity: %v", err)
	}
	raw := []byte("国密 SDK evidence")
	signed, err := BuildSignedFileClaim(bytes.NewReader(raw), identity, FileClaimOptions{
		ProducedAt:     time.Unix(20, 0),
		Nonce:          bytes.Repeat([]byte{0x43}, 16),
		IdempotencyKey: "cn-idem-1",
		EventType:      "file.snapshot",
	})
	if err != nil {
		t.Fatalf("BuildSignedFileClaim: %v", err)
	}
	if signed.CryptoSuite != cryptosuite.CNSMV1 ||
		signed.Claim.CryptoSuite != cryptosuite.CNSMV1 ||
		signed.Claim.Content.HashAlg != cryptosuite.HashSM3 ||
		signed.Signature.Alg != cryptosuite.SignatureSM2SM3 {
		t.Fatalf("CN claim profile = %+v", signed)
	}
	wantHash, err := trustcrypto.HashBytesForSuite(cryptosuite.CNSMV1, cryptosuite.HashSM3, raw)
	if err != nil {
		t.Fatalf("HashBytesForSuite: %v", err)
	}
	if !bytes.Equal(signed.Claim.Content.ContentHash, wantHash) {
		t.Fatalf("content hash = %x, want SM3 %x", signed.Claim.Content.ContentHash, wantHash)
	}
	descriptor, err := NewCNSMV1PublicKey("client-sm2", publicKey)
	if err != nil {
		t.Fatalf("NewCNSMV1PublicKey: %v", err)
	}
	if _, err := VerifySignedClaim(signed, descriptor); err != nil {
		t.Fatalf("VerifySignedClaim: %v", err)
	}

	intlPublic, _, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	intlDescriptor, err := NewINTLV1PublicKey("client-sm2", intlPublic)
	if err != nil {
		t.Fatalf("NewINTLV1PublicKey: %v", err)
	}
	if _, err := VerifySignedClaim(signed, intlDescriptor); err == nil {
		t.Fatal("VerifySignedClaim accepted an endpoint/suite-mismatched public key")
	}
}

func TestCallbackSignerIsValidatedAndCancellationAware(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := GenerateCNSMV1SoftwareKey()
	if err != nil {
		t.Fatalf("GenerateCNSMV1SoftwareKey: %v", err)
	}
	internalSigner, err := trustcrypto.NewSM2Signer("remote-sm2", privateKey)
	if err != nil {
		t.Fatalf("NewSM2Signer: %v", err)
	}
	descriptor, err := NewCNSMV1PublicKey("remote-sm2", publicKey)
	if err != nil {
		t.Fatalf("NewCNSMV1PublicKey: %v", err)
	}
	descriptor.Provider = "remote-hsm"
	callback, err := NewCallbackSigner(descriptor, func(ctx context.Context, message []byte) ([]byte, error) {
		signature, signErr := internalSigner.Sign(ctx, message)
		return signature.Signature, signErr
	})
	if err != nil {
		t.Fatalf("NewCallbackSigner: %v", err)
	}
	identity, err := NewIdentity("tenant-cn", "client-cn", callback)
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	signed, err := BuildSignedFileClaim(bytes.NewReader([]byte("callback")), identity, FileClaimOptions{
		Nonce:          bytes.Repeat([]byte{1}, 16),
		IdempotencyKey: "callback-1",
		EventType:      "file.snapshot",
	})
	if err != nil {
		t.Fatalf("BuildSignedFileClaim: %v", err)
	}
	if _, err := VerifySignedClaim(signed, descriptor); err != nil {
		t.Fatalf("VerifySignedClaim: %v", err)
	}

	bad, err := NewCallbackSigner(descriptor, func(context.Context, []byte) ([]byte, error) {
		return []byte{1, 2, 3}, nil
	})
	if err != nil {
		t.Fatalf("NewCallbackSigner(bad): %v", err)
	}
	badIdentity, err := NewIdentity("tenant-cn", "client-cn", bad)
	if err != nil {
		t.Fatalf("NewIdentity(bad): %v", err)
	}
	if _, err := BuildSignedFileClaim(bytes.NewReader([]byte("invalid")), badIdentity, FileClaimOptions{
		Nonce: bytes.Repeat([]byte{2}, 16), IdempotencyKey: "callback-2", EventType: "file.snapshot",
	}); err == nil {
		t.Fatal("BuildSignedFileClaim accepted an invalid callback signature")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := BuildSignedFileClaimContext(ctx, bytes.NewReader([]byte("cancel")), identity, FileClaimOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("BuildSignedFileClaimContext error = %v, want context.Canceled", err)
	}
}
