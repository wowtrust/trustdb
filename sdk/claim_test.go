package sdk

import (
	"bytes"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func TestBuildSignedFileClaimDefaultsAndVerifies(t *testing.T) {
	t.Parallel()

	pub, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	signed, err := BuildSignedFileClaim(bytes.NewReader([]byte("hello trustdb")), Identity{
		TenantID:   "tenant-1",
		ClientID:   "client-1",
		KeyID:      "client-key-1",
		PrivateKey: priv,
	}, FileClaimOptions{
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
	recordID, err := VerifySignedClaim(signed, pub)
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
