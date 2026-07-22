package sdk_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/wowtrust/trustdb/sdk"
)

func TestPublicModelAliasesCompile(t *testing.T) {
	t.Parallel()

	proof := sdk.ProofBundle{SchemaVersion: "trustdb.proof-bundle.v1", RecordID: "tr1example"}
	single := sdk.SingleProof{SchemaVersion: "trustdb.sproof.v1", RecordID: proof.RecordID, ProofBundle: proof}
	if single.ProofBundle.RecordID != "tr1example" {
		t.Fatalf("single proof = %+v", single)
	}
}

func ExampleClient_ExportSingleProof() {
	client, err := sdk.NewClient("http://127.0.0.1:8080")
	if err != nil {
		panic(err)
	}
	_, _ = client.ExportSingleProof(context.Background(), "tr1example")
}

func ExampleBuildSignedFileClaim() {
	_, privateKey, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
	signed, err := sdk.BuildSignedFileClaim(bytes.NewReader([]byte("hello")), sdk.Identity{
		TenantID:   "tenant",
		ClientID:   "client",
		KeyID:      "client-key",
		PrivateKey: privateKey,
	}, sdk.FileClaimOptions{
		IdempotencyKey: "demo-idempotency-key",
		Nonce:          bytes.Repeat([]byte{2}, 16),
		EventType:      "file.snapshot",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(signed.SchemaVersion)
	// Output: trustdb.signed-claim.v1
}

func ExampleBuildSignedJSONLogClaim() {
	_, privateKey, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
	signed, err := sdk.BuildSignedJSONLogClaim(map[string]any{
		"level": "info",
		"msg":   "payment accepted",
	}, sdk.Identity{
		TenantID:   "tenant",
		ClientID:   "client",
		KeyID:      "client-key",
		PrivateKey: privateKey,
	}, sdk.LogClaimOptions{
		IdempotencyKey: "demo-log-idempotency-key",
		Nonce:          bytes.Repeat([]byte{3}, 16),
		Source:         "billing-api",
		TraceID:        "trace-123",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(signed.Claim.Metadata.EventType)
	// Output: log.record
}
