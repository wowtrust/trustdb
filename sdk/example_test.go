package sdk_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/wowtrust/trustdb/v2/sdk"
)

func TestPublicModelAliasesCompile(t *testing.T) {
	t.Parallel()

	proof := sdk.ProofBundle{SchemaVersion: "trustdb.proof-bundle.v2", CryptoSuite: sdk.CryptoSuiteINTLV1, RecordID: "tr1example"}
	single := sdk.SingleProof{SchemaVersion: "trustdb.sproof.v2", FormatVersion: 2, CryptoSuite: sdk.CryptoSuiteINTLV1, RecordID: proof.RecordID, ProofBundle: proof}
	if single.ProofBundle.RecordID != "tr1example" {
		t.Fatalf("single proof = %+v", single)
	}
}

func ExampleNewCNSMV1Identity() {
	_, privateKey, err := sdk.GenerateCNSMV1SoftwareKey()
	if err != nil {
		panic(err)
	}
	identity, err := sdk.NewCNSMV1Identity("tenant-cn", "client-cn", "client-sm2", privateKey)
	if err != nil {
		panic(err)
	}
	signed, err := sdk.BuildSignedFileClaim(bytes.NewReader([]byte("国密证据")), identity, sdk.FileClaimOptions{
		IdempotencyKey: "cn-example-1",
		Nonce:          bytes.Repeat([]byte{6}, 16),
		EventType:      "file.snapshot",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(signed.CryptoSuite, signed.Claim.Content.HashAlg, signed.Signature.Alg)
	// Output: CN_SM_V1 sm3 sm2-sm3
}

func ExampleNewCallbackSigner() {
	publicKey, privateKey, err := sdk.GenerateCNSMV1SoftwareKey()
	if err != nil {
		panic(err)
	}
	remoteKey, err := sdk.NewCNSMV1SoftwareSigner("hsm-sm2", privateKey)
	if err != nil {
		panic(err)
	}
	descriptor, err := sdk.NewCNSMV1PublicKey("hsm-sm2", publicKey)
	if err != nil {
		panic(err)
	}
	descriptor.Provider = "application-hsm"
	signer, err := sdk.NewCallbackSigner(descriptor, func(ctx context.Context, message []byte) ([]byte, error) {
		// A production callback sends only message to the private-key boundary.
		// remoteKey stands in for that boundary in this self-contained example.
		return remoteKey.Sign(ctx, message)
	})
	if err != nil {
		panic(err)
	}
	_, err = sdk.NewIdentity("tenant-cn", "client-cn", signer)
	if err != nil {
		panic(err)
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
	identity, err := sdk.NewINTLV1Identity("tenant", "client", "client-key", privateKey)
	if err != nil {
		panic(err)
	}
	signed, err := sdk.BuildSignedFileClaim(bytes.NewReader([]byte("hello")), identity, sdk.FileClaimOptions{
		IdempotencyKey: "demo-idempotency-key",
		Nonce:          bytes.Repeat([]byte{2}, 16),
		EventType:      "file.snapshot",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(signed.SchemaVersion)
	// Output: trustdb.signed-claim.v2
}

func ExampleBuildSignedJSONLogClaim() {
	_, privateKey, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
	identity, err := sdk.NewINTLV1Identity("tenant", "client", "client-key", privateKey)
	if err != nil {
		panic(err)
	}
	signed, err := sdk.BuildSignedJSONLogClaim(map[string]any{
		"level": "info",
		"msg":   "payment accepted",
	}, identity, sdk.LogClaimOptions{
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

func ExampleNATSIngressClient_SubmitSignedClaim() {
	// The server must already trust the public half of the application's
	// signing identity. This deterministic key is used only to keep the checked
	// documentation example self-contained.
	_, privateKey, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{4}, 64)))
	identity, err := sdk.NewINTLV1Identity("tenant", "client", "client-key", privateKey)
	if err != nil {
		panic(err)
	}
	signed, err := sdk.BuildSignedFileClaim(bytes.NewReader([]byte("hello")), identity, sdk.FileClaimOptions{})
	if err != nil {
		panic(err)
	}

	cfg := sdk.DefaultNATSIngressConfig()
	cfg.URLs = []string{"tls://nats.internal.example:4222"}
	cfg.ConnectionOptions = []nats.Option{
		nats.UserCredentials("/run/secrets/trustdb-nats.creds"),
		nats.RootCAs("/etc/trust/nats-ca.pem"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := sdk.NewNATSIngressClient(ctx, cfg)
	if err != nil {
		return
	}
	defer client.Close()

	result, err := client.SubmitSignedClaim(ctx, signed)
	if err != nil {
		var serverError *sdk.Error
		if errors.As(err, &serverError) {
			_ = serverError.Code
		}
		return
	}
	_ = result.RecordID
}

func ExampleNATSIngressClient_PublishSignedClaim() {
	// PublishSignedClaim and WaitResult may be separated by caller-controlled
	// work or a process restart. Persist both fields of NATSSubmission together.
	_, privateKey, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{5}, 64)))
	identity, err := sdk.NewINTLV1Identity("tenant", "client", "client-key", privateKey)
	if err != nil {
		panic(err)
	}
	signed, err := sdk.BuildSignedFileClaim(bytes.NewReader([]byte("hello")), identity, sdk.FileClaimOptions{})
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := sdk.NewNATSIngressClient(ctx, sdk.DefaultNATSIngressConfig())
	if err != nil {
		return
	}
	defer client.Close()

	submission, err := client.PublishSignedClaim(ctx, signed)
	if err != nil {
		return
	}
	_ = submission.MessageID
	_ = submission.SignedClaim

	result, err := client.WaitResult(ctx, submission)
	if err != nil {
		return
	}
	_ = result.RecordID
}
