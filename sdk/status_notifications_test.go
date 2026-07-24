package sdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func TestDecodeAndVerifyStatusRefreshJSON(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	notification := model.StatusRefresh{
		SchemaVersion:   model.SchemaStatusRefresh,
		SubscriptionID:  "tss1subscription",
		TenantID:        "tenant",
		ClientID:        "client",
		Version:         42,
		RefreshRequired: true,
		EmittedAtUnixN:  time.Now().UTC().UnixNano(),
	}
	payload, err := cborx.Marshal(notification)
	if err != nil {
		t.Fatal(err)
	}
	input, err := trustcrypto.SignatureInputForSuite(cryptosuite.INTLV1, trustcrypto.SignaturePurposeStatusRefresh, payload)
	if err != nil {
		t.Fatal(err)
	}
	notification.ServerSig, err = trustcrypto.Sign(context.Background(), cryptosuite.INTLV1, trustcrypto.MustNewEd25519Signer("server-key", privateKey), input)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(notification)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAndVerifyStatusRefreshJSON(bytes.NewReader(body), publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SubscriptionID != notification.SubscriptionID || decoded.Version != notification.Version {
		t.Fatalf("decoded = %+v", decoded)
	}

	notification.Version++
	tampered, _ := json.Marshal(notification)
	if _, err := DecodeAndVerifyStatusRefreshJSON(bytes.NewReader(tampered), publicKey); err == nil {
		t.Fatal("tampered notification verified")
	}
}

func TestSubscribeNATSStatusRefreshSharesOneQueueGroupAcrossReplicas(t *testing.T) {
	t.Parallel()

	server, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go server.Start()
	if !server.ReadyForConnections(5 * time.Second) {
		t.Fatal("embedded NATS server did not become ready")
	}
	defer server.Shutdown()

	publisher, err := nats.Connect(server.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	consumerA, err := nats.Connect(server.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer consumerA.Close()
	consumerB, err := nats.Connect(server.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer consumerB.Close()

	serverPublicKey, serverPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eventsA, errorsA, err := SubscribeNATSStatusRefresh(ctx, consumerA, "trustdb.status.upstream", "trustdb-status-upstream", serverPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	eventsB, errorsB, err := SubscribeNATSStatusRefresh(ctx, consumerB, "trustdb.status.upstream", "trustdb-status-upstream", serverPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	for version := uint64(1); version <= 8; version++ {
		body := signedStatusRefreshCBOR(t, serverPrivateKey, version)
		if err := publisher.Publish("trustdb.status.upstream", body); err != nil {
			t.Fatal(err)
		}
		if err := publisher.Flush(); err != nil {
			t.Fatal(err)
		}

		var other <-chan StatusRefresh
		select {
		case notification := <-eventsA:
			if notification.Version != version {
				t.Fatalf("consumer A version = %d, want %d", notification.Version, version)
			}
			other = eventsB
		case notification := <-eventsB:
			if notification.Version != version {
				t.Fatalf("consumer B version = %d, want %d", notification.Version, version)
			}
			other = eventsA
		case streamErr := <-errorsA:
			t.Fatalf("consumer A error: %v", streamErr)
		case streamErr := <-errorsB:
			t.Fatalf("consumer B error: %v", streamErr)
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out waiting for NATS refresh version %d", version)
		}
		select {
		case duplicate := <-other:
			t.Fatalf("version %d was delivered to both queue-group replicas: %+v", version, duplicate)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func signedStatusRefreshCBOR(t *testing.T, privateKey ed25519.PrivateKey, version uint64) []byte {
	t.Helper()
	notification := model.StatusRefresh{
		SchemaVersion: model.SchemaStatusRefresh, SubscriptionID: "tss1queue", TenantID: "tenant", ClientID: "client",
		Version: version, RefreshRequired: true, EmittedAtUnixN: time.Now().UTC().UnixNano(),
	}
	payload, err := cborx.Marshal(notification)
	if err != nil {
		t.Fatal(err)
	}
	input, err := trustcrypto.SignatureInputForSuite(cryptosuite.INTLV1, trustcrypto.SignaturePurposeStatusRefresh, payload)
	if err != nil {
		t.Fatal(err)
	}
	notification.ServerSig, err = trustcrypto.Sign(context.Background(), cryptosuite.INTLV1, trustcrypto.MustNewEd25519Signer("server-key", privateKey), input)
	if err != nil {
		t.Fatal(err)
	}
	body, err := cborx.Marshal(notification)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
