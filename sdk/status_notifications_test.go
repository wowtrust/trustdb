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
	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

func TestDecodeAndVerifyStatusRefreshJSON(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	notification := model.StatusRefresh{
		SchemaVersion:   model.SchemaStatusRefresh,
		CryptoSuite:     cryptosuite.INTLV1,
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
	decoded, err := DecodeAndVerifyStatusRefreshJSON(bytes.NewReader(body), mustINTLV1PublicKey(t, "server-key", publicKey))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SubscriptionID != notification.SubscriptionID || decoded.Version != notification.Version {
		t.Fatalf("decoded = %+v", decoded)
	}

	notification.Version++
	tampered, _ := json.Marshal(notification)
	if _, err := DecodeAndVerifyStatusRefreshJSON(bytes.NewReader(tampered), mustINTLV1PublicKey(t, "server-key", publicKey)); err == nil {
		t.Fatal("tampered notification verified")
	}
}

func TestDecodeAndVerifyStatusRefreshCNSMV1(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := GenerateCNSMV1SoftwareKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := trustcrypto.NewSM2Signer("server-sm2", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	notification := model.StatusRefresh{
		SchemaVersion:   model.SchemaStatusRefresh,
		CryptoSuite:     cryptosuite.CNSMV1,
		SubscriptionID:  "tss1-cn",
		TenantID:        "tenant-cn",
		ClientID:        "client-cn",
		Version:         7,
		RefreshRequired: true,
		EmittedAtUnixN:  time.Now().UTC().UnixNano(),
	}
	payload, err := cborx.Marshal(notification)
	if err != nil {
		t.Fatal(err)
	}
	input, err := trustcrypto.SignatureInputForSuite(cryptosuite.CNSMV1, trustcrypto.SignaturePurposeStatusRefresh, payload)
	if err != nil {
		t.Fatal(err)
	}
	notification.ServerSig, err = trustcrypto.Sign(context.Background(), cryptosuite.CNSMV1, signer, input)
	if err != nil {
		t.Fatal(err)
	}
	body, err := cborx.Marshal(notification)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAndVerifyStatusRefreshCBOR(body, mustCNSMV1PublicKey(t, "server-sm2", publicKey))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.CryptoSuite != cryptosuite.CNSMV1 || decoded.ServerSig.Alg != cryptosuite.SignatureSM2SM3 {
		t.Fatalf("decoded status refresh = %+v", decoded)
	}
	intlPublic, _, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAndVerifyStatusRefreshCBOR(body, mustINTLV1PublicKey(t, "server-sm2", intlPublic)); err == nil {
		t.Fatal("CN status refresh verified with an INTL trust key")
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
	descriptor := mustINTLV1PublicKey(t, "server-key", serverPublicKey)
	eventsA, errorsA, err := SubscribeNATSStatusRefresh(ctx, consumerA, "trustdb.status.upstream", "trustdb-status-upstream", descriptor)
	if err != nil {
		t.Fatal(err)
	}
	eventsB, errorsB, err := SubscribeNATSStatusRefresh(ctx, consumerB, "trustdb.status.upstream", "trustdb-status-upstream", descriptor)
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

func TestSubscribeNATSStatusRefreshNilContextUsesBackground(t *testing.T) {
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

	conn, err := nats.Connect(server.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	serverPublicKey, serverPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	events, errorsCh, err := SubscribeNATSStatusRefresh(
		nil,
		conn,
		"trustdb.status.nil-context",
		"trustdb-status-nil-context",
		mustINTLV1PublicKey(t, "server-key", serverPublicKey),
	)
	if err != nil {
		t.Fatalf("SubscribeNATSStatusRefresh(nil): %v", err)
	}
	if err := conn.Publish("trustdb.status.nil-context", signedStatusRefreshCBOR(t, serverPrivateKey, 1)); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}

	select {
	case notification := <-events:
		if notification.Version != 1 {
			t.Fatalf("notification version = %d, want 1", notification.Version)
		}
	case streamErr := <-errorsCh:
		t.Fatalf("status refresh error: %v", streamErr)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for status refresh with nil context")
	}
	conn.Close()
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("events channel remained open after NATS connection close")
		}
	case <-time.After(time.Second):
		t.Fatal("events channel did not close after NATS connection close")
	}
	select {
	case _, ok := <-errorsCh:
		if ok {
			t.Fatal("errors channel remained open after NATS connection close")
		}
	case <-time.After(time.Second):
		t.Fatal("errors channel did not close after NATS connection close")
	}
}

func signedStatusRefreshCBOR(t *testing.T, privateKey ed25519.PrivateKey, version uint64) []byte {
	t.Helper()
	notification := model.StatusRefresh{
		SchemaVersion: model.SchemaStatusRefresh, CryptoSuite: cryptosuite.INTLV1,
		SubscriptionID: "tss1queue", TenantID: "tenant", ClientID: "client",
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
