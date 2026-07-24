package sdk

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/app"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/globallog"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/receipt"
	"github.com/wowtrust/trustdb/internal/sproof"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/wal"
)

func TestVerifySingleProofOfflineCNSMV1(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	provider, err := trustcrypto.ProviderForSuite(cryptosuite.CNSMV1)
	if err != nil {
		t.Fatal(err)
	}
	clientPublicBytes, clientPrivate, err := GenerateCNSMV1SoftwareKey()
	if err != nil {
		t.Fatal(err)
	}
	clientPublic := mustCNSMV1PublicKey(t, "client-sm2", clientPublicBytes)
	identity := mustCNSMV1Identity(t, "tenant-cn", "client-cn", "client-sm2", clientPrivate)
	acceptedSigner, acceptedPublic := newSDKSM2TrustKey(t, "server-accepted-sm2")
	committedSigner, committedPublic := newSDKSM2TrustKey(t, "server-committed-sm2")
	sthSigner, sthPublic := newSDKSM2TrustKey(t, "server-sth-sm2")

	contents := [][]byte{
		[]byte("portable CN-SM evidence"),
		[]byte("second record creates a non-empty audit path"),
	}
	signedClaims := make([]model.SignedClaim, len(contents))
	for index := range contents {
		signedClaims[index], err = BuildSignedFileClaim(
			bytes.NewReader(contents[index]),
			identity,
			FileClaimOptions{
				ProducedAt:     time.Unix(100+int64(index), 0),
				Nonce:          bytes.Repeat([]byte{byte(index + 1)}, 16),
				IdempotencyKey: fmt.Sprintf("sdk-offline-cn-%d", index),
				EventType:      "offline.evidence",
			},
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	walPath := filepath.Join(t.TempDir(), "records.wal")
	writer, err := wal.OpenWriterWithOptions(walPath, 1, wal.Options{
		CryptoSuite: cryptosuite.CNSMV1,
		NodeID:      "node-sdk-cn",
		LogID:       "log-sdk-cn",
		NamespaceID: "wal:" + walPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	engine := app.LocalEngine{
		ServerID:        "node-sdk-cn",
		LogID:           "log-sdk-cn",
		ServerKeyID:     "server-accepted-sm2",
		ClientPublicKey: clientPublic.internalPublicKey(),
		ServerSigner:    acceptedSigner,
		CryptoProvider:  provider,
		WAL:             writer,
		Now:             func() time.Time { return time.Unix(200, 0) },
	}
	records := make([]model.ServerRecord, len(signedClaims))
	accepted := make([]model.AcceptedReceipt, len(signedClaims))
	for index := range signedClaims {
		records[index], accepted[index], _, err = engine.Submit(ctx, signedClaims[index])
		if err != nil {
			t.Fatal(err)
		}
	}
	commit, err := engine.ComputeBatch(
		ctx,
		"batch-sdk-cn",
		time.Unix(300, 0),
		signedClaims,
		records,
		accepted,
		model.BatchComputeOptions{Mode: model.BatchComputeMaterialized},
	)
	if err != nil {
		t.Fatal(err)
	}
	for index := range commit.Bundles {
		commit.Bundles[index].CommittedReceipt, err = receipt.SignCommittedWithProvider(
			ctx,
			provider,
			commit.Bundles[index].CommittedReceipt,
			committedSigner,
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	store, err := proofstore.OpenLocalStore(
		t.TempDir(),
		cryptosuite.CNSMV1,
		"node-sdk-cn",
		"log-sdk-cn",
		"sdk-offline-cn",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	global, err := globallog.New(globallog.Options{
		Store:          store,
		NodeID:         "node-sdk-cn",
		LogID:          "log-sdk-cn",
		Signer:         sthSigner,
		CryptoProvider: provider,
		Clock:          func() time.Time { return time.Unix(400, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	sth, err := global.AppendBatchRoot(ctx, commit.Root)
	if err != nil {
		t.Fatal(err)
	}
	globalProof, err := global.InclusionProof(ctx, commit.Root.BatchID, sth.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := sproof.New(commit.Bundles[0], sproof.Options{
		GlobalProof:     &globalProof,
		ExportedAtUnixN: time.Unix(500, 0).UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	trust := OfflineTrust{Proof: TrustedKeys{
		ClientPublicKey:           clientPublic,
		AcceptedReceiptPublicKey:  acceptedPublic,
		CommittedReceiptPublicKey: committedPublic,
		SignedTreeHeadPublicKey:   sthPublic,
	}}
	result, err := VerifySingleProofOffline(bytes.NewReader(contents[0]), proof, trust, OfflineVerifyOptions{})
	if err != nil {
		t.Fatalf("VerifySingleProofOffline: %v", err)
	}
	if !result.Valid || result.ProofLevel != ProofLevelL4 ||
		result.ExternalNetworkAccess || result.ExternalProviderAccess {
		t.Fatalf("offline result = %+v", result)
	}
	for _, stage := range result.Stages {
		if stage.Status == OfflineStageFailed {
			t.Fatalf("offline stage = %+v", stage)
		}
	}

	path := filepath.Join(t.TempDir(), "cn-sm.sproof")
	if err := WriteSingleProofFile(path, proof); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadSingleProofFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err = VerifySingleProofOffline(bytes.NewReader(contents[0]), loaded, trust, OfflineVerifyOptions{})
	if err != nil || !result.Valid || result.ProofLevel != ProofLevelL4 {
		t.Fatalf("VerifySingleProofOffline(round trip) result=%+v error=%v", result, err)
	}
}

func newSDKSM2TrustKey(t testing.TB, keyID string) (trustcrypto.Signer, KeyDescriptor) {
	t.Helper()
	publicKey, privateKey, err := GenerateCNSMV1SoftwareKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := trustcrypto.NewSM2Signer(keyID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, mustCNSMV1PublicKey(t, keyID, publicKey)
}
