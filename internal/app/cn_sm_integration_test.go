package app

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/claim"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/globallog"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/receipt"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
	"github.com/wowtrust/trustdb/v2/internal/wal"
)

func TestCNSMV1ClaimReceiptBatchAndSTHEndToEnd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	provider, err := trustcrypto.ProviderForSuite(cryptosuite.CNSMV1)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate, err := trustcrypto.GenerateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverPrivate, err := trustcrypto.GenerateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := trustcrypto.NewSM2Signer("client-sm2", clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverSigner, err := trustcrypto.NewSM2Signer("server-sm2", serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	clientDescriptor, err := trustcrypto.NewSM2PublicKey("client-sm2", clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	serverDescriptor, err := trustcrypto.NewSM2PublicKey("server-sm2", serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	contentHash, err := trustcrypto.HashBytesWithProvider(provider, cryptosuite.HashSM3, []byte("cn-sm evidence"))
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := claim.NewFileClaimForSuite(
		cryptosuite.CNSMV1,
		"tenant-cn",
		"client-cn",
		"client-sm2",
		time.Unix(100, 0),
		bytes.Repeat([]byte{0x11}, 16),
		"cn-sm-e2e",
		model.Content{HashAlg: cryptosuite.HashSM3, ContentHash: contentHash, ContentLength: 14},
		model.Metadata{EventType: "cn.evidence"},
	)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := claim.SignWithProvider(ctx, provider, unsigned, clientSigner)
	if err != nil {
		t.Fatal(err)
	}
	walPath := filepath.Join(t.TempDir(), "records.wal")
	writer, err := wal.OpenWriterWithOptions(walPath, 1, wal.Options{
		CryptoSuite: cryptosuite.CNSMV1,
		NodeID:      "node-cn",
		LogID:       "log-cn",
		NamespaceID: "wal:" + walPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	engine := LocalEngine{
		ServerID:        "node-cn",
		LogID:           "log-cn",
		ServerKeyID:     "server-sm2",
		ClientPublicKey: clientDescriptor,
		ServerSigner:    serverSigner,
		CryptoProvider:  provider,
		WAL:             writer,
		Now:             func() time.Time { return time.Unix(200, 0) },
	}
	mixed := signed
	mixed.CryptoSuite = cryptosuite.INTLV1
	if _, _, _, err := engine.Submit(ctx, mixed); err == nil {
		t.Fatal("CN_SM_V1 server accepted a mixed-suite claim")
	}
	record, accepted, _, err := engine.Submit(ctx, signed)
	if err != nil {
		t.Fatal(err)
	}
	if record.WAL.Sequence != 1 {
		t.Fatalf("mixed-suite request consumed durable WAL sequence: got %d, want 1", record.WAL.Sequence)
	}
	if record.CryptoSuite != cryptosuite.CNSMV1 || accepted.CryptoSuite != cryptosuite.CNSMV1 {
		t.Fatalf("ingest suites record=%s accepted=%s", record.CryptoSuite, accepted.CryptoSuite)
	}
	if err := receipt.VerifyAcceptedWithProvider(ctx, accepted, serverDescriptor, provider); err != nil {
		t.Fatalf("verify accepted receipt: %v", err)
	}
	commit, err := engine.ComputeBatch(
		ctx,
		"batch-cn",
		time.Unix(300, 0),
		[]model.SignedClaim{signed},
		[]model.ServerRecord{record},
		[]model.AcceptedReceipt{accepted},
		model.BatchComputeOptions{Mode: model.BatchComputeMaterialized},
	)
	if err != nil {
		t.Fatal(err)
	}
	if commit.Root.CryptoSuite != cryptosuite.CNSMV1 || commit.Root.TreeAlg() != cryptosuite.MerkleRFC6962SM3 {
		t.Fatalf("batch root profile suite=%s tree=%s", commit.Root.CryptoSuite, commit.Root.TreeAlg())
	}
	if err := receipt.VerifyCommittedWithProvider(ctx, commit.Bundles[0].CommittedReceipt, serverDescriptor, provider); err != nil {
		t.Fatalf("verify committed receipt: %v", err)
	}
	store := newBoundTestLocalStoreForSuite(t, t.TempDir(), cryptosuite.CNSMV1)
	global, err := globallog.New(globallog.Options{
		Store: store, NodeID: "node-cn", LogID: "log-cn", Signer: serverSigner, CryptoProvider: provider,
		Clock: func() time.Time { return time.Unix(400, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	sth, err := global.AppendBatchRoot(ctx, commit.Root)
	if err != nil {
		t.Fatal(err)
	}
	if sth.CryptoSuite != cryptosuite.CNSMV1 || sth.TreeAlg != cryptosuite.MerkleRFC6962SM3 ||
		sth.Signature.Alg != cryptosuite.SignatureSM2SM3 {
		t.Fatalf("STH profile suite=%s tree=%s signature=%s", sth.CryptoSuite, sth.TreeAlg, sth.Signature.Alg)
	}
	if err := globallog.VerifySTHWithProvider(ctx, sth, serverDescriptor, provider); err != nil {
		t.Fatalf("verify STH: %v", err)
	}
}
