package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	internalapp "github.com/wowtrust/trustdb/v2/internal/app"
	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/globallog"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/proofstore"
	"github.com/wowtrust/trustdb/v2/internal/receipt"
	"github.com/wowtrust/trustdb/v2/internal/sproof"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
	"github.com/wowtrust/trustdb/v2/internal/wal"
	"github.com/wowtrust/trustdb/v2/sdk"
)

func TestReadGlobalProofFileExplainsAnchorResultMixup(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sth-1.tdanchor-result")
	writeCBORForTest(t, path, model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		TreeSize:      1,
		SinkName:      "ots",
		AnchorID:      "ots-test",
		RootHash:      []byte{1, 2, 3},
		STH: model.SignedTreeHead{
			SchemaVersion: model.SchemaSignedTreeHead,
			TreeSize:      1,
			RootHash:      []byte{1, 2, 3},
		},
	})

	var proof model.GlobalLogProof
	err := readGlobalProofFile(path, &proof)
	if err == nil {
		t.Fatal("readGlobalProofFile() error = nil, want type hint")
	}
	msg := err.Error()
	if !strings.Contains(msg, "STHAnchorResult") || !strings.Contains(msg, ".tdanchor-result") || !strings.Contains(msg, ".tdgproof") {
		t.Fatalf("error message = %q, want actionable file type hint", msg)
	}
}

func TestReadGlobalProofFileExplainsLegacyBatchAnchorMixup(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "batch-old.tdanchor-result")
	writeCBORForTest(t, path, map[string]any{
		"anchor_id":  "ots-old",
		"batch_root": []byte{1, 2, 3},
		"proof":      []byte(`{"schema_version":"trustdb.anchor-ots-proof.v1"}`),
	})

	var proof model.GlobalLogProof
	err := readGlobalProofFile(path, &proof)
	if err == nil {
		t.Fatal("readGlobalProofFile() error = nil, want legacy hint")
	}
	msg := err.Error()
	if !strings.Contains(msg, "legacy batch anchor") || !strings.Contains(msg, "GlobalLogProof") {
		t.Fatalf("error message = %q, want legacy batch-anchor hint", msg)
	}
}

func TestReadSingleProofFileRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sample.sproof")
	writeCBORForTest(t, path, model.SingleProof{
		SchemaVersion:   model.SchemaSingleProof,
		FormatVersion:   2,
		CryptoSuite:     cryptosuite.INTLV1,
		RecordID:        "rec-1",
		ProofLevel:      "L3",
		NodeID:          "node-1",
		LogID:           "log-1",
		ExportedAtUnixN: 1,
		ProofBundle: model.ProofBundle{
			SchemaVersion: model.SchemaProofBundle,
			CryptoSuite:   cryptosuite.INTLV1,
			RecordID:      "rec-1",
			NodeID:        "node-1",
			LogID:         "log-1",
		},
	})

	var proof model.SingleProof
	if err := readSingleProofFile(path, &proof); err != nil {
		t.Fatalf("readSingleProofFile() error = %v", err)
	}
	if proof.SchemaVersion != model.SchemaSingleProof || proof.RecordID != "rec-1" || proof.ProofBundle.RecordID != "rec-1" {
		t.Fatalf("decoded single proof = %+v, want bundled artefacts", proof)
	}
}

func TestReadProofBundleFileExplainsSingleProofMixup(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sample.sproof")
	writeCBORForTest(t, path, model.SingleProof{
		SchemaVersion: model.SchemaSingleProof,
		FormatVersion: 2,
		CryptoSuite:   cryptosuite.INTLV1,
		RecordID:      "rec-1",
		ProofLevel:    "L3",
		NodeID:        "node-1",
		LogID:         "log-1",
		ProofBundle: model.ProofBundle{
			SchemaVersion: model.SchemaProofBundle,
			CryptoSuite:   cryptosuite.INTLV1,
			RecordID:      "rec-1",
			NodeID:        "node-1",
			LogID:         "log-1",
		},
	})

	var bundle model.ProofBundle
	err := readProofBundleFile(path, &bundle)
	if err == nil {
		t.Fatal("readProofBundleFile() error = nil, want single-proof hint")
	}
	msg := err.Error()
	if !strings.Contains(msg, ".sproof") || !strings.Contains(msg, "main .sproof input") {
		t.Fatalf("error message = %q, want single-proof hint", msg)
	}
}

func TestReadProofBundleFileRejectsOversizedInput(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "oversized.tdproof")
	if err := os.WriteFile(path, make([]byte, cborx.DefaultMaxBytes+1), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var bundle model.ProofBundle
	err := readProofBundleFile(path, &bundle)
	if err == nil || !strings.Contains(err.Error(), "payload too large") {
		t.Fatalf("readProofBundleFile() error = %v, want payload too large", err)
	}
}

func TestRawDesktopVerifierDescriptorsPreserveRotatedSignatureKeyIDs(t *testing.T) {
	t.Parallel()

	clientPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	clientKeys, err := rawDesktopVerifierDescriptors(cryptosuite.INTLV1, []string{"client-key"}, clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	serverKeys, err := rawDesktopVerifierDescriptors(
		cryptosuite.INTLV1,
		[]string{"accepted-key", "committed-key", "sth-key"},
		serverPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(clientKeys) != 1 || clientKeys[0].KeyID != "client-key" {
		t.Fatalf("client keys = %+v", clientKeys)
	}
	for index, want := range []string{"accepted-key", "committed-key", "sth-key"} {
		if serverKeys[index].KeyID != want || serverKeys[index].CryptoSuite != cryptosuite.INTLV1 {
			t.Fatalf("server key[%d] = %+v, want key_id=%s INTL_V1", index, serverKeys[index], want)
		}
	}
}

func TestDesktopCNSMProofVerifiesOfflineAndRejectsEmbeddedIdentityAsTrust(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const passphrase = "correct horse battery staple"
	identityState, resolved, err := generateSoftwareIdentity(ctx, t.TempDir(), GenerateIdentityRequest{
		TenantID:    "tenant-cn",
		ClientID:    "desktop-cn",
		KeyID:       "client-sm2",
		CryptoSuite: string(cryptosuite.CNSMV1),
		Passphrase:  passphrase,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.close()
	clientDescriptor, err := loadDesktopIdentityDescriptor(identityState)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, err := clientDescriptor.PublicKeyDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	provider, err := trustcrypto.ProviderForSuite(cryptosuite.CNSMV1)
	if err != nil {
		t.Fatal(err)
	}
	acceptedSigner, acceptedDescriptor := newDesktopSM2TrustKey(t, "server-accepted-sm2")
	committedSigner, committedDescriptor := newDesktopSM2TrustKey(t, "server-committed-sm2")
	sthSigner, sthDescriptor := newDesktopSM2TrustKey(t, "server-sth-sm2")
	content := []byte("desktop CN_SM_V1 offline evidence")
	signed, err := sdk.BuildSignedFileClaim(bytes.NewReader(content), resolved.identity, sdk.FileClaimOptions{
		ProducedAt:     time.Unix(100, 0),
		Nonce:          bytes.Repeat([]byte{1}, 16),
		IdempotencyKey: "desktop-cn-offline",
		EventType:      "offline.evidence",
	})
	if err != nil {
		t.Fatal(err)
	}
	walPath := filepath.Join(t.TempDir(), "records.wal")
	writer, err := wal.OpenWriterWithOptions(walPath, 1, wal.Options{
		CryptoSuite: cryptosuite.CNSMV1,
		NodeID:      "node-desktop-cn",
		LogID:       "log-desktop-cn",
		NamespaceID: "wal:" + walPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	engine := internalapp.LocalEngine{
		ServerID:        "node-desktop-cn",
		LogID:           "log-desktop-cn",
		ServerKeyID:     acceptedDescriptor.KeyID,
		ClientPublicKey: clientPublic,
		ServerSigner:    acceptedSigner,
		CryptoProvider:  provider,
		WAL:             writer,
		Now:             func() time.Time { return time.Unix(200, 0) },
	}
	record, accepted, _, err := engine.Submit(ctx, signed)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := engine.ComputeBatch(
		ctx,
		"batch-desktop-cn",
		time.Unix(300, 0),
		[]model.SignedClaim{signed},
		[]model.ServerRecord{record},
		[]model.AcceptedReceipt{accepted},
		model.BatchComputeOptions{Mode: model.BatchComputeMaterialized},
	)
	if err != nil {
		t.Fatal(err)
	}
	commit.Bundles[0].CommittedReceipt, err = receipt.SignCommittedWithProvider(
		ctx,
		provider,
		commit.Bundles[0].CommittedReceipt,
		committedSigner,
	)
	if err != nil {
		t.Fatal(err)
	}
	proofStore, err := proofstore.OpenLocalStore(
		t.TempDir(),
		cryptosuite.CNSMV1,
		"node-desktop-cn",
		"log-desktop-cn",
		"desktop-cn-offline",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer proofStore.Close()
	global, err := globallog.New(globallog.Options{
		Store:          proofStore,
		NodeID:         "node-desktop-cn",
		LogID:          "log-desktop-cn",
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
	proof.IdentityEvidence = []model.ProofIdentityEvidence{
		desktopIdentityEvidence(t, model.ProofIdentityRoleClient, clientDescriptor),
		desktopIdentityEvidence(t, model.ProofIdentityRoleServer, acceptedDescriptor),
		desktopIdentityEvidence(t, model.ProofIdentityRoleServer, committedDescriptor),
		desktopIdentityEvidence(t, model.ProofIdentityRoleServer, sthDescriptor),
	}
	if err := sproof.Validate(proof); err != nil {
		t.Fatal(err)
	}

	configStore, err := newStore(filepath.Join(t.TempDir(), "desktop.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer configStore.close()
	if err := configStore.setIdentity(identityState); err != nil {
		t.Fatal(err)
	}
	desktop := NewApp()
	desktop.store = configStore
	serverPaths := []string{
		writeDesktopVerifierDescriptor(t, acceptedDescriptor),
		writeDesktopVerifierDescriptor(t, committedDescriptor),
		writeDesktopVerifierDescriptor(t, sthDescriptor),
	}
	trust, rootCount, err := desktop.desktopOfflineTrust(proof, VerifyRequest{
		ServerVerifierDescriptors: strings.Join(serverPaths, "\n"),
		RequireIdentityEvidence:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rootCount != 0 {
		t.Fatalf("local root count = %d, want 0", rootCount)
	}
	result, err := sdk.VerifySingleProofOffline(bytes.NewReader(content), proof, trust, sdk.OfflineVerifyOptions{})
	if err != nil || !result.Valid || result.ProofLevel != sdk.ProofLevelL4 {
		t.Fatalf("offline verification result=%+v error=%v", result, err)
	}
	if result.ExternalNetworkAccess || result.ExternalProviderAccess {
		t.Fatalf("offline verification accessed an external boundary: %+v", result)
	}
	contentPath := filepath.Join(t.TempDir(), "desktop-cn-evidence.txt")
	if err := os.WriteFile(contentPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	singleProofPath := filepath.Join(t.TempDir(), "desktop-cn.sproof")
	writeCBORForTest(t, singleProofPath, proof)
	response, err := desktop.VerifyProof(VerifyRequest{
		Mode:                      "local",
		FilePath:                  contentPath,
		SingleProofPath:           singleProofPath,
		ServerVerifierDescriptors: strings.Join(serverPaths, "\n"),
		RequireIdentityEvidence:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !response.Valid || response.Level != sdk.ProofLevelL4 ||
		response.CryptoSuite != string(cryptosuite.CNSMV1) || response.HashAlg != sdk.HashAlgorithmSM3 {
		t.Fatalf("desktop verification response = %+v", response)
	}
	if response.ExternalNetworkAccess || response.ExternalProviderAccess ||
		response.EvidenceCertificatesTrusted || len(response.Stages) == 0 {
		t.Fatalf("desktop offline boundary report = %+v", response)
	}

	wrongPaths := make([]string, 0, 3)
	for _, keyID := range []string{acceptedDescriptor.KeyID, committedDescriptor.KeyID, sthDescriptor.KeyID} {
		_, wrong := newDesktopSM2TrustKey(t, keyID)
		wrongPaths = append(wrongPaths, writeDesktopVerifierDescriptor(t, wrong))
	}
	wrongTrust, _, err := desktop.desktopOfflineTrust(proof, VerifyRequest{
		ServerVerifierDescriptors: strings.Join(wrongPaths, "\n"),
		RequireIdentityEvidence:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	wrongResult, err := sdk.VerifySingleProofOffline(bytes.NewReader(content), proof, wrongTrust, sdk.OfflineVerifyOptions{})
	if err == nil || wrongResult.Valid {
		t.Fatalf("embedded identity descriptors became trust: result=%+v error=%v", wrongResult, err)
	}
	if len(wrongResult.Stages) < 2 || wrongResult.Stages[1].Name != "identity_evidence" ||
		wrongResult.Stages[1].Status != sdk.OfflineStageFailed {
		t.Fatalf("wrong local trust did not fail identity stage: %+v", wrongResult.Stages)
	}
}

func newDesktopSM2TrustKey(t testing.TB, keyID string) (trustcrypto.Signer, keydescriptor.Descriptor) {
	t.Helper()
	publicKey, privateKey, err := trustcrypto.GenerateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := trustcrypto.NewSM2Signer(keyID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	suite, err := cryptosuite.RequireAvailable(cryptosuite.CNSMV1)
	if err != nil {
		t.Fatal(err)
	}
	return signer, keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindVerifier,
		Provider:      keydescriptor.ProviderPublic,
		CryptoSuite:   cryptosuite.CNSMV1,
		KeyID:         keyID,
		Algorithm:     suite.Signature.Algorithm,
		SM2UserID:     suite.Signature.SM2UserID,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: suite.Signature.PublicKeyEncoding,
			Bytes:    publicKey,
		},
	}
}

func desktopIdentityEvidence(t testing.TB, role string, descriptor keydescriptor.Descriptor) model.ProofIdentityEvidence {
	t.Helper()
	public := descriptor.Clone()
	public.Kind = keydescriptor.KindVerifier
	public.Provider = keydescriptor.ProviderPublic
	public.Software = nil
	public.PKCS11 = nil
	public.SDF = nil
	public.Remote = nil
	encoded, err := keydescriptor.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	return model.ProofIdentityEvidence{
		SchemaVersion: model.SchemaProofIdentity,
		CryptoSuite:   public.CryptoSuite,
		Role:          role,
		KeyID:         public.KeyID,
		KeyDescriptor: encoded,
	}
}

func writeDesktopVerifierDescriptor(t testing.TB, descriptor keydescriptor.Descriptor) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), fmt.Sprintf("%s.pub", descriptor.KeyID))
	if err := keydescriptor.WriteFile(path, descriptor); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCBORForTest(t *testing.T, path string, v any) {
	t.Helper()
	data, err := cborx.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
