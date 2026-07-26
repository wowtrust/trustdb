package cnsmvectors

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"

	"github.com/wowtrust/trustdb/v2/internal/claim"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/globallog"
	"github.com/wowtrust/trustdb/v2/internal/keystore"
	"github.com/wowtrust/trustdb/v2/internal/merkle"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/receipt"
	"github.com/wowtrust/trustdb/v2/internal/sproof"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
	"github.com/wowtrust/trustdb/v2/internal/verify"
)

func TestCorpusRegeneratesByteForByte(t *testing.T) {
	corpus, err := Generate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data, err := CanonicalJSON(corpus)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, EmbeddedBytes()) {
		t.Fatal("generated CN_SM_V1 corpus differs from the reviewed immutable bytes")
	}
	if got := Checksum(data); got != EmbeddedChecksum()+"\n" {
		t.Fatalf("generated checksum = %q, want %q", got, EmbeddedChecksum()+"\n")
	}
}

func TestCorpusArtifactsVerifyAsOneCN_SM_V1EvidenceChain(t *testing.T) {
	ctx := context.Background()
	corpus, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := corpus.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ProofBundle.RecordID != corpus.RecordID ||
		decoded.ServerRecord.RecordID != corpus.RecordID ||
		decoded.AcceptedReceipt.RecordID != corpus.RecordID ||
		decoded.CommittedReceipt.RecordID != corpus.RecordID {
		t.Fatal("record ID is not identical across the corpus evidence chain")
	}
	if len(decoded.ProofBundle.BatchProof.AuditPath) != 1 ||
		decoded.ProofBundle.BatchProof.TreeSize != 2 {
		t.Fatalf("batch proof does not exercise a two-leaf tree: %+v", decoded.ProofBundle.BatchProof)
	}
	if len(decoded.GlobalLogProof.InclusionPath) != 1 ||
		decoded.GlobalLogProof.TreeSize != 2 {
		t.Fatalf("global proof does not exercise a two-leaf tree: %+v", decoded.GlobalLogProof)
	}

	provider, err := trustcrypto.ProviderForSuite(cryptosuite.CNSMV1)
	if err != nil {
		t.Fatal(err)
	}
	client, err := corpus.Identities.Client.PublicKeyDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	server, err := corpus.Identities.Server.PublicKeyDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := corpus.Identities.Registry.PublicKeyDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	verifiedClaim, err := claim.VerifyWithProvider(ctx, decoded.SignedClaim, client, provider)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedClaim.RecordID != corpus.RecordID {
		t.Fatalf("verified record ID = %q, want %q", verifiedClaim.RecordID, corpus.RecordID)
	}
	if err := receipt.VerifyAcceptedWithProvider(ctx, decoded.AcceptedReceipt, server, provider); err != nil {
		t.Fatal(err)
	}
	if err := receipt.VerifyCommittedWithProvider(ctx, decoded.CommittedReceipt, server, provider); err != nil {
		t.Fatal(err)
	}
	batchOK, err := merkle.VerifyForSuite(
		cryptosuite.CNSMV1,
		cryptosuite.MerkleRFC6962SM3,
		decoded.CommittedReceipt.LeafHash,
		decoded.ProofBundle.BatchProof.LeafIndex,
		decoded.ProofBundle.BatchProof.TreeSize,
		decoded.ProofBundle.BatchProof.AuditPath,
		decoded.CommittedReceipt.BatchRoot,
	)
	if err != nil || !batchOK {
		t.Fatalf("batch inclusion verification = %v, %v", batchOK, err)
	}
	if err := globallog.VerifySTHWithProvider(ctx, decoded.SignedTreeHead, server, provider); err != nil {
		t.Fatal(err)
	}
	globalOK, err := globallog.VerifyInclusionForSuite(cryptosuite.CNSMV1, decoded.GlobalLogProof)
	if err != nil || !globalOK {
		t.Fatalf("global inclusion verification = %v, %v", globalOK, err)
	}
	registryEvidence, err := keystore.OpenEvidence(decoded.KeyRegistryV2, registry)
	if err != nil {
		t.Fatal(err)
	}
	events := registryEvidence.Events()
	if len(events) != 1 || !bytes.Equal(events[0].EventHash, decoded.KeyEvent.EventHash) {
		t.Fatalf("registry events do not match the corpus key event: %+v", events)
	}
	content, err := corpus.Contents[0].Bytes()
	if err != nil {
		t.Fatal(err)
	}
	result, err := sproof.VerifyOffline(bytes.NewReader(content), decoded.SingleProof, offlineTrust(provider, client, server, registry), sproof.OfflineOptions{})
	if err != nil || !result.Valid || result.ProofLevel != "L4" {
		t.Fatalf("offline verification result=%+v error=%v", result, err)
	}
	if result.ExternalNetworkAccess || result.ExternalProviderAccess {
		t.Fatalf("offline verifier crossed an external boundary: %+v", result)
	}
}

func TestCorpusNegativeConfusionCasesFailClosed(t *testing.T) {
	ctx := context.Background()
	corpus, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	requiredCases := map[string]bool{
		"cross-suite": false, "sm2-user-id": false, "signature-encoding": false,
		"embedded-trust-root": false, "wrong-trust-root": false, "global-root": false,
	}
	for _, item := range corpus.NegativeCases {
		if _, ok := requiredCases[item.ID]; ok {
			requiredCases[item.ID] = true
		}
	}
	for id, found := range requiredCases {
		if !found {
			t.Fatalf("negative case %q is missing from the corpus", id)
		}
	}
	decoded, err := corpus.Decode()
	if err != nil {
		t.Fatal(err)
	}
	client, _ := corpus.Identities.Client.PublicKeyDescriptor()
	server, _ := corpus.Identities.Server.PublicKeyDescriptor()
	registry, _ := corpus.Identities.Registry.PublicKeyDescriptor()
	provider, _ := trustcrypto.ProviderForSuite(cryptosuite.CNSMV1)
	content, _ := corpus.Contents[0].Bytes()

	t.Run("cross-suite", func(t *testing.T) {
		mutated := decoded.SingleProof
		mutated.CryptoSuite = cryptosuite.INTLV1
		if err := sproof.Validate(mutated); err == nil {
			t.Fatal("offline container accepted a cross-suite envelope")
		}
	})
	t.Run("sm2-user-id", func(t *testing.T) {
		publicKey, err := sm2.NewPublicKey(client.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		input, err := corpus.Artifacts.ClientClaim.SignatureInput()
		if err != nil {
			t.Fatal(err)
		}
		signature, err := corpus.Artifacts.ClientClaim.SignatureDER()
		if err != nil {
			t.Fatal(err)
		}
		if sm2.VerifyASN1WithSM2(publicKey, []byte("wrong-user-id"), input, signature) {
			t.Fatal("SM2 signature verified with a non-suite user ID")
		}
	})
	t.Run("signature-encoding", func(t *testing.T) {
		signature, err := corpus.Artifacts.ClientClaim.SignatureDER()
		if err != nil {
			t.Fatal(err)
		}
		if err := trustcrypto.ValidateSM2SignatureDER(append(signature, 0)); err == nil {
			t.Fatal("strict DER validator accepted trailing data")
		}
		var parsed struct {
			R *big.Int
			S *big.Int
		}
		if rest, err := asn1.Unmarshal(signature, &parsed); err != nil || len(rest) != 0 {
			t.Fatalf("decode reviewed DER signature: rest=%x err=%v", rest, err)
		}
		raw := make([]byte, 64)
		parsed.R.FillBytes(raw[:32])
		parsed.S.FillBytes(raw[32:])
		if err := trustcrypto.ValidateSM2SignatureDER(raw); err == nil {
			t.Fatal("strict DER validator accepted raw r||s")
		}
	})
	t.Run("embedded-trust-root", func(t *testing.T) {
		trust := offlineTrust(provider, client, server, registry)
		trust.Identity.ClientPublicKeys = nil
		trust.Identity.ServerPublicKeys = nil
		trust.Identity.RegistryPublicKey = trustcrypto.PublicKeyDescriptor{}
		if result, err := sproof.VerifyOffline(bytes.NewReader(content), decoded.SingleProof, trust, sproof.OfflineOptions{}); err == nil || result.Valid {
			t.Fatalf("embedded identity material became a trust root: result=%+v err=%v", result, err)
		}
	})
	t.Run("wrong-trust-root", func(t *testing.T) {
		wrongSigner, err := newDeterministicSM2Signer(client.KeyID, "4444444444444444444444444444444444444444444444444444444444444444")
		if err != nil {
			t.Fatal(err)
		}
		wrongClient, err := wrongSigner.PublicKey(ctx)
		if err != nil {
			t.Fatal(err)
		}
		trust := offlineTrust(provider, wrongClient, server, registry)
		if result, err := sproof.VerifyOffline(bytes.NewReader(content), decoded.SingleProof, trust, sproof.OfflineOptions{}); err == nil || result.Valid {
			t.Fatalf("wrong local trust root was accepted: result=%+v err=%v", result, err)
		}
	})
	t.Run("global-root", func(t *testing.T) {
		for _, mutation := range []struct {
			name   string
			mutate func(*model.SingleProof)
		}{
			{
				name: "STH root",
				mutate: func(proof *model.SingleProof) {
					proof.GlobalProof.STH.RootHash[0] ^= 1
				},
			},
			{
				name: "inclusion path",
				mutate: func(proof *model.SingleProof) {
					proof.GlobalProof.InclusionPath[0][0] ^= 1
				},
			},
		} {
			t.Run(mutation.name, func(t *testing.T) {
				fresh, err := corpus.Decode()
				if err != nil {
					t.Fatal(err)
				}
				mutation.mutate(&fresh.SingleProof)
				if result, err := sproof.VerifyOffline(bytes.NewReader(content), fresh.SingleProof, offlineTrust(provider, client, server, registry), sproof.OfflineOptions{}); err == nil || result.Valid {
					t.Fatalf("mutated %s was accepted: result=%+v err=%v", mutation.name, result, err)
				}
			})
		}
	})
}

func TestContentSM3ExpectedBytes(t *testing.T) {
	corpus, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range corpus.Contents {
		raw, err := item.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		got := sm3.Sum(raw)
		if hex.EncodeToString(got[:]) != item.DigestHex {
			t.Fatalf("%s SM3 = %x, want %s", item.ID, got, item.DigestHex)
		}
	}
}

func offlineTrust(
	provider trustcrypto.Provider,
	client, server, registry trustcrypto.PublicKeyDescriptor,
) sproof.OfflineTrust {
	return sproof.OfflineTrust{
		Proof: verify.TrustedKeys{
			ClientPublicKey:         client,
			ServerPublicKey:         server,
			SignedTreeHeadPublicKey: server,
			CryptoProvider:          provider,
		},
		Identity: sproof.IdentityTrust{
			ClientPublicKeys:  []trustcrypto.PublicKeyDescriptor{client},
			ServerPublicKeys:  []trustcrypto.PublicKeyDescriptor{server},
			RegistryPublicKey: registry,
			RequireEvidence:   true,
		},
	}
}
