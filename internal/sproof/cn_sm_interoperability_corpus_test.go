package sproof_test

import (
	"bytes"
	"testing"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/sproof"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/verify"
	"github.com/wowtrust/trustdb/test/cnsmvectors"
)

func TestOfflineVerifierConsumesSharedCNSMInteropProofWithoutExternalAccess(t *testing.T) {
	corpus, err := cnsmvectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := corpus.Decode()
	if err != nil {
		t.Fatal(err)
	}
	content, err := corpus.Contents[0].Bytes()
	if err != nil {
		t.Fatal(err)
	}
	client, _ := corpus.Identities.Client.PublicKeyDescriptor()
	server, _ := corpus.Identities.Server.PublicKeyDescriptor()
	registry, _ := corpus.Identities.Registry.PublicKeyDescriptor()
	provider, err := trustcrypto.ProviderForSuite(cryptosuite.CNSMV1)
	if err != nil {
		t.Fatal(err)
	}
	trust := sproof.OfflineTrust{
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
	result, err := sproof.VerifyOffline(bytes.NewReader(content), decoded.SingleProof, trust, sproof.OfflineOptions{})
	if err != nil || !result.Valid || result.ProofLevel != "L4" {
		t.Fatalf("offline result=%+v error=%v", result, err)
	}
	if result.ExternalNetworkAccess || result.ExternalProviderAccess {
		t.Fatalf("offline verifier reported external access: %+v", result)
	}

	trust.Identity = sproof.IdentityTrust{RequireEvidence: true}
	if result, err := sproof.VerifyOffline(bytes.NewReader(content), decoded.SingleProof, trust, sproof.OfflineOptions{}); err == nil || result.Valid {
		t.Fatalf("embedded evidence was accepted without local trust: result=%+v err=%v", result, err)
	}
}
