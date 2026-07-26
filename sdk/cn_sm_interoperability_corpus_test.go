package sdk_test

import (
	"bytes"
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/sdk"
	"github.com/wowtrust/trustdb/v2/test/cnsmvectors"
)

func TestGoSDKConsumesSharedCNSMInteropProof(t *testing.T) {
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
	client := sdkVectorDescriptor(t, corpus.Identities.Client)
	server := sdkVectorDescriptor(t, corpus.Identities.Server)
	registry := sdkVectorDescriptor(t, corpus.Identities.Registry)
	trust := sdk.OfflineTrust{
		Proof: sdk.TrustedKeys{
			ClientPublicKey:         client,
			ServerPublicKey:         server,
			SignedTreeHeadPublicKey: server,
		},
		Identity: sdk.OfflineIdentityTrust{
			ClientPublicKeys:  []sdk.KeyDescriptor{client},
			ServerPublicKeys:  []sdk.KeyDescriptor{server},
			RegistryPublicKey: registry,
			RequireEvidence:   true,
		},
	}
	result, err := sdk.VerifySingleProofOffline(bytes.NewReader(content), decoded.SingleProof, trust, sdk.OfflineVerifyOptions{})
	if err != nil || !result.Valid || result.ProofLevel != sdk.ProofLevelL4 {
		t.Fatalf("SDK result=%+v error=%v", result, err)
	}
	if result.ExternalNetworkAccess || result.ExternalProviderAccess {
		t.Fatalf("SDK offline verification crossed an external boundary: %+v", result)
	}

	wrong := client
	wrong.CryptoSuite = sdk.CryptoSuiteINTLV1
	trust.Proof.ClientPublicKey = wrong
	if result, err := sdk.VerifySingleProofOffline(bytes.NewReader(content), decoded.SingleProof, trust, sdk.OfflineVerifyOptions{}); err == nil || result.Valid {
		t.Fatalf("SDK accepted cross-suite trust: result=%+v err=%v", result, err)
	}
}

func sdkVectorDescriptor(t *testing.T, identity cnsmvectors.Identity) sdk.KeyDescriptor {
	t.Helper()
	descriptor, err := identity.Descriptor()
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.Kind != keydescriptor.KindVerifier || descriptor.Provider != keydescriptor.ProviderPublic {
		t.Fatalf("corpus descriptor is not a public verifier: %+v", descriptor)
	}
	out := sdk.KeyDescriptor{
		CryptoSuite:       descriptor.CryptoSuite,
		Provider:          descriptor.Provider,
		KeyID:             descriptor.KeyID,
		Algorithm:         descriptor.Algorithm,
		PublicKeyEncoding: descriptor.PublicKey.Encoding,
		PublicKey:         append([]byte(nil), descriptor.PublicKey.Bytes...),
		SM2UserID:         descriptor.SM2UserID,
		CertificateChain:  cloneBytesList(descriptor.CertificateChain),
	}
	if err := out.Validate(); err != nil {
		t.Fatal(err)
	}
	return out
}

func cloneBytesList(values [][]byte) [][]byte {
	out := make([][]byte, len(values))
	for index := range values {
		out[index] = append([]byte(nil), values[index]...)
	}
	return out
}
