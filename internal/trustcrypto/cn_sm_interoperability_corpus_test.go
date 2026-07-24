package trustcrypto_test

import (
	"context"
	"testing"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/test/cnsmvectors"
)

func TestProviderContractConsumesSharedCNSMInteropSignatures(t *testing.T) {
	corpus, err := cnsmvectors.Load()
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
	for _, item := range []struct {
		name      string
		publicKey trustcrypto.PublicKeyDescriptor
		artifact  cnsmvectors.Artifact
	}{
		{"client claim", client, corpus.Artifacts.ClientClaim},
		{"accepted receipt", server, corpus.Artifacts.AcceptedReceipt},
		{"committed receipt", server, corpus.Artifacts.CommittedReceipt},
		{"signed tree head", server, corpus.Artifacts.SignedTreeHead},
		{"key event", registry, corpus.Artifacts.KeyEvent},
	} {
		t.Run(item.name, func(t *testing.T) {
			input, err := item.artifact.SignatureInput()
			if err != nil {
				t.Fatal(err)
			}
			signature, err := item.artifact.SignatureDER()
			if err != nil {
				t.Fatal(err)
			}
			if err := trustcrypto.VerifySignatureForSuite(
				context.Background(),
				cryptosuite.CNSMV1,
				item.publicKey,
				input,
				model.Signature{
					Alg:       cryptosuite.SignatureSM2SM3,
					KeyID:     item.publicKey.KeyID,
					Signature: signature,
				},
			); err != nil {
				t.Fatalf("provider rejected corpus signature: %v", err)
			}
			if err := trustcrypto.VerifySignatureForSuite(
				context.Background(),
				cryptosuite.CNSMV1,
				item.publicKey,
				input,
				model.Signature{
					Alg:       cryptosuite.SignatureEd25519,
					KeyID:     item.publicKey.KeyID,
					Signature: signature,
				},
			); err == nil {
				t.Fatal("provider accepted an algorithm-confused signature")
			}
			if err := trustcrypto.VerifySignatureForSuite(
				context.Background(),
				cryptosuite.INTLV1,
				item.publicKey,
				input,
				model.Signature{
					Alg:       cryptosuite.SignatureSM2SM3,
					KeyID:     item.publicKey.KeyID,
					Signature: signature,
				},
			); err == nil {
				t.Fatal("provider accepted a cross-suite signature")
			}
			if err := trustcrypto.ValidateSM2SignatureDER(append(signature, 0)); err == nil {
				t.Fatal("provider accepted non-canonical DER")
			}
		})
	}
}
