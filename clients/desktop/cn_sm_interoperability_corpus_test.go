package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/test/cnsmvectors"
)

func TestDesktopConsumesSharedCNSMInteropProofOffline(t *testing.T) {
	corpus, err := cnsmvectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	content, err := corpus.Contents[0].Bytes()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := corpus.Artifacts.SingleProof.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	contentPath := writeDesktopVectorFile(t, dir, "content.bin", content)
	proofPath := writeDesktopVectorFile(t, dir, "proof.sproof", proof)
	clientPath := writeDesktopVectorDescriptor(t, dir, "client.pub", corpus.Identities.Client)
	serverPath := writeDesktopVectorDescriptor(t, dir, "server.pub", corpus.Identities.Server)
	registryPath := writeDesktopVectorDescriptor(t, dir, "registry.pub", corpus.Identities.Registry)

	configStore, err := newStore(filepath.Join(dir, "desktop.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer configStore.close()
	desktop := NewApp()
	desktop.store = configStore
	response, err := desktop.VerifyProof(VerifyRequest{
		Mode:                       "local",
		FilePath:                   contentPath,
		SingleProofPath:            proofPath,
		ClientVerifierDescriptors:  clientPath,
		ServerVerifierDescriptors:  serverPath,
		RegistryVerifierDescriptor: registryPath,
		RequireIdentityEvidence:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !response.Valid || response.Level != "L4" ||
		response.CryptoSuite != "CN_SM_V1" || response.HashAlg != "sm3" {
		t.Fatalf("desktop verification response = %+v", response)
	}
	if response.ExternalNetworkAccess || response.ExternalProviderAccess ||
		response.EvidenceCertificatesTrusted {
		t.Fatalf("desktop offline trust boundary = %+v", response)
	}

	if _, err := desktop.VerifyProof(VerifyRequest{
		Mode:                      "local",
		FilePath:                  contentPath,
		SingleProofPath:           proofPath,
		ServerVerifierDescriptors: serverPath,
		RequireIdentityEvidence:   true,
	}); err == nil {
		t.Fatal("Desktop trusted the proof's embedded client identity without verifier-local configuration")
	}
}

func writeDesktopVectorDescriptor(t *testing.T, dir, name string, identity cnsmvectors.Identity) string {
	t.Helper()
	descriptor, err := identity.Descriptor()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := keydescriptor.WriteFile(path, descriptor); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeDesktopVectorFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
