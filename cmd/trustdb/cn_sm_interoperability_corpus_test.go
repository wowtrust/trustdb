package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/wowtrust/trustdb/internal/sproof"
	"github.com/wowtrust/trustdb/test/cnsmvectors"
)

func TestCLIConsumesSharedCNSMInteropProofOffline(t *testing.T) {
	corpus, err := cnsmvectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	content, err := corpus.Contents[0].Bytes()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	contentPath := writeVectorFile(t, dir, "content.bin", content)
	proofBytes, err := corpus.Artifacts.SingleProof.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	proofPath := writeVectorFile(t, dir, "proof.sproof", proofBytes)
	clientPath := writeVectorDescriptor(t, dir, "client.pub", corpus.Identities.Client)
	serverPath := writeVectorDescriptor(t, dir, "server.pub", corpus.Identities.Server)
	registryPath := writeVectorDescriptor(t, dir, "registry.pub", corpus.Identities.Registry)

	rt, output := newVerifyRuntime(t)
	command := newVerifyCommand(rt)
	command.SetContext(context.Background())
	command.SetArgs([]string{
		"--file", contentPath,
		"--sproof", proofPath,
		"--client-public-key", clientPath,
		"--server-public-key", serverPath,
		"--registry-public-key", registryPath,
	})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	var result sproof.OfflineResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode CLI result: %v output=%q", err, output.String())
	}
	if !result.Valid || result.ProofLevel != "L4" ||
		result.ExternalNetworkAccess || result.ExternalProviderAccess {
		t.Fatalf("CLI offline result = %+v", result)
	}

	rt, _ = newVerifyRuntime(t)
	command = newVerifyCommand(rt)
	command.SetContext(context.Background())
	command.SetArgs([]string{
		"--file", contentPath,
		"--sproof", proofPath,
		"--client-public-key", clientPath,
		"--server-public-key", serverPath,
	})
	if err := command.Execute(); err == nil {
		t.Fatal("CLI trusted embedded Registry V2 material without a verifier-local registry key")
	}
}

func writeVectorDescriptor(t *testing.T, dir, name string, identity cnsmvectors.Identity) string {
	t.Helper()
	descriptor, err := identity.Descriptor()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := writeKeyDescriptor(path, descriptor); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeVectorFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
