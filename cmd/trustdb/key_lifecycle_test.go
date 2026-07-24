package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/statusnotify"
)

func TestKeyGenerateSM2ProducesLifecycleResolvableDescriptors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	command := newRootCommand(&stdout, &stderr)
	command.SetArgs([]string{
		"key", "generate",
		"--suite", string(cryptosuite.CNSMV1),
		"--out", dir,
		"--prefix", "sm2-client",
	})
	if err := command.Execute(); err != nil {
		t.Fatalf("key generate SM2 error = %v stderr=%s", err, stderr.String())
	}
	signerPath := filepath.Join(dir, "sm2-client.key")
	descriptor, err := keydescriptor.ReadFile(signerPath)
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.CryptoSuite != cryptosuite.CNSMV1 || descriptor.Algorithm != cryptosuite.SignatureSM2SM3 || descriptor.SM2UserID != cryptosuite.SM2DefaultUserID {
		t.Fatalf("SM2 descriptor = %+v", descriptor)
	}
	resolver := keydescriptor.NewDefaultResolver()
	if _, _, err := resolver.ResolveLifecycleSignerFile(context.Background(), signerPath); err != nil {
		t.Fatalf("ResolveLifecycleSignerFile() error = %v", err)
	}
	if _, _, err := resolver.ResolveSignerFile(context.Background(), signerPath); !errors.Is(err, cryptosuite.ErrUnavailableSuite) {
		t.Fatalf("server signer gate error = %v, want unavailable suite", err)
	}
}

func TestKeyLifecycleCLIImportRotateCompromiseAndList(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, prefix := range []string{"registry", "old", "new"} {
		executeKeyCommand(t, []string{"key", "generate", "--out", dir, "--prefix", prefix})
	}
	registryPath := filepath.Join(dir, "keys.tdkeys")
	common := []string{
		"--registry", registryPath,
		"--registry-private-key", filepath.Join(dir, "registry.key"),
		"--registry-public-key", filepath.Join(dir, "registry.pub"),
		"--registry-key-id", "registry-key",
		"--tenant", "tenant-a",
		"--client", "client-a",
	}
	importArgs := append([]string{"key", "import"}, common...)
	importArgs = append(importArgs,
		"--key-id", "old-key",
		"--public-key", filepath.Join(dir, "old.pub"),
		"--valid-from-unix", "100",
		"--status-webhook-url", "https://upstream.example/trustdb/status-refresh",
		"--status-nats-subject", "trustdb.status.client-a",
		"--status-nats-queue-group", "trustdb-status-client-a",
	)
	executeKeyCommand(t, importArgs)
	routeStore, err := statusnotify.OpenRouteStore(statusnotify.RouteStorePath(registryPath))
	if err != nil {
		t.Fatal(err)
	}
	wantRoute := model.UpstreamNotificationRoute{
		WebhookURL:     "https://upstream.example/trustdb/status-refresh",
		NATSSubject:    "trustdb.status.client-a",
		NATSQueueGroup: "trustdb-status-client-a",
	}
	if route, found := routeStore.Lookup("tenant-a", "client-a"); !found || route != wantRoute {
		t.Fatalf("registered notification route = %+v, %v", route, found)
	}

	rotateArgs := append([]string{"key", "rotate"}, common...)
	rotateArgs = append(rotateArgs,
		"--key-id", "new-key",
		"--previous-key-id", "old-key",
		"--descriptor", filepath.Join(dir, "new.pub"),
		"--rotated-at-unix", "200",
	)
	executeKeyCommand(t, rotateArgs)
	routeStore, err = statusnotify.OpenRouteStore(statusnotify.RouteStorePath(registryPath))
	if err != nil {
		t.Fatal(err)
	}
	if route, found := routeStore.Lookup("tenant-a", "client-a"); !found || route != wantRoute {
		t.Fatalf("notification route after rotation = %+v, %v", route, found)
	}

	compromiseArgs := append([]string{"key", "compromise"}, common...)
	compromiseArgs = append(compromiseArgs,
		"--key-id", "new-key",
		"--compromised-at-unix", "250",
		"--reason", "test incident",
	)
	executeKeyCommand(t, compromiseArgs)

	output := executeKeyCommand(t, []string{
		"key", "list",
		"--registry", registryPath,
		"--registry-public-key", filepath.Join(dir, "registry.pub"),
	})
	var listed struct {
		Manifest struct {
			SchemaVersion string `json:"schema_version"`
			CryptoSuite   string `json:"crypto_suite"`
		} `json:"manifest"`
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(output, &listed); err != nil {
		t.Fatalf("key list output = %q: %v", output, err)
	}
	if listed.Manifest.SchemaVersion != "trustdb.key-registry.v2" || listed.Manifest.CryptoSuite != string(cryptosuite.INTLV1) || len(listed.Events) != 3 {
		t.Fatalf("key list = %+v", listed)
	}
	if listed.Events[1]["type"] != "KEY_ROTATED" || listed.Events[2]["type"] != "KEY_COMPROMISED" {
		t.Fatalf("lifecycle event order = %+v", listed.Events)
	}
}

func executeKeyCommand(t *testing.T, args []string) []byte {
	t.Helper()
	var stdout, stderr bytes.Buffer
	command := newRootCommand(&stdout, &stderr)
	command.SetArgs(args)
	if err := command.Execute(); err != nil {
		t.Fatalf("trustdb %v error = %v stderr=%s", args, err, stderr.String())
	}
	return append([]byte(nil), stdout.Bytes()...)
}
