package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	trustconfig "github.com/wowtrust/trustdb/internal/config"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/keyenvelope"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/statusnotify"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/sdk/signerplugin"
)

const (
	signerPluginHelperEnv = "TRUSTDB_TEST_SIGNER_PLUGIN_HELPER"
	signerPluginKeyEnv    = "TRUSTDB_TEST_SIGNER_PLUGIN_PRIVATE_KEY"
)

func TestRuntimeConfigResolvesExternalSignerPlugin(t *testing.T) {
	publicKey, privateKey, descriptorPath := writeTestRemoteSignerDescriptor(t)
	rt := testRuntimeWithRemotePlugin(t, privateKey)
	signer, loaded, err := rt.readSigner(context.Background(), descriptorPath)
	if err != nil {
		t.Fatalf("readSigner() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.closeSignerResolver() })
	if loaded.Provider != keydescriptor.ProviderRemote || signer.Handle().Provider != keydescriptor.ProviderRemote {
		t.Fatalf("resolved providers = %q/%q", loaded.Provider, signer.Handle().Provider)
	}
	message := []byte("runtime-configured signer plugin")
	signature, err := trustcrypto.Sign(context.Background(), cryptosuite.INTLV1, signer, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if !ed25519.Verify(publicKey, message, signature.Signature) {
		t.Fatal("external signer returned an invalid signature")
	}
	if err := rt.closeSignerResolver(); err != nil {
		t.Fatalf("closeSignerResolver() error = %v", err)
	}
}

func TestRuntimeConfigRetainsDefaultEncryptedSoftwareProvider(t *testing.T) {
	t.Setenv(keyenvelope.DefaultPassphraseEnv, "correct horse battery staple")
	dir := t.TempDir()
	executeKeyCommand(t, []string{"key", "generate", "--out", dir, "--prefix", "encrypted"})

	rt := &runtimeConfig{cfg: trustconfig.Default(), errOut: io.Discard}
	signer, loaded, err := rt.readSigner(context.Background(), filepath.Join(dir, "encrypted.key"))
	if err != nil {
		t.Fatalf("readSigner() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.closeSignerResolver() })
	if loaded.Provider != keydescriptor.ProviderSoftware || signer.Handle().Provider != keydescriptor.ProviderSoftware {
		t.Fatalf("resolved providers = %q/%q", loaded.Provider, signer.Handle().Provider)
	}
	message := []byte("encrypted software signer through runtime resolver")
	signature, err := trustcrypto.Sign(context.Background(), cryptosuite.INTLV1, signer, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(loaded.PublicKey.Bytes), message, signature.Signature) {
		t.Fatal("encrypted software signer returned an invalid signature")
	}
}

func TestRuntimeConfigDoesNotFallbackForUnconfiguredExternalProvider(t *testing.T) {
	_, _, descriptorPath := writeTestRemoteSignerDescriptor(t)
	rt := &runtimeConfig{cfg: trustconfig.Default(), errOut: io.Discard}
	if _, _, err := rt.readSigner(context.Background(), descriptorPath); !errors.Is(err, keydescriptor.ErrUnsupportedProvider) {
		t.Fatalf("readSigner() error = %v, want ErrUnsupportedProvider", err)
	}
	if rt.signerResolver != nil {
		t.Fatal("failed resolution retained a signer resolver")
	}
}

func TestOpenLifecycleRegistryClosesPluginResolverOnValidationFailure(t *testing.T) {
	_, privateKey, descriptorPath := writeTestRemoteSignerDescriptor(t)
	rt := testRuntimeWithRemotePlugin(t, privateKey)
	_, err := openLifecycleRegistry(context.Background(), rt, filepath.Join(t.TempDir(), "keys.tdkeys"), descriptorPath, "", "wrong-key-id")
	if err == nil {
		t.Fatal("openLifecycleRegistry() accepted a mismatched registry key ID")
	}
	if rt.signerResolver != nil {
		t.Fatal("openLifecycleRegistry() failure retained the plugin resolver")
	}
}

func TestLifecycleRegistryPluginSignsStatusNotificationRoute(t *testing.T) {
	_, privateKey, descriptorPath := writeTestRemoteSignerDescriptor(t)
	rt := testRuntimeWithRemotePlugin(t, privateKey)
	t.Cleanup(func() { _ = rt.closeSignerResolver() })

	registryPath := filepath.Join(t.TempDir(), "keys.tdkeys")
	registry, signer, registryPub, err := openLifecycleRegistryWithSigner(
		context.Background(), rt, registryPath, descriptorPath, "", "plugin-key",
	)
	if err != nil {
		t.Fatalf("openLifecycleRegistryWithSigner() error = %v", err)
	}
	if registry == nil {
		t.Fatal("openLifecycleRegistryWithSigner() returned a nil registry")
	}
	route := model.UpstreamNotificationRoute{
		WebhookURL: "https://upstream.example.test/trustdb/status-refresh",
	}
	routePath, err := configureStatusNotificationRoute(
		registryPath, "tenant-a", "client-a", route, signer, registryPub,
	)
	if err != nil {
		t.Fatalf("configureStatusNotificationRoute() error = %v", err)
	}
	if err := rt.closeSignerResolver(); err != nil {
		t.Fatalf("closeSignerResolver() error = %v", err)
	}

	store, err := statusnotify.OpenRouteStore(routePath, nil, registryPub)
	if err != nil {
		t.Fatalf("OpenRouteStore() error = %v", err)
	}
	if got, found := store.Lookup("tenant-a", "client-a"); !found || got != route {
		t.Fatalf("signed notification route = %+v, %v; want %+v, true", got, found, route)
	}
}

func writeTestRemoteSignerDescriptor(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindSigner,
		Provider:      keydescriptor.ProviderRemote,
		CryptoSuite:   cryptosuite.INTLV1,
		KeyID:         "plugin-key",
		Algorithm:     cryptosuite.SignatureEd25519,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: cryptosuite.Ed25519PublicKeyEncoding,
			Bytes:    append([]byte(nil), publicKey...),
		},
		Remote: &keydescriptor.RemoteKeyReference{
			Endpoint:      "https://kms.example.test",
			Handle:        "plugin-key",
			CredentialRef: "env:" + signerPluginKeyEnv,
		},
	}
	descriptorPath := filepath.Join(t.TempDir(), "remote-signer.tdkey")
	if err := keydescriptor.WriteFile(descriptorPath, descriptor); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return publicKey, privateKey, descriptorPath
}

func testRuntimeWithRemotePlugin(t *testing.T, privateKey ed25519.PrivateKey) *runtimeConfig {
	t.Helper()
	t.Setenv(signerPluginHelperEnv, "1")
	t.Setenv(signerPluginKeyEnv, base64.RawURLEncoding.EncodeToString(privateKey))
	cfg := trustconfig.Default()
	cfg.Crypto.SignerPlugins.Remote = trustconfig.SignerPlugin{
		Command:        os.Args[0],
		Args:           []string{"-test.run=^TestSignerPluginHelperProcess$"},
		InheritEnv:     []string{signerPluginHelperEnv, signerPluginKeyEnv},
		StartTimeout:   "5s",
		RPCTimeout:     "5s",
		MaxConcurrency: 2,
	}
	return &runtimeConfig{cfg: cfg, errOut: io.Discard}
}

func TestSignerPluginHelperProcess(t *testing.T) {
	if os.Getenv(signerPluginHelperEnv) != "1" {
		return
	}
	encoded := os.Getenv(signerPluginKeyEnv)
	privateKey, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		os.Exit(2)
	}
	plugin := &testRemoteSignerPlugin{
		privateKey: ed25519.PrivateKey(append([]byte(nil), privateKey...)),
		publicKey:  append(ed25519.PublicKey(nil), ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)...),
	}
	if err := signerplugin.Serve(context.Background(), plugin); err != nil {
		os.Exit(3)
	}
}

type testRemoteSignerPlugin struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func (*testRemoteSignerPlugin) Info(context.Context) (signerplugin.Info, error) {
	return signerplugin.Info{
		PluginID:     "trustdb-test-remote",
		ProviderKind: signerplugin.ProviderRemote,
		Algorithms: []signerplugin.AlgorithmCapability{{
			CryptoSuite:       signerplugin.SuiteINTLV1,
			Algorithm:         signerplugin.AlgorithmEd25519,
			PublicKeyEncoding: signerplugin.Ed25519PublicKeyEncoding,
			SignatureEncoding: signerplugin.Ed25519SignatureEncoding,
		}},
		MaxConcurrentSigns: 4,
	}, nil
}

func (*testRemoteSignerPlugin) Health(context.Context) error { return nil }

func (p *testRemoteSignerPlugin) PublicKey(_ context.Context, key signerplugin.Key) ([]byte, error) {
	if key.Binding.KeyID != "plugin-key" || key.Reference.Remote == nil || key.Reference.Remote.Handle != "plugin-key" {
		return nil, signerplugin.NewProviderError(signerplugin.ErrorKeyNotFound, "signing key was not found")
	}
	return append([]byte(nil), p.publicKey...), nil
}

func (p *testRemoteSignerPlugin) Sign(_ context.Context, key signerplugin.Key, message []byte) ([]byte, error) {
	if key.Binding.KeyID != "plugin-key" {
		return nil, signerplugin.NewProviderError(signerplugin.ErrorKeyNotFound, "signing key was not found")
	}
	if len(message) == 0 {
		return nil, signerplugin.NewProviderError(signerplugin.ErrorInvalidArgument, "signing input is required")
	}
	return ed25519.Sign(p.privateKey, message), nil
}

var _ signerplugin.Plugin = (*testRemoteSignerPlugin)(nil)
