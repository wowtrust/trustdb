package main

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wowtrust/trustdb/internal/app"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keystore"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

// TestResolveClientKeysPrefersExplicitPubKey guards the bug where a non-empty
// default --key-registry (".trustdb/keys.tdkeys") silently overrode an
// explicitly-supplied --client-public-key. When the operator did NOT pass
// --key-registry on the command line, we want the pub key to win even if
// viper handed us a registry path from the defaults.
func TestResolveClientKeysPrefersExplicitPubKey(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	pubPath := filepath.Join(tmp, "client.pub")
	if err := writeKey(pubPath, pub); err != nil {
		t.Fatalf("writeKey() error = %v", err)
	}

	// Registry path points at a location that does not exist on disk — if
	// the old code path ran we'd get a keystore open error instead of the
	// single-key trust anchor we want.
	bogusRegistry := filepath.Join(tmp, "does-not-exist.tdkeys")

	got, resolver, err := resolveClientKeys(pubPath, bogusRegistry, "", false)
	if err != nil {
		t.Fatalf("resolveClientKeys() error = %v", err)
	}
	if resolver != nil {
		t.Fatalf("resolveClientKeys() resolver = %v, want nil (pub-key branch)", resolver)
	}
	if len(got.Bytes) != ed25519.PublicKeySize || !ed25519.PublicKey(got.Bytes).Equal(pub) {
		t.Fatalf("resolveClientKeys() pub key mismatch: %x vs %x", got.Bytes, pub)
	}
}

// TestResolveClientKeysExplicitRegistryWins makes sure the operator can still
// force the registry backend even when a pub-key is also available, as long
// as they flipped --key-registry themselves.
func TestResolveClientKeysExplicitRegistryWins(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	pubPath := filepath.Join(tmp, "client.pub")
	if err := writeKey(pubPath, pub); err != nil {
		t.Fatalf("writeKey() error = %v", err)
	}
	registryPath := filepath.Join(tmp, "keys.tdkeys")
	registryPublicPath := initializeTestRegistry(t, tmp, registryPath)

	gotPub, resolver, err := resolveClientKeys(pubPath, registryPath, registryPublicPath, true)
	if err != nil {
		t.Fatalf("resolveClientKeys() error = %v", err)
	}
	if len(gotPub.Bytes) != 0 {
		t.Fatalf("resolveClientKeys() pub = %x, want empty (registry branch)", gotPub.Bytes)
	}
	if resolver == nil {
		t.Fatalf("resolveClientKeys() resolver = nil, want registry-backed resolver")
	}
}

// TestResolveClientKeysRegistryFallback ensures deployments that rely on a
// default (non-explicit) registry and do NOT supply a pub key still open the
// registry as before — no regression for registry-first setups.
func TestResolveClientKeysRegistryFallback(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	registryPath := filepath.Join(tmp, "keys.tdkeys")
	registryPublicPath := initializeTestRegistry(t, tmp, registryPath)

	gotPub, resolver, err := resolveClientKeys("", registryPath, registryPublicPath, false)
	if err != nil {
		t.Fatalf("resolveClientKeys() error = %v", err)
	}
	if len(gotPub.Bytes) != 0 {
		t.Fatalf("resolveClientKeys() pub = %x, want empty", gotPub.Bytes)
	}
	if resolver == nil {
		t.Fatalf("resolveClientKeys() resolver = nil, want registry-backed resolver")
	}
}

func TestRequireClientKeySuiteFailsBeforeStorageForMixedSuites(t *testing.T) {
	t.Parallel()
	matchingPublic := trustcrypto.PublicKeyDescriptor{Suite: cryptosuite.INTLV1}
	if err := requireClientKeySuite(cryptosuite.INTLV1, matchingPublic, nil); err != nil {
		t.Fatalf("matching direct client suite error = %v", err)
	}

	mismatchedPublic := trustcrypto.PublicKeyDescriptor{Suite: cryptosuite.CNSMV1}
	if err := requireClientKeySuite(cryptosuite.INTLV1, mismatchedPublic, nil); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("direct client suite mismatch error = %v, code = %s", err, trusterr.CodeOf(err))
	}

	registry := suiteOnlyClientKeys{suite: cryptosuite.CNSMV1}
	if err := requireClientKeySuite(cryptosuite.INTLV1, trustcrypto.PublicKeyDescriptor{}, registry); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("registry suite mismatch error = %v, code = %s", err, trusterr.CodeOf(err))
	}
}

type suiteOnlyClientKeys struct {
	app.ClientKeyResolver
	suite cryptosuite.ID
}

func (r suiteOnlyClientKeys) Suite() cryptosuite.ID { return r.suite }

func initializeTestRegistry(t *testing.T, dir, registryPath string) string {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(dir, "registry.key")
	publicPath := filepath.Join(dir, "registry.pub")
	if err := writeKey(privatePath, privateKey); err != nil {
		t.Fatal(err)
	}
	if err := writeKey(publicPath, publicKey); err != nil {
		t.Fatal(err)
	}
	signer, _, err := readLifecycleSigner(context.Background(), privatePath)
	if err != nil {
		t.Fatal(err)
	}
	trustedPublic, _, err := readPublicKeyDescriptor(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keystore.Open(registryPath, signer, trustedPublic); err != nil {
		t.Fatal(err)
	}
	return publicPath
}

func TestSafeOutputFileNamePreventsTraversalAndCollisions(t *testing.T) {
	t.Parallel()

	outDir := t.TempDir()
	name := safeOutputFileName("../outside")
	if strings.ContainsAny(name, `/\`) {
		t.Fatalf("safeOutputFileName() = %q, want a single path segment", name)
	}
	outPath := filepath.Join(outDir, name+".tdproof")
	rel, err := filepath.Rel(outDir, outPath)
	if err != nil {
		t.Fatalf("Rel() error = %v", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		t.Fatalf("output path escapes out dir: outDir=%q outPath=%q rel=%q", outDir, outPath, rel)
	}
	if safeOutputFileName("rec/1") == safeOutputFileName("rec_2F1") {
		t.Fatalf("safeOutputFileName() collides for slash and escaped-slash spelling")
	}
	if safeOutputFileName("") == safeOutputFileName("_") {
		t.Fatalf("safeOutputFileName() collides for empty string and underscore")
	}
	if got := safeOutputFileName("rec-1_2.3"); got != "rec-1_2.3" {
		t.Fatalf("safeOutputFileName() = %q, want plain safe name unchanged", got)
	}
}
