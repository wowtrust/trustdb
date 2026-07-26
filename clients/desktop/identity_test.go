package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/keyenvelope"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
	"github.com/wowtrust/trustdb/v2/sdk"
)

func TestGeneratedDesktopIdentityIsEncryptedAndSuiteAware(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		suite   string
		hashAlg string
	}{
		{name: "international", suite: string(cryptosuite.INTLV1), hashAlg: sdk.HashAlgorithmSHA256},
		{name: "national cryptography", suite: string(cryptosuite.CNSMV1), hashAlg: sdk.HashAlgorithmSM3},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			const passphrase = "correct horse battery staple"
			id, resolved, err := generateSoftwareIdentity(context.Background(), t.TempDir(), GenerateIdentityRequest{
				TenantID:    "tenant-a",
				ClientID:    "desktop-a",
				KeyID:       "client-key",
				CryptoSuite: test.suite,
				Passphrase:  passphrase,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer resolved.close()
			descriptor, err := loadDesktopIdentityDescriptor(id)
			if err != nil {
				t.Fatal(err)
			}
			if string(descriptor.CryptoSuite) != test.suite {
				t.Fatalf("descriptor crypto_suite = %s, want %s", descriptor.CryptoSuite, test.suite)
			}
			if descriptor.Software == nil || descriptor.Software.Protection != keydescriptor.SoftwareProtectionSM4Envelope {
				t.Fatalf("software reference = %+v", descriptor.Software)
			}
			materialPath := filepath.Join(filepath.Dir(id.DescriptorPath), descriptor.Software.MaterialPath)
			encoded, err := keyenvelope.ReadFile(materialPath)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte(passphrase)) {
				t.Fatal("encrypted material contains its passphrase")
			}
			if _, err := keyenvelope.Unmarshal(encoded); err != nil {
				t.Fatalf("encrypted material is not a canonical envelope: %v", err)
			}
			configJSON, err := json.Marshal(id)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{passphrase, "private_key", "pin", "credential"} {
				if strings.Contains(strings.ToLower(string(configJSON)), strings.ToLower(forbidden)) {
					t.Fatalf("identity state leaked %q: %s", forbidden, configJSON)
				}
			}

			signed, err := sdk.BuildSignedFileClaim(
				strings.NewReader("suite-aware desktop evidence"),
				resolved.identity,
				sdk.FileClaimOptions{MediaType: "text/plain"},
			)
			if err != nil {
				t.Fatal(err)
			}
			if string(signed.CryptoSuite) != test.suite || signed.Claim.Content.HashAlg != test.hashAlg {
				t.Fatalf("signed claim suite/hash = %s/%s, want %s/%s", signed.CryptoSuite, signed.Claim.Content.HashAlg, test.suite, test.hashAlg)
			}
		})
	}
}

func TestDesktopIdentityWrongPassphraseAndCorruptionFailClosed(t *testing.T) {
	t.Parallel()
	id, resolved, err := generateSoftwareIdentity(context.Background(), t.TempDir(), GenerateIdentityRequest{
		TenantID:    "tenant-a",
		ClientID:    "desktop-a",
		KeyID:       "sm2-key",
		CryptoSuite: string(cryptosuite.CNSMV1),
		Passphrase:  "correct horse battery staple",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = resolved.close()
	if _, err := resolveDesktopIdentity(context.Background(), id, "incorrect horse battery staple"); err == nil {
		t.Fatal("wrong passphrase unlocked identity")
	} else if strings.Contains(err.Error(), "correct horse") || strings.Contains(err.Error(), "incorrect horse") {
		t.Fatalf("unlock error leaked a passphrase: %v", err)
	}

	if err := os.WriteFile(id.DescriptorPath, []byte("corrupt descriptor"), 0o600); err != nil {
		t.Fatal(err)
	}
	view := identityView(&id, false)
	if view.State != "invalid" || view.Error == "" {
		t.Fatalf("corrupted identity view = %+v", view)
	}
	if _, err := resolveDesktopIdentity(context.Background(), id, "correct horse battery staple"); err == nil {
		t.Fatal("corrupted descriptor resolved a signer")
	}
}

func TestImportedDesktopSM2IdentityIsImmediatelyEncrypted(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := trustcrypto.GenerateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)

	id, resolved, err := importSoftwareIdentity(context.Background(), t.TempDir(), ImportIdentityRequest{
		TenantID:      "tenant-a",
		ClientID:      "desktop-a",
		KeyID:         "imported-sm2",
		CryptoSuite:   string(cryptosuite.CNSMV1),
		PrivateKeyB64: encodeKey(privateKey),
		Passphrase:    "import passphrase",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.close()

	descriptor, err := loadDesktopIdentityDescriptor(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(descriptor.PublicKey.Bytes, publicKey) {
		t.Fatal("imported descriptor does not contain the derived SM2 public key")
	}
	if descriptor.Software == nil {
		t.Fatal("imported identity has no encrypted software-key reference")
	}
	materialPath := filepath.Join(filepath.Dir(id.DescriptorPath), descriptor.Software.MaterialPath)
	material, err := keyenvelope.ReadFile(materialPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(material, privateKey) || bytes.Contains(material, []byte("import passphrase")) {
		t.Fatal("encrypted identity material contains import input")
	}
}

func TestDesktopIdentityRejectsLegacyAndUnknownState(t *testing.T) {
	t.Parallel()
	for _, schema := range []string{"", "trustdb.desktop-identity.v1", "trustdb.desktop-identity.v4"} {
		_, err := loadDesktopIdentityDescriptor(Identity{
			SchemaVersion: schema,
			TenantID:      "tenant-a",
			ClientID:      "desktop-a",
		})
		if err == nil {
			t.Fatalf("schema %q was accepted", schema)
		}
		if !strings.Contains(err.Error(), "unsupported desktop identity state") {
			t.Fatalf("schema %q error = %v", schema, err)
		}
	}
}

func TestManagedIdentityCleanupCannotEscapeManagedDirectory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	managedDir := filepath.Join(root, "identities")
	if err := os.MkdirAll(managedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "must-not-delete.key")
	if err := os.WriteFile(outside, []byte("not a desktop identity"), 0o600); err != nil {
		t.Fatal(err)
	}

	removeManagedIdentityMaterial(managedDir, Identity{
		ManagedMaterial: true,
		DescriptorPath:  outside,
	})
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("managed identity cleanup escaped its directory: %v", err)
	}
}

func TestLockIdentityRevokesCopiedAndInFlightSigningCapabilities(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)
	software, err := trustcrypto.NewEd25519Signer("desktop-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	blocking := &blockingDesktopSigner{
		Signer:   software,
		started:  make(chan struct{}),
		release:  make(chan struct{}),
		finished: make(chan struct{}),
	}
	descriptor, err := sdk.NewINTLV1PublicKey("desktop-key", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Provider = keydescriptor.ProviderSoftware
	resolved, err := newResolvedDesktopIdentity(
		Identity{TenantID: "tenant-a", ClientID: "desktop-a"},
		descriptor,
		blocking,
		&releaseDesktopSigner{release: blocking.release},
	)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp()
	app.setUnlockedIdentity(resolved)
	copied, err := app.unlockedSDKIdentity()
	if err != nil {
		t.Fatal(err)
	}

	signDone := make(chan error, 1)
	go func() {
		_, signErr := sdk.BuildSignedFileClaim(
			strings.NewReader("already admitted"),
			copied,
			sdk.FileClaimOptions{MediaType: "text/plain"},
		)
		signDone <- signErr
	}()
	select {
	case <-blocking.started:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight signing did not reach the provider")
	}

	lockDone := make(chan struct{})
	go func() {
		app.LockIdentity()
		close(lockDone)
	}()
	select {
	case <-lockDone:
	case <-time.After(5 * time.Second):
		t.Fatal("LockIdentity did not synchronously drain the in-flight signer")
	}
	if err := <-signDone; err != nil {
		t.Fatalf("admitted signing failed while LockIdentity drained it: %v", err)
	}
	select {
	case <-blocking.finished:
	default:
		t.Fatal("LockIdentity returned before the provider call finished")
	}

	_, err = sdk.BuildSignedFileClaim(
		strings.NewReader("must be rejected"),
		copied,
		sdk.FileClaimOptions{MediaType: "text/plain"},
	)
	if !errors.Is(err, errDesktopSigningRevoked) {
		t.Fatalf("copied identity signed after LockIdentity: %v", err)
	}
	if _, err := software.Sign(context.Background(), []byte("destroyed")); !errors.Is(err, trustcrypto.ErrSignerDestroyed) {
		t.Fatalf("software signer survived LockIdentity: %v", err)
	}
}

type blockingDesktopSigner struct {
	trustcrypto.Signer
	started      chan struct{}
	release      chan struct{}
	finished     chan struct{}
	startOnce    sync.Once
	finishedOnce sync.Once
}

func (s *blockingDesktopSigner) Sign(ctx context.Context, message []byte) (model.Signature, error) {
	s.startOnce.Do(func() { close(s.started) })
	select {
	case <-ctx.Done():
		return model.Signature{}, ctx.Err()
	case <-s.release:
	}
	signature, err := s.Signer.Sign(ctx, message)
	s.finishedOnce.Do(func() { close(s.finished) })
	return signature, err
}

func (s *blockingDesktopSigner) Destroy() {
	trustcrypto.DestroySigner(s.Signer)
}

type releaseDesktopSigner struct {
	release chan struct{}
	once    sync.Once
}

func (c *releaseDesktopSigner) Close() error {
	c.once.Do(func() { close(c.release) })
	return nil
}
