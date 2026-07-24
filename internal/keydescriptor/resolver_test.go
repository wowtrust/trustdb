package keydescriptor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keyenvelope"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func TestSoftwareResolverLoadsDescriptorRelativeMaterial(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	descriptor := softwareDescriptor(publicKey, "client.material")
	writeMaterial(t, filepath.Join(dir, descriptor.Software.MaterialPath), privateKey, 0o600)
	descriptorPath := filepath.Join(dir, "client.signer.tdkey")
	if err := WriteFile(descriptorPath, descriptor); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	signer, loaded, err := NewDefaultResolver().ResolveSignerFile(context.Background(), descriptorPath)
	if err != nil {
		t.Fatalf("ResolveSignerFile() error = %v", err)
	}
	if loaded.KeyID != descriptor.KeyID || signer.Handle().KeyID != descriptor.KeyID {
		t.Fatalf("resolved key IDs = %q/%q", loaded.KeyID, signer.Handle().KeyID)
	}
	message := []byte("descriptor-driven signing")
	signature, err := signer.Sign(context.Background(), message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if !ed25519.Verify(publicKey, message, signature.Signature) {
		t.Fatal("resolved signer produced invalid signature")
	}
}

func TestSoftwareResolverOpensAuthenticatedEnvelope(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows envelope storage intentionally fails closed")
	}
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	descriptor := softwareDescriptor(publicKey, "client.material")
	descriptor.Software.Protection = SoftwareProtectionSM4Envelope
	provider := keyenvelope.NewPassphraseKEKProvider(func(ctx context.Context) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []byte("correct horse battery staple"), nil
	})
	encrypted, err := keyenvelope.Seal(context.Background(), softwareEnvelopeMetadata(descriptor), privateKey, provider)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyenvelope.WriteFile(filepath.Join(dir, descriptor.Software.MaterialPath), encrypted); err != nil {
		t.Fatal(err)
	}
	software, err := NewSoftwareProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewResolver(software)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := resolver.ResolveSigner(context.Background(), descriptor, dir)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("authenticated envelope signer")
	signature, err := signer.Sign(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(publicKey, message, signature.Signature) {
		t.Fatal("encrypted software signer produced invalid signature")
	}
}

func TestSoftwareEnvelopeConcurrentAndStaleRewrap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows envelope storage intentionally fails closed")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	descriptor := softwareDescriptor(publicKey, "client.material")
	descriptor.Software.Protection = SoftwareProtectionSM4Envelope
	descriptorPath := filepath.Join(dir, "client.key")
	if err := WriteFile(descriptorPath, descriptor); err != nil {
		t.Fatal(err)
	}
	oldProvider := resolverTestPassphraseProvider("correct horse battery staple")
	encrypted, err := keyenvelope.Seal(context.Background(), softwareEnvelopeMetadata(descriptor), privateKey, oldProvider)
	if err != nil {
		t.Fatal(err)
	}
	materialPath := filepath.Join(dir, descriptor.Software.MaterialPath)
	if err := keyenvelope.WriteFile(materialPath, encrypted); err != nil {
		t.Fatal(err)
	}

	newProviders := []*keyenvelope.PassphraseKEKProvider{
		resolverTestPassphraseProvider("replacement horse battery staple A"),
		resolverTestPassphraseProvider("replacement horse battery staple B"),
	}
	start := make(chan struct{})
	errorsOut := make(chan error, len(newProviders))
	var wait sync.WaitGroup
	for _, provider := range newProviders {
		provider := provider
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errorsOut <- RewrapSoftwareEnvelopeFile(context.Background(), descriptorPath, oldProvider, provider)
		}()
	}
	close(start)
	wait.Wait()
	close(errorsOut)
	succeeded := 0
	failedAuthentication := 0
	for err := range errorsOut {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, keyenvelope.ErrAuthenticationFailed):
			failedAuthentication++
		default:
			t.Fatalf("concurrent rewrap error = %v", err)
		}
	}
	if succeeded != 1 || failedAuthentication != 1 {
		t.Fatalf("concurrent rewrap results: success=%d authentication_failure=%d", succeeded, failedAuthentication)
	}

	current, err := keyenvelope.ReadFile(materialPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeStale := append([]byte(nil), current...)
	if err := RewrapSoftwareEnvelopeFile(
		context.Background(), descriptorPath, oldProvider,
		resolverTestPassphraseProvider("stale overwrite passphrase"),
	); !errors.Is(err, keyenvelope.ErrAuthenticationFailed) {
		t.Fatalf("stale rewrap error = %v, want authentication failure", err)
	}
	afterStale, err := keyenvelope.ReadFile(materialPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeStale, afterStale) {
		t.Fatal("stale rewrap overwrote the winning envelope")
	}
}

func TestResolverChecksProviderHandleCapabilitiesAndPublicKey(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*fakeSigner)
	}{
		{name: "provider", mutate: func(s *fakeSigner) { s.handle.Provider = ProviderSDF }},
		{name: "key id", mutate: func(s *fakeSigner) { s.handle.KeyID = "different"; s.publicKey.KeyID = "different" }},
		{name: "algorithm", mutate: func(s *fakeSigner) { s.handle.Algorithm = "different" }},
		{name: "capabilities", mutate: func(s *fakeSigner) { s.capabilities = trustcrypto.CapabilitySet(trustcrypto.CapabilityPublicKey) }},
		{name: "public key", mutate: func(s *fakeSigner) { s.publicKey.Bytes[0] ^= 0xff }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := providerDescriptor(publicKey, ProviderRemote)
			signer := newFakeSigner(ProviderRemote, descriptor.KeyID, privateKey)
			test.mutate(signer)
			resolver, err := NewResolver(fakeSignerProvider{name: ProviderRemote, signer: signer})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.ResolveSigner(context.Background(), descriptor, t.TempDir()); !errors.Is(err, ErrSignerMismatch) {
				t.Fatalf("ResolveSigner() error = %v, want ErrSignerMismatch", err)
			}
		})
	}
}

func TestResolverRoundTripsExternalProviderKinds(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, providerName := range []string{ProviderPKCS11, ProviderSDF, ProviderRemote} {
		providerName := providerName
		t.Run(providerName, func(t *testing.T) {
			t.Parallel()
			descriptor := providerDescriptor(publicKey, providerName)
			encoded, err := Marshal(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			descriptor, err = Unmarshal(encoded)
			if err != nil {
				t.Fatal(err)
			}
			resolver, err := NewResolver(fakeSignerProvider{
				name:   providerName,
				signer: newFakeSigner(providerName, descriptor.KeyID, privateKey),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.ResolveSigner(context.Background(), descriptor, t.TempDir()); err != nil {
				t.Fatalf("ResolveSigner() error = %v", err)
			}
		})
	}
}

func TestSoftwareResolverFailsClosed(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*testing.T, string, *Descriptor){
		"public mismatch": func(t *testing.T, dir string, d *Descriptor) {
			d.PublicKey.Bytes[0] ^= 0xff
		},
		"non-canonical material": func(t *testing.T, dir string, d *Descriptor) {
			if err := os.WriteFile(filepath.Join(dir, d.Software.MaterialPath), []byte(base64.StdEncoding.EncodeToString(privateKey)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"group readable": func(t *testing.T, dir string, d *Descriptor) {
			writeMaterial(t, filepath.Join(dir, d.Software.MaterialPath), privateKey, 0o640)
		},
		"sm4 envelope without provider": func(t *testing.T, dir string, d *Descriptor) {
			d.Software.Protection = SoftwareProtectionSM4Envelope
		},
	}
	if runtime.GOOS != "windows" {
		tests["symbolic link"] = func(t *testing.T, dir string, d *Descriptor) {
			target := filepath.Join(dir, "target.material")
			writeMaterial(t, target, privateKey, 0o600)
			if err := os.Symlink(target, filepath.Join(dir, d.Software.MaterialPath)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			descriptor := softwareDescriptor(publicKey, "secret-material")
			setup(t, dir, &descriptor)
			if _, err := NewDefaultResolver().ResolveSigner(context.Background(), descriptor, dir); err == nil {
				t.Fatal("ResolveSigner() error = nil")
			} else if strings.Contains(err.Error(), "secret-material") {
				t.Fatalf("ResolveSigner() leaked material path: %v", err)
			}
		})
	}
}

func TestResolverRejectsUnavailableAndUnregisteredProviders(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := providerDescriptor(publicKey, ProviderRemote)
	if _, err := NewDefaultResolver().ResolveSigner(context.Background(), descriptor, t.TempDir()); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("ResolveSigner() error = %v, want ErrUnsupportedProvider", err)
	}
	resolver, err := NewResolver(
		fakeSignerProvider{name: ProviderRemote, signer: newFakeSigner(ProviderRemote, descriptor.KeyID, privateKey)},
		fakeSignerProvider{name: ProviderRemote, signer: newFakeSigner(ProviderRemote, descriptor.KeyID, privateKey)},
	)
	if err == nil || resolver != nil {
		t.Fatal("NewResolver() accepted duplicate providers")
	}
}

func TestResolverHonorsContextCancellation(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := providerDescriptor(publicKey, ProviderRemote)
	resolver, err := NewResolver(fakeSignerProvider{name: ProviderRemote, signer: newFakeSigner(ProviderRemote, descriptor.KeyID, privateKey)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.ResolveSigner(ctx, descriptor, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveSigner() error = %v, want context.Canceled", err)
	}
}

type fakeSignerProvider struct {
	name   string
	signer trustcrypto.Signer
}

func (p fakeSignerProvider) Name() string { return p.name }

func (p fakeSignerProvider) ResolveSigner(ctx context.Context, _ Descriptor, _ string) (trustcrypto.Signer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return p.signer, nil
}

type fakeSigner struct {
	handle       trustcrypto.KeyHandle
	capabilities trustcrypto.CapabilitySet
	privateKey   ed25519.PrivateKey
	publicKey    trustcrypto.PublicKeyDescriptor
}

func newFakeSigner(provider, keyID string, privateKey ed25519.PrivateKey) *fakeSigner {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &fakeSigner{
		handle: trustcrypto.KeyHandle{Provider: provider, KeyID: keyID, Algorithm: cryptosuite.SignatureEd25519},
		capabilities: trustcrypto.CapabilitySet(
			trustcrypto.CapabilitySign | trustcrypto.CapabilityPublicKey,
		),
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		publicKey: trustcrypto.PublicKeyDescriptor{
			Suite:     cryptosuite.INTLV1,
			KeyID:     keyID,
			Algorithm: cryptosuite.SignatureEd25519,
			Encoding:  cryptosuite.Ed25519PublicKeyEncoding,
			Bytes:     append([]byte(nil), publicKey...),
		},
	}
}

func (s *fakeSigner) Handle() trustcrypto.KeyHandle { return s.handle }

func (s *fakeSigner) Capabilities() trustcrypto.CapabilitySet { return s.capabilities }

func (s *fakeSigner) PublicKey(ctx context.Context) (trustcrypto.PublicKeyDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return trustcrypto.PublicKeyDescriptor{}, err
	}
	return s.publicKey.Clone(), nil
}

func (s *fakeSigner) Sign(ctx context.Context, message []byte) (model.Signature, error) {
	if err := ctx.Err(); err != nil {
		return model.Signature{}, err
	}
	return model.Signature{
		Alg:       cryptosuite.SignatureEd25519,
		KeyID:     s.handle.KeyID,
		Signature: ed25519.Sign(s.privateKey, message),
	}, nil
}

func softwareDescriptor(publicKey ed25519.PublicKey, materialPath string) Descriptor {
	descriptor := intlDescriptor(publicKey)
	descriptor.Software = &SoftwareKeyReference{
		MaterialPath: materialPath,
		Encoding:     cryptosuite.Ed25519PrivateKeyEncoding,
		Protection:   SoftwareProtectionPlaintextDev,
	}
	return descriptor
}

func providerDescriptor(publicKey ed25519.PublicKey, provider string) Descriptor {
	descriptor := intlDescriptor(publicKey)
	descriptor.Provider = provider
	switch provider {
	case ProviderPKCS11:
		descriptor.PKCS11 = &PKCS11KeyReference{URI: "pkcs11:object=trustdb;type=private"}
	case ProviderSDF:
		descriptor.SDF = &SDFKeyReference{DeviceRef: "device-a", KeyIndex: 1}
	case ProviderRemote:
		descriptor.Remote = &RemoteKeyReference{Endpoint: "https://kms.example.test", Handle: "key-a", CredentialRef: "env:KMS_TOKEN"}
	}
	return descriptor
}

func writeMaterial(t *testing.T, path string, material []byte, mode os.FileMode) {
	t.Helper()
	encoded := []byte(base64.RawURLEncoding.EncodeToString(material))
	if err := os.WriteFile(path, encoded, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func resolverTestPassphraseProvider(passphrase string) *keyenvelope.PassphraseKEKProvider {
	return keyenvelope.NewPassphraseKEKProvider(func(ctx context.Context) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []byte(passphrase), nil
	})
}

func TestReadFileRejectsRawLegacyKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "legacy.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte("A"), 86), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(path); err == nil {
		t.Fatal("ReadFile() accepted legacy raw key material")
	}
}
