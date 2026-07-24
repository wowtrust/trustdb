package keydescriptor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keyenvelope"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

const maxSoftwareMaterialBytes = 4096

var (
	ErrInvalidResolver       = errors.New("invalid key resolver")
	ErrUnsupportedProtection = errors.New("unsupported software key protection")
	ErrUnsafeMaterial        = errors.New("unsafe software key material")
	ErrSignerMismatch        = errors.New("resolved signer does not match key descriptor")
)

// SignerProvider resolves a non-exportable signing capability for one
// descriptor provider. Implementations must not add private-key export methods
// to the returned signer and must keep their errors free of credentials,
// hardware handles, remote handles, and private material paths.
type SignerProvider interface {
	Name() string
	ResolveSigner(context.Context, Descriptor, string) (trustcrypto.Signer, error)
}

// Resolver selects signers only through the provider named by a validated
// descriptor. It never falls back to raw key bytes or another provider.
type Resolver struct {
	providers map[string]SignerProvider
}

func NewResolver(providers ...SignerProvider) (*Resolver, error) {
	resolver := &Resolver{providers: make(map[string]SignerProvider, len(providers))}
	for _, provider := range providers {
		if provider == nil {
			return nil, fmt.Errorf("%w: nil provider", ErrInvalidResolver)
		}
		name := provider.Name()
		if !isSignerProviderName(name) {
			return nil, fmt.Errorf("%w: provider name %q", ErrInvalidResolver, name)
		}
		if _, exists := resolver.providers[name]; exists {
			return nil, fmt.Errorf("%w: duplicate provider %q", ErrInvalidResolver, name)
		}
		resolver.providers[name] = provider
	}
	return resolver, nil
}

func NewDefaultResolver() *Resolver {
	software, err := NewSoftwareProvider(keyenvelope.NewPassphraseKEKProvider(
		keyenvelope.DefaultPassphraseSource(),
	))
	if err != nil {
		panic(err)
	}
	resolver, err := NewResolver(software)
	if err != nil {
		panic(err)
	}
	return resolver
}

// ResolveSigner validates the complete descriptor, enforces suite
// availability, delegates to exactly one provider, and verifies that the
// returned handle and public key exactly match the descriptor.
func (r *Resolver) ResolveSigner(ctx context.Context, descriptor Descriptor, materialBaseDir string) (trustcrypto.Signer, error) {
	return r.resolveSigner(ctx, descriptor, materialBaseDir, false)
}

// ResolveLifecycleSigner resolves a signer for key-registry lifecycle events.
// It accepts a known but not yet server-enabled suite so SM2 keys and registry
// events can be provisioned before CN_SM_V1 evidence generation is enabled.
// Callers must not use this method to sign claims, receipts, STHs, or anchors.
func (r *Resolver) ResolveLifecycleSigner(ctx context.Context, descriptor Descriptor, materialBaseDir string) (trustcrypto.Signer, error) {
	return r.resolveSigner(ctx, descriptor, materialBaseDir, true)
}

func (r *Resolver) resolveSigner(ctx context.Context, descriptor Descriptor, materialBaseDir string, allowKnownSuite bool) (trustcrypto.Signer, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: resolver is nil", ErrInvalidResolver)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}
	if descriptor.Kind != KindSigner {
		return nil, invalid("descriptor kind %q cannot resolve a signer", descriptor.Kind)
	}
	if allowKnownSuite {
		if _, err := cryptosuite.RequireKnown(descriptor.CryptoSuite); err != nil {
			return nil, err
		}
	} else {
		if _, err := cryptosuite.RequireAvailable(descriptor.CryptoSuite); err != nil {
			return nil, err
		}
	}
	provider, ok := r.providers[descriptor.Provider]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedProvider, descriptor.Provider)
	}
	signer, err := provider.ResolveSigner(ctx, descriptor.Clone(), materialBaseDir)
	if err != nil {
		return nil, fmt.Errorf("resolve signer with provider %q: %w", descriptor.Provider, err)
	}
	if err := validateResolvedSigner(ctx, descriptor, signer, allowKnownSuite); err != nil {
		return nil, err
	}
	return signer, nil
}

func (r *Resolver) ResolveSignerFile(ctx context.Context, descriptorPath string) (trustcrypto.Signer, Descriptor, error) {
	descriptor, err := ReadFile(descriptorPath)
	if err != nil {
		return nil, Descriptor{}, err
	}
	signer, err := r.ResolveSigner(ctx, descriptor, filepath.Dir(descriptorPath))
	if err != nil {
		return nil, Descriptor{}, err
	}
	return signer, descriptor, nil
}

func (r *Resolver) ResolveLifecycleSignerFile(ctx context.Context, descriptorPath string) (trustcrypto.Signer, Descriptor, error) {
	descriptor, err := ReadFile(descriptorPath)
	if err != nil {
		return nil, Descriptor{}, err
	}
	signer, err := r.ResolveLifecycleSigner(ctx, descriptor, filepath.Dir(descriptorPath))
	if err != nil {
		return nil, Descriptor{}, err
	}
	return signer, descriptor, nil
}

func ReadFile(path string) (Descriptor, error) {
	file, err := os.Open(path)
	if err != nil {
		return Descriptor{}, fmt.Errorf("open key descriptor: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxDescriptorBytes+1))
	if err != nil {
		return Descriptor{}, fmt.Errorf("read key descriptor: %w", err)
	}
	if len(data) > maxDescriptorBytes {
		return Descriptor{}, invalid("encoded descriptor is too large")
	}
	return Unmarshal(data)
}

func WriteFile(path string, descriptor Descriptor) error {
	data, err := Marshal(descriptor)
	if err != nil {
		return err
	}
	return writeFileExclusive(path, data, 0o600)
}

func validateResolvedSigner(ctx context.Context, descriptor Descriptor, signer trustcrypto.Signer, allowKnownSuite bool) error {
	if signer == nil {
		return fmt.Errorf("%w: provider returned nil signer", ErrSignerMismatch)
	}
	if allowKnownSuite {
		if err := validateKnownSuiteSigner(ctx, descriptor.CryptoSuite, signer); err != nil {
			return fmt.Errorf("%w: %v", ErrSignerMismatch, err)
		}
	} else if err := trustcrypto.ValidateSigner(ctx, descriptor.CryptoSuite, signer); err != nil {
		return fmt.Errorf("%w: %v", ErrSignerMismatch, err)
	}
	handle := signer.Handle()
	if handle.Provider != descriptor.Provider || handle.KeyID != descriptor.KeyID || handle.Algorithm != descriptor.Algorithm {
		return fmt.Errorf("%w: provider handle metadata differs", ErrSignerMismatch)
	}
	publicKey, err := signer.PublicKey(ctx)
	if err != nil {
		return fmt.Errorf("%w: read provider public key: %v", ErrSignerMismatch, err)
	}
	if publicKey.Suite != descriptor.CryptoSuite || publicKey.KeyID != descriptor.KeyID || publicKey.Algorithm != descriptor.Algorithm ||
		publicKey.Encoding != descriptor.PublicKey.Encoding || !bytes.Equal(publicKey.Bytes, descriptor.PublicKey.Bytes) {
		return fmt.Errorf("%w: provider public key differs", ErrSignerMismatch)
	}
	return nil
}

func validateKnownSuiteSigner(ctx context.Context, suiteID cryptosuite.ID, signer trustcrypto.Signer) error {
	suite, err := cryptosuite.RequireKnown(suiteID)
	if err != nil {
		return err
	}
	if signer == nil {
		return errors.New("signer is nil")
	}
	if !signer.Capabilities().Supports(trustcrypto.CapabilitySign) || !signer.Capabilities().Supports(trustcrypto.CapabilityPublicKey) {
		return trustcrypto.ErrUnsupportedCapability
	}
	handle := signer.Handle()
	if err := handle.Validate(); err != nil {
		return err
	}
	if handle.Algorithm != suite.Signature.Algorithm {
		return fmt.Errorf("signer algorithm %q does not match suite %s", handle.Algorithm, suiteID)
	}
	publicKey, err := signer.PublicKey(ctx)
	if err != nil {
		return err
	}
	return trustcrypto.ValidatePublicKeyForSuite(suiteID, publicKey)
}

func isSignerProviderName(name string) bool {
	switch name {
	case ProviderSoftware, ProviderPKCS11, ProviderSDF, ProviderRemote:
		return true
	default:
		return false
	}
}

// SoftwareProvider resolves development/reference software keys whose private
// material lives in a separate, owner-readable file. Encrypted material is
// opened only through the exact KEK provider named by its canonical envelope;
// there is no plaintext or provider fallback.
type SoftwareProvider struct {
	kekProviders map[string]keyenvelope.KEKProvider
}

func NewSoftwareProvider(providers ...keyenvelope.KEKProvider) (SoftwareProvider, error) {
	software := SoftwareProvider{kekProviders: make(map[string]keyenvelope.KEKProvider, len(providers))}
	for _, provider := range providers {
		if provider == nil || strings.TrimSpace(provider.Name()) == "" {
			return SoftwareProvider{}, fmt.Errorf("%w: invalid KEK provider", ErrInvalidResolver)
		}
		if _, exists := software.kekProviders[provider.Name()]; exists {
			return SoftwareProvider{}, fmt.Errorf("%w: duplicate KEK provider", ErrInvalidResolver)
		}
		software.kekProviders[provider.Name()] = provider
	}
	return software, nil
}

func (SoftwareProvider) Name() string { return ProviderSoftware }

func (p SoftwareProvider) ResolveSigner(ctx context.Context, descriptor Descriptor, materialBaseDir string) (trustcrypto.Signer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}
	if descriptor.Provider != ProviderSoftware || descriptor.Software == nil {
		return nil, invalid("software provider requires software reference")
	}
	path, err := secureMaterialPath(materialBaseDir, descriptor.Software.MaterialPath)
	if err != nil {
		return nil, err
	}
	var material []byte
	switch descriptor.Software.Protection {
	case SoftwareProtectionPlaintextDev:
		material, err = readSoftwareMaterial(path)
	case SoftwareProtectionSM4Envelope:
		encoded, readErr := keyenvelope.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		defer clear(encoded)
		providers := make([]keyenvelope.KEKProvider, 0, len(p.kekProviders))
		for _, provider := range p.kekProviders {
			providers = append(providers, provider)
		}
		material, err = keyenvelope.Open(ctx, encoded, softwareEnvelopeMetadata(descriptor), providers...)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedProtection, descriptor.Software.Protection)
	}
	if err != nil {
		return nil, err
	}
	defer clear(material)
	switch descriptor.CryptoSuite {
	case cryptosuite.INTLV1:
		return trustcrypto.NewEd25519Signer(descriptor.KeyID, ed25519.PrivateKey(material))
	case cryptosuite.CNSMV1:
		return trustcrypto.NewSM2Signer(descriptor.KeyID, material)
	default:
		return nil, fmt.Errorf("%w: suite %s", ErrUnsupportedProvider, descriptor.CryptoSuite)
	}
}

// RewrapSoftwareEnvelopeFile rotates only the KEK operation for an encrypted
// software key. The descriptor, private key, public identity, and encrypted
// content remain unchanged; UpdateFile holds the durable serialization and
// atomic-replacement boundary across the complete rotation.
func RewrapSoftwareEnvelopeFile(ctx context.Context, descriptorPath string, oldProvider, newProvider keyenvelope.KEKProvider) error {
	descriptor, err := ReadFile(descriptorPath)
	if err != nil {
		return err
	}
	if descriptor.Kind != KindSigner || descriptor.Provider != ProviderSoftware || descriptor.Software == nil ||
		descriptor.Software.Protection != SoftwareProtectionSM4Envelope {
		return fmt.Errorf("%w: descriptor is not an encrypted software signer", ErrUnsupportedProtection)
	}
	path, err := secureMaterialPath(filepath.Dir(descriptorPath), descriptor.Software.MaterialPath)
	if err != nil {
		return err
	}
	return keyenvelope.UpdateFile(ctx, path, func(data []byte) ([]byte, error) {
		return keyenvelope.Rewrap(ctx, data, softwareEnvelopeMetadata(descriptor), oldProvider, newProvider)
	})
}

func softwareEnvelopeMetadata(descriptor Descriptor) keyenvelope.Metadata {
	return keyenvelope.Metadata{
		CryptoSuite:        string(descriptor.CryptoSuite),
		KeyID:              descriptor.KeyID,
		KeyAlgorithm:       descriptor.Algorithm,
		PrivateKeyEncoding: descriptor.Software.Encoding,
	}
}

func secureMaterialPath(baseDir, relativePath string) (string, error) {
	if !validRelativePath(relativePath) {
		return "", fmt.Errorf("%w: material path is not a clean relative path", ErrUnsafeMaterial)
	}
	if baseDir == "" {
		baseDir = "."
	}
	base, err := filepath.Abs(baseDir)
	if err != nil {
		return "", secretSafePathError("resolve material directory", err)
	}
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		return "", secretSafePathError("resolve material directory", err)
	}
	candidate := filepath.Join(base, filepath.FromSlash(relativePath))
	rel, err := filepath.Rel(base, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: material path escapes descriptor directory", ErrUnsafeMaterial)
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", secretSafePathError("resolve software key material", err)
	}
	if resolved != candidate {
		return "", fmt.Errorf("%w: symbolic links are forbidden", ErrUnsafeMaterial)
	}
	return candidate, nil
}

func readSoftwareMaterial(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, secretSafePathError("open software key material", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, secretSafePathError("stat software key material", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: material is not a regular file", ErrUnsafeMaterial)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: material permissions must not grant group or other access", ErrUnsafeMaterial)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxSoftwareMaterialBytes+1))
	if err != nil {
		return nil, secretSafePathError("read software key material", err)
	}
	if len(encoded) == 0 || len(encoded) > maxSoftwareMaterialBytes {
		return nil, fmt.Errorf("%w: encoded material size is invalid", ErrUnsafeMaterial)
	}
	material := make([]byte, base64.RawURLEncoding.DecodedLen(len(encoded)))
	n, err := base64.RawURLEncoding.Strict().Decode(material, encoded)
	if err != nil {
		clear(material)
		return nil, fmt.Errorf("%w: material is not canonical raw URL base64", ErrUnsafeMaterial)
	}
	material = material[:n]
	if !bytes.Equal(encoded, []byte(base64.RawURLEncoding.EncodeToString(material))) {
		clear(material)
		return nil, fmt.Errorf("%w: material encoding is not canonical", ErrUnsafeMaterial)
	}
	return material, nil
}

func secretSafePathError(action string, err error) error {
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		return fmt.Errorf("%s: %w", action, pathError.Err)
	}
	return fmt.Errorf("%s: operation failed", action)
}

func writeFileExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	cleanup = false
	return nil
}
