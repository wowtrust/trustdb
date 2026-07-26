package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/keyenvelope"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
	"github.com/wowtrust/trustdb/v2/sdk"
)

const desktopIdentitySchemaV2 = "trustdb.desktop-identity.v2"

var errDesktopSigningRevoked = errors.New("desktop signing capability is locked or revoked")

// decodeKeyField is intentionally limited to public material and one-shot
// private-key imports before those bytes enter an encrypted envelope. Callers
// must never persist or return the decoded private bytes.
func decodeKeyField(value string) ([]byte, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil, errors.New("empty key")
	}
	if data, err := base64.RawURLEncoding.DecodeString(v); err == nil {
		return data, nil
	}
	if data, err := base64.StdEncoding.DecodeString(v); err == nil {
		return data, nil
	}
	if data, err := base64.URLEncoding.DecodeString(v); err == nil {
		return data, nil
	}
	return nil, errors.New("invalid key: not valid base64")
}

func encodeKey(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

type GenerateIdentityRequest struct {
	TenantID    string `json:"tenant_id"`
	ClientID    string `json:"client_id"`
	KeyID       string `json:"key_id"`
	CryptoSuite string `json:"crypto_suite"`
	Passphrase  string `json:"passphrase"`
}

type ImportIdentityRequest struct {
	TenantID      string `json:"tenant_id"`
	ClientID      string `json:"client_id"`
	KeyID         string `json:"key_id"`
	CryptoSuite   string `json:"crypto_suite"`
	PrivateKeyB64 string `json:"private_key_b64"`
	Passphrase    string `json:"passphrase"`
}

type ReferenceIdentityRequest struct {
	TenantID         string   `json:"tenant_id"`
	ClientID         string   `json:"client_id"`
	DescriptorPath   string   `json:"descriptor_path"`
	PluginCommand    string   `json:"plugin_command,omitempty"`
	PluginInheritEnv []string `json:"plugin_inherit_env,omitempty"`
	Passphrase       string   `json:"passphrase,omitempty"`
}

type RotateIdentityRequest struct {
	KeyID      string `json:"key_id"`
	Passphrase string `json:"passphrase"`
}

type resolvedDesktopIdentity struct {
	identity sdk.Identity
	closer   io.Closer
	signer   trustcrypto.Signer
	gate     *desktopSigningGate

	closeOnce sync.Once
	closeErr  error
}

func (r *resolvedDesktopIdentity) close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		if r.gate != nil {
			r.gate.revoke()
		}
		if r.closer != nil {
			r.closeErr = r.closer.Close()
		}
		if r.gate != nil {
			r.gate.wait()
		}
		trustcrypto.DestroySigner(r.signer)
	})
	return r.closeErr
}

type desktopSigningGate struct {
	mu      sync.Mutex
	cond    *sync.Cond
	revoked bool
	active  int
}

func newDesktopSigningGate() *desktopSigningGate {
	gate := &desktopSigningGate{}
	gate.cond = sync.NewCond(&gate.mu)
	return gate
}

func (g *desktopSigningGate) enter() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.revoked {
		return errDesktopSigningRevoked
	}
	g.active++
	return nil
}

func (g *desktopSigningGate) leave() {
	g.mu.Lock()
	g.active--
	if g.active == 0 {
		g.cond.Broadcast()
	}
	g.mu.Unlock()
}

func (g *desktopSigningGate) revoke() {
	g.mu.Lock()
	g.revoked = true
	g.mu.Unlock()
}

func (g *desktopSigningGate) wait() {
	g.mu.Lock()
	for g.active != 0 {
		g.cond.Wait()
	}
	g.mu.Unlock()
}

func validateIdentityRequest(tenantID, clientID string) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(clientID) == "" {
		return errors.New("tenant_id and client_id are required")
	}
	return nil
}

func generateSoftwareIdentity(
	ctx context.Context,
	baseDir string,
	req GenerateIdentityRequest,
) (Identity, *resolvedDesktopIdentity, error) {
	suite, err := requireDesktopSuite(req.CryptoSuite)
	if err != nil {
		return Identity{}, nil, err
	}
	var publicKey, privateKey []byte
	switch suite.ID {
	case cryptosuite.INTLV1:
		pub, priv, generateErr := trustcrypto.GenerateEd25519Key()
		if generateErr != nil {
			return Identity{}, nil, generateErr
		}
		publicKey, privateKey = pub, priv
	case cryptosuite.CNSMV1:
		publicKey, privateKey, err = trustcrypto.GenerateSM2Key()
		if err != nil {
			return Identity{}, nil, err
		}
	default:
		return Identity{}, nil, fmt.Errorf("unsupported desktop crypto_suite %s", suite.ID)
	}
	defer clear(privateKey)
	return persistSoftwareIdentity(ctx, baseDir, req.TenantID, req.ClientID, req.KeyID, suite, publicKey, privateKey, req.Passphrase)
}

func importSoftwareIdentity(
	ctx context.Context,
	baseDir string,
	req ImportIdentityRequest,
) (Identity, *resolvedDesktopIdentity, error) {
	suite, err := requireDesktopSuite(req.CryptoSuite)
	if err != nil {
		return Identity{}, nil, err
	}
	privateKey, err := decodeKeyField(req.PrivateKeyB64)
	if err != nil {
		return Identity{}, nil, fmt.Errorf("decode private key: %w", err)
	}
	defer clear(privateKey)
	var publicKey []byte
	switch suite.ID {
	case cryptosuite.INTLV1:
		if len(privateKey) != ed25519.PrivateKeySize {
			return Identity{}, nil, fmt.Errorf("INTL_V1 private key wrong size %d", len(privateKey))
		}
		publicKey = append([]byte(nil), ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)...)
	case cryptosuite.CNSMV1:
		signer, signerErr := trustcrypto.NewSM2Signer(strings.TrimSpace(req.KeyID), privateKey)
		if signerErr != nil {
			return Identity{}, nil, fmt.Errorf("CN_SM_V1 private key: %w", signerErr)
		}
		public, publicErr := signer.PublicKey(ctx)
		if publicErr != nil {
			return Identity{}, nil, fmt.Errorf("CN_SM_V1 public key: %w", publicErr)
		}
		publicKey = append([]byte(nil), public.Bytes...)
	default:
		return Identity{}, nil, fmt.Errorf("unsupported desktop crypto_suite %s", suite.ID)
	}
	return persistSoftwareIdentity(ctx, baseDir, req.TenantID, req.ClientID, req.KeyID, suite, publicKey, privateKey, req.Passphrase)
}

func persistSoftwareIdentity(
	ctx context.Context,
	baseDir, tenantID, clientID, keyID string,
	suite cryptosuite.Suite,
	publicKey, privateKey []byte,
	passphrase string,
) (Identity, *resolvedDesktopIdentity, error) {
	if err := validateIdentityRequest(tenantID, clientID); err != nil {
		return Identity{}, nil, err
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return Identity{}, nil, errors.New("key_id is required")
	}
	if strings.TrimSpace(passphrase) == "" {
		return Identity{}, nil, errors.New("an encryption passphrase is required")
	}
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return Identity{}, nil, fmt.Errorf("prepare identity directory: %w", err)
	}

	name := "identity-" + strings.TrimPrefix(newJobID(), "hj-")
	materialName := name + ".material"
	descriptorPath := filepath.Join(baseDir, name+".key")
	materialPath := filepath.Join(baseDir, materialName)
	descriptor := keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindSigner,
		Provider:      keydescriptor.ProviderSoftware,
		CryptoSuite:   suite.ID,
		KeyID:         keyID,
		Algorithm:     suite.Signature.Algorithm,
		SM2UserID:     suite.Signature.SM2UserID,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: suite.Signature.PublicKeyEncoding,
			Bytes:    append([]byte(nil), publicKey...),
		},
		Software: &keydescriptor.SoftwareKeyReference{
			MaterialPath: materialName,
			Encoding:     suite.Signature.PrivateKeyEncoding,
			Protection:   keydescriptor.SoftwareProtectionSM4Envelope,
		},
	}
	if err := descriptor.Validate(); err != nil {
		return Identity{}, nil, fmt.Errorf("create identity descriptor: %w", err)
	}

	provider, clearPassphrase := desktopPassphraseProvider(passphrase)
	defer clearPassphrase()
	encrypted, err := keyenvelope.Seal(ctx, keyenvelope.Metadata{
		CryptoSuite:        string(suite.ID),
		KeyID:              keyID,
		KeyAlgorithm:       suite.Signature.Algorithm,
		PrivateKeyEncoding: suite.Signature.PrivateKeyEncoding,
	}, privateKey, provider)
	if err != nil {
		return Identity{}, nil, fmt.Errorf("encrypt software identity: %w", err)
	}
	defer clear(encrypted)
	if err := keyenvelope.WriteFile(materialPath, encrypted); err != nil {
		return Identity{}, nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = keyenvelope.RemoveFile(context.Background(), materialPath)
			_ = os.Remove(descriptorPath)
		}
	}()
	if err := keydescriptor.WriteFile(descriptorPath, descriptor); err != nil {
		return Identity{}, nil, err
	}
	id := Identity{
		SchemaVersion:   desktopIdentitySchemaV2,
		TenantID:        strings.TrimSpace(tenantID),
		ClientID:        strings.TrimSpace(clientID),
		DescriptorPath:  descriptorPath,
		ManagedMaterial: true,
	}
	resolved, err := resolveDesktopIdentity(ctx, id, passphrase)
	if err != nil {
		return Identity{}, nil, err
	}
	cleanup = false
	return id, resolved, nil
}

func referenceDesktopIdentity(ctx context.Context, req ReferenceIdentityRequest) (Identity, *resolvedDesktopIdentity, error) {
	if err := validateIdentityRequest(req.TenantID, req.ClientID); err != nil {
		return Identity{}, nil, err
	}
	path, err := filepath.Abs(strings.TrimSpace(req.DescriptorPath))
	if err != nil || strings.TrimSpace(req.DescriptorPath) == "" {
		return Identity{}, nil, errors.New("descriptor_path is required")
	}
	descriptor, err := keydescriptor.ReadFile(path)
	if err != nil {
		return Identity{}, nil, fmt.Errorf("read identity descriptor: %w", err)
	}
	if descriptor.Kind != keydescriptor.KindSigner {
		return Identity{}, nil, errors.New("identity descriptor must describe a signer")
	}
	if descriptor.Provider != keydescriptor.ProviderSoftware && strings.TrimSpace(req.PluginCommand) == "" {
		return Identity{}, nil, fmt.Errorf("provider %s requires a signer plugin command", descriptor.Provider)
	}
	id := Identity{
		SchemaVersion:    desktopIdentitySchemaV2,
		TenantID:         strings.TrimSpace(req.TenantID),
		ClientID:         strings.TrimSpace(req.ClientID),
		DescriptorPath:   path,
		PluginCommand:    strings.TrimSpace(req.PluginCommand),
		PluginInheritEnv: normalizeEnvironmentNames(req.PluginInheritEnv),
	}
	resolved, err := resolveDesktopIdentity(ctx, id, req.Passphrase)
	if err != nil {
		return Identity{}, nil, err
	}
	return id, resolved, nil
}

func loadDesktopIdentityDescriptor(id Identity) (keydescriptor.Descriptor, error) {
	if id.SchemaVersion != desktopIdentitySchemaV2 {
		return keydescriptor.Descriptor{}, fmt.Errorf(
			"unsupported desktop identity state %q; only %s is accepted",
			id.SchemaVersion,
			desktopIdentitySchemaV2,
		)
	}
	if err := validateIdentityRequest(id.TenantID, id.ClientID); err != nil {
		return keydescriptor.Descriptor{}, fmt.Errorf("invalid desktop identity: %w", err)
	}
	if strings.TrimSpace(id.DescriptorPath) == "" {
		return keydescriptor.Descriptor{}, errors.New("invalid desktop identity: descriptor_path is required")
	}
	descriptor, err := keydescriptor.ReadFile(id.DescriptorPath)
	if err != nil {
		return keydescriptor.Descriptor{}, fmt.Errorf("read desktop identity descriptor: %w", err)
	}
	if descriptor.Kind != keydescriptor.KindSigner {
		return keydescriptor.Descriptor{}, errors.New("desktop identity descriptor is not a signer")
	}
	if descriptor.Provider != keydescriptor.ProviderSoftware && strings.TrimSpace(id.PluginCommand) == "" {
		return keydescriptor.Descriptor{}, fmt.Errorf("desktop identity provider %s has no signer plugin command", descriptor.Provider)
	}
	return descriptor, nil
}

func resolveDesktopIdentity(ctx context.Context, id Identity, passphrase string) (*resolvedDesktopIdentity, error) {
	descriptor, err := loadDesktopIdentityDescriptor(id)
	if err != nil {
		return nil, err
	}
	providers := make([]keydescriptor.SignerProvider, 0, 2)
	var clearPassphrase func()
	if descriptor.Provider == keydescriptor.ProviderSoftware {
		if descriptor.Software == nil || descriptor.Software.Protection != keydescriptor.SoftwareProtectionSM4Envelope {
			return nil, errors.New("desktop software identities require sm4-envelope-v1 protection")
		}
		if strings.TrimSpace(passphrase) == "" {
			return nil, errors.New("identity is locked; enter its encryption passphrase")
		}
		kek, clearSecret := desktopPassphraseProvider(passphrase)
		clearPassphrase = clearSecret
		software, providerErr := keydescriptor.NewSoftwareProvider(kek)
		if providerErr != nil {
			clearPassphrase()
			return nil, providerErr
		}
		providers = append(providers, software)
	} else {
		plugin, pluginErr := keydescriptor.NewPluginSignerProvider(keydescriptor.SignerPluginOptions{
			Provider:       descriptor.Provider,
			Command:        id.PluginCommand,
			InheritEnv:     append([]string(nil), id.PluginInheritEnv...),
			StartTimeout:   10 * time.Second,
			RPCTimeout:     30 * time.Second,
			MaxConcurrency: 8,
			Stderr:         io.Discard,
		})
		if pluginErr != nil {
			return nil, pluginErr
		}
		providers = append(providers, plugin)
	}
	if clearPassphrase != nil {
		defer clearPassphrase()
	}
	resolver, err := keydescriptor.NewResolver(providers...)
	if err != nil {
		return nil, err
	}
	signer, resolvedDescriptor, err := resolver.ResolveSignerFile(ctx, id.DescriptorPath)
	if err != nil {
		_ = resolver.Close()
		return nil, fmt.Errorf("unlock desktop identity: %w", err)
	}
	if resolvedDescriptor.CryptoSuite != descriptor.CryptoSuite || resolvedDescriptor.KeyID != descriptor.KeyID {
		_ = resolver.Close()
		return nil, errors.New("resolved desktop identity descriptor changed")
	}
	public, err := descriptor.PublicKeyDescriptor()
	if err != nil {
		_ = resolver.Close()
		return nil, err
	}
	sdkDescriptor := sdk.KeyDescriptor{
		CryptoSuite:       public.Suite,
		Provider:          descriptor.Provider,
		KeyID:             public.KeyID,
		Algorithm:         public.Algorithm,
		PublicKeyEncoding: public.Encoding,
		PublicKey:         append([]byte(nil), public.Bytes...),
		SM2UserID:         descriptor.SM2UserID,
		CertificateChain:  cloneByteSlices(descriptor.CertificateChain),
	}
	resolved, err := newResolvedDesktopIdentity(id, sdkDescriptor, signer, resolver)
	if err != nil {
		_ = resolver.Close()
		trustcrypto.DestroySigner(signer)
		return nil, err
	}
	return resolved, nil
}

func newResolvedDesktopIdentity(
	id Identity,
	descriptor sdk.KeyDescriptor,
	signer trustcrypto.Signer,
	closer io.Closer,
) (*resolvedDesktopIdentity, error) {
	gate := newDesktopSigningGate()
	callback, err := sdk.NewCallbackSigner(descriptor, func(ctx context.Context, message []byte) ([]byte, error) {
		if gateErr := gate.enter(); gateErr != nil {
			return nil, gateErr
		}
		defer gate.leave()
		signature, signErr := signer.Sign(ctx, message)
		if signErr != nil {
			return nil, signErr
		}
		return append([]byte(nil), signature.Signature...), nil
	})
	if err != nil {
		return nil, err
	}
	identity, err := sdk.NewIdentity(id.TenantID, id.ClientID, callback)
	if err != nil {
		return nil, err
	}
	return &resolvedDesktopIdentity{
		identity: identity,
		closer:   closer,
		signer:   signer,
		gate:     gate,
	}, nil
}

func requireDesktopSuite(value string) (cryptosuite.Suite, error) {
	id := cryptosuite.ID(strings.TrimSpace(value))
	if id == "" {
		return cryptosuite.Suite{}, errors.New("crypto_suite is required (INTL_V1 or CN_SM_V1)")
	}
	suite, err := cryptosuite.RequireAvailable(id)
	if err != nil {
		return cryptosuite.Suite{}, fmt.Errorf("desktop crypto_suite: %w", err)
	}
	return suite, nil
}

func desktopPublicKeyDescriptor(suiteID cryptosuite.ID, keyID string, publicKey []byte) (sdk.KeyDescriptor, error) {
	switch suiteID {
	case cryptosuite.INTLV1:
		return sdk.NewINTLV1PublicKey(keyID, ed25519.PublicKey(publicKey))
	case cryptosuite.CNSMV1:
		return sdk.NewCNSMV1PublicKey(keyID, publicKey)
	default:
		return sdk.KeyDescriptor{}, fmt.Errorf("unsupported desktop crypto_suite %s", suiteID)
	}
}

func desktopPassphraseProvider(passphrase string) (*keyenvelope.PassphraseKEKProvider, func()) {
	secret := []byte(passphrase)
	provider := keyenvelope.NewPassphraseKEKProvider(func(context.Context) ([]byte, error) {
		return append([]byte(nil), secret...), nil
	})
	return provider, func() { clear(secret) }
}

func normalizeEnvironmentNames(names []string) []string {
	out := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func cloneByteSlices(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for index := range in {
		out[index] = append([]byte(nil), in[index]...)
	}
	return out
}
