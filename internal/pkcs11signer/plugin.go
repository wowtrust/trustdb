package pkcs11signer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"

	"github.com/wowtrust/trustdb/v2/sdk/signerplugin"
)

type Plugin struct {
	backend  Backend
	config   Config
	selector TokenSelector
	identity TokenIdentity
	info     signerplugin.Info
	profiles map[string]Profile

	mu       sync.Mutex
	accepted map[string][]byte
	closed   bool
}

func New(ctx context.Context, config Config, backend Backend) (*Plugin, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if backend == nil || config.PIN == nil {
		return nil, fmt.Errorf("%w: backend and PIN source are required", ErrInvalidConfiguration)
	}
	if config.PluginID == "" || config.MaxConcurrentSigns == 0 || config.MaxConcurrentSigns > 1024 {
		return nil, fmt.Errorf("%w: plugin identity and concurrency are invalid", ErrInvalidConfiguration)
	}
	selector, err := parseTokenURI(config.TokenURI)
	if err != nil {
		return nil, fmt.Errorf("%w: token URI: %v", ErrInvalidConfiguration, err)
	}
	if len(config.Profiles) == 0 {
		return nil, fmt.Errorf("%w: at least one algorithm profile is required", ErrInvalidConfiguration)
	}
	profiles := make(map[string]Profile, len(config.Profiles))
	capabilities := make([]signerplugin.AlgorithmCapability, 0, len(config.Profiles))
	for _, profile := range config.Profiles {
		capability, profileErr := profile.capability()
		if profileErr != nil {
			return nil, profileErr
		}
		if _, exists := profiles[profile.CryptoSuite]; exists {
			return nil, fmt.Errorf("%w: duplicate crypto suite profile", ErrInvalidConfiguration)
		}
		profiles[profile.CryptoSuite] = profile.clone()
		capabilities = append(capabilities, capability)
	}
	sort.Slice(capabilities, func(i, j int) bool {
		return capabilities[i].CryptoSuite < capabilities[j].CryptoSuite
	})
	info := signerplugin.Info{
		PluginID:           config.PluginID,
		ProviderKind:       signerplugin.ProviderPKCS11,
		Algorithms:         capabilities,
		MaxConcurrentSigns: config.MaxConcurrentSigns,
	}
	if err := signerplugin.ValidateInfo(info); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfiguration, err)
	}
	token, err := backend.Discover(ctx, selector)
	if err != nil {
		return nil, providerError(err)
	}
	if token == nil || !selector.matchesIdentity(token.Identity()) {
		return nil, providerError(newFault(faultUnavailable))
	}
	if err := requireMechanisms(ctx, token, profiles); err != nil {
		return nil, providerError(err)
	}
	config.Profiles = nil
	return &Plugin{
		backend: backend, config: config, selector: selector, identity: token.Identity(),
		info: info, profiles: profiles, accepted: make(map[string][]byte),
	}, nil
}

func (p *Plugin) Info(context.Context) (signerplugin.Info, error) {
	if p == nil {
		return signerplugin.Info{}, signerplugin.NewProviderError(signerplugin.ErrorUnavailable, "PKCS#11 provider is unavailable")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return signerplugin.Info{}, signerplugin.NewProviderError(signerplugin.ErrorUnavailable, "PKCS#11 provider is unavailable")
	}
	info := p.info
	info.Algorithms = append([]signerplugin.AlgorithmCapability(nil), info.Algorithms...)
	return info, nil
}

func (p *Plugin) Health(ctx context.Context) error {
	token, err := p.token(ctx)
	if err != nil {
		return providerError(err)
	}
	return providerError(requireMechanisms(ctx, token, p.profiles))
}

func (p *Plugin) PublicKey(ctx context.Context, key signerplugin.Key) ([]byte, error) {
	selector, profile, err := p.validateKey(key)
	if err != nil {
		return nil, providerError(err)
	}
	material, err := p.lookup(ctx, selector)
	if err != nil {
		return nil, providerError(err)
	}
	publicKey, err := normalizePublicKey(profile.CryptoSuite, material)
	if err != nil {
		return nil, providerError(newFault(faultPrecondition))
	}
	if err := p.acceptPublicKey(selector, publicKey); err != nil {
		return nil, providerError(err)
	}
	return append([]byte(nil), publicKey...), nil
}

func (p *Plugin) Sign(ctx context.Context, key signerplugin.Key, message []byte) ([]byte, error) {
	selector, profile, err := p.validateKey(key)
	if err != nil {
		return nil, providerError(err)
	}
	if len(message) == 0 {
		return nil, providerError(newFault(faultInvalid))
	}
	token, err := p.token(ctx)
	if err != nil {
		return nil, providerError(err)
	}
	session, err := token.OpenSession(ctx)
	if err != nil {
		return nil, providerError(err)
	}
	defer session.Close()
	pin, err := p.config.PIN.Read(ctx)
	if err != nil {
		return nil, providerError(err)
	}
	if err := session.Login(ctx, pin); err != nil {
		clear(pin)
		return nil, providerError(err)
	}
	clear(pin)
	material, err := session.Lookup(ctx, selector)
	if err != nil {
		return nil, providerError(err)
	}
	publicKey, err := normalizePublicKey(profile.CryptoSuite, material)
	if err != nil {
		return nil, providerError(newFault(faultPrecondition))
	}
	if err := p.requireAcceptedPublicKey(selector, publicKey); err != nil {
		return nil, providerError(err)
	}
	signature, err := session.Sign(ctx, material.Private, profile, append([]byte(nil), message...))
	if err != nil {
		// Sign is deliberately never retried. A transport/session failure can
		// be ambiguous after a randomized token signature.
		return nil, providerError(err)
	}
	signature, err = normalizeSignature(profile, signature)
	if err != nil {
		return nil, providerError(newFault(faultPrecondition))
	}
	return signature, nil
}

// Certificate retrieves the matching public certificate for operational
// inventory. It is not exposed over signer-plugin v1 and therefore never
// enters evidence or replaces verifier-local trust material.
func (p *Plugin) Certificate(ctx context.Context, key signerplugin.Key) ([]byte, error) {
	selector, _, err := p.validateKey(key)
	if err != nil {
		return nil, providerError(err)
	}
	material, err := p.lookup(ctx, selector)
	if err != nil {
		return nil, providerError(err)
	}
	if len(material.CertificateDER) == 0 {
		return nil, providerError(newFault(faultNotFound))
	}
	return append([]byte(nil), material.CertificateDER...), nil
}

func (p *Plugin) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	return p.backend.Close()
}

func (p *Plugin) validateKey(key signerplugin.Key) (ObjectSelector, Profile, error) {
	if err := signerplugin.ValidateKey(key); err != nil {
		return ObjectSelector{}, Profile{}, newFault(faultInvalid)
	}
	if key.Binding.PluginID != p.info.PluginID || key.Binding.ProviderKind != signerplugin.ProviderPKCS11 ||
		key.Reference.PKCS11 == nil {
		return ObjectSelector{}, Profile{}, newFault(faultInvalid)
	}
	profile, ok := p.profiles[key.Binding.CryptoSuite]
	if !ok {
		return ObjectSelector{}, Profile{}, newFault(faultUnsupported)
	}
	capability, err := profile.capability()
	if err != nil ||
		key.Binding.Algorithm != capability.Algorithm ||
		key.Binding.PublicKeyEncoding != capability.PublicKeyEncoding ||
		key.Binding.SignatureEncoding != capability.SignatureEncoding ||
		key.Binding.SM2UserID != capability.SM2UserID {
		return ObjectSelector{}, Profile{}, newFault(faultInvalid)
	}
	selector, err := parseObjectURI(key.Reference.PKCS11.URI)
	if err != nil || !selector.Token.matchesIdentity(p.identity) {
		return ObjectSelector{}, Profile{}, newFault(faultInvalid)
	}
	return selector, profile, nil
}

func (p *Plugin) lookup(ctx context.Context, selector ObjectSelector) (KeyMaterial, error) {
	token, err := p.token(ctx)
	if err != nil {
		return KeyMaterial{}, err
	}
	session, err := token.OpenSession(ctx)
	if err != nil {
		return KeyMaterial{}, err
	}
	defer session.Close()
	pin, err := p.config.PIN.Read(ctx)
	if err != nil {
		return KeyMaterial{}, err
	}
	if err := session.Login(ctx, pin); err != nil {
		clear(pin)
		return KeyMaterial{}, err
	}
	clear(pin)
	material, err := session.Lookup(ctx, selector)
	if err != nil {
		return KeyMaterial{}, err
	}
	return material.clone(), nil
}

func (p *Plugin) token(ctx context.Context) (Token, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return nil, newFault(faultUnavailable)
	}
	token, err := p.backend.Discover(ctx, p.selector)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, newFault(faultUnavailable)
	}
	if !equalTokenIdentity(token.Identity(), p.identity) {
		return nil, newFault(faultPrecondition)
	}
	return token, nil
}

func (p *Plugin) acceptPublicKey(selector ObjectSelector, publicKey []byte) error {
	cacheKey := selector.cacheKey()
	p.mu.Lock()
	defer p.mu.Unlock()
	if accepted, exists := p.accepted[cacheKey]; exists {
		if !bytes.Equal(accepted, publicKey) {
			return newFault(faultPrecondition)
		}
		return nil
	}
	p.accepted[cacheKey] = append([]byte(nil), publicKey...)
	return nil
}

func (p *Plugin) requireAcceptedPublicKey(selector ObjectSelector, publicKey []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	accepted, exists := p.accepted[selector.cacheKey()]
	if !exists || !bytes.Equal(accepted, publicKey) {
		return newFault(faultPrecondition)
	}
	return nil
}

func requireMechanisms(ctx context.Context, token Token, profiles map[string]Profile) error {
	mechanisms, err := token.Mechanisms(ctx)
	if err != nil {
		return err
	}
	for _, profile := range profiles {
		found := false
		for _, mechanism := range mechanisms {
			if mechanism.Type == profile.Mechanism && mechanism.Flags&MechanismFlagSign != 0 {
				found = true
				break
			}
		}
		if !found {
			return newFault(faultUnsupported)
		}
	}
	return nil
}

func normalizePublicKey(suite string, material KeyMaterial) ([]byte, error) {
	var objectKey []byte
	for _, candidate := range [][]byte{material.ECPoint, material.PublicValue} {
		if len(candidate) == 0 {
			continue
		}
		decoded := unwrapOctetString(candidate)
		switch suite {
		case signerplugin.SuiteINTLV1:
			if len(decoded) == ed25519.PublicKeySize {
				objectKey = append([]byte(nil), decoded...)
			}
		case signerplugin.SuiteCNSMV1, signerplugin.SuiteFISCOBCOSGuomi:
			x, y := elliptic.Unmarshal(sm2.P256(), decoded)
			if x != nil && y != nil && len(decoded) == 65 {
				objectKey = append([]byte(nil), decoded...)
			}
		}
		if len(objectKey) != 0 {
			break
		}
	}
	var certificateKey []byte
	if len(material.CertificateDER) != 0 {
		certificate, err := smx509.ParseCertificate(material.CertificateDER)
		if err != nil || !bytes.Equal(certificate.Raw, material.CertificateDER) {
			return nil, errors.New("invalid token certificate")
		}
		switch suite {
		case signerplugin.SuiteINTLV1:
			publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
			if !ok {
				return nil, errors.New("token certificate is not Ed25519")
			}
			certificateKey = append([]byte(nil), publicKey...)
		case signerplugin.SuiteCNSMV1, signerplugin.SuiteFISCOBCOSGuomi:
			publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
			if !ok || publicKey.X == nil || publicKey.Y == nil || !sm2.P256().IsOnCurve(publicKey.X, publicKey.Y) {
				return nil, errors.New("token certificate is not SM2")
			}
			certificateKey = elliptic.Marshal(sm2.P256(), publicKey.X, publicKey.Y)
		default:
			return nil, errors.New("unsupported suite")
		}
	}
	if len(objectKey) == 0 {
		objectKey = certificateKey
	}
	if len(objectKey) == 0 {
		return nil, errors.New("token has no usable public material")
	}
	if len(certificateKey) != 0 && !bytes.Equal(objectKey, certificateKey) {
		return nil, errors.New("token public key and certificate differ")
	}
	return objectKey, nil
}

func unwrapOctetString(value []byte) []byte {
	var decoded []byte
	rest, err := asn1.Unmarshal(value, &decoded)
	if err == nil && len(rest) == 0 && len(decoded) != 0 {
		return decoded
	}
	return value
}

func normalizeSignature(profile Profile, signature []byte) ([]byte, error) {
	switch profile.CryptoSuite {
	case signerplugin.SuiteINTLV1:
		if profile.SignatureFormat != SignatureFormatRaw || len(signature) != ed25519.SignatureSize {
			return nil, errors.New("invalid Ed25519 token signature")
		}
		return append([]byte(nil), signature...), nil
	case signerplugin.SuiteCNSMV1, signerplugin.SuiteFISCOBCOSGuomi:
		var r, s *big.Int
		switch profile.SignatureFormat {
		case SignatureFormatRaw:
			if len(signature) != 64 {
				return nil, errors.New("invalid raw SM2 token signature")
			}
			r = new(big.Int).SetBytes(signature[:32])
			s = new(big.Int).SetBytes(signature[32:])
		case SignatureFormatDER:
			var values struct {
				R *big.Int
				S *big.Int
			}
			rest, err := asn1.Unmarshal(signature, &values)
			if err != nil || len(rest) != 0 || values.R == nil || values.S == nil {
				return nil, errors.New("invalid DER SM2 token signature")
			}
			r, s = values.R, values.S
		default:
			return nil, errors.New("unsupported SM2 signature format")
		}
		order := sm2.P256().Params().N
		if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(order) >= 0 || s.Cmp(order) >= 0 {
			return nil, errors.New("SM2 signature scalar is out of range")
		}
		encoded, err := asn1.Marshal(struct {
			R *big.Int
			S *big.Int
		}{R: r, S: s})
		if err != nil {
			return nil, err
		}
		if profile.SignatureFormat == SignatureFormatDER && !bytes.Equal(encoded, signature) {
			return nil, errors.New("SM2 signature DER is non-canonical")
		}
		return encoded, nil
	default:
		return nil, errors.New("unsupported suite")
	}
}
