package sdfsigner

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/emmansun/gmsm/sm2"

	"github.com/wowtrust/trustdb/v2/sdk/signerplugin"
)

type Plugin struct {
	backend  Backend
	config   Config
	identity DeviceIdentity
	info     signerplugin.Info
	required Capability

	mu       sync.Mutex
	accepted map[string][]byte
	closed   bool
}

func New(ctx context.Context, config Config, backend Backend) (*Plugin, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if backend == nil || config.Credential == nil {
		return nil, fmt.Errorf("%w: backend and credential source are required", ErrInvalidConfiguration)
	}
	required := config.RequiredCapabilities
	if required == 0 {
		required = SigningCapabilities
	}
	if !validIdentifier(config.DeviceRef, 4096) ||
		!validIdentifier(config.CredentialRef, 4096) ||
		required&SigningCapabilities != SigningCapabilities ||
		required&^AllCapabilities != 0 ||
		config.MaxConcurrentSigns == 0 || config.MaxConcurrentSigns > 1024 {
		return nil, fmt.Errorf("%w: device, credential, KEK, or concurrency is invalid", ErrInvalidConfiguration)
	}
	if required&SM4Capabilities != 0 {
		if !validIdentifier(config.KEKID, 256) || config.KEKIndex == 0 {
			return nil, fmt.Errorf("%w: SM4 KEK identity is required", ErrInvalidConfiguration)
		}
	} else if config.KEKID != "" || config.KEKIndex != 0 {
		return nil, fmt.Errorf("%w: SM4 KEK configured without capability", ErrInvalidConfiguration)
	}
	info := signerplugin.Info{
		PluginID:     config.PluginID,
		ProviderKind: signerplugin.ProviderSDF,
		Algorithms: []signerplugin.AlgorithmCapability{
			{
				CryptoSuite:       signerplugin.SuiteCNSMV1,
				Algorithm:         signerplugin.AlgorithmSM2SM3,
				PublicKeyEncoding: signerplugin.SM2PublicKeyEncoding,
				SignatureEncoding: signerplugin.SM2SignatureEncoding,
				SM2UserID:         signerplugin.SM2DefaultUserID,
			},
			{
				CryptoSuite:       signerplugin.SuiteFISCOBCOSGuomi,
				Algorithm:         signerplugin.AlgorithmSM2SM3,
				PublicKeyEncoding: signerplugin.SM2PublicKeyEncoding,
				SignatureEncoding: signerplugin.SM2SignatureEncoding,
				SM2UserID:         signerplugin.SM2DefaultUserID,
			},
		},
		MaxConcurrentSigns: config.MaxConcurrentSigns,
	}
	if err := signerplugin.ValidateInfo(info); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfiguration, err)
	}
	device, identity, err := discover(ctx, backend, config.DeviceRef)
	if err != nil {
		return nil, providerError(err)
	}
	capabilities, err := device.Capabilities(ctx)
	if err != nil {
		return nil, providerError(err)
	}
	if capabilities&required != required {
		return nil, providerError(newFault(faultUnsupported))
	}
	session, err := device.OpenSession(ctx)
	if err != nil {
		return nil, providerError(err)
	}
	healthErr := session.Health(ctx)
	closeErr := session.Close()
	if healthErr != nil {
		return nil, providerError(healthErr)
	}
	if closeErr != nil {
		return nil, providerError(closeErr)
	}
	return &Plugin{
		backend: backend, config: config, identity: identity, info: info, required: required,
		accepted: make(map[string][]byte),
	}, nil
}

func (p *Plugin) Info(context.Context) (signerplugin.Info, error) {
	if p == nil {
		return signerplugin.Info{}, signerplugin.NewProviderError(signerplugin.ErrorUnavailable, "SDF provider is unavailable")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return signerplugin.Info{}, signerplugin.NewProviderError(signerplugin.ErrorUnavailable, "SDF provider is unavailable")
	}
	info := p.info
	info.Algorithms = append([]signerplugin.AlgorithmCapability(nil), info.Algorithms...)
	return info, nil
}

func (p *Plugin) Health(ctx context.Context) error {
	session, err := p.openSession(ctx)
	if err != nil {
		return providerError(err)
	}
	defer session.Close()
	return providerError(session.Health(ctx))
}

func (p *Plugin) PublicKey(ctx context.Context, key signerplugin.Key) ([]byte, error) {
	keyIndex, cacheKey, err := p.validateKey(key)
	if err != nil {
		return nil, providerError(err)
	}
	publicKey, err := p.readPublicKey(ctx, keyIndex)
	if err != nil {
		return nil, providerError(err)
	}
	if err := p.acceptPublicKey(cacheKey, publicKey); err != nil {
		return nil, providerError(err)
	}
	return append([]byte(nil), publicKey...), nil
}

func (p *Plugin) Sign(ctx context.Context, key signerplugin.Key, message []byte) ([]byte, error) {
	keyIndex, cacheKey, err := p.validateKey(key)
	if err != nil || len(message) == 0 || len(message) > signerplugin.MaxSignInputBytes {
		return nil, providerError(newFault(faultInvalid))
	}
	session, err := p.openSession(ctx)
	if err != nil {
		return nil, providerError(err)
	}
	defer session.Close()
	credential, err := p.config.Credential.Read(ctx)
	if err != nil {
		return nil, providerError(err)
	}
	defer clear(credential)
	publicKey, err := session.PublicKey(ctx, keyIndex, credential)
	if err != nil {
		return nil, providerError(err)
	}
	if err := validatePublicKey(publicKey); err != nil {
		return nil, providerError(newFault(faultPrecondition))
	}
	if err := p.requireAcceptedPublicKey(cacheKey, publicKey); err != nil {
		return nil, providerError(err)
	}
	// Never retry Sign. A native failure can occur after the randomized
	// signature and device audit side effect have already happened.
	public, err := sm2.NewPublicKey(publicKey)
	if err != nil {
		return nil, providerError(newFault(faultPrecondition))
	}
	hasher, err := sm2.NewHashWithUserID(public, []byte(signerplugin.SM2DefaultUserID))
	if err != nil {
		return nil, providerError(newFault(faultPrecondition))
	}
	if _, err := hasher.Write(message); err != nil {
		return nil, providerError(newFault(faultInternal))
	}
	digest := hasher.Sum(nil)
	if len(digest) != 32 {
		clear(digest)
		return nil, providerError(newFault(faultInternal))
	}
	rawSignature, err := session.SignSM2Digest(ctx, keyIndex, credential, digest)
	clear(digest)
	if err != nil {
		return nil, providerError(err)
	}
	signature, err := normalizeRawSM2Signature(rawSignature)
	clear(rawSignature)
	if err != nil {
		return nil, providerError(newFault(faultPrecondition))
	}
	if !sm2.VerifyASN1WithSM2(public, []byte(signerplugin.SM2DefaultUserID), message, signature) {
		clear(signature)
		return nil, providerError(newFault(faultPrecondition))
	}
	return signature, nil
}

// Random obtains device random through the negotiated SDF capability. This
// operation is intentionally not part of signer-plugin v1.
func (p *Plugin) Random(ctx context.Context, length uint32) ([]byte, error) {
	if p == nil || p.required&CapabilityRandom == 0 {
		return nil, providerError(newFault(faultUnsupported))
	}
	if length == 0 || length > MaxRandomBytes {
		return nil, providerError(newFault(faultInvalid))
	}
	session, err := p.openSession(ctx)
	if err != nil {
		return nil, providerError(err)
	}
	defer session.Close()
	random, err := session.Random(ctx, length)
	if err != nil {
		return nil, providerError(err)
	}
	if len(random) != int(length) {
		clear(random)
		return nil, providerError(newFault(faultPrecondition))
	}
	return random, nil
}

// GenerateSM4Session asks the device to generate a non-exportable 128-bit
// session key and returns only its KEK-wrapped durable form plus an opaque
// same-session handle. The randomized generation operation is never retried.
func (p *Plugin) GenerateSM4Session(ctx context.Context) (WrappedSM4Key, *SM4Session, error) {
	if p == nil || p.required&SM4Capabilities != SM4Capabilities {
		return WrappedSM4Key{}, nil, providerError(newFault(faultUnsupported))
	}
	session, err := p.openSession(ctx)
	if err != nil {
		return WrappedSM4Key{}, nil, providerError(err)
	}
	credential, err := p.config.Credential.Read(ctx)
	if err != nil {
		_ = session.Close()
		return WrappedSM4Key{}, nil, providerError(err)
	}
	defer clear(credential)
	wrapped, handle, err := session.GenerateSM4KeyWithKEK(ctx, p.config.KEKIndex, credential)
	if err != nil {
		_ = session.Close()
		return WrappedSM4Key{}, nil, providerError(err)
	}
	if len(wrapped) == 0 || len(wrapped) > MaxWrappedKeyBytes || handle.value == 0 {
		clear(wrapped)
		if handle.value != 0 {
			_ = session.DestroySessionKey(context.Background(), handle)
		}
		_ = session.Close()
		return WrappedSM4Key{}, nil, providerError(newFault(faultPrecondition))
	}
	durable, durableErr := NewWrappedSM4Key(p.identity, p.config.KEKID, p.config.KEKIndex, wrapped)
	if durableErr != nil {
		_ = session.DestroySessionKey(context.Background(), handle)
		_ = session.Close()
		return WrappedSM4Key{}, nil, providerError(newFault(faultInternal))
	}
	return durable, &SM4Session{session: session, handle: handle}, nil
}

// ImportSM4Session imports only a KEK-wrapped session key. Exact KEK identity
// and index prevent a restored blob from silently binding to another KEK.
func (p *Plugin) ImportSM4Session(ctx context.Context, wrapped WrappedSM4Key) (*SM4Session, error) {
	if p == nil || p.required&SM4Capabilities != SM4Capabilities {
		return nil, providerError(newFault(faultUnsupported))
	}
	if err := wrapped.Validate(); err != nil {
		return nil, providerError(newFault(faultInvalid))
	}
	if wrapped.Device != p.identity ||
		wrapped.KEKID != p.config.KEKID || wrapped.KEKIndex != p.config.KEKIndex ||
		len(wrapped.Wrapped) == 0 || len(wrapped.Wrapped) > MaxWrappedKeyBytes {
		return nil, providerError(newFault(faultInvalid))
	}
	session, err := p.openSession(ctx)
	if err != nil {
		return nil, providerError(err)
	}
	credential, err := p.config.Credential.Read(ctx)
	if err != nil {
		_ = session.Close()
		return nil, providerError(err)
	}
	defer clear(credential)
	handle, err := session.ImportSM4KeyWithKEK(
		ctx,
		p.config.KEKIndex,
		credential,
		append([]byte(nil), wrapped.Wrapped...),
	)
	if err != nil {
		_ = session.Close()
		return nil, providerError(err)
	}
	if handle.value == 0 {
		_ = session.Close()
		return nil, providerError(newFault(faultPrecondition))
	}
	return &SM4Session{session: session, handle: handle}, nil
}

// SM4Session owns one non-serializable device handle. Close destroys the key
// before releasing the native session.
type SM4Session struct {
	session Session
	handle  SessionKeyHandle

	opMu      sync.Mutex
	mu        sync.Mutex
	closed    bool
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

func (s *SM4Session) EncryptCBC(ctx context.Context, iv, plaintext []byte) ([]byte, error) {
	if err := validateSM4Input(iv, plaintext); err != nil {
		return nil, providerError(err)
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	session, handle, err := s.active()
	if err != nil {
		return nil, providerError(err)
	}
	ciphertext, err := session.EncryptSM4CBC(
		ctx, handle, append([]byte(nil), iv...), append([]byte(nil), plaintext...),
	)
	if err != nil {
		return nil, providerError(err)
	}
	if len(ciphertext) != len(plaintext) {
		clear(ciphertext)
		return nil, providerError(newFault(faultPrecondition))
	}
	return ciphertext, nil
}

func (s *SM4Session) DecryptCBC(ctx context.Context, iv, ciphertext []byte) ([]byte, error) {
	if err := validateSM4Input(iv, ciphertext); err != nil {
		return nil, providerError(err)
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	session, handle, err := s.active()
	if err != nil {
		return nil, providerError(err)
	}
	plaintext, err := session.DecryptSM4CBC(
		ctx, handle, append([]byte(nil), iv...), append([]byte(nil), ciphertext...),
	)
	if err != nil {
		return nil, providerError(err)
	}
	if len(plaintext) != len(ciphertext) {
		clear(plaintext)
		return nil, providerError(newFault(faultPrecondition))
	}
	return plaintext, nil
}

func (s *SM4Session) MAC(ctx context.Context, iv, data []byte) ([]byte, error) {
	if err := validateSM4Input(iv, data); err != nil {
		return nil, providerError(err)
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	session, handle, err := s.active()
	if err != nil {
		return nil, providerError(err)
	}
	mac, err := session.CalculateSM4MAC(
		ctx, handle, append([]byte(nil), iv...), append([]byte(nil), data...),
	)
	if err != nil {
		return nil, providerError(err)
	}
	if len(mac) != SM4BlockBytes {
		clear(mac)
		return nil, providerError(newFault(faultPrecondition))
	}
	return mac, nil
}

func (s *SM4Session) Close() error {
	if s == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), DefaultSessionCloseTimeout)
	defer cancel()
	return s.CloseContext(ctx)
}

// CloseContext bounds the caller-visible cleanup wait. A native SDF call
// cannot be interrupted safely in-process, so timed-out cleanup continues in
// the isolated sidecar; the host supervisor remains the final hard-stop.
func (s *SM4Session) CloseContext(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.closeOnce.Do(func() {
		s.closeDone = make(chan struct{})
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		go func() {
			s.opMu.Lock()
			s.mu.Lock()
			session := s.session
			handle := s.handle
			s.session = nil
			s.handle = SessionKeyHandle{}
			s.mu.Unlock()
			if session != nil {
				destroyErr := session.DestroySessionKey(context.Background(), handle)
				closeErr := session.Close()
				if destroyErr != nil {
					s.closeErr = providerError(destroyErr)
				} else {
					s.closeErr = providerError(closeErr)
				}
			}
			s.opMu.Unlock()
			close(s.closeDone)
		}()
	})
	select {
	case <-s.closeDone:
		return s.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *SM4Session) active() (Session, SessionKeyHandle, error) {
	if s == nil {
		return nil, SessionKeyHandle{}, newFault(faultUnavailable)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.session == nil || s.handle.value == 0 {
		return nil, SessionKeyHandle{}, newFault(faultUnavailable)
	}
	return s.session, s.handle, nil
}

func validateSM4Input(iv, input []byte) error {
	if len(iv) != SM4BlockBytes || len(input) == 0 ||
		len(input) > MaxSM4OperationBytes || len(input)%SM4BlockBytes != 0 {
		return newFault(faultInvalid)
	}
	return nil
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

func (p *Plugin) validateKey(key signerplugin.Key) (uint32, string, error) {
	if err := signerplugin.ValidateKey(key); err != nil ||
		key.Binding.ProtocolVersion != signerplugin.ProtocolVersion ||
		key.Binding.PluginID != p.info.PluginID ||
		key.Binding.ProviderKind != signerplugin.ProviderSDF ||
		(key.Binding.CryptoSuite != signerplugin.SuiteCNSMV1 &&
			key.Binding.CryptoSuite != signerplugin.SuiteFISCOBCOSGuomi) ||
		key.Binding.Algorithm != signerplugin.AlgorithmSM2SM3 ||
		key.Binding.PublicKeyEncoding != signerplugin.SM2PublicKeyEncoding ||
		key.Binding.SignatureEncoding != signerplugin.SM2SignatureEncoding ||
		key.Binding.SM2UserID != signerplugin.SM2DefaultUserID ||
		key.Reference.SDF == nil ||
		key.Reference.SDF.DeviceRef != p.config.DeviceRef ||
		key.Reference.SDF.CredentialRef != p.config.CredentialRef ||
		key.Reference.SDF.KeyIndex == 0 {
		return 0, "", newFault(faultInvalid)
	}
	return key.Reference.SDF.KeyIndex, fmt.Sprintf("%d\x00%s", key.Reference.SDF.KeyIndex, key.Binding.KeyID), nil
}

func (p *Plugin) readPublicKey(ctx context.Context, keyIndex uint32) ([]byte, error) {
	session, err := p.openSession(ctx)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	credential, err := p.config.Credential.Read(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(credential)
	publicKey, err := session.PublicKey(ctx, keyIndex, credential)
	if err != nil {
		return nil, err
	}
	if err := validatePublicKey(publicKey); err != nil {
		return nil, newFault(faultPrecondition)
	}
	return append([]byte(nil), publicKey...), nil
}

func (p *Plugin) openSession(ctx context.Context) (Session, error) {
	device, identity, err := discover(ctx, p.backend, p.config.DeviceRef)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	closed := p.closed
	expected := p.identity
	p.mu.Unlock()
	if closed {
		return nil, newFault(faultUnavailable)
	}
	if identity != expected {
		return nil, newFault(faultPrecondition)
	}
	capabilities, err := device.Capabilities(ctx)
	if err != nil {
		return nil, err
	}
	if capabilities&p.required != p.required {
		return nil, newFault(faultUnsupported)
	}
	return device.OpenSession(ctx)
}

func discover(ctx context.Context, backend Backend, deviceRef string) (Device, DeviceIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, DeviceIdentity{}, err
	}
	device, err := backend.Discover(ctx, deviceRef)
	if err != nil {
		return nil, DeviceIdentity{}, err
	}
	if device == nil {
		return nil, DeviceIdentity{}, newFault(faultUnavailable)
	}
	identity, err := device.Identity(ctx)
	if err != nil {
		return nil, DeviceIdentity{}, err
	}
	if err := validateIdentity(identity); err != nil || identity.DeviceID != deviceRef {
		return nil, DeviceIdentity{}, newFault(faultPrecondition)
	}
	return device, identity, nil
}

func validateIdentity(identity DeviceIdentity) error {
	for _, value := range []string{
		identity.AdapterID,
		identity.AdapterVersion,
		identity.DeviceID,
		identity.Serial,
		identity.Firmware,
	} {
		if !validIdentifier(value, 256) {
			return errors.New("invalid SDF device identity")
		}
	}
	return nil
}

func validatePublicKey(encoded []byte) error {
	if len(encoded) != 65 || encoded[0] != 0x04 {
		return errors.New("invalid SDF SM2 public key")
	}
	x, y := elliptic.Unmarshal(sm2.P256(), encoded)
	if x == nil || y == nil || !bytes.Equal(elliptic.Marshal(sm2.P256(), x, y), encoded) {
		return errors.New("non-canonical SDF SM2 public key")
	}
	return nil
}

func normalizeRawSM2Signature(raw []byte) ([]byte, error) {
	if len(raw) != 64 {
		return nil, errors.New("invalid raw SDF SM2 signature")
	}
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	order := sm2.P256().Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(order) >= 0 || s.Cmp(order) >= 0 {
		return nil, errors.New("SDF SM2 signature scalar is out of range")
	}
	return asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{R: r, S: s})
}

func (p *Plugin) acceptPublicKey(cacheKey string, publicKey []byte) error {
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

type publicKeyAcceptance struct {
	cacheKey string
	bytes    []byte
}

// acceptPublicKeysAtomically preflights every existing pin before publishing
// any recovered pin. It prevents a later conflict from leaving an earlier
// recovery entry visible in the process-local accepted cache.
func (p *Plugin) acceptPublicKeysAtomically(values []publicKeyAcceptance) error {
	prepared := make([]publicKeyAcceptance, len(values))
	for i := range values {
		prepared[i] = publicKeyAcceptance{
			cacheKey: values[i].cacheKey,
			bytes:    append([]byte(nil), values[i].bytes...),
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return newFault(faultUnavailable)
	}
	for _, value := range prepared {
		if accepted, exists := p.accepted[value.cacheKey]; exists &&
			!bytes.Equal(accepted, value.bytes) {
			return newFault(faultPrecondition)
		}
	}
	for _, value := range prepared {
		if _, exists := p.accepted[value.cacheKey]; !exists {
			p.accepted[value.cacheKey] = value.bytes
		}
	}
	return nil
}

func (p *Plugin) requireAcceptedPublicKey(cacheKey string, publicKey []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	accepted, exists := p.accepted[cacheKey]
	if !exists || !bytes.Equal(accepted, publicKey) {
		return newFault(faultPrecondition)
	}
	return nil
}

func validIdentifier(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
