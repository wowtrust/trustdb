package keydescriptor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/sdk/signerplugin"
)

var (
	ErrSignerPluginClosed       = errors.New("signer plugin provider is closed")
	ErrSignerPluginBackoff      = errors.New("signer plugin restart is temporarily delayed")
	ErrSignerPluginIdentity     = errors.New("signer plugin identity changed")
	ErrSignerPluginProtocol     = errors.New("signer plugin protocol violation")
	ErrSignerPluginPublicKey    = errors.New("signer plugin public key changed")
	ErrSignerPluginRebind       = errors.New("signer plugin key rebind failed permanently")
	ErrSignerPluginBadSignature = errors.New("signer plugin returned an invalid signature")
)

const (
	initialPluginRestartBackoff = 100 * time.Millisecond
	maxPluginRestartBackoff     = 5 * time.Second
)

// SignerPluginOptions configures one supervised implementation of an existing
// key-descriptor provider kind. It does not add a new provider kind or allow a
// plugin to register cryptographic suites.
type SignerPluginOptions struct {
	Provider       string
	Command        string
	Args           []string
	InheritEnv     []string
	StartTimeout   time.Duration
	RPCTimeout     time.Duration
	MaxConcurrency uint32
	Stderr         io.Writer
}

type signerPluginProcess interface {
	Info() signerplugin.GetInfoResponse
	Done() <-chan struct{}
	ExitError() (error, bool)
	GetPublicKey(context.Context, signerplugin.Key) ([]byte, error)
	Sign(context.Context, signerplugin.Key, []byte) ([]byte, error)
	Close() error
}

type signerPluginProcessFactory func(context.Context, signerplugin.ProcessConfig) (signerPluginProcess, error)

type trackedPluginKey struct {
	key       signerplugin.Key
	publicKey []byte
}

// PluginSignerProvider adapts a supervised subprocess to SignerProvider. One
// provider instance owns at most one child process and may resolve multiple
// immutable keys of the same provider kind.
type PluginSignerProvider struct {
	opts    SignerPluginOptions
	factory signerPluginProcessFactory

	mu             sync.Mutex
	process        signerPluginProcess
	identity       *signerplugin.GetInfoResponse
	keys           []trackedPluginKey
	closed         bool
	compromisedErr error
	nextStart      time.Time
	restartBackoff time.Duration
}

func NewPluginSignerProvider(opts SignerPluginOptions) (*PluginSignerProvider, error) {
	return newPluginSignerProvider(opts, func(ctx context.Context, config signerplugin.ProcessConfig) (signerPluginProcess, error) {
		return signerplugin.StartProcess(ctx, config)
	})
}

func newPluginSignerProvider(opts SignerPluginOptions, factory signerPluginProcessFactory) (*PluginSignerProvider, error) {
	if !isExternalSignerProvider(opts.Provider) {
		return nil, fmt.Errorf("%w: signer plugin provider %q", ErrInvalidResolver, opts.Provider)
	}
	if factory == nil {
		return nil, fmt.Errorf("%w: signer plugin process factory is nil", ErrInvalidResolver)
	}
	opts.Command = strings.TrimSpace(opts.Command)
	if opts.Command == "" {
		return nil, fmt.Errorf("%w: signer plugin command is required", ErrInvalidResolver)
	}
	if opts.StartTimeout <= 0 || opts.RPCTimeout <= 0 {
		return nil, fmt.Errorf("%w: signer plugin timeouts must be positive", ErrInvalidResolver)
	}
	if opts.MaxConcurrency > 1024 {
		return nil, fmt.Errorf("%w: signer plugin max concurrency exceeds 1024", ErrInvalidResolver)
	}
	opts.Args = append([]string(nil), opts.Args...)
	opts.InheritEnv = append([]string(nil), opts.InheritEnv...)
	return &PluginSignerProvider{opts: opts, factory: factory}, nil
}

func (p *PluginSignerProvider) Name() string { return p.opts.Provider }

func (p *PluginSignerProvider) ResolveSigner(ctx context.Context, descriptor Descriptor, _ string) (trustcrypto.Signer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}
	if descriptor.Kind != KindSigner || descriptor.Provider != p.opts.Provider {
		return nil, invalid("signer plugin provider %q cannot resolve descriptor provider %q", p.opts.Provider, descriptor.Provider)
	}
	if _, err := cryptosuite.RequireKnown(descriptor.CryptoSuite); err != nil {
		return nil, err
	}
	process, info, err := p.getProcess(ctx)
	if err != nil {
		return nil, err
	}
	key, err := pluginKey(descriptor, info)
	if err != nil {
		return nil, err
	}
	publicKey, err := process.GetPublicKey(ctx, key)
	if err != nil {
		return nil, p.processError("resolve public key", process, err)
	}
	if !bytes.Equal(publicKey, descriptor.PublicKey.Bytes) {
		p.compromise(process, ErrSignerPluginPublicKey)
		return nil, ErrSignerPluginPublicKey
	}
	p.trackKey(key, publicKey)
	publicDescriptor, err := descriptor.PublicKeyDescriptor()
	if err != nil {
		return nil, err
	}
	return &pluginSigner{
		provider:  p,
		key:       key,
		handle:    trustcrypto.KeyHandle{Provider: descriptor.Provider, KeyID: descriptor.KeyID, Algorithm: descriptor.Algorithm},
		publicKey: publicDescriptor,
	}, nil
}

func (p *PluginSignerProvider) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	process := p.process
	p.process = nil
	p.mu.Unlock()
	if process != nil {
		return process.Close()
	}
	return nil
}

func (p *PluginSignerProvider) getProcess(ctx context.Context) (signerPluginProcess, signerplugin.GetInfoResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, signerplugin.GetInfoResponse{}, err
	}
	if p.closed {
		return nil, signerplugin.GetInfoResponse{}, ErrSignerPluginClosed
	}
	if p.compromisedErr != nil {
		return nil, signerplugin.GetInfoResponse{}, p.compromisedErr
	}
	if p.process != nil {
		select {
		case <-p.process.Done():
			_ = p.process.Close()
			p.process = nil
			p.scheduleRestartLocked()
		default:
			return p.process, p.process.Info(), nil
		}
	}
	if !p.nextStart.IsZero() && time.Now().Before(p.nextStart) {
		return nil, signerplugin.GetInfoResponse{}, ErrSignerPluginBackoff
	}
	process, err := p.factory(ctx, signerplugin.ProcessConfig{
		Command:                p.opts.Command,
		Args:                   append([]string(nil), p.opts.Args...),
		InheritEnv:             append([]string(nil), p.opts.InheritEnv...),
		StartTimeout:           p.opts.StartTimeout,
		HealthTimeout:          p.opts.RPCTimeout,
		PublicKeyTimeout:       p.opts.RPCTimeout,
		SignTimeout:            p.opts.RPCTimeout,
		HostMaxConcurrentSigns: p.opts.MaxConcurrency,
		Stderr:                 p.opts.Stderr,
	})
	if err != nil {
		switch {
		case errors.Is(err, signerplugin.ErrProtocolViolation), signerplugin.IsPermanentRPC(err):
			p.compromisedErr = ErrSignerPluginProtocol
			return nil, signerplugin.GetInfoResponse{}, p.compromisedErr
		case ctx.Err() != nil:
			return nil, signerplugin.GetInfoResponse{}, ctx.Err()
		default:
			p.scheduleRestartLocked()
			return nil, signerplugin.GetInfoResponse{}, safePluginError("start", err)
		}
	}
	info := normalizedPluginInfo(process.Info())
	if info.ProviderKind != p.opts.Provider {
		_ = process.Close()
		p.compromisedErr = fmt.Errorf("%w: provider kind differs", ErrSignerPluginIdentity)
		return nil, signerplugin.GetInfoResponse{}, p.compromisedErr
	}
	if p.identity == nil {
		identity := info
		p.identity = &identity
	} else if !reflect.DeepEqual(*p.identity, info) {
		_ = process.Close()
		p.compromisedErr = ErrSignerPluginIdentity
		return nil, signerplugin.GetInfoResponse{}, p.compromisedErr
	}
	for _, tracked := range p.keys {
		publicKey, keyErr := process.GetPublicKey(ctx, tracked.key)
		if keyErr != nil {
			_ = process.Close()
			switch {
			case errors.Is(keyErr, signerplugin.ErrProtocolViolation):
				p.compromisedErr = ErrSignerPluginProtocol
				return nil, signerplugin.GetInfoResponse{}, p.compromisedErr
			case signerplugin.IsPermanentRPC(keyErr):
				p.compromisedErr = ErrSignerPluginRebind
				return nil, signerplugin.GetInfoResponse{}, p.compromisedErr
			case ctx.Err() != nil:
				return nil, signerplugin.GetInfoResponse{}, ctx.Err()
			default:
				p.scheduleRestartLocked()
				return nil, signerplugin.GetInfoResponse{}, safePluginError("rebind public key", keyErr)
			}
		}
		if !bytes.Equal(publicKey, tracked.publicKey) {
			_ = process.Close()
			p.compromisedErr = ErrSignerPluginPublicKey
			return nil, signerplugin.GetInfoResponse{}, p.compromisedErr
		}
	}
	p.process = process
	p.nextStart = time.Time{}
	return process, info, nil
}

func (p *PluginSignerProvider) processError(operation string, process signerPluginProcess, err error) error {
	if errors.Is(err, signerplugin.ErrProtocolViolation) {
		p.compromise(process, ErrSignerPluginProtocol)
		return ErrSignerPluginProtocol
	}
	if errors.Is(err, signerplugin.ErrSignCapacityWait) {
		return safePluginError(operation, err)
	}
	if signerplugin.ShouldRestartProcess(err) || signerplugin.IsRPCDeadlineExceeded(err) || errors.Is(err, context.DeadlineExceeded) {
		p.invalidate(process)
	}
	return safePluginError(operation, err)
}

func (p *PluginSignerProvider) invalidate(process signerPluginProcess) {
	p.mu.Lock()
	if p.process == process {
		p.process = nil
		p.scheduleRestartLocked()
	}
	p.mu.Unlock()
	_ = process.Close()
}

func (p *PluginSignerProvider) compromise(process signerPluginProcess, err error) {
	p.mu.Lock()
	if p.process == process {
		p.process = nil
	}
	p.compromisedErr = err
	p.mu.Unlock()
	_ = process.Close()
}

func (p *PluginSignerProvider) scheduleRestartLocked() {
	if p.restartBackoff == 0 {
		p.restartBackoff = initialPluginRestartBackoff
	} else {
		p.restartBackoff *= 2
		if p.restartBackoff > maxPluginRestartBackoff {
			p.restartBackoff = maxPluginRestartBackoff
		}
	}
	p.nextStart = time.Now().Add(p.restartBackoff)
}

func (p *PluginSignerProvider) markSuccessfulSign(process signerPluginProcess) {
	p.mu.Lock()
	if p.process == process && p.compromisedErr == nil {
		p.restartBackoff = 0
		p.nextStart = time.Time{}
	}
	p.mu.Unlock()
}

func (p *PluginSignerProvider) trackKey(key signerplugin.Key, publicKey []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, tracked := range p.keys {
		if reflect.DeepEqual(tracked.key, key) {
			return
		}
	}
	p.keys = append(p.keys, trackedPluginKey{key: key, publicKey: append([]byte(nil), publicKey...)})
}

type pluginSigner struct {
	provider  *PluginSignerProvider
	key       signerplugin.Key
	handle    trustcrypto.KeyHandle
	publicKey trustcrypto.PublicKeyDescriptor
}

func (s *pluginSigner) Handle() trustcrypto.KeyHandle { return s.handle }

func (*pluginSigner) Capabilities() trustcrypto.CapabilitySet {
	return trustcrypto.CapabilitySet(trustcrypto.CapabilitySign | trustcrypto.CapabilityPublicKey)
}

func (s *pluginSigner) PublicKey(ctx context.Context) (trustcrypto.PublicKeyDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return trustcrypto.PublicKeyDescriptor{}, err
	}
	return s.publicKey.Clone(), nil
}

func (s *pluginSigner) Sign(ctx context.Context, message []byte) (model.Signature, error) {
	process, _, err := s.provider.getProcess(ctx)
	if err != nil {
		return model.Signature{}, err
	}
	signatureBytes, err := process.Sign(ctx, s.key, message)
	if err != nil {
		return model.Signature{}, s.provider.processError("sign", process, err)
	}
	signature := model.Signature{
		Alg:       s.handle.Algorithm,
		KeyID:     s.handle.KeyID,
		Signature: append([]byte(nil), signatureBytes...),
	}
	if err := trustcrypto.VerifySignatureForSuite(ctx, s.publicKey.Suite, s.publicKey, message, signature); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return model.Signature{}, err
		}
		s.provider.compromise(process, ErrSignerPluginBadSignature)
		return model.Signature{}, ErrSignerPluginBadSignature
	}
	s.provider.markSuccessfulSign(process)
	return signature, nil
}

func pluginKey(descriptor Descriptor, info signerplugin.GetInfoResponse) (signerplugin.Key, error) {
	suite, err := cryptosuite.RequireKnown(descriptor.CryptoSuite)
	if err != nil {
		return signerplugin.Key{}, err
	}
	key := signerplugin.Key{Binding: signerplugin.Binding{
		ProtocolVersion:   signerplugin.ProtocolVersion,
		PluginID:          info.PluginID,
		ProviderKind:      descriptor.Provider,
		CryptoSuite:       string(descriptor.CryptoSuite),
		Algorithm:         descriptor.Algorithm,
		PublicKeyEncoding: descriptor.PublicKey.Encoding,
		SignatureEncoding: suite.Signature.Encoding,
		KeyID:             descriptor.KeyID,
		SM2UserID:         descriptor.SM2UserID,
	}}
	switch descriptor.Provider {
	case ProviderPKCS11:
		key.Reference.PKCS11 = &signerplugin.PKCS11KeyReference{URI: descriptor.PKCS11.URI}
	case ProviderSDF:
		key.Reference.SDF = &signerplugin.SDFKeyReference{
			DeviceRef: descriptor.SDF.DeviceRef, KeyIndex: descriptor.SDF.KeyIndex, CredentialRef: descriptor.SDF.CredentialRef,
		}
	case ProviderRemote:
		key.Reference.Remote = &signerplugin.RemoteKeyReference{
			Endpoint: descriptor.Remote.Endpoint, Handle: descriptor.Remote.Handle, CredentialRef: descriptor.Remote.CredentialRef,
		}
	default:
		return signerplugin.Key{}, fmt.Errorf("%w: %q", ErrUnsupportedProvider, descriptor.Provider)
	}
	if err := signerplugin.ValidateKey(key); err != nil {
		return signerplugin.Key{}, err
	}
	if err := signerplugin.ValidateBindingForInfo(key.Binding, info); err != nil {
		return signerplugin.Key{}, err
	}
	return key, nil
}

func normalizedPluginInfo(info signerplugin.GetInfoResponse) signerplugin.GetInfoResponse {
	info.Capabilities = append([]string(nil), info.Capabilities...)
	info.Algorithms = append([]signerplugin.AlgorithmCapability(nil), info.Algorithms...)
	sort.Strings(info.Capabilities)
	sort.Slice(info.Algorithms, func(i, j int) bool {
		left := info.Algorithms[i]
		right := info.Algorithms[j]
		return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s", left.CryptoSuite, left.Algorithm, left.PublicKeyEncoding, left.SignatureEncoding, left.SM2UserID) <
			fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s", right.CryptoSuite, right.Algorithm, right.PublicKeyEncoding, right.SignatureEncoding, right.SM2UserID)
	})
	return info
}

func safePluginError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if signerplugin.IsRPCCanceled(err) {
		return fmt.Errorf("signer plugin %s: %w", operation, context.Canceled)
	}
	if signerplugin.IsRPCDeadlineExceeded(err) {
		return fmt.Errorf("signer plugin %s: %w", operation, context.DeadlineExceeded)
	}
	if signerplugin.IsPermanentRPC(err) {
		return fmt.Errorf("signer plugin %s failed permanently", operation)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("signer plugin %s: %w", operation, err)
	}
	return fmt.Errorf("signer plugin %s failed", operation)
}

func isExternalSignerProvider(provider string) bool {
	switch provider {
	case ProviderRemote, ProviderPKCS11, ProviderSDF:
		return true
	default:
		return false
	}
}
