package keydescriptor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/sdk/signerplugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestPluginSignerProviderSignsAndVerifiesLocally(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := providerDescriptor(publicKey, ProviderRemote)
	process := newFakePluginProcess(ProviderRemote, publicKey, func(message []byte) []byte {
		return ed25519.Sign(privateKey, message)
	})
	provider := testPluginProvider(t, ProviderRemote, func(context.Context, signerplugin.ProcessConfig) (signerPluginProcess, error) {
		return process, nil
	})
	resolver, err := NewResolver(SoftwareProvider{}, provider)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resolver.Close() })

	signer, err := resolver.ResolveSigner(context.Background(), descriptor, t.TempDir())
	if err != nil {
		t.Fatalf("ResolveSigner() error = %v", err)
	}
	message := []byte("plugin-bound signing input")
	signature, err := trustcrypto.Sign(context.Background(), cryptosuite.INTLV1, signer, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if !ed25519.Verify(publicKey, message, signature.Signature) {
		t.Fatal("plugin signature did not verify")
	}
	if process.signCalls != 1 {
		t.Fatalf("plugin sign calls = %d, want 1", process.signCalls)
	}
}

func TestPluginSignerProviderRejectsDescriptorPublicKeyMismatch(t *testing.T) {
	t.Parallel()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := providerDescriptor(publicKey, ProviderRemote)
	process := newFakePluginProcess(ProviderRemote, otherPublicKey, nil)
	provider := testPluginProvider(t, ProviderRemote, func(context.Context, signerplugin.ProcessConfig) (signerPluginProcess, error) {
		return process, nil
	})
	if _, err := provider.ResolveSigner(context.Background(), descriptor, t.TempDir()); !errors.Is(err, ErrSignerPluginPublicKey) {
		t.Fatalf("ResolveSigner() error = %v, want ErrSignerPluginPublicKey", err)
	}
	if !process.closed {
		t.Fatal("public-key mismatch did not close plugin process")
	}
}

func TestPluginSignerProviderRejectsCorrectLengthInvalidSignature(t *testing.T) {
	t.Parallel()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := providerDescriptor(publicKey, ProviderRemote)
	process := newFakePluginProcess(ProviderRemote, publicKey, func([]byte) []byte {
		return make([]byte, ed25519.SignatureSize)
	})
	provider := testPluginProvider(t, ProviderRemote, func(context.Context, signerplugin.ProcessConfig) (signerPluginProcess, error) {
		return process, nil
	})
	signer, err := provider.ResolveSigner(context.Background(), descriptor, t.TempDir())
	if err != nil {
		t.Fatalf("ResolveSigner() error = %v", err)
	}
	if _, err := signer.Sign(context.Background(), []byte("must not persist")); !errors.Is(err, ErrSignerPluginBadSignature) {
		t.Fatalf("Sign() error = %v, want ErrSignerPluginBadSignature", err)
	}
	if !process.closed {
		t.Fatal("invalid signature did not close plugin process")
	}
	if _, err := signer.Sign(context.Background(), []byte("no restart after compromise")); !errors.Is(err, ErrSignerPluginBadSignature) {
		t.Fatalf("second Sign() error = %v, want persistent compromise error", err)
	}
}

func TestPluginSignerProviderDoesNotTreatCallerCancellationAsCompromise(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := providerDescriptor(publicKey, ProviderRemote)
	ctx, cancel := context.WithCancel(context.Background())
	process := newFakePluginProcess(ProviderRemote, publicKey, func(message []byte) []byte {
		cancel()
		return ed25519.Sign(privateKey, message)
	})
	provider := testPluginProvider(t, ProviderRemote, func(context.Context, signerplugin.ProcessConfig) (signerPluginProcess, error) {
		return process, nil
	})
	signer, err := provider.ResolveSigner(context.Background(), descriptor, t.TempDir())
	if err != nil {
		t.Fatalf("ResolveSigner() error = %v", err)
	}
	if _, err := signer.Sign(ctx, []byte("canceled after provider response")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sign() error = %v, want context.Canceled", err)
	}
	process.setSign(func(message []byte) []byte { return ed25519.Sign(privateKey, message) })
	if _, err := signer.Sign(context.Background(), []byte("provider remains usable")); err != nil {
		t.Fatalf("Sign() after caller cancellation error = %v", err)
	}
}

func TestPluginSignerProviderTreatsProtocolViolationAsPermanentCompromise(t *testing.T) {
	t.Parallel()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := providerDescriptor(publicKey, ProviderRemote)
	process := newFakePluginProcess(ProviderRemote, publicKey, nil)
	process.signErr = signerplugin.ErrProtocolViolation
	provider := testPluginProvider(t, ProviderRemote, func(context.Context, signerplugin.ProcessConfig) (signerPluginProcess, error) {
		return process, nil
	})
	signer, err := provider.ResolveSigner(context.Background(), descriptor, t.TempDir())
	if err != nil {
		t.Fatalf("ResolveSigner() error = %v", err)
	}
	if _, err := signer.Sign(context.Background(), []byte("invalid response")); !errors.Is(err, ErrSignerPluginProtocol) {
		t.Fatalf("Sign() error = %v, want ErrSignerPluginProtocol", err)
	}
	if !process.isClosed() {
		t.Fatal("protocol violation did not close plugin process")
	}
	if _, err := signer.Sign(context.Background(), []byte("no restart after protocol violation")); !errors.Is(err, ErrSignerPluginProtocol) {
		t.Fatalf("second Sign() error = %v, want persistent protocol error", err)
	}
}

func TestPluginSignerProviderInvalidatesProcessAfterDeadline(t *testing.T) {
	t.Parallel()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := providerDescriptor(publicKey, ProviderRemote)
	process := newFakePluginProcess(ProviderRemote, publicKey, nil)
	process.signErr = status.Error(codes.DeadlineExceeded, "plugin deadline")
	provider := testPluginProvider(t, ProviderRemote, func(context.Context, signerplugin.ProcessConfig) (signerPluginProcess, error) {
		return process, nil
	})
	signer, err := provider.ResolveSigner(context.Background(), descriptor, t.TempDir())
	if err != nil {
		t.Fatalf("ResolveSigner() error = %v", err)
	}
	if _, err := signer.Sign(context.Background(), []byte("deadline")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Sign() error = %v, want DeadlineExceeded", err)
	}
	if !process.isClosed() {
		t.Fatal("deadline did not invalidate plugin process")
	}
	if _, err := signer.Sign(context.Background(), []byte("during backoff")); !errors.Is(err, ErrSignerPluginBackoff) {
		t.Fatalf("second Sign() error = %v, want ErrSignerPluginBackoff", err)
	}
}

func TestPluginSignerProviderDoesNotInvalidateForLocalCapacityDeadline(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := providerDescriptor(publicKey, ProviderRemote)
	process := newFakePluginProcess(ProviderRemote, publicKey, nil)
	process.signErr = fmt.Errorf("%w: %w", signerplugin.ErrSignCapacityWait, context.DeadlineExceeded)
	provider := testPluginProvider(t, ProviderRemote, func(context.Context, signerplugin.ProcessConfig) (signerPluginProcess, error) {
		return process, nil
	})
	signer, err := provider.ResolveSigner(context.Background(), descriptor, t.TempDir())
	if err != nil {
		t.Fatalf("ResolveSigner() error = %v", err)
	}
	if _, err := signer.Sign(context.Background(), []byte("capacity timeout")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Sign() error = %v, want DeadlineExceeded", err)
	}
	if process.isClosed() {
		t.Fatal("local sign-capacity timeout invalidated the healthy plugin process")
	}
	process.setSignError(nil)
	process.setSign(func(message []byte) []byte { return ed25519.Sign(privateKey, message) })
	if _, err := signer.Sign(context.Background(), []byte("provider remains usable")); err != nil {
		t.Fatalf("Sign() after capacity timeout error = %v", err)
	}
}

func TestPluginSignerProviderPreservesRPCCancellationWithoutCompromise(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := providerDescriptor(publicKey, ProviderRemote)
	process := newFakePluginProcess(ProviderRemote, publicKey, nil)
	process.signErr = status.Error(codes.Canceled, "plugin canceled")
	provider := testPluginProvider(t, ProviderRemote, func(context.Context, signerplugin.ProcessConfig) (signerPluginProcess, error) {
		return process, nil
	})
	signer, err := provider.ResolveSigner(context.Background(), descriptor, t.TempDir())
	if err != nil {
		t.Fatalf("ResolveSigner() error = %v", err)
	}
	if _, err := signer.Sign(context.Background(), []byte("canceled rpc")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sign() error = %v, want context.Canceled", err)
	}
	if process.isClosed() {
		t.Fatal("canceled RPC compromised or invalidated the plugin process")
	}
	process.setSignError(nil)
	process.setSign(func(message []byte) []byte { return ed25519.Sign(privateKey, message) })
	if _, err := signer.Sign(context.Background(), []byte("provider remains usable")); err != nil {
		t.Fatalf("Sign() after canceled RPC error = %v", err)
	}
}

func TestPluginSignerProviderTreatsDeterministicStartFailuresAsPermanent(t *testing.T) {
	t.Parallel()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := providerDescriptor(publicKey, ProviderRemote)
	tests := map[string]error{
		"handshake protocol": fmt.Errorf("decode handshake: %w", signerplugin.ErrProtocolViolation),
		"get info status":    status.Error(codes.Unimplemented, "unsupported protocol"),
	}
	for name, startErr := range tests {
		startErr := startErr
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var calls int
			provider := testPluginProvider(t, ProviderRemote, func(context.Context, signerplugin.ProcessConfig) (signerPluginProcess, error) {
				calls++
				return nil, startErr
			})
			if _, err := provider.ResolveSigner(context.Background(), descriptor, t.TempDir()); !errors.Is(err, ErrSignerPluginProtocol) {
				t.Fatalf("ResolveSigner() error = %v, want ErrSignerPluginProtocol", err)
			}
			if _, err := provider.ResolveSigner(context.Background(), descriptor, t.TempDir()); !errors.Is(err, ErrSignerPluginProtocol) {
				t.Fatalf("second ResolveSigner() error = %v, want persistent ErrSignerPluginProtocol", err)
			}
			if calls != 1 {
				t.Fatalf("factory calls = %d, want 1", calls)
			}
		})
	}
}

func TestPluginSignerProviderRejectsIdentityDriftAfterRestart(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := providerDescriptor(publicKey, ProviderRemote)
	first := newFakePluginProcess(ProviderRemote, publicKey, func(message []byte) []byte {
		return ed25519.Sign(privateKey, message)
	})
	second := newFakePluginProcess(ProviderRemote, publicKey, func(message []byte) []byte {
		return ed25519.Sign(privateKey, message)
	})
	second.info.PluginID = "different-plugin"
	processes := []signerPluginProcess{first, second}
	var factoryMu sync.Mutex
	provider := testPluginProvider(t, ProviderRemote, func(context.Context, signerplugin.ProcessConfig) (signerPluginProcess, error) {
		factoryMu.Lock()
		defer factoryMu.Unlock()
		if len(processes) == 0 {
			return nil, errors.New("no process")
		}
		process := processes[0]
		processes = processes[1:]
		return process, nil
	})
	signer, err := provider.ResolveSigner(context.Background(), descriptor, t.TempDir())
	if err != nil {
		t.Fatalf("ResolveSigner() error = %v", err)
	}
	first.exit()
	if _, err := signer.Sign(context.Background(), []byte("during backoff")); !errors.Is(err, ErrSignerPluginBackoff) {
		t.Fatalf("Sign() during backoff error = %v, want ErrSignerPluginBackoff", err)
	}
	time.Sleep(initialPluginRestartBackoff + 20*time.Millisecond)
	if _, err := signer.Sign(context.Background(), []byte("after restart")); !errors.Is(err, ErrSignerPluginIdentity) {
		t.Fatalf("Sign() after identity drift error = %v, want ErrSignerPluginIdentity", err)
	}
}

func TestPluginSignerProviderBackoffGrowsUntilVerifiedSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := providerDescriptor(publicKey, ProviderRemote)
	first := newFakePluginProcess(ProviderRemote, publicKey, nil)
	first.signErr = status.Error(codes.Unavailable, "crash one")
	second := newFakePluginProcess(ProviderRemote, publicKey, nil)
	second.signErr = status.Error(codes.Unavailable, "crash two")
	third := newFakePluginProcess(ProviderRemote, publicKey, func(message []byte) []byte {
		return ed25519.Sign(privateKey, message)
	})
	processes := []signerPluginProcess{first, second, third}
	provider := testPluginProvider(t, ProviderRemote, func(context.Context, signerplugin.ProcessConfig) (signerPluginProcess, error) {
		process := processes[0]
		processes = processes[1:]
		return process, nil
	})
	signer, err := provider.ResolveSigner(context.Background(), descriptor, t.TempDir())
	if err != nil {
		t.Fatalf("ResolveSigner() error = %v", err)
	}
	if _, err := signer.Sign(context.Background(), []byte("first crash")); err == nil {
		t.Fatal("first crashing Sign() error = nil")
	}
	time.Sleep(initialPluginRestartBackoff + 20*time.Millisecond)
	if _, err := signer.Sign(context.Background(), []byte("second crash")); err == nil {
		t.Fatal("second crashing Sign() error = nil")
	}
	provider.mu.Lock()
	backoff := provider.restartBackoff
	provider.mu.Unlock()
	if backoff != 2*initialPluginRestartBackoff {
		t.Fatalf("restart backoff = %v, want %v", backoff, 2*initialPluginRestartBackoff)
	}
	time.Sleep(2*initialPluginRestartBackoff + 20*time.Millisecond)
	if _, err := signer.Sign(context.Background(), []byte("verified recovery")); err != nil {
		t.Fatalf("recovered Sign() error = %v", err)
	}
	provider.mu.Lock()
	backoff = provider.restartBackoff
	provider.mu.Unlock()
	if backoff != 0 {
		t.Fatalf("restart backoff after verified signature = %v, want 0", backoff)
	}
}

func TestPluginSignerProviderTreatsRebindProtocolViolationAsPermanent(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := providerDescriptor(publicKey, ProviderRemote)
	first := newFakePluginProcess(ProviderRemote, publicKey, func(message []byte) []byte {
		return ed25519.Sign(privateKey, message)
	})
	second := newFakePluginProcess(ProviderRemote, publicKey, nil)
	second.publicKeyErr = signerplugin.ErrProtocolViolation
	processes := []signerPluginProcess{first, second}
	provider := testPluginProvider(t, ProviderRemote, func(context.Context, signerplugin.ProcessConfig) (signerPluginProcess, error) {
		process := processes[0]
		processes = processes[1:]
		return process, nil
	})
	signer, err := provider.ResolveSigner(context.Background(), descriptor, t.TempDir())
	if err != nil {
		t.Fatalf("ResolveSigner() error = %v", err)
	}
	first.exit()
	if _, err := signer.Sign(context.Background(), []byte("during backoff")); !errors.Is(err, ErrSignerPluginBackoff) {
		t.Fatalf("Sign() during backoff error = %v, want ErrSignerPluginBackoff", err)
	}
	time.Sleep(initialPluginRestartBackoff + 20*time.Millisecond)
	if _, err := signer.Sign(context.Background(), []byte("rebind violation")); !errors.Is(err, ErrSignerPluginProtocol) {
		t.Fatalf("Sign() after rebind violation error = %v, want ErrSignerPluginProtocol", err)
	}
	if _, err := signer.Sign(context.Background(), []byte("persistent violation")); !errors.Is(err, ErrSignerPluginProtocol) {
		t.Fatalf("second Sign() error = %v, want persistent protocol error", err)
	}
}

func TestPluginSignerProviderSupportsKnownSuiteForLifecycleOnly(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := trustcrypto.GenerateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	softwareSigner, err := trustcrypto.NewSM2Signer("sm2-registry", privateKey)
	clear(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	suite, err := cryptosuite.RequireKnown(cryptosuite.CNSMV1)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := Descriptor{
		SchemaVersion: SchemaV1,
		Kind:          KindSigner,
		Provider:      ProviderRemote,
		CryptoSuite:   suite.ID,
		KeyID:         "sm2-registry",
		Algorithm:     suite.Signature.Algorithm,
		SM2UserID:     suite.Signature.SM2UserID,
		PublicKey: PublicKeyMaterial{
			Encoding: suite.Signature.PublicKeyEncoding,
			Bytes:    append([]byte(nil), publicKey...),
		},
		Remote: &RemoteKeyReference{
			Endpoint:      "https://kms.example.test",
			Handle:        "sm2-registry",
			CredentialRef: "env:KMS_TOKEN",
		},
	}
	process := newFakePluginProcess(ProviderRemote, publicKey, func(message []byte) []byte {
		signature, err := softwareSigner.Sign(context.Background(), message)
		if err != nil {
			t.Fatalf("software SM2 Sign() error = %v", err)
		}
		return signature.Signature
	})
	process.info.Algorithms = []signerplugin.AlgorithmCapability{{
		CryptoSuite:       signerplugin.SuiteCNSMV1,
		Algorithm:         signerplugin.AlgorithmSM2SM3,
		PublicKeyEncoding: signerplugin.SM2PublicKeyEncoding,
		SignatureEncoding: signerplugin.SM2SignatureEncoding,
		SM2UserID:         signerplugin.SM2DefaultUserID,
	}}
	provider := testPluginProvider(t, ProviderRemote, func(context.Context, signerplugin.ProcessConfig) (signerPluginProcess, error) {
		return process, nil
	})
	resolver, err := NewResolver(provider)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resolver.Close() })
	if _, err := resolver.ResolveSigner(context.Background(), descriptor, t.TempDir()); err == nil {
		t.Fatal("ResolveSigner() enabled reserved CN_SM_V1 production signing")
	}
	signer, err := resolver.ResolveLifecycleSigner(context.Background(), descriptor, t.TempDir())
	if err != nil {
		t.Fatalf("ResolveLifecycleSigner() error = %v", err)
	}
	message := []byte("registry lifecycle event")
	signature, err := signer.Sign(context.Background(), message)
	if err != nil {
		t.Fatalf("lifecycle Sign() error = %v", err)
	}
	publicDescriptor, err := descriptor.PublicKeyDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if err := trustcrypto.VerifySignatureForSuite(context.Background(), suite.ID, publicDescriptor, message, signature); err != nil {
		t.Fatalf("lifecycle signature verification error = %v", err)
	}
}

func testPluginProvider(t *testing.T, provider string, factory signerPluginProcessFactory) *PluginSignerProvider {
	t.Helper()
	pluginProvider, err := newPluginSignerProvider(SignerPluginOptions{
		Provider:       provider,
		Command:        "test-signer-plugin",
		StartTimeout:   time.Second,
		RPCTimeout:     time.Second,
		MaxConcurrency: 4,
	}, factory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pluginProvider.Close() })
	return pluginProvider
}

type fakePluginProcess struct {
	info      signerplugin.GetInfoResponse
	publicKey []byte
	sign      func([]byte) []byte
	done      chan struct{}

	mu           sync.Mutex
	closed       bool
	signCalls    int
	signErr      error
	publicKeyErr error
}

func newFakePluginProcess(provider string, publicKey []byte, sign func([]byte) []byte) *fakePluginProcess {
	return &fakePluginProcess{
		info: signerplugin.GetInfoResponse{
			ProtocolVersion: signerplugin.ProtocolVersion,
			PluginID:        "test-plugin",
			ProviderKind:    provider,
			Capabilities: []string{
				signerplugin.CapabilityHealth,
				signerplugin.CapabilityPublicKey,
				signerplugin.CapabilitySign,
			},
			Algorithms: []signerplugin.AlgorithmCapability{{
				CryptoSuite:       signerplugin.SuiteINTLV1,
				Algorithm:         signerplugin.AlgorithmEd25519,
				PublicKeyEncoding: signerplugin.Ed25519PublicKeyEncoding,
				SignatureEncoding: signerplugin.Ed25519SignatureEncoding,
			}},
			MaxConcurrentSigns: 8,
		},
		publicKey: append([]byte(nil), publicKey...),
		sign:      sign,
		done:      make(chan struct{}),
	}
}

func (p *fakePluginProcess) Info() signerplugin.GetInfoResponse { return p.info }
func (p *fakePluginProcess) Done() <-chan struct{}              { return p.done }
func (p *fakePluginProcess) ExitError() (error, bool) {
	select {
	case <-p.done:
		return nil, true
	default:
		return nil, false
	}
}
func (p *fakePluginProcess) GetPublicKey(context.Context, signerplugin.Key) ([]byte, error) {
	if p.publicKeyErr != nil {
		return nil, p.publicKeyErr
	}
	return append([]byte(nil), p.publicKey...), nil
}
func (p *fakePluginProcess) Sign(_ context.Context, _ signerplugin.Key, message []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.signCalls++
	if p.signErr != nil {
		return nil, p.signErr
	}
	if p.sign == nil {
		return nil, errors.New("sign unavailable")
	}
	return append([]byte(nil), p.sign(message)...), nil
}
func (p *fakePluginProcess) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.exit()
	return nil
}
func (p *fakePluginProcess) exit() {
	select {
	case <-p.done:
	default:
		close(p.done)
	}
}

func (p *fakePluginProcess) setSign(sign func([]byte) []byte) {
	p.mu.Lock()
	p.sign = sign
	p.mu.Unlock()
}

func (p *fakePluginProcess) setSignError(err error) {
	p.mu.Lock()
	p.signErr = err
	p.mu.Unlock()
}

func (p *fakePluginProcess) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

var _ trustcrypto.Signer = (*pluginSigner)(nil)
var _ SignerProvider = (*PluginSignerProvider)(nil)
var _ io.Closer = (*PluginSignerProvider)(nil)
