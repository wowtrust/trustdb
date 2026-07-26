package sdfsigner

import (
	"context"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm4"
	"github.com/wowtrust/trustdb/v2/sdk/signerplugin"
)

func TestNewFailsClosedWhenAdapterMissesCapability(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(t)
	backend.capabilities &^= CapabilitySM4KEKImport
	_, err := New(context.Background(), testConfig(), backend)
	requireProviderCode(t, err, signerplugin.ErrorUnsupported)
}

func TestSigningOnlyConfigurationDoesNotRequireKEKCapabilities(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(t)
	backend.capabilities = SigningCapabilities
	config := testConfig()
	config.RequiredCapabilities = SigningCapabilities
	config.KEKID = ""
	config.KEKIndex = 0
	plugin, err := New(context.Background(), config, backend)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer plugin.Close()
	if _, err := plugin.PublicKey(context.Background(), testKey()); err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}
	_, err = plugin.Random(context.Background(), 32)
	requireProviderCode(t, err, signerplugin.ErrorUnsupported)
	_, _, err = plugin.GenerateSM4Session(context.Background())
	requireProviderCode(t, err, signerplugin.ErrorUnsupported)
}

func TestPluginConcurrentSM2SigningUsesIsolatedSessions(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(t)
	plugin := newTestPlugin(t, backend)
	key := testKey()
	publicKey, err := plugin.PublicKey(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}

	const operations = 32
	start := make(chan struct{})
	var failures atomic.Int32
	var wait sync.WaitGroup
	wait.Add(operations)
	for i := 0; i < operations; i++ {
		go func(index int) {
			defer wait.Done()
			<-start
			message := []byte(fmt.Sprintf("message-%d", index))
			signature, signErr := plugin.Sign(context.Background(), key, message)
			public, parseErr := sm2.NewPublicKey(publicKey)
			if signErr != nil || parseErr != nil ||
				!sm2.VerifyASN1WithSM2(public, []byte(signerplugin.SM2DefaultUserID), message, signature) {
				failures.Add(1)
			}
		}(i)
	}
	close(start)
	wait.Wait()
	if failures.Load() != 0 {
		t.Fatalf("concurrent sign failures = %d", failures.Load())
	}
	if got := backend.signCalls.Load(); got != operations {
		t.Fatalf("SignSM2 calls = %d, want %d", got, operations)
	}
	if got := backend.maxSessions.Load(); got < 2 {
		t.Fatalf("maximum concurrent sessions = %d, want at least 2", got)
	}
}

func TestPluginDoesNotReplayAmbiguousSignFailure(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(t)
	plugin := newTestPlugin(t, backend)
	key := testKey()
	if _, err := plugin.PublicKey(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	backend.setSignError(newFault(faultUnavailable))
	_, err := plugin.Sign(context.Background(), key, []byte("ambiguous"))
	requireProviderCode(t, err, signerplugin.ErrorUnavailable)
	if got := backend.signCalls.Load(); got != 1 {
		t.Fatalf("SignSM2 calls after failure = %d, want exactly 1", got)
	}
}

func TestPluginSignsExactSidecarPreparedSM2Digest(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(t)
	plugin := newTestPlugin(t, backend)
	key := testKey()
	publicKey, err := plugin.PublicKey(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("complete TrustDB message")
	if _, err := plugin.Sign(context.Background(), key, message); err != nil {
		t.Fatal(err)
	}
	public, err := sm2.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := sm2.NewHashWithUserID(public, []byte(signerplugin.SM2DefaultUserID))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = hasher.Write(message)
	expected := hasher.Sum(nil)
	backend.mu.Lock()
	got := append([]byte(nil), backend.lastDigest...)
	backend.mu.Unlock()
	if string(got) != string(expected) {
		t.Fatalf("adapter digest = %x, want %x", got, expected)
	}
}

func TestPluginRejectsDeviceAndKeyIdentityDrift(t *testing.T) {
	t.Parallel()
	t.Run("device", func(t *testing.T) {
		backend := newFakeBackend(t)
		plugin := newTestPlugin(t, backend)
		backend.mu.Lock()
		backend.identity.Serial = "serial-replacement"
		backend.mu.Unlock()
		requireProviderCode(t, plugin.Health(context.Background()), signerplugin.ErrorFailedPrecondition)
	})
	t.Run("key", func(t *testing.T) {
		backend := newFakeBackend(t)
		plugin := newTestPlugin(t, backend)
		key := testKey()
		if _, err := plugin.PublicKey(context.Background(), key); err != nil {
			t.Fatal(err)
		}
		backend.rotate(t)
		_, err := plugin.Sign(context.Background(), key, []byte("must fail"))
		requireProviderCode(t, err, signerplugin.ErrorFailedPrecondition)
		if got := backend.signCalls.Load(); got != 0 {
			t.Fatalf("replacement key signed %d times", got)
		}
	})
}

func TestPluginRequiresPublicKeyAcceptanceBeforeSigning(t *testing.T) {
	t.Parallel()
	plugin := newTestPlugin(t, newFakeBackend(t))
	_, err := plugin.Sign(context.Background(), testKey(), []byte("message"))
	requireProviderCode(t, err, signerplugin.ErrorFailedPrecondition)
}

func TestPluginRandomAndSM4KEKContract(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(t)
	plugin := newTestPlugin(t, backend)
	random, err := plugin.Random(context.Background(), 64)
	if err != nil || len(random) != 64 {
		t.Fatalf("Random() = %d bytes, %v", len(random), err)
	}
	wrapped, generated, err := plugin.GenerateSM4Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer generated.Close()
	if wrapped.KEKID != "backup-kek-v1" || wrapped.KEKIndex != 11 || len(wrapped.Wrapped) == 0 {
		t.Fatalf("wrapped key metadata = %+v", wrapped)
	}
	if wrapped.Device != backend.identity {
		t.Fatalf("wrapped device identity = %+v", wrapped.Device)
	}
	iv := []byte("0123456789abcdef")
	plaintext := []byte("block-0000000001block-0000000002")
	ciphertext, err := generated.EncryptCBC(context.Background(), iv, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := generated.MAC(context.Background(), iv, ciphertext)
	if err != nil || len(mac) != SM4BlockBytes {
		t.Fatalf("MAC() = %x, %v", mac, err)
	}
	if err := generated.Close(); err != nil {
		t.Fatal(err)
	}
	imported, err := plugin.ImportSM4Session(context.Background(), wrapped)
	if err != nil {
		t.Fatal(err)
	}
	defer imported.Close()
	roundTrip, err := imported.DecryptCBC(context.Background(), iv, ciphertext)
	if err != nil || string(roundTrip) != string(plaintext) {
		t.Fatalf("DecryptCBC() = %q, %v", roundTrip, err)
	}
	if backend.generateCalls.Load() != 1 || backend.importCalls.Load() != 1 {
		t.Fatal("KEK operations were unexpectedly repeated")
	}
	if backend.destroyCalls.Load() != 1 {
		t.Fatal("generated session key was not destroyed exactly once")
	}
}

func TestWrappedSM4KeyRestoresOnlyToSameDeviceAndKEK(t *testing.T) {
	t.Parallel()
	firstBackend := newFakeBackend(t)
	first, err := New(context.Background(), testConfig(), firstBackend)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, generated, err := first.GenerateSM4Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	iv := []byte("0123456789abcdef")
	plaintext := []byte("block-0000000001")
	ciphertext, err := generated.EncryptCBC(context.Background(), iv, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if err := generated.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	secondBackend := newFakeBackend(t)
	second, err := New(context.Background(), testConfig(), secondBackend)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	restored, err := second.ImportSM4Session(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("ImportSM4Session() after process restart error = %v", err)
	}
	roundTrip, err := restored.DecryptCBC(context.Background(), iv, ciphertext)
	if err != nil || string(roundTrip) != string(plaintext) {
		t.Fatalf("restored DecryptCBC() = %q, %v", roundTrip, err)
	}
	if err := restored.Close(); err != nil {
		t.Fatal(err)
	}

	changedDeviceBackend := newFakeBackend(t)
	changedDeviceBackend.identity.Serial = "replacement-serial"
	changedDevice, err := New(context.Background(), testConfig(), changedDeviceBackend)
	if err != nil {
		t.Fatal(err)
	}
	defer changedDevice.Close()
	if _, err := changedDevice.ImportSM4Session(context.Background(), wrapped); err == nil {
		t.Fatal("restore accepted a replacement device")
	} else {
		requireProviderCode(t, err, signerplugin.ErrorInvalidArgument)
	}

	changedKEKConfig := testConfig()
	changedKEKConfig.KEKID = "backup-kek-v2"
	changedKEK, err := New(context.Background(), changedKEKConfig, newFakeBackend(t))
	if err != nil {
		t.Fatal(err)
	}
	defer changedKEK.Close()
	if _, err := changedKEK.ImportSM4Session(context.Background(), wrapped); err == nil {
		t.Fatal("restore accepted a different KEK identity")
	} else {
		requireProviderCode(t, err, signerplugin.ErrorInvalidArgument)
	}
}

func TestSM4SessionCloseContextBoundsStuckDestroy(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(t)
	block := make(chan struct{})
	backend.destroyBlock = block
	plugin := newTestPlugin(t, backend)
	_, session, err := plugin.GenerateSM4Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := session.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseContext() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("CloseContext() blocked for %s", elapsed)
	}
	close(block)
	deadline := time.Now().Add(time.Second)
	for backend.destroyCalls.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if backend.destroyCalls.Load() != 1 {
		t.Fatal("timed-out key cleanup did not finish after adapter recovery")
	}
}

func TestPluginRejectsDescriptorReferenceDrift(t *testing.T) {
	t.Parallel()
	plugin := newTestPlugin(t, newFakeBackend(t))
	tests := []func(*signerplugin.SDFKeyReference){
		func(reference *signerplugin.SDFKeyReference) { reference.DeviceRef = "another-device" },
		func(reference *signerplugin.SDFKeyReference) { reference.CredentialRef = "another-credential" },
		func(reference *signerplugin.SDFKeyReference) { reference.KeyIndex = 0 },
	}
	for _, mutate := range tests {
		key := testKey()
		mutate(key.Reference.SDF)
		_, err := plugin.PublicKey(context.Background(), key)
		requireProviderCode(t, err, signerplugin.ErrorInvalidArgument)
	}
}

func TestPluginRedactsCredentialsDeviceAndNativeErrors(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(t)
	backend.publicErr = errors.New("vendor error pin=846295 device=sdf-production key=7")
	plugin := newTestPlugin(t, backend)
	_, err := plugin.PublicKey(context.Background(), testKey())
	requireProviderCode(t, err, signerplugin.ErrorInternal)
	for _, forbidden := range []string{"846295", "sdf-production", "key=7", "vendor error"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error %q disclosed %q", err, forbidden)
		}
	}
}

func TestFileCredentialSourceRejectsUnsafeFilesWithoutPathLeak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential-secret")
	if err := os.WriteFile(path, []byte("846295\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := NewFileCredentialSource(path)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := source.Read(context.Background())
	if runtime.GOOS == "windows" {
		if err == nil {
			t.Fatal("Windows accepted a credential without qualified DACL validation")
		}
		return
	}
	if err != nil || string(credential) != "846295" {
		t.Fatalf("Read() = %q, %v", credential, err)
	}
	clear(credential)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = source.Read(context.Background())
	if err == nil || strings.Contains(err.Error(), path) {
		t.Fatalf("unsafe credential result = %v", err)
	}
}

func testConfig() Config {
	return Config{
		PluginID:             DefaultPluginID,
		DeviceRef:            "sdf-production",
		CredentialRef:        "receipt-operator",
		Credential:           staticCredentialSource("846295"),
		KEKID:                "backup-kek-v1",
		KEKIndex:             11,
		RequiredCapabilities: AllCapabilities,
		MaxConcurrentSigns:   16,
	}
}

func testKey() signerplugin.Key {
	return signerplugin.Key{
		Binding: signerplugin.Binding{
			ProtocolVersion:   signerplugin.ProtocolVersion,
			PluginID:          DefaultPluginID,
			ProviderKind:      signerplugin.ProviderSDF,
			CryptoSuite:       signerplugin.SuiteCNSMV1,
			Algorithm:         signerplugin.AlgorithmSM2SM3,
			PublicKeyEncoding: signerplugin.SM2PublicKeyEncoding,
			SignatureEncoding: signerplugin.SM2SignatureEncoding,
			KeyID:             "receipt-sm2-v1",
			SM2UserID:         signerplugin.SM2DefaultUserID,
		},
		Reference: signerplugin.KeyReference{
			SDF: &signerplugin.SDFKeyReference{
				DeviceRef:     "sdf-production",
				KeyIndex:      7,
				CredentialRef: "receipt-operator",
			},
		},
	}
}

func newTestPlugin(t *testing.T, backend *fakeBackend) *Plugin {
	t.Helper()
	plugin, err := New(context.Background(), testConfig(), backend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plugin.Close() })
	return plugin
}

func requireProviderCode(t *testing.T, err error, code signerplugin.ErrorCode) {
	t.Helper()
	var providerErr *signerplugin.ProviderError
	if err == nil || !errors.As(err, &providerErr) || providerErr.Code != code {
		t.Fatalf("error = %v, want provider code %s", err, code)
	}
}

type fakeBackend struct {
	mu           sync.Mutex
	identity     DeviceIdentity
	capabilities Capability
	available    bool
	closed       bool
	privateKey   *sm2.PrivateKey
	publicKey    []byte
	publicErr    error
	signErr      error
	lastDigest   []byte

	signCalls      atomic.Int32
	generateCalls  atomic.Int32
	importCalls    atomic.Int32
	destroyCalls   atomic.Int32
	activeSessions atomic.Int32
	maxSessions    atomic.Int32
	destroyBlock   <-chan struct{}
}

func newFakeBackend(t *testing.T) *fakeBackend {
	t.Helper()
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeBackend{
		identity: DeviceIdentity{
			AdapterID: "fake-sdf", AdapterVersion: "1.0.0", DeviceID: "sdf-production",
			Serial: "serial-1", Firmware: "firmware-1",
		},
		capabilities: AllCapabilities,
		available:    true,
		privateKey:   privateKey,
		publicKey:    elliptic.Marshal(sm2.P256(), privateKey.X, privateKey.Y),
	}
}

func (b *fakeBackend) Discover(ctx context.Context, reference string) (Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || !b.available || reference != "sdf-production" {
		return nil, newFault(faultUnavailable)
	}
	return &fakeDevice{backend: b}, nil
}

func (b *fakeBackend) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return nil
}

func (b *fakeBackend) setSignError(err error) {
	b.mu.Lock()
	b.signErr = err
	b.mu.Unlock()
}

func (b *fakeBackend) rotate(t *testing.T) {
	t.Helper()
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.privateKey = privateKey
	b.publicKey = elliptic.Marshal(sm2.P256(), privateKey.X, privateKey.Y)
	b.mu.Unlock()
}

type fakeDevice struct {
	backend *fakeBackend
}

func (d *fakeDevice) Identity(ctx context.Context) (DeviceIdentity, error) {
	if err := ctx.Err(); err != nil {
		return DeviceIdentity{}, err
	}
	d.backend.mu.Lock()
	defer d.backend.mu.Unlock()
	if !d.backend.available {
		return DeviceIdentity{}, newFault(faultUnavailable)
	}
	return d.backend.identity, nil
}

func (d *fakeDevice) Capabilities(ctx context.Context) (Capability, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	d.backend.mu.Lock()
	defer d.backend.mu.Unlock()
	return d.backend.capabilities, nil
}

func (d *fakeDevice) OpenSession(ctx context.Context) (Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	active := d.backend.activeSessions.Add(1)
	for {
		maximum := d.backend.maxSessions.Load()
		if active <= maximum || d.backend.maxSessions.CompareAndSwap(maximum, active) {
			break
		}
	}
	return &fakeSession{backend: d.backend}, nil
}

type fakeSession struct {
	backend *fakeBackend
	closed  atomic.Bool

	keyMu      sync.Mutex
	nextHandle uint64
	keys       map[uint64][]byte
}

func (s *fakeSession) Health(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	if !s.backend.available {
		return newFault(faultUnavailable)
	}
	return nil
}

func (s *fakeSession) PublicKey(ctx context.Context, keyIndex uint32, credential []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	if s.backend.publicErr != nil {
		return nil, s.backend.publicErr
	}
	if keyIndex != 7 && keyIndex != 8 {
		return nil, newFault(faultNotFound)
	}
	if string(credential) != "846295" {
		return nil, newFault(faultAuthentication)
	}
	return append([]byte(nil), s.backend.publicKey...), nil
}

func (s *fakeSession) SignSM2Digest(ctx context.Context, keyIndex uint32, credential, digest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.backend.signCalls.Add(1)
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	if s.backend.signErr != nil {
		return nil, s.backend.signErr
	}
	if (keyIndex != 7 && keyIndex != 8) || string(credential) != "846295" || len(digest) != 32 {
		return nil, newFault(faultInvalid)
	}
	s.backend.lastDigest = append(s.backend.lastDigest[:0], digest...)
	signature, err := sm2.SignASN1(rand.Reader, s.backend.privateKey, digest, nil)
	if err != nil {
		return nil, newFault(faultInternal)
	}
	var parsed struct {
		R *big.Int
		S *big.Int
	}
	if _, err := asn1.Unmarshal(signature, &parsed); err != nil {
		return nil, newFault(faultInternal)
	}
	raw := make([]byte, 64)
	parsed.R.FillBytes(raw[:32])
	parsed.S.FillBytes(raw[32:])
	time.Sleep(time.Millisecond)
	return raw, nil
}

func (s *fakeSession) Random(ctx context.Context, length uint32) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]byte, length)
	if _, err := rand.Read(out); err != nil {
		return nil, newFault(faultInternal)
	}
	return out, nil
}

func (s *fakeSession) GenerateSM4KeyWithKEK(ctx context.Context, kekIndex uint32, credential []byte) ([]byte, SessionKeyHandle, error) {
	if err := ctx.Err(); err != nil {
		return nil, SessionKeyHandle{}, err
	}
	s.backend.generateCalls.Add(1)
	if kekIndex != 11 || string(credential) != "846295" {
		return nil, SessionKeyHandle{}, newFault(faultInvalid)
	}
	key := make([]byte, SM4KeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, SessionKeyHandle{}, newFault(faultInternal)
	}
	handle := s.storeKey(key)
	wrapped := make([]byte, 1+len(key))
	wrapped[0] = 0x53
	for i := range key {
		wrapped[i+1] = key[i] ^ 0xa5
	}
	clear(key)
	return wrapped, handle, nil
}

func (s *fakeSession) ImportSM4KeyWithKEK(ctx context.Context, kekIndex uint32, credential, wrapped []byte) (SessionKeyHandle, error) {
	if err := ctx.Err(); err != nil {
		return SessionKeyHandle{}, err
	}
	s.backend.importCalls.Add(1)
	if kekIndex != 11 || string(credential) != "846295" ||
		len(wrapped) != 1+SM4KeyBytes || wrapped[0] != 0x53 {
		return SessionKeyHandle{}, newFault(faultInvalid)
	}
	key := make([]byte, SM4KeyBytes)
	for i := range key {
		key[i] = wrapped[i+1] ^ 0xa5
	}
	handle := s.storeKey(key)
	clear(key)
	return handle, nil
}

func (s *fakeSession) EncryptSM4CBC(ctx context.Context, handle SessionKeyHandle, iv, plaintext []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	block, err := s.block(handle)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
	return out, nil
}

func (s *fakeSession) DecryptSM4CBC(ctx context.Context, handle SessionKeyHandle, iv, ciphertext []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	block, err := s.block(handle)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return out, nil
}

func (s *fakeSession) CalculateSM4MAC(ctx context.Context, handle SessionKeyHandle, iv, data []byte) ([]byte, error) {
	ciphertext, err := s.EncryptSM4CBC(ctx, handle, iv, data)
	if err != nil {
		return nil, err
	}
	mac := append([]byte(nil), ciphertext[len(ciphertext)-SM4BlockBytes:]...)
	clear(ciphertext)
	return mac, nil
}

func (s *fakeSession) DestroySessionKey(ctx context.Context, handle SessionKeyHandle) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.backend.mu.Lock()
	block := s.backend.destroyBlock
	s.backend.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	key, exists := s.keys[handle.value]
	if !exists {
		return newFault(faultPrecondition)
	}
	clear(key)
	delete(s.keys, handle.value)
	s.backend.destroyCalls.Add(1)
	return nil
}

func (s *fakeSession) storeKey(key []byte) SessionKeyHandle {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.keys == nil {
		s.keys = make(map[uint64][]byte)
	}
	s.nextHandle++
	s.keys[s.nextHandle] = append([]byte(nil), key...)
	return newSessionKeyHandle(s.nextHandle)
}

func (s *fakeSession) block(handle SessionKeyHandle) (cipher.Block, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	key, exists := s.keys[handle.value]
	if !exists {
		return nil, newFault(faultPrecondition)
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, newFault(faultInternal)
	}
	return block, nil
}

func (s *fakeSession) Close() error {
	if !s.closed.Swap(true) {
		s.backend.activeSessions.Add(-1)
	}
	return nil
}
