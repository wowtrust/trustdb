package pkcs11signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/sdk/signerplugin"
)

func TestNewFailsFastWhenConfiguredMechanismCannotSign(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(t)
	backend.mechanisms = []Mechanism{{Type: 0x1057, Flags: 0}}
	_, err := New(context.Background(), testConfig(), backend)
	requireProviderCode(t, err, signerplugin.ErrorUnsupported)
}

func TestPluginConcurrentSigningUsesIsolatedSessions(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(t)
	plugin := newTestPlugin(t, backend, testConfig())
	key := testKey("pkcs11:id=%01;object=receipt-key;token=trustdb;type=private")
	publicKey, err := plugin.PublicKey(context.Background(), key)
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}
	if !ed25519.PublicKey(publicKey).Equal(backend.publicKey()) {
		t.Fatal("PublicKey() returned the wrong key")
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
			if signErr != nil || !ed25519.Verify(publicKey, message, signature) {
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
		t.Fatalf("token Sign calls = %d, want %d", got, operations)
	}
	if got := backend.maxSessions.Load(); got < 2 {
		t.Fatalf("maximum concurrent sessions = %d, want at least 2", got)
	}
}

func TestPluginDoesNotReplayAmbiguousSessionFailure(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(t)
	plugin := newTestPlugin(t, backend, testConfig())
	key := testKey("pkcs11:object=receipt-key;serial=serial-1;type=private")
	if _, err := plugin.PublicKey(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	backend.setSignError(newFault(faultUnavailable))
	if _, err := plugin.Sign(context.Background(), key, []byte("ambiguous")); err == nil {
		t.Fatal("Sign() succeeded during session loss")
	} else {
		requireProviderCode(t, err, signerplugin.ErrorUnavailable)
	}
	if got := backend.signCalls.Load(); got != 1 {
		t.Fatalf("token Sign calls after failure = %d, want exactly 1", got)
	}
	backend.setSignError(nil)
	if _, err := plugin.Sign(context.Background(), key, []byte("recovered")); err != nil {
		t.Fatalf("Sign() after a fresh session error = %v", err)
	}
	if got := backend.signCalls.Load(); got != 2 {
		t.Fatalf("token Sign calls after recovery = %d, want 2", got)
	}
}

func TestPluginRecoversAfterTokenRemovalButRejectsReplacement(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(t)
	config := testConfig()
	config.TokenURI = "pkcs11:token=trustdb"
	plugin := newTestPlugin(t, backend, config)

	backend.setAvailable(false)
	requireProviderCode(t, plugin.Health(context.Background()), signerplugin.ErrorUnavailable)
	backend.setAvailable(true)
	if err := plugin.Health(context.Background()); err != nil {
		t.Fatalf("Health() after token return error = %v", err)
	}

	backend.setIdentity(TokenIdentity{
		Label: "trustdb", Manufacturer: "fake", Model: "fake-v1", Serial: "serial-2",
	})
	requireProviderCode(t, plugin.Health(context.Background()), signerplugin.ErrorFailedPrecondition)
}

func TestPluginRejectsSameURIRotationUntilRestart(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(t)
	plugin := newTestPlugin(t, backend, testConfig())
	key := testKey("pkcs11:id=%01;token=trustdb;type=private")
	original, err := plugin.PublicKey(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	backend.rotate(t)
	if _, err := plugin.Sign(context.Background(), key, []byte("must not use replacement")); err == nil {
		t.Fatal("Sign() accepted a replacement key at the same URI")
	} else {
		requireProviderCode(t, err, signerplugin.ErrorFailedPrecondition)
	}
	if got := backend.signCalls.Load(); got != 0 {
		t.Fatalf("replacement key was used for %d signatures", got)
	}
	if _, err := plugin.PublicKey(context.Background(), key); err == nil {
		t.Fatal("PublicKey() accepted same-URI rotation")
	}

	restarted := newTestPlugin(t, backend, testConfig())
	replacement, err := restarted.PublicKey(context.Background(), key)
	if err != nil {
		t.Fatalf("PublicKey() after explicit restart error = %v", err)
	}
	if string(original) == string(replacement) {
		t.Fatal("rotation test did not replace the key")
	}
}

func TestPluginUsesCertificateWhenPublicObjectIsUnavailable(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(t)
	backend.mu.Lock()
	backend.key.ecPoint = nil
	backend.key.publicValue = nil
	backend.key.certificate = selfSignedEd25519Certificate(t, backend.key.public, backend.key.private)
	certificate := append([]byte(nil), backend.key.certificate...)
	backend.mu.Unlock()
	plugin := newTestPlugin(t, backend, testConfig())
	key := testKey("pkcs11:object=receipt-key;token=trustdb;type=private")
	publicKey, err := plugin.PublicKey(context.Background(), key)
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}
	if !ed25519.PublicKey(publicKey).Equal(backend.publicKey()) {
		t.Fatal("certificate fallback returned the wrong public key")
	}
	gotCertificate, err := plugin.Certificate(context.Background(), key)
	if err != nil {
		t.Fatalf("Certificate() error = %v", err)
	}
	if string(gotCertificate) != string(certificate) {
		t.Fatal("Certificate() did not return an isolated copy")
	}
}

func TestPluginRedactsPINURIAndBackendErrors(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(t)
	backend.loginErr = errors.New("native failure included 846295 and pkcs11:token=trustdb;object=secret")
	config := testConfig()
	config.PIN = staticPINSource("846295")
	plugin := newTestPlugin(t, backend, config)
	_, err := plugin.PublicKey(context.Background(), testKey("pkcs11:object=receipt-key;token=trustdb;type=private"))
	if err == nil {
		t.Fatal("PublicKey() unexpectedly succeeded")
	}
	for _, forbidden := range []string{"846295", "receipt-key", "pkcs11:", "native failure"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error %q disclosed %q", err, forbidden)
		}
	}
	requireProviderCode(t, err, signerplugin.ErrorInternal)
}

func TestFilePINSourceRejectsUnsafeFilesWithoutLeakingPath(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "token-super-secret.pin")
	if err := os.WriteFile(path, []byte("846295\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := NewFilePINSource(path)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := source.Read(context.Background())
	if runtime.GOOS == "windows" {
		if err == nil {
			clear(pin)
			t.Fatal("Read() accepted a PIN file without qualified owner-only DACL validation")
		}
		return
	}
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(pin) != "846295" {
		t.Fatal("Read() returned the wrong PIN")
	}
	clear(pin)

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = source.Read(context.Background())
	if err == nil {
		t.Fatal("Read() accepted a group/other-readable PIN file")
	}
	if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "846295") {
		t.Fatalf("error %q leaked PIN source details", err)
	}
}

func TestNormalizeSM2SignatureFormats(t *testing.T) {
	t.Parallel()
	raw := make([]byte, 64)
	raw[31] = 1
	raw[63] = 2
	profile := Profile{CryptoSuite: signerplugin.SuiteCNSMV1, Mechanism: 1, SignatureFormat: SignatureFormatRaw}
	der, err := normalizeSignature(profile, raw)
	if err != nil {
		t.Fatalf("normalize raw signature: %v", err)
	}
	var values struct {
		R *big.Int
		S *big.Int
	}
	if rest, err := asn1.Unmarshal(der, &values); err != nil || len(rest) != 0 ||
		values.R.Cmp(big.NewInt(1)) != 0 || values.S.Cmp(big.NewInt(2)) != 0 {
		t.Fatal("raw SM2 signature was not normalized to canonical DER")
	}
	profile.SignatureFormat = SignatureFormatDER
	roundTrip, err := normalizeSignature(profile, der)
	if err != nil || string(roundTrip) != string(der) {
		t.Fatalf("normalize DER signature = %x, %v", roundTrip, err)
	}
}

func TestPortableSessionContractCannotExportPrivateMaterial(t *testing.T) {
	t.Parallel()
	sessionType := reflect.TypeOf((*Session)(nil)).Elem()
	for index := 0; index < sessionType.NumMethod(); index++ {
		name := strings.ToLower(sessionType.Method(index).Name)
		for _, forbidden := range []string{"export", "privatekey", "attribute", "value"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("Session method %q exposes a private-material path", sessionType.Method(index).Name)
			}
		}
	}
	materialType := reflect.TypeOf(KeyMaterial{})
	for index := 0; index < materialType.NumField(); index++ {
		field := materialType.Field(index)
		if strings.Contains(strings.ToLower(field.Name), "private") && field.Type.Kind() == reflect.Slice {
			t.Fatalf("KeyMaterial field %q can carry private bytes", field.Name)
		}
	}
}

func TestParsePKCS11URIs(t *testing.T) {
	t.Parallel()
	token, err := parseTokenURI("pkcs11:manufacturer=fake;serial=serial-1;token=trustdb")
	if err != nil {
		t.Fatal(err)
	}
	if token.Label != "trustdb" || token.Serial != "serial-1" {
		t.Fatalf("token selector = %+v", token)
	}
	object, err := parseObjectURI("pkcs11:id=%01%02;object=receipt%20key;token=trustdb;type=private")
	if err != nil {
		t.Fatal(err)
	}
	if object.Label != "receipt key" || string(object.ID) != "\x01\x02" {
		t.Fatalf("object selector = %+v", object)
	}
	for _, raw := range []string{
		"pkcs11:object=key;pin-value=1234;token=trustdb",
		"pkcs11:object=key;pin-source=file;token=trustdb",
		"pkcs11:token=trustdb",
		"pkcs11:token=trustdb;object=key",
		"pkcs11:object=key;token=other;type=public",
	} {
		if _, err := parseObjectURI(raw); err == nil {
			t.Fatalf("parseObjectURI(%q) succeeded", raw)
		}
	}
}

func newTestPlugin(t *testing.T, backend *fakeBackend, config Config) *Plugin {
	t.Helper()
	plugin, err := New(context.Background(), config, backend)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = plugin.Close() })
	return plugin
}

func testConfig() Config {
	return Config{
		PluginID:           DefaultPluginID,
		TokenURI:           "pkcs11:serial=serial-1;token=trustdb",
		MaxConcurrentSigns: 16,
		PIN:                staticPINSource("846295"),
		Profiles: []Profile{{
			CryptoSuite:     signerplugin.SuiteINTLV1,
			Mechanism:       0x1057,
			SignatureFormat: SignatureFormatRaw,
		}},
	}
}

func testKey(uri string) signerplugin.Key {
	return signerplugin.Key{
		Binding: signerplugin.Binding{
			ProtocolVersion:   signerplugin.ProtocolVersion,
			PluginID:          DefaultPluginID,
			ProviderKind:      signerplugin.ProviderPKCS11,
			CryptoSuite:       signerplugin.SuiteINTLV1,
			Algorithm:         signerplugin.AlgorithmEd25519,
			PublicKeyEncoding: signerplugin.Ed25519PublicKeyEncoding,
			SignatureEncoding: signerplugin.Ed25519SignatureEncoding,
			KeyID:             "receipt-key-v1",
		},
		Reference: signerplugin.KeyReference{
			PKCS11: &signerplugin.PKCS11KeyReference{URI: uri},
		},
	}
}

func requireProviderCode(t *testing.T, err error, code signerplugin.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want provider code %s", code)
	}
	var providerErr *signerplugin.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != code {
		t.Fatalf("error = %v, want provider code %s", err, code)
	}
}

type fakeKey struct {
	handle      uint64
	public      ed25519.PublicKey
	private     ed25519.PrivateKey
	ecPoint     []byte
	publicValue []byte
	certificate []byte
}

type fakeBackend struct {
	mu         sync.Mutex
	identity   TokenIdentity
	mechanisms []Mechanism
	available  bool
	closed     bool
	key        fakeKey
	loginErr   error
	signErr    error

	signCalls      atomic.Int32
	activeSessions atomic.Int32
	maxSessions    atomic.Int32
}

func newFakeBackend(t *testing.T) *fakeBackend {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeBackend{
		identity: TokenIdentity{
			Label: "trustdb", Manufacturer: "fake", Model: "fake-v1", Serial: "serial-1",
		},
		mechanisms: []Mechanism{{Type: 0x1057, Flags: MechanismFlagSign}},
		available:  true,
		key: fakeKey{
			handle: 1, public: publicKey, private: privateKey, ecPoint: append([]byte(nil), publicKey...),
		},
	}
}

func (b *fakeBackend) Discover(ctx context.Context, selector TokenSelector) (Token, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || !b.available || !selector.matchesIdentity(b.identity) {
		return nil, newFault(faultUnavailable)
	}
	return &fakeToken{backend: b, identity: b.identity}, nil
}

func (b *fakeBackend) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return nil
}

func (b *fakeBackend) setAvailable(available bool) {
	b.mu.Lock()
	b.available = available
	b.mu.Unlock()
}

func (b *fakeBackend) setIdentity(identity TokenIdentity) {
	b.mu.Lock()
	b.identity = identity
	b.mu.Unlock()
}

func (b *fakeBackend) setSignError(err error) {
	b.mu.Lock()
	b.signErr = err
	b.mu.Unlock()
}

func (b *fakeBackend) publicKey() ed25519.PublicKey {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append(ed25519.PublicKey(nil), b.key.public...)
}

func (b *fakeBackend) rotate(t *testing.T) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.key = fakeKey{
		handle: b.key.handle + 1, public: publicKey, private: privateKey, ecPoint: append([]byte(nil), publicKey...),
	}
	b.mu.Unlock()
}

type fakeToken struct {
	backend  *fakeBackend
	identity TokenIdentity
}

func (t *fakeToken) Identity() TokenIdentity { return t.identity }

func (t *fakeToken) Mechanisms(ctx context.Context) ([]Mechanism, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t.backend.mu.Lock()
	defer t.backend.mu.Unlock()
	if !t.backend.available {
		return nil, newFault(faultUnavailable)
	}
	return append([]Mechanism(nil), t.backend.mechanisms...), nil
}

func (t *fakeToken) OpenSession(ctx context.Context) (Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t.backend.mu.Lock()
	available := t.backend.available
	t.backend.mu.Unlock()
	if !available {
		return nil, newFault(faultUnavailable)
	}
	active := t.backend.activeSessions.Add(1)
	for {
		maximum := t.backend.maxSessions.Load()
		if active <= maximum || t.backend.maxSessions.CompareAndSwap(maximum, active) {
			break
		}
	}
	return &fakeSession{backend: t.backend}, nil
}

type fakeSession struct {
	backend *fakeBackend
	closed  atomic.Bool
}

func (s *fakeSession) Login(ctx context.Context, pin []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	if !s.backend.available {
		return newFault(faultUnavailable)
	}
	if s.backend.loginErr != nil {
		return s.backend.loginErr
	}
	if string(pin) != "846295" {
		return newFault(faultAuthentication)
	}
	return nil
}

func (s *fakeSession) Lookup(ctx context.Context, _ ObjectSelector) (KeyMaterial, error) {
	if err := ctx.Err(); err != nil {
		return KeyMaterial{}, err
	}
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	if !s.backend.available {
		return KeyMaterial{}, newFault(faultUnavailable)
	}
	return KeyMaterial{
		Private:        newObjectHandle(s.backend.key.handle),
		ECPoint:        append([]byte(nil), s.backend.key.ecPoint...),
		PublicValue:    append([]byte(nil), s.backend.key.publicValue...),
		CertificateDER: append([]byte(nil), s.backend.key.certificate...),
	}, nil
}

func (s *fakeSession) Sign(ctx context.Context, handle ObjectHandle, _ Profile, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.backend.signCalls.Add(1)
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	if !s.backend.available {
		return nil, newFault(faultUnavailable)
	}
	if s.backend.signErr != nil {
		return nil, s.backend.signErr
	}
	if handle.value != s.backend.key.handle {
		return nil, newFault(faultPrecondition)
	}
	time.Sleep(time.Millisecond)
	return ed25519.Sign(s.backend.key.private, message), nil
}

func (s *fakeSession) Close() error {
	if !s.closed.Swap(true) {
		s.backend.activeSessions.Add(-1)
	}
	return nil
}

func selfSignedEd25519Certificate(t *testing.T, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "TrustDB fake token"},
		NotBefore:    time.Unix(1, 0),
		NotAfter:     time.Unix(4102444800, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
