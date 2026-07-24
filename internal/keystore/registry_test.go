package keystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func TestRegistryV2RegisterLookupReloadAndProviderMetadata(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "keys.tdkeys")
	registrySigner, registryPub := newINTLRegistrySigner(t)
	clientPub, _ := mustINTLKey(t)
	descriptor := intlVerifierDescriptor("client-key", clientPub)
	descriptor.Kind = keydescriptor.KindSigner
	descriptor.Provider = keydescriptor.ProviderPKCS11
	descriptor.PKCS11 = &keydescriptor.PKCS11KeyReference{URI: "pkcs11:object=client-key;type=private"}

	registry, err := Open(path, registrySigner, registryPub)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	event, err := registry.RegisterClientKey("tenant", "client", descriptor, time.Unix(100, 0), time.Time{})
	if err != nil {
		t.Fatalf("RegisterClientKey() error = %v", err)
	}
	if event.SchemaVersion != model.SchemaKeyEvent || event.CryptoSuite != cryptosuite.INTLV1 || event.Sequence != 1 {
		t.Fatalf("registered event = %+v", event)
	}
	key, err := registry.LookupClientKeyAt("tenant", "client", "client-key", time.Unix(101, 0))
	if err != nil {
		t.Fatalf("LookupClientKeyAt() error = %v", err)
	}
	if key.Status != model.KeyStatusValid || key.Provider != keydescriptor.ProviderPKCS11 || !bytes.Equal(key.PublicKey, clientPub) {
		t.Fatalf("LookupClientKeyAt() = %+v", key)
	}
	storedDescriptor, err := keydescriptor.Unmarshal(key.KeyDescriptor)
	if err != nil {
		t.Fatalf("Unmarshal(stored descriptor) error = %v", err)
	}
	if storedDescriptor.PKCS11 == nil || storedDescriptor.PKCS11.URI != descriptor.PKCS11.URI {
		t.Fatalf("stored provider reference = %+v", storedDescriptor.PKCS11)
	}

	reloaded, err := Open(path, nil, registryPub)
	if err != nil {
		t.Fatalf("Open(reload) error = %v", err)
	}
	if reloaded.Manifest().SchemaVersion != SchemaRegistryV2 || reloaded.Suite() != cryptosuite.INTLV1 {
		t.Fatalf("manifest = %+v", reloaded.Manifest())
	}
	if _, err := reloaded.LookupClientKeyAt("tenant", "client", "client-key", time.Unix(101, 0)); err != nil {
		t.Fatalf("LookupClientKeyAt(reload) error = %v", err)
	}
}

func TestRegistryV2SupportsSM2AndRejectsMixedSuite(t *testing.T) {
	t.Parallel()
	registrySigner, registryPub := newSM2RegistrySigner(t)
	registry, err := Open(filepath.Join(t.TempDir(), "sm2.tdkeys"), registrySigner, registryPub)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	clientPub, _ := mustSM2Key(t)
	if _, err := registry.RegisterClientKey("tenant", "client", sm2VerifierDescriptor("sm2-client", clientPub), time.Unix(100, 0), time.Time{}); err != nil {
		t.Fatalf("RegisterClientKey(SM2) error = %v", err)
	}
	key, err := registry.LookupClientKeyAt("tenant", "client", "sm2-client", time.Unix(101, 0))
	if err != nil {
		t.Fatalf("LookupClientKeyAt(SM2) error = %v", err)
	}
	if key.CryptoSuite != cryptosuite.CNSMV1 || key.Alg != cryptosuite.SignatureSM2SM3 || key.SM2UserID != cryptosuite.SM2DefaultUserID {
		t.Fatalf("SM2 key metadata = %+v", key)
	}
	intlPub, _ := mustINTLKey(t)
	if _, err := registry.RegisterClientKey("tenant", "client", intlVerifierDescriptor("intl-key", intlPub), time.Unix(100, 0), time.Time{}); !errors.Is(err, cryptosuite.ErrMixedSuite) {
		t.Fatalf("mixed-suite registration error = %v", err)
	}
}

func TestRegistryAllowsUnixEpochValidity(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "keys.tdkeys")
	registrySigner, registryPub := newINTLRegistrySigner(t)
	registry, err := Open(path, registrySigner, registryPub)
	if err != nil {
		t.Fatal(err)
	}
	clientPub, _ := mustINTLKey(t)
	if _, err := registry.RegisterClientKey("tenant", "client", intlVerifierDescriptor("epoch-key", clientPub), time.Unix(0, 0), time.Time{}); err != nil {
		t.Fatalf("RegisterClientKey(epoch) error = %v", err)
	}
	if _, err := registry.LookupClientKeyAt("tenant", "client", "epoch-key", time.Unix(0, 0)); err != nil {
		t.Fatalf("LookupClientKeyAt(epoch) error = %v", err)
	}

	reloaded, err := Open(path, nil, registryPub)
	if err != nil {
		t.Fatalf("Open(reload) error = %v", err)
	}
	if _, err := reloaded.LookupClientKeyAt("tenant", "client", "epoch-key", time.Unix(1, 0)); err != nil {
		t.Fatalf("LookupClientKeyAt(reload) error = %v", err)
	}
}

func TestRegistryRotationPreservesHistoricalLookup(t *testing.T) {
	t.Parallel()
	registrySigner, registryPub := newINTLRegistrySigner(t)
	registry, err := Open(filepath.Join(t.TempDir(), "keys.tdkeys"), registrySigner, registryPub)
	if err != nil {
		t.Fatal(err)
	}
	oldPub, _ := mustINTLKey(t)
	newPub, _ := mustINTLKey(t)
	if _, err := registry.RegisterClientKey("tenant", "client", intlVerifierDescriptor("old-key", oldPub), time.Unix(100, 0), time.Time{}); err != nil {
		t.Fatal(err)
	}
	rotation, err := registry.RotateClientKey("tenant", "client", "old-key", intlVerifierDescriptor("new-key", newPub), time.Unix(200, 0), time.Time{}, "scheduled rotation")
	if err != nil {
		t.Fatalf("RotateClientKey() error = %v", err)
	}
	if rotation.Type != model.KeyEventRotate || rotation.PreviousKeyID != "old-key" {
		t.Fatalf("rotation event = %+v", rotation)
	}
	if _, err := registry.LookupClientKeyAt("tenant", "client", "old-key", time.Unix(199, 0)); err != nil {
		t.Fatalf("historical old-key lookup error = %v", err)
	}
	oldAtRotation, err := registry.LookupClientKeyAt("tenant", "client", "old-key", time.Unix(200, 0))
	if err == nil || oldAtRotation.Status != model.KeyStatusRevoked {
		t.Fatalf("old key after rotation = %+v, err = %v", oldAtRotation, err)
	}
	newBeforeRotation, err := registry.LookupClientKeyAt("tenant", "client", "new-key", time.Unix(199, 0))
	if err == nil || newBeforeRotation.KeyID != "new-key" {
		t.Fatalf("new key before rotation = %+v, err = %v", newBeforeRotation, err)
	}
	if _, err := registry.LookupClientKeyAt("tenant", "client", "new-key", time.Unix(200, 0)); err != nil {
		t.Fatalf("new key at rotation error = %v", err)
	}
}

func TestRegistryDuplicateImportIsIdempotentButConflictsFailClosed(t *testing.T) {
	t.Parallel()
	registrySigner, registryPub := newINTLRegistrySigner(t)
	registry, err := Open(filepath.Join(t.TempDir(), "keys.tdkeys"), registrySigner, registryPub)
	if err != nil {
		t.Fatal(err)
	}
	firstPub, _ := mustINTLKey(t)
	descriptor := intlVerifierDescriptor("client-key", firstPub)
	first, err := registry.RegisterClientKey("tenant", "client", descriptor, time.Unix(100, 0), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	retry, err := registry.RegisterClientKey("tenant", "client", descriptor, time.Unix(100, 0), time.Time{})
	if err != nil {
		t.Fatalf("idempotent retry error = %v", err)
	}
	if retry.Sequence != first.Sequence || len(registry.Events()) != 1 {
		t.Fatalf("retry sequence/events = %d/%d", retry.Sequence, len(registry.Events()))
	}
	secondPub, _ := mustINTLKey(t)
	if _, err := registry.RegisterClientKey("tenant", "client", intlVerifierDescriptor("client-key", secondPub), time.Unix(100, 0), time.Time{}); !errors.Is(err, ErrConflictingKeyID) {
		t.Fatalf("conflicting public material error = %v", err)
	}
	sm2Pub, _ := mustSM2Key(t)
	if _, err := registry.RegisterClientKey("tenant", "client", sm2VerifierDescriptor("client-key", sm2Pub), time.Unix(100, 0), time.Time{}); !errors.Is(err, cryptosuite.ErrMixedSuite) {
		t.Fatalf("conflicting algorithm/suite error = %v", err)
	}
}

func TestRegistryConstrainsValidityToLeafCertificate(t *testing.T) {
	t.Parallel()
	registrySigner, registryPub := newINTLRegistrySigner(t)
	registry, err := Open(filepath.Join(t.TempDir(), "keys.tdkeys"), registrySigner, registryPub)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := mustINTLKey(t)
	template := &smx509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "registry-client"},
		NotBefore:    time.Unix(100, 0).UTC(),
		NotAfter:     time.Unix(200, 0).UTC(),
		KeyUsage:     smx509.KeyUsageDigitalSignature,
	}
	certificate, err := smx509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := intlVerifierDescriptor("cert-key", publicKey)
	descriptor.CertificateChain = [][]byte{certificate}
	if _, err := registry.RegisterClientKey("tenant", "client", descriptor, time.Unix(99, 0), time.Time{}); err == nil {
		t.Fatal("RegisterClientKey() accepted valid_from before the leaf certificate")
	}
	event, err := registry.RegisterClientKey("tenant", "client", descriptor, time.Unix(150, 0), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if event.ValidUntilUnixN != time.Unix(200, 0).UnixNano() {
		t.Fatalf("valid_until = %d, want certificate expiry", event.ValidUntilUnixN)
	}
}

func TestRegistryRevocationAndCompromiseAreTimeQualified(t *testing.T) {
	t.Parallel()
	registrySigner, registryPub := newINTLRegistrySigner(t)
	registry, err := Open(filepath.Join(t.TempDir(), "keys.tdkeys"), registrySigner, registryPub)
	if err != nil {
		t.Fatal(err)
	}
	clientPub, _ := mustINTLKey(t)
	if _, err := registry.RegisterClientKey("tenant", "client", intlVerifierDescriptor("client-key", clientPub), time.Unix(100, 0), time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RevokeClientKey("tenant", "client", "client-key", time.Unix(300, 0), "retired"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.MarkClientKeyCompromised("tenant", "client", "client-key", time.Unix(250, 0), "incident"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.LookupClientKeyAt("tenant", "client", "client-key", time.Unix(249, 0)); err != nil {
		t.Fatalf("lookup before compromise error = %v", err)
	}
	compromised, err := registry.LookupClientKeyAt("tenant", "client", "client-key", time.Unix(250, 0))
	if err == nil || compromised.Status != model.KeyStatusCompromised {
		t.Fatalf("compromised lookup = %+v, err = %v", compromised, err)
	}
}

func TestRegistryRecoversIncompleteFinalFrameBeforeNextAppend(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "keys.tdkeys")
	registrySigner, registryPub := newINTLRegistrySigner(t)
	registry, err := Open(path, registrySigner, registryPub)
	if err != nil {
		t.Fatal(err)
	}
	firstPub, _ := mustINTLKey(t)
	if _, err := registry.RegisterClientKey("tenant", "client", intlVerifierDescriptor("key-1", firstPub), time.Unix(100, 0), time.Time{}); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0, 0, 0, 20, 0xa1, 0x61}); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(path, registrySigner, registryPub)
	if err != nil {
		t.Fatalf("Open(recover tail) error = %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != before.Size() {
		t.Fatalf("repaired size = %d, want %d", after.Size(), before.Size())
	}
	secondPub, _ := mustINTLKey(t)
	second, err := recovered.RegisterClientKey("tenant", "client", intlVerifierDescriptor("key-2", secondPub), time.Unix(101, 0), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if second.Sequence != 2 {
		t.Fatalf("second sequence = %d", second.Sequence)
	}
}

func TestRegistryRejectsLegacyFormatAndUntrustedManifest(t *testing.T) {
	t.Parallel()
	legacyPath := filepath.Join(t.TempDir(), "legacy.tdkeys")
	if err := os.WriteFile(legacyPath, []byte{0, 0, 0, 1, 0xa0, 0, 0, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	_, trustedPub := newINTLRegistrySigner(t)
	if _, err := Open(legacyPath, nil, trustedPub); !errors.Is(err, ErrUnsupportedRegistryFormat) {
		t.Fatalf("legacy format error = %v", err)
	}

	path := filepath.Join(t.TempDir(), "keys.tdkeys")
	signer, publicKey := newINTLRegistrySigner(t)
	if _, err := Open(path, signer, publicKey); err != nil {
		t.Fatal(err)
	}
	_, otherPublicKey := newINTLRegistrySigner(t)
	if _, err := Open(path, nil, otherPublicKey); err == nil {
		t.Fatal("Open() accepted an untrusted manifest signer")
	}
	if _, err := Open(path, nil, trustcrypto.PublicKeyDescriptor{}); err == nil {
		t.Fatal("Open() accepted an existing registry without an external trust root")
	}
}

func TestRegistryConcurrentInitializationCannotReplaceManifest(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "keys.tdkeys")
	signer, publicKey := newINTLRegistrySigner(t)
	errorsOut := make(chan error, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			_, err := Open(path, signer, publicKey)
			errorsOut <- err
		}()
	}
	close(start)
	for range 2 {
		if err := <-errorsOut; err != nil {
			t.Fatalf("concurrent Open() error = %v", err)
		}
	}
	if _, err := Open(path, nil, publicKey); err != nil {
		t.Fatalf("Open(verified manifest) error = %v", err)
	}
}

func TestRegistryRejectsSignedEventTampering(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "keys.tdkeys")
	signer, publicKey := newINTLRegistrySigner(t)
	registry, err := Open(path, signer, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, _ := mustINTLKey(t)
	if _, err := registry.RegisterClientKey("tenant", "client", intlVerifierDescriptor("client-key", clientPublic), time.Unix(100, 0), time.Time{}); err != nil {
		t.Fatal(err)
	}
	manifestPayload, err := cborx.Marshal(registry.Manifest())
	if err != nil {
		t.Fatal(err)
	}
	manifestFrame, err := encodeFrame(manifestPayload)
	if err != nil {
		t.Fatal(err)
	}
	baseEvent := registry.Events()[0]
	for name, mutate := range map[string]func(*model.KeyEvent){
		"signature":  func(event *model.KeyEvent) { event.RegistrySignature.Signature[0] ^= 0x01 },
		"event hash": func(event *model.KeyEvent) { event.EventHash[0] ^= 0x01 },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := cloneEvent(baseEvent)
			mutate(&tampered)
			payload, err := cborx.Marshal(tampered)
			if err != nil {
				t.Fatal(err)
			}
			eventFrame, err := encodeFrame(payload)
			if err != nil {
				t.Fatal(err)
			}
			tamperedPath := filepath.Join(t.TempDir(), "tampered.tdkeys")
			fileBytes := append(append(append([]byte(nil), registryMagic...), manifestFrame...), eventFrame...)
			if err := os.WriteFile(tamperedPath, fileBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(tamperedPath, nil, publicKey); err == nil {
				t.Fatal("Open() accepted a tampered signed event")
			}
		})
	}
}

func TestRegistryV2CanonicalFileGolden(t *testing.T) {
	t.Parallel()
	registryPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	registryPublic := registryPrivate.Public().(ed25519.PublicKey)
	clientPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	clientPublic := clientPrivate.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "golden.tdkeys")
	registry, err := Open(
		path,
		trustcrypto.MustNewEd25519Signer("registry-golden", registryPrivate),
		trustcrypto.MustNewEd25519PublicKey("registry-golden", registryPublic),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RegisterClientKey("tenant-golden", "client-golden", intlVerifierDescriptor("client-golden-key", clientPublic), time.Unix(100, 0), time.Unix(200, 0)); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	const wantSHA256 = "501b71c13f875c545d34b0d0b620638076d5909dae273aed012d5a2647f2b810"
	if got := hex.EncodeToString(digest[:]); got != wantSHA256 {
		t.Fatalf("registry V2 golden SHA-256 = %s, want %s", got, wantSHA256)
	}
}

func newINTLRegistrySigner(t *testing.T) (trustcrypto.Signer, trustcrypto.PublicKeyDescriptor) {
	t.Helper()
	publicKey, privateKey := mustINTLKey(t)
	return trustcrypto.MustNewEd25519Signer("registry-key", privateKey), trustcrypto.MustNewEd25519PublicKey("registry-key", publicKey)
}

func newSM2RegistrySigner(t *testing.T) (trustcrypto.Signer, trustcrypto.PublicKeyDescriptor) {
	t.Helper()
	publicKey, privateKey := mustSM2Key(t)
	signer, err := trustcrypto.NewSM2Signer("sm2-registry-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := trustcrypto.NewSM2PublicKey("sm2-registry-key", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, descriptor
}

func mustINTLKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func mustSM2Key(t *testing.T) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := trustcrypto.GenerateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func intlVerifierDescriptor(keyID string, publicKey []byte) keydescriptor.Descriptor {
	return keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindVerifier,
		Provider:      keydescriptor.ProviderPublic,
		CryptoSuite:   cryptosuite.INTLV1,
		KeyID:         keyID,
		Algorithm:     cryptosuite.SignatureEd25519,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: cryptosuite.Ed25519PublicKeyEncoding,
			Bytes:    append([]byte(nil), publicKey...),
		},
	}
}

func sm2VerifierDescriptor(keyID string, publicKey []byte) keydescriptor.Descriptor {
	return keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindVerifier,
		Provider:      keydescriptor.ProviderPublic,
		CryptoSuite:   cryptosuite.CNSMV1,
		KeyID:         keyID,
		Algorithm:     cryptosuite.SignatureSM2SM3,
		SM2UserID:     cryptosuite.SM2DefaultUserID,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: cryptosuite.SM2PublicKeyEncoding,
			Bytes:    append([]byte(nil), publicKey...),
		},
	}
}
