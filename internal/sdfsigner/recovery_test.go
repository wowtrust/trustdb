package sdfsigner

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/sdk/signerplugin"
)

func TestRecoveryBundleRestoresSignerAndWrappedKeyAfterRestart(t *testing.T) {
	firstBackend := newFakeBackend(t)
	first, err := New(context.Background(), testConfig(), firstBackend)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := recoveryDescriptor(firstBackend.publicKey)
	wrapped, generated, err := first.GenerateSM4Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	iv := []byte("0123456789abcdef")
	plaintext := []byte("recovery-block!!")
	ciphertext, err := generated.EncryptCBC(context.Background(), iv, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := first.ExportRecoveryBundle(
		context.Background(),
		[]keydescriptor.Descriptor{descriptor},
		[]WrappedSM4Key{wrapped},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("846295"), plaintext} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("recovery artifact disclosed protected bytes %q", forbidden)
		}
	}
	if err := generated.Close(); err != nil {
		t.Fatal(err)
	}
	restartedBackend := cloneFakeBackendForRestart(t, firstBackend)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := New(context.Background(), testConfig(), restartedBackend)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restored, err := restarted.RestoreRecoveryBundle(context.Background(), encoded)
	if err != nil {
		t.Fatalf("RestoreRecoveryBundle() error = %v", err)
	}
	if len(restored.SignerDescriptors) != 1 ||
		restored.SignerDescriptors[0].SDF == nil ||
		*restored.SignerDescriptors[0].SDF != *descriptor.SDF ||
		!bytes.Equal(restored.SignerDescriptors[0].PublicKey.Bytes, descriptor.PublicKey.Bytes) ||
		len(restored.WrappedSM4Keys) != 1 {
		t.Fatalf("restored inventory = %+v", restored)
	}
	if restartedBackend.importCalls.Load() != 1 ||
		restartedBackend.destroyCalls.Load() != 1 {
		t.Fatalf(
			"recovery KEK validation calls = import %d destroy %d",
			restartedBackend.importCalls.Load(),
			restartedBackend.destroyCalls.Load(),
		)
	}
	if _, err := restarted.Sign(
		context.Background(),
		recoveryPluginKey(restored.SignerDescriptors[0], DefaultPluginID),
		[]byte("sign after recovery"),
	); err != nil {
		t.Fatalf("Sign() after recovery error = %v", err)
	}
	session, err := restarted.ImportSM4Session(context.Background(), restored.WrappedSM4Keys[0])
	if err != nil {
		t.Fatalf("ImportSM4Session() after recovery error = %v", err)
	}
	roundTrip, err := session.DecryptCBC(context.Background(), iv, ciphertext)
	if err != nil || !bytes.Equal(roundTrip, plaintext) {
		t.Fatalf("DecryptCBC() after recovery = %x, %v", roundTrip, err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryBundleFailsClosedOnRuntimeBindingDrift(t *testing.T) {
	source := newFakeBackend(t)
	sourcePlugin, err := New(context.Background(), testConfig(), source)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, session, err := sourcePlugin.GenerateSM4Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	encoded, err := sourcePlugin.ExportRecoveryBundle(
		context.Background(),
		[]keydescriptor.Descriptor{recoveryDescriptor(source.publicKey)},
		[]WrappedSM4Key{wrapped},
	)
	if err != nil {
		t.Fatal(err)
	}
	restartBase := cloneFakeBackendForRestart(t, source)
	if err := sourcePlugin.Close(); err != nil {
		t.Fatal(err)
	}

	t.Run("device identity", func(t *testing.T) {
		backend := cloneFakeBackendForRestart(t, restartBase)
		backend.identity.Serial = "replacement-serial"
		plugin, err := New(context.Background(), testConfig(), backend)
		if err != nil {
			t.Fatal(err)
		}
		defer plugin.Close()
		if _, err := plugin.RestoreRecoveryBundle(context.Background(), encoded); !errors.Is(err, ErrInvalidRecoveryBundle) {
			t.Fatalf("RestoreRecoveryBundle() error = %v", err)
		}
	})
	t.Run("public key", func(t *testing.T) {
		backend := cloneFakeBackendForRestart(t, restartBase)
		backend.rotate(t)
		plugin, err := New(context.Background(), testConfig(), backend)
		if err != nil {
			t.Fatal(err)
		}
		defer plugin.Close()
		if _, err := plugin.RestoreRecoveryBundle(context.Background(), encoded); !errors.Is(err, ErrInvalidRecoveryBundle) {
			t.Fatalf("RestoreRecoveryBundle() error = %v", err)
		}
	})
	t.Run("credential identity", func(t *testing.T) {
		config := testConfig()
		config.CredentialRef = "replacement-credential"
		plugin, err := New(context.Background(), config, cloneFakeBackendForRestart(t, restartBase))
		if err != nil {
			t.Fatal(err)
		}
		defer plugin.Close()
		if _, err := plugin.RestoreRecoveryBundle(context.Background(), encoded); !errors.Is(err, ErrInvalidRecoveryBundle) {
			t.Fatalf("RestoreRecoveryBundle() error = %v", err)
		}
	})
	t.Run("KEK identity", func(t *testing.T) {
		config := testConfig()
		config.KEKID = "replacement-kek"
		plugin, err := New(context.Background(), config, cloneFakeBackendForRestart(t, restartBase))
		if err != nil {
			t.Fatal(err)
		}
		defer plugin.Close()
		if _, err := plugin.RestoreRecoveryBundle(context.Background(), encoded); !errors.Is(err, ErrInvalidRecoveryBundle) {
			t.Fatalf("RestoreRecoveryBundle() error = %v", err)
		}
	})
}

func TestRecoveryBundleRejectsTamperUnknownTrailingNonCanonicalAndOversize(t *testing.T) {
	backend := newFakeBackend(t)
	plugin, err := New(context.Background(), testConfig(), backend)
	if err != nil {
		t.Fatal(err)
	}
	defer plugin.Close()
	encoded, err := plugin.ExportRecoveryBundle(
		context.Background(),
		[]keydescriptor.Descriptor{recoveryDescriptor(backend.publicKey)},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := plugin.RestoreRecoveryBundle(context.Background(), tampered); err == nil {
		t.Fatal("RestoreRecoveryBundle() accepted tampered data")
	}
	if _, err := plugin.RestoreRecoveryBundle(context.Background(), append(append([]byte(nil), encoded...), 0xf6)); err == nil {
		t.Fatal("RestoreRecoveryBundle() accepted trailing data")
	}
	var fields map[string]any
	if err := cborx.UnmarshalLimit(encoded, &fields, MaxRecoveryBundleBytes); err != nil {
		t.Fatal(err)
	}
	fields["unknown"] = "rejected"
	unknown, err := cborx.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.RestoreRecoveryBundle(context.Background(), unknown); err == nil {
		t.Fatal("RestoreRecoveryBundle() accepted an unknown field")
	}

	checksumNeedle := append([]byte{0x6c}, []byte("checksum_sm3")...)
	checksumNeedle = append(checksumNeedle, 0x58, 0x20)
	index := bytes.Index(encoded, checksumNeedle)
	if index < 0 {
		t.Fatalf("canonical fixture lacks checksum field: %x", encoded)
	}
	nonCanonical := make([]byte, 0, len(encoded)+1)
	lengthIndex := index + len(checksumNeedle) - 2
	nonCanonical = append(nonCanonical, encoded[:lengthIndex]...)
	nonCanonical = append(nonCanonical, 0x59, 0x00, 0x20)
	nonCanonical = append(nonCanonical, encoded[lengthIndex+2:]...)
	if _, err := plugin.RestoreRecoveryBundle(context.Background(), nonCanonical); err == nil {
		t.Fatal("RestoreRecoveryBundle() accepted non-canonical CBOR")
	}
	if _, err := plugin.RestoreRecoveryBundle(context.Background(), make([]byte, MaxRecoveryBundleBytes+1)); err == nil {
		t.Fatal("RestoreRecoveryBundle() accepted oversized input")
	}

	arrayNeedle := append([]byte{0x72}, []byte("signer_descriptors")...)
	arrayNeedle = append(arrayNeedle, 0x81)
	index = bytes.Index(encoded, arrayNeedle)
	if index < 0 {
		t.Fatalf("canonical fixture lacks signer_descriptors: %x", encoded)
	}
	arrayHeaderIndex := index + len(arrayNeedle) - 1
	hugeDeclaredCount := make([]byte, 0, len(encoded)+4)
	hugeDeclaredCount = append(hugeDeclaredCount, encoded[:arrayHeaderIndex]...)
	hugeDeclaredCount = append(hugeDeclaredCount, 0x9a, 0x00, 0x10, 0x00, 0x00)
	hugeDeclaredCount = append(hugeDeclaredCount, encoded[arrayHeaderIndex+1:]...)
	if _, err := plugin.RestoreRecoveryBundle(context.Background(), hugeDeclaredCount); err == nil {
		t.Fatal("RestoreRecoveryBundle() accepted a malicious declared array count")
	}
}

func TestRecoveryBundleExportRejectsAmbiguousOrOversizedInventory(t *testing.T) {
	backend := newFakeBackend(t)
	plugin, err := New(context.Background(), testConfig(), backend)
	if err != nil {
		t.Fatal(err)
	}
	defer plugin.Close()
	descriptor := recoveryDescriptor(backend.publicKey)
	duplicateHandle := descriptor.Clone()
	duplicateHandle.KeyID = "same-provider-handle"
	if _, err := plugin.ExportRecoveryBundle(
		context.Background(),
		[]keydescriptor.Descriptor{descriptor, duplicateHandle},
		nil,
	); !errors.Is(err, ErrInvalidRecoveryBundle) {
		t.Fatalf("ExportRecoveryBundle(duplicate handle) error = %v", err)
	}
	tooMany := make([]keydescriptor.Descriptor, MaxRecoverySignerDescriptors+1)
	if _, err := plugin.ExportRecoveryBundle(context.Background(), tooMany, nil); !errors.Is(err, ErrInvalidRecoveryBundle) {
		t.Fatalf("ExportRecoveryBundle(oversized inventory) error = %v", err)
	}
}

func TestRecoveryBundlePublicPinsPublishAtomically(t *testing.T) {
	backend := newFakeBackend(t)
	plugin, err := New(context.Background(), testConfig(), backend)
	if err != nil {
		t.Fatal(err)
	}
	defer plugin.Close()
	first := recoveryDescriptor(backend.publicKey)
	first.KeyID = "recovery-first"
	second := recoveryDescriptor(backend.publicKey)
	second.KeyID = "recovery-second"
	second.SDF.KeyIndex = 8
	encoded, err := plugin.ExportRecoveryBundle(
		context.Background(),
		[]keydescriptor.Descriptor{first, second},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	conflictingKey := recoveryPluginKey(second, DefaultPluginID)
	_, conflictingCacheKey, err := plugin.validateKey(conflictingKey)
	if err != nil {
		t.Fatal(err)
	}
	plugin.mu.Lock()
	plugin.accepted[conflictingCacheKey] = bytes.Repeat([]byte{0xff}, len(backend.publicKey))
	plugin.mu.Unlock()

	_, err = plugin.RestoreRecoveryBundle(context.Background(), encoded)
	requireProviderCode(t, err, signerplugin.ErrorFailedPrecondition)
	plugin.mu.Lock()
	defer plugin.mu.Unlock()
	if len(plugin.accepted) != 1 ||
		!bytes.Equal(plugin.accepted[conflictingCacheKey], bytes.Repeat([]byte{0xff}, len(backend.publicKey))) {
		t.Fatalf("failed recovery partially published accepted pins: %+v", plugin.accepted)
	}
}

func recoveryDescriptor(publicKey []byte) keydescriptor.Descriptor {
	return keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindSigner,
		Provider:      keydescriptor.ProviderSDF,
		CryptoSuite:   cryptosuite.CNSMV1,
		KeyID:         "receipt-sm2-v1",
		Algorithm:     cryptosuite.SignatureSM2SM3,
		SM2UserID:     cryptosuite.SM2DefaultUserID,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: cryptosuite.SM2PublicKeyEncoding,
			Bytes:    append([]byte(nil), publicKey...),
		},
		SDF: &keydescriptor.SDFKeyReference{
			DeviceRef:     "sdf-production",
			KeyIndex:      7,
			CredentialRef: "receipt-operator",
		},
	}
}

func cloneFakeBackendForRestart(t *testing.T, source *fakeBackend) *fakeBackend {
	t.Helper()
	cloned := newFakeBackend(t)
	source.mu.Lock()
	cloned.identity = source.identity
	cloned.capabilities = source.capabilities
	cloned.available = source.available
	cloned.privateKey = source.privateKey
	cloned.publicKey = append([]byte(nil), source.publicKey...)
	source.mu.Unlock()
	return cloned
}
