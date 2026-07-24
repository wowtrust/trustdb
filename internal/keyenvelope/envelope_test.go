package keyenvelope

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wowtrust/trustdb/internal/cborx"
)

var testMetadata = Metadata{
	CryptoSuite:        "INTL_V1",
	KeyID:              "client-key",
	KeyAlgorithm:       "ed25519",
	PrivateKeyEncoding: "ed25519-private-raw-v1",
}

func TestEnvelopeRoundTripUniqueNonceAndKEKRotation(t *testing.T) {
	ctx := context.Background()
	privateKey := bytes.Repeat([]byte{0x5a}, 64)
	oldProvider := testPassphraseProvider("correct horse battery staple")
	newProvider := testPassphraseProvider("another correct battery staple")

	first, err := sealWithRand(ctx, testMetadata, privateKey, oldProvider, deterministicReader(1))
	if err != nil {
		t.Fatal(err)
	}
	second, err := sealWithRand(ctx, testMetadata, privateKey, oldProvider, deterministicReader(9))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(first, privateKey) || bytes.Contains(second, privateKey) {
		t.Fatal("canonical envelope persisted plaintext private key bytes")
	}
	firstEnvelope, err := Unmarshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondEnvelope, err := Unmarshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstEnvelope.ContentNonce, secondEnvelope.ContentNonce) {
		t.Fatal("independent envelopes reused a content nonce")
	}
	if bytes.Equal(firstEnvelope.WrappedDEK.Parameters, secondEnvelope.WrappedDEK.Parameters) {
		t.Fatal("independent envelopes reused KEK parameters")
	}
	opened, err := Open(ctx, first, testMetadata, oldProvider)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, privateKey) {
		t.Fatal("opened private key differs")
	}
	clearBytes(opened)

	rotated, err := Rewrap(ctx, first, testMetadata, oldProvider, newProvider)
	if err != nil {
		t.Fatal(err)
	}
	rotatedEnvelope, err := Unmarshal(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rotatedEnvelope.ContentNonce, firstEnvelope.ContentNonce) ||
		!bytes.Equal(rotatedEnvelope.Ciphertext, firstEnvelope.Ciphertext) {
		t.Fatal("KEK rotation changed encrypted private key content")
	}
	if bytes.Equal(rotatedEnvelope.WrappedDEK.Parameters, firstEnvelope.WrappedDEK.Parameters) {
		t.Fatal("KEK rotation reused provider parameters")
	}
	if _, err := Open(ctx, rotated, testMetadata, oldProvider); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("old passphrase opened rotated envelope: %v", err)
	}
	opened, err = Open(ctx, rotated, testMetadata, newProvider)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, privateKey) {
		t.Fatal("rotated envelope changed private key")
	}
	clearBytes(opened)
}

func TestEnvelopeFailsClosedForWrongKeyTamperTruncationAndDowngrade(t *testing.T) {
	ctx := context.Background()
	provider := testPassphraseProvider("correct horse battery staple")
	data, err := sealWithRand(ctx, testMetadata, bytes.Repeat([]byte{0x42}, 64), provider, deterministicReader(3))
	if err != nil {
		t.Fatal(err)
	}
	wrong := testPassphraseProvider("wrong horse battery staple!!")
	if _, err := Open(ctx, data, testMetadata, wrong); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("wrong passphrase error = %v", err)
	} else if strings.Contains(err.Error(), "correct horse") || strings.Contains(err.Error(), "wrong horse") {
		t.Fatalf("wrong passphrase diagnostic leaked secret text: %v", err)
	}

	tests := map[string]func(Envelope) []byte{
		"ciphertext": func(envelope Envelope) []byte {
			envelope.Ciphertext[0] ^= 0x80
			return mustMarshalRaw(t, envelope)
		},
		"content nonce": func(envelope Envelope) []byte {
			envelope.ContentNonce[0] ^= 0x01
			return mustMarshalRaw(t, envelope)
		},
		"wrapped DEK": func(envelope Envelope) []byte {
			envelope.WrappedDEK.Ciphertext[0] ^= 0x01
			return mustMarshalRaw(t, envelope)
		},
		"provider metadata": func(envelope Envelope) []byte {
			envelope.WrappedDEK.Parameters[len(envelope.WrappedDEK.Parameters)-1] ^= 0x01
			return mustMarshalRaw(t, envelope)
		},
		"KDF work-factor downgrade": func(envelope Envelope) []byte {
			var parameters passphraseParameters
			if err := cborx.Unmarshal(envelope.WrappedDEK.Parameters, &parameters); err != nil {
				t.Fatal(err)
			}
			parameters.Iterations = MinPBKDF2Iterations - 1
			envelope.WrappedDEK.Parameters, err = cborx.Marshal(parameters)
			if err != nil {
				t.Fatal(err)
			}
			return mustMarshalRaw(t, envelope)
		},
		"KDF work-factor inflation": func(envelope Envelope) []byte {
			var parameters passphraseParameters
			if err := cborx.Unmarshal(envelope.WrappedDEK.Parameters, &parameters); err != nil {
				t.Fatal(err)
			}
			parameters.Iterations = MaxPBKDF2Iterations + 1
			envelope.WrappedDEK.Parameters, err = cborx.Marshal(parameters)
			if err != nil {
				t.Fatal(err)
			}
			return mustMarshalRaw(t, envelope)
		},
		"algorithm downgrade": func(envelope Envelope) []byte {
			envelope.ContentAlgorithm = "SM4-CBC"
			return mustMarshalRaw(t, envelope)
		},
		"schema downgrade": func(envelope Envelope) []byte {
			envelope.SchemaVersion = "trustdb.software-key-envelope.v0"
			return mustMarshalRaw(t, envelope)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			envelope, err := Unmarshal(data)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Open(ctx, mutate(envelope), testMetadata, provider); err == nil {
				t.Fatal("tampered envelope opened")
			}
		})
	}
	for _, cut := range []int{1, len(data) / 2, len(data) - 1} {
		if _, err := Open(ctx, data[:cut], testMetadata, provider); err == nil {
			t.Fatalf("truncated envelope of %d bytes opened", cut)
		}
	}
	mismatched := testMetadata
	mismatched.KeyID = "attacker-key"
	if _, err := Open(ctx, data, mismatched, provider); !errors.Is(err, ErrMetadataMismatch) {
		t.Fatalf("metadata mismatch error = %v", err)
	}
	if _, err := Open(ctx, data, testMetadata); !errors.Is(err, ErrUnsupportedKEK) {
		t.Fatalf("unregistered provider error = %v", err)
	}
}

func TestRewrapRejectsProviderParameterReuse(t *testing.T) {
	provider := testPassphraseProvider("correct horse battery staple")
	provider.random = deterministicReader(7)
	data, err := sealWithRand(context.Background(), testMetadata, bytes.Repeat([]byte{0x33}, 64), provider, deterministicReader(1))
	if err != nil {
		t.Fatal(err)
	}
	provider.random = deterministicReader(7)
	if _, err := Rewrap(context.Background(), data, testMetadata, provider, provider); err == nil {
		t.Fatal("Rewrap accepted reused salt and nonce parameters")
	}
}

func TestSM4GCMKnownAnswer(t *testing.T) {
	key := mustHex(t, "0123456789abcdeffedcba9876543210")
	nonce := mustHex(t, "000102030405060708090a0b")
	aad := mustHex(t, "0017747275737464622e736d342d656e76656c6f70652e76320008434e5f534d5f5631000e6c6f676963616c2d6261636b7570000974656e616e742d303100066b65792d303100086d616e6966657374")
	plaintext := []byte("TrustDB CN_SM_V1 backup envelope")
	want := mustHex(t, "01536de2c5f5eb3f27cedcf896033064a89b48ce2b24ce9f23dadf4afc82631ebb4c850df99186a6dd87687a0a5622fc")
	got, err := sm4Seal(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("SM4-GCM sealed = %x, want %x", got, want)
	}
}

func TestEnvelopeStorageAtomicPermissionsAndSymlinkRejection(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Parallel()
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "client.material")
	provider := testPassphraseProvider("correct horse battery staple")
	first, err := sealWithRand(context.Background(), testMetadata, bytes.Repeat([]byte{0x11}, 64), provider, deterministicReader(1))
	if err != nil {
		t.Fatal(err)
	}
	second, err := sealWithRand(context.Background(), testMetadata, bytes.Repeat([]byte{0x22}, 64), provider, deterministicReader(2))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, second); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second WriteFile error = %v", err)
	}
	if err := ReplaceFile(path, second); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(path, second[:len(second)/2]); err == nil {
		t.Fatal("ReplaceFile accepted a truncated envelope")
	}
	got, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, second) {
		t.Fatalf("stored bytes = %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.bak"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("secret backup artifacts = %v, err=%v", matches, err)
	}
	if runtime.GOOS != "windows" {
		target := filepath.Join(dir, "target")
		link := filepath.Join(dir, "link")
		if err := os.WriteFile(target, first, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadFile(link); !errors.Is(err, ErrUnsafeEnvelopeStorage) {
			t.Fatalf("ReadFile(symlink) error = %v", err)
		}
		if err := ReplaceFile(link, second); !errors.Is(err, ErrUnsafeEnvelopeStorage) {
			t.Fatalf("ReplaceFile(symlink) error = %v", err)
		}
	}
	secretPath := filepath.Join(dir, "private-secret-material")
	if _, err := ReadFile(secretPath); err == nil {
		t.Fatal("ReadFile(missing secret path) error = nil")
	} else if strings.Contains(err.Error(), filepath.Base(secretPath)) {
		t.Fatalf("storage diagnostic leaked material path: %v", err)
	}
}

func FuzzEnvelopeUnmarshal(f *testing.F) {
	provider := testPassphraseProvider("correct horse battery staple")
	seed, err := sealWithRand(context.Background(), testMetadata, bytes.Repeat([]byte{0x44}, 64), provider, deterministicReader(4))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, data []byte) {
		envelope, err := Unmarshal(data)
		if err != nil {
			return
		}
		canonical, err := Marshal(envelope)
		if err != nil {
			t.Fatalf("accepted envelope failed marshal: %v", err)
		}
		if !bytes.Equal(canonical, data) {
			t.Fatal("accepted envelope was not canonical")
		}
	})
}

func testPassphraseProvider(passphrase string) *PassphraseKEKProvider {
	provider := NewPassphraseKEKProvider(func(ctx context.Context) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []byte(passphrase), nil
	})
	provider.iterations = MinPBKDF2Iterations
	return provider
}

func deterministicReader(seed byte) *bytes.Reader {
	data := make([]byte, 512)
	for i := range data {
		data[i] = seed + byte(i)
	}
	return bytes.NewReader(data)
}

func mustMarshalRaw(t *testing.T, envelope Envelope) []byte {
	t.Helper()
	data, err := cborx.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
