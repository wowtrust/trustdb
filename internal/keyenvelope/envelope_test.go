package keyenvelope

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
	if runtime.GOOS == "windows" {
		t.Skip("Windows envelope storage intentionally fails closed")
	}
	t.Parallel()
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
	if err := UpdateFile(context.Background(), path, func(current []byte) ([]byte, error) {
		return append([]byte(nil), second...), nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := UpdateFile(context.Background(), path, func(current []byte) ([]byte, error) {
		return append([]byte(nil), second[:len(second)/2]...), nil
	}); err == nil {
		t.Fatal("UpdateFile accepted a truncated envelope")
	}
	injected := errors.New("injected update failure")
	if err := UpdateFile(context.Background(), path, func(current []byte) ([]byte, error) {
		return nil, injected
	}); !errors.Is(err, injected) {
		t.Fatalf("UpdateFile callback failure = %v", err)
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
		if err := UpdateFile(context.Background(), link, func(current []byte) ([]byte, error) {
			return append([]byte(nil), second...), nil
		}); !errors.Is(err, ErrUnsafeEnvelopeStorage) {
			t.Fatalf("UpdateFile(symlink) error = %v", err)
		}
	}
	secretPath := filepath.Join(dir, "private-secret-material")
	if _, err := ReadFile(secretPath); err == nil {
		t.Fatal("ReadFile(missing secret path) error = nil")
	} else if strings.Contains(err.Error(), filepath.Base(secretPath)) {
		t.Fatalf("storage diagnostic leaked material path: %v", err)
	}
}

func TestUpdateFileSerializesAcrossProcesses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows envelope storage intentionally fails closed")
	}
	provider := testPassphraseProvider("correct horse battery staple")
	data, err := sealWithRand(context.Background(), testMetadata, bytes.Repeat([]byte{0x31}, 64), provider, deterministicReader(6))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.material")
	if err := WriteFile(path, data); err != nil {
		t.Fatal(err)
	}

	first := startEnvelopeLockHelper(t, path)
	waitHelperReady(t, first, 5*time.Second)
	second := startEnvelopeLockHelper(t, path)
	select {
	case err := <-second.ready:
		t.Fatalf("second process entered update while first held lock: %v", err)
	case <-time.After(250 * time.Millisecond):
	}
	first.release(t)
	first.wait(t)
	waitHelperReady(t, second, 5*time.Second)
	second.release(t)
	second.wait(t)
}

func TestUpdateFileRecoversAfterLockHolderProcessExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows envelope storage intentionally fails closed")
	}
	provider := testPassphraseProvider("correct horse battery staple")
	data, err := sealWithRand(context.Background(), testMetadata, bytes.Repeat([]byte{0x32}, 64), provider, deterministicReader(7))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.material")
	if err := WriteFile(path, data); err != nil {
		t.Fatal(err)
	}

	helper := startEnvelopeLockHelper(t, path)
	waitHelperReady(t, helper, 5*time.Second)
	if err := helper.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := helper.cmd.Wait(); err == nil {
		t.Fatal("killed lock helper exited successfully")
	}
	_ = helper.releaseOut.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := UpdateFile(ctx, path, func(current []byte) ([]byte, error) {
		return append([]byte(nil), current...), nil
	}); err != nil {
		t.Fatalf("UpdateFile after lock-holder exit: %v", err)
	}
}

func TestEnvelopeLockProcessHelper(t *testing.T) {
	if os.Getenv("TRUSTDB_ENVELOPE_LOCK_HELPER") != "1" {
		return
	}
	ready := os.NewFile(uintptr(3), "ready")
	release := os.NewFile(uintptr(4), "release")
	if ready == nil || release == nil {
		t.Fatal("helper pipes are unavailable")
	}
	defer ready.Close()
	defer release.Close()
	path := os.Getenv("TRUSTDB_ENVELOPE_LOCK_PATH")
	err := UpdateFile(context.Background(), path, func(current []byte) ([]byte, error) {
		if _, err := ready.Write([]byte{1}); err != nil {
			return nil, err
		}
		one := make([]byte, 1)
		if _, err := release.Read(one); err != nil {
			return nil, err
		}
		return append([]byte(nil), current...), nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type envelopeLockHelper struct {
	cmd        *exec.Cmd
	ready      <-chan error
	releaseOut *os.File
	output     *bytes.Buffer
}

func startEnvelopeLockHelper(t *testing.T, path string) *envelopeLockHelper {
	t.Helper()
	readyIn, readyOut, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	releaseIn, releaseOut, err := os.Pipe()
	if err != nil {
		readyIn.Close()
		readyOut.Close()
		t.Fatal(err)
	}
	output := new(bytes.Buffer)
	cmd := exec.Command(os.Args[0], "-test.run=^TestEnvelopeLockProcessHelper$")
	cmd.Env = append(os.Environ(),
		"TRUSTDB_ENVELOPE_LOCK_HELPER=1",
		"TRUSTDB_ENVELOPE_LOCK_PATH="+path,
	)
	cmd.ExtraFiles = []*os.File{readyOut, releaseIn}
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		readyIn.Close()
		readyOut.Close()
		releaseIn.Close()
		releaseOut.Close()
		t.Fatal(err)
	}
	readyOut.Close()
	releaseIn.Close()
	ready := make(chan error, 1)
	go func() {
		one := make([]byte, 1)
		_, err := readyIn.Read(one)
		_ = readyIn.Close()
		ready <- err
	}()
	helper := &envelopeLockHelper{cmd: cmd, ready: ready, releaseOut: releaseOut, output: output}
	t.Cleanup(func() {
		_ = helper.releaseOut.Close()
		if helper.cmd.Process != nil {
			_ = helper.cmd.Process.Kill()
		}
	})
	return helper
}

func waitHelperReady(t *testing.T, helper *envelopeLockHelper, timeout time.Duration) {
	t.Helper()
	select {
	case err := <-helper.ready:
		if err != nil {
			t.Fatalf("lock helper readiness failed: %v\n%s", err, helper.output.String())
		}
	case <-time.After(timeout):
		t.Fatalf("lock helper did not become ready\n%s", helper.output.String())
	}
}

func (h *envelopeLockHelper) release(t *testing.T) {
	t.Helper()
	if _, err := h.releaseOut.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := h.releaseOut.Close(); err != nil {
		t.Fatal(err)
	}
}

func (h *envelopeLockHelper) wait(t *testing.T) {
	t.Helper()
	if err := h.cmd.Wait(); err != nil {
		t.Fatalf("lock helper failed: %v\n%s", err, h.output.String())
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
