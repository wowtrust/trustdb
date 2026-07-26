//go:build sdf && cgo && (linux || darwin)

package sdfsigner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/v2/sdk/signerplugin"
)

func TestNativeAdapterABIContract(t *testing.T) {
	library := buildFakeNativeAdapter(t)
	backend, err := OpenNativeBackend(library, []byte("normal"))
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	device, err := backend.Discover(context.Background(), "sdf-production")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := device.Identity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if identity.DeviceID != "sdf-production" || identity.AdapterID != "trustdb.fake-sdf" {
		t.Fatalf("identity = %+v", identity)
	}
	capabilities, err := device.Capabilities(context.Background())
	if err != nil || capabilities != AllCapabilities {
		t.Fatalf("capabilities = %#x, %v", capabilities, err)
	}
	session, err := device.OpenSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte("846295")
	publicKey, err := session.PublicKey(context.Background(), 7, credential)
	if err != nil || len(publicKey) != 65 {
		t.Fatalf("PublicKey() = %x, %v", publicKey, err)
	}
	digest := make([]byte, 32)
	for index := range digest {
		digest[index] = byte(index)
	}
	signature, err := session.SignSM2Digest(context.Background(), 7, credential, digest)
	if err != nil || len(signature) != 64 ||
		string(signature[:32]) != string(digest) || string(signature[32:]) != string(digest) {
		t.Fatalf("SignSM2Digest() = %x, %v", signature, err)
	}
	random, err := session.Random(context.Background(), 64)
	if err != nil || len(random) != 64 || random[1] != 0xa4 {
		t.Fatalf("Random() = %x, %v", random, err)
	}
	wrapped, generated, err := session.GenerateSM4KeyWithKEK(context.Background(), 11, credential)
	if err != nil || len(wrapped) != 17 || generated.value == 0 {
		t.Fatalf("GenerateSM4KeyWithKEK() = %x, %#v, %v", wrapped, generated, err)
	}
	iv := []byte("0123456789abcdef")
	plaintext := []byte("block-0000000001")
	ciphertext, err := session.EncryptSM4CBC(context.Background(), generated, iv, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := session.DecryptSM4CBC(context.Background(), generated, iv, ciphertext)
	if err != nil || string(roundTrip) != string(plaintext) {
		t.Fatalf("DecryptSM4CBC() = %q, %v", roundTrip, err)
	}
	if err := session.DestroySessionKey(context.Background(), generated); err != nil {
		t.Fatal(err)
	}
	imported, err := session.ImportSM4KeyWithKEK(context.Background(), 11, credential, wrapped)
	if err != nil || imported.value == 0 {
		t.Fatalf("ImportSM4KeyWithKEK() = %#v, %v", imported, err)
	}
	mac, err := session.CalculateSM4MAC(context.Background(), imported, iv, plaintext)
	if err != nil || len(mac) != SM4BlockBytes {
		t.Fatalf("CalculateSM4MAC() = %x, %v", mac, err)
	}
	if err := session.DestroySessionKey(context.Background(), imported); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeAdapterRejectsMalformedIdentityAndSanitizesStatus(t *testing.T) {
	library := buildFakeNativeAdapter(t)
	t.Run("identity", func(t *testing.T) {
		backend, err := OpenNativeBackend(library, []byte("bad-identity"))
		if err != nil {
			t.Fatal(err)
		}
		defer backend.Close()
		device, err := backend.Discover(context.Background(), "sdf-production")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := device.Identity(context.Background()); err == nil {
			t.Fatal("Identity() accepted a non-terminated native field")
		}
	})
	t.Run("status", func(t *testing.T) {
		backend, err := OpenNativeBackend(library, []byte("health=busy"))
		if err != nil {
			t.Fatal(err)
		}
		defer backend.Close()
		device, _ := backend.Discover(context.Background(), "sdf-production")
		session, _ := device.OpenSession(context.Background())
		defer session.Close()
		err = session.Health(context.Background())
		var fault *Fault
		if !errors.As(err, &fault) || fault.class != faultBusy {
			t.Fatalf("Health() error = %v", err)
		}
		if strings.Contains(err.Error(), "busy") || strings.Contains(err.Error(), "health") {
			t.Fatalf("native diagnostic leaked: %v", err)
		}
	})
}

func TestOpenNativeBackendRejectsNonAdapterLibraryWithoutPathLeak(t *testing.T) {
	path := "/definitely/not/a/customer-secret-adapter.so"
	_, err := OpenNativeBackend(path, []byte("normal"))
	requireProviderCode(t, providerError(err), signerplugin.ErrorUnavailable)
	if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "customer-secret") {
		t.Fatalf("loader error leaked path: %v", err)
	}
}

func TestNativeSessionCloseWaitsForInFlightCall(t *testing.T) {
	library := buildFakeNativeAdapter(t)
	entered := filepath.Join(t.TempDir(), "entered")
	release := filepath.Join(t.TempDir(), "release")
	t.Setenv("TRUSTDB_SDF_FAKE_RANDOM_ENTERED", entered)
	t.Setenv("TRUSTDB_SDF_FAKE_RANDOM_RELEASE", release)
	backend, err := OpenNativeBackend(library, []byte("random=blocking"))
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	device, err := backend.Discover(context.Background(), "sdf-production")
	if err != nil {
		t.Fatal(err)
	}
	session, err := device.OpenSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	randomDone := make(chan error, 1)
	go func() {
		_, randomErr := session.Random(context.Background(), 64)
		randomDone <- randomErr
	}()
	waitForFile(t, entered)
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- session.Close()
	}()
	select {
	case closeErr := <-closeDone:
		t.Fatalf("Close() returned while native call was in flight: %v", closeErr)
	case <-time.After(50 * time.Millisecond):
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-randomDone; err != nil {
		t.Fatalf("Random() = %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if _, err := session.Random(context.Background(), 1); err == nil {
		t.Fatal("Random() succeeded after Close()")
	}
}

func TestNativeBackendCloseClosesSessionsBeforeDevice(t *testing.T) {
	library := buildFakeNativeAdapter(t)
	backend, err := OpenNativeBackend(library, []byte("normal"))
	if err != nil {
		t.Fatal(err)
	}
	device, err := backend.Discover(context.Background(), "sdf-production")
	if err != nil {
		t.Fatal(err)
	}
	first, err := device.OpenSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := device.OpenSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatalf("backend Close() = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close() after backend Close() = %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("second Close() after backend Close() = %v", err)
	}
	if err := backend.Close(); err != nil {
		t.Fatalf("second backend Close() = %v", err)
	}
}

func TestNativeBackendCloseWaitsForInFlightCall(t *testing.T) {
	library := buildFakeNativeAdapter(t)
	entered := filepath.Join(t.TempDir(), "entered")
	release := filepath.Join(t.TempDir(), "release")
	t.Setenv("TRUSTDB_SDF_FAKE_RANDOM_ENTERED", entered)
	t.Setenv("TRUSTDB_SDF_FAKE_RANDOM_RELEASE", release)
	backend, err := OpenNativeBackend(library, []byte("random=blocking"))
	if err != nil {
		t.Fatal(err)
	}
	device, err := backend.Discover(context.Background(), "sdf-production")
	if err != nil {
		t.Fatal(err)
	}
	session, err := device.OpenSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	randomDone := make(chan error, 1)
	go func() {
		_, randomErr := session.Random(context.Background(), 64)
		randomDone <- randomErr
	}()
	waitForFile(t, entered)
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- backend.Close()
	}()
	select {
	case closeErr := <-closeDone:
		t.Fatalf("backend Close() returned while native call was in flight: %v", closeErr)
	case <-time.After(50 * time.Millisecond):
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-randomDone; err != nil {
		t.Fatalf("Random() = %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("backend Close() = %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("session Close() after backend Close() = %v", err)
	}
}

func TestNativeBackendCloseWaitsForOpeningSession(t *testing.T) {
	library := buildFakeNativeAdapter(t)
	entered := filepath.Join(t.TempDir(), "entered")
	release := filepath.Join(t.TempDir(), "release")
	t.Setenv("TRUSTDB_SDF_FAKE_OPEN_SESSION_ENTERED", entered)
	t.Setenv("TRUSTDB_SDF_FAKE_OPEN_SESSION_RELEASE", release)
	backend, err := OpenNativeBackend(library, []byte("session=blocking"))
	if err != nil {
		t.Fatal(err)
	}
	device, err := backend.Discover(context.Background(), "sdf-production")
	if err != nil {
		t.Fatal(err)
	}
	sessionDone := make(chan Session, 1)
	sessionError := make(chan error, 1)
	go func() {
		session, openErr := device.OpenSession(context.Background())
		sessionDone <- session
		sessionError <- openErr
	}()
	waitForFile(t, entered)
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- backend.Close()
	}()
	select {
	case closeErr := <-closeDone:
		t.Fatalf("backend Close() returned while session was opening: %v", closeErr)
	case <-time.After(50 * time.Millisecond):
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	session := <-sessionDone
	if err := <-sessionError; err != nil {
		t.Fatalf("OpenSession() = %v", err)
	}
	if session == nil {
		t.Fatal("OpenSession() returned a nil session")
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("backend Close() = %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("session Close() after backend Close() = %v", err)
	}
	if _, err := device.OpenSession(context.Background()); err == nil {
		t.Fatal("OpenSession() succeeded after backend Close()")
	}
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", filepath.Base(path))
		}
		time.Sleep(time.Millisecond)
	}
}

func buildFakeNativeAdapter(t *testing.T) string {
	t.Helper()
	output := filepath.Join(t.TempDir(), "libtrustdb-fake-sdf.so")
	args := []string{
		"-shared", "-fPIC",
		"-I", filepath.Join("..", "..", "sdk", "sdfadapter"),
		"-o", output,
		filepath.Join("testdata", "fake_adapter.c"),
	}
	if runtime.GOOS == "darwin" {
		args[0] = "-dynamiclib"
	}
	command := exec.Command("cc", args...)
	if outputBytes, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile fake adapter: %v\n%s", err, outputBytes)
	}
	return output
}
