package keyenvelope

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEnvironmentOrFilePassphraseSource(t *testing.T) {
	const valueEnv = "TRUSTDB_TEST_PASSPHRASE"
	const fileEnv = "TRUSTDB_TEST_PASSPHRASE_FILE"
	t.Setenv(valueEnv, "direct development passphrase")
	source := EnvironmentOrFilePassphraseSource(valueEnv, fileEnv)
	got, err := source(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("direct development passphrase")) {
		t.Fatalf("direct passphrase = %q", got)
	}
	clearBytes(got)

	file := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(file, []byte("file development passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(valueEnv, "")
	if err := os.Unsetenv(valueEnv); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fileEnv, file)
	got, err = source(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("file development passphrase")) {
		t.Fatalf("file passphrase = %q", got)
	}
	clearBytes(got)

	t.Setenv(valueEnv, "another direct passphrase")
	if _, err := source(context.Background()); !errors.Is(err, ErrPassphraseUnavailable) {
		t.Fatalf("mutually exclusive source error = %v", err)
	}
}

func TestPassphraseFileFailsClosedAndRedactsPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows encrypted envelope storage is unsupported")
	}
	dir := t.TempDir()
	secretName := "private-passphrase-secret"
	path := filepath.Join(dir, secretName)
	if err := os.WriteFile(path, []byte("file development passphrase"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readPassphraseFile(path); !errors.Is(err, ErrPassphraseUnavailable) {
		t.Fatalf("group-readable passphrase error = %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "passphrase-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPassphraseFile(link); !errors.Is(err, ErrPassphraseUnavailable) {
		t.Fatalf("symlink passphrase error = %v", err)
	}
	missing := filepath.Join(dir, secretName+"-missing")
	if _, err := readPassphraseFile(missing); err == nil {
		t.Fatal("missing passphrase file error = nil")
	} else if strings.Contains(err.Error(), filepath.Base(missing)) {
		t.Fatalf("passphrase diagnostic leaked path: %v", err)
	}
}
