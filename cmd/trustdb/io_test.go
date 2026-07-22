package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/wowtrust/trustdb/internal/cborx"
)

func TestReadFileLimitBoundsInputBeforeDecode(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "input.bin")
	data := bytes.Repeat([]byte{0x42}, 32)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile(input) error = %v", err)
	}
	got, err := readFileLimit(path, int64(len(data)))
	if err != nil {
		t.Fatalf("readFileLimit(exact boundary) error = %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("readFileLimit() = %x, want %x", got, data)
	}

	if err := os.WriteFile(path, append(data, 0x43), 0o600); err != nil {
		t.Fatalf("WriteFile(oversized) error = %v", err)
	}
	if _, err := readFileLimit(path, int64(len(data))); err == nil {
		t.Fatal("readFileLimit(oversized) error = nil")
	}
}

func TestCLIInputHelpersRejectOversizedFiles(t *testing.T) {
	t.Parallel()

	cborPath := filepath.Join(t.TempDir(), "oversized.tdproof")
	if err := os.WriteFile(cborPath, bytes.Repeat([]byte{0x42}, cborx.DefaultMaxBytes+1), 0o600); err != nil {
		t.Fatalf("WriteFile(CBOR) error = %v", err)
	}
	var decoded map[string]any
	if err := readCBORFile(cborPath, &decoded); err == nil {
		t.Fatal("readCBORFile(oversized) error = nil")
	}

	keyPath := filepath.Join(t.TempDir(), "oversized.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{'A'}, maxEncodedKeyFileBytes+1), 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}
	if _, err := readKey(keyPath); err == nil {
		t.Fatal("readKey(oversized) error = nil")
	}
}

func TestWriteFileAtomicReplacesFileAndCleansTemp(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "artifact.json")
	if err := writeFileAtomic(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic(old) error = %v", err)
	}
	if err := writeFileAtomic(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic(new) error = %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("file content = %q, want new", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %v, want 0600", info.Mode().Perm())
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", matches)
	}
}

func TestWriteFileAtomicRejectsDirectoryTarget(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "artifact.json")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}

	if err := writeFileAtomic(path, []byte("new"), 0o600); err == nil {
		t.Fatalf("writeFileAtomic() error = nil, want directory target error")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(target) error = %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("target directory was replaced")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", matches)
	}
}
