package objectstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalStorePutRejectsDirectoryObjectTarget(t *testing.T) {
	t.Parallel()

	raw := []byte("object store payload")
	sum := sha256.Sum256(raw)
	hexSum := hex.EncodeToString(sum[:])
	store := LocalStore{Root: t.TempDir()}
	target := store.pathForHex(hexSum)
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll(target) error = %v", err)
	}

	if _, err := store.Put(context.Background(), bytes.NewReader(raw)); err == nil {
		t.Fatalf("Put() error = nil, want directory target error")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat(target) error = %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("target directory was replaced")
	}
	matches, err := filepath.Glob(filepath.Join(store.Root, "put-*.tmp"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", matches)
	}
}
