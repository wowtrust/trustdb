//go:build windows

package wal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSyncDirectoryWindows(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := syncDirectory(dir); err != nil {
		t.Fatalf("syncDirectory(%q) error = %v", dir, err)
	}
	path := filepath.Join(dir, "regular-file")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}
	if err := syncDirectory(path); err == nil {
		t.Fatal("syncDirectory(regular file) error = nil, want type rejection")
	}
}
