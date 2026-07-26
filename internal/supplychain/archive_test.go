package supplychain

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteArchiveIsReproducible(t *testing.T) {
	for _, format := range []string{"tar.gz", "zip"} {
		t.Run(format, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "trustdb-1.0.0-linux-amd64")
			if err := os.MkdirAll(filepath.Join(source, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, filepath.Join(source, "README.md"), "release")
			writeTestFile(t, filepath.Join(source, "bin", "trustdb"), "binary")
			if err := os.Chmod(filepath.Join(source, "README.md"), 0o600); err != nil {
				t.Fatal(err)
			}
			first := filepath.Join(root, "first."+format)
			second := filepath.Join(root, "second."+format)
			if err := WriteArchive(source, first, format, "2026-07-25T10:00:00Z"); err != nil {
				t.Fatal(err)
			}
			later := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
			if err := os.Chtimes(filepath.Join(source, "README.md"), later, later); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(source, "README.md"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := WriteArchive(source, second, format, "2026-07-25T10:00:00Z"); err != nil {
				t.Fatal(err)
			}
			firstBytes, err := os.ReadFile(first)
			if err != nil {
				t.Fatal(err)
			}
			secondBytes, err := os.ReadFile(second)
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(firstBytes) != sha256.Sum256(secondBytes) {
				t.Fatalf("%s archive is not reproducible", format)
			}
		})
	}
}

func TestWriteArchiveRejectsOutputInsideSource(t *testing.T) {
	source := t.TempDir()
	writeTestFile(t, filepath.Join(source, "README.md"), "release")
	err := WriteArchive(source, filepath.Join(source, "release.tar.gz"), "tar.gz", "2026-07-25T10:00:00Z")
	if err == nil {
		t.Fatal("WriteArchive() accepted output inside the source directory")
	}
}
