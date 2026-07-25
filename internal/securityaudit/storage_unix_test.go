//go:build !windows

package securityaudit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditRejectsParentDirectoryWritableByOtherUsers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	_, err := OpenWriter(context.Background(), testOptions(
		filepath.Join(dir, "security.audit"),
		filepath.Join(dir, "security.checkpoint"),
		newEd25519Signer(t),
		nil,
	))
	if !errors.Is(err, ErrUnsafeStorage) {
		t.Fatalf("open error=%v, want ErrUnsafeStorage", err)
	}
}
