//go:build windows

package keyenvelope

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestWindowsEnvelopeStorageFailsClosedWithoutQualifiedACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.material")
	if err := WriteFile(path, []byte{0xa0}); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("WriteFile error = %v, want unsupported", err)
	}
	if _, err := ReadFile(path); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("ReadFile error = %v, want unsupported", err)
	}
	if err := UpdateFile(context.Background(), path, func(current []byte) ([]byte, error) {
		return current, nil
	}); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("UpdateFile error = %v, want unsupported", err)
	}
}
