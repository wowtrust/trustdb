//go:build cgo && windows

package csdk

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTrustDBLoadedLibraryPathUsesReleaseFilename(t *testing.T) {
	path, err := LoadedLibraryPath()
	if err != nil {
		t.Fatal(err)
	}
	if got := filepath.Base(path); !strings.EqualFold(got, "bcos-c-sdk.dll") {
		t.Fatalf("loaded DLL filename = %q, want the long release filename", got)
	}
}
