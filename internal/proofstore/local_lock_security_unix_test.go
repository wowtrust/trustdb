//go:build !windows

package proofstore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/trusterr"
)

func TestLocalStoreRejectsInsecureUnixPermissions(t *testing.T) {
	t.Run("writable root", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "store")
		if err := os.Mkdir(root, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenLocalStore(root, cryptosuite.INTLV1, "node", "log", "namespace"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("writable root code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})

	t.Run("broad lock mode", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "store")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, localNamespaceLockFile), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenLocalStore(root, cryptosuite.INTLV1, "node", "log", "namespace"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("broad lock mode code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
}
