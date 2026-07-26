package proofstore

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/trusterr"
)

func TestLocalStoreRejectsSymlinkRootAndLockFile(t *testing.T) {
	t.Run("root symlink", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(t.TempDir(), "root-link")
		if err := os.Symlink(target, root); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlink unavailable: %v", err)
			}
			t.Fatal(err)
		}
		if _, err := OpenLocalStore(root, cryptosuite.INTLV1, "node", "log", "namespace"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("root symlink code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})

	t.Run("lock symlink", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "store")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, localNamespaceLockFile)); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlink unavailable: %v", err)
			}
			t.Fatal(err)
		}
		if _, err := OpenLocalStore(root, cryptosuite.INTLV1, "node", "log", "namespace"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("lock symlink code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})

	t.Run("lock directory", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "store")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(root, localNamespaceLockFile), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenLocalStore(root, cryptosuite.INTLV1, "node", "log", "namespace"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("lock directory code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
}
