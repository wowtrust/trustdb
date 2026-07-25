//go:build !windows

package adminauth

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func validatePolicyFilePermissions(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("adminauth: policy file must not be accessible by group or other users")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("adminauth: policy file must be owned by the current user")
	}
	return nil
}

func securePolicyFile(file *os.File) error { return file.Chmod(0o600) }

func installPolicyFile(source, target string, replace bool) error {
	if !replace {
		if err := os.Link(source, target); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return fs.ErrExist
			}
			return err
		}
		return os.Remove(source)
	}
	return os.Rename(source, target)
}

func syncPolicyDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
