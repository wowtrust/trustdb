//go:build !windows

package securityaudit

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func secureAuditFile(file *os.File) error { return file.Chmod(0o600) }

func validateAuditFilePermissions(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: file is accessible by group or other users", ErrUnsafeStorage)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: file is not owned by the current user", ErrUnsafeStorage)
	}
	return nil
}

func lockAuditFile(file *os.File) (func() error, error) {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}
	return func() error { return unix.Flock(int(file.Fd()), unix.LOCK_UN) }, nil
}

func installAuditFile(source, target string) error { return os.Rename(source, target) }

func syncAuditDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
