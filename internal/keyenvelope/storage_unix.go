//go:build unix

package keyenvelope

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func storageSupported() bool { return true }

func secureEnvelopeFile(file *os.File, mode fs.FileMode) error {
	if err := file.Chmod(mode); err != nil {
		return secretSafePathError("set software key envelope permissions", err)
	}
	info, err := file.Stat()
	if err != nil {
		return secretSafePathError("stat software key envelope", err)
	}
	return validateEnvelopeFile(file, info)
}

func validateEnvelopeFile(_ *os.File, info fs.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: envelope permissions grant group or other access", ErrUnsafeEnvelopeStorage)
	}
	return nil
}

func acquireEnvelopeLock(ctx context.Context, path string) (func() error, error) {
	lockPath := path + ".lock"
	fd, err := unix.Open(lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, secretSafePathError("open software key envelope lock", err)
	}
	file := os.NewFile(uintptr(fd), lockPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: create lock handle", ErrUnsafeEnvelopeStorage)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, secretSafePathError("stat software key envelope lock", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("%w: lock file is unsafe", ErrUnsafeEnvelopeStorage)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = file.Close()
			return nil, secretSafePathError("lock software key envelope", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
	return func() error {
		return errors.Join(unix.Flock(fd, unix.LOCK_UN), file.Close())
	}, nil
}

func atomicInstall(src, dst string) error {
	if err := os.Link(src, dst); err != nil {
		return err
	}
	return os.Remove(src)
}

func atomicReplace(src, dst string) error {
	return os.Rename(src, dst)
}

func removeFileDurable(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}
