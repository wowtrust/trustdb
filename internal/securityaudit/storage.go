package securityaudit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func openProtectedAppend(path string) (*os.File, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: parent is not a stable directory", ErrUnsafeStorage)
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := validateStableProtectedFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func openProtectedExisting(path string) (*os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if err := validateStableProtectedFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateStableProtectedFile(path string, file *os.File) error {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !fileInfo.Mode().IsRegular() || !os.SameFile(pathInfo, fileInfo) {
		return fmt.Errorf("%w: target is not a stable regular file", ErrUnsafeStorage)
	}
	if err := secureAuditFile(file); err != nil {
		return err
	}
	return validateAuditFilePermissions(path, fileInfo)
}

func acquireLock(path string) (func() error, error) {
	file, err := openProtectedAppend(path + ".lock")
	if err != nil {
		return nil, err
	}
	unlock, err := lockAuditFile(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() error { return errors.Join(unlock(), file.Close()) }, nil
}

func writeProtectedAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if target, err := os.Lstat(path); err == nil {
		if target.Mode()&os.ModeSymlink != 0 || !target.Mode().IsRegular() {
			return fmt.Errorf("%w: atomic target is not a regular file", ErrUnsafeStorage)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := file.Name()
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()
	if err := secureAuditFile(file); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := installAuditFile(tmp, path); err != nil {
		return err
	}
	if err := syncAuditDirectory(dir); err != nil {
		return err
	}
	cleanup = false
	return nil
}
