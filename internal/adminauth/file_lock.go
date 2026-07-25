package adminauth

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func acquirePolicyFileLock(policyPath string) (func() error, error) {
	dir := filepath.Dir(policyPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return nil, fmt.Errorf("%w: policy parent is not a directory", ErrUnsafeStorage)
	}
	lockPath := policyPath + ".lock"
	file, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	created := err == nil
	if errors.Is(err, fs.ErrExist) {
		file, err = os.OpenFile(lockPath, os.O_RDWR, 0)
	}
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()
	pathInfo, err := os.Lstat(lockPath)
	if err != nil {
		return nil, err
	}
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !fileInfo.Mode().IsRegular() || !os.SameFile(pathInfo, fileInfo) {
		return nil, fmt.Errorf("%w: policy lock is not a stable regular file", ErrUnsafeStorage)
	}
	if created {
		if err := securePolicyFile(file); err != nil {
			return nil, err
		}
	} else if err := validatePolicyFilePermissions(lockPath, fileInfo); err != nil {
		return nil, err
	}
	unlock, err := lockPolicyFile(file)
	if err != nil {
		return nil, err
	}
	closeOnError = false
	return func() error {
		return errors.Join(unlock(), file.Close())
	}, nil
}
