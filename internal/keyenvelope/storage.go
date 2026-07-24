package keyenvelope

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// WriteFile installs a new envelope without replacing an existing path.
func WriteFile(path string, data []byte) error {
	if !storageSupported() {
		return errors.ErrUnsupported
	}
	if err := validateStoredEnvelope(data); err != nil {
		return err
	}
	return withEnvelopeLock(context.Background(), path, func() error {
		return writeFileAtomic(path, data, 0o600, false)
	})
}

// UpdateFile serializes the complete read/authenticate/transform/replace
// transaction with an OS-level adjacent lock. The callback always receives
// the current bytes after the lock is held, so a process cannot publish an
// envelope computed from stale pre-lock state.
func UpdateFile(ctx context.Context, path string, update func([]byte) ([]byte, error)) error {
	if !storageSupported() {
		return errors.ErrUnsupported
	}
	if update == nil {
		return errors.New("software key envelope update is nil")
	}
	return withEnvelopeLock(ctx, path, func() error {
		current, err := readFile(path)
		if err != nil {
			return err
		}
		defer clearBytes(current)
		next, err := update(current)
		if err != nil {
			clearBytes(next)
			return err
		}
		defer clearBytes(next)
		if err := validateStoredEnvelope(next); err != nil {
			return err
		}
		return writeFileAtomic(path, next, 0o600, true)
	})
}

func validateStoredEnvelope(data []byte) error {
	envelope, err := Unmarshal(data)
	if err != nil {
		return err
	}
	clearEnvelope(&envelope)
	return nil
}

func ReadFile(path string) ([]byte, error) {
	if !storageSupported() {
		return nil, errors.ErrUnsupported
	}
	return readFile(path)
}

func readFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, secretSafePathError("inspect software key envelope", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: envelope is not a regular file", ErrUnsafeEnvelopeStorage)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, secretSafePathError("open software key envelope", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, secretSafePathError("stat software key envelope", err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(before, info) {
		return nil, fmt.Errorf("%w: envelope is not a regular file", ErrUnsafeEnvelopeStorage)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: envelope permissions grant group or other access", ErrUnsafeEnvelopeStorage)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxEnvelopeBytes+1))
	if err != nil {
		return nil, secretSafePathError("read software key envelope", err)
	}
	if len(data) == 0 || len(data) > maxEnvelopeBytes {
		clearBytes(data)
		return nil, fmt.Errorf("%w: envelope size is invalid", ErrUnsafeEnvelopeStorage)
	}
	return data, nil
}

func writeFileAtomic(path string, data []byte, mode fs.FileMode, replace bool) error {
	if len(data) == 0 || len(data) > maxEnvelopeBytes {
		return invalid("encoded envelope size is invalid")
	}
	dir := filepath.Dir(path)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: target is not a regular file", ErrUnsafeEnvelopeStorage)
		}
		if !replace {
			return fs.ErrExist
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%w: target permissions grant group or other access", ErrUnsafeEnvelopeStorage)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return secretSafePathError("inspect software key envelope", err)
	} else if replace {
		return fs.ErrNotExist
	}
	tmp, err := os.CreateTemp(dir, ".trustdb-key-envelope-*.tmp")
	if err != nil {
		return secretSafePathError("create software key envelope", err)
	}
	tmpPath := tmp.Name()
	closed := false
	cleanup := true
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return secretSafePathError("set software key envelope permissions", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return secretSafePathError("write software key envelope", err)
	}
	if err := tmp.Sync(); err != nil {
		return secretSafePathError("sync software key envelope", err)
	}
	if err := tmp.Close(); err != nil {
		closed = true
		return secretSafePathError("close software key envelope", err)
	}
	closed = true
	if replace {
		err = atomicReplace(tmpPath, path)
	} else {
		err = atomicInstall(tmpPath, path)
	}
	if err != nil {
		return secretSafePathError("install software key envelope", err)
	}
	cleanup = false
	if err := syncDirectory(dir); err != nil {
		return secretSafePathError("sync software key envelope directory", err)
	}
	return nil
}

func withEnvelopeLock(ctx context.Context, path string, action func() error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	release, err := acquireEnvelopeLock(ctx, path)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, release())
	}()
	return action()
}

func secretSafePathError(action string, err error) error {
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		return fmt.Errorf("%s: %w", action, pathError.Err)
	}
	return fmt.Errorf("%s: operation failed", action)
}
