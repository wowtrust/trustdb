//go:build windows

package keyenvelope

import (
	"context"
	"errors"

	"golang.org/x/sys/windows"
)

// Windows envelope storage fails closed until the project can continuously
// runtime-qualify an owner-only DACL across supported Windows editions and
// filesystems. Plaintext-dev and external non-software providers are separate
// explicit paths.
func storageSupported() bool { return false }

func acquireEnvelopeLock(ctx context.Context, path string) (func() error, error) {
	return nil, errors.ErrUnsupported
}

func atomicInstall(src, dst string) error {
	return moveFile(src, dst, windows.MOVEFILE_WRITE_THROUGH)
}

func atomicReplace(src, dst string) error {
	return moveFile(src, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func moveFile(src, dst string, flags uint32) error {
	source, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(source, target, flags)
}

func syncDirectory(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return err
	}
	flushErr := windows.FlushFileBuffers(handle)
	closeErr := windows.CloseHandle(handle)
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}
