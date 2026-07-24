//go:build windows

package keystore

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

func syncRegistryDirectory(path string) error {
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
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return errors.Join(err, windows.CloseHandle(handle))
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.Join(fmt.Errorf("%q is not a directory", path), windows.CloseHandle(handle))
	}
	flushErr := windows.FlushFileBuffers(handle)
	closeErr := windows.CloseHandle(handle)
	return errors.Join(flushErr, closeErr)
}
