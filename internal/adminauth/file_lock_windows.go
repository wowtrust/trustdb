//go:build windows

package adminauth

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockPolicyFile(file *os.File) (func() error, error) {
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, overlapped); err != nil {
		return nil, err
	}
	return func() error {
		return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, overlapped)
	}, nil
}
