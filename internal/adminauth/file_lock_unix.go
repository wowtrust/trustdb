//go:build !windows

package adminauth

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockPolicyFile(file *os.File) (func() error, error) {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}
	return func() error {
		return unix.Flock(int(file.Fd()), unix.LOCK_UN)
	}, nil
}
