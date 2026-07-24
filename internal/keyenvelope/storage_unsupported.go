//go:build !unix && !windows

package keyenvelope

import (
	"errors"
)

func storageSupported() bool { return false }

func atomicInstall(src, dst string) error {
	return errors.ErrUnsupported
}

func atomicReplace(src, dst string) error {
	return errors.ErrUnsupported
}

func syncDirectory(path string) error {
	return errors.ErrUnsupported
}
