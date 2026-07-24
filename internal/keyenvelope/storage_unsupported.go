//go:build !unix && !windows

package keyenvelope

import (
	"context"
	"errors"
)

func storageSupported() bool { return false }

func acquireEnvelopeLock(ctx context.Context, path string) (func() error, error) {
	return nil, errors.ErrUnsupported
}

func atomicInstall(src, dst string) error {
	return errors.ErrUnsupported
}

func atomicReplace(src, dst string) error {
	return errors.ErrUnsupported
}

func syncDirectory(path string) error {
	return errors.ErrUnsupported
}
