//go:build !unix && !windows

package keyenvelope

import (
	"context"
	"errors"
	"io/fs"
	"os"
)

func storageSupported() bool { return false }

func secureEnvelopeFile(*os.File, fs.FileMode) error { return errors.ErrUnsupported }

func validateEnvelopeFile(*os.File, fs.FileInfo) error { return errors.ErrUnsupported }

func acquireEnvelopeLock(ctx context.Context, path string) (func() error, error) {
	return nil, errors.ErrUnsupported
}

func atomicInstall(src, dst string) error {
	return errors.ErrUnsupported
}

func atomicReplace(src, dst string) error {
	return errors.ErrUnsupported
}

func removeFileDurable(path string) error {
	return errors.ErrUnsupported
}

func syncDirectory(path string) error {
	return errors.ErrUnsupported
}
