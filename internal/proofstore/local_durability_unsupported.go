//go:build !unix && !windows

package proofstore

import (
	"errors"
	"fmt"
	"os"
	"runtime"
)

func replaceLocalFile(source, target string) error {
	return os.Rename(source, target)
}

func syncLocalDirectory(string) error {
	return fmt.Errorf("proofstore directory synchronization on %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
