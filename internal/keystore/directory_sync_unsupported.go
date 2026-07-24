//go:build !unix && !windows

package keystore

import (
	"errors"
	"fmt"
	"runtime"
)

func syncRegistryDirectory(string) error {
	return fmt.Errorf("keystore: directory synchronization on %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
