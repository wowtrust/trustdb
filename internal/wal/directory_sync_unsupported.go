//go:build !unix && !windows

package wal

import (
	"errors"
	"fmt"
	"runtime"
)

func syncDirectory(string) error {
	return fmt.Errorf("wal: directory synchronization on %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
