//go:build unix

package wal

import (
	"errors"
	"fmt"
	"os"
)

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	info, statErr := dir.Stat()
	if statErr != nil {
		return errors.Join(statErr, dir.Close())
	}
	if !info.IsDir() {
		return errors.Join(fmt.Errorf("%q is not a directory", path), dir.Close())
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	return errors.Join(syncErr, closeErr)
}
