//go:build unix

package keystore

import (
	"errors"
	"fmt"
	"os"
)

func syncRegistryDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	info, statErr := directory.Stat()
	if statErr != nil {
		return errors.Join(statErr, directory.Close())
	}
	if !info.IsDir() {
		return errors.Join(fmt.Errorf("%q is not a directory", path), directory.Close())
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}
