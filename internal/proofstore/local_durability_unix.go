//go:build unix

package proofstore

import (
	"errors"
	"fmt"
	"os"
)

func replaceLocalFile(source, target string) error {
	return os.Rename(source, target)
}

func syncLocalDirectory(path string) error {
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
	return errors.Join(dir.Sync(), dir.Close())
}
