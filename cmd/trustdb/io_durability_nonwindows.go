//go:build !windows

package main

import (
	"errors"
	"os"
)

func replaceFileDurable(source, target string) error {
	return os.Rename(source, target)
}

func syncDirectoryDurable(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
