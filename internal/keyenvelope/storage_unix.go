//go:build unix

package keyenvelope

import "os"

func storageSupported() bool { return true }

func atomicInstall(src, dst string) error {
	if err := os.Link(src, dst); err != nil {
		return err
	}
	return os.Remove(src)
}

func atomicReplace(src, dst string) error {
	return os.Rename(src, dst)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}
