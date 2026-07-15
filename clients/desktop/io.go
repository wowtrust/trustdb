package main

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
)

// marshalCBOR keeps a single import path for CBOR output so future
// replacements (e.g. switching to a deterministic encoder) only
// touch one file in the desktop package.
func marshalCBOR(v any) ([]byte, error) {
	return cborx.Marshal(v)
}

// writeFileAtomic writes to a sibling ".tmp" file and renames into
// place, matching the behaviour of the TrustDB server's disk stores
// so an interrupted export never leaves a half-written file the
// user might mistake for a valid proof.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := renameReplace(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func renameReplace(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		if os.IsExist(err) {
			if removeErr := os.Remove(dst); removeErr == nil {
				return os.Rename(src, dst)
			}
		}
		return err
	}
	return nil
}
