package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/wowtrust/trustdb/internal/cborx"
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
	abs, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(abs))
	if err != nil {
		return err
	}
	defer root.Close()
	return writeFileAtomicRoot(root, filepath.Base(abs), data, mode)
}

func writeFileAtomicRoot(root *os.Root, name string, data []byte, mode fs.FileMode) error {
	name, err := cleanRootRelativePath(name)
	if err != nil {
		return err
	}
	dir := filepath.Dir(name)
	if err := root.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, tmpName, err := createTempFileRoot(root, dir, filepath.Base(name))
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = root.Remove(tmpName)
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
	if err := renameReplaceRoot(root, tmpName, name); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func createTempFileRoot(root *os.Root, dir, base string) (*os.File, string, error) {
	for range 128 {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, "", err
		}
		name := filepath.Join(dir, "."+base+"."+hex.EncodeToString(suffix[:])+".tmp")
		f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return f, name, nil
		}
		if !os.IsExist(err) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("could not allocate temporary file")
}

func renameReplaceRoot(root *os.Root, src, dst string) error {
	if err := rejectDirectoryTargetRoot(root, dst); err != nil {
		return err
	}
	if err := root.Rename(src, dst); err != nil {
		if os.IsExist(err) {
			if removeErr := root.Remove(dst); removeErr == nil {
				return root.Rename(src, dst)
			}
		}
		return err
	}
	return nil
}

func rejectDirectoryTargetRoot(root *os.Root, name string) error {
	info, err := root.Stat(name)
	if err == nil {
		if info.IsDir() {
			return fmt.Errorf("%s is a directory", name)
		}
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func cleanRootRelativePath(name string) (string, error) {
	clean := filepath.Clean(strings.TrimSpace(name))
	if clean == "." || clean == ".." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("path must stay within the selected directory")
	}
	return clean, nil
}

func (a *App) rememberSavePath(path string) (string, error) {
	abs, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	a.savePathMu.Lock()
	defer a.savePathMu.Unlock()
	if len(a.savePaths) >= 64 {
		clear(a.savePaths)
	}
	a.savePaths[abs] = abs
	return abs, nil
}

func (a *App) consumeSavePath(path string) (string, error) {
	abs, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	a.savePathMu.Lock()
	defer a.savePathMu.Unlock()
	authorized, ok := a.savePaths[abs]
	if !ok {
		return "", errors.New("output path was not selected with the native save dialog")
	}
	delete(a.savePaths, abs)
	return authorized, nil
}

func (a *App) writeAuthorizedFile(path string, data []byte, mode fs.FileMode) error {
	authorized, err := a.consumeSavePath(path)
	if err != nil {
		return err
	}
	return writeFileAtomic(authorized, data, mode)
}
