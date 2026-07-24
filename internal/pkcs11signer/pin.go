package pkcs11signer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

const maxPINBytes = 1024

// FilePINSource reads an owner-controlled regular file on every login. The
// path and PIN are never included in returned errors.
type FilePINSource struct {
	path string
}

func NewFilePINSource(path string) (*FilePINSource, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: TRUSTDB_PKCS11_PIN_FILE is required", ErrInvalidConfiguration)
	}
	return &FilePINSource{path: path}, nil
}

func (s *FilePINSource) Read(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.path == "" {
		return nil, newFault(faultAuthentication)
	}
	before, err := os.Lstat(s.path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, newFault(faultAuthentication)
	}
	if !pinFilePermissionsSafe(before) {
		return nil, newFault(faultAuthentication)
	}
	file, err := os.Open(s.path)
	if err != nil {
		return nil, newFault(faultAuthentication)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, newFault(faultAuthentication)
	}
	pin, err := io.ReadAll(io.LimitReader(file, maxPINBytes+1))
	if err != nil || len(pin) == 0 || len(pin) > maxPINBytes {
		clear(pin)
		return nil, newFault(faultAuthentication)
	}
	pin = bytes.TrimSuffix(pin, []byte("\n"))
	pin = bytes.TrimSuffix(pin, []byte("\r"))
	if len(pin) == 0 || bytes.IndexByte(pin, 0) >= 0 {
		clear(pin)
		return nil, newFault(faultAuthentication)
	}
	if err := ctx.Err(); err != nil {
		clear(pin)
		return nil, err
	}
	out := append([]byte(nil), pin...)
	clear(pin)
	return out, nil
}

// StaticPINSource is intentionally unexported from production configuration.
// It exists only to make the portable fake-token contract deterministic.
type staticPINSource []byte

func (s staticPINSource) Read(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(s) == 0 {
		return nil, errors.New("test PIN is empty")
	}
	return append([]byte(nil), s...), nil
}
