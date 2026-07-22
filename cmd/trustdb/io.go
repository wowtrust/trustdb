package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"github.com/spf13/cobra"
)

const (
	encodedOutputNamePrefix = "~"
	maxEncodedKeyFileBytes  = 1 << 10
)

type multiFlag []string

func (m *multiFlag) String() string {
	return fmt.Sprint([]string(*m))
}

func (m *multiFlag) Set(value string) error {
	if value == "" {
		return fmt.Errorf("empty value")
	}
	*m = append(*m, value)
	return nil
}

func (m *multiFlag) Type() string {
	return "stringArray"
}

func usageError(message string) error {
	return trusterr.New(trusterr.CodeInvalidArgument, message)
}

func ensureDir(path string) error {
	if path == "" {
		path = "."
	}
	return os.MkdirAll(path, 0o755)
}

func joinPath(parts ...string) string {
	return filepath.Join(parts...)
}

func safeOutputFileName(value string) string {
	if isPlainOutputFileName(value) {
		return value
	}
	return encodedOutputNamePrefix + base64.RawURLEncoding.EncodeToString([]byte(value))
}

func isPlainOutputFileName(value string) bool {
	if value == "" || value == "." || value == ".." || strings.HasPrefix(value, ".") {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func readCBORFile(path string, v any) error {
	data, err := readFileLimit(path, int64(cborx.DefaultMaxBytes))
	if err != nil {
		return err
	}
	return cborx.Unmarshal(data, v)
}

func writeCBORFile(path string, v any) error {
	data, err := cborx.Marshal(v)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0o600)
}

func writeJSONFile(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileAtomic(path, data, 0o600)
}

func resolveExportFormat(format, outPath string) (string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		if strings.TrimSpace(outPath) == "" {
			return "json", nil
		}
		return "cbor", nil
	}
	switch format {
	case "json", "cbor":
		return format, nil
	default:
		return "", usageError("--format must be json or cbor")
	}
}

func writeExportObject(rt *runtimeConfig, outPath, format string, v any) (string, error) {
	resolved, err := resolveExportFormat(format, outPath)
	if err != nil {
		return "", err
	}
	switch resolved {
	case "json":
		if outPath == "" {
			return resolved, rt.writeJSON(v)
		}
		return resolved, writeJSONFile(outPath, v)
	case "cbor":
		if outPath == "" {
			data, err := cborx.Marshal(v)
			if err != nil {
				return "", err
			}
			_, err = rt.out.Write(data)
			return resolved, err
		}
		return resolved, writeCBORFile(outPath, v)
	default:
		return "", usageError("--format must be json or cbor")
	}
}

func writeKey(path string, key []byte) error {
	return writeFileAtomic(path, []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600)
}

func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := ensureDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	closed := false
	cleanup := true
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
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
		closed = true
		return err
	}
	closed = true
	if err := renameReplace(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func renameReplace(src, dst string) error {
	if err := rejectDirectoryTarget(dst); err != nil {
		return err
	}
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

func rejectDirectoryTarget(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return fmt.Errorf("%s is a directory", path)
		}
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func readPublicKey(path string) (ed25519.PublicKey, error) {
	key, err := readKey(path)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size %d", len(key))
	}
	return ed25519.PublicKey(key), nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	key, err := readKey(path)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size %d", len(key))
	}
	return ed25519.PrivateKey(key), nil
}

func readKey(path string) ([]byte, error) {
	data, err := readFileLimit(path, maxEncodedKeyFileBytes)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	key := make([]byte, base64.RawURLEncoding.DecodedLen(len(data)))
	n, err := base64.RawURLEncoding.Decode(key, data)
	if err != nil {
		return nil, err
	}
	return key[:n], nil
}

func readFileLimit(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("max bytes must be positive")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("input file too large: %d > %d", len(data), maxBytes)
	}
	return data, nil
}

func stringOrConfig(cmd *cobra.Command, rt *runtimeConfig, flagName, flagValue, key string) string {
	if cmd.Flags().Changed(flagName) {
		return flagValue
	}
	return configString(rt.cfg, key)
}
