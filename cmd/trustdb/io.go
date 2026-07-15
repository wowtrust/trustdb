package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
	"github.com/spf13/cobra"
)

const encodedOutputNamePrefix = "~"

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
	data, err := os.ReadFile(path)
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
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func writeJSONFile(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
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
	return os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600)
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
	data, err := os.ReadFile(path)
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

func stringOrConfig(cmd *cobra.Command, rt *runtimeConfig, flagName, flagValue, key string) string {
	if cmd.Flags().Changed(flagName) {
		return flagValue
	}
	return configString(rt.cfg, key)
}
