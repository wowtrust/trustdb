//go:build fiscobcos_sdk && cgo

package standardsdk

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/FISCO-BCOS/bcos-c-sdk/bindings/go/csdk"

	"github.com/wowtrust/trustdb/v2/internal/anchor/fiscobcos"
)

type nativeArtifactPin struct {
	name           string
	size           int64
	sha256         string
	version        string
	commit         string
	reportedCommit string
}

const windowsAMD64ReportedNativeCommit = "73a3f93b2b88bd4af93e1df9c8f8c4f0be57a8ae"

var nativeArtifactPins = map[string]nativeArtifactPin{
	"linux/amd64": {
		name: "libbcos-c-sdk.so", size: 18_160_440,
		sha256:  "b5a2a1606086245cc73d356d70011b32a112a38cf5e6a10631377a4b4a7dec83",
		version: supportedNativeVersion, commit: supportedNativeCommit,
		// The official v3.6.0 linux/amd64 release reports Git Commit "0".
		// Its source commit is therefore bound by the exact artifact digest.
		reportedCommit: "0",
	},
	"linux/arm64": {
		name: "libbcos-c-sdk-aarch64.so", size: 16_632_368,
		sha256:  "8e4e75b64353ac50e0571b7f776cf297fcb7ea3b7e4871d13e29d0b0b29f4a30",
		version: supportedNativeVersion, commit: supportedNativeCommit,
		reportedCommit: supportedNativeCommit,
	},
	"darwin/amd64": {
		name: "libbcos-c-sdk.dylib", size: 22_073_856,
		sha256:  "3d4c51b31709c8814a58c8c6b8c8dbb8174140337590e86b30e8104cd264fc74",
		version: supportedNativeVersion, commit: supportedNativeCommit,
		reportedCommit: supportedNativeCommit,
	},
	"darwin/arm64": {
		name: "libbcos-c-sdk-aarch64.dylib", size: 18_097_480,
		sha256:  "4b9c16fb91e15317408a83fddd08bab33bd35c6b5d1c3482dc538ccf9fe95afc",
		version: supportedNativeVersion, commit: supportedNativeCommit,
		reportedCommit: supportedNativeCommit,
	},
	"windows/amd64": {
		name: "bcos-c-sdk.dll", size: 14_499_328,
		sha256:  "2e805fa3cb79e441059e69e981a3d23f1613e7006594d929aa83bec1a0f3a751",
		version: supportedNativeVersion, commit: supportedNativeCommit,
		// The official Windows DLL embeds a platform build commit that differs
		// from the v3.6.0 source provenance. The exact DLL digest binds the two.
		reportedCommit: windowsAMD64ReportedNativeCommit,
	},
}

func observeAndVerifyNativeRuntime() (string, error) {
	version, err := csdk.Version()
	if err != nil {
		return "", fmt.Errorf("%w: observe native version: %v", fiscobcos.ErrUnsupportedSDK, err)
	}
	path, err := csdk.LoadedLibraryPath()
	if err != nil {
		return "", fmt.Errorf("%w: observe native artifact: %v", fiscobcos.ErrUnsupportedSDK, err)
	}
	pin, ok := nativeArtifactPins[runtime.GOOS+"/"+runtime.GOARCH]
	if !ok {
		return "", fmt.Errorf("%w: platform %s/%s", fiscobcos.ErrUnsupportedSDK, runtime.GOOS, runtime.GOARCH)
	}
	return verifyNativeRuntime(version, path, pin)
}

func verifyNativeRuntime(versionText, artifactPath string, pin nativeArtifactPin) (string, error) {
	version, reportedCommit, err := parseNativeVersion(versionText)
	if err != nil {
		return "", fmt.Errorf("%w: %v", fiscobcos.ErrUnsupportedSDK, err)
	}
	if pin.version != supportedNativeVersion ||
		pin.commit != supportedNativeCommit ||
		pin.reportedCommit == "" {
		return "", fmt.Errorf("%w: native artifact provenance pin is invalid", fiscobcos.ErrUnsupportedSDK)
	}
	if version != pin.version || reportedCommit != pin.reportedCommit {
		return "", fmt.Errorf(
			"%w: native version=%q reported_commit=%q",
			fiscobcos.ErrUnsupportedSDK,
			version,
			reportedCommit,
		)
	}
	if err := verifyNativeArtifact(artifactPath, pin); err != nil {
		return "", fmt.Errorf("%w: %v", fiscobcos.ErrUnsupportedSDK, err)
	}
	observed := fmt.Sprintf(
		"fisco-bcos-go-sdk-v3.0.2+c-sdk-v%s@%s",
		pin.version,
		pin.commit,
	)
	if observed != fiscobcos.StandardSDKVersion {
		return "", fmt.Errorf("%w: observed SDK identity does not match the protocol pin", fiscobcos.ErrUnsupportedSDK)
	}
	return observed, nil
}

func parseNativeVersion(value string) (string, string, error) {
	if value == "" || len(value) > 4<<10 {
		return "", "", errors.New("FISCO BCOS native SDK version output is empty or oversized")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(value), "\n") {
		key, item, ok := strings.Cut(line, ":")
		if !ok {
			return "", "", errors.New("FISCO BCOS native SDK version output is malformed")
		}
		key = strings.TrimSpace(key)
		item = strings.TrimSpace(item)
		switch key {
		case "FISCO BCOS C SDK Version", "Build Time", "Build Type", "Git Branch", "Git Commit":
		default:
			return "", "", fmt.Errorf("FISCO BCOS native SDK version output contains unknown field %q", key)
		}
		// The official v3.6.0 linux/amd64 artifact has an empty Git Branch.
		// Branch is non-identity metadata; all other fields remain mandatory.
		if item == "" && key != "Git Branch" {
			return "", "", fmt.Errorf("FISCO BCOS native SDK version output contains empty field %q", key)
		}
		if _, exists := fields[key]; exists {
			return "", "", fmt.Errorf("FISCO BCOS native SDK version output repeats field %q", key)
		}
		fields[key] = item
	}
	if len(fields) != 5 {
		return "", "", errors.New("FISCO BCOS native SDK version output is incomplete")
	}
	return fields["FISCO BCOS C SDK Version"], fields["Git Commit"], nil
}

func verifyNativeArtifact(path string, pin nativeArtifactPin) error {
	if path == "" || !filepath.IsAbs(path) ||
		!nativeArtifactNameMatches(runtime.GOOS, filepath.Base(path), pin.name) ||
		pin.size <= 0 || len(pin.sha256) != sha256.Size*2 {
		return errors.New("FISCO BCOS native SDK artifact identity is invalid")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect FISCO BCOS native SDK artifact: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() != pin.size {
		return errors.New("FISCO BCOS native SDK artifact is not the exact pinned regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open FISCO BCOS native SDK artifact: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || opened.Size() != pin.size {
		return errors.New("FISCO BCOS native SDK artifact changed while opening")
	}
	digest := sha256.New()
	written, err := io.Copy(digest, file)
	if err != nil || written != pin.size {
		return errors.New("hash FISCO BCOS native SDK artifact failed or read a partial file")
	}
	if got := hex.EncodeToString(digest.Sum(nil)); got != pin.sha256 {
		return fmt.Errorf("FISCO BCOS native SDK artifact SHA-256 mismatch: got %s", got)
	}
	return nil
}

func nativeArtifactNameMatches(goos, actual, expected string) bool {
	if goos == "windows" {
		// Windows resolves DLL names case-insensitively and GetModuleFileNameW
		// may return a different case from the release asset name. The exact
		// size and SHA-256 checks below still bind the loaded file's identity.
		return strings.EqualFold(actual, expected)
	}
	return actual == expected
}
