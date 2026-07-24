//go:build fiscobcos_sdk && cgo

package standardsdk

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
)

const nativeVersionFixture = `FISCO BCOS C SDK Version : 3.6.0
Build Time         : 20240219 16:21:14
Build Type         : Darwin/appleclang/MinSizeRel
Git Branch         : main
Git Commit         : 53240138c396c10cb0e1a2b7b4d5c0cdaa0ac539
`

const linuxAMD64NativeVersionFixture = `FISCO BCOS C SDK Version : 3.6.0
Build Time         : 20240219 07:49:23
Build Type         : Linux/g++/MinSizeRel
Git Branch         :
Git Commit         : 0
`

func TestVerifyNativeRuntimeRequiresExactVersionAndArtifact(t *testing.T) {
	t.Parallel()
	content := []byte("pinned native fixture")
	sum := sha256.Sum256(content)
	pin := nativeArtifactPin{
		name:           "libbcos-c-sdk-test",
		size:           int64(len(content)),
		sha256:         hex.EncodeToString(sum[:]),
		version:        supportedNativeVersion,
		commit:         supportedNativeCommit,
		reportedCommit: supportedNativeCommit,
	}
	path := filepath.Join(t.TempDir(), pin.name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := verifyNativeRuntime(nativeVersionFixture, path, pin)
	if err != nil {
		t.Fatalf("verifyNativeRuntime: %v", err)
	}
	if got != fiscobcos.StandardSDKVersion {
		t.Fatalf("SDK identity = %q, want %q", got, fiscobcos.StandardSDKVersion)
	}

	for _, test := range []struct {
		name    string
		version string
		path    string
		pin     nativeArtifactPin
	}{
		{
			name:    "version",
			version: strings.Replace(nativeVersionFixture, "3.6.0", "3.6.1", 1),
			path:    path,
			pin:     pin,
		},
		{
			name:    "commit",
			version: strings.Replace(nativeVersionFixture, supportedNativeCommit, strings.Repeat("0", 40), 1),
			path:    path,
			pin:     pin,
		},
		{
			name:    "unknown version field",
			version: nativeVersionFixture + "Unexpected : value\n",
			path:    path,
			pin:     pin,
		},
		{
			name:    "basename",
			version: nativeVersionFixture,
			path:    path,
			pin: nativeArtifactPin{
				name: "different-library", size: pin.size, sha256: pin.sha256,
				version: pin.version, commit: pin.commit, reportedCommit: pin.reportedCommit,
			},
		},
		{
			name:    "size",
			version: nativeVersionFixture,
			path:    path,
			pin: nativeArtifactPin{
				name: pin.name, size: pin.size + 1, sha256: pin.sha256,
				version: pin.version, commit: pin.commit, reportedCommit: pin.reportedCommit,
			},
		},
		{
			name:    "digest",
			version: nativeVersionFixture,
			path:    path,
			pin: nativeArtifactPin{
				name: pin.name, size: pin.size, sha256: strings.Repeat("0", 64),
				version: pin.version, commit: pin.commit, reportedCommit: pin.reportedCommit,
			},
		},
		{
			name:    "provenance commit",
			version: nativeVersionFixture,
			path:    path,
			pin: nativeArtifactPin{
				name: pin.name, size: pin.size, sha256: pin.sha256,
				version: pin.version, commit: strings.Repeat("0", 40), reportedCommit: pin.reportedCommit,
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := verifyNativeRuntime(test.version, test.path, test.pin); !errors.Is(err, fiscobcos.ErrUnsupportedSDK) {
				t.Fatalf("mismatched native runtime error = %v, want ErrUnsupportedSDK", err)
			}
		})
	}
}

func TestVerifyNativeRuntimeAcceptsExactLinuxAMD64ReleaseMetadata(t *testing.T) {
	t.Parallel()
	content := []byte("pinned linux/amd64 native fixture")
	sum := sha256.Sum256(content)
	path := filepath.Join(t.TempDir(), "libbcos-c-sdk.so")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := verifyNativeRuntime(linuxAMD64NativeVersionFixture, path, nativeArtifactPin{
		name: "libbcos-c-sdk.so", size: int64(len(content)),
		sha256:  hex.EncodeToString(sum[:]),
		version: supportedNativeVersion, commit: supportedNativeCommit, reportedCommit: "0",
	})
	if err != nil {
		t.Fatalf("verifyNativeRuntime(linux/amd64): %v", err)
	}
	if got != fiscobcos.StandardSDKVersion {
		t.Fatalf("SDK identity = %q, want %q", got, fiscobcos.StandardSDKVersion)
	}
}

func TestVerifyNativeRuntimeBindsWindowsReportedCommitToSourceProvenance(t *testing.T) {
	t.Parallel()
	content := []byte("pinned windows/amd64 native fixture")
	sum := sha256.Sum256(content)
	path := filepath.Join(t.TempDir(), "bcos-c-sdk.dll")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	pin := nativeArtifactPin{
		name: "bcos-c-sdk.dll", size: int64(len(content)),
		sha256:  hex.EncodeToString(sum[:]),
		version: supportedNativeVersion, commit: supportedNativeCommit,
		reportedCommit: windowsAMD64ReportedNativeCommit,
	}
	windowsVersion := strings.Replace(
		nativeVersionFixture,
		supportedNativeCommit,
		windowsAMD64ReportedNativeCommit,
		1,
	)
	got, err := verifyNativeRuntime(windowsVersion, path, pin)
	if err != nil {
		t.Fatalf("verifyNativeRuntime(windows/amd64): %v", err)
	}
	if got != fiscobcos.StandardSDKVersion {
		t.Fatalf("SDK identity = %q, want source provenance %q", got, fiscobcos.StandardSDKVersion)
	}

	for _, test := range []struct {
		name    string
		version string
		pin     nativeArtifactPin
	}{
		{
			name:    "different reported commit",
			version: nativeVersionFixture,
			pin:     pin,
		},
		{
			name:    "different source provenance",
			version: windowsVersion,
			pin: func() nativeArtifactPin {
				invalid := pin
				invalid.commit = windowsAMD64ReportedNativeCommit
				return invalid
			}(),
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := verifyNativeRuntime(test.version, path, test.pin); !errors.Is(err, fiscobcos.ErrUnsupportedSDK) {
				t.Fatalf("mismatched Windows runtime error = %v, want ErrUnsupportedSDK", err)
			}
		})
	}
}

func TestParseNativeVersionRejectsEmptyRequiredFields(t *testing.T) {
	t.Parallel()
	version, commit, err := parseNativeVersion(linuxAMD64NativeVersionFixture)
	if err != nil || version != supportedNativeVersion || commit != "0" {
		t.Fatalf("parse real linux/amd64 output = %q, %q, %v", version, commit, err)
	}
	for _, field := range []string{
		"FISCO BCOS C SDK Version",
		"Build Time",
		"Build Type",
		"Git Commit",
	} {
		field := field
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			lines := strings.Split(nativeVersionFixture, "\n")
			for index, line := range lines {
				key, _, ok := strings.Cut(line, ":")
				if ok && strings.TrimSpace(key) == field {
					lines[index] = key + ":"
				}
			}
			if _, _, err := parseNativeVersion(strings.Join(lines, "\n")); err == nil {
				t.Fatalf("accepted empty required field %q", field)
			}
		})
	}
}

func TestVerifyNativeArtifactRejectsSymlink(t *testing.T) {
	t.Parallel()
	content := []byte("pinned native fixture")
	sum := sha256.Sum256(content)
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "libbcos-c-sdk-test")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := verifyNativeArtifact(link, nativeArtifactPin{
		name: "libbcos-c-sdk-test", size: int64(len(content)),
		sha256: hex.EncodeToString(sum[:]), version: supportedNativeVersion,
		commit: supportedNativeCommit, reportedCommit: supportedNativeCommit,
	}); err == nil {
		t.Fatal("accepted symlinked native artifact")
	}
}

func TestVerifyNativeArtifactSupportsUnicodePath(t *testing.T) {
	t.Parallel()
	content := []byte("pinned native fixture")
	sum := sha256.Sum256(content)
	directory := filepath.Join(t.TempDir(), "国密运行时")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "libbcos-c-sdk-test")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyNativeArtifact(path, nativeArtifactPin{
		name: "libbcos-c-sdk-test", size: int64(len(content)),
		sha256: hex.EncodeToString(sum[:]), version: supportedNativeVersion,
		commit: supportedNativeCommit, reportedCommit: supportedNativeCommit,
	}); err != nil {
		t.Fatalf("unicode native artifact path rejected: %v", err)
	}
}

func TestObservedNativeRuntimeMatchesProtocolPin(t *testing.T) {
	got, err := observeAndVerifyNativeRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if got != fiscobcos.StandardSDKVersion {
		t.Fatalf("SDK identity = %q, want %q", got, fiscobcos.StandardSDKVersion)
	}
}

func TestTransactionHashTextIsExactAndBounded(t *testing.T) {
	t.Parallel()
	valid := "0x" + strings.Repeat("a5", 32)
	if err := validateTransactionHashText(valid); err != nil {
		t.Fatalf("valid transaction hash rejected: %v", err)
	}
	for _, value := range []string{
		"",
		strings.Repeat("a5", 32),
		"0X" + strings.Repeat("a5", 32),
		"0x" + strings.Repeat("a5", 31),
		"0x" + strings.Repeat("a5", 33),
		"0x" + strings.Repeat("gg", 32),
	} {
		if err := validateTransactionHashText(value); err == nil {
			t.Fatalf("invalid transaction hash %q accepted", value)
		}
	}
}
