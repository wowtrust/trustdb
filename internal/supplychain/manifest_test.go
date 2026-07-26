package supplychain

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

func TestGenerateWriteAndVerify(t *testing.T) {
	directory := t.TempDir()
	writeTestFile(t, filepath.Join(directory, "trustdb-1.2.3-linux-amd64.tar.gz"), "archive")
	policy := filepath.Join(t.TempDir(), "policy.json")
	writeTestFile(t, policy, "{}")
	writeMandatoryDocuments(t, directory, "{}")

	manifest, err := Generate(GenerateOptions{
		Directory: directory, Version: "1.2.3", Commit: testCommit,
		BuildDate: "2026-07-25T10:00:00Z", PolicyPath: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(directory, manifest); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(directory, AttestationFilename), "{}")
	decoded, err := Read(filepath.Join(directory, ManifestFilename))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(directory, decoded); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsTamperingAndUnmanifestedFiles(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, directory string)
		want   string
	}{
		{
			name: "artifact",
			mutate: func(t *testing.T, directory string) {
				writeTestFile(t, filepath.Join(directory, "artifact.zip"), "changed")
			},
			want: "does not match",
		},
		{
			name: "extra",
			mutate: func(t *testing.T, directory string) {
				writeTestFile(t, filepath.Join(directory, "extra.txt"), "untracked")
			},
			want: "unmanifested",
		},
		{
			name: "checksum",
			mutate: func(t *testing.T, directory string) {
				writeTestFile(t, filepath.Join(directory, SHA256Filename), "bad\n")
			},
			want: "invalid entry",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			writeTestFile(t, filepath.Join(directory, "artifact.zip"), "original")
			policy := filepath.Join(t.TempDir(), "policy.json")
			writeTestFile(t, policy, "{}")
			writeMandatoryDocuments(t, directory, "{}")
			manifest, err := Generate(GenerateOptions{
				Directory: directory, Version: "1.0.0", Commit: testCommit,
				BuildDate: "2026-07-25T10:00:00Z", PolicyPath: policy,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := Write(directory, manifest); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, filepath.Join(directory, AttestationFilename), "{}")
			test.mutate(t, directory)
			err = Verify(directory, manifest)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Verify() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestGenerateRejectsUnsafeBundleShapes(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(t.TempDir(), "policy.json")
	writeTestFile(t, policy, "{}")
	writeMandatoryDocuments(t, directory, "{}")
	_, err := Generate(GenerateOptions{
		Directory: directory, Version: "1.0.0", Commit: testCommit,
		BuildDate: "2026-07-25T10:00:00Z", PolicyPath: policy,
	})
	if err == nil || !strings.Contains(err.Error(), "flat") {
		t.Fatalf("Generate() error = %v, want flat-directory rejection", err)
	}
}

func TestReleaseArtifactClassificationIsDeterministic(t *testing.T) {
	tests := []struct {
		name      string
		kind      string
		mediaType string
	}{
		{name: "trustdb-linux-amd64.tar.gz", kind: "distribution", mediaType: "application/gzip"},
		{name: "trustdb-windows-amd64.zip", kind: "distribution", mediaType: "application/zip"},
		{name: "trustdb-desktop.dmg", kind: "distribution", mediaType: "application/x-apple-diskimage"},
		{name: "trustdb-desktop.pkg", kind: "distribution", mediaType: "application/vnd.apple.installer+xml"},
		{name: "trustdb-desktop.msi", kind: "distribution", mediaType: "application/x-msi"},
		{name: "trustdb-desktop-setup.exe", kind: "distribution", mediaType: "application/octet-stream"},
		{name: "trustdb-desktop.cer", kind: "release-metadata", mediaType: "application/pkix-cert"},
		{name: "trustdb-desktop-certificate.txt", kind: "release-metadata", mediaType: "text/plain"},
		{name: "trustdb-desktop.wixpdb", kind: "release-metadata", mediaType: "application/octet-stream"},
		{name: "TRUSTDB_RELEASE_METADATA.json", kind: "release-metadata", mediaType: "application/json"},
		{name: "trustdb-release.spdx.json", kind: "sbom", mediaType: "application/spdx+json"},
		{name: "TRUSTDB_VULNERABILITY_REPORT.json", kind: "vulnerability-report", mediaType: "application/json"},
		{name: ProductionInputsFile, kind: "release-metadata", mediaType: "application/json"},
		{name: "TRUSTDB_CONTAINER_DIGESTS.json", kind: "release-metadata", mediaType: "application/json"},
		{name: "artifact.unknown", kind: "release-metadata", mediaType: "application/octet-stream"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := artifactKind(test.name); got != test.kind {
				t.Fatalf("artifactKind(%q) = %q, want %q", test.name, got, test.kind)
			}
			if got := mediaType(test.name); got != test.mediaType {
				t.Fatalf("mediaType(%q) = %q, want %q", test.name, got, test.mediaType)
			}
		})
	}
}

func TestValidateManifestRequiresBuiltInDocumentsAndRejectsReservedArtifacts(t *testing.T) {
	manifest := Manifest{
		Schema:  ManifestSchema,
		Version: "1.0.0",
		Source: Source{
			Repository: defaultSourceRepo,
			Commit:     testCommit,
			BuildDate:  "2026-07-25T10:00:00Z",
		},
		PolicySHA256: strings.Repeat("0", 64),
		Artifacts: []Artifact{{
			Path: ManifestFilename, Kind: artifactKind(ManifestFilename),
			MediaType: mediaType(ManifestFilename), SHA256: strings.Repeat("0", 64),
			SM3: strings.Repeat("0", 64),
		}},
	}
	if err := validateManifest(manifest); err == nil || !strings.Contains(err.Error(), "mandatory document") {
		t.Fatalf("validateManifest() error = %v, want missing mandatory document", err)
	}
	manifest.RequiredDocuments = append([]string(nil), mandatoryDocuments...)
	sort.Strings(manifest.RequiredDocuments)
	if err := validateManifest(manifest); err == nil || !strings.Contains(err.Error(), "reserved sidecar") {
		t.Fatalf("validateManifest() error = %v, want reserved sidecar rejection", err)
	}
}

func writeMandatoryDocuments(t *testing.T, directory, policyValue string) {
	t.Helper()
	for _, name := range mandatoryDocuments {
		value := "{}"
		if name == ProductionInputsFile {
			value = policyValue
		}
		writeTestFile(t, filepath.Join(directory, name), value)
	}
}

func writeTestFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
}
