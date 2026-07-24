package tlcpbuild

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testImageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testPlatform    = "linux/arm64"
)

func TestNormalizeSBOMIsDeterministicAndIncludesPinnedSources(t *testing.T) {
	baseline := testBaseline()
	first, err := NormalizeSBOM(testRawSBOM("2026-07-24T00:00:00Z", "urn:random:one"), baseline, testImageDigest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NormalizeSBOM(testRawSBOM("2027-08-25T00:00:00Z", "urn:random:two"), baseline, testImageDigest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("normalized SBOM retained nondeterministic Syft fields")
	}
	if err := VerifySBOM(first, baseline, testImageDigest); err != nil {
		t.Fatal(err)
	}

	tampered := bytes.Replace(
		first,
		[]byte(baseline.Tongsuo.ArchiveSHA256),
		[]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		1,
	)
	if err := VerifySBOM(tampered, baseline, testImageDigest); err == nil {
		t.Fatal("accepted a tampered Tongsuo source checksum")
	}
}

func TestRepositoryProductionBaselineHasReviewedDigest(t *testing.T) {
	path := filepath.Join("..", "..", "packaging", "tlcp-gateway", "baseline.json")
	if _, _, err := LoadPinnedBaseline(path); err != nil {
		t.Fatal(err)
	}
}

func TestBuildxReleaseMustBeExactStableSemver(t *testing.T) {
	for _, invalid := range []string{"", "latest", "v0.35", "v0.35.0-rc1", "v0.x.0"} {
		if isExactRelease(invalid) {
			t.Fatalf("accepted non-exact Buildx release %q", invalid)
		}
	}
	if !isExactRelease("v0.35.0") {
		t.Fatal("rejected exact stable Buildx release")
	}
}

func TestRepositoryAutomationPinsReviewedBuildToolchain(t *testing.T) {
	root := filepath.Join("..", "..")
	baseline, _, err := LoadPinnedBaseline(
		filepath.Join(root, "packaging", "tlcp-gateway", "baseline.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "tlcp-gateway.yml"))
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join(root, "packaging", "tlcp-gateway", "build.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, exact := range []string{
		"version: " + baseline.BuildxVersion,
		"image=" + baseline.BuildKitImage,
	} {
		if !strings.Contains(string(workflow), exact) {
			t.Fatalf("TLCP workflow does not pin reviewed toolchain value %q", exact)
		}
	}
	for _, exact := range []string{
		"buildx_version='" + baseline.BuildxVersion + "'",
		"buildkit_image='" + baseline.BuildKitImage + "'",
	} {
		if !strings.Contains(string(script), exact) {
			t.Fatalf("TLCP build script does not verify reviewed toolchain value %q", exact)
		}
	}
}

func TestBuildRecordBindsArchiveSBOMAndBaseline(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	baselineData := []byte(`{
  "schema_version": "trustdb.tlcp-gateway-build-baseline.v1",
  "source_date_epoch": 1702545703,
  "tengine": {
    "version": "2.3.4",
    "commit": "698e1798e8d691c55b5405ca1526c3dca4759d47",
    "archive_url": "https://example.invalid/tengine.tar.gz",
    "archive_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
    "license_sha256": "2222222222222222222222222222222222222222222222222222222222222222"
  },
  "tongsuo": {
    "version": "8.4.0",
    "commit": "a8ae0925d26de3b449f7a21767910cd41291bcd8",
    "archive_url": "https://example.invalid/tongsuo.tar.gz",
    "archive_sha256": "3333333333333333333333333333333333333333333333333333333333333333",
    "license_sha256": "4444444444444444444444444444444444444444444444444444444444444444"
  },
  "builder_image": "example.invalid/builder@sha256:5555555555555555555555555555555555555555555555555555555555555555",
  "runtime_image": "example.invalid/runtime@sha256:6666666666666666666666666666666666666666666666666666666666666666",
  "validator_builder_image": "example.invalid/go@sha256:9999999999999999999999999999999999999999999999999999999999999999",
  "dockerfile_frontend_image": "example.invalid/frontend@sha256:7777777777777777777777777777777777777777777777777777777777777777",
  "buildx_version": "v0.35.0",
  "buildkit_image": "example.invalid/buildkit@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "debian_snapshot": "20260713T000000Z",
  "builder_packages": ["compiler=1"],
  "runtime_packages": ["runtime=1"],
  "syft_image": "example.invalid/syft@sha256:8888888888888888888888888888888888888888888888888888888888888888",
  "build_parameters": ["--pinned"]
}
`)
	writeTestFile(t, baselinePath, baselineData)
	baseline, _, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatal(err)
	}

	archivePath := filepath.Join(dir, "gateway.oci.tar")
	imageDigest := writeOCIArchive(t, archivePath, testPlatform)
	raw := testRawSBOM("2026-07-24T00:00:00Z", "urn:random")
	sbom, err := NormalizeSBOM(raw, baseline, imageDigest)
	if err != nil {
		t.Fatal(err)
	}
	sbomPath := filepath.Join(dir, "gateway.spdx.json")
	writeTestFile(t, sbomPath, sbom)

	record, err := CreateBuildRecord(baselinePath, archivePath, sbomPath, testPlatform)
	if err != nil {
		t.Fatal(err)
	}
	if record.BuildxVersion != baseline.BuildxVersion ||
		record.BuildKitImage != baseline.BuildKitImage {
		t.Fatal("build record does not bind the reviewed Buildx and BuildKit toolchain")
	}
	recordData, err := EncodeBuildRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(dir, "build-record.json")
	checksumPath := filepath.Join(dir, "build-record.json.sha256")
	writeTestFile(t, recordPath, recordData)
	writeTestFile(t, checksumPath, []byte(bytesSHA256(recordData)+"\n"))
	if err := VerifyBuildRecord(
		recordPath,
		checksumPath,
		baselinePath,
		archivePath,
		sbomPath,
		testPlatform,
	); err != nil {
		t.Fatal(err)
	}

	writeTestFile(t, checksumPath, []byte("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"))
	if err := VerifyBuildRecord(
		recordPath,
		checksumPath,
		baselinePath,
		archivePath,
		sbomPath,
		testPlatform,
	); err == nil {
		t.Fatal("accepted a tampered build-record checksum")
	}
}

func testBaseline() Baseline {
	return Baseline{
		SchemaVersion:   BaselineSchemaVersion,
		SourceDateEpoch: 1702545703,
		Tengine: BaselineSource{
			Version:       "2.3.4",
			Commit:        "698e1798e8d691c55b5405ca1526c3dca4759d47",
			ArchiveURL:    "https://example.invalid/tengine.tar.gz",
			ArchiveSHA256: "1111111111111111111111111111111111111111111111111111111111111111",
			LicenseSHA256: "2222222222222222222222222222222222222222222222222222222222222222",
		},
		Tongsuo: BaselineSource{
			Version:       "8.4.0",
			Commit:        "a8ae0925d26de3b449f7a21767910cd41291bcd8",
			ArchiveURL:    "https://example.invalid/tongsuo.tar.gz",
			ArchiveSHA256: "3333333333333333333333333333333333333333333333333333333333333333",
			LicenseSHA256: "4444444444444444444444444444444444444444444444444444444444444444",
		},
		BuildxVersion: "v0.35.0",
		BuildKitImage: "example.invalid/buildkit@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}

func testRawSBOM(created, namespace string) []byte {
	return []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "random-input-name",
  "documentNamespace": "` + namespace + `",
  "creationInfo": {
    "licenseListVersion": "3.27",
    "creators": ["Organization: Anchore, Inc", "Tool: syft-1.38.2"],
    "created": "` + created + `"
  },
  "packages": [{
    "name": "libpcre3",
    "SPDXID": "SPDXRef-Package-libpcre3",
    "versionInfo": "2:8.39-15",
    "downloadLocation": "NOASSERTION",
    "filesAnalyzed": false,
    "licenseConcluded": "NOASSERTION",
    "licenseDeclared": "BSD-3-Clause",
    "copyrightText": "NOASSERTION"
  }],
  "relationships": []
}`)
}

func writeOCIArchive(t *testing.T, path, platform string) string {
	t.Helper()
	parts := bytes.Split([]byte(platform), []byte("/"))
	if len(parts) != 2 {
		t.Fatalf("invalid test platform %q", platform)
	}
	layer := []byte("deterministic test layer")
	layerDigest := testSHA256(layer)
	config := []byte(`{"architecture":"` + string(parts[1]) + `","os":"` + string(parts[0]) + `"}`)
	configDigest := testSHA256(config)
	manifest := []byte(`{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:` + configDigest + `",
    "size": ` + fmt.Sprint(len(config)) + `
  },
  "layers": [{
    "mediaType": "application/vnd.oci.image.layer.v1.tar",
    "digest": "sha256:` + layerDigest + `",
    "size": ` + fmt.Sprint(len(layer)) + `
  }]
}`)
	manifestDigest := testSHA256(manifest)
	index := []byte(`{
  "schemaVersion": 2,
  "manifests": [{
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": "sha256:` + manifestDigest + `",
    "size": ` + fmt.Sprint(len(manifest)) + `,
    "platform": {"os": "` + string(parts[0]) + `", "architecture": "` + string(parts[1]) + `"}
  }]
}`)
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	for _, item := range []struct {
		Name string
		Data []byte
	}{
		{"index.json", index},
		{"blobs/sha256/" + manifestDigest, manifest},
		{"blobs/sha256/" + configDigest, config},
		{"blobs/sha256/" + layerDigest, layer},
	} {
		if err := writer.WriteHeader(&tar.Header{
			Name: item.Name,
			Mode: 0o644,
			Size: int64(len(item.Data)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(item.Data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + manifestDigest
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
