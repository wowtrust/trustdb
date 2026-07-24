package tlcpbuild

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	BaselineSchemaVersion = "trustdb.tlcp-gateway-build-baseline.v1"
	BuildRecordSchema     = "trustdb.tlcp-gateway-build-record.v1"
	SPDXVersion           = "SPDX-2.3"
	DataLicense           = "CC0-1.0"
	PinnedBaselineSHA256  = "940e27034999e9b6ffbd89666123fb062c0a7384dc183eeabd3eb7eca436aecf"
	maxBaselineBytes      = 1 << 20
	maxBuildRecordBytes   = 1 << 20
	maxSBOMBytes          = 128 << 20
	maxOCIEntries         = 100_000
	maxStoredOCIJSONBytes = 32 << 20
)

type Baseline struct {
	SchemaVersion           string         `json:"schema_version"`
	SourceDateEpoch         int64          `json:"source_date_epoch"`
	Tengine                 BaselineSource `json:"tengine"`
	Tongsuo                 BaselineSource `json:"tongsuo"`
	BuilderImage            string         `json:"builder_image"`
	RuntimeImage            string         `json:"runtime_image"`
	ValidatorBuilderImage   string         `json:"validator_builder_image"`
	DockerfileFrontendImage string         `json:"dockerfile_frontend_image"`
	DebianSnapshot          string         `json:"debian_snapshot"`
	BuilderPackages         []string       `json:"builder_packages"`
	RuntimePackages         []string       `json:"runtime_packages"`
	SyftImage               string         `json:"syft_image"`
	BuildParameters         []string       `json:"build_parameters"`
}

type BaselineSource struct {
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	ArchiveURL    string `json:"archive_url"`
	ArchiveSHA256 string `json:"archive_sha256"`
	LicenseSHA256 string `json:"license_sha256"`
}

type BuildRecord struct {
	SchemaVersion           string         `json:"schema_version"`
	GeneratedAt             string         `json:"generated_at"`
	Platform                string         `json:"platform"`
	ImageDigest             string         `json:"image_digest"`
	OCIArchiveSHA256        string         `json:"oci_archive_sha256"`
	SBOMSHA256              string         `json:"sbom_sha256"`
	BaselineSHA256          string         `json:"baseline_sha256"`
	SourceDateEpoch         int64          `json:"source_date_epoch"`
	Tengine                 BaselineSource `json:"tengine"`
	Tongsuo                 BaselineSource `json:"tongsuo"`
	BuilderImage            string         `json:"builder_image"`
	RuntimeImage            string         `json:"runtime_image"`
	ValidatorBuilderImage   string         `json:"validator_builder_image"`
	DockerfileFrontendImage string         `json:"dockerfile_frontend_image"`
	SyftImage               string         `json:"syft_image"`
}

type ociIndex struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Manifests     []struct {
		MediaType   string            `json:"mediaType"`
		Digest      string            `json:"digest"`
		Size        int64             `json:"size"`
		Annotations map[string]string `json:"annotations,omitempty"`
		Platform    struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		} `json:"platform"`
	} `json:"manifests"`
}

type ociManifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"config"`
	Layers []struct {
		MediaType   string            `json:"mediaType"`
		Digest      string            `json:"digest"`
		Size        int64             `json:"size"`
		Annotations map[string]string `json:"annotations,omitempty"`
	} `json:"layers"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func LoadBaseline(path string) (Baseline, []byte, error) {
	data, err := readFileBounded(path, maxBaselineBytes)
	if err != nil {
		return Baseline{}, nil, fmt.Errorf("read build baseline: %w", err)
	}
	var baseline Baseline
	if err := decodeStrict(data, &baseline); err != nil {
		return Baseline{}, nil, fmt.Errorf("decode build baseline: %w", err)
	}
	if err := validateBaseline(baseline); err != nil {
		return Baseline{}, nil, err
	}
	return baseline, data, nil
}

func LoadPinnedBaseline(path string) (Baseline, []byte, error) {
	baseline, data, err := LoadBaseline(path)
	if err != nil {
		return Baseline{}, nil, err
	}
	if bytesSHA256(data) != PinnedBaselineSHA256 {
		return Baseline{}, nil, errors.New("TLCP build baseline does not match the reviewed production SHA-256")
	}
	return baseline, data, nil
}

func NormalizeSBOM(raw []byte, baseline Baseline, imageDigest string) ([]byte, error) {
	if err := validateDigest("image digest", imageDigest, true); err != nil {
		return nil, err
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("decode Syft SPDX JSON: %w", err)
	}
	if document["spdxVersion"] != SPDXVersion || document["dataLicense"] != DataLicense {
		return nil, errors.New("Syft output is not an SPDX-2.3 JSON document")
	}
	creation, ok := document["creationInfo"].(map[string]any)
	if !ok {
		return nil, errors.New("Syft SPDX document has no creationInfo object")
	}
	creators, ok := creation["creators"].([]any)
	if !ok || !containsString(creators, "Tool: syft-1.38.2") {
		return nil, errors.New("SPDX document was not generated by pinned Syft 1.38.2")
	}
	created := time.Unix(baseline.SourceDateEpoch, 0).UTC().Format(time.RFC3339)
	creation["created"] = created
	document["name"] = "trustdb-tlcp-gateway"
	document["documentNamespace"] = "https://wowtrust.dev/trustdb/tlcp-gateway/sbom/" +
		strings.Replace(imageDigest, ":", "-", 1)

	packages, ok := document["packages"].([]any)
	if !ok {
		return nil, errors.New("Syft SPDX document has no packages array")
	}
	packages = removePackages(packages, "Tengine", "Tongsuo")
	packages = append(
		packages,
		sourcePackage("Tengine", "BSD-2-Clause", "SPDXRef-Package-Tengine", baseline.Tengine),
		sourcePackage("Tongsuo", "Apache-2.0", "SPDXRef-Package-Tongsuo", baseline.Tongsuo),
	)
	sortMaps(packages, "SPDXID", "name")
	document["packages"] = packages

	relationships, _ := document["relationships"].([]any)
	relationships = removeRelationships(
		relationships,
		"SPDXRef-Package-Tengine",
		"SPDXRef-Package-Tongsuo",
	)
	relationships = append(
		relationships,
		map[string]any{
			"spdxElementId":      "SPDXRef-DOCUMENT",
			"relatedSpdxElement": "SPDXRef-Package-Tengine",
			"relationshipType":   "DESCRIBES",
		},
		map[string]any{
			"spdxElementId":      "SPDXRef-DOCUMENT",
			"relatedSpdxElement": "SPDXRef-Package-Tongsuo",
			"relationshipType":   "DESCRIBES",
		},
	)
	sortMaps(relationships, "spdxElementId", "relatedSpdxElement", "relationshipType")
	document["relationships"] = relationships
	document["documentDescribes"] = []string{
		"SPDXRef-Package-Tengine",
		"SPDXRef-Package-Tongsuo",
	}

	if files, ok := document["files"].([]any); ok {
		sortMaps(files, "SPDXID", "fileName")
		document["files"] = files
	}
	output, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode normalized SPDX JSON: %w", err)
	}
	return append(output, '\n'), nil
}

func VerifySBOM(data []byte, baseline Baseline, imageDigest string) error {
	normalized, err := NormalizeSBOM(data, baseline, imageDigest)
	if err != nil {
		return err
	}
	if !bytes.Equal(normalized, data) {
		return errors.New("SBOM is not in canonical deterministic form")
	}
	var document struct {
		DocumentDescribes []string `json:"documentDescribes"`
		Packages          []struct {
			Name            string `json:"name"`
			Version         string `json:"versionInfo"`
			LicenseDeclared string `json:"licenseDeclared"`
			Checksums       []struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"checksumValue"`
			} `json:"checksums"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("decode normalized SPDX JSON: %w", err)
	}
	expected := map[string]struct {
		Version string
		License string
		SHA256  string
	}{
		"Tengine": {baseline.Tengine.Version, "BSD-2-Clause", baseline.Tengine.ArchiveSHA256},
		"Tongsuo": {baseline.Tongsuo.Version, "Apache-2.0", baseline.Tongsuo.ArchiveSHA256},
	}
	found := make(map[string]bool, len(expected))
	for _, pkg := range document.Packages {
		want, ok := expected[pkg.Name]
		if !ok {
			continue
		}
		if pkg.Version != want.Version || pkg.LicenseDeclared != want.License ||
			!hasChecksum(pkg.Checksums, "SHA256", want.SHA256) {
			return fmt.Errorf("SBOM %s package does not match the build baseline", pkg.Name)
		}
		found[pkg.Name] = true
	}
	for name := range expected {
		if !found[name] {
			return fmt.Errorf("SBOM does not contain %s", name)
		}
	}
	if !equalStrings(document.DocumentDescribes, []string{
		"SPDXRef-Package-Tengine",
		"SPDXRef-Package-Tongsuo",
	}) {
		return errors.New("SBOM document does not describe the pinned Tengine and Tongsuo packages")
	}
	return nil
}

func OCIImageDigest(path, platform string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open OCI archive: %w", err)
	}
	defer file.Close()
	reader := tar.NewReader(file)
	var indexData []byte
	blobHashes := make(map[string]string)
	blobSizes := make(map[string]int64)
	jsonBlobs := make(map[string][]byte)
	var entries int
	var storedJSONBytes int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read OCI archive: %w", err)
		}
		entries++
		if entries > maxOCIEntries {
			return "", fmt.Errorf("OCI archive exceeds %d entries", maxOCIEntries)
		}
		if !header.FileInfo().Mode().IsRegular() {
			continue
		}
		if header.Name == "index.json" {
			if indexData != nil {
				return "", errors.New("OCI archive contains duplicate index.json entries")
			}
			if header.Size > 1<<20 {
				return "", errors.New("OCI index exceeds 1 MiB")
			}
			indexData, err = io.ReadAll(reader)
			if err != nil {
				return "", fmt.Errorf("read OCI index: %w", err)
			}
			continue
		}
		const blobPrefix = "blobs/sha256/"
		if !strings.HasPrefix(header.Name, blobPrefix) {
			continue
		}
		nameDigest := strings.TrimPrefix(header.Name, blobPrefix)
		if err := validateDigest("OCI blob name", nameDigest, false); err != nil {
			return "", err
		}
		if _, exists := blobHashes[nameDigest]; exists {
			return "", fmt.Errorf("OCI archive contains duplicate blob %s", nameDigest)
		}
		hash := sha256.New()
		if header.Size <= 4<<20 {
			storedJSONBytes += header.Size
			if storedJSONBytes > maxStoredOCIJSONBytes {
				return "", errors.New("OCI archive contains too many small candidate JSON blobs")
			}
			data, err := io.ReadAll(io.TeeReader(reader, hash))
			if err != nil {
				return "", fmt.Errorf("read OCI blob %s: %w", nameDigest, err)
			}
			jsonBlobs[nameDigest] = data
		} else if _, err := io.Copy(hash, reader); err != nil {
			return "", fmt.Errorf("hash OCI blob %s: %w", nameDigest, err)
		}
		actualDigest := hex.EncodeToString(hash.Sum(nil))
		if actualDigest != nameDigest {
			return "", fmt.Errorf("OCI blob %s content digest is %s", nameDigest, actualDigest)
		}
		blobHashes[nameDigest] = actualDigest
		blobSizes[nameDigest] = header.Size
	}
	if indexData == nil {
		return "", errors.New("OCI archive has no index.json")
	}
	var index ociIndex
	if err := decodeStrict(indexData, &index); err != nil {
		return "", fmt.Errorf("decode OCI index: %w", err)
	}
	if index.SchemaVersion != 2 || len(index.Manifests) != 1 {
		return "", errors.New("OCI archive must contain exactly one image manifest")
	}
	descriptor := index.Manifests[0]
	actualPlatform := descriptor.Platform.OS + "/" + descriptor.Platform.Architecture
	if actualPlatform != platform {
		return "", fmt.Errorf("OCI image platform is %s, expected %s", actualPlatform, platform)
	}
	if descriptor.MediaType != "application/vnd.oci.image.manifest.v1+json" {
		return "", fmt.Errorf("unexpected OCI manifest media type %q", descriptor.MediaType)
	}
	if err := validateDigest("OCI image digest", descriptor.Digest, true); err != nil {
		return "", err
	}
	manifestDigest := strings.TrimPrefix(descriptor.Digest, "sha256:")
	manifestData, ok := jsonBlobs[manifestDigest]
	if !ok || blobHashes[manifestDigest] == "" {
		return "", errors.New("OCI image manifest blob is missing")
	}
	if blobSizes[manifestDigest] != descriptor.Size {
		return "", errors.New("OCI image manifest descriptor size does not match its blob")
	}
	var manifest ociManifest
	if err := decodeStrict(manifestData, &manifest); err != nil {
		return "", fmt.Errorf("decode OCI image manifest: %w", err)
	}
	if manifest.SchemaVersion != 2 ||
		manifest.Config.MediaType != "application/vnd.oci.image.config.v1+json" ||
		len(manifest.Layers) == 0 {
		return "", errors.New("OCI image manifest has an unsupported config or no layers")
	}
	if err := requireOCIBlob(
		blobHashes,
		blobSizes,
		manifest.Config.Digest,
		manifest.Config.Size,
		"config",
	); err != nil {
		return "", err
	}
	for index, layer := range manifest.Layers {
		switch layer.MediaType {
		case "application/vnd.oci.image.layer.v1.tar+gzip",
			"application/vnd.oci.image.layer.v1.tar+zstd",
			"application/vnd.oci.image.layer.v1.tar":
		default:
			return "", fmt.Errorf("OCI layer %d has unsupported media type %q", index, layer.MediaType)
		}
		if err := requireOCIBlob(
			blobHashes,
			blobSizes,
			layer.Digest,
			layer.Size,
			fmt.Sprintf("layer %d", index),
		); err != nil {
			return "", err
		}
	}
	return descriptor.Digest, nil
}

func requireOCIBlob(
	blobs map[string]string,
	sizes map[string]int64,
	digest string,
	size int64,
	name string,
) error {
	if err := validateDigest("OCI "+name+" digest", digest, true); err != nil {
		return err
	}
	value := strings.TrimPrefix(digest, "sha256:")
	if blobs[value] != value {
		return fmt.Errorf("OCI %s blob %s is missing", name, digest)
	}
	if sizes[value] != size {
		return fmt.Errorf("OCI %s descriptor size does not match its blob", name)
	}
	return nil
}

func CreateBuildRecord(
	baselinePath, ociArchivePath, sbomPath, platform string,
) (BuildRecord, error) {
	baseline, baselineData, err := LoadBaseline(baselinePath)
	if err != nil {
		return BuildRecord{}, err
	}
	imageDigest, err := OCIImageDigest(ociArchivePath, platform)
	if err != nil {
		return BuildRecord{}, err
	}
	sbomData, err := readFileBounded(sbomPath, maxSBOMBytes)
	if err != nil {
		return BuildRecord{}, fmt.Errorf("read SBOM: %w", err)
	}
	if err := VerifySBOM(sbomData, baseline, imageDigest); err != nil {
		return BuildRecord{}, fmt.Errorf("verify SBOM: %w", err)
	}
	ociSHA, err := fileSHA256(ociArchivePath)
	if err != nil {
		return BuildRecord{}, err
	}
	return BuildRecord{
		SchemaVersion:           BuildRecordSchema,
		GeneratedAt:             time.Unix(baseline.SourceDateEpoch, 0).UTC().Format(time.RFC3339),
		Platform:                platform,
		ImageDigest:             imageDigest,
		OCIArchiveSHA256:        ociSHA,
		SBOMSHA256:              bytesSHA256(sbomData),
		BaselineSHA256:          bytesSHA256(baselineData),
		SourceDateEpoch:         baseline.SourceDateEpoch,
		Tengine:                 baseline.Tengine,
		Tongsuo:                 baseline.Tongsuo,
		BuilderImage:            baseline.BuilderImage,
		RuntimeImage:            baseline.RuntimeImage,
		ValidatorBuilderImage:   baseline.ValidatorBuilderImage,
		DockerfileFrontendImage: baseline.DockerfileFrontendImage,
		SyftImage:               baseline.SyftImage,
	}, nil
}

func EncodeBuildRecord(record BuildRecord) ([]byte, error) {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode build record: %w", err)
	}
	return append(data, '\n'), nil
}

func VerifyBuildRecord(
	recordPath, checksumPath, baselinePath, ociArchivePath, sbomPath, platform string,
) error {
	recordData, err := readFileBounded(recordPath, maxBuildRecordBytes)
	if err != nil {
		return fmt.Errorf("read build record: %w", err)
	}
	var actual BuildRecord
	if err := decodeStrict(recordData, &actual); err != nil {
		return fmt.Errorf("decode build record: %w", err)
	}
	expected, err := CreateBuildRecord(baselinePath, ociArchivePath, sbomPath, platform)
	if err != nil {
		return err
	}
	expectedData, err := EncodeBuildRecord(expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(recordData, expectedData) {
		return errors.New("build record does not match the image, SBOM, baseline, and platform")
	}
	checksumData, err := readFileBounded(checksumPath, 1024)
	if err != nil {
		return fmt.Errorf("read build-record checksum: %w", err)
	}
	fields := strings.Fields(string(checksumData))
	if len(fields) != 1 || fields[0] != bytesSHA256(recordData) {
		return errors.New("build-record checksum does not match")
	}
	return nil
}

func validateBaseline(value Baseline) error {
	if value.SchemaVersion != BaselineSchemaVersion {
		return fmt.Errorf("unsupported TLCP build baseline %q", value.SchemaVersion)
	}
	if value.SourceDateEpoch <= 0 {
		return errors.New("build baseline source_date_epoch must be positive")
	}
	for name, source := range map[string]BaselineSource{
		"Tengine": value.Tengine,
		"Tongsuo": value.Tongsuo,
	} {
		if strings.TrimSpace(source.Version) == "" ||
			strings.TrimSpace(source.Commit) == "" ||
			strings.TrimSpace(source.ArchiveURL) == "" {
			return fmt.Errorf("%s build source is incomplete", name)
		}
		if err := validateDigest(name+" archive SHA-256", source.ArchiveSHA256, false); err != nil {
			return err
		}
		if err := validateDigest(name+" license SHA-256", source.LicenseSHA256, false); err != nil {
			return err
		}
	}
	for name, image := range map[string]string{
		"builder image":             value.BuilderImage,
		"runtime image":             value.RuntimeImage,
		"validator builder image":   value.ValidatorBuilderImage,
		"Dockerfile frontend image": value.DockerfileFrontendImage,
		"Syft image":                value.SyftImage,
	} {
		separator := strings.LastIndex(image, "@")
		if separator < 1 || validateDigest(name, image[separator+1:], true) != nil {
			return fmt.Errorf("%s must use an exact sha256 digest", name)
		}
	}
	if len(value.BuilderPackages) == 0 || len(value.RuntimePackages) == 0 ||
		len(value.BuildParameters) == 0 {
		return errors.New("build baseline package and parameter lists must not be empty")
	}
	return nil
}

func sourcePackage(name, license, id string, source BaselineSource) map[string]any {
	return map[string]any{
		"name":             name,
		"SPDXID":           id,
		"versionInfo":      source.Version,
		"supplier":         "Organization: " + name + " project",
		"downloadLocation": source.ArchiveURL,
		"filesAnalyzed":    false,
		"checksums": []any{
			map[string]any{
				"algorithm":     "SHA256",
				"checksumValue": source.ArchiveSHA256,
			},
		},
		"sourceInfo":       "Pinned upstream commit " + source.Commit,
		"licenseConcluded": license,
		"licenseDeclared":  license,
		"copyrightText":    "NOASSERTION",
		"externalRefs": []any{
			map[string]any{
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceType":     "purl",
				"referenceLocator": "pkg:generic/" + strings.ToLower(name) + "@" +
					source.Version,
			},
		},
	}
}

func removePackages(values []any, names ...string) []any {
	remove := make(map[string]bool, len(names))
	for _, name := range names {
		remove[name] = true
	}
	result := values[:0]
	for _, value := range values {
		item, _ := value.(map[string]any)
		name, _ := item["name"].(string)
		if !remove[name] {
			result = append(result, value)
		}
	}
	return result
}

func removeRelationships(values []any, ids ...string) []any {
	remove := make(map[string]bool, len(ids))
	for _, id := range ids {
		remove[id] = true
	}
	result := values[:0]
	for _, value := range values {
		item, _ := value.(map[string]any)
		element, _ := item["spdxElementId"].(string)
		related, _ := item["relatedSpdxElement"].(string)
		if !remove[element] && !remove[related] {
			result = append(result, value)
		}
	}
	return result
}

func sortMaps(values []any, fields ...string) {
	sort.SliceStable(values, func(i, j int) bool {
		return mapSortKey(values[i], fields...) < mapSortKey(values[j], fields...)
	})
}

func mapSortKey(value any, fields ...string) string {
	item, _ := value.(map[string]any)
	var builder strings.Builder
	for _, field := range fields {
		builder.WriteString(fmt.Sprint(item[field]))
		builder.WriteByte(0)
	}
	return builder.String()
}

func decodeStrict(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON: %v", err)
	}
	return nil
}

func validateDigest(name, value string, prefix bool) error {
	if prefix {
		if !strings.HasPrefix(value, "sha256:") {
			return fmt.Errorf("%s must include the sha256: prefix", name)
		}
		value = strings.TrimPrefix(value, "sha256:")
	}
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return fmt.Errorf("%s must be 64 lowercase hexadecimal characters", name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%s must be lowercase hexadecimal: %w", name, err)
	}
	return nil
}

func containsString(values []any, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func hasChecksum(
	values []struct {
		Algorithm string `json:"algorithm"`
		Value     string `json:"checksumValue"`
	},
	algorithm, wanted string,
) bool {
	for _, value := range values {
		if value.Algorithm == algorithm && value.Value == wanted {
			return true
		}
	}
	return false
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readFileBounded(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maximum)
	}
	return data, nil
}

func bytesSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
