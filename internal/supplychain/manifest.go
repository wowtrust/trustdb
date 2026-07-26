package supplychain

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm3"
)

const (
	ManifestSchema       = "trustdb.release-manifest.v1"
	ManifestFilename     = "TRUSTDB_RELEASE_MANIFEST.json"
	SHA256Filename       = "SHA256SUMS"
	SM3Filename          = "SM3SUMS"
	AttestationFilename  = "trustdb-release-attestation.sigstore.json"
	ProductionInputsFile = "TRUSTDB_PRODUCTION_INPUTS.json"
	defaultSourceRepo    = "https://github.com/wowtrust/trustdb"
	maxManifestFileBytes = 4 << 20
)

var mandatoryDocuments = []string{
	"TRUSTDB_CONTAINER_DIGESTS.json",
	ProductionInputsFile,
	"TRUSTDB_VULNERABILITY_REPORT.json",
	"trustdb-release.spdx.json",
}

var (
	releaseVersion       = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	portableArtifactName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
)

type Manifest struct {
	Schema            string     `json:"schema"`
	Version           string     `json:"version"`
	Source            Source     `json:"source"`
	PolicySHA256      string     `json:"policy_sha256"`
	RequiredDocuments []string   `json:"required_documents"`
	Artifacts         []Artifact `json:"artifacts"`
}

type Source struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	BuildDate  string `json:"build_date"`
}

type Artifact struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	SM3       string `json:"sm3"`
}

type GenerateOptions struct {
	Directory         string
	Version           string
	Commit            string
	BuildDate         string
	PolicyPath        string
	RequiredDocuments []string
}

func Generate(options GenerateOptions) (Manifest, error) {
	if strings.TrimSpace(options.Version) == "" {
		return Manifest{}, errors.New("release version is required")
	}
	if !isLowerHex(options.Commit, 40) {
		return Manifest{}, errors.New("source commit must be a 40-character lowercase hexadecimal Git commit")
	}
	if _, err := time.Parse(time.RFC3339, options.BuildDate); err != nil {
		return Manifest{}, fmt.Errorf("build date must be RFC 3339: %w", err)
	}
	directory, err := cleanDirectory(options.Directory)
	if err != nil {
		return Manifest{}, err
	}
	policyHash, _, err := hashFile(options.PolicyPath)
	if err != nil {
		return Manifest{}, fmt.Errorf("hash production-input policy: %w", err)
	}
	required, err := cleanSortedPaths(append(append([]string(nil), mandatoryDocuments...), options.RequiredDocuments...))
	if err != nil {
		return Manifest{}, fmt.Errorf("required documents: %w", err)
	}

	var artifacts []Artifact
	err = filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == directory {
			return nil
		}
		if entry.IsDir() {
			return fmt.Errorf("release directory must be flat; found directory %q", path)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("release artifact %q must not be a symbolic link", path)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("release artifact %q must be a regular file", path)
		}
		name := filepath.Base(path)
		if isGeneratedSidecar(name) {
			return nil
		}
		sha256Hex, sm3Hex, size, err := hashFileWithSize(path)
		if err != nil {
			return err
		}
		artifacts = append(artifacts, Artifact{
			Path:      name,
			Kind:      artifactKind(name),
			MediaType: mediaType(name),
			Size:      size,
			SHA256:    sha256Hex,
			SM3:       sm3Hex,
		})
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	if len(artifacts) == 0 {
		return Manifest{}, errors.New("release directory contains no artifacts")
	}
	byPath := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		byPath[artifact.Path] = struct{}{}
	}
	for _, name := range required {
		if _, ok := byPath[name]; !ok {
			return Manifest{}, fmt.Errorf("required release document %q is missing", name)
		}
	}
	if artifact, ok := artifactByPath(artifacts, ProductionInputsFile); !ok || artifact.SHA256 != policyHash {
		return Manifest{}, errors.New("release production-input inventory must exactly match the policy used to generate the manifest")
	}
	return Manifest{
		Schema:            ManifestSchema,
		Version:           options.Version,
		Source:            Source{Repository: defaultSourceRepo, Commit: options.Commit, BuildDate: options.BuildDate},
		PolicySHA256:      policyHash,
		RequiredDocuments: required,
		Artifacts:         artifacts,
	}, nil
}

func Write(directory string, manifest Manifest) error {
	if err := validateManifest(manifest); err != nil {
		return err
	}
	directory, err := cleanDirectory(directory)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(directory, ManifestFilename), encoded, 0o644); err != nil {
		return fmt.Errorf("write release manifest: %w", err)
	}
	return WriteChecksums(directory, manifest)
}

func Read(path string) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Manifest{}, err
	}
	if info.Size() > maxManifestFileBytes {
		return Manifest{}, fmt.Errorf("release manifest exceeds %d bytes", maxManifestFileBytes)
	}
	var manifest Manifest
	decoder := json.NewDecoder(io.LimitReader(file, maxManifestFileBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode release manifest: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return Manifest{}, err
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func Verify(directory string, manifest Manifest) error {
	if err := validateManifest(manifest); err != nil {
		return err
	}
	directory, err := cleanDirectory(directory)
	if err != nil {
		return err
	}
	for _, name := range []string{ManifestFilename, SHA256Filename, SM3Filename, AttestationFilename} {
		if err := requireRegularFile(filepath.Join(directory, name)); err != nil {
			return fmt.Errorf("release sidecar %q: %w", name, err)
		}
	}
	expected := map[string]struct{}{
		ManifestFilename:    {},
		SHA256Filename:      {},
		SM3Filename:         {},
		AttestationFilename: {},
	}
	for _, artifact := range manifest.Artifacts {
		expected[artifact.Path] = struct{}{}
		path := filepath.Join(directory, filepath.FromSlash(artifact.Path))
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("stat release artifact %q: %w", artifact.Path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("release artifact %q must be a regular file", artifact.Path)
		}
		sha256Hex, sm3Hex, size, err := hashFileWithSize(path)
		if err != nil {
			return fmt.Errorf("hash release artifact %q: %w", artifact.Path, err)
		}
		if size != artifact.Size || sha256Hex != artifact.SHA256 || sm3Hex != artifact.SM3 {
			return fmt.Errorf("release artifact %q does not match its manifest entry", artifact.Path)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return fmt.Errorf("unexpected directory %q in release bundle", entry.Name())
		}
		if _, ok := expected[entry.Name()]; !ok {
			return fmt.Errorf("unmanifested file %q in release bundle", entry.Name())
		}
	}
	if err := verifyChecksumFile(directory, manifest, SHA256Filename, func(artifact Artifact) string { return artifact.SHA256 }); err != nil {
		return err
	}
	if err := verifyChecksumFile(directory, manifest, SM3Filename, func(artifact Artifact) string { return artifact.SM3 }); err != nil {
		return err
	}
	return nil
}

func WriteChecksums(directory string, manifest Manifest) error {
	manifestSHA256, manifestSM3, _, err := hashFileWithSize(filepath.Join(directory, ManifestFilename))
	if err != nil {
		return err
	}
	shaLines := []string{manifestSHA256 + "  " + ManifestFilename}
	sm3Lines := []string{manifestSM3 + "  " + ManifestFilename}
	for _, artifact := range manifest.Artifacts {
		shaLines = append(shaLines, artifact.SHA256+"  "+artifact.Path)
		sm3Lines = append(sm3Lines, artifact.SM3+"  "+artifact.Path)
	}
	if err := os.WriteFile(filepath.Join(directory, SHA256Filename), []byte(strings.Join(shaLines, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, SM3Filename), []byte(strings.Join(sm3Lines, "\n")+"\n"), 0o644)
}

func validateManifest(manifest Manifest) error {
	if manifest.Schema != ManifestSchema {
		return fmt.Errorf("unsupported release manifest schema %q", manifest.Schema)
	}
	if !releaseVersion.MatchString(manifest.Version) {
		return errors.New("release manifest version is invalid")
	}
	if manifest.Source.Repository != defaultSourceRepo {
		return fmt.Errorf("unexpected source repository %q", manifest.Source.Repository)
	}
	if !isLowerHex(manifest.Source.Commit, 40) {
		return errors.New("release manifest source commit is invalid")
	}
	if _, err := time.Parse(time.RFC3339, manifest.Source.BuildDate); err != nil {
		return errors.New("release manifest build date is invalid")
	}
	if !isLowerHex(manifest.PolicySHA256, 64) {
		return errors.New("release manifest policy SHA-256 is invalid")
	}
	required, err := cleanSortedPaths(manifest.RequiredDocuments)
	if err != nil || !equalStrings(required, manifest.RequiredDocuments) {
		return errors.New("release manifest required_documents must be sorted, unique, safe paths")
	}
	requiredSet := make(map[string]struct{}, len(required))
	for _, name := range required {
		requiredSet[name] = struct{}{}
	}
	for _, name := range mandatoryDocuments {
		if _, ok := requiredSet[name]; !ok {
			return fmt.Errorf("release manifest is missing mandatory document %q", name)
		}
	}
	if len(manifest.Artifacts) == 0 {
		return errors.New("release manifest contains no artifacts")
	}
	seen := make(map[string]struct{}, len(manifest.Artifacts))
	last := ""
	for _, artifact := range manifest.Artifacts {
		if artifact.Path <= last {
			return errors.New("release manifest artifacts must be sorted and unique")
		}
		if err := validateRelativePath(artifact.Path); err != nil {
			return fmt.Errorf("release artifact path: %w", err)
		}
		if strings.Contains(artifact.Path, "/") {
			return fmt.Errorf("release artifact %q must be at bundle root", artifact.Path)
		}
		if !portableArtifactName.MatchString(artifact.Path) {
			return fmt.Errorf("release artifact %q is not a portable filename", artifact.Path)
		}
		if isGeneratedSidecar(artifact.Path) {
			return fmt.Errorf("release artifact %q uses a reserved sidecar name", artifact.Path)
		}
		if artifact.Size < 0 || !isLowerHex(artifact.SHA256, 64) || !isLowerHex(artifact.SM3, 64) {
			return fmt.Errorf("release artifact %q has invalid size or digest", artifact.Path)
		}
		if artifact.Kind != artifactKind(artifact.Path) || artifact.MediaType != mediaType(artifact.Path) {
			return fmt.Errorf("release artifact %q has inconsistent kind or media type", artifact.Path)
		}
		seen[artifact.Path] = struct{}{}
		last = artifact.Path
	}
	for _, name := range required {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("required release document %q is not manifested", name)
		}
	}
	if artifact, ok := artifactByPath(manifest.Artifacts, ProductionInputsFile); !ok || artifact.SHA256 != manifest.PolicySHA256 {
		return errors.New("release manifest policy digest does not match the production-input inventory")
	}
	return nil
}

func verifyChecksumFile(directory string, manifest Manifest, filename string, digest func(Artifact) string) error {
	expected := make(map[string]string, len(manifest.Artifacts)+1)
	manifestSHA256, manifestSM3, _, err := hashFileWithSize(filepath.Join(directory, ManifestFilename))
	if err != nil {
		return err
	}
	if filename == SHA256Filename {
		expected[ManifestFilename] = manifestSHA256
	} else {
		expected[ManifestFilename] = manifestSM3
	}
	for _, artifact := range manifest.Artifacts {
		expected[artifact.Path] = digest(artifact)
	}
	file, err := os.Open(filepath.Join(directory, filename))
	if err != nil {
		return fmt.Errorf("open %s: %w", filename, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() > maxManifestFileBytes {
		return fmt.Errorf("%s exceeds %d bytes", filename, maxManifestFileBytes)
	}
	seen := make(map[string]struct{}, len(expected))
	scanner := bufio.NewScanner(io.LimitReader(file, maxManifestFileBytes))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || expected[parts[1]] != parts[0] {
			return fmt.Errorf("%s contains an invalid entry", filename)
		}
		if _, duplicate := seen[parts[1]]; duplicate {
			return fmt.Errorf("%s contains duplicate entry %q", filename, parts[1])
		}
		seen[parts[1]] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("%s does not cover every manifested file", filename)
	}
	return nil
}

func hashFile(path string) (string, string, error) {
	sha256Hex, sm3Hex, _, err := hashFileWithSize(path)
	return sha256Hex, sm3Hex, err
}

func hashFileWithSize(path string) (string, string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", 0, err
	}
	defer file.Close()
	shaHasher := sha256.New()
	sm3Hasher := sm3.New()
	size, err := io.Copy(io.MultiWriter(shaHasher, sm3Hasher), file)
	if err != nil {
		return "", "", 0, err
	}
	return hex.EncodeToString(shaHasher.Sum(nil)), hex.EncodeToString(sm3Hasher.Sum(nil)), size, nil
}

func cleanDirectory(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("release directory is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%q must not be a symbolic link", path)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%q is not a directory", path)
	}
	return absolute, nil
}

func cleanSortedPaths(paths []string) ([]string, error) {
	cleaned := append([]string(nil), paths...)
	for _, path := range cleaned {
		if err := validateRelativePath(path); err != nil {
			return nil, err
		}
	}
	sort.Strings(cleaned)
	for index := 1; index < len(cleaned); index++ {
		if cleaned[index] == cleaned[index-1] {
			return nil, fmt.Errorf("duplicate path %q", cleaned[index])
		}
	}
	return cleaned, nil
}

func validateRelativePath(path string) error {
	if path == "" || strings.ContainsAny(path, `\:`) || filepath.IsAbs(path) || filepath.ToSlash(filepath.Clean(path)) != path || path == "." || strings.HasPrefix(path, "../") {
		return fmt.Errorf("unsafe relative path %q", path)
	}
	for _, value := range path {
		if value < 0x20 || value == 0x7f {
			return fmt.Errorf("unsafe relative path %q", path)
		}
	}
	return nil
}

func isGeneratedSidecar(name string) bool {
	switch name {
	case ManifestFilename, SHA256Filename, SM3Filename, AttestationFilename:
		return true
	default:
		return false
	}
}

func artifactByPath(artifacts []Artifact, path string) (Artifact, bool) {
	index := sort.Search(len(artifacts), func(index int) bool { return artifacts[index].Path >= path })
	if index == len(artifacts) || artifacts[index].Path != path {
		return Artifact{}, false
	}
	return artifacts[index], true
}

func requireRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("must be a regular file")
	}
	return nil
}

func artifactKind(name string) string {
	switch {
	case strings.HasSuffix(name, ".spdx.json"):
		return "sbom"
	case strings.Contains(strings.ToLower(name), "vulnerability"):
		return "vulnerability-report"
	case strings.Contains(strings.ToLower(name), "production-input"):
		return "production-input-inventory"
	case strings.Contains(strings.ToLower(name), "container-digest"):
		return "container-digest-inventory"
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".zip"), strings.HasSuffix(name, ".dmg"), strings.HasSuffix(name, ".pkg"), strings.HasSuffix(name, ".msi"), strings.HasSuffix(name, ".exe"):
		return "distribution"
	default:
		return "release-metadata"
	}
}

func mediaType(name string) string {
	switch {
	case strings.HasSuffix(name, ".tar.gz"):
		return "application/gzip"
	case strings.HasSuffix(name, ".spdx.json"):
		return "application/spdx+json"
	case strings.HasSuffix(name, ".json"):
		return "application/json"
	case strings.HasSuffix(name, ".zip"):
		return "application/zip"
	case strings.HasSuffix(name, ".dmg"):
		return "application/x-apple-diskimage"
	case strings.HasSuffix(name, ".pkg"):
		return "application/vnd.apple.installer+xml"
	case strings.HasSuffix(name, ".msi"):
		return "application/x-msi"
	case strings.HasSuffix(name, ".cer"):
		return "application/pkix-cert"
	case strings.HasSuffix(name, ".txt"):
		return "text/plain"
	case strings.HasSuffix(name, ".exe"), strings.HasSuffix(name, ".wixpdb"):
		return "application/octet-stream"
	default:
		return "application/octet-stream"
	}
}

func isLowerHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON document contains trailing data")
		}
		return err
	}
	return nil
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
