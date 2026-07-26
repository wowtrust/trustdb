package supplychain

import (
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
)

const PolicySchema = "trustdb.production-inputs.v1"

var (
	requiredInputIDs = []string{
		"admin-web-lock",
		"desktop-go-lock",
		"desktop-web-lock",
		"fisco-bcos-c-sdk",
		"fisco-bcos-contracts",
		"fisco-bcos-go-sdk",
		"go-lock",
		"pkcs11-interface",
		"sdf-interface",
		"tlcp-gateway",
		"website-lock",
	}
	requiredMirrorKinds  = []string{"gomod", "npm", "oci"}
	requiredContainerIDs = []string{"go-builder", "node-builder", "runtime"}
	actionReference      = regexp.MustCompile(`(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)`)
	dockerFromReference  = regexp.MustCompile(`(?m)^\s*FROM(?:\s+--platform=\S+)?\s+([^\s]+)`)
	dockerArgReference   = regexp.MustCompile(`(?m)^\s*ARG\s+([A-Z][A-Z0-9_]*)=([^\s#]+)\s*$`)
	workflowBuildArg     = regexp.MustCompile(`(?m)^\s+([A-Z][A-Z0-9_]*)=([^\s#]+)\s*$`)
	debianSnapshot       = regexp.MustCompile(`(?m)^\s*ARG\s+DEBIAN_SNAPSHOT=[0-9]{8}T[0-9]{6}Z\s*$`)
)

type Policy struct {
	Schema     string            `json:"schema"`
	Inputs     []ProductionInput `json:"inputs"`
	Containers []ContainerInput  `json:"containers"`
	Mirrors    []MirrorPolicy    `json:"mirrors"`
}

type ProductionInput struct {
	ID                  string   `json:"id"`
	Kind                string   `json:"kind"`
	Version             string   `json:"version"`
	Path                string   `json:"path"`
	SHA256              string   `json:"sha256"`
	LicenseExpression   string   `json:"license_expression"`
	LicenseEvidencePath string   `json:"license_evidence_path"`
	Architectures       []string `json:"architectures"`
}

type ContainerInput struct {
	ID             string   `json:"id"`
	Reference      string   `json:"reference"`
	MirrorBuildArg string   `json:"mirror_build_arg"`
	Architectures  []string `json:"architectures"`
}

type MirrorPolicy struct {
	Kind              string `json:"kind"`
	OverrideEnv       string `json:"override_env"`
	IntegrityRequired string `json:"integrity_required"`
}

func ReadPolicy(path string) (Policy, error) {
	file, err := os.Open(path)
	if err != nil {
		return Policy{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Policy{}, err
	}
	if info.Size() > maxManifestFileBytes {
		return Policy{}, fmt.Errorf("production-input policy exceeds %d bytes", maxManifestFileBytes)
	}
	var policy Policy
	decoder := json.NewDecoder(io.LimitReader(file, maxManifestFileBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("decode production-input policy: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func ValidatePolicy(repositoryRoot, policyPath string) error {
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	resolvedPolicyPath, err := resolveRepositoryPath(root, policyPath)
	if err != nil {
		return fmt.Errorf("production-input policy path: %w", err)
	}
	policy, err := ReadPolicy(resolvedPolicyPath)
	if err != nil {
		return err
	}
	if policy.Schema != PolicySchema {
		return fmt.Errorf("unsupported production-input policy schema %q", policy.Schema)
	}
	if err := validateInputs(root, policy.Inputs); err != nil {
		return err
	}
	if err := validateContainers(policy.Containers); err != nil {
		return err
	}
	if err := validateMirrors(policy.Mirrors); err != nil {
		return err
	}
	if err := validatePinnedActions(filepath.Join(root, ".github", "workflows", "release.yml")); err != nil {
		return err
	}
	if err := validateWorkflowImageOverrides(filepath.Join(root, ".github", "workflows", "release.yml"), policy.Containers); err != nil {
		return err
	}
	if err := validatePinnedDockerfile(filepath.Join(root, "Dockerfile"), policy.Containers); err != nil {
		return err
	}
	return nil
}

func DigestPath(root, relative string) (string, error) {
	path, err := resolveRepositoryPath(root, relative)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode().IsRegular() {
		sha, _, err := hashFile(path)
		return sha, err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("production input %q must be a regular file or directory", relative)
	}
	type record struct {
		path   string
		mode   fs.FileMode
		size   int64
		digest string
	}
	var records []record
	err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("production input %q contains unsupported entry %q", relative, current)
		}
		fileInfo, err := entry.Info()
		if err != nil {
			return err
		}
		digest, _, err := hashFile(current)
		if err != nil {
			return err
		}
		relativePath, err := filepath.Rel(path, current)
		if err != nil {
			return err
		}
		records = append(records, record{
			path: filepath.ToSlash(relativePath), mode: fileInfo.Mode().Perm(), size: fileInfo.Size(), digest: digest,
		})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].path < records[j].path })
	hasher := sha256.New()
	for _, item := range records {
		fmt.Fprintf(hasher, "%s\x00%04o\x00%d\x00%s\n", item.path, item.mode, item.size, item.digest)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func validateInputs(root string, inputs []ProductionInput) error {
	if len(inputs) == 0 {
		return errors.New("production-input policy contains no inputs")
	}
	seen := make(map[string]struct{}, len(inputs))
	last := ""
	for _, input := range inputs {
		if input.ID <= last {
			return errors.New("production inputs must be sorted and unique by id")
		}
		if input.Kind == "" || input.Version == "" {
			return fmt.Errorf("production input %q is missing kind or version", input.ID)
		}
		if err := validateRelativePath(input.Path); err != nil {
			return fmt.Errorf("production input %q: %w", input.ID, err)
		}
		if !isLowerHex(input.SHA256, 64) {
			return fmt.Errorf("production input %q has an invalid SHA-256", input.ID)
		}
		license := strings.ToUpper(strings.TrimSpace(input.LicenseExpression))
		if license == "" || license == "UNKNOWN" || license == "NOASSERTION" {
			return fmt.Errorf("production input %q has unresolved license metadata", input.ID)
		}
		if err := validateRelativePath(input.LicenseEvidencePath); err != nil {
			return fmt.Errorf("production input %q license evidence: %w", input.ID, err)
		}
		licensePath, err := resolveRepositoryPath(root, input.LicenseEvidencePath)
		if err != nil {
			return fmt.Errorf("production input %q license evidence: %w", input.ID, err)
		}
		if err := requireRegularFile(licensePath); err != nil {
			return fmt.Errorf("production input %q license evidence is missing", input.ID)
		}
		if err := validateArchitectures(input.ID, input.Architectures); err != nil {
			return err
		}
		digest, err := DigestPath(root, input.Path)
		if err != nil {
			return fmt.Errorf("digest production input %q: %w", input.ID, err)
		}
		if digest != input.SHA256 {
			return fmt.Errorf("production input %q digest changed: got %s, policy has %s", input.ID, digest, input.SHA256)
		}
		seen[input.ID] = struct{}{}
		last = input.ID
	}
	for _, id := range requiredInputIDs {
		if _, ok := seen[id]; !ok {
			return fmt.Errorf("required production input %q is missing", id)
		}
	}
	return nil
}

func validateContainers(containers []ContainerInput) error {
	if len(containers) == 0 {
		return errors.New("production-input policy contains no container inputs")
	}
	last := ""
	seenIDs := make(map[string]struct{}, len(containers))
	seenBuildArgs := make(map[string]struct{}, len(containers))
	for _, container := range containers {
		if container.ID <= last {
			return errors.New("container inputs must be sorted and unique by id")
		}
		parts := strings.Split(container.Reference, "@sha256:")
		if len(parts) != 2 || parts[0] == "" || !isLowerHex(parts[1], 64) {
			return fmt.Errorf("container input %q is not pinned by sha256 digest", container.ID)
		}
		if container.MirrorBuildArg == "" {
			return fmt.Errorf("container input %q does not expose a domestic-mirror build argument", container.ID)
		}
		if _, duplicate := seenBuildArgs[container.MirrorBuildArg]; duplicate {
			return fmt.Errorf("container mirror build argument %q is duplicated", container.MirrorBuildArg)
		}
		if err := validateArchitectures(container.ID, container.Architectures); err != nil {
			return err
		}
		seenIDs[container.ID] = struct{}{}
		seenBuildArgs[container.MirrorBuildArg] = struct{}{}
		last = container.ID
	}
	for _, id := range requiredContainerIDs {
		if _, ok := seenIDs[id]; !ok {
			return fmt.Errorf("required container input %q is missing", id)
		}
	}
	return nil
}

func validateMirrors(mirrors []MirrorPolicy) error {
	seen := make(map[string]struct{}, len(mirrors))
	last := ""
	for _, mirror := range mirrors {
		if mirror.Kind <= last {
			return errors.New("mirror policies must be sorted and unique by kind")
		}
		if mirror.OverrideEnv == "" {
			return fmt.Errorf("%s mirror has no override environment variable", mirror.Kind)
		}
		if mirror.IntegrityRequired != "sha256-or-stronger" {
			return fmt.Errorf("%s mirror must retain sha256-or-stronger integrity", mirror.Kind)
		}
		seen[mirror.Kind] = struct{}{}
		last = mirror.Kind
	}
	for _, kind := range requiredMirrorKinds {
		if _, ok := seen[kind]; !ok {
			return fmt.Errorf("required %s mirror policy is missing", kind)
		}
	}
	return nil
}

func validatePinnedActions(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	matches := actionReference.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return errors.New("release workflow contains no action references")
	}
	for _, match := range matches {
		reference := string(match[1])
		if strings.HasPrefix(reference, "./") {
			if err := validateRelativePath(strings.TrimPrefix(reference, "./")); err != nil {
				return fmt.Errorf("release workflow local action reference %q is unsafe", reference)
			}
			continue
		}
		separator := strings.LastIndexByte(reference, '@')
		if separator <= 0 || !isLowerHex(reference[separator+1:], 40) {
			return fmt.Errorf("release workflow action reference %q is not pinned to a full commit SHA", reference)
		}
	}
	return nil
}

func validateWorkflowImageOverrides(path string, containers []ContainerInput) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	expected := make(map[string]string, len(containers))
	for _, container := range containers {
		expected[container.MirrorBuildArg] = container.Reference
	}
	for _, match := range workflowBuildArg.FindAllSubmatch(data, -1) {
		name := string(match[1])
		reference, controlled := expected[name]
		if !controlled {
			continue
		}
		if string(match[2]) != reference {
			return fmt.Errorf("release workflow overrides %q with a non-policy image reference", name)
		}
	}
	return nil
}

func validatePinnedDockerfile(path string, containers []ContainerInput) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	matches := dockerFromReference.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return errors.New("Dockerfile contains no FROM instructions")
	}
	allowedArgs := make(map[string]struct{}, len(containers))
	expectedDefaults := make(map[string]string, len(containers))
	for _, container := range containers {
		allowedArgs["${"+container.MirrorBuildArg+"}"] = struct{}{}
		expectedDefaults[container.MirrorBuildArg] = container.Reference
	}
	for _, match := range matches {
		reference := string(match[1])
		if _, ok := allowedArgs[reference]; !ok {
			return fmt.Errorf("Dockerfile base image %q is not a policy-controlled digest build argument", reference)
		}
	}
	actualDefaults := make(map[string]string)
	for _, match := range dockerArgReference.FindAllSubmatch(data, -1) {
		actualDefaults[string(match[1])] = string(match[2])
	}
	for name, reference := range expectedDefaults {
		if actualDefaults[name] != reference {
			return fmt.Errorf("Dockerfile build argument %q must default to policy reference %q", name, reference)
		}
	}
	if !debianSnapshot.Match(data) {
		return errors.New("Dockerfile must pin an immutable Debian snapshot timestamp")
	}
	for _, packageName := range []string{"ca-certificates", "curl", "tini", "tzdata"} {
		if !regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(packageName) + `=[^\s\\]+`).Match(data) {
			return fmt.Errorf("Dockerfile runtime package %q is not pinned to an exact version", packageName)
		}
	}
	return nil
}

func resolveRepositoryPath(root, relative string) (string, error) {
	relative = filepath.ToSlash(relative)
	if err := validateRelativePath(relative); err != nil {
		return "", err
	}
	rootPath, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	rootPath, err = filepath.EvalSymlinks(rootPath)
	if err != nil {
		return "", err
	}
	candidate := filepath.Join(rootPath, filepath.FromSlash(relative))
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	if filepath.Clean(resolved) != filepath.Clean(candidate) {
		return "", fmt.Errorf("repository path %q must not traverse symbolic links", relative)
	}
	withinRoot, err := filepath.Rel(rootPath, resolved)
	if err != nil || withinRoot == ".." || strings.HasPrefix(withinRoot, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("repository path %q escapes repository root", relative)
	}
	return candidate, nil
}

func validateArchitectures(id string, architectures []string) error {
	if len(architectures) == 0 {
		return fmt.Errorf("production input %q has no architecture support declaration", id)
	}
	last := ""
	for _, architecture := range architectures {
		if architecture <= last {
			return fmt.Errorf("production input %q architectures must be sorted and unique", id)
		}
		switch architecture {
		case "all", "darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64", "windows/amd64", "windows/arm64":
		default:
			return fmt.Errorf("production input %q has unsupported architecture value %q", id, architecture)
		}
		last = architecture
	}
	return nil
}
