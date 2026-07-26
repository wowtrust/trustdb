package supplychain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDigestPathIsStableAndContentBound(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "input"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "input", "b.txt"), "b")
	writeTestFile(t, filepath.Join(root, "input", "a.txt"), "a")
	first, err := DigestPath(root, "input")
	if err != nil {
		t.Fatal(err)
	}
	second, err := DigestPath(root, "input")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("directory digest changed: %s != %s", first, second)
	}
	writeTestFile(t, filepath.Join(root, "input", "a.txt"), "changed")
	changed, err := DigestPath(root, "input")
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Fatal("directory digest did not bind file content")
	}
}

func TestValidatePinnedActionsRejectsFloatingTag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release.yml")
	writeTestFile(t, path, "steps:\n  - uses: actions/checkout@v7\n")
	err := validatePinnedActions(path)
	if err == nil || !strings.Contains(err.Error(), "full commit SHA") {
		t.Fatalf("validatePinnedActions() error = %v", err)
	}
	writeTestFile(t, path, "steps:\n  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n")
	if err := validatePinnedActions(path); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, "steps:\n  - uses: attacker/floating-action\n  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n")
	if err := validatePinnedActions(path); err == nil || !strings.Contains(err.Error(), "full commit SHA") {
		t.Fatalf("validatePinnedActions() missing-at error = %v", err)
	}
}

func TestValidatePinnedDockerfileBindsPolicyDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Dockerfile")
	containers := []ContainerInput{
		{
			ID: "go-builder", MirrorBuildArg: "GO_IMAGE",
			Reference:     "registry.example/go@sha256:" + strings.Repeat("a", 64),
			Architectures: []string{"linux/amd64"},
		},
	}
	writeTestFile(t, path, "ARG GO_IMAGE=registry.example/go:latest\nFROM ${GO_IMAGE}\nARG DEBIAN_SNAPSHOT=20260713T000000Z\nca-certificates=1 \\\ncurl=1 \\\ntini=1 \\\ntzdata=1 \\\n")
	err := validatePinnedDockerfile(path, containers)
	if err == nil || !strings.Contains(err.Error(), "must default to policy reference") {
		t.Fatalf("validatePinnedDockerfile() error = %v", err)
	}
}

func TestValidateWorkflowImageOverridesRejectsFloatingReference(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release.yml")
	containers := []ContainerInput{{
		ID:             "go-builder",
		MirrorBuildArg: "GO_IMAGE",
		Reference:      "registry.example/go@sha256:" + strings.Repeat("a", 64),
		Architectures:  []string{"linux/amd64"},
	}}
	writeTestFile(t, path, "build-args: |\n  GO_IMAGE=registry.example/go:latest\n")
	err := validateWorkflowImageOverrides(path, containers)
	if err == nil || !strings.Contains(err.Error(), "non-policy image") {
		t.Fatalf("validateWorkflowImageOverrides() error = %v", err)
	}
}

func TestDigestPathRejectsSymlinkTraversal(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeTestFile(t, filepath.Join(outside, "input.txt"), "outside")
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := DigestPath(root, "linked/input.txt"); err == nil || !strings.Contains(err.Error(), "symbolic links") {
		t.Fatalf("DigestPath() error = %v, want symlink rejection", err)
	}
}
