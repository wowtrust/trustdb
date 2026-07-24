package tlcpprofile

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type buildBaseline struct {
	SchemaVersion         string         `json:"schema_version"`
	SourceDateEpoch       int64          `json:"source_date_epoch"`
	Tengine               baselineSource `json:"tengine"`
	Tongsuo               baselineSource `json:"tongsuo"`
	BuilderImage          string         `json:"builder_image"`
	RuntimeImage          string         `json:"runtime_image"`
	ValidatorBuilderImage string         `json:"validator_builder_image"`
	FrontendImage         string         `json:"dockerfile_frontend_image"`
	DebianSnapshot        string         `json:"debian_snapshot"`
	BuilderPackages       []string       `json:"builder_packages"`
	RuntimePackages       []string       `json:"runtime_packages"`
	SyftImage             string         `json:"syft_image"`
	BuildParameters       []string       `json:"build_parameters"`
}

type baselineSource struct {
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	ArchiveURL    string `json:"archive_url"`
	ArchiveSHA256 string `json:"archive_sha256"`
	LicenseSHA256 string `json:"license_sha256"`
}

func TestProductionBuildBaselineMatchesProfileContract(t *testing.T) {
	path := filepath.Join("..", "..", "packaging", "tlcp-gateway", "baseline.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var baseline buildBaseline
	if err := decoder.Decode(&baseline); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("baseline has trailing JSON: %v", err)
	}
	if baseline.SchemaVersion != "trustdb.tlcp-gateway-build-baseline.v1" ||
		baseline.SourceDateEpoch != 1702545703 ||
		baseline.Tengine.Version != PinnedTengineVersion ||
		baseline.Tengine.Commit != PinnedTengineCommit ||
		baseline.Tengine.ArchiveSHA256 != PinnedTengineSourceSHA256 ||
		baseline.Tongsuo.Version != PinnedTongsuoVersion ||
		baseline.Tongsuo.Commit != PinnedTongsuoCommit ||
		baseline.Tongsuo.ArchiveSHA256 != PinnedTongsuoSourceSHA256 ||
		baseline.BuilderImage != PinnedBuilderImage ||
		baseline.RuntimeImage != PinnedRuntimeImage ||
		baseline.ValidatorBuilderImage != PinnedValidatorBuilderImage ||
		!equalStrings(baseline.BuildParameters, requiredBuildParameters()) {
		t.Fatalf("build baseline drifted from the profile contract: %+v", baseline)
	}
	for name, value := range map[string]string{
		"tengine archive URL": baseline.Tengine.ArchiveURL,
		"tengine license":     baseline.Tengine.LicenseSHA256,
		"tongsuo archive URL": baseline.Tongsuo.ArchiveURL,
		"tongsuo license":     baseline.Tongsuo.LicenseSHA256,
		"Debian snapshot":     baseline.DebianSnapshot,
		"Dockerfile frontend": baseline.FrontendImage,
		"Syft image":          baseline.SyftImage,
	} {
		if strings.TrimSpace(value) == "" {
			t.Fatalf("%s is empty", name)
		}
	}
	if len(baseline.BuilderPackages) == 0 || len(baseline.RuntimePackages) == 0 {
		t.Fatal("build baseline contains no builder or runtime packages")
	}
}

func TestDockerfileContainsExactBuildPins(t *testing.T) {
	path := filepath.Join("..", "..", "packaging", "tlcp-gateway", "Dockerfile")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"Tengine source SHA-256":  PinnedTengineSourceSHA256,
		"Tongsuo source SHA-256":  PinnedTongsuoSourceSHA256,
		"builder/runtime image":   PinnedBuilderImage,
		"validator builder image": PinnedValidatorBuilderImage,
		"Tengine commit":          PinnedTengineCommit,
		"Tongsuo commit":          PinnedTongsuoCommit,
	} {
		if !bytes.Contains(data, []byte(value)) {
			t.Fatalf("Dockerfile does not contain pinned %s", name)
		}
	}
}
