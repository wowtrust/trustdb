package config

import (
	"fmt"
	"strings"
)

// Shipped run profile labels (YAML field run_profile).
const (
	RunProfileDevelopment          = "development"
	RunProfileSingleNodeProduction = "single_node_production"
	RunProfileChinaProduction      = "china_production"
	RunProfileOfflineIsolated      = "offline_isolated"
	RunProfileAssessment           = "assessment"
	RunProfileBenchmark            = "benchmark"
)

// NormalizeRunProfile maps aliases to canonical slugs. Unknown values return "".
func NormalizeRunProfile(s string) string {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return ""
	}
	switch strings.ToLower(raw) {
	case "dev", "development":
		return RunProfileDevelopment
	case "single-node-prod", "single_node_production", "prod", "production":
		return RunProfileSingleNodeProduction
	case "china-prod", "china_production", "cn-prod", "cn_production":
		return RunProfileChinaProduction
	case "air-gapped", "offline", "offline-isolated", "offline_isolated":
		return RunProfileOfflineIsolated
	case "assessment", "assess":
		return RunProfileAssessment
	case "bench", "benchmark", "loadtest":
		return RunProfileBenchmark
	default:
		return ""
	}
}

func validateRunProfileField(s string) error {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	if n := NormalizeRunProfile(s); n == "" {
		return fmt.Errorf("run_profile must be one of development, single_node_production, china_production, offline_isolated, assessment, benchmark; got %q", s)
	}
	return nil
}

// RunProfileStartupTitle is a single-line operator-facing summary for logs.
func RunProfileStartupTitle(canonical string) string {
	switch canonical {
	case RunProfileDevelopment:
		return "declared run_profile=development: local demos and debugging; not for production traffic"
	case RunProfileSingleNodeProduction:
		return "declared run_profile=single_node_production: baseline single-node operations; verify keys, disks, and anchor sink"
	case RunProfileChinaProduction:
		return "declared run_profile=china_production: CN_SM_V1, non-exportable keys, pinned transports, audited startup, and explicit egress are enforced"
	case RunProfileOfflineIsolated:
		return "declared run_profile=offline_isolated: Internet-independent operation with all outbound connections denied"
	case RunProfileAssessment:
		return "declared run_profile=assessment: China production controls plus signed evidence of every time-bounded exception"
	case RunProfileBenchmark:
		return "declared run_profile=benchmark: throughput and load experiments; durability and L5 semantics may be relaxed"
	default:
		return ""
	}
}

// RunProfileWarnings lists extra cautions when the live flags diverge from the profile intent.
func RunProfileWarnings(canonical, metastoreBackend, anchorSink string) []string {
	meta := strings.ToLower(strings.TrimSpace(metastoreBackend))
	anchor := strings.ToLower(strings.TrimSpace(anchorSink))
	var out []string
	switch canonical {
	case RunProfileDevelopment:
		if meta != "" && meta != "file" {
			out = append(out, fmt.Sprintf("run_profile is development but proofstore backend is %q; shipped development.yaml uses file", meta))
		}
		if anchor != "" && anchor != "noop" && anchor != "off" {
			out = append(out, fmt.Sprintf("run_profile is development but anchor sink is %q; demos usually use noop", anchor))
		}
	case RunProfileSingleNodeProduction:
		if meta == "file" {
			out = append(out, "run_profile is single_node_production but proofstore backend is file; use pebble or tikv for sustained write loads")
		}
		if anchor == "noop" || anchor == "off" || anchor == "" {
			out = append(out, "run_profile is single_node_production but anchor sink will not publish L5 anchors (noop/off)")
		}
	case RunProfileChinaProduction, RunProfileAssessment:
		if meta == "file" {
			out = append(out, fmt.Sprintf("run_profile is %s but proofstore backend is file; use pebble or tikv", canonical))
		}
		if anchor != "fisco-bcos" {
			out = append(out, fmt.Sprintf("run_profile is %s but anchor sink is %q; the strict profile requires fisco-bcos", canonical, anchor))
		}
	case RunProfileOfflineIsolated:
		if anchor != "" && anchor != "off" && anchor != "file" && anchor != "noop" {
			out = append(out, fmt.Sprintf("offline_isolated profile uses an outbound anchor sink %q", anchor))
		}
	case RunProfileBenchmark:
		out = append(out, "benchmark profile: results are not audit-grade; re-run with production.yaml semantics before any compliance claims")
		if anchor != "" && anchor != "noop" && anchor != "off" {
			out = append(out, fmt.Sprintf("benchmark profile usually pairs with noop anchor; sink=%q may skew ingest numbers", anchor))
		}
	}
	return out
}
