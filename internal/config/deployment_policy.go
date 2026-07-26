package config

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	EgressUnrestricted = "unrestricted"
	EgressAllowlist    = "allowlist"
	EgressDenyAll      = "deny_all"

	PolicyControlServerCryptoSuite = "server_crypto_suite"
	PolicyControlAuditCryptoSuite  = "audit_crypto_suite"
	PolicyControlBCOSCryptoMode    = "bcos_crypto_mode"
	PolicyControlServerKeyCustody  = "server_key_custody"
	PolicyControlAuditKeyCustody   = "audit_key_custody"
	PolicyControlBCOSKeyCustody    = "bcos_key_custody"
	PolicyControlServerPins        = "server_transport_pins"
	PolicyControlBCOSPins          = "bcos_transport_pins"
	PolicyControlEgress            = "egress"
	PolicyControlAnchor            = "anchor"
	PolicyControlBackupKey         = "backup_key"
)

var supportedPolicyControls = map[string]struct{}{
	PolicyControlServerCryptoSuite: {},
	PolicyControlAuditCryptoSuite:  {},
	PolicyControlBCOSCryptoMode:    {},
	PolicyControlServerKeyCustody:  {},
	PolicyControlAuditKeyCustody:   {},
	PolicyControlBCOSKeyCustody:    {},
	PolicyControlServerPins:        {},
	PolicyControlBCOSPins:          {},
	PolicyControlEgress:            {},
	PolicyControlAnchor:            {},
	PolicyControlBackupKey:         {},
}

// DeploymentPolicy is an application-level startup gate. It does not claim to
// replace a host firewall: it prevents TrustDB from opening any configured
// outbound connection that is not declared exactly in AllowedEndpoints.
type DeploymentPolicy struct {
	EgressMode          string            `mapstructure:"egress_mode" json:"egress_mode"`
	AllowedEndpoints    []string          `mapstructure:"allowed_endpoints" json:"allowed_endpoints"`
	DNSAllowlist        []string          `mapstructure:"dns_allowlist" json:"dns_allowlist"`
	TelemetryEnabled    bool              `mapstructure:"telemetry_enabled" json:"telemetry_enabled"`
	UpdateChecksEnabled bool              `mapstructure:"update_checks_enabled" json:"update_checks_enabled"`
	Exceptions          []PolicyException `mapstructure:"exceptions" json:"exceptions"`
}

// PolicyException is deliberately verbose because every field is copied into
// the signed security audit trail before TrustDB opens a listener.
type PolicyException struct {
	ID         string `mapstructure:"id" json:"id"`
	Control    string `mapstructure:"control" json:"control"`
	Reason     string `mapstructure:"reason" json:"reason"`
	ApprovedBy string `mapstructure:"approved_by" json:"approved_by"`
	Ticket     string `mapstructure:"ticket" json:"ticket"`
	ExpiresAt  string `mapstructure:"expires_at" json:"expires_at"`
}

type OutboundEndpoint struct {
	Source   string
	Endpoint string
}

type DeploymentRuntime struct {
	ServerCryptoSuite string
	ServerKeyProvider string
	AuditCryptoSuite  string
	AuditKeyProvider  string
	FISCOCryptoMode   string
	FISCOKeyProvider  string
	FISCOPeerPins     bool
	AnchorSink        string
	StorageBackend    string
	Outbound          []OutboundEndpoint
}

func IsStrictDeploymentProfile(profile string) bool {
	switch NormalizeRunProfile(profile) {
	case RunProfileChinaProduction, RunProfileOfflineIsolated, RunProfileAssessment:
		return true
	default:
		return false
	}
}

func (c Config) validateDeploymentPolicy(now time.Time) error {
	profile := NormalizeRunProfile(c.RunProfile)
	policy := c.DeploymentPolicy
	mode := strings.ToLower(strings.TrimSpace(policy.EgressMode))
	switch mode {
	case "", EgressUnrestricted, EgressAllowlist, EgressDenyAll:
	default:
		return fmt.Errorf("deployment_policy.egress_mode must be unrestricted, allowlist, or deny_all")
	}
	if !IsStrictDeploymentProfile(profile) {
		return validatePolicyExceptions(now, policy.Exceptions)
	}
	if mode != EgressAllowlist && mode != EgressDenyAll {
		return fmt.Errorf("deployment_policy.egress_mode must be allowlist or deny_all for %s", profile)
	}
	if profile == RunProfileOfflineIsolated && mode != EgressDenyAll {
		return fmt.Errorf("deployment_policy.egress_mode must be deny_all for offline_isolated")
	}
	if policy.TelemetryEnabled {
		return fmt.Errorf("deployment_policy.telemetry_enabled must be false for %s", profile)
	}
	if policy.UpdateChecksEnabled {
		return fmt.Errorf("deployment_policy.update_checks_enabled must be false for %s", profile)
	}
	if err := validateAllowedEndpoints(policy); err != nil {
		return err
	}
	if mode == EgressDenyAll && len(policy.AllowedEndpoints) != 0 {
		return fmt.Errorf("deployment_policy.allowed_endpoints must be empty when egress_mode is deny_all")
	}
	if err := validatePolicyExceptions(now, policy.Exceptions); err != nil {
		return err
	}
	if !c.Audit.Enabled || !c.Audit.Required || !c.Audit.RequireSynchronizedTime {
		return fmt.Errorf("audit must be enabled, required, and synchronized for %s", profile)
	}
	retention, _ := time.ParseDuration(c.Audit.Retention)
	if retention < 180*24*time.Hour {
		return fmt.Errorf("audit.retention must be at least 4320h for %s", profile)
	}
	transportMode := strings.ToLower(strings.TrimSpace(c.Server.Transport.Mode))
	if transportMode == "" {
		transportMode = "plaintext"
	}
	switch transportMode {
	case "mtls":
		if len(c.Server.Transport.ClientCAPinsSHA256) == 0 &&
			!policyHasException(policy.Exceptions, PolicyControlServerPins) {
			return fmt.Errorf("server.transport.client_ca_pins_sha256 is required for %s mTLS", profile)
		}
	case "plaintext":
		if strings.TrimSpace(c.TLCP.GatewayProfile) == "" ||
			strings.TrimSpace(c.TLCP.IdentityManifest) == "" {
			return fmt.Errorf("tlcp.gateway_profile and tlcp.identity_manifest are required for %s plaintext boundary", profile)
		}
	default:
		return fmt.Errorf("server.transport.mode must be mtls or loopback plaintext behind TLCP for %s", profile)
	}
	if c.NATS.Enabled {
		if !c.NATS.TLS.Enabled || c.NATS.TLS.InsecureSkipVerify ||
			strings.TrimSpace(c.NATS.TLS.CAFile) == "" {
			return fmt.Errorf("nats TLS with CA verification is required for %s", profile)
		}
		for _, raw := range c.NATS.URLs {
			parsed, _ := url.Parse(raw)
			if !strings.EqualFold(parsed.Scheme, "tls") {
				return fmt.Errorf("nats.urls must use tls:// for %s", profile)
			}
		}
	}
	if strings.EqualFold(strings.TrimSpace(c.Backup.KeyProvider), "passphrase-dev-v1") &&
		!policyHasException(policy.Exceptions, PolicyControlBackupKey) {
		return fmt.Errorf("backup.key_provider passphrase-dev-v1 is forbidden for %s", profile)
	}
	sink := strings.ToLower(strings.TrimSpace(c.Anchor.Sink))
	switch profile {
	case RunProfileChinaProduction, RunProfileAssessment:
		if !c.GlobalLog.Enabled {
			return fmt.Errorf("global_log.enabled must be true for %s", profile)
		}
		if sink != "fisco-bcos" && !policyHasException(policy.Exceptions, PolicyControlAnchor) {
			return fmt.Errorf("anchor.sink must be fisco-bcos for %s", profile)
		}
		if (sink == "ots" || sink == "opentimestamps" || sink == "plugin") &&
			!policyHasException(policy.Exceptions, PolicyControlEgress) {
			return fmt.Errorf("anchor.sink %q has uninspectable or dynamic egress; an explicit egress exception is required for %s", sink, profile)
		}
	case RunProfileOfflineIsolated:
		switch sink {
		case "", "off", "file", "noop":
		default:
			return fmt.Errorf("anchor.sink %q is forbidden for offline_isolated", sink)
		}
		if c.NATS.Enabled {
			return fmt.Errorf("nats.enabled must be false for offline_isolated")
		}
	}
	return nil
}

func ValidateDeploymentRuntime(profile string, policy DeploymentPolicy, runtime DeploymentRuntime) error {
	canonical := NormalizeRunProfile(profile)
	if !IsStrictDeploymentProfile(canonical) {
		return nil
	}
	if err := ValidateDeploymentKey(
		canonical,
		policy,
		"server",
		runtime.ServerCryptoSuite,
		runtime.ServerKeyProvider,
		"",
	); err != nil {
		return err
	}
	if err := ValidateDeploymentKey(
		canonical,
		policy,
		"audit",
		runtime.AuditCryptoSuite,
		runtime.AuditKeyProvider,
		"",
	); err != nil {
		return err
	}
	sink := strings.ToLower(strings.TrimSpace(runtime.AnchorSink))
	storage := strings.ToLower(strings.TrimSpace(runtime.StorageBackend))
	switch canonical {
	case RunProfileChinaProduction, RunProfileAssessment:
		if sink != "fisco-bcos" &&
			!policyHasException(policy.Exceptions, PolicyControlAnchor) {
			return fmt.Errorf("effective anchor sink must be fisco-bcos for %s", canonical)
		}
		if (sink == "ots" || sink == "opentimestamps" || sink == "plugin") &&
			!policyHasException(policy.Exceptions, PolicyControlEgress) {
			return fmt.Errorf("effective anchor sink %q requires an explicit egress exception for %s", sink, canonical)
		}
		if storage != "pebble" && storage != "tikv" {
			return fmt.Errorf("proofstore backend must be pebble or tikv for %s", canonical)
		}
	case RunProfileOfflineIsolated:
		switch sink {
		case "", "off", "file", "noop":
		default:
			return fmt.Errorf("effective anchor sink %q is forbidden for offline_isolated", sink)
		}
		if storage != "pebble" {
			return fmt.Errorf("proofstore backend must be pebble for offline_isolated")
		}
	}
	if canonical != RunProfileOfflineIsolated && sink == "fisco-bcos" {
		if runtime.FISCOCryptoMode != "guomi" &&
			!policyHasException(policy.Exceptions, PolicyControlBCOSCryptoMode) {
			return fmt.Errorf("FISCO BCOS crypto mode must be guomi for %s", canonical)
		}
		if strings.EqualFold(strings.TrimSpace(runtime.FISCOKeyProvider), "software") &&
			!policyHasException(policy.Exceptions, PolicyControlBCOSKeyCustody) {
			return fmt.Errorf("FISCO BCOS account provider software is forbidden for %s", canonical)
		}
		if !runtime.FISCOPeerPins &&
			!policyHasException(policy.Exceptions, PolicyControlBCOSPins) {
			return fmt.Errorf("FISCO BCOS pinned peer certificate hashes are required for %s", canonical)
		}
	}
	return validateRuntimeEgress(policy, runtime.Outbound)
}

// ValidateDeploymentKey performs the descriptor-only gate before an external
// provider process can be started. endpoint is empty for local SDF/PKCS#11
// providers and the exact HTTPS origin for a remote descriptor.
func ValidateDeploymentKey(profile string, policy DeploymentPolicy, role, suite, provider, endpoint string) error {
	canonical := NormalizeRunProfile(profile)
	if !IsStrictDeploymentProfile(canonical) {
		return nil
	}
	var suiteControl, custodyControl string
	switch role {
	case "server":
		suiteControl = PolicyControlServerCryptoSuite
		custodyControl = PolicyControlServerKeyCustody
	case "audit":
		suiteControl = PolicyControlAuditCryptoSuite
		custodyControl = PolicyControlAuditKeyCustody
	default:
		return fmt.Errorf("unsupported deployment key role %q", role)
	}
	if suite != "CN_SM_V1" && !policyHasException(policy.Exceptions, suiteControl) {
		return fmt.Errorf("%s signing key must use CN_SM_V1 for %s", role, canonical)
	}
	if strings.EqualFold(strings.TrimSpace(provider), "software") &&
		!policyHasException(policy.Exceptions, custodyControl) {
		return fmt.Errorf("%s signing key provider software is forbidden for %s", role, canonical)
	}
	if strings.TrimSpace(endpoint) != "" {
		return validateRuntimeEgress(policy, []OutboundEndpoint{{
			Source: role + " signer", Endpoint: endpoint,
		}})
	}
	return nil
}

func validateAllowedEndpoints(policy DeploymentPolicy) error {
	seen := make(map[string]struct{}, len(policy.AllowedEndpoints))
	for _, raw := range policy.AllowedEndpoints {
		canonical, _, err := canonicalPolicyEndpoint(raw)
		if err != nil {
			return fmt.Errorf("deployment_policy.allowed_endpoints: %w", err)
		}
		if _, exists := seen[canonical]; exists {
			return fmt.Errorf("deployment_policy.allowed_endpoints contains duplicate %q", canonical)
		}
		seen[canonical] = struct{}{}
	}
	dnsSeen := make(map[string]struct{}, len(policy.DNSAllowlist))
	for _, raw := range policy.DNSAllowlist {
		host := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(raw, ".")))
		if host == "" || net.ParseIP(host) != nil || strings.ContainsAny(host, ":/") {
			return fmt.Errorf("deployment_policy.dns_allowlist contains invalid hostname %q", raw)
		}
		if _, exists := dnsSeen[host]; exists {
			return fmt.Errorf("deployment_policy.dns_allowlist contains duplicate %q", host)
		}
		dnsSeen[host] = struct{}{}
	}
	return nil
}

func validateRuntimeEgress(policy DeploymentPolicy, endpoints []OutboundEndpoint) error {
	if len(endpoints) == 0 {
		return nil
	}
	if strings.EqualFold(policy.EgressMode, EgressDenyAll) {
		return fmt.Errorf("deployment_policy.egress_mode deny_all rejects configured outbound endpoint %s=%q", endpoints[0].Source, endpoints[0].Endpoint)
	}
	allowed := make(map[string]struct{}, len(policy.AllowedEndpoints))
	for _, raw := range policy.AllowedEndpoints {
		canonical, _, _ := canonicalPolicyEndpoint(raw)
		allowed[canonical] = struct{}{}
	}
	dnsAllowed := make(map[string]struct{}, len(policy.DNSAllowlist))
	for _, raw := range policy.DNSAllowlist {
		dnsAllowed[strings.ToLower(strings.TrimSpace(strings.TrimSuffix(raw, ".")))] = struct{}{}
	}
	sorted := append([]OutboundEndpoint(nil), endpoints...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Source == sorted[j].Source {
			return sorted[i].Endpoint < sorted[j].Endpoint
		}
		return sorted[i].Source < sorted[j].Source
	})
	for _, endpoint := range sorted {
		canonical, host, err := canonicalRuntimeEndpoint(endpoint.Endpoint)
		if err != nil {
			return fmt.Errorf("%s endpoint: %w", endpoint.Source, err)
		}
		if _, ok := allowed[canonical]; !ok &&
			!policyHasException(policy.Exceptions, PolicyControlEgress) {
			return fmt.Errorf("%s endpoint %q is not in deployment_policy.allowed_endpoints", endpoint.Source, canonical)
		}
		if net.ParseIP(host) == nil {
			if _, ok := dnsAllowed[host]; !ok &&
				!policyHasException(policy.Exceptions, PolicyControlEgress) {
				return fmt.Errorf("%s hostname %q is not in deployment_policy.dns_allowlist", endpoint.Source, host)
			}
		}
	}
	return nil
}

func canonicalPolicyEndpoint(raw string) (string, string, error) {
	return canonicalEndpoint(raw, false)
}

func canonicalRuntimeEndpoint(raw string) (string, string, error) {
	return canonicalEndpoint(raw, true)
}

func canonicalEndpoint(raw string, runtime bool) (string, string, error) {
	value := strings.TrimSpace(raw)
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "", fmt.Errorf("endpoint %q must be an absolute scheme://host:port URL", raw)
	}
	if parsed.User != nil || (!runtime && parsed.Path != "") ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", fmt.Errorf("endpoint %q must not contain credentials, path, query, or fragment", raw)
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	port := parsed.Port()
	if runtime && port == "" && strings.EqualFold(parsed.Scheme, "https") {
		port = "443"
	}
	if host == "" || port == "" {
		return "", "", fmt.Errorf("endpoint %q must include host and port", raw)
	}
	scheme := strings.ToLower(parsed.Scheme)
	return scheme + "://" + net.JoinHostPort(host, port), host, nil
}

func validatePolicyExceptions(now time.Time, exceptions []PolicyException) error {
	seen := make(map[string]struct{}, len(exceptions))
	for index, exception := range exceptions {
		prefix := fmt.Sprintf("deployment_policy.exceptions[%d]", index)
		if strings.TrimSpace(exception.ID) == "" || strings.TrimSpace(exception.Reason) == "" ||
			strings.TrimSpace(exception.ApprovedBy) == "" || strings.TrimSpace(exception.Ticket) == "" {
			return fmt.Errorf("%s requires id, reason, approved_by, and ticket", prefix)
		}
		if len(exception.ID) > 128 || len(exception.Reason) > 512 ||
			len(exception.ApprovedBy) > 256 || len(exception.Ticket) > 256 {
			return fmt.Errorf("%s contains an oversized id, reason, approved_by, or ticket", prefix)
		}
		if _, ok := supportedPolicyControls[exception.Control]; !ok {
			return fmt.Errorf("%s.control %q is unsupported", prefix, exception.Control)
		}
		if _, exists := seen[exception.ID]; exists {
			return fmt.Errorf("%s.id %q is duplicated", prefix, exception.ID)
		}
		seen[exception.ID] = struct{}{}
		expires, err := time.Parse(time.RFC3339, exception.ExpiresAt)
		if err != nil {
			return fmt.Errorf("%s.expires_at must be RFC3339", prefix)
		}
		if !expires.After(now) {
			return fmt.Errorf("%s %q expired at %s", prefix, exception.ID, expires.Format(time.RFC3339))
		}
		if expires.Sub(now) > 30*24*time.Hour {
			return fmt.Errorf("%s %q may not exceed 30 days", prefix, exception.ID)
		}
	}
	return nil
}

func policyHasException(exceptions []PolicyException, control string) bool {
	for _, exception := range exceptions {
		if exception.Control == control {
			return true
		}
	}
	return false
}
