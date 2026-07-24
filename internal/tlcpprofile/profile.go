// Package tlcpprofile validates the public trust and deployment contract for
// the external TLCP gateway. It never reads gateway or proof-signing private
// keys.
package tlcpprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion = "trustdb.tlcp-gateway-profile.v1"

	ImplementationTengineTongsuo = "tengine-tongsuo"
	PinnedTengineVersion         = "2.3.4"
	PinnedTengineCommit          = "698e1798e8d691c55b5405ca1526c3dca4759d47"
	PinnedTengineSourceSHA256    = "9a8d1e83ec7664f799255b0dec5baebde2d12b6578b29cfadf92316b3d3e221c"
	PinnedTongsuoVersion         = "8.4.0"
	PinnedTongsuoCommit          = "a8ae0925d26de3b449f7a21767910cd41291bcd8"
	PinnedTongsuoSourceSHA256    = "57c2741750a699bfbdaa1bbe44a5733e9c8fc65d086c210151cfbc2bbd6fc975"
	PinnedBuilderImage           = "docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818"
	PinnedRuntimeImage           = "docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818"
	PinnedValidatorBuilderImage  = "docker.io/library/golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651"

	EnvironmentProduction = "production"
	EnvironmentTest       = "test"
	ModeTLCPMTLS          = "tlcp_mtls"
	CryptoModeGuomi       = "guomi"
	RevocationCRL         = "crl"

	KeyProviderEngine = "engine"
	KeyProviderPKCS11 = "pkcs11"
	KeyProviderSDF    = "sdf"
	KeyProviderFile   = "file"

	CipherECDHESM2SM4GCMSM3 = "ECDHE-SM2-SM4-GCM-SM3"

	MaxProfileBytes        = 128 << 10
	MaxCertificateBytes    = 1 << 20
	MaxCertificateCount    = 8
	MaxCRLBytes            = 4 << 20
	MaxCRLCount            = 8
	MaxStringBytes         = 4096
	MaxBuildParameterCount = 32
	MaxProofSigningKeys    = 32
)

type Profile struct {
	SchemaVersion    string            `json:"schema_version"`
	ProfileID        string            `json:"profile_id"`
	Environment      string            `json:"environment"`
	Mode             string            `json:"mode"`
	CryptoMode       string            `json:"crypto_mode"`
	ServerName       string            `json:"server_name"`
	CipherSuites     []string          `json:"cipher_suites"`
	ALPNProtocols    []string          `json:"alpn_protocols"`
	Implementation   Implementation    `json:"implementation"`
	Network          Network           `json:"network"`
	Certificates     Certificates      `json:"certificates"`
	ProofSigningKeys []ProofSigningKey `json:"proof_signing_keys"`
	Revocation       Revocation        `json:"revocation"`
	Timeouts         Timeouts          `json:"timeouts"`
}

type Implementation struct {
	Name                  string   `json:"name"`
	TengineVersion        string   `json:"tengine_version"`
	TengineCommit         string   `json:"tengine_commit"`
	TengineSourceSHA256   string   `json:"tengine_source_sha256"`
	TongsuoVersion        string   `json:"tongsuo_version"`
	TongsuoCommit         string   `json:"tongsuo_commit"`
	TongsuoSourceSHA256   string   `json:"tongsuo_source_sha256"`
	BuilderImage          string   `json:"builder_image"`
	RuntimeImage          string   `json:"runtime_image"`
	ValidatorBuilderImage string   `json:"validator_builder_image"`
	GatewayImageDigest    string   `json:"gateway_image_digest"`
	BuildParameters       []string `json:"build_parameters"`
	SBOMSHA256            string   `json:"sbom_sha256"`
	BuildRecordSHA256     string   `json:"build_record_sha256"`
}

type Network struct {
	SharedNetworkNamespace bool     `json:"shared_network_namespace"`
	HostNetwork            bool     `json:"host_network"`
	AllowedContainers      []string `json:"allowed_containers"`
	TrustDBHTTPUpstream    string   `json:"trustdb_http_upstream"`
	TrustDBGRPCUpstream    string   `json:"trustdb_grpc_upstream"`
	GatewayHTTPBind        string   `json:"gateway_http_bind"`
	GatewayGRPCBind        string   `json:"gateway_grpc_bind"`
}

type Certificates struct {
	ServerSigningChainFile    string       `json:"server_signing_chain_file"`
	ServerEncryptionChainFile string       `json:"server_encryption_chain_file"`
	ServerCAFile              string       `json:"server_ca_file"`
	ClientCAFile              string       `json:"client_ca_file"`
	SigningKey                KeyReference `json:"signing_key"`
	EncryptionKey             KeyReference `json:"encryption_key"`
}

type KeyReference struct {
	Provider        string `json:"provider"`
	Reference       string `json:"reference"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

// ProofSigningKey contains only public identity material. It binds the
// gateway profile to every TrustDB proof-signing key that must remain outside
// the transport trust boundary.
type ProofSigningKey struct {
	Reference       string `json:"reference"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

type Revocation struct {
	Mode                 string   `json:"mode"`
	CRLFiles             []string `json:"crl_files"`
	GatewayCRLBundleFile string   `json:"gateway_crl_bundle_file"`
	MaxStaleness         string   `json:"max_staleness"`
}

type Timeouts struct {
	Startup string `json:"startup"`
	Reload  string `json:"reload"`
	Canary  string `json:"canary"`
}

type Options struct {
	Now                       time.Time
	ForbiddenKeyReferences    []string
	ForbiddenPublicKeySHA256s []string
}

type Report struct {
	SchemaVersion                 string    `json:"schema_version"`
	ProfileID                     string    `json:"profile_id"`
	ServerName                    string    `json:"server_name"`
	SigningCertificateSHA256      string    `json:"signing_certificate_sha256"`
	EncryptionCertificateSHA256   string    `json:"encryption_certificate_sha256"`
	SigningPublicKeySHA256        string    `json:"signing_public_key_sha256"`
	EncryptionPublicKeySHA256     string    `json:"encryption_public_key_sha256"`
	ServerCASHA256                []string  `json:"server_ca_sha256"`
	ClientCASHA256                []string  `json:"client_ca_sha256"`
	ProofSigningPublicKeySHA256   []string  `json:"proof_signing_public_key_sha256"`
	CRLIssuers                    []string  `json:"crl_issuers"`
	EarliestCertificateExpiration time.Time `json:"earliest_certificate_expiration"`
	EarliestCRLExpiration         time.Time `json:"earliest_crl_expiration"`
}

func Decode(data []byte) (Profile, error) {
	if len(data) == 0 || len(data) > MaxProfileBytes {
		return Profile{}, fmt.Errorf("TLCP gateway profile size must be between 1 and %d bytes", MaxProfileBytes)
	}
	if !utf8.Valid(data) {
		return Profile{}, errors.New("decode TLCP gateway profile: input is not valid UTF-8")
	}
	if err := validateJSONStructure(data); err != nil {
		return Profile{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var profile Profile
	if err := decoder.Decode(&profile); err != nil {
		return Profile{}, fmt.Errorf("decode TLCP gateway profile: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Profile{}, errors.New("decode TLCP gateway profile: trailing JSON value")
		}
		return Profile{}, fmt.Errorf("decode TLCP gateway profile: %w", err)
	}
	return profile, nil
}

func Validate(profile Profile, options Options) (Report, error) {
	if err := validateProfileFields(profile, options); err != nil {
		return Report{}, err
	}
	now := options.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return validatePublicTrust(profile, now)
}

func validateProfileFields(profile Profile, options Options) error {
	if profile.SchemaVersion != SchemaVersion {
		return fmt.Errorf("TLCP gateway profile schema_version must be %q", SchemaVersion)
	}
	for name, value := range map[string]string{
		"profile_id":  profile.ProfileID,
		"server_name": profile.ServerName,
	} {
		if err := validateString(name, value); err != nil {
			return err
		}
	}
	switch profile.Environment {
	case EnvironmentProduction, EnvironmentTest:
	default:
		return errors.New("TLCP gateway profile environment must be production or test")
	}
	if profile.Mode != ModeTLCPMTLS {
		return errors.New("TLCP gateway profile mode must be tlcp_mtls")
	}
	if profile.CryptoMode != CryptoModeGuomi {
		return errors.New("TLCP gateway profile crypto_mode must be guomi")
	}
	if len(profile.CipherSuites) != 1 || profile.CipherSuites[0] != CipherECDHESM2SM4GCMSM3 {
		return fmt.Errorf("TLCP gateway profile must use only %s", CipherECDHESM2SM4GCMSM3)
	}
	if len(profile.ALPNProtocols) != 2 || profile.ALPNProtocols[0] != "h2" || profile.ALPNProtocols[1] != "http/1.1" {
		return errors.New("TLCP gateway profile ALPN protocols must be exactly [h2, http/1.1]")
	}
	if err := validateImplementation(profile.Implementation); err != nil {
		return err
	}
	if err := validateNetwork(profile.Network); err != nil {
		return err
	}
	if err := validateCertificatesConfig(
		profile.Certificates,
		profile.Environment,
		append(proofSigningKeyReferences(profile.ProofSigningKeys), options.ForbiddenKeyReferences...),
		append(proofSigningKeyFingerprints(profile.ProofSigningKeys), options.ForbiddenPublicKeySHA256s...),
	); err != nil {
		return err
	}
	if err := validateProofSigningKeys(profile.ProofSigningKeys, profile.Environment); err != nil {
		return err
	}
	if err := validateRevocationConfig(profile.Revocation); err != nil {
		return err
	}
	if err := validateTimeouts(profile.Timeouts); err != nil {
		return err
	}
	return nil
}

func validateImplementation(value Implementation) error {
	if value.Name != ImplementationTengineTongsuo ||
		value.TengineVersion != PinnedTengineVersion ||
		value.TengineCommit != PinnedTengineCommit ||
		value.TengineSourceSHA256 != PinnedTengineSourceSHA256 ||
		value.TongsuoVersion != PinnedTongsuoVersion ||
		value.TongsuoCommit != PinnedTongsuoCommit ||
		value.TongsuoSourceSHA256 != PinnedTongsuoSourceSHA256 ||
		value.BuilderImage != PinnedBuilderImage ||
		value.RuntimeImage != PinnedRuntimeImage ||
		value.ValidatorBuilderImage != PinnedValidatorBuilderImage {
		return errors.New("TLCP gateway implementation does not match the pinned Tengine/Tongsuo baseline")
	}
	for name, digest := range map[string]string{
		"sbom_sha256":         value.SBOMSHA256,
		"build_record_sha256": value.BuildRecordSHA256,
	} {
		if err := validateSHA256(name, digest); err != nil {
			return err
		}
	}
	if !strings.HasPrefix(value.GatewayImageDigest, "sha256:") {
		return errors.New("TLCP gateway gateway_image_digest must include the sha256: algorithm prefix")
	}
	if err := validateSHA256("gateway_image_digest", value.GatewayImageDigest); err != nil {
		return err
	}
	if len(value.BuildParameters) > MaxBuildParameterCount ||
		!equalStrings(value.BuildParameters, requiredBuildParameters()) {
		return errors.New("TLCP gateway build_parameters do not match the pinned baseline")
	}
	return nil
}

func validateProofSigningKeys(values []ProofSigningKey, environment string) error {
	if environment == EnvironmentProduction && len(values) == 0 {
		return errors.New("production TLCP gateway profile requires proof_signing_keys")
	}
	if len(values) > MaxProofSigningKeys {
		return fmt.Errorf("TLCP gateway profile proof_signing_keys exceeds %d entries", MaxProofSigningKeys)
	}
	references := make(map[string]struct{}, len(values))
	publicKeys := make(map[string]struct{}, len(values))
	for index, value := range values {
		if err := validateString(
			fmt.Sprintf("proof_signing_keys[%d].reference", index),
			value.Reference,
		); err != nil {
			return err
		}
		if err := validateCanonicalSHA256(
			fmt.Sprintf("proof_signing_keys[%d].public_key_sha256", index),
			value.PublicKeySHA256,
		); err != nil {
			return err
		}
		if _, duplicate := references[value.Reference]; duplicate {
			return errors.New("TLCP gateway profile contains a duplicate proof-signing key reference")
		}
		if _, duplicate := publicKeys[value.PublicKeySHA256]; duplicate {
			return errors.New("TLCP gateway profile contains a duplicate proof-signing public key")
		}
		references[value.Reference] = struct{}{}
		publicKeys[value.PublicKeySHA256] = struct{}{}
	}
	return nil
}

func proofSigningKeyReferences(values []ProofSigningKey) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Reference)
	}
	return result
}

func proofSigningKeyFingerprints(values []ProofSigningKey) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.PublicKeySHA256)
	}
	return result
}

func requiredBuildParameters() []string {
	return []string{
		"--add-module=modules/ngx_openssl_ntls",
		"--build=trustdb-tlcp-gateway-reproducible",
		"--conf-path=/etc/trustdb/tlcp/nginx.conf",
		"--error-log-path=stderr",
		"--group=trustdb",
		"--http-log-path=/dev/stdout",
		"--http-proxy-temp-path=/var/cache/tlcp-gateway/proxy",
		"--lock-path=/run/tlcp-gateway/tlcp-gateway.lock",
		"--pid-path=/run/tlcp-gateway/tlcp-gateway.pid",
		"--prefix=/opt/tlcp-gateway",
		"--sbin-path=/usr/local/sbin/tlcp-gateway",
		"--user=trustdb",
		"--with-cc-opt=-O2 -fdebug-prefix-map=/src=. -ffile-prefix-map=/src=. -fno-record-gcc-switches -Wno-deprecated-declarations",
		"--with-http_ssl_module",
		"--with-http_v2_module",
		"--with-ld-opt=-Wl,--build-id=none",
		"--with-openssl=/src/tongsuo",
		"--with-openssl-opt=enable-ntls no-tests",
		"--with-stream",
		"--with-stream_ssl_module",
		"--with-stream_ssl_preread_module",
		"CGO_ENABLED=0",
		"go build -trimpath -buildvcs=false -ldflags=-s -w -buildid=",
	}
}

func validateNetwork(value Network) error {
	if !value.SharedNetworkNamespace {
		return errors.New("TLCP gateway and TrustDB must share a restricted network namespace")
	}
	if value.HostNetwork {
		return errors.New("TLCP gateway profile forbids hostNetwork")
	}
	if !equalStrings(value.AllowedContainers, []string{
		"trustdb",
		"tlcp-gateway",
		"tlcp-gateway-candidate",
	}) {
		return errors.New("TLCP gateway profile allows exactly trustdb, the active gateway, and one rotation candidate")
	}
	httpUpstream, err := parseAddress("trustdb_http_upstream", value.TrustDBHTTPUpstream)
	if err != nil {
		return err
	}
	grpcUpstream, err := parseAddress("trustdb_grpc_upstream", value.TrustDBGRPCUpstream)
	if err != nil {
		return err
	}
	allowedUpstream := netip.MustParseAddr("127.0.0.1")
	if httpUpstream.Addr() != allowedUpstream || grpcUpstream.Addr() != allowedUpstream {
		return errors.New("TrustDB TLCP gateway upstreams must use exactly 127.0.0.1")
	}
	httpBind, err := parseAddress("gateway_http_bind", value.GatewayHTTPBind)
	if err != nil {
		return err
	}
	grpcBind, err := parseAddress("gateway_grpc_bind", value.GatewayGRPCBind)
	if err != nil {
		return err
	}
	if httpBind.Addr().IsLoopback() || grpcBind.Addr().IsLoopback() {
		return errors.New("TLCP gateway external binds must not be loopback-only")
	}
	addresses := []netip.AddrPort{httpUpstream, grpcUpstream, httpBind, grpcBind}
	seen := make(map[uint16]struct{}, len(addresses))
	for _, address := range addresses {
		if _, duplicate := seen[address.Port()]; duplicate {
			return errors.New("TLCP gateway listeners and TrustDB upstreams must use distinct ports in the shared namespace")
		}
		seen[address.Port()] = struct{}{}
	}
	return nil
}

func validateCertificatesConfig(
	value Certificates,
	environment string,
	forbiddenReferences []string,
	forbiddenPublicKeys []string,
) error {
	for name, path := range map[string]string{
		"server_signing_chain_file":    value.ServerSigningChainFile,
		"server_encryption_chain_file": value.ServerEncryptionChainFile,
		"server_ca_file":               value.ServerCAFile,
		"client_ca_file":               value.ClientCAFile,
	} {
		if err := validateAbsoluteCleanPath(name, path); err != nil {
			return err
		}
	}
	if err := validateKeyReference(
		"signing_key", value.SigningKey, environment, forbiddenReferences, forbiddenPublicKeys,
	); err != nil {
		return err
	}
	if err := validateKeyReference(
		"encryption_key", value.EncryptionKey, environment, forbiddenReferences, forbiddenPublicKeys,
	); err != nil {
		return err
	}
	if value.SigningKey.Reference == value.EncryptionKey.Reference {
		return errors.New("TLCP signing and encryption keys must use distinct references")
	}
	if value.SigningKey.PublicKeySHA256 == value.EncryptionKey.PublicKeySHA256 {
		return errors.New("TLCP signing and encryption keys must use distinct public keys")
	}
	return nil
}

func validateKeyReference(
	name string,
	value KeyReference,
	environment string,
	forbiddenReferences []string,
	forbiddenPublicKeys []string,
) error {
	if err := validateString(name+".reference", value.Reference); err != nil {
		return err
	}
	if err := validateCanonicalSHA256(name+".public_key_sha256", value.PublicKeySHA256); err != nil {
		return err
	}
	switch value.Provider {
	case KeyProviderEngine, KeyProviderPKCS11, KeyProviderSDF:
		if environment == EnvironmentProduction {
			if err := validateOpaqueEngineReference(name, value.Provider, value.Reference); err != nil {
				return err
			}
		}
	case KeyProviderFile:
		if environment != EnvironmentTest {
			return fmt.Errorf("%s file provider is allowed only in test profiles", name)
		}
		if err := validateAbsoluteCleanPath(name+".reference", value.Reference); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s provider must be engine, pkcs11, sdf, or test-only file", name)
	}
	for _, item := range forbiddenReferences {
		if value.Reference == item {
			return fmt.Errorf("%s reference overlaps a proof-signing key reference", name)
		}
	}
	for _, item := range forbiddenPublicKeys {
		if err := validateCanonicalSHA256("forbidden_public_key_sha256", item); err != nil {
			return err
		}
		if value.PublicKeySHA256 == item {
			return fmt.Errorf("%s public key overlaps a proof-signing public key", name)
		}
	}
	return nil
}

func validateOpaqueEngineReference(name, provider, reference string) error {
	parts := strings.SplitN(reference, ":", 3)
	if len(parts) != 3 || parts[0] != "engine" || parts[1] == "" || parts[2] == "" {
		return fmt.Errorf("%s production reference must use engine:<id>:<key-id>", name)
	}
	if provider != KeyProviderEngine && parts[1] != provider {
		return fmt.Errorf("%s production engine id must match provider %s", name, provider)
	}
	for _, value := range parts[1:] {
		if strings.IndexFunc(value, func(char rune) bool {
			return !((char >= 'a' && char <= 'z') ||
				(char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') ||
				strings.ContainsRune("_./@,=+-", char))
		}) >= 0 {
			return fmt.Errorf("%s production reference contains unsupported characters", name)
		}
	}
	return nil
}

func validateRevocationConfig(value Revocation) error {
	if value.Mode != RevocationCRL {
		return errors.New("TLCP gateway profile v1 supports only fail-closed CRL revocation")
	}
	if len(value.CRLFiles) == 0 || len(value.CRLFiles) > MaxCRLCount {
		return fmt.Errorf("TLCP gateway profile requires 1..%d CRL files", MaxCRLCount)
	}
	if err := validateAbsoluteCleanPath("gateway_crl_bundle_file", value.GatewayCRLBundleFile); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(value.CRLFiles))
	for index, path := range value.CRLFiles {
		if err := validateAbsoluteCleanPath(fmt.Sprintf("crl_files[%d]", index), path); err != nil {
			return err
		}
		if _, duplicate := seen[path]; duplicate {
			return errors.New("TLCP gateway profile contains a duplicate CRL file")
		}
		seen[path] = struct{}{}
	}
	duration, err := time.ParseDuration(value.MaxStaleness)
	if err != nil || duration <= 0 || duration > 7*24*time.Hour {
		return errors.New("TLCP gateway CRL max_staleness must be between 1ns and 168h")
	}
	return nil
}

func validateTimeouts(value Timeouts) error {
	for name, text := range map[string]string{
		"startup": value.Startup,
		"reload":  value.Reload,
		"canary":  value.Canary,
	} {
		duration, err := time.ParseDuration(text)
		if err != nil || duration < time.Second || duration > 10*time.Minute {
			return fmt.Errorf("TLCP gateway %s timeout must be between 1s and 10m", name)
		}
	}
	return nil
}

func validateString(name, value string) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > MaxStringBytes ||
		!utf8.ValidString(value) || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return fmt.Errorf("TLCP gateway %s is empty, oversized, non-canonical, or contains control characters", name)
	}
	return nil
}

func validateSHA256(name, value string) error {
	value = strings.TrimPrefix(value, "sha256:")
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return fmt.Errorf("TLCP gateway %s must be a lowercase SHA-256 digest", name)
	}
	return nil
}

func validateCanonicalSHA256(name, value string) error {
	if strings.HasPrefix(value, "sha256:") {
		return fmt.Errorf("TLCP gateway %s must omit the sha256: prefix", name)
	}
	return validateSHA256(name, value)
}

func validateAbsoluteCleanPath(name, value string) error {
	if err := validateString(name, value); err != nil {
		return err
	}
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return fmt.Errorf("TLCP gateway %s must be an absolute clean path", name)
	}
	return nil
}

func parseAddress(name, value string) (netip.AddrPort, error) {
	if err := validateString(name, value); err != nil {
		return netip.AddrPort{}, err
	}
	address, err := netip.ParseAddrPort(value)
	if err != nil || address.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("TLCP gateway %s must be an IP address with a non-zero port", name)
	}
	return address, nil
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
