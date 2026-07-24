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
	PinnedTongsuoVersion         = "8.4.0"
	PinnedTongsuoCommit          = "a8ae0925d26de3b449f7a21767910cd41291bcd8"

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
)

type Profile struct {
	SchemaVersion  string         `json:"schema_version"`
	ProfileID      string         `json:"profile_id"`
	Environment    string         `json:"environment"`
	Mode           string         `json:"mode"`
	CryptoMode     string         `json:"crypto_mode"`
	ServerName     string         `json:"server_name"`
	CipherSuites   []string       `json:"cipher_suites"`
	ALPNProtocols  []string       `json:"alpn_protocols"`
	Implementation Implementation `json:"implementation"`
	Network        Network        `json:"network"`
	Certificates   Certificates   `json:"certificates"`
	Revocation     Revocation     `json:"revocation"`
	Timeouts       Timeouts       `json:"timeouts"`
}

type Implementation struct {
	Name                string   `json:"name"`
	TengineVersion      string   `json:"tengine_version"`
	TengineCommit       string   `json:"tengine_commit"`
	TengineSourceSHA256 string   `json:"tengine_source_sha256"`
	TongsuoVersion      string   `json:"tongsuo_version"`
	TongsuoCommit       string   `json:"tongsuo_commit"`
	TongsuoSourceSHA256 string   `json:"tongsuo_source_sha256"`
	BuilderImage        string   `json:"builder_image"`
	RuntimeImage        string   `json:"runtime_image"`
	GatewayImageDigest  string   `json:"gateway_image_digest"`
	BuildParameters     []string `json:"build_parameters"`
	SBOMSHA256          string   `json:"sbom_sha256"`
	BuildRecordSHA256   string   `json:"build_record_sha256"`
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
	Provider  string `json:"provider"`
	Reference string `json:"reference"`
}

type Revocation struct {
	Mode         string   `json:"mode"`
	CRLFiles     []string `json:"crl_files"`
	MaxStaleness string   `json:"max_staleness"`
}

type Timeouts struct {
	Startup string `json:"startup"`
	Reload  string `json:"reload"`
	Canary  string `json:"canary"`
}

type Options struct {
	Now                    time.Time
	ForbiddenKeyReferences []string
}

type Report struct {
	SchemaVersion                 string    `json:"schema_version"`
	ProfileID                     string    `json:"profile_id"`
	ServerName                    string    `json:"server_name"`
	SigningCertificateSHA256      string    `json:"signing_certificate_sha256"`
	EncryptionCertificateSHA256   string    `json:"encryption_certificate_sha256"`
	ServerCASHA256                []string  `json:"server_ca_sha256"`
	ClientCASHA256                []string  `json:"client_ca_sha256"`
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
	if err := validateCertificatesConfig(profile.Certificates, profile.Environment, options.ForbiddenKeyReferences); err != nil {
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
		value.TongsuoVersion != PinnedTongsuoVersion ||
		value.TongsuoCommit != PinnedTongsuoCommit {
		return errors.New("TLCP gateway implementation does not match the pinned Tengine/Tongsuo baseline")
	}
	for name, digest := range map[string]string{
		"tengine_source_sha256": value.TengineSourceSHA256,
		"tongsuo_source_sha256": value.TongsuoSourceSHA256,
		"sbom_sha256":           value.SBOMSHA256,
		"build_record_sha256":   value.BuildRecordSHA256,
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
	for name, image := range map[string]string{
		"builder_image": value.BuilderImage,
		"runtime_image": value.RuntimeImage,
	} {
		if err := validateDigestPinnedImage(name, image); err != nil {
			return err
		}
	}
	if len(value.BuildParameters) > MaxBuildParameterCount ||
		!equalStrings(value.BuildParameters, requiredBuildParameters()) {
		return errors.New("TLCP gateway build_parameters do not match the pinned baseline")
	}
	return nil
}

func requiredBuildParameters() []string {
	return []string{
		"--add-module=modules/ngx_openssl_ntls",
		"--with-http_ssl_module",
		"--with-http_v2_module",
		"--with-openssl=/src/tongsuo",
		"--with-openssl-opt=enable-ntls",
		"--with-stream",
		"--with-stream_ssl_module",
		"--with-stream_ssl_preread_module",
	}
}

func validateNetwork(value Network) error {
	if !value.SharedNetworkNamespace {
		return errors.New("TLCP gateway and TrustDB must share a restricted network namespace")
	}
	if value.HostNetwork {
		return errors.New("TLCP gateway profile forbids hostNetwork")
	}
	if !equalStrings(value.AllowedContainers, []string{"trustdb", "tlcp-gateway"}) {
		return errors.New("TLCP gateway profile allows exactly the trustdb and tlcp-gateway containers")
	}
	httpUpstream, err := parseAddress("trustdb_http_upstream", value.TrustDBHTTPUpstream)
	if err != nil {
		return err
	}
	grpcUpstream, err := parseAddress("trustdb_grpc_upstream", value.TrustDBGRPCUpstream)
	if err != nil {
		return err
	}
	if !httpUpstream.Addr().IsLoopback() || !grpcUpstream.Addr().IsLoopback() {
		return errors.New("TrustDB TLCP gateway upstreams must be loopback-only")
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

func validateCertificatesConfig(value Certificates, environment string, forbidden []string) error {
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
	if err := validateKeyReference("signing_key", value.SigningKey, environment, forbidden); err != nil {
		return err
	}
	if err := validateKeyReference("encryption_key", value.EncryptionKey, environment, forbidden); err != nil {
		return err
	}
	if value.SigningKey.Reference == value.EncryptionKey.Reference {
		return errors.New("TLCP signing and encryption keys must use distinct references")
	}
	return nil
}

func validateKeyReference(name string, value KeyReference, environment string, forbidden []string) error {
	if err := validateString(name+".reference", value.Reference); err != nil {
		return err
	}
	switch value.Provider {
	case KeyProviderEngine, KeyProviderPKCS11, KeyProviderSDF:
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
	for _, item := range forbidden {
		if value.Reference == item {
			return fmt.Errorf("%s reference overlaps a proof-signing key reference", name)
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

func validateDigestPinnedImage(name, value string) error {
	if err := validateString(name, value); err != nil {
		return err
	}
	index := strings.LastIndex(value, "@sha256:")
	if index <= 0 {
		return fmt.Errorf("TLCP gateway %s must be pinned by sha256 digest", name)
	}
	return validateSHA256(name, value[index+1:])
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
