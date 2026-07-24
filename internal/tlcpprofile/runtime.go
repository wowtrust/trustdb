package tlcpprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const (
	RuntimeManifestSchema   = "trustdb.tlcp-gateway-runtime-manifest.v1"
	MaxRuntimeManifestBytes = 256 << 10
)

type RuntimeManifest struct {
	SchemaVersion          string `json:"schema_version"`
	PreparedAt             string `json:"prepared_at"`
	ProfileSHA256          string `json:"profile_sha256"`
	ConfigurationSHA256    string `json:"configuration_sha256"`
	GatewayCRLBundleSHA256 string `json:"gateway_crl_bundle_sha256"`
	GatewayImageDigest     string `json:"gateway_image_digest"`
	Validation             Report `json:"validation"`
}

type RuntimeOptions struct {
	ExpectedGatewayImageDigest string
	ConfigurationPath          string
	ManifestPath               string
	Now                        time.Time
}

func PrepareRuntime(profilePath string, options RuntimeOptions) (RuntimeManifest, error) {
	profile, report, profileData, err := loadRuntimeProfile(profilePath, options)
	if err != nil {
		return RuntimeManifest{}, err
	}
	configuration := RenderNginxConfiguration(profile)
	bundle, err := readBoundedRegularFile(
		profile.Revocation.GatewayCRLBundleFile,
		MaxCRLBytes*MaxCRLCount,
	)
	if err != nil {
		return RuntimeManifest{}, fmt.Errorf("read validated gateway CRL bundle: %w", err)
	}
	now := options.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	manifest := RuntimeManifest{
		SchemaVersion:          RuntimeManifestSchema,
		PreparedAt:             now.Format(time.RFC3339Nano),
		ProfileSHA256:          digestBytes(profileData),
		ConfigurationSHA256:    digestBytes(configuration),
		GatewayCRLBundleSHA256: digestBytes(bundle),
		GatewayImageDigest:     profile.Implementation.GatewayImageDigest,
		Validation:             report,
	}
	manifestData, err := encodeRuntimeManifest(manifest)
	if err != nil {
		return RuntimeManifest{}, err
	}
	if err := atomicWriteRuntimeFile(options.ConfigurationPath, configuration); err != nil {
		return RuntimeManifest{}, fmt.Errorf("write TLCP gateway configuration: %w", err)
	}
	if err := atomicWriteRuntimeFile(options.ManifestPath, manifestData); err != nil {
		return RuntimeManifest{}, fmt.Errorf("write TLCP runtime manifest: %w", err)
	}
	return manifest, nil
}

func VerifyRuntime(profilePath string, options RuntimeOptions) (RuntimeManifest, error) {
	profile, report, profileData, err := loadRuntimeProfile(profilePath, options)
	if err != nil {
		return RuntimeManifest{}, err
	}
	manifestData, err := readBoundedRegularFile(options.ManifestPath, MaxRuntimeManifestBytes)
	if err != nil {
		return RuntimeManifest{}, fmt.Errorf("read TLCP runtime manifest: %w", err)
	}
	var manifest RuntimeManifest
	if err := decodeStrictRuntimeJSON(manifestData, &manifest); err != nil {
		return RuntimeManifest{}, fmt.Errorf("decode TLCP runtime manifest: %w", err)
	}
	canonical, err := encodeRuntimeManifest(manifest)
	if err != nil {
		return RuntimeManifest{}, err
	}
	if !bytes.Equal(canonical, manifestData) {
		return RuntimeManifest{}, errors.New("TLCP runtime manifest is not canonical")
	}
	preparedAt, err := time.Parse(time.RFC3339Nano, manifest.PreparedAt)
	verificationNow := options.Now.UTC()
	if verificationNow.IsZero() {
		verificationNow = time.Now().UTC()
	}
	if err != nil || preparedAt.After(verificationNow.Add(time.Minute)) {
		return RuntimeManifest{}, errors.New("TLCP runtime manifest prepared_at is invalid")
	}
	configuration, err := readBoundedRegularFile(options.ConfigurationPath, MaxProfileBytes)
	if err != nil {
		return RuntimeManifest{}, fmt.Errorf("read TLCP gateway configuration: %w", err)
	}
	bundle, err := readBoundedRegularFile(
		profile.Revocation.GatewayCRLBundleFile,
		MaxCRLBytes*MaxCRLCount,
	)
	if err != nil {
		return RuntimeManifest{}, fmt.Errorf("read validated gateway CRL bundle: %w", err)
	}
	expected := manifest
	expected.SchemaVersion = RuntimeManifestSchema
	expected.ProfileSHA256 = digestBytes(profileData)
	expected.ConfigurationSHA256 = digestBytes(configuration)
	expected.GatewayCRLBundleSHA256 = digestBytes(bundle)
	expected.GatewayImageDigest = profile.Implementation.GatewayImageDigest
	expected.Validation = report
	if !reflect.DeepEqual(manifest, expected) {
		return RuntimeManifest{}, errors.New("TLCP runtime manifest no longer matches the profile, public trust, or gateway image")
	}
	if !bytes.Equal(configuration, RenderNginxConfiguration(profile)) {
		return RuntimeManifest{}, errors.New("TLCP gateway configuration drifted from the validated profile")
	}
	return manifest, nil
}

func loadRuntimeProfile(
	profilePath string,
	options RuntimeOptions,
) (Profile, Report, []byte, error) {
	for name, path := range map[string]string{
		"profile":       profilePath,
		"configuration": options.ConfigurationPath,
		"manifest":      options.ManifestPath,
	} {
		if err := validateAbsoluteCleanPath(name+"_path", path); err != nil {
			return Profile{}, Report{}, nil, err
		}
	}
	if err := validateSHA256("expected_gateway_image_digest", options.ExpectedGatewayImageDigest); err != nil ||
		!strings.HasPrefix(options.ExpectedGatewayImageDigest, "sha256:") {
		return Profile{}, Report{}, nil, errors.New("expected gateway image digest must be a canonical sha256 digest")
	}
	profileData, err := readBoundedRegularFile(profilePath, MaxProfileBytes)
	if err != nil {
		return Profile{}, Report{}, nil, fmt.Errorf("load TLCP gateway profile: %w", err)
	}
	profile, err := Decode(profileData)
	if err != nil {
		return Profile{}, Report{}, nil, err
	}
	if profile.Implementation.GatewayImageDigest != options.ExpectedGatewayImageDigest {
		return Profile{}, Report{}, nil, errors.New("running gateway image digest does not match the strict profile")
	}
	report, err := Validate(profile, Options{Now: options.Now})
	if err != nil {
		return Profile{}, Report{}, nil, err
	}
	return profile, report, profileData, nil
}

func RenderNginxConfiguration(profile Profile) []byte {
	var builder strings.Builder
	builder.WriteString("worker_processes auto;\n")
	builder.WriteString("worker_rlimit_nofile 16384;\n")
	builder.WriteString("worker_shutdown_timeout 30s;\n")
	builder.WriteString("daemon off;\n")
	builder.WriteString("pid /run/tlcp-gateway/tlcp-gateway.pid;\n")
	builder.WriteString("error_log stderr info;\n\n")
	builder.WriteString("events {\n")
	builder.WriteString("    worker_connections 2048;\n")
	builder.WriteString("    multi_accept off;\n")
	builder.WriteString("}\n\n")
	builder.WriteString("http {\n")
	builder.WriteString("    include /opt/tlcp-gateway/conf/mime.types;\n")
	builder.WriteString("    default_type application/octet-stream;\n")
	builder.WriteString("    access_log /dev/stdout;\n")
	builder.WriteString("    server_tokens off;\n")
	builder.WriteString("    client_header_timeout 10s;\n")
	builder.WriteString("    client_body_timeout 30s;\n")
	builder.WriteString("    client_max_body_size 16m;\n")
	builder.WriteString("    client_body_temp_path /var/cache/tlcp-gateway/client-body;\n")
	builder.WriteString("    keepalive_timeout 15s;\n")
	builder.WriteString("    keepalive_requests 100;\n")
	builder.WriteString("    send_timeout 30s;\n")
	builder.WriteString("    reset_timedout_connection on;\n")
	builder.WriteString("    http2_max_concurrent_streams 64;\n")
	builder.WriteString("    limit_conn_zone $binary_remote_addr zone=tlcp_clients:10m;\n\n")
	writeNginxServer(&builder, profile, false)
	builder.WriteByte('\n')
	writeNginxServer(&builder, profile, true)
	builder.WriteString("}\n")
	return []byte(builder.String())
}

func writeNginxServer(builder *strings.Builder, profile Profile, grpc bool) {
	listen := profile.Network.GatewayHTTPBind
	upstream := profile.Network.TrustDBHTTPUpstream
	if grpc {
		listen = profile.Network.GatewayGRPCBind
		upstream = profile.Network.TrustDBGRPCUpstream
	}
	builder.WriteString("    server {\n")
	fmt.Fprintf(builder, "        listen %s ssl http2;\n", listen)
	fmt.Fprintf(builder, "        server_name %s;\n", nginxQuote(profile.ServerName))
	builder.WriteString("        enable_ntls on;\n")
	builder.WriteString("        ssl_ciphers ECDHE-SM2-SM4-GCM-SM3:ECDHE-RSA-AES256-GCM-SHA384;\n")
	builder.WriteString("        ssl_prefer_server_ciphers on;\n")
	fmt.Fprintf(builder, "        ssl_sign_certificate %s;\n", nginxQuote(profile.Certificates.ServerSigningChainFile))
	fmt.Fprintf(builder, "        ssl_sign_certificate_key %s;\n", nginxQuote(profile.Certificates.SigningKey.Reference))
	fmt.Fprintf(builder, "        ssl_enc_certificate %s;\n", nginxQuote(profile.Certificates.ServerEncryptionChainFile))
	fmt.Fprintf(builder, "        ssl_enc_certificate_key %s;\n", nginxQuote(profile.Certificates.EncryptionKey.Reference))
	fmt.Fprintf(builder, "        ssl_client_certificate %s;\n", nginxQuote(profile.Certificates.ClientCAFile))
	fmt.Fprintf(builder, "        ssl_crl %s;\n", nginxQuote(profile.Revocation.GatewayCRLBundleFile))
	builder.WriteString("        ssl_verify_client on;\n")
	builder.WriteString("        ssl_verify_depth 8;\n")
	builder.WriteString("        limit_conn tlcp_clients 32;\n\n")
	builder.WriteString("        location = /.well-known/trustdb/tlcp-active-identities {\n")
	builder.WriteString("            return 404;\n")
	builder.WriteString("        }\n\n")
	builder.WriteString("        location / {\n")
	if grpc {
		builder.WriteString("            grpc_connect_timeout 5s;\n")
		builder.WriteString("            grpc_send_timeout 30s;\n")
		builder.WriteString("            grpc_read_timeout 30s;\n")
		fmt.Fprintf(builder, "            grpc_pass %s;\n", nginxQuote("grpc://"+upstream))
	} else {
		builder.WriteString("            proxy_http_version 1.1;\n")
		builder.WriteString("            proxy_connect_timeout 5s;\n")
		builder.WriteString("            proxy_send_timeout 30s;\n")
		builder.WriteString("            proxy_read_timeout 30s;\n")
		builder.WriteString("            proxy_set_header Host $host;\n")
		builder.WriteString("            proxy_set_header X-Forwarded-Proto tlcp;\n")
		fmt.Fprintf(builder, "            proxy_pass %s;\n", nginxQuote("http://"+upstream))
	}
	builder.WriteString("        }\n")
	builder.WriteString("    }\n")
}

func nginxQuote(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`)
	return `"` + replacer.Replace(value) + `"`
}

func encodeRuntimeManifest(manifest RuntimeManifest) ([]byte, error) {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode TLCP runtime manifest: %w", err)
	}
	return append(data, '\n'), nil
}

func decodeStrictRuntimeJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("trailing JSON value")
	}
	return nil
}

func atomicWriteRuntimeFile(path string, data []byte) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
