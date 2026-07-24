package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/wowtrust/trustdb/internal/tlcpprofile"
	"github.com/wowtrust/trustdb/internal/tlcpready"
)

const (
	configurationPath = "/run/tlcp-gateway/nginx.conf"
	manifestPath      = "/run/tlcp-gateway/runtime-manifest.json"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	profilePath := requiredEnvironment("TLCP_PROFILE_FILE")
	imageDigest := requiredEnvironment("TLCP_EXPECTED_GATEWAY_IMAGE_DIGEST")
	if profilePath == "" || imageDigest == "" {
		return errors.New("TLCP_PROFILE_FILE and TLCP_EXPECTED_GATEWAY_IMAGE_DIGEST are required")
	}
	options := tlcpprofile.RuntimeOptions{
		ExpectedGatewayImageDigest: imageDigest,
		ConfigurationPath:          configurationPath,
		ManifestPath:               manifestPath,
	}
	if _, err := tlcpprofile.VerifyRuntime(profilePath, options); err != nil {
		return fmt.Errorf("verify strict runtime manifest: %w", err)
	}
	profile, _, err := tlcpprofile.LoadAndValidate(profilePath, tlcpprofile.Options{})
	if err != nil {
		return err
	}
	httpAddress, err := tlcpready.LoopbackAddress(profile.Network.GatewayHTTPBind)
	if err != nil {
		return err
	}
	grpcAddress, err := tlcpready.LoopbackAddress(profile.Network.GatewayGRPCBind)
	if err != nil {
		return err
	}
	timeout, err := time.ParseDuration(profile.Timeouts.Canary)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return tlcpready.Check(ctx, tlcpready.Config{
		OpenSSLPath:               "/opt/tongsuo/bin/openssl",
		ServerName:                profile.ServerName,
		ServerCAFile:              profile.Certificates.ServerCAFile,
		HTTPAddress:               httpAddress,
		GRPCAddress:               grpcAddress,
		ClientSigningChainFile:    requiredEnvironment("TLCP_READINESS_SIGNING_CHAIN_FILE"),
		ClientSigningKey:          requiredEnvironment("TLCP_READINESS_SIGNING_KEY_REFERENCE"),
		ClientEncryptionChainFile: requiredEnvironment("TLCP_READINESS_ENCRYPTION_CHAIN_FILE"),
		ClientEncryptionKey:       requiredEnvironment("TLCP_READINESS_ENCRYPTION_KEY_REFERENCE"),
	})
}

func requiredEnvironment(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}
