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
	return runReadiness(readinessDependencies{
		now:             time.Now,
		verifyRuntime:   tlcpprofile.VerifyRuntime,
		loadAndValidate: tlcpprofile.LoadAndValidate,
		check:           tlcpready.Check,
	})
}

type readinessDependencies struct {
	now             func() time.Time
	verifyRuntime   func(string, tlcpprofile.RuntimeOptions) (tlcpprofile.RuntimeManifest, error)
	loadAndValidate func(string, tlcpprofile.Options) (tlcpprofile.Profile, tlcpprofile.Report, error)
	check           func(context.Context, tlcpready.Config) error
}

func runReadiness(dependencies readinessDependencies) error {
	started := dependencies.now()
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
	if _, err := dependencies.verifyRuntime(profilePath, options); err != nil {
		return fmt.Errorf("verify strict runtime manifest: %w", err)
	}
	profile, _, err := dependencies.loadAndValidate(
		profilePath,
		tlcpprofile.Options{},
	)
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
	timeout, err := tlcpprofile.LifecycleTimeout(profile, tlcpprofile.LifecycleCanary)
	if err != nil {
		return err
	}
	deadline := started.Add(timeout)
	if !dependencies.now().Before(deadline) {
		return errors.New(
			"TLCP canary deadline expired during runtime and profile validation",
		)
	}
	readinessSigningChain := requiredEnvironment(
		"TLCP_READINESS_SIGNING_CHAIN_FILE",
	)
	readinessEncryptionChain := requiredEnvironment(
		"TLCP_READINESS_ENCRYPTION_CHAIN_FILE",
	)
	if readinessSigningChain != profile.Readiness.SigningChainFile ||
		readinessEncryptionChain != profile.Readiness.EncryptionChainFile {
		return errors.New(
			"TLCP readiness certificate paths do not exactly match the authenticated profile identities",
		)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	return dependencies.check(ctx, tlcpready.Config{
		OpenSSLPath:               "/opt/tongsuo/bin/openssl",
		ServerName:                profile.ServerName,
		ServerCAFile:              profile.Certificates.ServerCAFile,
		HTTPAddress:               httpAddress,
		GRPCAddress:               grpcAddress,
		ClientSigningChainFile:    readinessSigningChain,
		ClientSigningKey:          requiredEnvironment("TLCP_READINESS_SIGNING_KEY_REFERENCE"),
		ClientEncryptionChainFile: readinessEncryptionChain,
		ClientEncryptionKey:       requiredEnvironment("TLCP_READINESS_ENCRYPTION_KEY_REFERENCE"),
	})
}

func requiredEnvironment(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}
