package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/tlcpprofile"
	"github.com/wowtrust/trustdb/internal/tlcpready"
)

const (
	configurationPath = "/run/tlcp-gateway/nginx.conf"
	manifestPath      = "/run/tlcp-gateway/runtime-manifest.json"
	profileToolPath   = "/usr/local/bin/trustdb-tlcp-profile"

	maxVerifierOutputBytes = 64 << 10
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	return runReadiness(readinessDependencies{
		now:            time.Now,
		loadProfile:    tlcpprofile.Load,
		verifyRuntime:  verifyRuntimeUnderDeadline,
		verifyIdentity: tlcpprofile.VerifyActiveIdentityChallenge,
		check:          tlcpready.Check,
	})
}

type readinessDependencies struct {
	now            func() time.Time
	loadProfile    func(string) (tlcpprofile.Profile, error)
	verifyRuntime  func(context.Context, string, tlcpprofile.RuntimeOptions) error
	verifyIdentity func(context.Context, string, tlcpprofile.Profile) error
	check          func(context.Context, tlcpready.Config) error
}

func runReadiness(dependencies readinessDependencies) error {
	started := dependencies.now()
	profilePath := requiredEnvironment("TLCP_PROFILE_FILE")
	imageDigest := requiredEnvironment("TLCP_EXPECTED_GATEWAY_IMAGE_DIGEST")
	if profilePath == "" || imageDigest == "" {
		return errors.New("TLCP_PROFILE_FILE and TLCP_EXPECTED_GATEWAY_IMAGE_DIGEST are required")
	}
	profile, err := dependencies.loadProfile(profilePath)
	if err != nil {
		return err
	}
	timeout, err := tlcpprofile.LifecycleTimeout(
		profile,
		tlcpprofile.LifecycleCanary,
	)
	if err != nil {
		return err
	}
	deadline := started.Add(timeout)
	if !dependencies.now().Before(deadline) {
		return errors.New(
			"TLCP canary deadline expired during initial profile loading",
		)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	options := tlcpprofile.RuntimeOptions{
		ExpectedGatewayImageDigest: imageDigest,
		ConfigurationPath:          configurationPath,
		ManifestPath:               manifestPath,
	}
	if err := dependencies.verifyRuntime(ctx, profilePath, options); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf(
				"verify strict runtime manifest: canary deadline exceeded: %w",
				ctxErr,
			)
		}
		return fmt.Errorf("verify strict runtime manifest: %w", err)
	}
	reloaded, err := dependencies.loadProfile(profilePath)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(reloaded, profile) {
		return errors.New(
			"TLCP profile changed while the runtime verifier was running",
		)
	}
	if !dependencies.now().Before(deadline) {
		return errors.New(
			"TLCP canary deadline expired during runtime and profile validation",
		)
	}
	httpAddress, err := tlcpready.LoopbackAddress(profile.Network.GatewayHTTPBind)
	if err != nil {
		return err
	}
	grpcAddress, err := tlcpready.LoopbackAddress(profile.Network.GatewayGRPCBind)
	if err != nil {
		return err
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
	if err := dependencies.verifyIdentity(ctx, profilePath, profile); err != nil {
		return fmt.Errorf("verify active TrustDB identities: %w", err)
	}
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

func verifyRuntimeUnderDeadline(
	ctx context.Context,
	profilePath string,
	options tlcpprofile.RuntimeOptions,
) error {
	return runBoundedVerifier(
		ctx,
		profileToolPath,
		"verify-runtime",
		"--profile", profilePath,
		"--expected-image-digest", options.ExpectedGatewayImageDigest,
		"--configuration", options.ConfigurationPath,
		"--runtime-manifest", options.ManifestPath,
	)
}

func runBoundedVerifier(
	ctx context.Context,
	path string,
	arguments ...string,
) error {
	command := exec.CommandContext(ctx, path, arguments...)
	output := &boundedVerifierOutput{limit: maxVerifierOutputBytes}
	command.Stdout = output
	command.Stderr = output
	runErr := command.Run()
	if output.Exceeded() {
		return fmt.Errorf(
			"runtime verifier output exceeds %d bytes",
			maxVerifierOutputBytes,
		)
	}
	if runErr != nil {
		diagnostics := strings.TrimSpace(string(output.Bytes()))
		if diagnostics == "" {
			return runErr
		}
		return fmt.Errorf("%w: %s", runErr, diagnostics)
	}
	return nil
}

type boundedVerifierOutput struct {
	mutex    sync.Mutex
	data     []byte
	limit    int
	exceeded bool
}

func (output *boundedVerifierOutput) Write(data []byte) (int, error) {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	remaining := output.limit - len(output.data)
	if remaining <= 0 {
		output.exceeded = true
		return 0, io.ErrShortWrite
	}
	if len(data) > remaining {
		output.data = append(output.data, data[:remaining]...)
		output.exceeded = true
		return remaining, io.ErrShortWrite
	}
	output.data = append(output.data, data...)
	return len(data), nil
}

func (output *boundedVerifierOutput) Bytes() []byte {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	return append([]byte(nil), output.data...)
}

func (output *boundedVerifierOutput) Exceeded() bool {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	return output.exceeded
}

func requiredEnvironment(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}
