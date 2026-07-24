//go:build integration && tlcp

package tlcpe2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/tlcpprofile"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	serverName     = "trustdb.test"
	httpPort       = "8443"
	grpcPort       = "9443"
	canaryHTTPPort = "10443"
	canaryGRPCPort = "11443"
)

type certificateFixture struct {
	dir                    string
	serverSigningSHA256    string
	serverEncryptionSHA256 string
	clientSigningCert      string
	clientSigningKey       string
	clientEncryptionCert   string
	clientEncryptionKey    string
	serverCA               string
	wrongCA                string
	serverCAObject         *smx509.Certificate
	serverCAKey            *sm2.PrivateKey
	clientCAObject         *smx509.Certificate
	clientCAKey            *sm2.PrivateKey
	clientSerials          []*big.Int
	profile                tlcpprofile.Profile
	profileFile            string
}

type runningGateway struct {
	gatewayContainer  string
	upstreamContainer string
	gatewayImage      string
	fixture           certificateFixture
	httpPort          string
	grpcPort          string
}

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *synchronizedBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(data)
}

func (buffer *synchronizedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

type serverGeneration struct {
	name                      string
	signingPublicKeySHA256    string
	encryptionPublicKeySHA256 string
	profileFile               string
}

func TestTLCPGatewayHTTPAndGRPCMutualAuthentication(t *testing.T) {
	requireDocker(t)
	root := repositoryRoot(t)
	architecture := dockerArchitecture(t)
	gatewayImage := buildGatewayImage(t, root, architecture)
	upstreamImage := buildUpstreamImage(t, root, architecture)
	fixture := newCertificateFixture(t)
	running := startGateway(t, upstreamImage, gatewayImage, fixture, nil)

	publishedPorts := dockerOutput(
		t,
		"inspect", "--format", "{{json .NetworkSettings.Ports}}", running.upstreamContainer,
	)
	for _, port := range []string{"18080/tcp", "19090/tcp"} {
		if strings.Contains(publishedPorts, `"`+port+`"`) {
			t.Fatalf("plaintext TrustDB port %s appears in published ports %s", port, publishedPorts)
		}
	}
	httpResult := runHTTPClient(t, running, fixture, nil)
	for _, expected := range []string{
		"HTTP/1.1 200 OK",
		`{"status":"ok","transport":"loopback"}`,
		"Protocol version: NTLSv1.1",
		"Ciphersuite: ECDHE-SM2-SM4-GCM-SM3",
	} {
		if !strings.Contains(httpResult, expected) {
			t.Fatalf("HTTP TLCP result does not contain %q:\n%s", expected, httpResult)
		}
	}
	if err := runGRPCHealthClient(running, fixture); err != nil {
		t.Fatal(err)
	}

	t.Run("bounded concurrent HTTP and gRPC", func(t *testing.T) {
		const clients = 8
		errs := make(chan error, clients*2)
		var group sync.WaitGroup
		for index := 0; index < clients; index++ {
			group.Add(2)
			go func() {
				defer group.Done()
				result, err := runOpenSSLText(
					running,
					fixture,
					"http/1.1",
					nil,
					"GET /healthz HTTP/1.1\r\nHost: "+serverName+
						"\r\nConnection: close\r\n\r\n",
					true,
				)
				if err != nil || !strings.Contains(result, "HTTP/1.1 200 OK") {
					errs <- fmt.Errorf("concurrent HTTP readiness failed: %w: %s", err, result)
				}
			}()
			go func() {
				defer group.Done()
				if err := runGRPCHealthClient(running, fixture); err != nil {
					errs <- err
				}
			}()
		}
		group.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})

	t.Run("request body threshold", func(t *testing.T) {
		const maximum = 16 << 20
		body := bytes.Repeat([]byte{'a'}, maximum)
		request := "POST /echo-size HTTP/1.1\r\nHost: " + serverName +
			"\r\nContent-Length: " + strconv.Itoa(len(body)) +
			"\r\nConnection: close\r\n\r\n" + string(body)
		result, err := runOpenSSLText(
			running,
			fixture,
			"http/1.1",
			nil,
			request,
			true,
		)
		if err != nil || !strings.Contains(result, "HTTP/1.1 200 OK") ||
			!strings.Contains(result, strconv.Itoa(maximum)) {
			t.Fatalf("maximum request body was not accepted: %v\n%s", err, result)
		}

		result, err = runOpenSSLText(
			running,
			fixture,
			"http/1.1",
			nil,
			"POST /echo-size HTTP/1.1\r\nHost: "+serverName+
				"\r\nContent-Length: "+strconv.Itoa(maximum+1)+
				"\r\nConnection: close\r\n\r\n",
			true,
		)
		if !strings.Contains(result, "HTTP/1.1 413 Request Entity Too Large") {
			t.Fatalf("oversized request body was not rejected at 16 MiB: %v\n%s", err, result)
		}
	})

	t.Run("sustained authenticated traffic", func(t *testing.T) {
		const rounds = 4
		const clients = 4
		errs := make(chan error, rounds*clients*2)
		var group sync.WaitGroup
		for index := 0; index < clients; index++ {
			group.Add(1)
			go func() {
				defer group.Done()
				for round := 0; round < rounds; round++ {
					result, err := runOpenSSLText(
						running,
						fixture,
						"http/1.1",
						nil,
						"GET /healthz HTTP/1.1\r\nHost: "+serverName+
							"\r\nConnection: close\r\n\r\n",
						true,
					)
					if err != nil || !strings.Contains(result, "HTTP/1.1 200 OK") {
						errs <- fmt.Errorf("sustained HTTP request failed: %w: %s", err, result)
					}
					if err := runGRPCHealthClient(running, fixture); err != nil {
						errs <- fmt.Errorf("sustained gRPC request failed: %w", err)
					}
				}
			}()
		}
		group.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})

	t.Run("slow partial header is bounded", func(t *testing.T) {
		if err := runSlowHeaderClient(running, fixture); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("missing client certificate", func(t *testing.T) {
		result, err := runOpenSSLText(
			running,
			fixture,
			"http/1.1",
			nil,
			"GET /health HTTP/1.1\r\nHost: "+serverName+"\r\nConnection: close\r\n\r\n",
			false,
		)
		if err == nil || strings.Contains(result, "HTTP/1.1 200 OK") {
			t.Fatalf("gateway accepted a client without a certificate: err=%v\n%s", err, result)
		}
	})

	t.Run("wrong server CA", func(t *testing.T) {
		result, err := runOpenSSLText(
			running,
			fixture,
			"http/1.1",
			[]string{"-CAfile", "/certs/" + filepath.Base(fixture.wrongCA)},
			"GET /health HTTP/1.1\r\nHost: "+serverName+"\r\nConnection: close\r\n\r\n",
			true,
		)
		if err == nil || strings.Contains(result, "HTTP/1.1 200 OK") {
			t.Fatalf("client trusted a server under the wrong CA: err=%v\n%s", err, result)
		}
	})

	t.Run("different NTLS cipher", func(t *testing.T) {
		result, err := runOpenSSLText(
			running,
			fixture,
			"http/1.1",
			[]string{"-cipher", "ECC-SM2-SM4-GCM-SM3"},
			"GET /health HTTP/1.1\r\nHost: "+serverName+"\r\nConnection: close\r\n\r\n",
			true,
		)
		if err == nil || strings.Contains(result, "HTTP/1.1 200 OK") {
			t.Fatalf("gateway negotiated an unapproved NTLS cipher: err=%v\n%s", err, result)
		}
	})

	t.Run("standard TLS mismatch", func(t *testing.T) {
		result, err := runStandardTLSClient(running, fixture)
		if err == nil || strings.Contains(result, "HTTP/1.1 200 OK") {
			t.Fatalf("gateway accepted standard TLS on a TLCP listener: err=%v\n%s", err, result)
		}
	})

	t.Run("mismatched encryption private key", func(t *testing.T) {
		name := startGatewayContainer(
			t,
			running.upstreamContainer,
			gatewayImage,
			fixture,
			map[string]string{
				"TLCP_ENCRYPTION_KEY_REFERENCE": "/certs/" +
					filepath.Base(fixture.clientEncryptionKey),
			},
			true,
		)
		logs := dockerOutput(t, "logs", name)
		if !strings.Contains(logs, "key values mismatch") {
			t.Fatalf("mismatched key did not fail closed:\n%s", logs)
		}
	})

	t.Run("missing encryption certificate", func(t *testing.T) {
		name := startGatewayContainer(
			t,
			running.upstreamContainer,
			gatewayImage,
			fixture,
			map[string]string{
				"TLCP_SERVER_ENCRYPTION_CHAIN_FILE": "/certs/missing-encryption.pem",
			},
			true,
		)
		logs := dockerOutput(t, "logs", name)
		if !strings.Contains(logs, "no such file or directory") {
			t.Fatalf("missing encryption certificate did not fail closed:\n%s", logs)
		}
	})

	t.Run("revoked client certificate", func(t *testing.T) {
		revokedBundle, revokedServerCRL, revokedClientCRL := writeRevokedCRLBundle(t, fixture)
		name := startGatewayContainer(
			t,
			running.upstreamContainer,
			gatewayImage,
			fixture,
			map[string]string{
				"TLCP_CRL_BUNDLE_FILE":   "/certs/" + filepath.Base(revokedBundle),
				"TLCP_SERVER_CRL_FILE":   "/certs/" + filepath.Base(revokedServerCRL),
				"TLCP_CLIENT_CRL_FILE":   "/certs/" + filepath.Base(revokedClientCRL),
				"TLCP_GATEWAY_HTTP_BIND": "0.0.0.0:" + canaryHTTPPort,
				"TLCP_GATEWAY_GRPC_BIND": "0.0.0.0:" + canaryGRPCPort,
			},
			false,
		)
		waitForLog(t, name, "start worker processes")
		waitForUnhealthy(t, name)
		revokedGateway := runningGateway{
			gatewayContainer:  name,
			upstreamContainer: running.upstreamContainer,
			gatewayImage:      gatewayImage,
			fixture:           fixture,
			httpPort:          canaryHTTPPort,
			grpcPort:          canaryGRPCPort,
		}
		result, err := runOpenSSLText(
			revokedGateway,
			fixture,
			"http/1.1",
			nil,
			"GET /health HTTP/1.1\r\nHost: "+serverName+"\r\nConnection: close\r\n\r\n",
			true,
		)
		if strings.Contains(result, "HTTP/1.1 200 OK") ||
			!strings.Contains(result, "400 The SSL certificate error") {
			t.Fatalf("gateway did not reject a revoked HTTP client: err=%v\n%s", err, result)
		}
		if err := runGRPCHealthClient(revokedGateway, fixture); err == nil {
			t.Fatal("gateway accepted a revoked client for the gRPC health service")
		}
	})

	t.Run("expired server certificate", func(t *testing.T) {
		expired := prepareExpiredServerGeneration(t, fixture)
		name := startGatewayContainer(
			t,
			running.upstreamContainer,
			gatewayImage,
			fixture,
			generationEnvironment(expired, canaryHTTPPort, canaryGRPCPort),
			true,
		)
		if logs := dockerOutput(t, "logs", name); !strings.Contains(logs, "certificate expired") {
			t.Fatalf("expired server certificate did not fail before readiness:\n%s", logs)
		}
	})

	t.Run("atomic certificate rotation", func(t *testing.T) {
		first, second := prepareServerGenerations(t, fixture)
		firstFixture := fixtureForGeneration(fixture, first)
		secondFixture := fixtureForGeneration(fixture, second)
		for _, name := range []string{
			"server-ca.pem",
			"client-ca.pem",
			"client-signing.pem",
			"client-encryption.pem",
			"server-ca.crl",
			"client-ca.crl",
		} {
			firstDigest := testFileDigest(t, filepath.Join(fixture.dir, first.name, name))
			secondDigest := testFileDigest(t, filepath.Join(fixture.dir, second.name, name))
			if firstDigest == secondDigest {
				t.Fatalf("%s did not rotate between generations", name)
			}
		}
		activeGeneration := first
		activeGeneration.name = "active"
		activeGeneration.profileFile = "/certs/active/active-profile.json"
		active := startGateway(
			t,
			upstreamImage,
			gatewayImage,
			fixture,
			generationEnvironment(activeGeneration, httpPort, grpcPort),
		)
		if err := runGRPCHealthClient(active, firstFixture); err != nil {
			t.Fatalf("initial generation gRPC canary: %v", err)
		}
		if got := serverPublicKeySHA256(t, active, firstFixture); got != first.signingPublicKeySHA256 {
			t.Fatalf("initial signing public key = %s, want %s", got, first.signingPublicKeySHA256)
		}

		invalidEnvironment := generationEnvironment(second, canaryHTTPPort, canaryGRPCPort)
		invalidEnvironment["TLCP_ENCRYPTION_KEY_REFERENCE"] = "/certs/" + first.name + "/server-encryption.key"
		failedCandidate := startGatewayContainer(
			t,
			active.upstreamContainer,
			gatewayImage,
			fixture,
			invalidEnvironment,
			true,
		)
		if logs := dockerOutput(t, "logs", failedCandidate); !strings.Contains(logs, "key values mismatch") {
			t.Fatalf("invalid candidate did not fail closed:\n%s", logs)
		}
		runHTTPClient(t, active, firstFixture, nil)
		if err := runGRPCHealthClient(active, firstFixture); err != nil {
			t.Fatalf("failed candidate disrupted the active generation: %v", err)
		}

		candidateName := startGatewayContainer(
			t,
			active.upstreamContainer,
			gatewayImage,
			fixture,
			generationEnvironment(second, canaryHTTPPort, canaryGRPCPort),
			false,
		)
		waitForLog(t, candidateName, "start worker processes")
		waitForHealthy(t, candidateName)
		candidate := runningGateway{
			gatewayContainer:  candidateName,
			upstreamContainer: active.upstreamContainer,
			gatewayImage:      gatewayImage,
			fixture:           fixture,
			httpPort:          canaryHTTPPort,
			grpcPort:          canaryGRPCPort,
		}
		_ = publishedAddress(t, active.upstreamContainer, canaryHTTPPort)
		_ = publishedAddress(t, active.upstreamContainer, canaryGRPCPort)
		runHTTPClient(t, candidate, secondFixture, nil)
		if err := runGRPCHealthClient(candidate, secondFixture); err != nil {
			t.Fatalf("candidate generation gRPC canary: %v", err)
		}
		if got := serverPublicKeySHA256(t, candidate, secondFixture); got != second.signingPublicKeySHA256 {
			t.Fatalf("candidate signing public key = %s, want %s", got, second.signingPublicKeySHA256)
		}

		started := time.Now()
		activateGeneration(t, fixture.dir, second.name)
		prepareRuntimeInContainer(t, active.gatewayContainer)
		runDocker(t, "kill", "--signal", "HUP", active.gatewayContainer)
		reloadTimeout, err := tlcpprofile.LifecycleTimeout(
			fixture.profile,
			tlcpprofile.LifecycleReload,
		)
		if err != nil {
			t.Fatal(err)
		}
		waitForRuntimeReadiness(t, active.gatewayContainer, reloadTimeout)
		if got := serverPublicKeySHA256(t, active, secondFixture); got != second.signingPublicKeySHA256 {
			t.Fatalf("rotated signing public key = %s, want %s", got, second.signingPublicKeySHA256)
		}
		if elapsed := time.Since(started); elapsed > reloadTimeout {
			t.Fatalf("gateway reload took %s, want at most %s", elapsed, reloadTimeout)
		}
		runHTTPClient(t, active, secondFixture, nil)
		if err := runGRPCHealthClient(active, secondFixture); err != nil {
			t.Fatalf("rotated generation gRPC canary: %v", err)
		}
		oldClient := firstFixture
		oldClient.serverCA = secondFixture.serverCA
		if result, err := runOpenSSLText(
			active,
			oldClient,
			"http/1.1",
			nil,
			"GET /health HTTP/1.1\r\nHost: "+serverName+"\r\nConnection: close\r\n\r\n",
			true,
		); strings.Contains(result, "HTTP/1.1 200 OK") ||
			!strings.Contains(result, "400 The SSL certificate error") {
			t.Fatalf("rotated client CA accepted the old readiness identity: err=%v\n%s", err, result)
		}
		oldServerTrust := secondFixture
		oldServerTrust.serverCA = firstFixture.serverCA
		if result, err := runOpenSSLText(
			active,
			oldServerTrust,
			"http/1.1",
			nil,
			"GET /health HTTP/1.1\r\nHost: "+serverName+"\r\nConnection: close\r\n\r\n",
			true,
		); err == nil || strings.Contains(result, "HTTP/1.1 200 OK") {
			t.Fatalf("rotated server CA remained trusted by the old bundle: err=%v\n%s", err, result)
		}

		runtimeBeforeFailure := runtimeConfigurationDigest(t, active.gatewayContainer)
		activeProfilePath := filepath.Join(fixture.dir, second.name, "active-profile.json")
		previousProfile, err := os.ReadFile(activeProfilePath)
		if err != nil {
			t.Fatal(err)
		}
		rewriteGenerationGRPCUpstream(
			t,
			activeProfilePath,
			"127.0.0.1:19091",
		)
		prepareRuntimeInContainer(t, active.gatewayContainer)
		if got := runtimeConfigurationDigest(t, active.gatewayContainer); got == runtimeBeforeFailure {
			t.Fatal("failed-canary configuration was not promoted")
		}
		runDocker(t, "kill", "--signal", "HUP", active.gatewayContainer)
		waitForRuntimeReadinessFailure(t, active.gatewayContainer, reloadTimeout)
		replaceTestFile(t, activeProfilePath, previousProfile)
		prepareRuntimeInContainer(t, active.gatewayContainer)
		runDocker(t, "kill", "--signal", "HUP", active.gatewayContainer)
		waitForRuntimeReadiness(t, active.gatewayContainer, reloadTimeout)
		if got := runtimeConfigurationDigest(t, active.gatewayContainer); got != runtimeBeforeFailure {
			t.Fatalf(
				"rollback did not restore the previous runtime files:\nwant: %s\ngot:  %s",
				runtimeBeforeFailure,
				got,
			)
		}
		runHTTPClient(t, active, secondFixture, nil)
		if err := runGRPCHealthClient(active, secondFixture); err != nil {
			t.Fatalf("rollback generation gRPC canary: %v", err)
		}
	})
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	command := exec.Command("docker", "info", "--format", "{{.ServerVersion}}")
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("docker is unavailable: %v: %s", err, output)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate integration test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func dockerArchitecture(t *testing.T) string {
	t.Helper()
	value := strings.TrimSpace(dockerOutput(t, "version", "--format", "{{.Server.Arch}}"))
	switch value {
	case "amd64", "x86_64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	default:
		t.Fatalf("unsupported Docker architecture %q", value)
		return ""
	}
}

func buildGatewayImage(t *testing.T, root, architecture string) string {
	t.Helper()
	if image := strings.TrimSpace(os.Getenv("TRUSTDB_TLCP_GATEWAY_IMAGE")); image != "" {
		return image
	}
	image := "trustdb-tlcp-gateway:e2e-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	runDocker(
		t,
		"buildx", "build",
		"--file", filepath.Join(root, "packaging", "tlcp-gateway", "Dockerfile"),
		"--load",
		"--platform", "linux/"+architecture,
		"--provenance=false",
		"--tag", image,
		root,
	)
	return image
}

func buildUpstreamImage(t *testing.T, root, architecture string) string {
	t.Helper()
	if image := strings.TrimSpace(os.Getenv("TRUSTDB_TLCP_UPSTREAM_IMAGE")); image != "" {
		return image
	}
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "upstream")
	command := exec.Command(
		"go", "build",
		"-tags=integration",
		"-trimpath",
		"-o", binaryPath,
		"./internal/tlcpe2e/testserver",
	)
	command.Dir = root
	command.Env = append(
		os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH="+architecture,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build loopback upstream: %v\n%s", err, output)
	}
	dockerfile, err := os.ReadFile(filepath.Join(root, "internal", "tlcpe2e", "testdata", "Dockerfile.upstream"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), dockerfile, 0o600); err != nil {
		t.Fatal(err)
	}
	image := "trustdb-tlcp-upstream:e2e-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	runDocker(t, "build", "--tag", image, dir)
	return image
}

func startGateway(
	t *testing.T,
	upstreamImage, gatewayImage string,
	fixture certificateFixture,
	extra map[string]string,
) runningGateway {
	t.Helper()
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	upstream := "trustdb-tlcp-upstream-" + suffix
	gateway := "trustdb-tlcp-gateway-" + suffix
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "--force", gateway).Run()
		_ = exec.Command("docker", "rm", "--force", upstream).Run()
	})
	runDocker(
		t,
		"run", "--detach",
		"--name", upstream,
		"--publish", "127.0.0.1::"+httpPort,
		"--publish", "127.0.0.1::"+grpcPort,
		"--publish", "127.0.0.1::"+canaryHTTPPort,
		"--publish", "127.0.0.1::"+canaryGRPCPort,
		"--read-only",
		upstreamImage,
	)
	waitForLog(t, upstream, "upstream ready")
	startGatewayContainerNamed(t, gateway, upstream, gatewayImage, fixture, extra)
	waitForLog(t, gateway, "start worker processes")
	waitForHealthy(t, gateway)
	_ = publishedAddress(t, upstream, httpPort)
	_ = publishedAddress(t, upstream, grpcPort)
	return runningGateway{
		gatewayContainer:  gateway,
		upstreamContainer: upstream,
		gatewayImage:      gatewayImage,
		fixture:           fixture,
		httpPort:          httpPort,
		grpcPort:          grpcPort,
	}
}

func startGatewayContainer(
	t *testing.T,
	upstream, image string,
	fixture certificateFixture,
	extra map[string]string,
	expectFailure bool,
) string {
	t.Helper()
	name := "trustdb-tlcp-negative-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "--force", name).Run() })
	args := gatewayDockerArgs(t, name, upstream, image, fixture, extra)
	command := exec.Command("docker", args...)
	output, err := command.CombinedOutput()
	if expectFailure {
		if err != nil {
			return name
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		waitOutput, waitErr := exec.CommandContext(ctx, "docker", "wait", name).CombinedOutput()
		if waitErr != nil {
			t.Fatalf("gateway %s did not fail closed: %v\n%s", name, waitErr, waitOutput)
		}
		if strings.TrimSpace(string(waitOutput)) == "0" {
			t.Fatalf("gateway %s exited successfully for an invalid configuration: %s", name, output)
		}
		return name
	}
	if err != nil {
		t.Fatalf("start gateway %s: %v\n%s", name, err, output)
	}
	return name
}

func startGatewayContainerNamed(
	t *testing.T,
	name, upstream, image string,
	fixture certificateFixture,
	extra map[string]string,
) {
	t.Helper()
	args := gatewayDockerArgs(t, name, upstream, image, fixture, extra)
	if output, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start gateway %s: %v\n%s", name, err, output)
	}
}

func gatewayDockerArgs(
	t *testing.T,
	name, upstream, image string,
	fixture certificateFixture,
	extra map[string]string,
) []string {
	t.Helper()
	profile := fixture.profile
	profilePath := ""
	profileChanged := false
	for name, value := range extra {
		switch name {
		case "TLCP_PROFILE_FILE":
			profilePath = value
		case "TLCP_SERVER_SIGNING_CHAIN_FILE":
			profile.Certificates.ServerSigningChainFile = value
			profileChanged = true
		case "TLCP_SERVER_ENCRYPTION_CHAIN_FILE":
			profile.Certificates.ServerEncryptionChainFile = value
			profileChanged = true
		case "TLCP_SERVER_CA_FILE":
			profile.Certificates.ServerCAFile = value
			profileChanged = true
		case "TLCP_CLIENT_CA_FILE":
			profile.Certificates.ClientCAFile = value
			profileChanged = true
		case "TLCP_CRL_BUNDLE_FILE":
			profile.Revocation.GatewayCRLBundleFile = value
			profileChanged = true
		case "TLCP_SERVER_CRL_FILE":
			profile.Revocation.CRLFiles[0] = value
			profileChanged = true
		case "TLCP_CLIENT_CRL_FILE":
			profile.Revocation.CRLFiles[1] = value
			profileChanged = true
		case "TLCP_SIGNING_KEY_REFERENCE":
			profile.Certificates.SigningKey.Reference = value
			profileChanged = true
		case "TLCP_SIGNING_PUBLIC_KEY_SHA256":
			profile.Certificates.SigningKey.PublicKeySHA256 = value
			profileChanged = true
		case "TLCP_ENCRYPTION_KEY_REFERENCE":
			profile.Certificates.EncryptionKey.Reference = value
			profileChanged = true
		case "TLCP_ENCRYPTION_PUBLIC_KEY_SHA256":
			profile.Certificates.EncryptionKey.PublicKeySHA256 = value
			profileChanged = true
		case "TLCP_GATEWAY_HTTP_BIND":
			profile.Network.GatewayHTTPBind = value
			profileChanged = true
		case "TLCP_GATEWAY_GRPC_BIND":
			profile.Network.GatewayGRPCBind = value
			profileChanged = true
		case "TLCP_TRUSTDB_IDENTITY_MANIFEST_FILE":
			profile.TrustDBIdentityManifestFile = value
			profileChanged = true
		case "TLCP_READINESS_SIGNING_CHAIN_FILE":
			profile.Readiness.SigningChainFile = value
			profileChanged = true
		case "TLCP_READINESS_ENCRYPTION_CHAIN_FILE":
			profile.Readiness.EncryptionChainFile = value
			profileChanged = true
		case "TLCP_READINESS_SIGNING_KEY_REFERENCE",
			"TLCP_READINESS_ENCRYPTION_KEY_REFERENCE":
		default:
			t.Fatalf("unsupported TLCP profile test override %q", name)
		}
	}
	profileFile := fixture.profileFile
	if profileChanged {
		profileFile = writeGatewayProfile(t, fixture.dir, profile)
	}
	if profilePath == "" {
		profilePath = "/certs/" + filepath.Base(profileFile)
	}
	environment := map[string]string{
		"TLCP_PROFILE_FILE":                       profilePath,
		"TLCP_EXPECTED_GATEWAY_IMAGE_DIGEST":      profile.Implementation.GatewayImageDigest,
		"TLCP_READINESS_SIGNING_CHAIN_FILE":       fixtureContainerPath(t, fixture, fixture.clientSigningCert),
		"TLCP_READINESS_SIGNING_KEY_REFERENCE":    fixtureContainerPath(t, fixture, fixture.clientSigningKey),
		"TLCP_READINESS_ENCRYPTION_CHAIN_FILE":    fixtureContainerPath(t, fixture, fixture.clientEncryptionCert),
		"TLCP_READINESS_ENCRYPTION_KEY_REFERENCE": fixtureContainerPath(t, fixture, fixture.clientEncryptionKey),
	}
	for name, value := range extra {
		if strings.HasPrefix(name, "TLCP_READINESS_") {
			environment[name] = value
		}
	}
	args := []string{
		"run", "--detach",
		"--name", name,
		"--network", "container:" + upstream,
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--tmpfs", "/run/tlcp-gateway:uid=10001,gid=10001,mode=0700",
		"--tmpfs", "/var/cache/tlcp-gateway:uid=10001,gid=10001,mode=0700",
		"--mount", "type=bind,src=" + fixture.dir + ",dst=/certs,readonly",
	}
	names := make([]string, 0, len(environment))
	for name := range environment {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		args = append(args, "--env", name+"="+environment[name])
	}
	return append(args, image)
}

func runHTTPClient(
	t *testing.T,
	running runningGateway,
	fixture certificateFixture,
	extra []string,
) string {
	t.Helper()
	result, err := runOpenSSLText(
		running,
		fixture,
		"http/1.1",
		extra,
		"GET /health HTTP/1.1\r\nHost: "+serverName+"\r\nConnection: close\r\n\r\n",
		true,
	)
	if err != nil {
		t.Fatalf(
			"HTTP TLCP request: %v\nclient:\n%s\ngateway:\n%s",
			err,
			result,
			dockerOutput(t, "logs", running.gatewayContainer),
		)
	}
	return result
}

func runOpenSSLText(
	running runningGateway,
	fixture certificateFixture,
	alpn string,
	extra []string,
	request string,
	withClientCertificate bool,
) (string, error) {
	args := opensslDockerArgs(running, fixture, alpn, withClientCertificate)
	args = append(args, extra...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	stdin, err := command.StdinPipe()
	if err != nil {
		return "", err
	}
	if err := command.Start(); err != nil {
		return "", err
	}
	if _, err := io.WriteString(stdin, request); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return stdout.String() + stderr.String(), err
	}
	err = command.Wait()
	return stdout.String() + stderr.String(), err
}

func runStandardTLSClient(
	running runningGateway,
	fixture certificateFixture,
) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	args := []string{
		"run", "--rm", "--interactive",
		"--network", "container:" + running.upstreamContainer,
		"--user", "0:0",
		"--mount", "type=bind,src=" + fixture.dir + ",dst=/certs,readonly",
		"--entrypoint", "/opt/tongsuo/bin/openssl",
		running.gatewayImage,
		"s_client",
		"-connect", "127.0.0.1:" + running.httpPort,
		"-servername", serverName,
		"-tls1_2",
		"-cipher", "ECDHE-RSA-AES256-GCM-SHA384",
		"-brief",
	}
	command := exec.CommandContext(ctx, "docker", args...)
	command.Stdin = strings.NewReader(
		"GET /health HTTP/1.1\r\nHost: " + serverName + "\r\nConnection: close\r\n\r\n",
	)
	output, err := command.CombinedOutput()
	return string(output), err
}

func runSlowHeaderClient(running runningGateway, fixture certificateFixture) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	args := opensslDockerArgs(running, fixture, "http/1.1", true)
	command := exec.CommandContext(ctx, "docker", args...)
	var output synchronizedBuffer
	command.Stdout = &output
	command.Stderr = &output
	stdin, err := command.StdinPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	if _, err := io.WriteString(
		stdin,
		"GET /healthz HTTP/1.1\r\nHost: "+serverName+"\r\nX-Slow: ",
	); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return err
	}
	err = command.Wait()
	if ctx.Err() != nil {
		return errors.New("slow partial header exceeded the gateway's configured bound")
	}
	result := output.String()
	if !strings.Contains(result, "Protocol version: NTLSv1.1") ||
		strings.Contains(result, "HTTP/1.1 200 OK") {
		return fmt.Errorf("slow-header result did not prove a bounded TLCP rejection: %v: %s", err, result)
	}
	return nil
}

func opensslDockerArgs(
	running runningGateway,
	fixture certificateFixture,
	alpn string,
	withClientCertificate bool,
) []string {
	port := runningPort(running, alpn)
	args := []string{
		"run", "--rm", "--interactive",
		"--network", "container:" + running.upstreamContainer,
		"--user", "0:0",
		"--mount", "type=bind,src=" + fixture.dir + ",dst=/certs,readonly",
		"--entrypoint", "/opt/tongsuo/bin/openssl",
		running.gatewayImage,
		"s_client",
		"-connect", "127.0.0.1:" + port,
		"-servername", serverName,
		"-verify_hostname", serverName,
		"-verify_return_error",
		"-CAfile", fixtureContainerPath(nil, fixture, fixture.serverCA),
		"-enable_ntls",
		"-ntls",
		"-cipher", "ECDHE-SM2-SM4-GCM-SM3",
		"-alpn", alpn,
		"-brief",
	}
	if withClientCertificate {
		args = append(args,
			"-sign_cert", fixtureContainerPath(nil, fixture, fixture.clientSigningCert),
			"-sign_key", fixtureContainerPath(nil, fixture, fixture.clientSigningKey),
			"-enc_cert", fixtureContainerPath(nil, fixture, fixture.clientEncryptionCert),
			"-enc_key", fixtureContainerPath(nil, fixture, fixture.clientEncryptionKey),
		)
	}
	return args
}

func fixtureContainerPath(t testing.TB, fixture certificateFixture, path string) string {
	if t != nil {
		t.Helper()
	}
	relative, err := filepath.Rel(fixture.dir, path)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		if t != nil {
			t.Fatalf("fixture path %q is outside %q", path, fixture.dir)
		}
		panic(fmt.Sprintf("fixture path %q is outside %q", path, fixture.dir))
	}
	return "/certs/" + filepath.ToSlash(relative)
}

func runGRPCHealthClient(running runningGateway, fixture certificateFixture) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	args := opensslDockerArgs(running, fixture, "h2", true)
	command := exec.CommandContext(ctx, "docker", args...)
	var diagnostics synchronizedBuffer
	command.Stderr = &diagnostics
	stdin, err := command.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	defer func() {
		_ = stdin.Close()
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	}()

	framer := http2.NewFramer(stdin, stdout)
	if _, err := io.WriteString(stdin, http2.ClientPreface); err != nil {
		return fmt.Errorf("write HTTP/2 preface: %w", err)
	}
	if err := framer.WriteSettings(); err != nil {
		return fmt.Errorf("write HTTP/2 settings: %w", err)
	}
	var headers bytes.Buffer
	encoder := hpack.NewEncoder(&headers)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/grpc.health.v1.Health/Check"},
		{Name: ":authority", Value: serverName},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "te", Value: "trailers"},
	} {
		if err := encoder.WriteField(field); err != nil {
			return err
		}
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: headers.Bytes(),
		EndHeaders:    true,
	}); err != nil {
		return fmt.Errorf("write gRPC headers: %w", err)
	}
	if err := framer.WriteData(1, true, []byte{0, 0, 0, 0, 0}); err != nil {
		return fmt.Errorf("write gRPC request: %w", err)
	}

	var response []byte
	grpcStatus := ""
	decoder := hpack.NewDecoder(4096, func(field hpack.HeaderField) {
		if field.Name == "grpc-status" {
			grpcStatus = field.Value
		}
	})
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return fmt.Errorf("read gRPC HTTP/2 frame: %w; TLS diagnostics: %s", err, diagnostics.String())
		}
		switch value := frame.(type) {
		case *http2.SettingsFrame:
			if !value.IsAck() {
				if err := framer.WriteSettingsAck(); err != nil {
					return err
				}
			}
		case *http2.HeadersFrame:
			if _, err := decoder.Write(value.HeaderBlockFragment()); err != nil {
				return fmt.Errorf("decode gRPC headers: %w", err)
			}
			if value.StreamEnded() && grpcStatus != "0" {
				return fmt.Errorf("gRPC health failed with status %q", grpcStatus)
			}
			if value.StreamEnded() {
				return verifyGRPCHealthResponse(response, waitForTLCPDiagnostics(&diagnostics))
			}
		case *http2.DataFrame:
			response = append(response, value.Data()...)
			if value.StreamEnded() {
				return verifyGRPCHealthResponse(response, waitForTLCPDiagnostics(&diagnostics))
			}
		case *http2.GoAwayFrame:
			return fmt.Errorf("gateway sent HTTP/2 GOAWAY %s: %s", value.ErrCode, value.DebugData())
		}
	}
}

func waitForTLCPDiagnostics(diagnostics *synchronizedBuffer) string {
	const expected = "Protocol version: NTLSv1.1"
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		value := diagnostics.String()
		if strings.Contains(value, expected) || time.Now().After(deadline) {
			return value
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func verifyGRPCHealthResponse(response []byte, diagnostics string) error {
	if len(response) != 7 ||
		response[0] != 0 ||
		binary.BigEndian.Uint32(response[1:5]) != 2 ||
		response[5] != 0x08 ||
		response[6] != 0x01 {
		return fmt.Errorf("unexpected gRPC health response %x; TLS diagnostics: %s", response, diagnostics)
	}
	for _, expected := range []string{
		"Protocol version: NTLSv1.1",
		"Ciphersuite: ECDHE-SM2-SM4-GCM-SM3",
	} {
		if !strings.Contains(diagnostics, expected) {
			return fmt.Errorf("TLS diagnostics do not contain %q: %s", expected, diagnostics)
		}
	}
	return nil
}

func serverPublicKeySHA256(
	t *testing.T,
	running runningGateway,
	fixture certificateFixture,
) string {
	t.Helper()
	args := opensslDockerArgs(running, fixture, "http/1.1", true)
	for index, value := range args {
		if value == "-brief" {
			args = append(args[:index], args[index+1:]...)
			break
		}
	}
	args = append(args, "-showcerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "docker", args...)
	command.Stdin = strings.NewReader(
		"GET /health HTTP/1.1\r\nHost: " + serverName + "\r\nConnection: close\r\n\r\n",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("read gateway certificate: %v\n%s", err, output)
	}
	start := bytes.Index(output, []byte("-----BEGIN CERTIFICATE-----"))
	if start < 0 {
		t.Fatalf("gateway did not return a PEM certificate:\n%s", output)
	}
	block, _ := pem.Decode(output[start:])
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("gateway returned an invalid PEM certificate:\n%s", output)
	}
	certificate, err := smx509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse gateway certificate: %v", err)
	}
	return publicKeySHA256(t, certificate)
}

func waitForServerPublicKey(
	t *testing.T,
	running runningGateway,
	fixture certificateFixture,
	expected string,
	timeout time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		last = serverPublicKeySHA256(t, running, fixture)
		if last == expected {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server public key remained %s, want %s after %s", last, expected, timeout)
}

func runningPort(running runningGateway, alpn string) string {
	if alpn == "h2" {
		return running.grpcPort
	}
	return running.httpPort
}

func publishedAddress(t *testing.T, container, port string) string {
	t.Helper()
	value := strings.TrimSpace(dockerOutput(t, "port", container, port+"/tcp"))
	if value == "" {
		t.Fatalf("container %s has no published port %s", container, port)
	}
	lines := strings.Split(value, "\n")
	return lines[0]
}

func waitForLog(t *testing.T, container, text string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		logs := dockerOutput(t, "logs", container)
		if strings.Contains(logs, text) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("container %s did not log %q:\n%s", container, text, dockerOutput(t, "logs", container))
}

func waitForHealthy(t *testing.T, container string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status := strings.TrimSpace(dockerOutput(
			t,
			"inspect",
			"--format",
			"{{if .State.Health}}{{.State.Health.Status}}{{end}}",
			container,
		))
		if status == "healthy" {
			return
		}
		if status == "unhealthy" {
			t.Fatalf("container %s became unhealthy:\n%s", container, dockerOutput(t, "logs", container))
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("container %s did not become healthy:\n%s", container, dockerOutput(t, "logs", container))
}

func waitForUnhealthy(t *testing.T, container string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status := strings.TrimSpace(dockerOutput(
			t,
			"inspect",
			"--format",
			"{{if .State.Health}}{{.State.Health.Status}}{{end}}",
			container,
		))
		if status == "unhealthy" {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("container %s did not become unhealthy", container)
}

func waitForRuntimeReadiness(t *testing.T, container string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last []byte
	for time.Now().Before(deadline) {
		output, err := exec.Command(
			"docker",
			"exec",
			container,
			"/usr/local/bin/trustdb-tlcp-readiness",
		).CombinedOutput()
		last = output
		if err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("container %s did not pass runtime readiness:\n%s", container, last)
}

func waitForRuntimeReadinessFailure(t *testing.T, container string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := exec.Command(
			"docker",
			"exec",
			container,
			"/usr/local/bin/trustdb-tlcp-readiness",
		).CombinedOutput(); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("container %s continued to pass the failed post-HUP canary", container)
}

func runDocker(t *testing.T, args ...string) string {
	t.Helper()
	output, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

func dockerOutput(t *testing.T, args ...string) string {
	t.Helper()
	output, _ := exec.Command("docker", args...).CombinedOutput()
	return string(output)
}

func newCertificateFixture(t *testing.T) certificateFixture {
	t.Helper()
	dir := t.TempDir()
	// The gateway deliberately runs as UID 10001. Test fixtures are ephemeral,
	// test-only software keys and must be readable through a native Linux bind
	// mount even when the test runner has a different UID.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	serverCA, serverCAKey := createCA(t, filepath.Join(dir, "server-ca.pem"), 1, "TLCP Server CA", now)
	clientCA, clientCAKey := createCA(t, filepath.Join(dir, "client-ca.pem"), 2, "TLCP Client CA", now)
	_, _ = createCA(t, filepath.Join(dir, "wrong-ca.pem"), 3, "Wrong TLCP CA", now)

	serverSigning, _ := createEndpoint(
		t, filepath.Join(dir, "server-signing.pem"), filepath.Join(dir, "server-signing.key"),
		serverCA, serverCAKey, 10, serverName, smx509.KeyUsageDigitalSignature,
		smx509.ExtKeyUsageServerAuth, now,
	)
	serverEncryption, _ := createEndpoint(
		t, filepath.Join(dir, "server-encryption.pem"), filepath.Join(dir, "server-encryption.key"),
		serverCA, serverCAKey, 11, serverName, smx509.KeyUsageKeyEncipherment,
		smx509.ExtKeyUsageServerAuth, now,
	)
	clientSigning, _ := createEndpoint(
		t, filepath.Join(dir, "client-signing.pem"), filepath.Join(dir, "client-signing.key"),
		clientCA, clientCAKey, 20, "TLCP Client", smx509.KeyUsageDigitalSignature,
		smx509.ExtKeyUsageClientAuth, now,
	)
	clientEncryption, _ := createEndpoint(
		t, filepath.Join(dir, "client-encryption.pem"), filepath.Join(dir, "client-encryption.key"),
		clientCA, clientCAKey, 21, "TLCP Client", smx509.KeyUsageKeyEncipherment,
		smx509.ExtKeyUsageClientAuth, now,
	)
	appendCertificate(t, filepath.Join(dir, "client-signing.pem"), clientCA)
	appendCertificate(t, filepath.Join(dir, "client-encryption.pem"), clientCA)
	serverCRL := createCRL(t, serverCA, serverCAKey, now, nil)
	clientCRL := createCRL(t, clientCA, clientCAKey, now, nil)
	serverCRLPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: serverCRL})
	clientCRLPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: clientCRL})
	writePEMFile(t, filepath.Join(dir, "server-ca.crl"), serverCRLPEM)
	writePEMFile(t, filepath.Join(dir, "client-ca.crl"), clientCRLPEM)
	writePEMFile(
		t,
		filepath.Join(dir, "crl-bundle.pem"),
		append(append([]byte(nil), serverCRLPEM...), clientCRLPEM...),
	)
	writeE2ETrustDBIdentityManifest(
		t,
		filepath.Join(dir, "trustdb-active-identities.json"),
	)
	fixture := certificateFixture{
		dir:                    dir,
		serverSigningSHA256:    publicKeySHA256(t, serverSigning),
		serverEncryptionSHA256: publicKeySHA256(t, serverEncryption),
		clientSigningCert:      filepath.Join(dir, "client-signing.pem"),
		clientSigningKey:       filepath.Join(dir, "client-signing.key"),
		clientEncryptionCert:   filepath.Join(dir, "client-encryption.pem"),
		clientEncryptionKey:    filepath.Join(dir, "client-encryption.key"),
		serverCA:               filepath.Join(dir, "server-ca.pem"),
		wrongCA:                filepath.Join(dir, "wrong-ca.pem"),
		serverCAObject:         serverCA,
		serverCAKey:            serverCAKey,
		clientCAObject:         clientCA,
		clientCAKey:            clientCAKey,
		clientSerials: []*big.Int{
			new(big.Int).Set(clientSigning.SerialNumber),
			new(big.Int).Set(clientEncryption.SerialNumber),
		},
	}
	fixture.profile = newGatewayProfile(t, fixture)
	fixture.profileFile = writeGatewayProfile(t, fixture.dir, fixture.profile)
	return fixture
}

func newGatewayProfile(t *testing.T, fixture certificateFixture) tlcpprofile.Profile {
	t.Helper()
	path := filepath.Join(repositoryRoot(t), "test", "vectors", "tlcp-gateway-profile-v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.ReplaceAll(data, []byte("${FIXTURE_DIR}"), []byte("/certs"))
	var profile tlcpprofile.Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatal(err)
	}
	profile.ProfileID = "tlcp-e2e"
	profile.ServerName = serverName
	profile.Network.TrustDBHTTPUpstream = "127.0.0.1:18080"
	profile.Network.TrustDBGRPCUpstream = "127.0.0.1:19090"
	profile.Network.GatewayHTTPBind = "0.0.0.0:" + httpPort
	profile.Network.GatewayGRPCBind = "0.0.0.0:" + grpcPort
	profile.Certificates.SigningKey.PublicKeySHA256 = fixture.serverSigningSHA256
	profile.Certificates.EncryptionKey.PublicKeySHA256 = fixture.serverEncryptionSHA256
	return profile
}

func writeGatewayProfile(t *testing.T, dir string, profile tlcpprofile.Profile) string {
	t.Helper()
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	name := "profile-" + strconv.FormatInt(time.Now().UnixNano(), 36) + ".json"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func prepareServerGenerations(
	t *testing.T,
	fixture certificateFixture,
) (serverGeneration, serverGeneration) {
	t.Helper()
	first := serverGeneration{
		name:                      "generation-1",
		signingPublicKeySHA256:    fixture.serverSigningSHA256,
		encryptionPublicKeySHA256: fixture.serverEncryptionSHA256,
	}
	firstDir := filepath.Join(fixture.dir, first.name)
	if err := os.Mkdir(firstDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"server-signing.pem",
		"server-signing.key",
		"server-encryption.pem",
		"server-encryption.key",
	} {
		if err := os.Rename(filepath.Join(fixture.dir, name), filepath.Join(firstDir, name)); err != nil {
			t.Fatalf("stage first generation %s: %v", name, err)
		}
	}
	for _, name := range []string{
		"server-ca.pem",
		"client-ca.pem",
		"server-ca.crl",
		"client-ca.crl",
		"crl-bundle.pem",
		"trustdb-active-identities.json",
		"client-signing.pem",
		"client-signing.key",
		"client-encryption.pem",
		"client-encryption.key",
	} {
		copyTestFile(t, filepath.Join(fixture.dir, name), filepath.Join(firstDir, name))
	}

	second := serverGeneration{name: "generation-2"}
	secondDir := filepath.Join(fixture.dir, second.name)
	if err := os.Mkdir(secondDir, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	secondServerCA, secondServerCAKey := createCA(
		t,
		filepath.Join(secondDir, "server-ca.pem"),
		101,
		"TLCP Server CA generation 2",
		now,
	)
	secondClientCA, secondClientCAKey := createCA(
		t,
		filepath.Join(secondDir, "client-ca.pem"),
		102,
		"TLCP Client CA generation 2",
		now,
	)
	signing, _ := createEndpoint(
		t,
		filepath.Join(secondDir, "server-signing.pem"),
		filepath.Join(secondDir, "server-signing.key"),
		secondServerCA,
		secondServerCAKey,
		110,
		serverName,
		smx509.KeyUsageDigitalSignature,
		smx509.ExtKeyUsageServerAuth,
		now,
	)
	encryption, _ := createEndpoint(
		t,
		filepath.Join(secondDir, "server-encryption.pem"),
		filepath.Join(secondDir, "server-encryption.key"),
		secondServerCA,
		secondServerCAKey,
		111,
		serverName,
		smx509.KeyUsageKeyEncipherment,
		smx509.ExtKeyUsageServerAuth,
		now,
	)
	secondClientSigning, _ := createEndpoint(
		t,
		filepath.Join(secondDir, "client-signing.pem"),
		filepath.Join(secondDir, "client-signing.key"),
		secondClientCA,
		secondClientCAKey,
		120,
		"TLCP readiness generation 2",
		smx509.KeyUsageDigitalSignature,
		smx509.ExtKeyUsageClientAuth,
		now,
	)
	secondClientEncryption, _ := createEndpoint(
		t,
		filepath.Join(secondDir, "client-encryption.pem"),
		filepath.Join(secondDir, "client-encryption.key"),
		secondClientCA,
		secondClientCAKey,
		121,
		"TLCP readiness generation 2",
		smx509.KeyUsageKeyEncipherment,
		smx509.ExtKeyUsageClientAuth,
		now,
	)
	appendCertificate(t, filepath.Join(secondDir, "client-signing.pem"), secondClientCA)
	appendCertificate(t, filepath.Join(secondDir, "client-encryption.pem"), secondClientCA)
	copyTestFile(
		t,
		filepath.Join(fixture.dir, "trustdb-active-identities.json"),
		filepath.Join(secondDir, "trustdb-active-identities.json"),
	)
	secondServerCRL := createCRL(
		t,
		secondServerCA,
		secondServerCAKey,
		now.Add(time.Minute),
		nil,
	)
	secondClientCRL := createCRL(
		t,
		secondClientCA,
		secondClientCAKey,
		now.Add(time.Minute),
		nil,
	)
	secondServerPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: secondServerCRL})
	secondClientPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: secondClientCRL})
	writePEMFile(t, filepath.Join(secondDir, "server-ca.crl"), secondServerPEM)
	writePEMFile(t, filepath.Join(secondDir, "client-ca.crl"), secondClientPEM)
	writePEMFile(
		t,
		filepath.Join(secondDir, "crl-bundle.pem"),
		append(append([]byte(nil), secondServerPEM...), secondClientPEM...),
	)
	second.signingPublicKeySHA256 = publicKeySHA256(t, signing)
	second.encryptionPublicKeySHA256 = publicKeySHA256(t, encryption)
	if publicKeySHA256(t, secondClientSigning) == publicKeySHA256(t, secondClientEncryption) {
		t.Fatal("second-generation readiness identity reused one key")
	}
	writeGenerationProfile(t, fixture, first, "active", httpPort, grpcPort)
	writeGenerationProfile(t, fixture, second, "active", httpPort, grpcPort)
	activateGeneration(t, fixture.dir, first.name)
	return first, second
}

func prepareExpiredServerGeneration(
	t *testing.T,
	fixture certificateFixture,
) serverGeneration {
	t.Helper()
	generation := serverGeneration{name: "expired-generation"}
	dir := filepath.Join(fixture.dir, generation.name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	expiredAt := time.Now().UTC().Add(-48 * time.Hour)
	signing, _ := createEndpoint(
		t,
		filepath.Join(dir, "server-signing.pem"),
		filepath.Join(dir, "server-signing.key"),
		fixture.serverCAObject,
		fixture.serverCAKey,
		40,
		serverName,
		smx509.KeyUsageDigitalSignature,
		smx509.ExtKeyUsageServerAuth,
		expiredAt,
	)
	encryption, _ := createEndpoint(
		t,
		filepath.Join(dir, "server-encryption.pem"),
		filepath.Join(dir, "server-encryption.key"),
		fixture.serverCAObject,
		fixture.serverCAKey,
		41,
		serverName,
		smx509.KeyUsageKeyEncipherment,
		smx509.ExtKeyUsageServerAuth,
		expiredAt,
	)
	for _, name := range []string{
		"server-ca.pem",
		"client-ca.pem",
		"server-ca.crl",
		"client-ca.crl",
		"crl-bundle.pem",
		"trustdb-active-identities.json",
	} {
		copyTestFile(t, filepath.Join(fixture.dir, name), filepath.Join(dir, name))
	}
	generation.signingPublicKeySHA256 = publicKeySHA256(t, signing)
	generation.encryptionPublicKeySHA256 = publicKeySHA256(t, encryption)
	return generation
}

func generationEnvironment(generation serverGeneration, httpBind, grpcBind string) map[string]string {
	prefix := "/certs/" + generation.name
	environment := map[string]string{
		"TLCP_READINESS_SIGNING_CHAIN_FILE":       prefix + "/client-signing.pem",
		"TLCP_READINESS_SIGNING_KEY_REFERENCE":    prefix + "/client-signing.key",
		"TLCP_READINESS_ENCRYPTION_CHAIN_FILE":    prefix + "/client-encryption.pem",
		"TLCP_READINESS_ENCRYPTION_KEY_REFERENCE": prefix + "/client-encryption.key",
	}
	if generation.profileFile != "" {
		environment["TLCP_PROFILE_FILE"] = generation.profileFile
		return environment
	}
	for name, value := range map[string]string{
		"TLCP_SERVER_SIGNING_CHAIN_FILE":      prefix + "/server-signing.pem",
		"TLCP_SERVER_ENCRYPTION_CHAIN_FILE":   prefix + "/server-encryption.pem",
		"TLCP_SERVER_CA_FILE":                 prefix + "/server-ca.pem",
		"TLCP_CLIENT_CA_FILE":                 prefix + "/client-ca.pem",
		"TLCP_SERVER_CRL_FILE":                prefix + "/server-ca.crl",
		"TLCP_CLIENT_CRL_FILE":                prefix + "/client-ca.crl",
		"TLCP_CRL_BUNDLE_FILE":                prefix + "/crl-bundle.pem",
		"TLCP_TRUSTDB_IDENTITY_MANIFEST_FILE": prefix + "/trustdb-active-identities.json",
		"TLCP_SIGNING_KEY_REFERENCE":          prefix + "/server-signing.key",
		"TLCP_SIGNING_PUBLIC_KEY_SHA256":      generation.signingPublicKeySHA256,
		"TLCP_ENCRYPTION_KEY_REFERENCE":       prefix + "/server-encryption.key",
		"TLCP_ENCRYPTION_PUBLIC_KEY_SHA256":   generation.encryptionPublicKeySHA256,
		"TLCP_GATEWAY_HTTP_BIND":              "0.0.0.0:" + httpBind,
		"TLCP_GATEWAY_GRPC_BIND":              "0.0.0.0:" + grpcBind,
	} {
		environment[name] = value
	}
	return environment
}

func fixtureForGeneration(
	fixture certificateFixture,
	generation serverGeneration,
) certificateFixture {
	result := fixture
	prefix := filepath.Join(fixture.dir, generation.name)
	result.clientSigningCert = filepath.Join(prefix, "client-signing.pem")
	result.clientSigningKey = filepath.Join(prefix, "client-signing.key")
	result.clientEncryptionCert = filepath.Join(prefix, "client-encryption.pem")
	result.clientEncryptionKey = filepath.Join(prefix, "client-encryption.key")
	result.serverCA = filepath.Join(prefix, "server-ca.pem")
	return result
}

func writeGenerationProfile(
	t *testing.T,
	fixture certificateFixture,
	generation serverGeneration,
	runtimeName, httpBind, grpcBind string,
) {
	t.Helper()
	profile := fixture.profile
	prefix := "/certs/" + runtimeName
	profile.Certificates.ServerSigningChainFile = prefix + "/server-signing.pem"
	profile.Certificates.ServerEncryptionChainFile = prefix + "/server-encryption.pem"
	profile.Certificates.ServerCAFile = prefix + "/server-ca.pem"
	profile.Certificates.ClientCAFile = prefix + "/client-ca.pem"
	profile.Certificates.SigningKey.Reference = prefix + "/server-signing.key"
	profile.Certificates.SigningKey.PublicKeySHA256 = generation.signingPublicKeySHA256
	profile.Certificates.EncryptionKey.Reference = prefix + "/server-encryption.key"
	profile.Certificates.EncryptionKey.PublicKeySHA256 = generation.encryptionPublicKeySHA256
	profile.Revocation.CRLFiles = []string{
		prefix + "/server-ca.crl",
		prefix + "/client-ca.crl",
	}
	profile.Revocation.GatewayCRLBundleFile = prefix + "/crl-bundle.pem"
	profile.Readiness.SigningChainFile = prefix + "/client-signing.pem"
	profile.Readiness.EncryptionChainFile = prefix + "/client-encryption.pem"
	profile.TrustDBIdentityManifestFile = prefix + "/trustdb-active-identities.json"
	profile.Network.GatewayHTTPBind = "0.0.0.0:" + httpBind
	profile.Network.GatewayGRPCBind = "0.0.0.0:" + grpcBind
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fixture.dir, generation.name, "active-profile.json")
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func prepareRuntimeInContainer(t *testing.T, container string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var output []byte
	var err error
	for {
		output, err = exec.Command("docker", prepareRuntimeCommand(container)...).CombinedOutput()
		if err == nil {
			return
		}
		if !strings.Contains(string(output), "invalid argument") ||
			time.Now().After(deadline) {
			t.Fatalf(
				"docker %s: %v\n%s",
				strings.Join(prepareRuntimeCommand(container), " "),
				err,
				output,
			)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func prepareRuntimeCommand(container string) []string {
	return []string{
		"exec",
		container,
		"/usr/local/bin/tlcp-gateway-prepare-runtime",
		"reload",
	}
}

func runtimeConfigurationDigest(t *testing.T, container string) string {
	t.Helper()
	return dockerOutput(
		t,
		"exec",
		container,
		"sha256sum",
		"/run/tlcp-gateway/nginx.conf",
	)
}

func testFileDigest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func rewriteGenerationGRPCUpstream(t *testing.T, path, upstream string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var profile tlcpprofile.Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatal(err)
	}
	profile.Network.TrustDBGRPCUpstream = upstream
	data, err = json.MarshalIndent(profile, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	replaceTestFile(t, path, append(data, '\n'))
}

func replaceTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		t.Fatal(err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o644); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, path); err != nil {
		t.Fatal(err)
	}
}

func copyTestFile(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func copyGeneration(t *testing.T, root, source, destination string) {
	t.Helper()
	destinationDir := filepath.Join(root, destination)
	if err := os.Mkdir(destinationDir, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, source))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("unexpected directory in generation: %s", entry.Name())
		}
		copyTestFile(
			t,
			filepath.Join(root, source, entry.Name()),
			filepath.Join(destinationDir, entry.Name()),
		)
	}
}

func activateGeneration(t *testing.T, root, generation string) {
	t.Helper()
	temporary := filepath.Join(root, ".active-"+strconv.FormatInt(time.Now().UnixNano(), 36))
	if err := os.Symlink(generation, temporary); err != nil {
		t.Fatalf("create staged active-generation link: %v", err)
	}
	if err := os.Rename(temporary, filepath.Join(root, "active")); err != nil {
		_ = os.Remove(temporary)
		t.Fatalf("atomically activate certificate generation: %v", err)
	}
}

func writeRevokedCRLBundle(t *testing.T, fixture certificateFixture) (string, string, string) {
	t.Helper()
	now := time.Now().UTC()
	serverCRL := createCRL(t, fixture.serverCAObject, fixture.serverCAKey, now, nil)
	clientCRL := createCRL(
		t,
		fixture.clientCAObject,
		fixture.clientCAKey,
		now,
		fixture.clientSerials,
	)
	path := filepath.Join(fixture.dir, "crl-bundle-revoked-client.pem")
	serverPath := filepath.Join(fixture.dir, "server-ca-revoked-client.crl")
	clientPath := filepath.Join(fixture.dir, "client-ca-revoked-client.crl")
	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: serverCRL})
	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: clientCRL})
	writePEMFile(t, serverPath, serverPEM)
	writePEMFile(t, clientPath, clientPEM)
	writePEMFile(
		t,
		path,
		append(append([]byte(nil), serverPEM...), clientPEM...),
	)
	return path, serverPath, clientPath
}

func createCA(
	t *testing.T,
	path string,
	serial int64,
	commonName string,
	now time.Time,
) (*smx509.Certificate, *sm2.PrivateKey) {
	t.Helper()
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &smx509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		SignatureAlgorithm:    smx509.SM2WithSM3,
		KeyUsage:              smx509.KeyUsageDigitalSignature | smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{byte(serial), 0x11, 0x22, 0x33},
	}
	der, err := smx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	writePEMFile(t, path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	certificate, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func createEndpoint(
	t *testing.T,
	certificatePath, keyPath string,
	ca *smx509.Certificate,
	caKey *sm2.PrivateKey,
	serial int64,
	commonName string,
	usage smx509.KeyUsage,
	extendedUsage smx509.ExtKeyUsage,
	now time.Time,
) (*smx509.Certificate, *sm2.PrivateKey) {
	t.Helper()
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &smx509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		DNSNames:              []string{commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		SignatureAlgorithm:    smx509.SM2WithSM3,
		KeyUsage:              usage,
		ExtKeyUsage:           []smx509.ExtKeyUsage{extendedUsage},
		BasicConstraintsValid: true,
		AuthorityKeyId:        ca.SubjectKeyId,
	}
	der, err := smx509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEMFile(t, certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := smx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEMFile(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	certificate, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func createCRL(
	t *testing.T,
	ca *smx509.Certificate,
	caKey *sm2.PrivateKey,
	now time.Time,
	revoked []*big.Int,
) []byte {
	t.Helper()
	entries := make([]smx509.RevocationListEntry, 0, len(revoked))
	for _, serial := range revoked {
		entries = append(entries, smx509.RevocationListEntry{
			SerialNumber:   new(big.Int).Set(serial),
			RevocationTime: now.Add(-time.Minute),
		})
	}
	der, err := smx509.CreateRevocationList(rand.Reader, &smx509.RevocationList{
		SignatureAlgorithm:        smx509.SM2WithSM3,
		RevokedCertificateEntries: entries,
		Number:                    big.NewInt(1),
		ThisUpdate:                now.Add(-time.Hour),
		NextUpdate:                now.Add(12 * time.Hour),
	}, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func appendCertificate(t *testing.T, path string, certificate *smx509.Certificate) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	})); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writePEMFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeE2ETrustDBIdentityManifest(t *testing.T, path string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := trustcrypto.MustNewEd25519Signer("e2e-proof-signer", privateKey)
	activePublicKey, err := signer.PublicKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	descriptor := keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindVerifier,
		Provider:      keydescriptor.ProviderPublic,
		CryptoSuite:   cryptosuite.INTLV1,
		KeyID:         "e2e-proof-signer",
		Algorithm:     cryptosuite.SignatureEd25519,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: cryptosuite.Ed25519PublicKeyEncoding,
			Bytes:    activePublicKey.Bytes,
		},
	}
	data, err := keydescriptor.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tlcpprofile.WriteTrustDBIdentityManifest(
		path,
		data,
		nil,
	); err != nil {
		t.Fatal(err)
	}
}

func publicKeySHA256(t *testing.T, certificate *smx509.Certificate) string {
	t.Helper()
	der, err := smx509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
