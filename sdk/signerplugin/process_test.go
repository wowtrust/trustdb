package signerplugin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	helperEnv      = "TRUSTDB_TEST_SIGNER_PLUGIN_HELPER"
	hostSecretEnv  = "TRUSTDB_TEST_SIGNER_PLUGIN_HOST_SECRET"
	helperModeEnv  = "TRUSTDB_TEST_SIGNER_PLUGIN_MODE"
	blockMarkerEnv = "TRUSTDB_TEST_SIGNER_PLUGIN_BLOCK_MARKER"
)

var helperPrivateKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))

type helperPlugin struct{}

func (helperPlugin) Info(context.Context) (Info, error) {
	if os.Getenv(hostSecretEnv) != "" {
		return Info{}, errors.New("host environment leaked into signer plugin")
	}
	return Info{
		PluginID:           "test-signer",
		ProviderKind:       ProviderRemote,
		Algorithms:         []AlgorithmCapability{intlCapability()},
		MaxConcurrentSigns: 2,
	}, nil
}

func (helperPlugin) Health(context.Context) error { return nil }

func (helperPlugin) PublicKey(context.Context, Key) ([]byte, error) {
	switch os.Getenv(helperModeEnv) {
	case "malformed-public-key":
		return bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize-1), nil
	case "internal-public-key-error":
		return nil, errors.New("provider internals unavailable")
	}
	return append([]byte(nil), helperPrivateKey.Public().(ed25519.PublicKey)...), nil
}

func (helperPlugin) Sign(ctx context.Context, _ Key, message []byte) ([]byte, error) {
	switch os.Getenv(helperModeEnv) {
	case "malformed-signature":
		return bytes.Repeat([]byte{0x42}, ed25519.SignatureSize-1), nil
	case "internal-sign-error":
		return nil, errors.New("provider internals unavailable")
	}
	if bytes.Equal(message, []byte("block")) {
		if marker := os.Getenv(blockMarkerEnv); marker != "" {
			if err := os.WriteFile(marker, []byte("started"), 0o600); err != nil {
				return nil, err
			}
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return ed25519.Sign(helperPrivateKey, message), nil
}

func TestProcessCloseInterruptsInflightRPC(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "sign-started")
	process, err := StartProcess(context.Background(), ProcessConfig{
		Command:         os.Args[0],
		Args:            []string{"-test.run=TestSignerPluginHelperProcess"},
		Env:             []string{helperEnv + "=1", blockMarkerEnv + "=" + marker},
		StartTimeout:    5 * time.Second,
		SignTimeout:     30 * time.Second,
		ShutdownTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("StartProcess() error = %v", err)
	}
	defer process.Close()

	signErr := make(chan error, 1)
	go func() {
		_, err := process.Sign(context.Background(), helperKey(), []byte("block"))
		signErr <- err
	}()
	waitForFile(t, marker, 5*time.Second)

	started := time.Now()
	if err := process.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-signErr:
		if err == nil {
			t.Fatal("in-flight Sign() unexpectedly succeeded after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close() did not interrupt the in-flight Sign RPC")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("Close() took too long to interrupt RPC: %v", elapsed)
	}
	select {
	case <-process.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("plugin process did not exit after Close")
	}
}

func TestProcessRecognizesRealRPCCancellation(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "sign-started")
	process, err := StartProcess(context.Background(), ProcessConfig{
		Command:      os.Args[0],
		Args:         []string{"-test.run=TestSignerPluginHelperProcess"},
		Env:          []string{helperEnv + "=1", blockMarkerEnv + "=" + marker},
		StartTimeout: 5 * time.Second,
		SignTimeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("StartProcess() error = %v", err)
	}
	defer process.Close()

	ctx, cancel := context.WithCancel(context.Background())
	signErr := make(chan error, 1)
	go func() {
		_, err := process.Sign(ctx, helperKey(), []byte("block"))
		signErr <- err
	}()
	waitForFile(t, marker, 5*time.Second)
	cancel()

	select {
	case err := <-signErr:
		if !IsRPCCanceled(err) {
			t.Fatalf("real canceled Sign() error = %v, want gRPC Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled Sign RPC did not return")
	}
}

func TestMalformedPluginOutputIsPermanentProtocolFailureOverRPC(t *testing.T) {
	tests := []struct {
		name string
		mode string
		call func(*Process) error
	}{
		{
			name: "public key",
			mode: "malformed-public-key",
			call: func(process *Process) error {
				_, err := process.GetPublicKey(context.Background(), helperKey())
				return err
			},
		},
		{
			name: "signature",
			mode: "malformed-signature",
			call: func(process *Process) error {
				_, err := process.Sign(context.Background(), helperKey(), []byte("message"))
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			process, err := StartProcess(context.Background(), ProcessConfig{
				Command:      os.Args[0],
				Args:         []string{"-test.run=TestSignerPluginHelperProcess"},
				Env:          []string{helperEnv + "=1", helperModeEnv + "=" + test.mode},
				StartTimeout: 5 * time.Second,
			})
			if err != nil {
				t.Fatalf("StartProcess() error = %v", err)
			}
			defer process.Close()

			err = test.call(process)
			if !errors.Is(err, ErrProtocolViolation) {
				t.Fatalf("operation error = %v, want ErrProtocolViolation", err)
			}
			if !IsRPCProtocolViolation(err) || !IsPermanentRPC(err) || ShouldRestartProcess(err) {
				t.Fatalf("protocol violation classification is inconsistent: %v", err)
			}
		})
	}
}

type malformedResponseCodec struct {
	cborCodec
	response []byte
}

func (codec malformedResponseCodec) Marshal(value any) ([]byte, error) {
	if _, ok := value.(*SignResponse); ok {
		return append([]byte(nil), codec.response...), nil
	}
	return codec.cborCodec.Marshal(value)
}

func TestMalformedCBORResponseIsProtocolViolationOverRPC(t *testing.T) {
	validResponse := SignResponse{
		Binding:   helperKey().Binding,
		Signature: bytes.Repeat([]byte{0x42}, ed25519.SignatureSize),
	}
	canonical := mustEncode(t, validResponse)
	nonCanonical := []byte{0xa2}
	nonCanonical = append(nonCanonical, mustEncode(t, "signature")...)
	nonCanonical = append(nonCanonical, mustEncode(t, validResponse.Signature)...)
	nonCanonical = append(nonCanonical, mustEncode(t, "binding")...)
	nonCanonical = append(nonCanonical, mustEncode(t, validResponse.Binding)...)
	if bytes.Equal(nonCanonical, canonical) {
		t.Fatal("non-canonical response fixture unexpectedly uses canonical map order")
	}
	malformedResponses := map[string][]byte{
		"non-canonical": nonCanonical,
		"unknown field": mustEncode(t, map[string]any{
			"binding":    validResponse.Binding,
			"signature":  validResponse.Signature,
			"unexpected": true,
		}),
		"invalid CBOR":   {0xff},
		"trailing bytes": append(canonical, 0x00),
	}
	for name, malformed := range malformedResponses {
		t.Run(name, func(t *testing.T) {
			testMalformedCBORResponse(t, malformed)
		})
	}
}

func testMalformedCBORResponse(t *testing.T, malformed []byte) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.ForceServerCodec(malformedResponseCodec{response: malformed}))
	RegisterRPCServer(server, newPluginServer(helperPlugin{}, helperInfoResponse()))
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(ctx, listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(Codec())),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	_, err = NewRPCClient(connection).Sign(ctx, &SignRequest{Key: helperKey(), Message: []byte("message")})
	if !errors.Is(err, ErrProtocolViolation) || !IsRPCProtocolViolation(err) || !IsPermanentRPC(err) || ShouldRestartProcess(err) {
		t.Fatalf("malformed CBOR response classification = %v", err)
	}
}

func TestProviderInternalErrorIsNotProtocolViolationOverRPC(t *testing.T) {
	process, err := StartProcess(context.Background(), ProcessConfig{
		Command:      os.Args[0],
		Args:         []string{"-test.run=TestSignerPluginHelperProcess"},
		Env:          []string{helperEnv + "=1", helperModeEnv + "=internal-sign-error"},
		StartTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("StartProcess() error = %v", err)
	}
	defer process.Close()

	_, err = process.Sign(context.Background(), helperKey(), []byte("message"))
	if errors.Is(err, ErrProtocolViolation) {
		t.Fatalf("provider internal error was classified as a protocol violation: %v", err)
	}
	if status.Code(err) != codes.Internal || !ShouldRestartProcess(err) {
		t.Fatalf("provider internal error classification = %v", err)
	}
}

func TestSignerPluginHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		return
	}
	if err := Serve(context.Background(), helperPlugin{}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(0)
}

func TestProcessPublicKeySignDeadlineAndNoAmbientEnvironment(t *testing.T) {
	t.Setenv(hostSecretEnv, "must-not-be-inherited")
	process, err := StartProcess(context.Background(), ProcessConfig{
		Command:                os.Args[0],
		Args:                   []string{"-test.run=TestSignerPluginHelperProcess"},
		Env:                    []string{helperEnv + "=1"},
		StartTimeout:           5 * time.Second,
		HealthTimeout:          time.Second,
		PublicKeyTimeout:       time.Second,
		SignTimeout:            time.Second,
		HostMaxConcurrentSigns: 1,
	})
	if err != nil {
		t.Fatalf("StartProcess() error = %v", err)
	}
	defer process.Close()

	if info := process.Info(); info.PluginID != "test-signer" || info.ProviderKind != ProviderRemote {
		t.Fatalf("Info() = %+v", info)
	}
	if got := cap(process.signSlots); got != 1 {
		t.Fatalf("effective sign concurrency = %d, want 1", got)
	}
	if err := process.Health(context.Background()); err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	key := helperKey()
	publicKey, err := process.GetPublicKey(context.Background(), key)
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}
	wantPublicKey := helperPrivateKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(publicKey, wantPublicKey) {
		t.Fatal("GetPublicKey() returned a different key")
	}
	message := []byte("final host-framed signing input")
	signature, err := process.Sign(context.Background(), key, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("Sign() returned an invalid signature")
	}

	process.signTimeout = 50 * time.Millisecond
	started := time.Now()
	_, err = process.Sign(context.Background(), key, []byte("block"))
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("blocking Sign() error = %v, want DeadlineExceeded", err)
	}
	if !IsRPCDeadlineExceeded(err) {
		t.Fatalf("real blocking Sign() deadline was not recognized: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("blocking Sign() exceeded deadline by too much: %v", elapsed)
	}

	if err := process.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-process.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("plugin process did not exit after Close")
	}
	if _, exited := process.ExitError(); !exited {
		t.Fatal("ExitError() did not report exited process")
	}
}

func TestProcessSignCapacityDeadlineIsLocalAndLeavesProcessUsable(t *testing.T) {
	process, err := StartProcess(context.Background(), ProcessConfig{
		Command:                os.Args[0],
		Args:                   []string{"-test.run=TestSignerPluginHelperProcess"},
		Env:                    []string{helperEnv + "=1"},
		StartTimeout:           5 * time.Second,
		HealthTimeout:          time.Second,
		PublicKeyTimeout:       time.Second,
		SignTimeout:            time.Second,
		HostMaxConcurrentSigns: 1,
	})
	if err != nil {
		t.Fatalf("StartProcess() error = %v", err)
	}
	defer process.Close()

	process.signSlots <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = process.Sign(ctx, helperKey(), []byte("queued"))
	<-process.signSlots
	if !errors.Is(err, ErrSignCapacityWait) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("capacity wait error = %v", err)
	}
	if IsRPCDeadlineExceeded(err) || ShouldRestartProcess(err) {
		t.Fatalf("local capacity wait was classified as an RPC/process failure: %v", err)
	}
	select {
	case <-process.Done():
		t.Fatal("local capacity timeout terminated the plugin process")
	default:
	}
	if _, err := process.Sign(context.Background(), helperKey(), []byte("still usable")); err != nil {
		t.Fatalf("Sign() after capacity timeout error = %v", err)
	}
}

func TestRPCRejectsMissingMagicCookie(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	info := helperInfoResponse()
	server := grpc.NewServer(
		grpc.ForceServerCodec(Codec()),
		grpc.UnaryInterceptor(cookieInterceptor("expected-cookie")),
	)
	RegisterRPCServer(server, newPluginServer(helperPlugin{}, info))
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(ctx, listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(Codec())),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, err = NewRPCClient(connection).GetInfo(ctx, &GetInfoRequest{ProtocolVersion: ProtocolVersion})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("GetInfo() error = %v, want Unauthenticated", err)
	}
}

type concurrentPlugin struct {
	helperPlugin
	current atomic.Int32
	maximum atomic.Int32
}

func (plugin *concurrentPlugin) Sign(context.Context, Key, []byte) ([]byte, error) {
	current := plugin.current.Add(1)
	defer plugin.current.Add(-1)
	for {
		maximum := plugin.maximum.Load()
		if current <= maximum || plugin.maximum.CompareAndSwap(maximum, current) {
			break
		}
	}
	time.Sleep(20 * time.Millisecond)
	return bytes.Repeat([]byte{0x5a}, ed25519.SignatureSize), nil
}

func TestServerEnforcesAdvertisedSignConcurrency(t *testing.T) {
	plugin := &concurrentPlugin{}
	server := newPluginServer(plugin, helperInfoResponse())
	const calls = 12
	errorsCh := make(chan error, calls)
	var wait sync.WaitGroup
	for range calls {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := server.Sign(context.Background(), &SignRequest{Key: helperKey(), Message: []byte("message")})
			errorsCh <- err
		}()
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
	}
	if maximum := plugin.maximum.Load(); maximum == 0 || maximum > 2 {
		t.Fatalf("maximum concurrent Sign calls = %d, want 1..2", maximum)
	}
}

type failingPlugin struct {
	helperPlugin
	err error
}

func (plugin failingPlugin) Sign(context.Context, Key, []byte) ([]byte, error) {
	return nil, plugin.err
}

func TestServerRedactsArbitraryErrorsAndMapsSafeErrors(t *testing.T) {
	request := &SignRequest{Key: helperKey(), Message: []byte("message")}
	server := newPluginServer(failingPlugin{err: errors.New("pin=1234 handle=secret")}, helperInfoResponse())
	_, err := server.Sign(context.Background(), request)
	if status.Code(err) != codes.Internal || strings.Contains(err.Error(), "1234") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("arbitrary provider error was not redacted: %v", err)
	}

	server = newPluginServer(failingPlugin{err: NewProviderError(ErrorUnavailable, "HSM session unavailable")}, helperInfoResponse())
	_, err = server.Sign(context.Background(), request)
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "HSM session unavailable") {
		t.Fatalf("safe provider error mapping = %v", err)
	}

	err = rpcError(NewProviderError(ErrorUnavailable, string([]byte{0xff})))
	if got := status.Convert(err).Message(); got != "signer provider is unavailable" {
		t.Fatalf("invalid UTF-8 safe message was not replaced: %q", got)
	}

	err = rpcError(fmt.Errorf("credential leaked: %w", context.Canceled))
	if status.Code(err) != codes.Canceled || strings.Contains(err.Error(), "credential") {
		t.Fatalf("wrapped cancellation was not safely mapped: %v", err)
	}
}

func TestBuildProcessEnvIsExplicitAndRejectsReservedVariables(t *testing.T) {
	t.Setenv("SIGNER_PLUGIN_ALLOWED_ENV", "allowed")
	t.Setenv(hostSecretEnv, "secret")
	environment, err := buildProcessEnv([]string{"SIGNER_PLUGIN_ALLOWED_ENV"}, []string{"EXPLICIT=value"}, "cookie")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(environment, "\n")
	if !strings.Contains(joined, "SIGNER_PLUGIN_ALLOWED_ENV=allowed") || !strings.Contains(joined, "EXPLICIT=value") {
		t.Fatalf("explicit environment is incomplete: %v", environment)
	}
	if strings.Contains(joined, hostSecretEnv) || strings.Contains(joined, "secret") {
		t.Fatalf("ambient environment leaked: %v", environment)
	}
	if _, err := buildProcessEnv(nil, []string{EnvMagicCookie + "=override"}, "cookie"); err == nil {
		t.Fatal("buildProcessEnv() accepted reserved cookie override")
	}
	if _, err := buildProcessEnv(nil, []string{"trustdb_signer_plugin_magic_cookie=override"}, "cookie"); err == nil {
		t.Fatal("buildProcessEnv() accepted case-variant reserved cookie override")
	}
	if _, err := buildProcessEnv(nil, []string{"PLUGIN_PATH=one", "plugin_path=two"}, "cookie"); err == nil {
		t.Fatal("buildProcessEnv() accepted case-colliding environment names")
	}
}

func TestRPCErrorClassificationDoesNotTreatLocalErrorsAsTransportFailures(t *testing.T) {
	localErr := errors.New("local validation failure")
	if ShouldRestartProcess(localErr) || IsPermanentRPC(localErr) || IsRPCDeadlineExceeded(localErr) || IsRPCCanceled(localErr) {
		t.Fatal("local error was classified as a gRPC failure")
	}
	if !ShouldRestartProcess(status.Error(codes.Unavailable, "unavailable")) {
		t.Fatal("Unavailable was not classified as restartable")
	}
	if !IsPermanentRPC(status.Error(codes.InvalidArgument, "invalid")) {
		t.Fatal("InvalidArgument was not classified as permanent")
	}
	if !IsRPCDeadlineExceeded(status.Error(codes.DeadlineExceeded, "deadline")) {
		t.Fatal("DeadlineExceeded was not recognized")
	}
	if !IsRPCCanceled(status.Error(codes.Canceled, "canceled")) {
		t.Fatal("Canceled was not recognized")
	}
	protocolErr := status.Error(codes.DataLoss, "malformed output")
	if !IsRPCProtocolViolation(protocolErr) || !IsPermanentRPC(protocolErr) || ShouldRestartProcess(protocolErr) {
		t.Fatal("DataLoss was not classified as a permanent protocol violation")
	}
}

func TestDecodeHandshakeIsStrict(t *testing.T) {
	valid := `{"protocol_version":"` + ProtocolVersion + `","address":"127.0.0.1:1234","magic_cookie":"cookie"}` + "\n"
	startup, err := decodeHandshake([]byte(valid))
	if err != nil {
		t.Fatalf("valid handshake rejected: %v", err)
	}
	if startup.ProtocolVersion != ProtocolVersion || startup.Address != "127.0.0.1:1234" || startup.MagicCookie != "cookie" {
		t.Fatalf("decoded handshake = %+v", startup)
	}

	invalid := map[string]string{
		"non-object":        `[]`,
		"missing field":     `{"protocol_version":"` + ProtocolVersion + `","address":"127.0.0.1:1"}`,
		"unknown field":     `{"protocol_version":"` + ProtocolVersion + `","address":"127.0.0.1:1","magic_cookie":"cookie","extra":"x"}`,
		"case variant":      `{"Protocol_Version":"` + ProtocolVersion + `","address":"127.0.0.1:1","magic_cookie":"cookie"}`,
		"duplicate field":   `{"protocol_version":"` + ProtocolVersion + `","protocol_version":"other","address":"127.0.0.1:1","magic_cookie":"cookie"}`,
		"non-string value":  `{"protocol_version":1,"address":"127.0.0.1:1","magic_cookie":"cookie"}`,
		"invalid UTF-8":     string(append([]byte(`{"protocol_version":"`), append([]byte{0xff}, []byte(`","address":"127.0.0.1:1","magic_cookie":"cookie"}`)...)...)),
		"trailing JSON":     valid + `{}`,
		"trailing non-JSON": valid + `garbage`,
	}
	for name, data := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeHandshake([]byte(data)); !errors.Is(err, ErrProtocolViolation) {
				t.Fatalf("decodeHandshake() error = %v, want ErrProtocolViolation", err)
			}
		})
	}
}

func TestReadProcessHandshakeRejectsOversizeAndMissingNewline(t *testing.T) {
	validWithoutNewline := `{"protocol_version":"` + ProtocolVersion + `","address":"127.0.0.1:1","magic_cookie":"cookie"}`
	for name, data := range map[string]string{
		"oversize":        strings.Repeat("x", maxHandshakeBytes) + "\n",
		"missing newline": validWithoutNewline,
	} {
		t.Run(name, func(t *testing.T) {
			results := make(chan handshakeResult, 1)
			readProcessHandshake(strings.NewReader(data), results, nil)
			if result := <-results; !errors.Is(result.err, ErrProtocolViolation) {
				t.Fatalf("readProcessHandshake() error = %v, want ErrProtocolViolation", result.err)
			}
		})
	}
}

func TestValidateHandshakeWrapsProtocolViolations(t *testing.T) {
	valid := handshake{ProtocolVersion: ProtocolVersion, Address: "127.0.0.1:1234", MagicCookie: "cookie"}
	if err := validateHandshake(valid, "cookie"); err != nil {
		t.Fatalf("valid handshake rejected: %v", err)
	}
	for name, startup := range map[string]handshake{
		"protocol":     {ProtocolVersion: "future", Address: valid.Address, MagicCookie: valid.MagicCookie},
		"cookie":       {ProtocolVersion: valid.ProtocolVersion, Address: valid.Address, MagicCookie: "wrong"},
		"address":      {ProtocolVersion: valid.ProtocolVersion, Address: "missing-port", MagicCookie: valid.MagicCookie},
		"non-loopback": {ProtocolVersion: valid.ProtocolVersion, Address: "192.0.2.1:1234", MagicCookie: valid.MagicCookie},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateHandshake(startup, "cookie"); !errors.Is(err, ErrProtocolViolation) {
				t.Fatalf("validateHandshake() error = %v, want ErrProtocolViolation", err)
			}
		})
	}
}

func TestValidateStartupInfoClassifiesDeterministicFailures(t *testing.T) {
	valid := helperInfoResponse()
	if _, err := validateStartupInfo(&valid, nil); err != nil {
		t.Fatalf("valid startup info rejected: %v", err)
	}
	invalid := cloneInfoResponse(valid)
	invalid.ProtocolVersion = "future"
	for name, test := range map[string]struct {
		info   *GetInfoResponse
		rpcErr error
	}{
		"empty":           {},
		"invalid":         {info: &invalid},
		"invalid request": {rpcErr: status.Error(codes.InvalidArgument, "bad request")},
		"data loss":       {rpcErr: status.Error(codes.DataLoss, "bad response")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateStartupInfo(test.info, test.rpcErr); !errors.Is(err, ErrProtocolViolation) {
				t.Fatalf("validateStartupInfo() error = %v, want ErrProtocolViolation", err)
			}
		})
	}
	for _, code := range []codes.Code{codes.Unavailable, codes.Internal, codes.DeadlineExceeded, codes.Canceled} {
		_, err := validateStartupInfo(nil, status.Error(code, "transient"))
		if errors.Is(err, ErrProtocolViolation) {
			t.Fatalf("%s was classified as a protocol violation: %v", code, err)
		}
	}
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func intlCapability() AlgorithmCapability {
	return AlgorithmCapability{
		CryptoSuite:       SuiteINTLV1,
		Algorithm:         AlgorithmEd25519,
		PublicKeyEncoding: Ed25519PublicKeyEncoding,
		SignatureEncoding: Ed25519SignatureEncoding,
	}
}

func helperInfoResponse() GetInfoResponse {
	return Info{
		PluginID:           "test-signer",
		ProviderKind:       ProviderRemote,
		Algorithms:         []AlgorithmCapability{intlCapability()},
		MaxConcurrentSigns: 2,
	}.response()
}

func helperKey() Key {
	return Key{
		Binding: Binding{
			ProtocolVersion:   ProtocolVersion,
			PluginID:          "test-signer",
			ProviderKind:      ProviderRemote,
			CryptoSuite:       SuiteINTLV1,
			Algorithm:         AlgorithmEd25519,
			PublicKeyEncoding: Ed25519PublicKeyEncoding,
			SignatureEncoding: Ed25519SignatureEncoding,
			KeyID:             "key-a",
		},
		Reference: KeyReference{Remote: &RemoteKeyReference{
			Endpoint:      "https://kms.example.test",
			Handle:        "key-a",
			CredentialRef: "env:KMS_TOKEN",
		}},
	}
}
