package signerplugin

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	DefaultStartTimeout     = 10 * time.Second
	DefaultHealthTimeout    = 5 * time.Second
	DefaultPublicKeyTimeout = 10 * time.Second
	DefaultSignTimeout      = 30 * time.Second
	DefaultShutdownTimeout  = 2 * time.Second
	maxHandshakeBytes       = 16 << 10
)

var (
	ErrProtocolViolation = errors.New("signer plugin protocol violation")
	// ErrSignCapacityWait marks a deadline or cancellation that occurred
	// before an RPC was sent while waiting for a local concurrency slot.
	// Supervisors must not invalidate an otherwise healthy child for it.
	ErrSignCapacityWait = errors.New("signer plugin sign capacity wait")
)

type ProcessConfig struct {
	Command string
	Args    []string
	// InheritEnv names individual variables to copy from the host.  The
	// subprocess inherits no ambient environment by default.
	InheritEnv []string
	// Env contains explicit NAME=VALUE entries.  Reserved protocol/cookie
	// variables cannot be supplied through either environment option.
	Env                    []string
	StartTimeout           time.Duration
	HealthTimeout          time.Duration
	PublicKeyTimeout       time.Duration
	SignTimeout            time.Duration
	ShutdownTimeout        time.Duration
	HostMaxConcurrentSigns uint32
	Stderr                 io.Writer
}

// Process owns one signer-plugin subprocess and its authenticated loopback
// gRPC connection.  It does not automatically retry Sign: a timeout can be
// ambiguous for randomized or externally audited signatures, so callers must
// make an explicit retry decision.
type Process struct {
	cmd    *exec.Cmd
	conn   *grpc.ClientConn
	client RPCClient
	info   GetInfoResponse

	healthTimeout    time.Duration
	publicKeyTimeout time.Duration
	signTimeout      time.Duration
	shutdownTimeout  time.Duration
	signSlots        chan struct{}

	waitDone chan struct{}
	waitMu   sync.RWMutex
	waitErr  error

	closeOnce sync.Once
}

func StartProcess(ctx context.Context, config ProcessConfig) (*Process, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(config.Command) == "" {
		return nil, errors.New("signer plugin command is required")
	}
	applyProcessDefaults(&config)
	if config.HostMaxConcurrentSigns > maxConcurrentSigns {
		return nil, fmt.Errorf("signer plugin host concurrency cap must not exceed %d", maxConcurrentSigns)
	}
	commandPath, err := exec.LookPath(config.Command)
	if err != nil {
		return nil, fmt.Errorf("resolve signer plugin command: %w", err)
	}
	cookie, err := randomCookie()
	if err != nil {
		return nil, err
	}
	processEnv, err := buildProcessEnv(config.InheritEnv, config.Env, cookie)
	if err != nil {
		return nil, err
	}
	command := exec.Command(commandPath, config.Args...)
	command.Env = processEnv
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("open signer plugin stdout: %w", err)
	}
	command.Stderr = config.Stderr
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start signer plugin: %w", err)
	}
	process := &Process{
		cmd:              command,
		healthTimeout:    config.HealthTimeout,
		publicKeyTimeout: config.PublicKeyTimeout,
		signTimeout:      config.SignTimeout,
		shutdownTimeout:  config.ShutdownTimeout,
		waitDone:         make(chan struct{}),
	}
	go func() {
		err := command.Wait()
		process.waitMu.Lock()
		process.waitErr = err
		process.waitMu.Unlock()
		close(process.waitDone)
	}()

	startCtx, cancel := context.WithTimeout(ctx, config.StartTimeout)
	defer cancel()
	handshakeCh := make(chan handshakeResult, 1)
	go readProcessHandshake(stdout, handshakeCh, config.Stderr)
	var startup handshake
	select {
	case <-startCtx.Done():
		process.killAndWait()
		return nil, fmt.Errorf("signer plugin handshake: %w", startCtx.Err())
	case <-process.waitDone:
		if waitErr := process.exitError(); waitErr != nil {
			return nil, fmt.Errorf("signer plugin exited before handshake: %w", waitErr)
		}
		return nil, errors.New("signer plugin exited before handshake")
	case result := <-handshakeCh:
		if result.err != nil {
			process.killAndWait()
			return nil, result.err
		}
		startup = result.handshake
	}
	if err := validateHandshake(startup, cookie); err != nil {
		process.killAndWait()
		return nil, err
	}

	connection, err := grpc.DialContext(startCtx, startup.Address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(cookieCredentials{cookie: cookie}),
		grpc.WithDefaultCallOptions(
			grpc.ForceCodec(Codec()),
			grpc.MaxCallRecvMsgSize(MaxMessageBytes),
			grpc.MaxCallSendMsgSize(MaxMessageBytes),
		),
		grpc.WithBlock(),
	)
	if err != nil {
		process.killAndWait()
		return nil, fmt.Errorf("connect to signer plugin: %w", err)
	}
	process.conn = connection
	process.client = NewRPCClient(connection)
	info, err := process.client.GetInfo(startCtx, &GetInfoRequest{ProtocolVersion: ProtocolVersion})
	validatedInfo, err := validateStartupInfo(info, err)
	if err != nil {
		_ = process.Close()
		return nil, err
	}
	process.info = cloneInfoResponse(validatedInfo)
	concurrency := validatedInfo.MaxConcurrentSigns
	if config.HostMaxConcurrentSigns > 0 && config.HostMaxConcurrentSigns < concurrency {
		concurrency = config.HostMaxConcurrentSigns
	}
	process.signSlots = make(chan struct{}, concurrency)
	if err := process.Health(startCtx); err != nil {
		_ = process.Close()
		return nil, fmt.Errorf("signer plugin startup health: %w", err)
	}
	return process, nil
}

func buildProcessEnv(inheritNames, explicit []string, cookie string) ([]string, error) {
	values := make(map[string]string, len(inheritNames)+len(explicit)+2)
	seenNames := make(map[string]struct{}, len(inheritNames)+len(explicit)+2)
	for _, name := range inheritNames {
		if err := validateEnvironmentName(name); err != nil {
			return nil, err
		}
		if reservedEnvironmentName(name) {
			return nil, fmt.Errorf("signer plugin environment variable %q is reserved", name)
		}
		normalizedName := strings.ToUpper(name)
		if _, exists := seenNames[normalizedName]; exists {
			return nil, fmt.Errorf("signer plugin environment variable %q is duplicated", name)
		}
		value, ok := os.LookupEnv(name)
		if !ok {
			return nil, fmt.Errorf("signer plugin inherited environment variable %q is not set", name)
		}
		if strings.IndexByte(value, 0) >= 0 {
			return nil, fmt.Errorf("signer plugin environment variable %q contains NUL", name)
		}
		seenNames[normalizedName] = struct{}{}
		values[name] = value
	}
	for _, entry := range explicit {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, errors.New("signer plugin explicit environment entries must use NAME=VALUE")
		}
		if err := validateEnvironmentName(name); err != nil {
			return nil, err
		}
		if reservedEnvironmentName(name) {
			return nil, fmt.Errorf("signer plugin environment variable %q is reserved", name)
		}
		if strings.IndexByte(value, 0) >= 0 {
			return nil, fmt.Errorf("signer plugin environment variable %q contains NUL", name)
		}
		normalizedName := strings.ToUpper(name)
		if _, exists := seenNames[normalizedName]; exists {
			return nil, fmt.Errorf("signer plugin environment variable %q is duplicated", name)
		}
		seenNames[normalizedName] = struct{}{}
		values[name] = value
	}
	values[EnvProtocol] = ProtocolVersion
	values[EnvMagicCookie] = cookie
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, name+"="+values[name])
	}
	return out, nil
}

func validateEnvironmentName(name string) error {
	if name == "" || strings.ContainsAny(name, "=\x00") {
		return fmt.Errorf("signer plugin environment variable name %q is invalid", name)
	}
	for index, character := range name {
		valid := character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character == '_' ||
			index > 0 && character >= '0' && character <= '9'
		if !valid {
			return fmt.Errorf("signer plugin environment variable name %q is invalid", name)
		}
	}
	return nil
}

func reservedEnvironmentName(name string) bool {
	return strings.HasPrefix(strings.ToUpper(name), "TRUSTDB_SIGNER_PLUGIN_")
}

func applyProcessDefaults(config *ProcessConfig) {
	if config.StartTimeout <= 0 {
		config.StartTimeout = DefaultStartTimeout
	}
	if config.HealthTimeout <= 0 {
		config.HealthTimeout = DefaultHealthTimeout
	}
	if config.PublicKeyTimeout <= 0 {
		config.PublicKeyTimeout = DefaultPublicKeyTimeout
	}
	if config.SignTimeout <= 0 {
		config.SignTimeout = DefaultSignTimeout
	}
	if config.ShutdownTimeout <= 0 {
		config.ShutdownTimeout = DefaultShutdownTimeout
	}
	if config.Stderr == nil {
		config.Stderr = os.Stderr
	}
}

type cookieCredentials struct{ cookie string }

func (credentials cookieCredentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{CookieMetadata: credentials.cookie}, nil
}

func (cookieCredentials) RequireTransportSecurity() bool { return false }

func (p *Process) Info() GetInfoResponse {
	if p == nil {
		return GetInfoResponse{}
	}
	return cloneInfoResponse(p.info)
}

// Done closes when the child process exits.  ExitError can be read after Done
// closes without consuming lifecycle state needed by Close.
func (p *Process) Done() <-chan struct{} {
	if p == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return p.waitDone
}

func (p *Process) ExitError() (error, bool) {
	if p == nil {
		return nil, true
	}
	select {
	case <-p.waitDone:
		return p.exitError(), true
	default:
		return nil, false
	}
}

func (p *Process) Health(ctx context.Context) error {
	if p == nil || p.client == nil {
		return errors.New("signer plugin process is not connected")
	}
	callCtx, cancel := callContext(ctx, p.healthTimeout)
	defer cancel()
	response, err := p.client.Health(callCtx, &HealthRequest{
		ProtocolVersion: ProtocolVersion,
		PluginID:        p.info.PluginID,
	})
	if err != nil {
		return classifyRPCResult("Health", err)
	}
	if response == nil {
		return fmt.Errorf("%w: Health returned an empty response", ErrProtocolViolation)
	}
	if err := ValidateHealthResponse(*response, p.info); err != nil {
		return fmt.Errorf("%w: invalid Health response", ErrProtocolViolation)
	}
	return nil
}

func (p *Process) GetPublicKey(ctx context.Context, key Key) ([]byte, error) {
	if p == nil || p.client == nil {
		return nil, errors.New("signer plugin process is not connected")
	}
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	if err := ValidateBindingForInfo(key.Binding, p.info); err != nil {
		return nil, err
	}
	callCtx, cancel := callContext(ctx, p.publicKeyTimeout)
	defer cancel()
	response, err := p.client.GetPublicKey(callCtx, &GetPublicKeyRequest{Key: cloneKey(key)})
	if err != nil {
		return nil, classifyRPCResult("GetPublicKey", err)
	}
	if response == nil {
		return nil, fmt.Errorf("%w: GetPublicKey returned an empty response", ErrProtocolViolation)
	}
	if !sameBinding(response.Binding, key.Binding) {
		return nil, fmt.Errorf("%w: GetPublicKey binding mismatch", ErrProtocolViolation)
	}
	if err := validatePublicKey(key.Binding, response.PublicKey); err != nil {
		return nil, fmt.Errorf("%w: invalid GetPublicKey output", ErrProtocolViolation)
	}
	return append([]byte(nil), response.PublicKey...), nil
}

func (p *Process) Sign(ctx context.Context, key Key, message []byte) ([]byte, error) {
	if p == nil || p.client == nil {
		return nil, errors.New("signer plugin process is not connected")
	}
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	if err := ValidateBindingForInfo(key.Binding, p.info); err != nil {
		return nil, err
	}
	if len(message) > MaxSignInputBytes {
		return nil, errors.New("signer plugin signing input is too large")
	}
	callCtx, cancel := callContext(ctx, p.signTimeout)
	defer cancel()
	select {
	case p.signSlots <- struct{}{}:
		defer func() { <-p.signSlots }()
	case <-callCtx.Done():
		return nil, fmt.Errorf("%w: %w", ErrSignCapacityWait, callCtx.Err())
	}
	response, err := p.client.Sign(callCtx, &SignRequest{
		Key:     cloneKey(key),
		Message: append([]byte(nil), message...),
	})
	if err != nil {
		return nil, classifyRPCResult("Sign", err)
	}
	if response == nil {
		return nil, fmt.Errorf("%w: Sign returned an empty response", ErrProtocolViolation)
	}
	if !sameBinding(response.Binding, key.Binding) {
		return nil, fmt.Errorf("%w: Sign binding mismatch", ErrProtocolViolation)
	}
	if err := validateSignature(key.Binding, response.Signature); err != nil {
		return nil, fmt.Errorf("%w: invalid Sign output", ErrProtocolViolation)
	}
	return append([]byte(nil), response.Signature...), nil
}

func callContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, timeout)
}

func (p *Process) Close() error {
	if p == nil {
		return nil
	}
	var closeErr error
	p.closeOnce.Do(func() {
		if p.conn != nil {
			closeErr = p.conn.Close()
		}
		if p.cmd == nil || p.cmd.Process == nil {
			return
		}
		select {
		case <-p.waitDone:
			return
		default:
		}
		if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
			p.killAndWait()
			return
		}
		timer := time.NewTimer(p.shutdownTimeout)
		defer timer.Stop()
		select {
		case <-p.waitDone:
		case <-timer.C:
			p.killAndWait()
		}
	})
	return closeErr
}

func (p *Process) killAndWait() {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	select {
	case <-p.waitDone:
		return
	default:
	}
	_ = p.cmd.Process.Kill()
	<-p.waitDone
}

func (p *Process) exitError() error {
	p.waitMu.RLock()
	defer p.waitMu.RUnlock()
	return p.waitErr
}

// IsPermanentRPC reports protocol, provider, and request failures that cannot
// be fixed by restarting the same subprocess with the same configuration.
func IsPermanentRPC(err error) bool {
	if errors.Is(err, ErrProtocolViolation) {
		return true
	}
	rpcStatus, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch rpcStatus.Code() {
	case codes.InvalidArgument, codes.NotFound, codes.FailedPrecondition,
		codes.PermissionDenied, codes.Unauthenticated, codes.Unimplemented,
		codes.DataLoss:
		return true
	default:
		return false
	}
}

// ShouldRestartProcess reports transport/server failures for which a
// supervisor should invalidate the child.  The failed Sign must still be
// returned to its caller and must not be automatically replayed.
func ShouldRestartProcess(err error) bool {
	rpcStatus, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch rpcStatus.Code() {
	case codes.Unavailable, codes.Internal, codes.Unknown:
		return true
	default:
		return false
	}
}

// IsRPCDeadlineExceeded reports a gRPC deadline failure without classifying
// arbitrary local errors as transport failures.
func IsRPCDeadlineExceeded(err error) bool {
	rpcStatus, ok := status.FromError(err)
	return ok && rpcStatus.Code() == codes.DeadlineExceeded
}

// IsRPCCanceled reports a gRPC cancellation without classifying arbitrary
// local errors as RPC failures.
func IsRPCCanceled(err error) bool {
	rpcStatus, ok := status.FromError(err)
	return ok && rpcStatus.Code() == codes.Canceled
}

// IsRPCProtocolViolation reports the wire status reserved for malformed
// plugin output.  Provider failures never map to this status.
func IsRPCProtocolViolation(err error) bool {
	if errors.Is(err, ErrProtocolViolation) {
		return true
	}
	rpcStatus, ok := status.FromError(err)
	return ok && rpcStatus.Code() == codes.DataLoss
}

func classifyRPCResult(method string, err error) error {
	if errors.Is(err, ErrProtocolViolation) {
		return err
	}
	if !IsRPCProtocolViolation(err) {
		return err
	}
	return fmt.Errorf("%w: %s returned malformed output", ErrProtocolViolation, method)
}

func validateStartupInfo(info *GetInfoResponse, rpcErr error) (GetInfoResponse, error) {
	if rpcErr != nil {
		if errors.Is(rpcErr, ErrProtocolViolation) {
			return GetInfoResponse{}, fmt.Errorf("%w: GetInfo response is malformed", ErrProtocolViolation)
		}
		if IsRPCProtocolViolation(rpcErr) || IsPermanentRPC(rpcErr) {
			return GetInfoResponse{}, fmt.Errorf("%w: GetInfo RPC failed with %s", ErrProtocolViolation, status.Code(rpcErr))
		}
		return GetInfoResponse{}, fmt.Errorf("signer plugin GetInfo: %w", rpcErr)
	}
	if info == nil {
		return GetInfoResponse{}, fmt.Errorf("%w: GetInfo returned an empty response", ErrProtocolViolation)
	}
	if err := ValidateGetInfoResponse(*info); err != nil {
		return GetInfoResponse{}, fmt.Errorf("%w: invalid GetInfo response: %v", ErrProtocolViolation, err)
	}
	return cloneInfoResponse(*info), nil
}

type handshakeResult struct {
	handshake handshake
	err       error
}

func readProcessHandshake(stdout io.Reader, result chan<- handshakeResult, remaining io.Writer) {
	reader := bufio.NewReaderSize(stdout, maxHandshakeBytes)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			result <- handshakeResult{err: fmt.Errorf("%w: handshake exceeds %d bytes", ErrProtocolViolation, maxHandshakeBytes)}
			return
		}
		if errors.Is(err, io.EOF) && len(line) > 0 {
			result <- handshakeResult{err: fmt.Errorf("%w: handshake must end with a newline", ErrProtocolViolation)}
			return
		}
		result <- handshakeResult{err: fmt.Errorf("read signer plugin handshake: %w", err)}
		return
	}
	startup, err := decodeHandshake(line)
	if err != nil {
		result <- handshakeResult{err: err}
		return
	}
	result <- handshakeResult{handshake: startup}
	if remaining != nil {
		_, _ = io.Copy(remaining, reader)
	}
}

func decodeHandshake(data []byte) (handshake, error) {
	if !utf8.Valid(data) {
		return handshake{}, fmt.Errorf("%w: handshake is not valid UTF-8", ErrProtocolViolation)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return handshake{}, fmt.Errorf("%w: decode handshake object", ErrProtocolViolation)
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return handshake{}, fmt.Errorf("%w: handshake must be a JSON object", ErrProtocolViolation)
	}

	var startup handshake
	seen := make(map[string]struct{}, 3)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return handshake{}, fmt.Errorf("%w: decode handshake field name", ErrProtocolViolation)
		}
		key, ok := keyToken.(string)
		if !ok {
			return handshake{}, fmt.Errorf("%w: handshake field name must be a string", ErrProtocolViolation)
		}
		switch key {
		case "protocol_version", "address", "magic_cookie":
		default:
			return handshake{}, fmt.Errorf("%w: unknown handshake field %q", ErrProtocolViolation, key)
		}
		if _, exists := seen[key]; exists {
			return handshake{}, fmt.Errorf("%w: duplicate handshake field %q", ErrProtocolViolation, key)
		}
		seen[key] = struct{}{}

		var value string
		if err := decoder.Decode(&value); err != nil {
			return handshake{}, fmt.Errorf("%w: handshake field %q must be a string", ErrProtocolViolation, key)
		}
		switch key {
		case "protocol_version":
			startup.ProtocolVersion = value
		case "address":
			startup.Address = value
		case "magic_cookie":
			startup.MagicCookie = value
		}
	}
	closingToken, err := decoder.Token()
	if err != nil {
		return handshake{}, fmt.Errorf("%w: decode handshake object end", ErrProtocolViolation)
	}
	closingDelimiter, ok := closingToken.(json.Delim)
	if !ok || closingDelimiter != '}' {
		return handshake{}, fmt.Errorf("%w: handshake object is malformed", ErrProtocolViolation)
	}
	for _, required := range []string{"protocol_version", "address", "magic_cookie"} {
		if _, ok := seen[required]; !ok {
			return handshake{}, fmt.Errorf("%w: handshake field %q is required", ErrProtocolViolation, required)
		}
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return handshake{}, fmt.Errorf("%w: trailing handshake content", ErrProtocolViolation)
	}
	return startup, nil
}

func writeHandshake(writer io.Writer, startup handshake) error {
	if err := json.NewEncoder(writer).Encode(startup); err != nil {
		return fmt.Errorf("write signer plugin handshake: %w", err)
	}
	return nil
}

func validateHandshake(startup handshake, cookie string) error {
	if startup.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: handshake protocol %q is incompatible with %q", ErrProtocolViolation, startup.ProtocolVersion, ProtocolVersion)
	}
	if startup.MagicCookie != cookie {
		return fmt.Errorf("%w: handshake magic cookie mismatch", ErrProtocolViolation)
	}
	host, _, err := net.SplitHostPort(startup.Address)
	if err != nil {
		return fmt.Errorf("%w: malformed handshake address", ErrProtocolViolation)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%w: signer plugin must listen on a loopback address", ErrProtocolViolation)
	}
	return nil
}

func randomCookie() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate signer plugin cookie: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
