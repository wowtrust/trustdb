package anchorplugin

import (
	"bufio"
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
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	DefaultStartTimeout = 10 * time.Second
	DefaultRPCTimeout   = 30 * time.Second
	maxHandshakeBytes   = 16 << 10
)

type ProcessConfig struct {
	Command      string
	Args         []string
	Env          []string
	StartTimeout time.Duration
	RPCTimeout   time.Duration
	Stderr       io.Writer
}

// Process owns one plugin subprocess and its gRPC connection.
type Process struct {
	cmd        *exec.Cmd
	conn       *grpc.ClientConn
	client     RPCClient
	info       GetInfoResponse
	rpcTimeout time.Duration
	done       chan error
	closeOnce  sync.Once
}

func StartProcess(ctx context.Context, cfg ProcessConfig) (*Process, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(cfg.Command) == "" {
		return nil, fmt.Errorf("anchor plugin command is required")
	}
	if cfg.StartTimeout <= 0 {
		cfg.StartTimeout = DefaultStartTimeout
	}
	if cfg.RPCTimeout <= 0 {
		cfg.RPCTimeout = DefaultRPCTimeout
	}
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}
	cookie, err := randomCookie()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(cfg.Command, cfg.Args...)
	cmd.Env = append(os.Environ(), cfg.Env...)
	cmd.Env = append(cmd.Env, EnvProtocol+"="+ProtocolVersion, EnvMagicCookie+"="+cookie)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("open anchor plugin stdout: %w", err)
	}
	cmd.Stderr = cfg.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start anchor plugin: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	startCtx, cancel := context.WithTimeout(ctx, cfg.StartTimeout)
	defer cancel()
	handshakeCh := make(chan handshakeResult, 1)
	go readProcessHandshake(stdout, handshakeCh, cfg.Stderr)
	var hs handshake
	select {
	case <-startCtx.Done():
		_ = cmd.Process.Kill()
		<-done
		return nil, fmt.Errorf("anchor plugin handshake: %w", startCtx.Err())
	case waitErr := <-done:
		if waitErr == nil {
			return nil, fmt.Errorf("anchor plugin exited before handshake")
		}
		return nil, fmt.Errorf("anchor plugin exited before handshake: %w", waitErr)
	case result := <-handshakeCh:
		if result.err != nil {
			_ = cmd.Process.Kill()
			<-done
			return nil, result.err
		}
		hs = result.handshake
	}
	if err := validateHandshake(hs, cookie); err != nil {
		_ = cmd.Process.Kill()
		<-done
		return nil, err
	}

	conn, err := grpc.DialContext(startCtx, hs.Address,
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
		_ = cmd.Process.Kill()
		<-done
		return nil, fmt.Errorf("connect to anchor plugin: %w", err)
	}
	process := &Process{cmd: cmd, conn: conn, client: NewRPCClient(conn), rpcTimeout: cfg.RPCTimeout, done: done}
	info, err := process.GetInfo(startCtx)
	if err != nil {
		_ = process.Close()
		return nil, err
	}
	process.info = info
	return process, nil
}

type cookieCredentials struct{ cookie string }

func (c cookieCredentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{CookieMetadata: c.cookie}, nil
}

func (cookieCredentials) RequireTransportSecurity() bool { return false }

func (p *Process) Info() GetInfoResponse { return p.info }

func (p *Process) GetInfo(ctx context.Context) (GetInfoResponse, error) {
	callCtx, cancel := p.callContext(ctx)
	defer cancel()
	response, err := p.client.GetInfo(callCtx, &GetInfoRequest{})
	if err != nil {
		return GetInfoResponse{}, fmt.Errorf("anchor plugin GetInfo: %w", err)
	}
	if response.ProtocolVersion != ProtocolVersion {
		return GetInfoResponse{}, fmt.Errorf("anchor plugin protocol %q is incompatible with %q", response.ProtocolVersion, ProtocolVersion)
	}
	if err := ValidateSinkName(response.SinkName); err != nil {
		return GetInfoResponse{}, err
	}
	if !hasCapability(response.Capabilities, CapabilityPublish) || !hasCapability(response.Capabilities, CapabilityVerify) {
		return GetInfoResponse{}, fmt.Errorf("anchor plugin must advertise publish and verify capabilities")
	}
	return *response, nil
}

func (p *Process) Publish(ctx context.Context, sth SignedTreeHead) (AnchorResult, error) {
	callCtx, cancel := p.callContext(ctx)
	defer cancel()
	response, err := p.client.Publish(callCtx, &PublishRequest{STH: sth})
	if err != nil {
		return AnchorResult{}, err
	}
	if response.Result.AnchorID == "" {
		return AnchorResult{}, fmt.Errorf("anchor plugin returned an empty anchor_id")
	}
	return response.Result, nil
}

func (p *Process) Verify(ctx context.Context, sth SignedTreeHead, result AnchorResult) error {
	callCtx, cancel := p.callContext(ctx)
	defer cancel()
	response, err := p.client.Verify(callCtx, &VerifyRequest{STH: sth, Result: result})
	if err != nil {
		return err
	}
	if !response.Valid {
		return fmt.Errorf("anchor plugin rejected proof without an error")
	}
	return nil
}

func (p *Process) Status(ctx context.Context) (SystemStatus, error) {
	callCtx, cancel := p.callContext(ctx)
	defer cancel()
	response, err := p.client.GetStatus(callCtx, &GetStatusRequest{})
	if err != nil {
		return SystemStatus{}, err
	}
	return response.Status, nil
}

func (p *Process) ListResources(ctx context.Context, req ListResourcesRequest) (ListResourcesResponse, error) {
	callCtx, cancel := p.callContext(ctx)
	defer cancel()
	response, err := p.client.ListResources(callCtx, &req)
	if err != nil {
		return ListResourcesResponse{}, err
	}
	return *response, nil
}

func (p *Process) Resource(ctx context.Context, kind, resourceID string) (Resource, bool, error) {
	callCtx, cancel := p.callContext(ctx)
	defer cancel()
	response, err := p.client.GetResource(callCtx, &GetResourceRequest{Kind: kind, ResourceID: resourceID})
	if err != nil {
		return Resource{}, false, err
	}
	return response.Resource, response.Found, nil
}

func (p *Process) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, p.rpcTimeout)
}

func (p *Process) Close() error {
	var closeErr error
	p.closeOnce.Do(func() {
		if p.conn != nil {
			closeErr = p.conn.Close()
		}
		if p.cmd == nil || p.cmd.Process == nil {
			return
		}
		_ = p.cmd.Process.Signal(os.Interrupt)
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			_ = p.cmd.Process.Kill()
			<-p.done
		case <-p.done:
		}
	})
	return closeErr
}

// IsPermanentRPC reports status codes that a host should translate to its
// non-retryable anchor failure sentinel.
func IsPermanentRPC(err error) bool {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.Unauthenticated, codes.Unimplemented:
		return true
	default:
		return false
	}
}

func ValidateSinkName(name string) error {
	if len(name) == 0 || len(name) > 64 {
		return fmt.Errorf("anchor plugin sink_name must contain 1 to 64 characters")
	}
	for i, r := range name {
		valid := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'
		if !valid || i == 0 && !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return fmt.Errorf("anchor plugin sink_name %q must match [a-z0-9][a-z0-9._-]*", name)
		}
	}
	return nil
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
			result <- handshakeResult{err: fmt.Errorf("anchor plugin handshake exceeds %d bytes", maxHandshakeBytes)}
			return
		}
		result <- handshakeResult{err: fmt.Errorf("read anchor plugin handshake: %w", err)}
		return
	}
	var hs handshake
	if err := json.Unmarshal(line, &hs); err != nil {
		result <- handshakeResult{err: fmt.Errorf("decode anchor plugin handshake: %w", err)}
		return
	}
	result <- handshakeResult{handshake: hs}
	if remaining != nil {
		_, _ = io.Copy(remaining, reader)
	}
}

func writeHandshake(w io.Writer, hs handshake) error {
	if err := json.NewEncoder(w).Encode(hs); err != nil {
		return fmt.Errorf("write anchor plugin handshake: %w", err)
	}
	return nil
}

func validateHandshake(hs handshake, cookie string) error {
	if hs.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("anchor plugin handshake protocol %q is incompatible with %q", hs.ProtocolVersion, ProtocolVersion)
	}
	if hs.MagicCookie != cookie {
		return fmt.Errorf("anchor plugin handshake magic cookie mismatch")
	}
	host, _, err := net.SplitHostPort(hs.Address)
	if err != nil {
		return fmt.Errorf("anchor plugin handshake address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("anchor plugin must listen on a loopback address")
	}
	return nil
}

func randomCookie() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate anchor plugin cookie: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func hasCapability(capabilities []string, wanted string) bool {
	for _, capability := range capabilities {
		if capability == wanted {
			return true
		}
	}
	return false
}
