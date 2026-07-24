package tlcpready

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type Config struct {
	OpenSSLPath               string
	ServerName                string
	ServerCAFile              string
	HTTPAddress               string
	GRPCAddress               string
	ClientSigningChainFile    string
	ClientSigningKey          string
	ClientEncryptionChainFile string
	ClientEncryptionKey       string
}

func Check(ctx context.Context, config Config) error {
	if err := validateConfig(config); err != nil {
		return err
	}
	if err := checkHTTP(ctx, config); err != nil {
		return fmt.Errorf("TLCP HTTP readiness: %w", err)
	}
	if err := checkGRPC(ctx, config); err != nil {
		return fmt.Errorf("TLCP gRPC readiness: %w", err)
	}
	return nil
}

func LoopbackAddress(address string) (string, error) {
	parsed, err := netip.ParseAddrPort(address)
	if err != nil || parsed.Port() == 0 {
		return "", errors.New("gateway address must be an explicit IP address and non-zero port")
	}
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), parsed.Port()).String(), nil
}

func validateConfig(config Config) error {
	for name, value := range map[string]string{
		"openssl path":                  config.OpenSSLPath,
		"server name":                   config.ServerName,
		"server CA":                     config.ServerCAFile,
		"HTTP address":                  config.HTTPAddress,
		"gRPC address":                  config.GRPCAddress,
		"client signing certificate":    config.ClientSigningChainFile,
		"client signing key":            config.ClientSigningKey,
		"client encryption certificate": config.ClientEncryptionChainFile,
		"client encryption key":         config.ClientEncryptionKey,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	return nil
}

func opensslArgs(config Config, address, alpn string) []string {
	return []string{
		"s_client",
		"-connect", address,
		"-servername", config.ServerName,
		"-verify_hostname", config.ServerName,
		"-verify_return_error",
		"-CAfile", config.ServerCAFile,
		"-enable_ntls",
		"-ntls",
		"-cipher", "ECDHE-SM2-SM4-GCM-SM3",
		"-alpn", alpn,
		"-sign_cert", config.ClientSigningChainFile,
		"-sign_key", config.ClientSigningKey,
		"-enc_cert", config.ClientEncryptionChainFile,
		"-enc_key", config.ClientEncryptionKey,
		"-brief",
	}
}

func checkHTTP(ctx context.Context, config Config) error {
	command := exec.CommandContext(
		ctx,
		config.OpenSSLPath,
		opensslArgs(config, config.HTTPAddress, "http/1.1")...,
	)
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
		"GET /healthz HTTP/1.1\r\nHost: "+config.ServerName+
			"\r\nConnection: close\r\n\r\n",
	); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return err
	}
	err = command.Wait()
	result := []byte(output.String())
	if err != nil {
		return fmt.Errorf("request failed: %w: %s", err, boundedDiagnostics(result))
	}
	if !bytes.Contains(result, []byte("HTTP/1.1 200 OK")) {
		return fmt.Errorf("health endpoint did not return HTTP 200: %s", boundedDiagnostics(result))
	}
	return requireTLCPDiagnostics(string(result))
}

func checkGRPC(ctx context.Context, config Config) error {
	command := exec.CommandContext(
		ctx,
		config.OpenSSLPath,
		opensslArgs(config, config.GRPCAddress, "h2")...,
	)
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
		return err
	}
	if err := framer.WriteSettings(); err != nil {
		return err
	}
	var headers bytes.Buffer
	encoder := hpack.NewEncoder(&headers)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/grpc.health.v1.Health/Check"},
		{Name: ":authority", Value: config.ServerName},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "te", Value: "trailers"},
	} {
		if err := encoder.WriteField(field); err != nil {
			return err
		}
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: headers.Bytes(), EndHeaders: true,
	}); err != nil {
		return err
	}
	if err := framer.WriteData(1, true, []byte{0, 0, 0, 0, 0}); err != nil {
		return err
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
			return fmt.Errorf("read HTTP/2 frame: %w: %s", err, diagnostics.String())
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
				return err
			}
			if value.StreamEnded() {
				if grpcStatus != "0" {
					return fmt.Errorf("gRPC health status is %q", grpcStatus)
				}
				return verifyGRPCResponse(response, waitForDiagnostics(&diagnostics))
			}
		case *http2.DataFrame:
			response = append(response, value.Data()...)
		case *http2.GoAwayFrame:
			return fmt.Errorf("gateway returned GOAWAY %s", value.ErrCode)
		}
	}
}

func waitForDiagnostics(diagnostics *synchronizedBuffer) string {
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

func verifyGRPCResponse(response []byte, diagnostics string) error {
	if len(response) != 7 ||
		response[0] != 0 ||
		binary.BigEndian.Uint32(response[1:5]) != 2 ||
		response[5] != 0x08 ||
		response[6] != 0x01 {
		return fmt.Errorf("unexpected gRPC health response %x", response)
	}
	return requireTLCPDiagnostics(diagnostics)
}

func requireTLCPDiagnostics(value string) error {
	for _, expected := range []string{
		"Protocol version: NTLSv1.1",
		"Ciphersuite: ECDHE-SM2-SM4-GCM-SM3",
	} {
		if !strings.Contains(value, expected) {
			return fmt.Errorf("handshake diagnostics do not contain %q", expected)
		}
	}
	return nil
}

func boundedDiagnostics(value []byte) string {
	const maximum = 4096
	if len(value) > maximum {
		value = value[len(value)-maximum:]
	}
	return string(value)
}

type synchronizedBuffer struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
}

func (buffer *synchronizedBuffer) Write(data []byte) (int, error) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return buffer.buffer.Write(data)
}

func (buffer *synchronizedBuffer) String() string {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return buffer.buffer.String()
}
