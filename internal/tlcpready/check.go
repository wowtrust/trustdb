package tlcpready

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	maxReadinessOutputBytes = 64 << 10
	maxHTTPStatusLineBytes  = 4096
	maxGRPCFrameBytes       = 16 << 10
	maxGRPCHeaderBytes      = 16 << 10
	maxGRPCResponseBytes    = 7
	maxGRPCFrameCount       = 128
)

var errReadinessOutputLimit = errors.New("readiness command output exceeds limit")

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
	var output boundedCommandOutput
	command.Stdout = output.writer(&output.stdout)
	command.Stderr = output.writer(&output.stderr)
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
	stdout, stderr, exceeded := output.snapshot()
	if exceeded {
		return fmt.Errorf("%w (%d bytes)", errReadinessOutputLimit, maxReadinessOutputBytes)
	}
	if err != nil {
		return fmt.Errorf(
			"request failed: %w: %s",
			err,
			boundedDiagnostics(append(append([]byte(nil), stdout...), stderr...)),
		)
	}
	if err := requireHTTP200(stdout); err != nil {
		return fmt.Errorf(
			"health endpoint did not return HTTP 200: %w: %s",
			err,
			boundedDiagnostics(stdout),
		)
	}
	return requireTLCPDiagnostics(string(stderr))
}

func requireHTTP200(response []byte) error {
	reader := bufio.NewReaderSize(bytes.NewReader(response), maxHTTPStatusLineBytes)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read first HTTP status line: %w", err)
	}
	if len(line) > maxHTTPStatusLineBytes {
		return errors.New("first HTTP status line exceeds limit")
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || parts[0] != "HTTP/1.1" || len(parts[1]) != 3 {
		return fmt.Errorf("invalid first HTTP status line %q", line)
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid first HTTP status code %q", parts[1])
	}
	if status != 200 {
		return fmt.Errorf("first HTTP status is %d", status)
	}
	return nil
}

func checkGRPC(ctx context.Context, config Config) error {
	command := exec.CommandContext(
		ctx,
		config.OpenSSLPath,
		opensslArgs(config, config.GRPCAddress, "h2")...,
	)
	diagnostics := newBoundedSynchronizedBuffer(maxReadinessOutputBytes)
	command.Stderr = diagnostics
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
	framer.SetMaxReadFrameSize(maxGRPCFrameBytes)
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

	return readGRPCResponse(framer, diagnostics)
}

func readGRPCResponse(
	framer *http2.Framer,
	diagnostics *boundedSynchronizedBuffer,
) error {
	response := make([]byte, 0, maxGRPCResponseBytes)
	grpcStatus := ""
	headerBytes := 0
	decoder := hpack.NewDecoder(4096, func(field hpack.HeaderField) {
		headerBytes += len(field.Name) + len(field.Value)
		if field.Name == "grpc-status" {
			grpcStatus = field.Value
		}
	})
	decoder.SetMaxStringLength(maxGRPCHeaderBytes)
	var (
		headerBlockBytes int
		headerStreamID   uint32
		frameCount       int
	)
	for {
		if diagnostics.Exceeded() {
			return fmt.Errorf(
				"%w (%d bytes)",
				errReadinessOutputLimit,
				maxReadinessOutputBytes,
			)
		}
		if frameCount >= maxGRPCFrameCount {
			return fmt.Errorf(
				"gRPC readiness frame count exceeds %d",
				maxGRPCFrameCount,
			)
		}
		frame, err := framer.ReadFrame()
		if err != nil {
			return fmt.Errorf(
				"read HTTP/2 frame: %w: %s",
				err,
				boundedDiagnostics(diagnostics.Bytes()),
			)
		}
		frameCount++
		switch value := frame.(type) {
		case *http2.SettingsFrame:
			if !value.IsAck() {
				if err := framer.WriteSettingsAck(); err != nil {
					return err
				}
			}
		case *http2.HeadersFrame:
			if headerStreamID != 0 {
				return errors.New("received HEADERS before the previous header block ended")
			}
			headerStreamID = value.StreamID
			if err := decodeGRPCHeaderFragment(
				decoder,
				value.HeaderBlockFragment(),
				&headerBlockBytes,
				&headerBytes,
			); err != nil {
				return err
			}
			if value.HeadersEnded() {
				headerStreamID = 0
			}
			if value.StreamEnded() {
				if headerStreamID != 0 {
					return errors.New("gRPC trailers ended the stream before END_HEADERS")
				}
				if grpcStatus != "0" {
					return fmt.Errorf("gRPC health status is %q", grpcStatus)
				}
				return verifyGRPCResponse(response, waitForDiagnostics(diagnostics))
			}
		case *http2.ContinuationFrame:
			if headerStreamID == 0 || value.StreamID != headerStreamID {
				return errors.New("received an unexpected HTTP/2 CONTINUATION frame")
			}
			if err := decodeGRPCHeaderFragment(
				decoder,
				value.HeaderBlockFragment(),
				&headerBlockBytes,
				&headerBytes,
			); err != nil {
				return err
			}
			if value.HeadersEnded() {
				headerStreamID = 0
			}
		case *http2.DataFrame:
			if len(value.Data()) > maxGRPCResponseBytes-len(response) {
				return fmt.Errorf(
					"gRPC health response exceeds %d bytes",
					maxGRPCResponseBytes,
				)
			}
			response = append(response, value.Data()...)
		case *http2.GoAwayFrame:
			return fmt.Errorf("gateway returned GOAWAY %s", value.ErrCode)
		}
	}
}

func decodeGRPCHeaderFragment(
	decoder *hpack.Decoder,
	fragment []byte,
	blockBytes *int,
	decodedBytes *int,
) error {
	if len(fragment) > maxGRPCHeaderBytes-*blockBytes {
		return fmt.Errorf(
			"gRPC header block exceeds %d bytes",
			maxGRPCHeaderBytes,
		)
	}
	*blockBytes += len(fragment)
	previousDecoded := *decodedBytes
	if _, err := decoder.Write(fragment); err != nil {
		return fmt.Errorf("decode gRPC header block: %w", err)
	}
	if *decodedBytes < previousDecoded ||
		*decodedBytes > maxGRPCHeaderBytes {
		return fmt.Errorf(
			"decoded gRPC headers exceed %d bytes",
			maxGRPCHeaderBytes,
		)
	}
	return nil
}

func waitForDiagnostics(diagnostics *boundedSynchronizedBuffer) string {
	const expected = "Protocol version: NTLSv1.1"
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		value := string(diagnostics.Bytes())
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
		return errors.New("unexpected gRPC health response")
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

type boundedCommandOutput struct {
	mutex    sync.Mutex
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	total    int
	exceeded bool
}

type boundedCommandOutputWriter struct {
	output *boundedCommandOutput
	target *bytes.Buffer
}

func (output *boundedCommandOutput) writer(target *bytes.Buffer) io.Writer {
	return boundedCommandOutputWriter{output: output, target: target}
}

func (writer boundedCommandOutputWriter) Write(data []byte) (int, error) {
	writer.output.mutex.Lock()
	defer writer.output.mutex.Unlock()
	remaining := maxReadinessOutputBytes - writer.output.total
	if remaining <= 0 {
		writer.output.exceeded = true
		return 0, errReadinessOutputLimit
	}
	if len(data) > remaining {
		_, _ = writer.target.Write(data[:remaining])
		writer.output.total += remaining
		writer.output.exceeded = true
		return remaining, errReadinessOutputLimit
	}
	written, err := writer.target.Write(data)
	writer.output.total += written
	return written, err
}

func (output *boundedCommandOutput) snapshot() (stdout, stderr []byte, exceeded bool) {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	return append([]byte(nil), output.stdout.Bytes()...),
		append([]byte(nil), output.stderr.Bytes()...),
		output.exceeded
}

type boundedSynchronizedBuffer struct {
	mutex    sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func newBoundedSynchronizedBuffer(limit int) *boundedSynchronizedBuffer {
	return &boundedSynchronizedBuffer{limit: limit}
}

func (buffer *boundedSynchronizedBuffer) Write(data []byte) (int, error) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.exceeded = true
		return 0, errReadinessOutputLimit
	}
	if len(data) > remaining {
		_, _ = buffer.buffer.Write(data[:remaining])
		buffer.exceeded = true
		return remaining, errReadinessOutputLimit
	}
	return buffer.buffer.Write(data)
}

func (buffer *boundedSynchronizedBuffer) Bytes() []byte {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return append([]byte(nil), buffer.buffer.Bytes()...)
}

func (buffer *boundedSynchronizedBuffer) Exceeded() bool {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return buffer.exceeded
}
