package tlcpready

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestLoopbackAddressPreservesOnlyTheValidatedPort(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{"0.0.0.0:8443", "127.0.0.1:8443"},
		{"[::]:9443", "127.0.0.1:9443"},
	} {
		got, err := LoopbackAddress(test.input)
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("LoopbackAddress(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestLoopbackAddressRejectsImplicitOrZeroPorts(t *testing.T) {
	for _, value := range []string{"localhost:8443", "127.0.0.1", "127.0.0.1:0"} {
		if _, err := LoopbackAddress(value); err == nil {
			t.Fatalf("LoopbackAddress(%q) succeeded", value)
		}
	}
}

func TestConfigRequiresEveryCredential(t *testing.T) {
	if err := validateConfig(Config{}); err == nil {
		t.Fatal("empty readiness configuration was accepted")
	}
}

func TestRequireHTTP200ParsesOnlyTheFirstStatusLine(t *testing.T) {
	for _, test := range []struct {
		name     string
		response string
		wantErr  bool
	}{
		{
			name:     "success",
			response: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
		},
		{
			name: "fake success in error body",
			response: "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\n" +
				"upstream said HTTP/1.1 200 OK",
			wantErr: true,
		},
		{
			name:     "diagnostic prefix",
			response: "CONNECTED\nHTTP/1.1 200 OK\r\n\r\n",
			wantErr:  true,
		},
		{
			name:     "wrong protocol",
			response: "HTTP/1.0 200 OK\r\n\r\n",
			wantErr:  true,
		},
		{
			name:     "malformed code",
			response: "HTTP/1.1 20 OK\r\n\r\n",
			wantErr:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := requireHTTP200([]byte(test.response))
			if (err != nil) != test.wantErr {
				t.Fatalf("requireHTTP200() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestBoundedCommandOutputCapsCombinedStreams(t *testing.T) {
	var output boundedCommandOutput
	stdout := output.writer(&output.stdout)
	stderr := output.writer(&output.stderr)
	if _, err := stdout.Write(bytes.Repeat([]byte{'a'}, maxReadinessOutputBytes-3)); err != nil {
		t.Fatal(err)
	}
	written, err := stderr.Write([]byte("overflow"))
	if written != 3 || !errors.Is(err, errReadinessOutputLimit) {
		t.Fatalf("overflow write = (%d, %v), want (3, output limit)", written, err)
	}
	gotStdout, gotStderr, exceeded := output.snapshot()
	if !exceeded || len(gotStdout)+len(gotStderr) != maxReadinessOutputBytes {
		t.Fatalf(
			"bounded output = stdout %d + stderr %d, exceeded %v",
			len(gotStdout),
			len(gotStderr),
			exceeded,
		)
	}
}

func TestVerifyGRPCResponseRequiresServingAndExactTLCP(t *testing.T) {
	serving := []byte{0, 0, 0, 0, 2, 0x08, 0x01}
	diagnostics := strings.Join([]string{
		"Protocol version: NTLSv1.1",
		"Ciphersuite: ECDHE-SM2-SM4-GCM-SM3",
	}, "\n")
	if err := verifyGRPCResponse(serving, diagnostics); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		response    []byte
		diagnostics string
	}{
		{"not serving", []byte{0, 0, 0, 0, 2, 0x08, 0x00}, diagnostics},
		{"wrong protocol", serving, "Protocol version: TLSv1.3\nCiphersuite: ECDHE-SM2-SM4-GCM-SM3"},
		{"wrong cipher", serving, "Protocol version: NTLSv1.1\nCiphersuite: ECC-SM2-SM4-CBC-SM3"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := verifyGRPCResponse(test.response, test.diagnostics); err == nil {
				t.Fatal("invalid readiness response was accepted")
			}
		})
	}
}

func TestReadGRPCResponseAcceptsOnlyTheBoundedHealthExchange(t *testing.T) {
	var wire bytes.Buffer
	writer := http2.NewFramer(&wire, nil)
	if err := writer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	writeTestHeaders(t, writer, false, hpack.HeaderField{
		Name: "content-type", Value: "application/grpc",
	})
	if err := writer.WriteData(
		1,
		false,
		[]byte{0, 0, 0, 0, 2, 0x08, 0x01},
	); err != nil {
		t.Fatal(err)
	}
	writeTestHeaders(t, writer, true, hpack.HeaderField{
		Name: "grpc-status", Value: "0",
	})
	diagnostics := newBoundedSynchronizedBuffer(maxReadinessOutputBytes)
	_, _ = diagnostics.Write([]byte(
		"Protocol version: NTLSv1.1\n" +
			"Ciphersuite: ECDHE-SM2-SM4-GCM-SM3\n",
	))
	reader := http2.NewFramer(io.Discard, bytes.NewReader(wire.Bytes()))
	reader.SetMaxReadFrameSize(maxGRPCFrameBytes)
	if err := readGRPCResponse(reader, diagnostics); err != nil {
		t.Fatal(err)
	}
}

func TestReadGRPCResponseRejectsUnboundedDataWithoutRetainingIt(t *testing.T) {
	for _, test := range []struct {
		name   string
		chunks [][]byte
	}{
		{
			name:   "single oversized frame",
			chunks: [][]byte{bytes.Repeat([]byte{1}, maxGRPCResponseBytes+1)},
		},
		{
			name: "continued response",
			chunks: [][]byte{
				bytes.Repeat([]byte{1}, maxGRPCResponseBytes),
				{1},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var wire bytes.Buffer
			writer := http2.NewFramer(&wire, nil)
			for _, chunk := range test.chunks {
				if err := writer.WriteData(1, false, chunk); err != nil {
					t.Fatal(err)
				}
			}
			reader := http2.NewFramer(io.Discard, bytes.NewReader(wire.Bytes()))
			reader.SetMaxReadFrameSize(maxGRPCFrameBytes)
			err := readGRPCResponse(
				reader,
				newBoundedSynchronizedBuffer(maxReadinessOutputBytes),
			)
			if err == nil || !strings.Contains(err.Error(), "exceeds 7 bytes") {
				t.Fatalf("readGRPCResponse() error = %v", err)
			}
		})
	}
}

func TestReadGRPCResponseRejectsAHostileContinuousFrameStream(t *testing.T) {
	var wire bytes.Buffer
	writer := http2.NewFramer(&wire, nil)
	for index := 0; index < maxGRPCFrameCount+1; index++ {
		if err := writer.WritePing(false, [8]byte{byte(index)}); err != nil {
			t.Fatal(err)
		}
	}
	reader := http2.NewFramer(io.Discard, bytes.NewReader(wire.Bytes()))
	reader.SetMaxReadFrameSize(maxGRPCFrameBytes)
	err := readGRPCResponse(
		reader,
		newBoundedSynchronizedBuffer(maxReadinessOutputBytes),
	)
	if err == nil || !strings.Contains(err.Error(), "frame count exceeds") {
		t.Fatalf("readGRPCResponse() error = %v", err)
	}
}

func TestReadGRPCResponseRejectsOversizedHeaders(t *testing.T) {
	var wire bytes.Buffer
	writer := http2.NewFramer(&wire, nil)
	var encoded bytes.Buffer
	encoder := hpack.NewEncoder(&encoded)
	if err := encoder.WriteField(hpack.HeaderField{
		Name:  "hostile",
		Value: strings.Repeat("x", maxGRPCHeaderBytes),
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: encoded.Bytes(),
		EndHeaders:    true,
	}); err != nil {
		t.Fatal(err)
	}
	reader := http2.NewFramer(io.Discard, bytes.NewReader(wire.Bytes()))
	reader.SetMaxReadFrameSize(maxGRPCFrameBytes)
	err := readGRPCResponse(
		reader,
		newBoundedSynchronizedBuffer(maxReadinessOutputBytes),
	)
	if err == nil || !strings.Contains(err.Error(), "header") {
		t.Fatalf("readGRPCResponse() error = %v", err)
	}
}

func TestBoundedDiagnosticsRejectsOpenSSLFloods(t *testing.T) {
	diagnostics := newBoundedSynchronizedBuffer(4)
	written, err := diagnostics.Write([]byte("overflow"))
	if written != 4 || !errors.Is(err, errReadinessOutputLimit) {
		t.Fatalf("Write() = (%d, %v), want (4, output limit)", written, err)
	}
	if !diagnostics.Exceeded() || len(diagnostics.Bytes()) != 4 {
		t.Fatalf(
			"bounded diagnostics = exceeded %v, bytes %d",
			diagnostics.Exceeded(),
			len(diagnostics.Bytes()),
		)
	}
}

func writeTestHeaders(
	t *testing.T,
	framer *http2.Framer,
	endStream bool,
	fields ...hpack.HeaderField,
) {
	t.Helper()
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: block.Bytes(),
		EndHeaders:    true,
		EndStream:     endStream,
	}); err != nil {
		t.Fatal(err)
	}
}
