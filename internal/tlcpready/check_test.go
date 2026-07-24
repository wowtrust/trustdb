package tlcpready

import (
	"strings"
	"testing"
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
