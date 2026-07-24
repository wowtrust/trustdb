package sdk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/grpcapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestHTTPSClientUsesConfiguredCATrustAndHostnameVerification(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"transport_security":"tls","tls_version":"TLS1.3"}`))
	}))
	defer server.Close()

	caFile := filepath.Join(t.TempDir(), "server-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(server.URL, WithTLSConfig(TLSConfig{CAFile: caFile, ReloadInterval: "1h"}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	status := client.CheckHealth(context.Background())
	if !status.OK || status.TransportSecurity != "tls" {
		t.Fatalf("health status = %+v", status)
	}

	wrongHost, err := NewClient(server.URL, WithTLSConfig(TLSConfig{CAFile: caFile, ServerName: "wrong.example", ReloadInterval: "1h"}))
	if err != nil {
		t.Fatal(err)
	}
	defer wrongHost.Close()
	if status := wrongHost.CheckHealth(context.Background()); status.OK || status.Error == "" {
		t.Fatalf("wrong-host health status = %+v", status)
	}

	wrongCAFile := filepath.Join(t.TempDir(), "wrong-ca.pem")
	if err := os.WriteFile(wrongCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: unrelatedCA(t)}), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongCA, err := NewClient(server.URL, WithTLSConfig(TLSConfig{CAFile: wrongCAFile, ReloadInterval: "1h"}))
	if err != nil {
		t.Fatal(err)
	}
	defer wrongCA.Close()
	if status := wrongCA.CheckHealth(context.Background()); status.OK || status.Error == "" {
		t.Fatalf("wrong-CA health status = %+v", status)
	}
}

func unrelatedCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(987654321), Subject: pkix.Name{CommonName: "unrelated-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestHTTPPlaintextIsLoopbackOnly(t *testing.T) {
	t.Parallel()
	if _, err := NewClient("http://example.com:8080"); err == nil {
		t.Fatal("external plaintext HTTP client was accepted")
	}
	if _, err := NewClient("http://127.0.0.1:8080"); err != nil {
		t.Fatalf("loopback plaintext client: %v", err)
	}
}

func TestHTTPSReloadableTLSRejectsProxy(t *testing.T) {
	t.Parallel()
	proxyURL, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	transport := NewHTTPTransportForConcurrency(1)
	transport.Proxy = http.ProxyURL(proxyURL)
	client, err := NewClient("https://trustdb.invalid",
		WithHTTPClient(&http.Client{Transport: transport, Timeout: time.Second}),
		WithTLSConfig(TLSConfig{ReloadInterval: "1h"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	status := client.CheckHealth(context.Background())
	if status.OK || !strings.Contains(status.Error, "proxies are unsupported") {
		t.Fatalf("proxy health status = %+v", status)
	}
}

func TestGRPCClientUsesConfiguredTLS(t *testing.T) {
	t.Parallel()
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := fixture.TLS.Certificates[0]
	caRaw := fixture.Certificate().Raw
	fixture.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2"},
	})))
	grpcapi.RegisterTrustDBServiceServer(server, grpcapi.NewServer(nil, nil, nil, nil, nil))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	caFile := filepath.Join(t.TempDir(), "grpc-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caRaw}), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewGRPCClient(listener.Addr().String(), WithGRPCTLSConfig(TLSConfig{CAFile: caFile, ReloadInterval: "1h"}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	status := client.CheckHealth(context.Background())
	if !status.OK || status.TransportSecurity != "tls" || status.TLSVersion == "" {
		t.Fatalf("gRPC TLS health status = %+v", status)
	}
}

func TestGRPCPlaintextRequiresExplicitLoopbackOption(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	grpcapi.RegisterTrustDBServiceServer(server, grpcapi.NewServer(nil, nil, nil, nil, nil))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	secureDefault, err := NewGRPCClient(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer secureDefault.Close()
	if status := secureDefault.CheckHealth(context.Background()); status.OK || status.Error == "" {
		t.Fatalf("TLS-default client reached plaintext server: %+v", status)
	}

	localPlaintext, err := NewGRPCClient(listener.Addr().String(), WithGRPCLocalPlaintext())
	if err != nil {
		t.Fatal(err)
	}
	defer localPlaintext.Close()
	if status := localPlaintext.CheckHealth(context.Background()); !status.OK || status.TransportSecurity != "plaintext" {
		t.Fatalf("explicit plaintext health status = %+v", status)
	}
}
