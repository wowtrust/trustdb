package transporttls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestTLSRejectsWrongHostCAAndDowngrade(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ca := newTestCA(t, "ca-one")
	otherCA := newTestCA(t, "ca-two")
	serverCert, serverKey, _ := issueTestCertificate(t, ca, "server", []string{"trustdb.test"}, false, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	caFile := writePEM(t, dir, "ca.pem", "CERTIFICATE", ca.cert.Raw)
	otherCAFile := writePEM(t, dir, "other-ca.pem", "CERTIFICATE", otherCA.cert.Raw)
	certFile := writeBytes(t, dir, "server.crt", serverCert)
	keyFile := writeBytes(t, dir, "server.key", serverKey)

	server, err := NewServerManager(ServerConfig{Mode: ModeTLS, CertFile: certFile, KeyFile: keyFile, MinVersion: "1.3", ReloadInterval: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	address := startTestTLSServer(t, server)

	good := newTestClientManager(t, ClientConfig{CAFile: caFile, ServerName: "trustdb.test", MinVersion: "1.3", ReloadInterval: "1h"})
	if err := dialTestTLS(good, address); err != nil {
		t.Fatalf("valid TLS 1.3 handshake: %v", err)
	}
	wrongHost := newTestClientManager(t, ClientConfig{CAFile: caFile, ServerName: "wrong.test", ReloadInterval: "1h"})
	if err := dialTestTLS(wrongHost, address); err == nil || !strings.Contains(err.Error(), "not wrong.test") {
		t.Fatalf("wrong-host error = %v", err)
	}
	wrongCA := newTestClientManager(t, ClientConfig{CAFile: otherCAFile, ServerName: "trustdb.test", ReloadInterval: "1h"})
	if err := dialTestTLS(wrongCA, address); err == nil {
		t.Fatal("wrong CA handshake succeeded")
	}
	downgrade := newTestClientManager(t, ClientConfig{CAFile: caFile, ServerName: "trustdb.test", MinVersion: "1.2", MaxVersion: "1.2", ReloadInterval: "1h"})
	if err := dialTestTLS(downgrade, address); err == nil {
		t.Fatal("TLS 1.2 downgrade handshake succeeded against TLS 1.3 minimum")
	}
}

func TestMutualTLSRejectsMissingWrongAndRevokedClient(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	serverCA := newTestCA(t, "server-ca")
	clientCA := newTestCA(t, "client-ca")
	wrongClientCA := newTestCA(t, "wrong-client-ca")
	serverCert, serverKey, _ := issueTestCertificate(t, serverCA, "server", []string{"trustdb.test"}, false, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	clientCert, clientKey, clientLeaf := issueTestCertificate(t, clientCA, "client-a", nil, true, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	wrongCert, wrongKey, _ := issueTestCertificate(t, wrongClientCA, "client-b", nil, true, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	serverCAFile := writePEM(t, dir, "server-ca.pem", "CERTIFICATE", serverCA.cert.Raw)
	clientCAFile := writePEM(t, dir, "client-ca.pem", "CERTIFICATE", clientCA.cert.Raw)
	serverCertFile := writeBytes(t, dir, "server.crt", serverCert)
	serverKeyFile := writeBytes(t, dir, "server.key", serverKey)
	clientCertFile := writeBytes(t, dir, "client.crt", clientCert)
	clientKeyFile := writeBytes(t, dir, "client.key", clientKey)
	wrongCertFile := writeBytes(t, dir, "wrong.crt", wrongCert)
	wrongKeyFile := writeBytes(t, dir, "wrong.key", wrongKey)
	revokedFile := writeBytes(t, dir, "revoked.txt", nil)

	server, err := NewServerManager(ServerConfig{
		Mode: ModeMTLS, CertFile: serverCertFile, KeyFile: serverKeyFile, ClientCAFile: clientCAFile,
		ReloadInterval: "1h", Revocation: RevocationConfig{Mode: RevocationSerialDenylist, SerialFile: revokedFile},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	address := startTestTLSServer(t, server)

	missing := newTestClientManager(t, ClientConfig{CAFile: serverCAFile, ServerName: "trustdb.test", ReloadInterval: "1h"})
	if err := dialTestTLS(missing, address); err == nil {
		t.Fatal("mTLS handshake without a client certificate succeeded")
	}
	wrong := newTestClientManager(t, ClientConfig{CAFile: serverCAFile, CertFile: wrongCertFile, KeyFile: wrongKeyFile, ServerName: "trustdb.test", ReloadInterval: "1h"})
	if err := dialTestTLS(wrong, address); err == nil {
		t.Fatal("mTLS handshake with an untrusted client certificate succeeded")
	}
	good := newTestClientManager(t, ClientConfig{CAFile: serverCAFile, CertFile: clientCertFile, KeyFile: clientKeyFile, ServerName: "trustdb.test", ReloadInterval: "1h"})
	if err := dialTestTLS(good, address); err != nil {
		t.Fatalf("valid mTLS handshake: %v", err)
	}
	if err := os.WriteFile(revokedFile, []byte(clientLeaf.SerialNumber.Text(16)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := dialTestTLS(good, address); err == nil {
		t.Fatalf("revoked-client error = %v", err)
	}
}

func TestCertificateAndCARotationPublishAtomicSnapshots(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caOne := newTestCA(t, "ca-one")
	caTwo := newTestCA(t, "ca-two")
	certOne, keyOne, _ := issueTestCertificate(t, caOne, "server-one", []string{"trustdb.test"}, false, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	certTwo, keyTwo, _ := issueTestCertificate(t, caTwo, "server-two", []string{"trustdb.test"}, false, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	expired, expiredKey, _ := issueTestCertificate(t, caTwo, "expired", []string{"trustdb.test"}, false, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	caOneFile := writePEM(t, dir, "ca-one.pem", "CERTIFICATE", caOne.cert.Raw)
	caTwoFile := writePEM(t, dir, "ca-two.pem", "CERTIFICATE", caTwo.cert.Raw)
	certFile := writeBytes(t, dir, "server.crt", certOne)
	keyFile := writeBytes(t, dir, "server.key", keyOne)

	server, err := NewServerManager(ServerConfig{Mode: ModeTLS, CertFile: certFile, KeyFile: keyFile, ReloadInterval: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	address := startTestTLSServer(t, server)
	clientOne := newTestClientManager(t, ClientConfig{CAFile: caOneFile, ServerName: "trustdb.test", ReloadInterval: "1h"})
	clientTwo := newTestClientManager(t, ClientConfig{CAFile: caTwoFile, ServerName: "trustdb.test", ReloadInterval: "1h"})
	if err := dialTestTLS(clientOne, address); err != nil {
		t.Fatal(err)
	}
	replaceFile(t, certFile, certTwo)
	replaceFile(t, keyFile, keyTwo)
	if err := server.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := dialTestTLS(clientOne, address); err == nil {
		t.Fatal("old CA trusted the rotated server certificate")
	}
	if err := dialTestTLS(clientTwo, address); err != nil {
		t.Fatalf("rotated certificate handshake: %v", err)
	}

	replaceFile(t, certFile, expired)
	replaceFile(t, keyFile, expiredKey)
	if err := server.Reload(); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired reload error = %v", err)
	}
	if err := dialTestTLS(clientTwo, address); err != nil {
		t.Fatalf("failed reload did not retain last known-good snapshot: %v", err)
	}

	replaceFile(t, caOneFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caTwo.cert.Raw}))
	if err := clientOne.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := dialTestTLS(clientOne, address); err != nil {
		t.Fatalf("client CA reload: %v", err)
	}
}

func TestCAPinningAndExpiredCertificateLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ca := newTestCA(t, "ca")
	cert, key, _ := issueTestCertificate(t, ca, "server", []string{"trustdb.test"}, false, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	expired, expiredKey, _ := issueTestCertificate(t, ca, "expired", []string{"trustdb.test"}, false, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	caFile := writePEM(t, dir, "ca.pem", "CERTIFICATE", ca.cert.Raw)
	certFile := writeBytes(t, dir, "server.crt", cert)
	keyFile := writeBytes(t, dir, "server.key", key)
	server, err := NewServerManager(ServerConfig{Mode: ModeTLS, CertFile: certFile, KeyFile: keyFile, ReloadInterval: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	address := startTestTLSServer(t, server)
	wrongPin := strings.Repeat("00", sha256.Size)
	client := newTestClientManager(t, ClientConfig{CAFile: caFile, CAPinsSHA256: []string{wrongPin}, ServerName: "trustdb.test", ReloadInterval: "1h"})
	if err := dialTestTLS(client, address); err == nil || !strings.Contains(err.Error(), "CA pin") {
		t.Fatalf("wrong-pin error = %v", err)
	}

	replaceFile(t, certFile, expired)
	replaceFile(t, keyFile, expiredKey)
	if _, err := NewServerManager(ServerConfig{Mode: ModeTLS, CertFile: certFile, KeyFile: keyFile, ReloadInterval: "1h"}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired startup error = %v", err)
	}
}

func TestHTTPServerServeTLSSupportsDynamicSnapshotAndHTTP2(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ca := newTestCA(t, "ca")
	cert, key, _ := issueTestCertificate(t, ca, "server", []string{"trustdb.test"}, false, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	serverManager, err := NewServerManager(ServerConfig{
		Mode: ModeTLS, CertFile: writeBytes(t, dir, "server.crt", cert), KeyFile: writeBytes(t, dir, "server.key", key), ReloadInterval: "1h",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer serverManager.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		TLSConfig: serverManager.ServerTLSConfig(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(r.Proto))
		}),
	}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})
	clientManager := newTestClientManager(t, ClientConfig{CAFile: writePEM(t, dir, "ca.pem", "CERTIFICATE", ca.cert.Raw), ServerName: "trustdb.test", ReloadInterval: "1h"})
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = nil
	transport.DialTLSContext = clientManager.DialTLSContext
	transport.ForceAttemptHTTP2 = true
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get("https://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.ProtoMajor != 2 {
		t.Fatalf("HTTP protocol = %s, want HTTP/2", response.Proto)
	}
}

func TestGRPCServerAndClientUseDynamicTLSCredentials(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ca := newTestCA(t, "ca")
	cert, key, _ := issueTestCertificate(t, ca, "server", []string{"trustdb.test"}, false, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	serverManager, err := NewServerManager(ServerConfig{
		Mode: ModeTLS, CertFile: writeBytes(t, dir, "server.crt", cert), KeyFile: writeBytes(t, dir, "server.key", key), ReloadInterval: "1h",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer serverManager.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverManager.ServerTLSConfig())))
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, healthServer)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	clientManager := newTestClientManager(t, ClientConfig{CAFile: writePEM(t, dir, "ca.pem", "CERTIFICATE", ca.cert.Raw), ServerName: "trustdb.test", ReloadInterval: "1h"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, listener.Addr().String(), grpc.WithTransportCredentials(clientManager.TransportCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	response, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("health status = %s", response.Status)
	}
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key}
}

func issueTestCertificate(t *testing.T, ca testCA, commonName string, dns []string, client bool, notBefore, notAfter time.Time) ([]byte, []byte, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if client {
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t), Subject: pkix.Name{CommonName: commonName}, DNSNames: dns,
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	keyRaw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})...)
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyRaw}), leaf
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

func writePEM(t *testing.T, dir, name, blockType string, raw []byte) string {
	t.Helper()
	return writeBytes(t, dir, name, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: raw}))
}

func writeBytes(t *testing.T, dir, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func replaceFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	tmp := path + ".new"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func newTestClientManager(t *testing.T, config ClientConfig) *Manager {
	t.Helper()
	manager, err := NewClientManager(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return manager
}

func startTestTLSServer(t *testing.T, manager *Manager) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tlsListener{Listener: listener, config: manager.ServerTLSConfig()}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				if handshaker, ok := conn.(interface{ Handshake() error }); ok {
					if err := handshaker.Handshake(); err != nil {
						return
					}
				}
				_, _ = conn.Write([]byte{1})
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		wg.Wait()
	})
	return listener.Addr().String()
}

type tlsListener struct {
	net.Listener
	config *tls.Config
}

func (l tlsListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return tls.Server(conn, l.config), nil
}

func dialTestTLS(manager *Manager, address string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := manager.DialTLSContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var response [1]byte
	_, err = conn.Read(response[:])
	return err
}

func TestFingerprintDocumentationFormat(t *testing.T) {
	ca := newTestCA(t, "ca")
	fingerprint := sha256.Sum256(ca.cert.Raw)
	if len(hex.EncodeToString(fingerprint[:])) != 64 {
		t.Fatal("unexpected SHA-256 fingerprint length")
	}
}
