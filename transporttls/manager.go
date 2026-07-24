package transporttls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/credentials"
)

type managerRole uint8

const (
	serverRole managerRole = iota + 1
	clientRole
)

type certificatePurpose uint8

const (
	serverCertificate certificatePurpose = iota + 1
	clientCertificate
)

type snapshot struct {
	certificate *tls.Certificate
	roots       *x509.CertPool
	pins        map[[sha256.Size]byte]struct{}
	revoked     map[string]struct{}
	minVersion  uint16
	maxVersion  uint16
	clientAuth  tls.ClientAuthType
	checker     CertificateRevocationChecker
}

// Manager atomically replaces complete, immutable TLS policy snapshots. A
// failed reload leaves the last known-good snapshot active.
type Manager struct {
	role           managerRole
	serverConfig   ServerConfig
	clientConfig   ClientConfig
	state          atomic.Pointer[snapshot]
	reloadInterval time.Duration
	reloadMu       sync.Mutex
	lifecycleMu    sync.Mutex
	closed         bool
	cancel         context.CancelFunc
	reloadWG       sync.WaitGroup
	closeDone      chan struct{}
	callbackActive bool
}

var errManagerClosed = errors.New("transporttls: manager is closed")

func NewServerManager(config ServerConfig) (*Manager, error) {
	config = config.normalized()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if config.Mode == ModePlaintext {
		return nil, errors.New("transporttls: plaintext mode does not use a TLS manager")
	}
	interval, _ := time.ParseDuration(config.ReloadInterval)
	m := &Manager{role: serverRole, serverConfig: config, reloadInterval: interval, closeDone: make(chan struct{})}
	if err := m.Reload(); err != nil {
		return nil, err
	}
	return m, nil
}

func NewClientManager(config ClientConfig) (*Manager, error) {
	config = config.normalized()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	interval, _ := time.ParseDuration(config.ReloadInterval)
	m := &Manager{role: clientRole, clientConfig: config, reloadInterval: interval, closeDone: make(chan struct{})}
	if err := m.Reload(); err != nil {
		return nil, err
	}
	return m, nil
}

// Start begins periodic reload. onError may log failures and may safely call
// Close. At most one callback is active at a time; Close prevents any new
// callback from starting. A failure never replaces the active snapshot or
// interrupts established connections.
func (m *Manager) Start(parent context.Context, onError func(error)) {
	if m == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	m.lifecycleMu.Lock()
	if m.closed || m.cancel != nil {
		m.lifecycleMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	m.cancel = cancel
	m.reloadWG.Add(1)
	m.lifecycleMu.Unlock()
	go func() {
		defer m.reloadWG.Done()
		ticker := time.NewTicker(m.reloadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := m.Reload(); err != nil && !errors.Is(err, errManagerClosed) {
					m.dispatchReloadError(onError, err)
				}
			}
		}
	}()
}

func (m *Manager) dispatchReloadError(onError func(error), err error) {
	if onError == nil {
		return
	}
	m.lifecycleMu.Lock()
	if m.closed || m.callbackActive {
		m.lifecycleMu.Unlock()
		return
	}
	m.callbackActive = true
	m.lifecycleMu.Unlock()

	// Keep callbacks outside reloadWG so a callback may safely call Close.
	// The start handshake ensures Close cannot return before a callback that
	// was accepted before shutdown has actually begun; closed prevents any
	// later callback from being accepted.
	started := make(chan struct{})
	go func() {
		defer func() {
			m.lifecycleMu.Lock()
			m.callbackActive = false
			m.lifecycleMu.Unlock()
		}()
		close(started)
		onError(err)
	}()
	<-started
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.lifecycleMu.Lock()
	if m.closed {
		done := m.closeDone
		m.lifecycleMu.Unlock()
		if done != nil {
			<-done
		}
		return nil
	}
	m.closed = true
	cancel := m.cancel
	if m.closeDone == nil {
		m.closeDone = make(chan struct{})
	}
	done := m.closeDone
	m.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
	}
	// Wait for any in-flight or queued reload before waiting for the periodic
	// worker. Reload re-checks closed after loading, so a snapshot prepared
	// concurrently with Close can never be published.
	m.reloadMu.Lock()
	m.reloadMu.Unlock()
	m.reloadWG.Wait()
	close(done)
	return nil
}

// Reload parses every configured certificate, root, pin, and denylist before
// publishing one complete snapshot.
func (m *Manager) Reload() error {
	if m == nil {
		return errors.New("transporttls: nil manager")
	}
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	if m.isClosed() {
		return errManagerClosed
	}
	var (
		next *snapshot
		err  error
	)
	switch m.role {
	case serverRole:
		next, err = loadServerSnapshot(m.serverConfig)
	case clientRole:
		next, err = loadClientSnapshot(m.clientConfig)
	default:
		err = errors.New("transporttls: invalid manager role")
	}
	if err != nil {
		return err
	}
	if m.isClosed() {
		return errManagerClosed
	}
	m.state.Store(next)
	return nil
}

func (m *Manager) isClosed() bool {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	return m.closed
}

func loadServerSnapshot(config ServerConfig) (*snapshot, error) {
	cert, err := loadCertificate(config.CertFile, config.KeyFile, serverCertificate)
	if err != nil {
		return nil, fmt.Errorf("load server TLS certificate: %w", err)
	}
	min, _ := ParseVersion(config.MinVersion)
	max, err := optionalVersion(config.MaxVersion)
	if err != nil {
		return nil, err
	}
	next := &snapshot{certificate: cert, minVersion: min, maxVersion: max, checker: config.Checker}
	if config.Mode == ModeMTLS {
		next.roots, err = loadCertPool(config.ClientCAFile, false)
		if err != nil {
			return nil, fmt.Errorf("load client CA: %w", err)
		}
		next.clientAuth = tls.RequireAndVerifyClientCert
		next.pins, err = parsePins(config.ClientCAPinsSHA256)
		if err != nil {
			return nil, err
		}
		next.revoked, err = loadRevoked(config.Revocation)
		if err != nil {
			return nil, err
		}
	} else {
		next.clientAuth = tls.NoClientCert
	}
	return next, nil
}

func loadClientSnapshot(config ClientConfig) (*snapshot, error) {
	min, _ := ParseVersion(config.MinVersion)
	max, err := optionalVersion(config.MaxVersion)
	if err != nil {
		return nil, err
	}
	roots, err := loadCertPool(config.CAFile, true)
	if err != nil {
		return nil, fmt.Errorf("load server CA: %w", err)
	}
	next := &snapshot{roots: roots, minVersion: min, maxVersion: max, checker: config.Checker}
	if strings.TrimSpace(config.CertFile) != "" {
		next.certificate, err = loadCertificate(config.CertFile, config.KeyFile, clientCertificate)
		if err != nil {
			return nil, fmt.Errorf("load client TLS certificate: %w", err)
		}
	}
	next.pins, err = parsePins(config.CAPinsSHA256)
	if err != nil {
		return nil, err
	}
	next.revoked, err = loadRevoked(config.Revocation)
	if err != nil {
		return nil, err
	}
	return next, nil
}

func loadCertificate(certFile, keyFile string, purpose certificatePurpose) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(strings.TrimSpace(certFile))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(strings.TrimSpace(keyFile))
	if err != nil {
		return nil, err
	}
	parsed, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}
	if err := validateEndpointCertificateChain(parsed, purpose, time.Now()); err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) != len(parsed) {
		return nil, errors.New("certificate chain changed while loading")
	}
	cert.Leaf = parsed[0]
	// Trust anchors are never needed on the wire. Keeping them in the input
	// enables strict full-chain validation while avoiding redundant root
	// certificates in TLS Certificate messages.
	if len(parsed) > 1 && isSelfSigned(parsed[len(parsed)-1]) {
		cert.Certificate = cert.Certificate[:len(cert.Certificate)-1]
	}
	return &cert, nil
}

func loadCertPool(path string, allowSystem bool) (*x509.CertPool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		if !allowSystem {
			return nil, errors.New("CA file is required")
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		return pool, nil
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	certificates, err := parseCertificatePEM(pemBytes)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	now := time.Now()
	seen := make(map[[sha256.Size]byte]struct{}, len(certificates))
	for index, cert := range certificates {
		if err := validateCurrentCertificate(cert, now); err != nil {
			return nil, fmt.Errorf("CA certificate %d: %w", index, err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("CA certificate %d is not authorized to sign certificates", index)
		}
		fingerprint := sha256.Sum256(cert.Raw)
		if _, ok := seen[fingerprint]; ok {
			return nil, fmt.Errorf("CA certificate %d duplicates an earlier certificate", index)
		}
		seen[fingerprint] = struct{}{}
		pool.AddCert(cert)
	}
	return pool, nil
}

func parseCertificatePEM(data []byte) ([]*x509.Certificate, error) {
	remaining := data
	var certificates []*x509.Certificate
	for {
		remaining = bytes.TrimSpace(remaining)
		if len(remaining) == 0 {
			break
		}
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("certificate PEM contains malformed or trailing data")
		}
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, errors.New("certificate PEM contains a malformed block")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("certificate PEM contains unsupported block %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %d: %w", len(certificates), err)
		}
		certificates = append(certificates, cert)
		remaining = rest
	}
	if len(certificates) == 0 {
		return nil, errors.New("certificate PEM contains no certificates")
	}
	return certificates, nil
}

func validateEndpointCertificateChain(certificates []*x509.Certificate, purpose certificatePurpose, now time.Time) error {
	if len(certificates) < 2 {
		return errors.New("certificate chain must contain a leaf followed by at least one CA certificate")
	}
	leaf := certificates[0]
	if leaf.BasicConstraintsValid && leaf.IsCA {
		return errors.New("certificate chain leaf must be an end-entity certificate")
	}
	seen := make(map[[sha256.Size]byte]struct{}, len(certificates))
	for index, cert := range certificates {
		if err := validateCurrentCertificate(cert, now); err != nil {
			return fmt.Errorf("certificate %d: %w", index, err)
		}
		fingerprint := sha256.Sum256(cert.Raw)
		if _, ok := seen[fingerprint]; ok {
			return fmt.Errorf("certificate %d duplicates an earlier certificate", index)
		}
		seen[fingerprint] = struct{}{}
		if index == 0 {
			continue
		}
		if !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("certificate %d is not an authorized CA", index)
		}
		if err := certificates[index-1].CheckSignatureFrom(cert); err != nil {
			return fmt.Errorf("certificate %d does not issue certificate %d: %w", index, index-1, err)
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificates[len(certificates)-1])
	intermediates := x509.NewCertPool()
	for _, cert := range certificates[1 : len(certificates)-1] {
		intermediates.AddCert(cert)
	}
	usage := x509.ExtKeyUsageServerAuth
	if purpose == clientCertificate {
		usage = x509.ExtKeyUsageClientAuth
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{usage},
	}); err != nil {
		return fmt.Errorf("verify certificate chain: %w", err)
	}
	return nil
}

func validateCurrentCertificate(cert *x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not valid before %s", cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(cert.NotAfter) {
		return fmt.Errorf("certificate expired at %s", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

func parsePins(values []string) (map[[sha256.Size]byte]struct{}, error) {
	if len(values) == 0 {
		return nil, nil
	}
	pins := make(map[[sha256.Size]byte]struct{}, len(values))
	for _, value := range values {
		decoded, err := hex.DecodeString(normalizeFingerprint(value))
		if err != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf("invalid CA SHA-256 pin %q", value)
		}
		var pin [sha256.Size]byte
		copy(pin[:], decoded)
		pins[pin] = struct{}{}
	}
	return pins, nil
}

func loadRevoked(config RevocationConfig) (map[string]struct{}, error) {
	if strings.ToLower(strings.TrimSpace(config.Mode)) != RevocationSerialDenylist {
		return nil, nil
	}
	f, err := os.Open(strings.TrimSpace(config.SerialFile))
	if err != nil {
		return nil, fmt.Errorf("load TLS revocation serial denylist: %w", err)
	}
	defer f.Close()
	revoked := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		serial := new(big.Int)
		line = strings.TrimPrefix(strings.ToLower(line), "0x")
		if _, ok := serial.SetString(line, 16); !ok || serial.Sign() < 0 {
			return nil, fmt.Errorf("invalid revoked certificate serial %q", line)
		}
		revoked[serial.Text(16)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return revoked, nil
}

func optionalVersion(text string) (uint16, error) {
	if strings.TrimSpace(text) == "" {
		return 0, nil
	}
	return ParseVersion(text)
}

// ServerTLSConfig returns a stable dispatcher. Each new handshake receives the
// latest immutable configuration snapshot through GetConfigForClient.
func (m *Manager) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			state := m.state.Load()
			if state == nil || state.certificate == nil {
				return nil, errors.New("transporttls: server TLS certificate is unavailable")
			}
			return state.certificate, nil
		},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return m.currentServerTLSConfig()
		},
	}
}

func (m *Manager) currentServerTLSConfig() (*tls.Config, error) {
	state := m.state.Load()
	if state == nil || state.certificate == nil {
		return nil, errors.New("transporttls: server TLS state is unavailable")
	}
	config := &tls.Config{
		MinVersion:   state.minVersion,
		MaxVersion:   state.maxVersion,
		Certificates: []tls.Certificate{*state.certificate},
		ClientAuth:   state.clientAuth,
		ClientCAs:    state.roots,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	if state.clientAuth != tls.NoClientCert {
		config.VerifyConnection = state.verifyConnection
	}
	return config, nil
}

// ClientTLSConfig returns a current immutable client-side snapshot. Hostname
// verification remains Go's standard verification and is never bypassed.
func (m *Manager) ClientTLSConfig(serverName string) (*tls.Config, error) {
	state := m.state.Load()
	if state == nil {
		return nil, errors.New("transporttls: client TLS state is unavailable")
	}
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		serverName = strings.TrimSpace(m.clientConfig.ServerName)
	}
	config := &tls.Config{
		MinVersion: state.minVersion,
		MaxVersion: state.maxVersion,
		RootCAs:    state.roots,
		ServerName: serverName,
		NextProtos: []string{"h2", "http/1.1"},
	}
	if state.certificate != nil {
		config.Certificates = []tls.Certificate{*state.certificate}
	}
	config.VerifyConnection = state.verifyConnection
	return config, nil
}

func (s *snapshot) verifyConnection(cs tls.ConnectionState) error {
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return errors.New("transporttls: verified certificate chain is unavailable")
	}
	if len(s.pins) > 0 {
		matched := false
		for _, chain := range cs.VerifiedChains {
			root := chain[len(chain)-1]
			fingerprint := sha256.Sum256(root.Raw)
			if _, ok := s.pins[fingerprint]; ok {
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("transporttls: verified chain does not match a configured CA pin")
		}
	}
	if len(s.revoked) > 0 {
		for _, chain := range cs.VerifiedChains {
			for _, cert := range chain[:len(chain)-1] {
				if _, ok := s.revoked[cert.SerialNumber.Text(16)]; ok {
					return fmt.Errorf("transporttls: certificate serial %s is revoked", cert.SerialNumber.Text(16))
				}
			}
		}
	}
	if s.checker != nil {
		if err := s.checker.CheckCertificate(cs.VerifiedChains[0][0], cs.VerifiedChains); err != nil {
			return fmt.Errorf("transporttls: revocation policy: %w", err)
		}
	}
	return nil
}

// DialTLSContext performs a client handshake with the latest snapshot. It is
// suitable for http.Transport.DialTLSContext.
func (m *Manager) DialTLSContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{}
	raw, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	serverName := strings.TrimSpace(m.clientConfig.ServerName)
	if serverName == "" {
		serverName, _, err = net.SplitHostPort(address)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
	}
	config, err := m.ClientTLSConfig(serverName)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	conn := tls.Client(raw, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

// TransportCredentials returns reload-aware gRPC client credentials.
func (m *Manager) TransportCredentials() credentials.TransportCredentials {
	return &dynamicCredentials{manager: m}
}

type dynamicCredentials struct {
	manager  *Manager
	override atomic.Value
}

func (c *dynamicCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	serverName := ""
	if value := c.override.Load(); value != nil {
		serverName, _ = value.(string)
	}
	if serverName == "" {
		serverName = strings.TrimSpace(c.manager.clientConfig.ServerName)
	}
	if serverName == "" {
		serverName = authority
		if host, _, err := net.SplitHostPort(authority); err == nil {
			serverName = host
		}
	}
	config, err := c.manager.ClientTLSConfig(serverName)
	if err != nil {
		return nil, nil, err
	}
	conn := tls.Client(rawConn, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, nil, err
	}
	return conn, credentials.TLSInfo{State: conn.ConnectionState(), CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity}}, nil
}

func (c *dynamicCredentials) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("transporttls: dynamic client credentials cannot accept server handshakes")
}

func (c *dynamicCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls", SecurityVersion: "1.2+"}
}

func (c *dynamicCredentials) Clone() credentials.TransportCredentials {
	clone := &dynamicCredentials{manager: c.manager}
	if value := c.override.Load(); value != nil {
		clone.override.Store(value)
	}
	return clone
}

func (c *dynamicCredentials) OverrideServerName(name string) error {
	c.override.Store(strings.TrimSpace(name))
	return nil
}

// VersionName returns a stable health/audit label.
func VersionName(version uint16) string {
	switch version {
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return ""
	}
}
