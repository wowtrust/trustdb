package transporttls

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
	lifecycleMu    sync.Mutex
	closed         bool
	cancel         context.CancelFunc
}

func NewServerManager(config ServerConfig) (*Manager, error) {
	config = config.normalized()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if config.Mode == ModePlaintext {
		return nil, errors.New("transporttls: plaintext mode does not use a TLS manager")
	}
	interval, _ := time.ParseDuration(config.ReloadInterval)
	m := &Manager{role: serverRole, serverConfig: config, reloadInterval: interval}
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
	m := &Manager{role: clientRole, clientConfig: config, reloadInterval: interval}
	if err := m.Reload(); err != nil {
		return nil, err
	}
	return m, nil
}

// Start begins periodic reload. onError may log failures; a failure never
// replaces the active snapshot or interrupts established connections.
func (m *Manager) Start(parent context.Context, onError func(error)) {
	if m == nil {
		return
	}
	m.lifecycleMu.Lock()
	if m.closed || m.cancel != nil {
		m.lifecycleMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	m.cancel = cancel
	m.lifecycleMu.Unlock()
	go func() {
		ticker := time.NewTicker(m.reloadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := m.Reload(); err != nil && onError != nil {
					onError(err)
				}
			}
		}
	}()
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.lifecycleMu.Lock()
	if m.closed {
		m.lifecycleMu.Unlock()
		return nil
	}
	m.closed = true
	cancel := m.cancel
	m.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

// Reload parses every configured certificate, root, pin, and denylist before
// publishing one complete snapshot.
func (m *Manager) Reload() error {
	if m == nil {
		return errors.New("transporttls: nil manager")
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
	m.state.Store(next)
	return nil
}

func loadServerSnapshot(config ServerConfig) (*snapshot, error) {
	cert, err := loadCertificate(config.CertFile, config.KeyFile, true)
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
		next.certificate, err = loadCertificate(config.CertFile, config.KeyFile, true)
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

func loadCertificate(certFile, keyFile string, requireCurrent bool) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(strings.TrimSpace(certFile), strings.TrimSpace(keyFile))
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	if requireCurrent {
		now := time.Now()
		if now.Before(leaf.NotBefore) {
			return nil, fmt.Errorf("certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
		}
		if !now.Before(leaf.NotAfter) {
			return nil, fmt.Errorf("certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	cert.Leaf = leaf
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
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("CA file contains no certificates")
	}
	return pool, nil
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
