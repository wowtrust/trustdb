// Package transporttls provides TLS transport policy for TrustDB listeners and
// clients. Transport certificate roots are deliberately independent from the
// proof-signing keys used by the evidence verifier.
package transporttls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ModePlaintext = "plaintext"
	ModeTLS       = "tls"
	ModeMTLS      = "mtls"

	RevocationOff            = "off"
	RevocationSerialDenylist = "serial_denylist"
)

// RevocationConfig configures the built-in reloadable serial-number denylist.
// SerialFile contains one hexadecimal certificate serial number per line.
type RevocationConfig struct {
	Mode       string `mapstructure:"mode" json:"mode"`
	SerialFile string `mapstructure:"serial_file" json:"serial_file"`
}

// ServerConfig configures one TLS policy shared by HTTP and gRPC listeners.
type ServerConfig struct {
	Mode               string                       `mapstructure:"mode" json:"mode"`
	CertFile           string                       `mapstructure:"cert_file" json:"cert_file"`
	KeyFile            string                       `mapstructure:"key_file" json:"key_file"`
	ClientCAFile       string                       `mapstructure:"client_ca_file" json:"client_ca_file"`
	ClientCAPinsSHA256 []string                     `mapstructure:"client_ca_pins_sha256" json:"client_ca_pins_sha256"`
	MinVersion         string                       `mapstructure:"min_version" json:"min_version"`
	MaxVersion         string                       `mapstructure:"max_version" json:"max_version"`
	ReloadInterval     string                       `mapstructure:"reload_interval" json:"reload_interval"`
	Revocation         RevocationConfig             `mapstructure:"revocation" json:"revocation"`
	Checker            CertificateRevocationChecker `mapstructure:"-" json:"-"`
}

// ClientConfig configures server authentication, optional client
// authentication, CA pinning, and certificate reload for SDK transports.
type ClientConfig struct {
	CAFile         string                       `json:"ca_file"`
	CAPinsSHA256   []string                     `json:"ca_pins_sha256"`
	CertFile       string                       `json:"cert_file"`
	KeyFile        string                       `json:"key_file"`
	ServerName     string                       `json:"server_name"`
	MinVersion     string                       `json:"min_version"`
	MaxVersion     string                       `json:"max_version"`
	ReloadInterval string                       `json:"reload_interval"`
	ReloadError    func(error)                  `json:"-"`
	Revocation     RevocationConfig             `json:"revocation"`
	Checker        CertificateRevocationChecker `json:"-"`
}

// CertificateRevocationChecker receives an already verified leaf and chain.
// It is suitable for OCSP/CRL integrations that are not represented by the
// built-in serial denylist.
type CertificateRevocationChecker interface {
	CheckCertificate(leaf *x509.Certificate, verifiedChains [][]*x509.Certificate) error
}

func (c ServerConfig) normalized() ServerConfig {
	c.Mode = strings.ToLower(strings.TrimSpace(c.Mode))
	if c.Mode == "" {
		c.Mode = ModePlaintext
	}
	c.MinVersion = defaultString(c.MinVersion, "1.2")
	c.ReloadInterval = defaultString(c.ReloadInterval, "1m")
	c.Revocation.Mode = strings.ToLower(strings.TrimSpace(c.Revocation.Mode))
	if c.Revocation.Mode == "" {
		c.Revocation.Mode = RevocationOff
	}
	return c
}

func (c ClientConfig) normalized() ClientConfig {
	c.MinVersion = defaultString(c.MinVersion, "1.2")
	c.ReloadInterval = defaultString(c.ReloadInterval, "1m")
	c.Revocation.Mode = strings.ToLower(strings.TrimSpace(c.Revocation.Mode))
	if c.Revocation.Mode == "" {
		c.Revocation.Mode = RevocationOff
	}
	return c
}

func (c ServerConfig) Validate() error {
	c = c.normalized()
	switch c.Mode {
	case ModePlaintext:
		return nil
	case ModeTLS, ModeMTLS:
	default:
		return fmt.Errorf("transport TLS mode must be plaintext, tls, or mtls")
	}
	if strings.TrimSpace(c.CertFile) == "" || strings.TrimSpace(c.KeyFile) == "" {
		return errors.New("transport TLS cert_file and key_file are required")
	}
	if c.Mode == ModeMTLS && strings.TrimSpace(c.ClientCAFile) == "" {
		return errors.New("transport TLS client_ca_file is required in mtls mode")
	}
	if err := validateCommon(c.MinVersion, c.MaxVersion, c.ReloadInterval, c.ClientCAPinsSHA256, c.Revocation); err != nil {
		return err
	}
	if c.Mode != ModeMTLS && c.Revocation.Mode != RevocationOff {
		return errors.New("transport TLS client revocation policy requires mtls mode")
	}
	return nil
}

func (c ClientConfig) Validate() error {
	c = c.normalized()
	if (strings.TrimSpace(c.CertFile) == "") != (strings.TrimSpace(c.KeyFile) == "") {
		return errors.New("transport TLS client cert_file and key_file must be configured together")
	}
	return validateCommon(c.MinVersion, c.MaxVersion, c.ReloadInterval, c.CAPinsSHA256, c.Revocation)
}

func validateCommon(minText, maxText, reloadText string, pins []string, revocation RevocationConfig) error {
	min, err := ParseVersion(minText)
	if err != nil {
		return fmt.Errorf("transport TLS min_version: %w", err)
	}
	max := uint16(0)
	if strings.TrimSpace(maxText) != "" {
		max, err = ParseVersion(maxText)
		if err != nil {
			return fmt.Errorf("transport TLS max_version: %w", err)
		}
	}
	if max != 0 && max < min {
		return errors.New("transport TLS max_version must be greater than or equal to min_version")
	}
	d, err := time.ParseDuration(strings.TrimSpace(reloadText))
	if err != nil || d <= 0 {
		return errors.New("transport TLS reload_interval must be a positive duration")
	}
	for _, pin := range pins {
		pin = normalizeFingerprint(pin)
		decoded, err := hex.DecodeString(pin)
		if err != nil || len(decoded) != 32 {
			return fmt.Errorf("transport TLS CA pin %q must be a SHA-256 fingerprint", pin)
		}
	}
	switch strings.ToLower(strings.TrimSpace(revocation.Mode)) {
	case "", RevocationOff:
	case RevocationSerialDenylist:
		if strings.TrimSpace(revocation.SerialFile) == "" {
			return errors.New("transport TLS revocation.serial_file is required for serial_denylist mode")
		}
	default:
		return errors.New("transport TLS revocation.mode must be off or serial_denylist")
	}
	return nil
}

// ParseVersion accepts only TLS 1.2 and TLS 1.3. Older protocol versions are
// intentionally unavailable even when a caller supplies an explicit value.
func ParseVersion(text string) (uint16, error) {
	switch strings.TrimSpace(strings.ToLower(text)) {
	case "1.2", "tls1.2", "tls12":
		return tls.VersionTLS12, nil
	case "1.3", "tls1.3", "tls13":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("must be 1.2 or 1.3")
	}
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func normalizeFingerprint(value string) string {
	replacer := strings.NewReplacer(":", "", " ", "", "-", "")
	return strings.ToLower(replacer.Replace(strings.TrimSpace(value)))
}
