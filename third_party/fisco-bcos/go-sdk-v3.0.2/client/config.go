package client

import (
	"fmt"
)

// Config contains configuration items for sdk
type Config struct {
	TLSCaFile       string
	TLSKeyFile      string
	TLSCertFile     string
	TLSSmEnKeyFile  string
	TLSSmEnCertFile string
	IsSMCrypto      bool
	PrivateKey      []byte
	GroupID         string
	Host            string
	Port            int
	DisableSsl      bool
	// TLSCaContext   []byte
	// TLSKeyContext  []byte
	// TLSCertContext []byte
}

// ParseConfigOptions parses from arguments
func ParseConfigOptions(caFile string, key string, cert, keyFile string, groupId string, host string, port int, isSMCrypto bool) (*Config, error) {
	config := Config{
		TLSCaFile:   caFile,
		TLSKeyFile:  key,
		TLSCertFile: cert,
		IsSMCrypto:  isSMCrypto,
		GroupID:     groupId,
		Host:        host,
		Port:        port,
	}
	keyBytes, curve, err := LoadECPrivateKeyFromPEM(keyFile)
	if err != nil {
		return nil, fmt.Errorf("parse private key failed, err: %v", err)
	}
	if config.IsSMCrypto && curve != Sm2p256v1 {
		return nil, fmt.Errorf("smcrypto should use sm2p256v1 private key, but found %s", curve)
	}
	if !config.IsSMCrypto && curve != Secp256k1 {
		return nil, fmt.Errorf("must should secp256k1 private key, but found %s", curve)
	}
	config.PrivateKey = keyBytes
	return &config, nil
}
