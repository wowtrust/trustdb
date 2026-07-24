// Package fiscobcos defines the immutable TrustDB-to-FISCO-BCOS anchor
// protocol. Network submission and native receipt/finality verification live
// in later layers; this package owns the canonical payload, local trust
// configuration, and versioned proof envelope they must share.
package fiscobcos

import (
	"errors"
	"fmt"
)

const (
	SinkName = "fisco-bcos"

	SchemaTrustConfig = "trustdb.fisco-bcos-trust-config.v1"
	SchemaAnchorProof = "trustdb.fisco-bcos-anchor-proof.v1"

	PayloadVersion uint16 = 1
	ProofVersion   uint64 = 1

	DomainStreamID      = "trustdb/fisco-bcos/stream/v1"
	DomainAnchorID      = "trustdb/fisco-bcos/sth-anchor/v1"
	DomainChainContext  = "trustdb/fisco-bcos/chain-context/v1"
	DomainTrustConfig   = "trustdb/fisco-bcos/trust-config/v1"
	DomainValidatorSet  = "trustdb/fisco-bcos/validator-set/v1"
	QuorumPolicyPBFTV1  = "fisco-bcos-pbft-2f-plus-1-v1"
	StandardAccountAlg  = "ecdsa-secp256k1"
	StandardKeyEncoding = "sec1-uncompressed-65-byte-secp256k1"
	GuomiAccountAlg     = "sm2-sm3"
	GuomiKeyEncoding    = "sec1-uncompressed-65-byte-sm2p256v1"
	StandardTransport   = "tls"
	GuomiTransport      = "gm-tls"
	HashKeccak256       = "keccak256"
)

type CryptoMode string

const (
	CryptoModeStandard CryptoMode = "standard"
	CryptoModeGuomi    CryptoMode = "guomi"
)

type ModeParameters struct {
	Mode                    CryptoMode
	ProtocolHashAlgorithm   string
	ChainHashAlgorithm      string
	ChainSignatureAlgorithm string
	PublicKeyEncoding       string
	TransportMode           string
}

var (
	ErrInvalidPayload     = errors.New("invalid FISCO BCOS anchor payload")
	ErrInvalidTrustConfig = errors.New("invalid FISCO BCOS trust configuration")
	ErrInvalidProof       = errors.New("invalid FISCO BCOS anchor proof")
)

func ParametersForMode(mode CryptoMode) (ModeParameters, error) {
	switch mode {
	case CryptoModeStandard:
		return ModeParameters{
			Mode:                    mode,
			ProtocolHashAlgorithm:   "sha256",
			ChainHashAlgorithm:      HashKeccak256,
			ChainSignatureAlgorithm: StandardAccountAlg,
			PublicKeyEncoding:       StandardKeyEncoding,
			TransportMode:           StandardTransport,
		}, nil
	case CryptoModeGuomi:
		return ModeParameters{
			Mode:                    mode,
			ProtocolHashAlgorithm:   "sm3",
			ChainHashAlgorithm:      "sm3",
			ChainSignatureAlgorithm: GuomiAccountAlg,
			PublicKeyEncoding:       GuomiKeyEncoding,
			TransportMode:           GuomiTransport,
		}, nil
	default:
		return ModeParameters{}, fmt.Errorf("%w: unsupported crypto_mode %q", ErrInvalidTrustConfig, mode)
	}
}

func validateExplicitModeParameters(mode CryptoMode, protocolHash, chainHash, chainSignature string) error {
	want, err := ParametersForMode(mode)
	if err != nil {
		return err
	}
	if protocolHash != want.ProtocolHashAlgorithm {
		return fmt.Errorf("%w: crypto_mode %s requires protocol_hash_algorithm=%s, got %q", ErrInvalidTrustConfig, mode, want.ProtocolHashAlgorithm, protocolHash)
	}
	if chainHash != want.ChainHashAlgorithm {
		return fmt.Errorf("%w: crypto_mode %s requires chain_hash_algorithm=%s, got %q", ErrInvalidTrustConfig, mode, want.ChainHashAlgorithm, chainHash)
	}
	if chainSignature != want.ChainSignatureAlgorithm {
		return fmt.Errorf("%w: crypto_mode %s requires chain_signature_algorithm=%s, got %q", ErrInvalidTrustConfig, mode, want.ChainSignatureAlgorithm, chainSignature)
	}
	return nil
}
