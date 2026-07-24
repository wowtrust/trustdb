package fiscobcos

import (
	"bytes"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

const (
	MaxTrustConfigBytes = 4 << 20
	maxConfigString     = 4096
	maxEndpoints        = 32
	maxValidators       = 1024
	maxCertificatePins  = 64
)

type BlockCheckpoint struct {
	BlockNumber uint64 `cbor:"block_number" json:"block_number"`
	BlockHash   []byte `cbor:"block_hash" json:"block_hash"`
}

type ContractBinding struct {
	Address         []byte `cbor:"address" json:"address"`
	CodeHash        []byte `cbor:"code_hash" json:"code_hash"`
	ProtocolVersion string `cbor:"protocol_version" json:"protocol_version"`
	EventSignature  string `cbor:"event_signature" json:"event_signature"`
}

type AccountProviderConfig struct {
	Provider     string `cbor:"provider" json:"provider"`
	KeyID        string `cbor:"key_id" json:"key_id"`
	KeyReference string `cbor:"key_reference" json:"key_reference"`
	Algorithm    string `cbor:"algorithm" json:"algorithm"`
}

// CertificateConfig stores references and public certificate fingerprints,
// never private key bytes. Guomi mode requires independent signing and
// encryption certificate/key references.
type CertificateConfig struct {
	TransportMode                  string   `cbor:"transport_mode" json:"transport_mode"`
	TrustedCAReferences            []string `cbor:"trusted_ca_references" json:"trusted_ca_references"`
	TrustedCACertificateHashes     [][]byte `cbor:"trusted_ca_certificate_hashes" json:"trusted_ca_certificate_hashes"`
	PinnedPeerCertificateHashes    [][]byte `cbor:"pinned_peer_certificate_hashes,omitempty" json:"pinned_peer_certificate_hashes,omitempty"`
	ClientSigningCertificateRef    string   `cbor:"client_signing_certificate_ref" json:"client_signing_certificate_ref"`
	ClientSigningKeyRef            string   `cbor:"client_signing_key_ref" json:"client_signing_key_ref"`
	ClientEncryptionCertificateRef string   `cbor:"client_encryption_certificate_ref,omitempty" json:"client_encryption_certificate_ref,omitempty"`
	ClientEncryptionKeyRef         string   `cbor:"client_encryption_key_ref,omitempty" json:"client_encryption_key_ref,omitempty"`
}

type ValidatorDescriptor struct {
	NodeID            string `cbor:"node_id" json:"node_id"`
	Algorithm         string `cbor:"algorithm" json:"algorithm"`
	PublicKeyEncoding string `cbor:"public_key_encoding" json:"public_key_encoding"`
	PublicKey         []byte `cbor:"public_key" json:"public_key"`
}

// TrustConfig is supplied locally by the publisher/verifier. AnchorProof does
// not contain validators, certificate roots, account references, or endpoint
// credentials, so evidence can never promote its own trust material.
type TrustConfig struct {
	SchemaVersion           string                `cbor:"schema_version" json:"schema_version"`
	CryptoMode              CryptoMode            `cbor:"crypto_mode" json:"crypto_mode"`
	ProtocolHashAlgorithm   string                `cbor:"protocol_hash_algorithm" json:"protocol_hash_algorithm"`
	ChainHashAlgorithm      string                `cbor:"chain_hash_algorithm" json:"chain_hash_algorithm"`
	ChainSignatureAlgorithm string                `cbor:"chain_signature_algorithm" json:"chain_signature_algorithm"`
	ChainID                 string                `cbor:"chain_id" json:"chain_id"`
	GroupID                 string                `cbor:"group_id" json:"group_id"`
	GenesisHash             []byte                `cbor:"genesis_hash" json:"genesis_hash"`
	TrustedCheckpoint       BlockCheckpoint       `cbor:"trusted_checkpoint" json:"trusted_checkpoint"`
	Contract                ContractBinding       `cbor:"contract" json:"contract"`
	Endpoints               []string              `cbor:"endpoints" json:"endpoints"`
	ReadQuorum              uint32                `cbor:"read_quorum" json:"read_quorum"`
	AccountProvider         AccountProviderConfig `cbor:"account_provider" json:"account_provider"`
	Certificates            CertificateConfig     `cbor:"certificates" json:"certificates"`
	ValidatorQuorumPolicy   string                `cbor:"validator_quorum_policy" json:"validator_quorum_policy"`
	Validators              []ValidatorDescriptor `cbor:"validators" json:"validators"`
	SM2UserID               string                `cbor:"sm2_user_id,omitempty" json:"sm2_user_id,omitempty"`
}

func NewTrustConfig(mode CryptoMode) (TrustConfig, error) {
	params, err := ParametersForMode(mode)
	if err != nil {
		return TrustConfig{}, err
	}
	config := TrustConfig{
		SchemaVersion:           SchemaTrustConfig,
		CryptoMode:              mode,
		ProtocolHashAlgorithm:   params.ProtocolHashAlgorithm,
		ChainHashAlgorithm:      params.ChainHashAlgorithm,
		ChainSignatureAlgorithm: params.ChainSignatureAlgorithm,
		ValidatorQuorumPolicy:   QuorumPolicyPBFTV1,
	}
	config.AccountProvider.Algorithm = params.ChainSignatureAlgorithm
	config.Certificates.TransportMode = params.TransportMode
	if mode == CryptoModeGuomi {
		config.SM2UserID = cryptosuite.SM2DefaultUserID
	}
	return config, nil
}

func MarshalTrustConfig(config TrustConfig) ([]byte, error) {
	canonical, err := canonicalTrustConfig(config)
	if err != nil {
		return nil, err
	}
	data, err := cborx.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("%w: encode canonical config: %v", ErrInvalidTrustConfig, err)
	}
	if len(data) > MaxTrustConfigBytes {
		return nil, fmt.Errorf("%w: encoded config is %d bytes, limit %d", ErrInvalidTrustConfig, len(data), MaxTrustConfigBytes)
	}
	return data, nil
}

func UnmarshalTrustConfig(data []byte) (TrustConfig, error) {
	var config TrustConfig
	if err := cborx.UnmarshalLimit(data, &config, MaxTrustConfigBytes); err != nil {
		return TrustConfig{}, fmt.Errorf("%w: decode config: %v", ErrInvalidTrustConfig, err)
	}
	canonical, err := canonicalTrustConfig(config)
	if err != nil {
		return TrustConfig{}, err
	}
	return canonical, nil
}

func TrustConfigDigest(config TrustConfig) ([]byte, error) {
	data, err := MarshalTrustConfig(config)
	if err != nil {
		return nil, err
	}
	params, _ := ParametersForMode(config.CryptoMode)
	framed, err := frameDomain(DomainTrustConfig, []byte(params.ProtocolHashAlgorithm), data)
	if err != nil {
		return nil, err
	}
	return hashForMode(config.CryptoMode, framed)
}

type chainContextBinding struct {
	SchemaVersion           string          `cbor:"schema_version"`
	CryptoMode              CryptoMode      `cbor:"crypto_mode"`
	ProtocolHashAlgorithm   string          `cbor:"protocol_hash_algorithm"`
	ChainHashAlgorithm      string          `cbor:"chain_hash_algorithm"`
	ChainSignatureAlgorithm string          `cbor:"chain_signature_algorithm"`
	ChainID                 string          `cbor:"chain_id"`
	GroupID                 string          `cbor:"group_id"`
	GenesisHash             []byte          `cbor:"genesis_hash"`
	TrustedCheckpoint       BlockCheckpoint `cbor:"trusted_checkpoint"`
	Contract                ContractBinding `cbor:"contract"`
	ValidatorSetDigest      []byte          `cbor:"validator_set_digest"`
}

func ChainContextID(config TrustConfig) ([]byte, error) {
	canonical, err := canonicalTrustConfig(config)
	if err != nil {
		return nil, err
	}
	validatorData, err := cborx.Marshal(struct {
		QuorumPolicy string                `cbor:"quorum_policy"`
		SM2UserID    string                `cbor:"sm2_user_id,omitempty"`
		Validators   []ValidatorDescriptor `cbor:"validators"`
	}{canonical.ValidatorQuorumPolicy, canonical.SM2UserID, canonical.Validators})
	if err != nil {
		return nil, fmt.Errorf("%w: encode validator set: %v", ErrInvalidTrustConfig, err)
	}
	validatorFrame, err := frameDomain(DomainValidatorSet, []byte(canonical.ProtocolHashAlgorithm), validatorData)
	if err != nil {
		return nil, err
	}
	validatorDigest, err := hashForMode(canonical.CryptoMode, validatorFrame)
	if err != nil {
		return nil, err
	}
	context := chainContextBinding{
		SchemaVersion:           "trustdb.fisco-bcos-chain-context.v1",
		CryptoMode:              canonical.CryptoMode,
		ProtocolHashAlgorithm:   canonical.ProtocolHashAlgorithm,
		ChainHashAlgorithm:      canonical.ChainHashAlgorithm,
		ChainSignatureAlgorithm: canonical.ChainSignatureAlgorithm,
		ChainID:                 canonical.ChainID,
		GroupID:                 canonical.GroupID,
		GenesisHash:             canonical.GenesisHash,
		TrustedCheckpoint:       canonical.TrustedCheckpoint,
		Contract:                canonical.Contract,
		ValidatorSetDigest:      validatorDigest,
	}
	data, err := cborx.Marshal(context)
	if err != nil {
		return nil, fmt.Errorf("%w: encode chain context: %v", ErrInvalidTrustConfig, err)
	}
	framed, err := frameDomain(DomainChainContext, []byte(canonical.ProtocolHashAlgorithm), data)
	if err != nil {
		return nil, err
	}
	return hashForMode(canonical.CryptoMode, framed)
}

func canonicalTrustConfig(config TrustConfig) (TrustConfig, error) {
	if err := validateTrustConfig(config); err != nil {
		return TrustConfig{}, err
	}
	out := cloneTrustConfig(config)
	sort.Strings(out.Endpoints)
	sort.Strings(out.Certificates.TrustedCAReferences)
	sortByteSlices(out.Certificates.TrustedCACertificateHashes)
	sortByteSlices(out.Certificates.PinnedPeerCertificateHashes)
	sort.Slice(out.Validators, func(i, j int) bool { return out.Validators[i].NodeID < out.Validators[j].NodeID })
	return out, nil
}

func validateTrustConfig(config TrustConfig) error {
	if config.SchemaVersion != SchemaTrustConfig {
		return fmt.Errorf("%w: schema_version=%q", ErrInvalidTrustConfig, config.SchemaVersion)
	}
	if err := validateExplicitModeParameters(config.CryptoMode, config.ProtocolHashAlgorithm, config.ChainHashAlgorithm, config.ChainSignatureAlgorithm); err != nil {
		return err
	}
	params, _ := ParametersForMode(config.CryptoMode)
	for name, value := range map[string]string{
		"chain_id": config.ChainID, "group_id": config.GroupID,
		"contract.protocol_version":      config.Contract.ProtocolVersion,
		"contract.event_signature":       config.Contract.EventSignature,
		"account_provider.provider":      config.AccountProvider.Provider,
		"account_provider.key_id":        config.AccountProvider.KeyID,
		"account_provider.key_reference": config.AccountProvider.KeyReference,
	} {
		if err := validateConfigString(name, value); err != nil {
			return err
		}
	}
	if config.Contract.ProtocolVersion != TrustDBAnchorV1ProtocolVersion ||
		config.Contract.EventSignature != TrustDBAnchorV1EventSignature {
		return fmt.Errorf(
			"%w: contract must use exact %s protocol and %s event",
			ErrInvalidTrustConfig,
			TrustDBAnchorV1ProtocolVersion,
			TrustDBAnchorV1EventSignature,
		)
	}
	if len(config.GenesisHash) != identifierBytes || len(config.TrustedCheckpoint.BlockHash) != identifierBytes {
		return fmt.Errorf("%w: genesis_hash and trusted checkpoint hash must be %d bytes", ErrInvalidTrustConfig, identifierBytes)
	}
	if len(config.Contract.Address) != 20 || len(config.Contract.CodeHash) != identifierBytes {
		return fmt.Errorf("%w: contract address must be 20 bytes and code_hash %d bytes", ErrInvalidTrustConfig, identifierBytes)
	}
	if config.AccountProvider.Algorithm != params.ChainSignatureAlgorithm {
		return fmt.Errorf("%w: account provider algorithm %q does not match crypto_mode %s", ErrInvalidTrustConfig, config.AccountProvider.Algorithm, config.CryptoMode)
	}
	if len(config.Endpoints) == 0 || len(config.Endpoints) > maxEndpoints {
		return fmt.Errorf("%w: endpoints count=%d", ErrInvalidTrustConfig, len(config.Endpoints))
	}
	seenEndpoints := make(map[string]struct{}, len(config.Endpoints))
	for _, endpoint := range config.Endpoints {
		if err := validateEndpoint(endpoint); err != nil {
			return err
		}
		if _, exists := seenEndpoints[endpoint]; exists {
			return fmt.Errorf("%w: duplicate endpoint %q", ErrInvalidTrustConfig, endpoint)
		}
		seenEndpoints[endpoint] = struct{}{}
	}
	if config.ReadQuorum == 0 || int(config.ReadQuorum) > len(config.Endpoints) {
		return fmt.Errorf("%w: read_quorum=%d exceeds endpoint count %d", ErrInvalidTrustConfig, config.ReadQuorum, len(config.Endpoints))
	}
	if config.ValidatorQuorumPolicy != QuorumPolicyPBFTV1 {
		return fmt.Errorf("%w: validator_quorum_policy=%q", ErrInvalidTrustConfig, config.ValidatorQuorumPolicy)
	}
	if len(config.Validators) == 0 || len(config.Validators) > maxValidators {
		return fmt.Errorf("%w: validators count=%d", ErrInvalidTrustConfig, len(config.Validators))
	}
	seenValidators := make(map[string]struct{}, len(config.Validators))
	for _, validator := range config.Validators {
		if err := validateValidator(validator, params); err != nil {
			return err
		}
		if _, exists := seenValidators[validator.NodeID]; exists {
			return fmt.Errorf("%w: duplicate validator node_id %q", ErrInvalidTrustConfig, validator.NodeID)
		}
		seenValidators[validator.NodeID] = struct{}{}
	}
	if config.CryptoMode == CryptoModeGuomi {
		if config.SM2UserID != cryptosuite.SM2DefaultUserID {
			return fmt.Errorf("%w: Guomi mode requires fixed SM2 user ID %q", ErrInvalidTrustConfig, cryptosuite.SM2DefaultUserID)
		}
	} else if config.SM2UserID != "" {
		return fmt.Errorf("%w: standard mode must not set sm2_user_id", ErrInvalidTrustConfig)
	}
	return validateCertificates(config.Certificates, params)
}

func validateCertificates(certificates CertificateConfig, params ModeParameters) error {
	if certificates.TransportMode != params.TransportMode {
		return fmt.Errorf("%w: crypto_mode %s requires certificate transport_mode=%s", ErrInvalidTrustConfig, params.Mode, params.TransportMode)
	}
	if len(certificates.TrustedCAReferences) == 0 || len(certificates.TrustedCAReferences) > maxCertificatePins || len(certificates.TrustedCACertificateHashes) == 0 || len(certificates.TrustedCACertificateHashes) > maxCertificatePins {
		return fmt.Errorf("%w: at least one local CA reference and certificate hash are required", ErrInvalidTrustConfig)
	}
	for _, ref := range certificates.TrustedCAReferences {
		if err := validateConfigString("certificates.trusted_ca_reference", ref); err != nil {
			return err
		}
	}
	for _, digest := range append(cloneByteSlices(certificates.TrustedCACertificateHashes), certificates.PinnedPeerCertificateHashes...) {
		if len(digest) != identifierBytes {
			return fmt.Errorf("%w: certificate fingerprints must be %d bytes", ErrInvalidTrustConfig, identifierBytes)
		}
	}
	if err := validateConfigString("certificates.client_signing_certificate_ref", certificates.ClientSigningCertificateRef); err != nil {
		return err
	}
	if err := validateConfigString("certificates.client_signing_key_ref", certificates.ClientSigningKeyRef); err != nil {
		return err
	}
	if params.Mode == CryptoModeGuomi {
		if err := validateConfigString("certificates.client_encryption_certificate_ref", certificates.ClientEncryptionCertificateRef); err != nil {
			return err
		}
		if err := validateConfigString("certificates.client_encryption_key_ref", certificates.ClientEncryptionKeyRef); err != nil {
			return err
		}
	} else if certificates.ClientEncryptionCertificateRef != "" || certificates.ClientEncryptionKeyRef != "" {
		return fmt.Errorf("%w: standard mode must not set Guomi encryption certificate references", ErrInvalidTrustConfig)
	}
	return nil
}

func validateValidator(validator ValidatorDescriptor, params ModeParameters) error {
	if err := validateConfigString("validator.node_id", validator.NodeID); err != nil {
		return err
	}
	if validator.Algorithm != params.ChainSignatureAlgorithm || validator.PublicKeyEncoding != params.PublicKeyEncoding {
		return fmt.Errorf("%w: validator %q algorithm/encoding does not match crypto_mode %s", ErrInvalidTrustConfig, validator.NodeID, params.Mode)
	}
	if len(validator.PublicKey) != 65 || validator.PublicKey[0] != 0x04 {
		return fmt.Errorf("%w: validator %q public key must be canonical 65-byte uncompressed form", ErrInvalidTrustConfig, validator.NodeID)
	}
	return nil
}

func validateConfigString(name, value string) error {
	if strings.TrimSpace(value) == "" || len(value) > maxConfigString || !utf8.ValidString(value) || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return fmt.Errorf("%w: %s is empty, oversized, or contains control characters", ErrInvalidTrustConfig, name)
	}
	return nil
}

func validateEndpoint(endpoint string) error {
	if err := validateConfigString("endpoint", endpoint); err != nil {
		return err
	}
	if strings.Contains(endpoint, "@") {
		return fmt.Errorf("%w: endpoint must not contain user information", ErrInvalidTrustConfig)
	}
	if strings.Contains(endpoint, "://") {
		u, err := url.Parse(endpoint)
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
			return fmt.Errorf("%w: malformed endpoint %q", ErrInvalidTrustConfig, endpoint)
		}
	}
	return nil
}

func hashForMode(mode CryptoMode, data []byte) ([]byte, error) {
	params, err := ParametersForMode(mode)
	if err != nil {
		return nil, err
	}
	suiteID := cryptosuite.INTLV1
	if mode == CryptoModeGuomi {
		suiteID = cryptosuite.CNSMV1
	}
	digest, err := trustcrypto.HashBytesForSuite(suiteID, params.ProtocolHashAlgorithm, data)
	if err != nil {
		return nil, fmt.Errorf("%w: protocol hash: %v", ErrInvalidTrustConfig, err)
	}
	return digest, nil
}

func cloneTrustConfig(in TrustConfig) TrustConfig {
	out := in
	out.GenesisHash = append([]byte(nil), in.GenesisHash...)
	out.TrustedCheckpoint.BlockHash = append([]byte(nil), in.TrustedCheckpoint.BlockHash...)
	out.Contract.Address = append([]byte(nil), in.Contract.Address...)
	out.Contract.CodeHash = append([]byte(nil), in.Contract.CodeHash...)
	out.Endpoints = append([]string(nil), in.Endpoints...)
	out.Certificates.TrustedCAReferences = append([]string(nil), in.Certificates.TrustedCAReferences...)
	out.Certificates.TrustedCACertificateHashes = cloneByteSlices(in.Certificates.TrustedCACertificateHashes)
	out.Certificates.PinnedPeerCertificateHashes = cloneByteSlices(in.Certificates.PinnedPeerCertificateHashes)
	out.Validators = append([]ValidatorDescriptor(nil), in.Validators...)
	for i := range out.Validators {
		out.Validators[i].PublicKey = append([]byte(nil), in.Validators[i].PublicKey...)
	}
	return out
}

func cloneByteSlices(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = append([]byte(nil), in[i]...)
	}
	return out
}

func sortByteSlices(values [][]byte) {
	sort.Slice(values, func(i, j int) bool { return bytes.Compare(values[i], values[j]) < 0 })
}
