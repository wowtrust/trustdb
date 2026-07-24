package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const maxFISCOBCOSTrustConfigJSONBytes = 4 << 20

type fiscoBCOSTrustConfigInput struct {
	CryptoMode        string                              `json:"crypto_mode"`
	ChainID           string                              `json:"chain_id"`
	GroupID           string                              `json:"group_id"`
	GenesisHashHex    string                              `json:"genesis_hash_hex"`
	TrustedCheckpoint fiscoBCOSCheckpointInput            `json:"trusted_checkpoint"`
	Contract          fiscoBCOSContractInput              `json:"contract"`
	Endpoints         []string                            `json:"endpoints"`
	ReadQuorum        uint32                              `json:"read_quorum"`
	AccountProvider   fiscoBCOSAccountProviderInput       `json:"account_provider"`
	Certificates      fiscoBCOSCertificateInput           `json:"certificates"`
	Validators        []fiscoBCOSValidatorDescriptorInput `json:"validators"`
}

type fiscoBCOSCheckpointInput struct {
	BlockNumber  uint64 `json:"block_number"`
	BlockHashHex string `json:"block_hash_hex"`
}

type fiscoBCOSContractInput struct {
	AddressHex      string `json:"address_hex"`
	CodeHashHex     string `json:"code_hash_hex"`
	ProtocolVersion string `json:"protocol_version"`
	EventSignature  string `json:"event_signature"`
}

type fiscoBCOSAccountProviderInput struct {
	Provider     string `json:"provider"`
	KeyID        string `json:"key_id"`
	KeyReference string `json:"key_reference"`
}

type fiscoBCOSCertificateInput struct {
	TrustedCAReferences            []string `json:"trusted_ca_references"`
	TrustedCACertificateHashesHex  []string `json:"trusted_ca_certificate_hashes_hex"`
	PinnedPeerCertificateHashesHex []string `json:"pinned_peer_certificate_hashes_hex,omitempty"`
	ClientSigningCertificateRef    string   `json:"client_signing_certificate_ref"`
	ClientSigningKeyRef            string   `json:"client_signing_key_ref"`
	ClientEncryptionCertificateRef string   `json:"client_encryption_certificate_ref,omitempty"`
	ClientEncryptionKeyRef         string   `json:"client_encryption_key_ref,omitempty"`
}

type fiscoBCOSValidatorDescriptorInput struct {
	NodeID       string `json:"node_id"`
	PublicKeyHex string `json:"public_key_hex"`
}

type fiscoBCOSTrustConfigReport struct {
	SchemaVersion     string                              `json:"schema_version"`
	CryptoMode        fiscobcos.CryptoMode                `json:"crypto_mode"`
	ChainID           string                              `json:"chain_id"`
	GroupID           string                              `json:"group_id"`
	TrustConfigDigest string                              `json:"trust_config_digest"`
	ChainContextID    string                              `json:"chain_context_id"`
	Endpoints         []string                            `json:"endpoints"`
	ReadQuorum        uint32                              `json:"read_quorum"`
	Validators        []fiscoBCOSValidatorDescriptorInput `json:"validators"`
}

func newAnchorFISCOBCOSCommand(rt *runtimeConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fisco-bcos",
		Short: "Prepare and inspect mode-bound FISCO BCOS anchor trust",
	}
	cmd.AddCommand(newFISCOBCOSTrustConfigCommand(rt))
	return cmd
}

func newFISCOBCOSTrustConfigCommand(rt *runtimeConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust-config",
		Short: "Create or inspect canonical FISCO BCOS TrustConfig CBOR",
	}
	cmd.AddCommand(newFISCOBCOSTrustConfigCreateCommand(rt))
	cmd.AddCommand(newFISCOBCOSTrustConfigInspectCommand(rt))
	return cmd
}

func newFISCOBCOSTrustConfigCreateCommand(rt *runtimeConfig) *cobra.Command {
	var inputPath, outputPath string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Validate a readable JSON manifest and atomically write canonical TrustConfig CBOR",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(inputPath) == "" {
				return usageError("--input is required")
			}
			if strings.TrimSpace(outputPath) == "" {
				return usageError("--out is required")
			}
			data, err := readFileLimit(inputPath, maxFISCOBCOSTrustConfigJSONBytes)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeFailedPrecondition, "read FISCO BCOS TrustConfig JSON", err)
			}
			var input fiscoBCOSTrustConfigInput
			if err := decodeStrictJSON(data, &input); err != nil {
				return trusterr.Wrap(trusterr.CodeInvalidArgument, "decode FISCO BCOS TrustConfig JSON", err)
			}
			config, err := input.trustConfig()
			if err != nil {
				return trusterr.Wrap(trusterr.CodeInvalidArgument, "validate FISCO BCOS TrustConfig JSON", err)
			}
			canonical, err := fiscobcos.MarshalTrustConfig(config)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeInvalidArgument, "encode canonical FISCO BCOS TrustConfig", err)
			}
			config, err = fiscobcos.UnmarshalTrustConfig(canonical)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeInternal, "re-read canonical FISCO BCOS TrustConfig", err)
			}
			report, err := newFISCOBCOSTrustConfigReport(config)
			if err != nil {
				return err
			}
			if err := writeFileAtomic(outputPath, canonical, 0o600); err != nil {
				return trusterr.Wrap(trusterr.CodeFailedPrecondition, "write canonical FISCO BCOS TrustConfig", err)
			}
			return rt.writeJSON(report)
		},
	}
	cmd.Flags().StringVar(&inputPath, "input", "", "JSON manifest with hex-encoded hashes, addresses, and validator public keys")
	cmd.Flags().StringVar(&outputPath, "out", "", "canonical CBOR output path (written atomically with mode 0600)")
	return cmd
}

func newFISCOBCOSTrustConfigInspectCommand(rt *runtimeConfig) *cobra.Command {
	var inputPath string
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Decode canonical TrustConfig CBOR and print its trust identities",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(inputPath) == "" {
				return usageError("--input is required")
			}
			config, err := loadCanonicalFISCOBCOSTrustConfig(inputPath)
			if err != nil {
				return err
			}
			report, err := newFISCOBCOSTrustConfigReport(config)
			if err != nil {
				return err
			}
			return rt.writeJSON(report)
		},
	}
	cmd.Flags().StringVar(&inputPath, "input", "", "absolute path to canonical FISCO BCOS TrustConfig CBOR")
	return cmd
}

func decodeStrictJSON(data []byte, target any) error {
	if err := validateFISCOBCOSJSONStructure(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON input contains more than one value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func validateFISCOBCOSJSONStructure(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeFISCOBCOSJSONValue(decoder, 0); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("JSON input contains trailing token %v", token)
		}
		return err
	}
	return nil
}

func consumeFISCOBCOSJSONValue(decoder *json.Decoder, depth int) error {
	const (
		maxDepth       = 16
		maxObjectKeys  = 64
		maxArrayValues = 2048
	)
	if depth > maxDepth {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			if len(seen) >= maxObjectKeys {
				return errors.New("JSON object key count exceeds limit")
			}
			seen[key] = struct{}{}
			if err := consumeFISCOBCOSJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("JSON object is not terminated")
		}
	case '[':
		count := 0
		for decoder.More() {
			if count >= maxArrayValues {
				return errors.New("JSON array length exceeds limit")
			}
			if err := consumeFISCOBCOSJSONValue(decoder, depth+1); err != nil {
				return err
			}
			count++
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("JSON array is not terminated")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func (input fiscoBCOSTrustConfigInput) trustConfig() (fiscobcos.TrustConfig, error) {
	mode := fiscobcos.CryptoMode(strings.TrimSpace(input.CryptoMode))
	config, err := fiscobcos.NewTrustConfig(mode)
	if err != nil {
		return fiscobcos.TrustConfig{}, err
	}
	params, err := fiscobcos.ParametersForMode(mode)
	if err != nil {
		return fiscobcos.TrustConfig{}, err
	}
	config.ChainID = input.ChainID
	config.GroupID = input.GroupID
	if config.GenesisHash, err = decodeExactHex("genesis_hash_hex", input.GenesisHashHex, 32); err != nil {
		return fiscobcos.TrustConfig{}, err
	}
	config.TrustedCheckpoint.BlockNumber = input.TrustedCheckpoint.BlockNumber
	if config.TrustedCheckpoint.BlockHash, err = decodeExactHex(
		"trusted_checkpoint.block_hash_hex",
		input.TrustedCheckpoint.BlockHashHex,
		32,
	); err != nil {
		return fiscobcos.TrustConfig{}, err
	}
	if config.Contract.Address, err = decodeExactHex("contract.address_hex", input.Contract.AddressHex, 20); err != nil {
		return fiscobcos.TrustConfig{}, err
	}
	if config.Contract.CodeHash, err = decodeExactHex("contract.code_hash_hex", input.Contract.CodeHashHex, 32); err != nil {
		return fiscobcos.TrustConfig{}, err
	}
	config.Contract.ProtocolVersion = input.Contract.ProtocolVersion
	config.Contract.EventSignature = input.Contract.EventSignature
	config.Endpoints = append([]string(nil), input.Endpoints...)
	config.ReadQuorum = input.ReadQuorum
	config.AccountProvider = fiscobcos.AccountProviderConfig{
		Provider:     input.AccountProvider.Provider,
		KeyID:        input.AccountProvider.KeyID,
		KeyReference: input.AccountProvider.KeyReference,
		Algorithm:    params.ChainSignatureAlgorithm,
	}
	config.Certificates.TrustedCAReferences = append(
		[]string(nil),
		input.Certificates.TrustedCAReferences...,
	)
	config.Certificates.TrustedCACertificateHashes, err = decodeHexList(
		"certificates.trusted_ca_certificate_hashes_hex",
		input.Certificates.TrustedCACertificateHashesHex,
		32,
	)
	if err != nil {
		return fiscobcos.TrustConfig{}, err
	}
	config.Certificates.PinnedPeerCertificateHashes, err = decodeHexList(
		"certificates.pinned_peer_certificate_hashes_hex",
		input.Certificates.PinnedPeerCertificateHashesHex,
		32,
	)
	if err != nil {
		return fiscobcos.TrustConfig{}, err
	}
	config.Certificates.ClientSigningCertificateRef = input.Certificates.ClientSigningCertificateRef
	config.Certificates.ClientSigningKeyRef = input.Certificates.ClientSigningKeyRef
	config.Certificates.ClientEncryptionCertificateRef = input.Certificates.ClientEncryptionCertificateRef
	config.Certificates.ClientEncryptionKeyRef = input.Certificates.ClientEncryptionKeyRef
	config.Validators = make([]fiscobcos.ValidatorDescriptor, len(input.Validators))
	for index, validator := range input.Validators {
		publicKey, decodeErr := decodeExactHex(
			fmt.Sprintf("validators[%d].public_key_hex", index),
			validator.PublicKeyHex,
			65,
		)
		if decodeErr != nil {
			return fiscobcos.TrustConfig{}, decodeErr
		}
		config.Validators[index] = fiscobcos.ValidatorDescriptor{
			NodeID:            validator.NodeID,
			Algorithm:         params.ChainSignatureAlgorithm,
			PublicKeyEncoding: params.PublicKeyEncoding,
			PublicKey:         publicKey,
		}
	}
	return config, nil
}

func decodeHexList(name string, values []string, size int) ([][]byte, error) {
	result := make([][]byte, len(values))
	for index, value := range values {
		decoded, err := decodeExactHex(fmt.Sprintf("%s[%d]", name, index), value, size)
		if err != nil {
			return nil, err
		}
		result[index] = decoded
	}
	return result, nil
}

func decodeExactHex(name, value string, size int) ([]byte, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "0x")
	if len(value) != size*2 {
		return nil, fmt.Errorf("%s must encode exactly %d bytes", name, size)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not hexadecimal: %w", name, err)
	}
	return decoded, nil
}

func newFISCOBCOSTrustConfigReport(config fiscobcos.TrustConfig) (fiscoBCOSTrustConfigReport, error) {
	digest, err := fiscobcos.TrustConfigDigest(config)
	if err != nil {
		return fiscoBCOSTrustConfigReport{}, err
	}
	contextID, err := fiscobcos.ChainContextID(config)
	if err != nil {
		return fiscoBCOSTrustConfigReport{}, err
	}
	validators := make([]fiscoBCOSValidatorDescriptorInput, len(config.Validators))
	for index, validator := range config.Validators {
		validators[index] = fiscoBCOSValidatorDescriptorInput{
			NodeID:       validator.NodeID,
			PublicKeyHex: "0x" + hex.EncodeToString(validator.PublicKey),
		}
	}
	return fiscoBCOSTrustConfigReport{
		SchemaVersion:     config.SchemaVersion,
		CryptoMode:        config.CryptoMode,
		ChainID:           config.ChainID,
		GroupID:           config.GroupID,
		TrustConfigDigest: "0x" + hex.EncodeToString(digest),
		ChainContextID:    "0x" + hex.EncodeToString(contextID),
		Endpoints:         append([]string(nil), config.Endpoints...),
		ReadQuorum:        config.ReadQuorum,
		Validators:        validators,
	}, nil
}
