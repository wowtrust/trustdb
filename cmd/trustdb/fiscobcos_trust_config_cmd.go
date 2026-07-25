package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/sproof"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const maxFISCOBCOSTrustConfigJSONBytes = 4 << 20

type fiscoBCOSTrustConfigInput struct {
	CryptoMode                string                              `json:"crypto_mode"`
	ChainID                   string                              `json:"chain_id"`
	GroupID                   string                              `json:"group_id"`
	GenesisHashHex            string                              `json:"genesis_hash_hex"`
	TrustedCheckpoint         fiscoBCOSCheckpointInput            `json:"trusted_checkpoint"`
	Contract                  fiscoBCOSContractInput              `json:"contract"`
	Endpoints                 []string                            `json:"endpoints"`
	ReadQuorum                uint32                              `json:"read_quorum"`
	ValidatorTransitionPolicy string                              `json:"validator_transition_policy"`
	AccountProvider           fiscoBCOSAccountProviderInput       `json:"account_provider"`
	Certificates              fiscoBCOSCertificateInput           `json:"certificates"`
	Validators                []fiscoBCOSValidatorDescriptorInput `json:"validators"`
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
	VoteWeight   uint64 `json:"vote_weight"`
}

type fiscoBCOSTrustConfigReport struct {
	SchemaVersion             string                              `json:"schema_version"`
	CryptoMode                fiscobcos.CryptoMode                `json:"crypto_mode"`
	ChainID                   string                              `json:"chain_id"`
	GroupID                   string                              `json:"group_id"`
	TrustConfigDigest         string                              `json:"trust_config_digest"`
	ChainContextID            string                              `json:"chain_context_id"`
	Endpoints                 []string                            `json:"endpoints"`
	ReadQuorum                uint32                              `json:"read_quorum"`
	ValidatorTransitionPolicy string                              `json:"validator_transition_policy"`
	Checkpoint                fiscoBCOSCheckpointReport           `json:"checkpoint"`
	Validators                []fiscoBCOSValidatorDescriptorInput `json:"validators"`
}

type fiscoBCOSCheckpointReport struct {
	BlockNumber          uint64 `json:"block_number"`
	BlockHash            string `json:"block_hash"`
	Generation           uint64 `json:"generation"`
	PreviousConfigDigest string `json:"previous_config_digest,omitempty"`
}

type fiscoBCOSAdvanceReport struct {
	OldTrustConfigDigest string                    `json:"old_trust_config_digest"`
	NewTrustConfigDigest string                    `json:"new_trust_config_digest"`
	OldCheckpoint        fiscoBCOSCheckpointReport `json:"old_checkpoint"`
	NewCheckpoint        fiscoBCOSCheckpointReport `json:"new_checkpoint"`
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
	cmd.AddCommand(newFISCOBCOSTrustConfigAdvanceCommand(rt))
	return cmd
}

func newFISCOBCOSTrustConfigAdvanceCommand(rt *runtimeConfig) *cobra.Command {
	var inputPath, evidencePath, outputPath, expectedDigestHex string
	cmd := &cobra.Command{
		Use:   "advance",
		Short: "Verify an offline transition chain and atomically advance the local trust checkpoint",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, required := range []struct{ name, value string }{
				{name: "--input", value: inputPath},
				{name: "--evidence", value: evidencePath},
				{name: "--out", value: outputPath},
				{name: "--expect-current-digest", value: expectedDigestHex},
			} {
				if strings.TrimSpace(required.value) == "" {
					return usageError(required.name + " is required")
				}
			}
			samePath, err := pathsNameSameFile(inputPath, outputPath)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeInvalidArgument, "compare FISCO BCOS TrustConfig paths", err)
			}
			if !samePath {
				return usageError("--out must name the same canonical TrustConfig file as --input")
			}
			expectedDigest, err := decodeExactHex("expect_current_digest", expectedDigestHex, 32)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeInvalidArgument, "decode expected FISCO BCOS TrustConfig digest", err)
			}
			lockPath := inputPath + ".advance.lock"
			lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeFailedPrecondition, "acquire exclusive FISCO BCOS checkpoint advancement lock", err)
			}
			lockClosed := false
			defer func() {
				if !lockClosed {
					_ = lock.Close()
				}
				_ = os.Remove(lockPath)
			}()
			if _, err := lock.Write([]byte("0x" + hex.EncodeToString(expectedDigest) + "\n")); err != nil {
				return trusterr.Wrap(trusterr.CodeFailedPrecondition, "record FISCO BCOS checkpoint advancement lock", err)
			}
			if err := lock.Sync(); err != nil {
				return trusterr.Wrap(trusterr.CodeFailedPrecondition, "sync FISCO BCOS checkpoint advancement lock", err)
			}
			if err := lock.Close(); err != nil {
				lockClosed = true
				return trusterr.Wrap(trusterr.CodeFailedPrecondition, "close FISCO BCOS checkpoint advancement lock", err)
			}
			lockClosed = true

			current, err := loadCanonicalFISCOBCOSTrustConfig(inputPath)
			if err != nil {
				return err
			}
			currentDigest, err := fiscobcos.TrustConfigDigest(current)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeInternal, "digest current FISCO BCOS TrustConfig", err)
			}
			if !bytes.Equal(currentDigest, expectedDigest) {
				return trusterr.New(trusterr.CodeFailedPrecondition, "current FISCO BCOS TrustConfig digest changed; refusing checkpoint advancement")
			}
			evidence, err := sproof.ReadFile(evidencePath)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeInvalidArgument, "read offline .sproof transition evidence", err)
			}
			if evidence.AnchorResult == nil || evidence.AnchorResult.SinkName != fiscobcos.SinkName {
				return trusterr.New(trusterr.CodeInvalidArgument, "offline evidence does not carry a FISCO BCOS anchor result")
			}
			proof, err := fiscobcos.UnmarshalProof(evidence.AnchorResult.Proof)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeInvalidArgument, "decode FISCO BCOS transition proof", err)
			}
			next, err := fiscobcos.AdvanceTrustConfigCheckpoint(current, proof)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeFailedPrecondition, "verify FISCO BCOS validator transition chain", err)
			}
			nextBytes, err := fiscobcos.MarshalTrustConfig(next)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeInternal, "encode advanced FISCO BCOS TrustConfig", err)
			}
			if err := writeFileAtomic(outputPath, nextBytes, 0o600); err != nil {
				return trusterr.Wrap(trusterr.CodeFailedPrecondition, "write advanced FISCO BCOS TrustConfig", err)
			}
			nextDigest, err := fiscobcos.TrustConfigDigest(next)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeInternal, "digest advanced FISCO BCOS TrustConfig", err)
			}
			return rt.writeJSON(fiscoBCOSAdvanceReport{
				OldTrustConfigDigest: "0x" + hex.EncodeToString(currentDigest),
				NewTrustConfigDigest: "0x" + hex.EncodeToString(nextDigest),
				OldCheckpoint:        checkpointReport(current),
				NewCheckpoint:        checkpointReport(next),
			})
		},
	}
	cmd.Flags().StringVar(&inputPath, "input", "", "current canonical TrustConfig CBOR path")
	cmd.Flags().StringVar(&evidencePath, "evidence", "", "complete offline .sproof file carrying the authenticated transition chain")
	cmd.Flags().StringVar(&outputPath, "out", "", "canonical TrustConfig CBOR path; must name the same file as --input")
	cmd.Flags().StringVar(&expectedDigestHex, "expect-current-digest", "", "required 32-byte current TrustConfig digest for rollback/concurrency protection")
	return cmd
}

func pathsNameSameFile(left, right string) (bool, error) {
	leftAbsolute, err := filepath.Abs(left)
	if err != nil {
		return false, err
	}
	rightAbsolute, err := filepath.Abs(right)
	if err != nil {
		return false, err
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(leftAbsolute), filepath.Clean(rightAbsolute)), nil
	}
	return filepath.Clean(leftAbsolute) == filepath.Clean(rightAbsolute), nil
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
			if !isCanonicalFISCOBCOSJSONKey(key) {
				return fmt.Errorf("JSON object key %q must use lowercase snake_case", key)
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

func isCanonicalFISCOBCOSJSONKey(key string) bool {
	if key == "" {
		return false
	}
	for _, item := range key {
		if item != '_' && (item < 'a' || item > 'z') && (item < '0' || item > '9') {
			return false
		}
	}
	return true
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
	config.ValidatorTransitionPolicy = input.ValidatorTransitionPolicy
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
			VoteWeight:        validator.VoteWeight,
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
			VoteWeight:   validator.VoteWeight,
		}
	}
	return fiscoBCOSTrustConfigReport{
		SchemaVersion:             config.SchemaVersion,
		CryptoMode:                config.CryptoMode,
		ChainID:                   config.ChainID,
		GroupID:                   config.GroupID,
		TrustConfigDigest:         "0x" + hex.EncodeToString(digest),
		ChainContextID:            "0x" + hex.EncodeToString(contextID),
		Endpoints:                 append([]string(nil), config.Endpoints...),
		ReadQuorum:                config.ReadQuorum,
		ValidatorTransitionPolicy: config.ValidatorTransitionPolicy,
		Checkpoint:                checkpointReport(config),
		Validators:                validators,
	}, nil
}

func checkpointReport(config fiscobcos.TrustConfig) fiscoBCOSCheckpointReport {
	report := fiscoBCOSCheckpointReport{
		BlockNumber: config.TrustedCheckpoint.BlockNumber,
		BlockHash:   "0x" + hex.EncodeToString(config.TrustedCheckpoint.BlockHash),
		Generation:  config.CheckpointGeneration,
	}
	if len(config.PreviousConfigDigest) != 0 {
		report.PreviousConfigDigest = "0x" + hex.EncodeToString(config.PreviousConfigDigest)
	}
	return report
}
