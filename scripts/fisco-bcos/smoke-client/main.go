package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/FISCO-BCOS/go-sdk/v3/abi"
	"github.com/FISCO-BCOS/go-sdk/v3/client"
	"github.com/FISCO-BCOS/go-sdk/v3/precompiled"
	bcossm3 "github.com/FISCO-BCOS/go-sdk/v3/smcrypto/sm3"
	"github.com/FISCO-BCOS/go-sdk/v3/types"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

type config struct {
	Mode                string
	Host                string
	Port                int
	CertDir             string
	ABIPath             string
	BINPath             string
	RawEVM              bool
	AnchorV1Constructor bool
	AccountKeyPath      string
	ScenarioDir         string
	RestartPort         int
	PerformanceWarmup   int
	PerformanceSamples  int
}

type txEvidence struct {
	Hash                string   `json:"hash"`
	Status              int      `json:"status"`
	BlockNumber         int      `json:"block_number"`
	ContractAddress     string   `json:"contract_address,omitempty"`
	ReceiptProof        []string `json:"receipt_proof"`
	ReceiptProofPresent bool     `json:"receipt_proof_field_present"`
	TransactionProof    []string `json:"transaction_proof"`
	TxProofPresent      bool     `json:"transaction_proof_field_present"`
	PrepareSignEncodeNS int64    `json:"prepare_sign_encode_ns"`
	SubmitToReceiptNS   int64    `json:"submit_to_receipt_ns"`
	ProofRetrievalNS    int64    `json:"proof_retrieval_ns"`
}

type txPhaseDurations struct {
	prepareSignEncode time.Duration
	submitToReceipt   time.Duration
}

type performanceTimingSample struct {
	PrepareSignEncodeNS         int64 `json:"prepare_sign_encode_ns"`
	SubmitToReceiptNS           int64 `json:"submit_to_receipt_ns"`
	ReceiptProofRetrievalNS     int64 `json:"receipt_proof_retrieval_ns"`
	TransactionProofRetrievalNS int64 `json:"transaction_proof_retrieval_ns"`
	BlockRetrievalNS            int64 `json:"block_retrieval_ns"`
}

type performanceVerificationSample struct {
	Receipt *types.Receipt `json:"receipt"`
	Block   *types.Block   `json:"block"`
}

type performanceEvidence struct {
	RunBinding                string                          `json:"run_binding"`
	WarmupCount               int                             `json:"warmup_count"`
	SampleCount               int                             `json:"sample_count"`
	Payload                   string                          `json:"payload"`
	DeploymentExcluded        bool                            `json:"deployment_excluded"`
	TimingSamples             []performanceTimingSample       `json:"timing_samples"`
	WarmupVerificationSamples []performanceVerificationSample `json:"warmup_verification_samples"`
	VerificationSamples       []performanceVerificationSample `json:"verification_samples"`
}

type anchorPayload struct {
	AnchorID        [32]byte
	StreamID        [32]byte
	TreeSize        uint64
	RootHash        [32]byte
	SignedSTHDigest [32]byte
	PayloadVersion  uint16
}

type anchorPayloadEvidence struct {
	AnchorID        string `json:"anchor_id"`
	StreamID        string `json:"stream_id"`
	TreeSize        uint64 `json:"tree_size"`
	RootHash        string `json:"root_hash"`
	SignedSTHDigest string `json:"signed_sth_digest"`
	PayloadVersion  uint16 `json:"payload_version"`
	Publisher       string `json:"publisher"`
}

type anchorPublishedData struct {
	TreeSize        uint64
	RootHash        [32]byte
	SignedSTHDigest [32]byte
	PayloadVersion  uint16
}

type storedAnchorRecord struct {
	StreamID        [32]byte
	TreeSize        uint64
	RootHash        [32]byte
	SignedSTHDigest [32]byte
	Publisher       common.Address
	PayloadVersion  uint16
	Exists          bool
}

type evidence struct {
	SchemaVersion       int                        `json:"schema_version"`
	TimingSemantics     string                     `json:"timing_semantics"`
	Mode                string                     `json:"mode"`
	SMCrypto            bool                       `json:"sm_crypto"`
	ChainID             string                     `json:"chain_id"`
	GenesisHash         string                     `json:"genesis_hash"`
	TrustedCheckpoint   trustedCheckpointEvidence  `json:"trusted_checkpoint"`
	ContractCodeHash    string                     `json:"contract_code_hash"`
	InitialBlockNumber  int64                      `json:"initial_block_number"`
	FinalBlockNumber    int64                      `json:"final_block_number"`
	Deployment          txEvidence                 `json:"deployment"`
	EventTransaction    txEvidence                 `json:"event_transaction"`
	EventReceipt        *types.Receipt             `json:"event_receipt"`
	Event               types.Log                  `json:"event"`
	Block               *types.Block               `json:"containing_block"`
	ConsensusStatus     json.RawMessage            `json:"consensus_status"`
	Sealers             []client.ConsensusNodeInfo `json:"sealers"`
	StaleBlockLimit     int64                      `json:"stale_block_limit"`
	StaleLimitRejected  bool                       `json:"stale_block_limit_rejected"`
	StaleRejectionError string                     `json:"stale_rejection_error,omitempty"`
	AnchorPayload       *anchorPayloadEvidence     `json:"anchor_payload,omitempty"`
	ProductionPublish   bool                       `json:"production_publish_verified"`
	ProbeSource         string                     `json:"probe_source"`
	Performance         performanceEvidence        `json:"performance"`
	Qualification       *qualificationEvidence     `json:"qualification,omitempty"`
	CleanTeardown       bool                       `json:"clean_teardown"`
}

type trustedCheckpointEvidence struct {
	BlockNumber uint64 `json:"block_number"`
	BlockHash   string `json:"block_hash"`
}

type qualificationEvidence struct {
	NodeLossTransaction    txEvidence                  `json:"node_loss_transaction"`
	PostRestartTransaction txEvidence                  `json:"post_restart_transaction"`
	RestartedNodeHeight    int64                       `json:"restarted_node_height"`
	ReferenceNodeHeight    int64                       `json:"reference_node_height"`
	ValidatorTransition    validatorTransitionEvidence `json:"validator_transition"`
}

type validatorTransitionEvidence struct {
	NodeID              string                     `json:"node_id"`
	InitialWeight       uint                       `json:"initial_weight"`
	ChangedWeight       uint                       `json:"changed_weight"`
	RestoredWeight      uint                       `json:"restored_weight"`
	ChangedTransaction  txEvidence                 `json:"changed_transaction"`
	RestoredTransaction txEvidence                 `json:"restored_transaction"`
	SealersAfterChange  []client.ConsensusNodeInfo `json:"sealers_after_change"`
	SealersAfterRestore []client.ConsensusNodeInfo `json:"sealers_after_restore"`
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.Mode, "mode", "", "standard or guomi")
	flag.StringVar(&cfg.Host, "host", "127.0.0.1", "RPC host")
	flag.IntVar(&cfg.Port, "port", 20200, "RPC port")
	flag.StringVar(&cfg.CertDir, "cert-dir", "", "generated SDK certificate directory")
	flag.StringVar(&cfg.ABIPath, "abi", "", "compiled contract ABI path")
	flag.StringVar(&cfg.BINPath, "bin", "", "compiled contract bytecode path")
	flag.BoolVar(&cfg.RawEVM, "raw-evm-fixture", false, "use a compiler-independent LOG0 EVM fixture")
	flag.BoolVar(&cfg.AnchorV1Constructor, "anchor-v1-constructor", false, "pack the production TrustDBAnchorV1 administrator and publisher constructor arguments")
	flag.StringVar(&cfg.AccountKeyPath, "account-key-file", "", "optional 0600 file containing an exact 32-byte hex transaction key")
	flag.StringVar(&cfg.ScenarioDir, "scenario-dir", "", "coordinate four-node fault and validator-transition qualification through this directory")
	flag.IntVar(&cfg.RestartPort, "restart-port", 0, "RPC port of the validator restarted by the qualification scenario")
	flag.IntVar(&cfg.PerformanceWarmup, "performance-warmup", 5, "discarded full-pipeline performance warmup samples (3-20)")
	flag.IntVar(&cfg.PerformanceSamples, "performance-samples", 20, "recorded post-warmup performance samples (20-100)")
	flag.Parse()
	if cfg.Mode != "standard" && cfg.Mode != "guomi" {
		fatalf("--mode must be standard or guomi")
	}
	if cfg.CertDir == "" {
		fatalf("--cert-dir is required")
	}
	if !cfg.RawEVM && (cfg.ABIPath == "" || cfg.BINPath == "") {
		fatalf("--abi and --bin are required unless --raw-evm-fixture is set")
	}
	if cfg.RawEVM && cfg.ScenarioDir != "" {
		fatalf("--scenario-dir requires the production TrustDBAnchorV1 contract")
	}
	if cfg.RawEVM && cfg.AnchorV1Constructor {
		fatalf("--anchor-v1-constructor cannot be used with --raw-evm-fixture")
	}
	if cfg.ScenarioDir != "" && cfg.RestartPort < 1 {
		fatalf("--restart-port is required with --scenario-dir")
	}
	if cfg.PerformanceWarmup < 3 || cfg.PerformanceWarmup > 20 {
		fatalf("--performance-warmup must be between 3 and 20")
	}
	if cfg.PerformanceSamples < 20 || cfg.PerformanceSamples > 100 {
		fatalf("--performance-samples must be between 20 and 100")
	}
	return cfg
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func readContract(cfg config) (abi.ABI, string, string) {
	if cfg.RawEVM {
		// Creation code returns runtime 0x60006000a000. Every call emits one LOG0
		// with empty data and then stops. It contains no suite-specific selector.
		parsed, err := abi.JSON(strings.NewReader("[]"))
		if err != nil {
			panic(err)
		}
		return parsed, "6006600c60003960066000f360006000a000", "[]"
	}
	abiBytes, err := os.ReadFile(cfg.ABIPath)
	if err != nil {
		fatalf("read ABI: %v", err)
	}
	parsed, err := abi.JSON(strings.NewReader(string(abiBytes)))
	if err != nil {
		fatalf("parse ABI: %v", err)
	}
	if cfg.Mode == "guomi" {
		parsed.SetSMCrypto()
	}
	binBytes, err := os.ReadFile(cfg.BINPath)
	if err != nil {
		fatalf("read BIN: %v", err)
	}
	return parsed, strings.TrimSpace(string(binBytes)), string(abiBytes)
}

func sdkConfig(cfg config) (*client.Config, error) {
	var privateKeyBytes []byte
	if cfg.AccountKeyPath == "" {
		privateKey, err := ethcrypto.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral smoke key: %w", err)
		}
		privateKeyBytes = ethcrypto.FromECDSA(privateKey)
	} else {
		info, err := os.Stat(cfg.AccountKeyPath)
		if err != nil {
			return nil, fmt.Errorf("inspect smoke account key: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("smoke account key must be a regular file inaccessible to group and other users")
		}
		encoded, err := os.ReadFile(cfg.AccountKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read smoke account key: %w", err)
		}
		privateKeyBytes, err = hex.DecodeString(strings.TrimSpace(string(encoded)))
		if err != nil || len(privateKeyBytes) != 32 {
			return nil, errors.New("smoke account key must contain exactly 32 hex-encoded bytes")
		}
		if _, err := ethcrypto.ToECDSA(privateKeyBytes); err != nil {
			return nil, fmt.Errorf("parse smoke account key: %w", err)
		}
	}
	result := &client.Config{
		IsSMCrypto: cfg.Mode == "guomi",
		PrivateKey: privateKeyBytes,
		GroupID:    "group0",
		Host:       cfg.Host,
		Port:       cfg.Port,
		DisableSsl: false,
	}
	if cfg.Mode == "guomi" {
		result.TLSCaFile = filepath.Join(cfg.CertDir, "sm_ca.crt")
		result.TLSKeyFile = filepath.Join(cfg.CertDir, "sm_sdk.key")
		result.TLSCertFile = filepath.Join(cfg.CertDir, "sm_sdk.crt")
		result.TLSSmEnKeyFile = filepath.Join(cfg.CertDir, "sm_ensdk.key")
		result.TLSSmEnCertFile = filepath.Join(cfg.CertDir, "sm_ensdk.crt")
	} else {
		result.TLSCaFile = filepath.Join(cfg.CertDir, "ca.crt")
		result.TLSKeyFile = filepath.Join(cfg.CertDir, "sdk.key")
		result.TLSCertFile = filepath.Join(cfg.CertDir, "sdk.crt")
	}
	return result, nil
}

func sendEncoded(
	ctx context.Context,
	c *client.Client,
	to *common.Address,
	input []byte,
	abiJSON string,
	blockLimit int64,
) (common.Hash, *types.Receipt, txPhaseDurations, error) {
	prepareStarted := time.Now()
	txData, hashBytes, err := c.CreateEncodedTransactionDataV1(to, input, blockLimit, abiJSON)
	if err != nil {
		return common.Hash{}, nil, txPhaseDurations{}, fmt.Errorf("create transaction data: %w", err)
	}
	signature, err := c.CreateEncodedSignature(hashBytes)
	if err != nil {
		return common.Hash{}, nil, txPhaseDurations{}, fmt.Errorf("sign transaction: %w", err)
	}
	tx, err := c.CreateEncodedTransaction(txData, hashBytes, signature, 0, "")
	if err != nil {
		return common.Hash{}, nil, txPhaseDurations{}, fmt.Errorf("encode transaction: %w", err)
	}
	prepareElapsed := time.Since(prepareStarted)
	submitStarted := time.Now()
	receipt, err := c.SendEncodedTransaction(ctx, tx, true)
	return common.BytesToHash(hashBytes), receipt, txPhaseDurations{
		prepareSignEncode: prepareElapsed,
		submitToReceipt:   time.Since(submitStarted),
	}, err
}

func observedContractCodeHash(
	ctx context.Context,
	c *client.Client,
	mode string,
	address common.Address,
) (string, error) {
	rawJSON, err := c.GetCode(ctx, address)
	if err != nil {
		return "", err
	}
	var encoded string
	if err := json.Unmarshal(rawJSON, &encoded); err != nil {
		return "", fmt.Errorf("decode contract code: %w", err)
	}
	code := common.FromHex(encoded)
	if len(code) == 0 {
		return "", errors.New("deployed contract code is empty")
	}
	if mode == "guomi" {
		hash := bcossm3.NewContext()
		hash.Append(code)
		return hex.EncodeToString(hash.Final()), nil
	}
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write(code)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func collectTxEvidence(ctx context.Context, c *client.Client, hash common.Hash, receipt *types.Receipt, phases txPhaseDurations) (txEvidence, error) {
	if receipt == nil {
		return txEvidence{}, errors.New("nil receipt")
	}
	proofStarted := time.Now()
	queriedReceipt, err := c.GetTransactionReceipt(ctx, hash, true)
	if err != nil {
		return txEvidence{}, fmt.Errorf("get receipt with proof: %w", err)
	}
	tx, err := c.GetTransactionByHash(ctx, hash, true)
	if err != nil {
		return txEvidence{}, fmt.Errorf("get transaction with proof: %w", err)
	}
	proofElapsed := time.Since(proofStarted)
	return txEvidence{
		Hash:                hash.Hex(),
		Status:              queriedReceipt.Status,
		BlockNumber:         queriedReceipt.BlockNumber,
		ContractAddress:     queriedReceipt.ContractAddress,
		ReceiptProof:        queriedReceipt.ReceiptProof,
		ReceiptProofPresent: queriedReceipt.ReceiptProof != nil,
		TransactionProof:    tx.TransactionProof,
		TxProofPresent:      tx.TransactionProof != nil,
		PrepareSignEncodeNS: phases.prepareSignEncode.Nanoseconds(),
		SubmitToReceiptNS:   phases.submitToReceipt.Nanoseconds(),
		ProofRetrievalNS:    proofElapsed.Nanoseconds(),
	}, nil
}

func collectPerformanceEvidence(
	ctx context.Context,
	c *client.Client,
	hash common.Hash,
	receipt *types.Receipt,
	phases txPhaseDurations,
	expectFreshAnchor bool,
) (performanceTimingSample, performanceVerificationSample, error) {
	if receipt == nil {
		return performanceTimingSample{}, performanceVerificationSample{}, errors.New("nil performance receipt")
	}
	receiptProofStarted := time.Now()
	queriedReceipt, err := c.GetTransactionReceipt(ctx, hash, true)
	receiptProofElapsed := time.Since(receiptProofStarted)
	if err != nil {
		return performanceTimingSample{}, performanceVerificationSample{}, fmt.Errorf("get performance receipt with proof: %w", err)
	}
	if queriedReceipt == nil || queriedReceipt.Status != types.Success || queriedReceipt.ReceiptProof == nil {
		return performanceTimingSample{}, performanceVerificationSample{}, errors.New("performance receipt is unsuccessful or lacks its proof field")
	}
	if expectFreshAnchor && len(queriedReceipt.Logs) != 1 {
		return performanceTimingSample{}, performanceVerificationSample{}, fmt.Errorf(
			"fresh performance anchor emitted %d logs, expected exactly AnchorPublished",
			len(queriedReceipt.Logs),
		)
	}
	transactionProofStarted := time.Now()
	transaction, err := c.GetTransactionByHash(ctx, hash, true)
	transactionProofElapsed := time.Since(transactionProofStarted)
	if err != nil {
		return performanceTimingSample{}, performanceVerificationSample{}, fmt.Errorf("get performance transaction with proof: %w", err)
	}
	if transaction == nil || transaction.TransactionProof == nil {
		return performanceTimingSample{}, performanceVerificationSample{}, errors.New("performance transaction lacks its proof field")
	}
	blockRetrievalStarted := time.Now()
	block, err := c.GetBlockByNumber(ctx, int64(queriedReceipt.BlockNumber), false, true)
	blockRetrievalElapsed := time.Since(blockRetrievalStarted)
	if err != nil {
		return performanceTimingSample{}, performanceVerificationSample{}, fmt.Errorf("get performance containing block: %w", err)
	}
	if block == nil || block.Hash == "" || block.TxsRoot == "" ||
		block.ReceiptsRoot == "" || len(block.SignatureList) == 0 {
		return performanceTimingSample{}, performanceVerificationSample{}, errors.New("performance containing block lacks hash, roots, or signatures")
	}
	return performanceTimingSample{
			PrepareSignEncodeNS:         phases.prepareSignEncode.Nanoseconds(),
			SubmitToReceiptNS:           phases.submitToReceipt.Nanoseconds(),
			ReceiptProofRetrievalNS:     receiptProofElapsed.Nanoseconds(),
			TransactionProofRetrievalNS: transactionProofElapsed.Nanoseconds(),
			BlockRetrievalNS:            blockRetrievalElapsed.Nanoseconds(),
		}, performanceVerificationSample{
			Receipt: queriedReceipt,
			Block:   block,
		}, nil
}

func runPerformanceSamples(
	ctx context.Context,
	c *client.Client,
	cfg config,
	parsed abi.ABI,
	address common.Address,
) (performanceEvidence, error) {
	current, err := c.GetBlockNumber(ctx)
	if err != nil {
		return performanceEvidence{}, fmt.Errorf("get performance block limit: %w", err)
	}
	result := performanceEvidence{
		WarmupCount:        cfg.PerformanceWarmup,
		SampleCount:        cfg.PerformanceSamples,
		DeploymentExcluded: true,
		Payload:            "deterministic unique TrustDBAnchorV1 publish calls with identical fields in both modes",
		TimingSamples:      make([]performanceTimingSample, 0, cfg.PerformanceSamples),
		WarmupVerificationSamples: make(
			[]performanceVerificationSample,
			0,
			cfg.PerformanceWarmup,
		),
		VerificationSamples: make(
			[]performanceVerificationSample,
			0,
			cfg.PerformanceSamples,
		),
	}
	if cfg.RawEVM {
		result.Payload = "deterministic unique raw-EVM calls with one input byte each"
	}
	total := cfg.PerformanceWarmup + cfg.PerformanceSamples
	for index := 0; index < total; index++ {
		callInput, err := performanceCallInput(parsed, cfg.RawEVM, index)
		if err != nil {
			return performanceEvidence{}, err
		}
		hash, receipt, phases, err := sendEncoded(ctx, c, &address, callInput, "", current+600)
		if err != nil {
			return performanceEvidence{}, fmt.Errorf("performance transaction %d: %w", index, err)
		}
		if receipt == nil || receipt.Status != types.Success {
			status := -1
			if receipt != nil {
				status = receipt.Status
			}
			return performanceEvidence{}, fmt.Errorf("performance transaction %d receipt status: %d", index, status)
		}
		timing, verification, err := collectPerformanceEvidence(
			ctx,
			c,
			hash,
			receipt,
			phases,
			!cfg.RawEVM,
		)
		if err != nil {
			return performanceEvidence{}, fmt.Errorf("collect performance transaction %d: %w", index, err)
		}
		if index < cfg.PerformanceWarmup {
			result.WarmupVerificationSamples = append(result.WarmupVerificationSamples, verification)
			continue
		}
		result.TimingSamples = append(result.TimingSamples, timing)
		result.VerificationSamples = append(result.VerificationSamples, verification)
	}
	runBinding, err := performanceRunBinding(cfg.Mode, result)
	if err != nil {
		return performanceEvidence{}, err
	}
	result.RunBinding = runBinding
	return result, nil
}

func performanceCallInput(parsed abi.ABI, rawEVM bool, index int) ([]byte, error) {
	if index < 0 || index >= 256 {
		return nil, errors.New("performance sample index is outside the bounded input domain")
	}
	if rawEVM {
		return []byte{byte(index)}, nil
	}
	payload := performanceAnchorPayload(index)
	input, err := packAnchorCall(parsed, payload)
	if err != nil {
		return nil, fmt.Errorf("pack performance publish call %d: %w", index, err)
	}
	return input, nil
}

func performanceDigest(index int) [32]byte {
	return deterministicDigest("performance-anchor", index)
}

func deterministicDigest(label string, index int) [32]byte {
	var encodedIndex [8]byte
	binary.BigEndian.PutUint64(encodedIndex[:], uint64(index))
	hash := sha256.New()
	_, _ = hash.Write([]byte("trustdb.fisco-bcos.smoke.v1\x00"))
	_, _ = hash.Write([]byte(label))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(encodedIndex[:])
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func functionalAnchorPayload() anchorPayload {
	return anchorPayload{
		AnchorID:        deterministicDigest("functional-anchor", 0),
		StreamID:        deterministicDigest("stream", 0),
		TreeSize:        1,
		RootHash:        deterministicDigest("functional-root", 0),
		SignedSTHDigest: deterministicDigest("functional-sth", 0),
		PayloadVersion:  1,
	}
}

func performanceAnchorPayload(index int) anchorPayload {
	return anchorPayload{
		AnchorID:        performanceDigest(index),
		StreamID:        deterministicDigest("stream", 0),
		TreeSize:        uint64(index) + 2,
		RootHash:        deterministicDigest("performance-root", index),
		SignedSTHDigest: deterministicDigest("performance-sth", index),
		PayloadVersion:  1,
	}
}

func packAnchorCall(parsed abi.ABI, payload anchorPayload) ([]byte, error) {
	return parsed.Pack(
		"publish",
		payload.AnchorID,
		payload.StreamID,
		payload.TreeSize,
		payload.RootHash,
		payload.SignedSTHDigest,
		payload.PayloadVersion,
	)
}

func verifyAnchorPublishedEvent(
	parsed abi.ABI,
	event types.Log,
	payload anchorPayload,
	publisher common.Address,
) error {
	published, ok := parsed.Events["AnchorPublished"]
	if !ok {
		return errors.New("compiled ABI does not contain AnchorPublished event")
	}
	expectedTopics := []common.Hash{
		published.ID(),
		common.BytesToHash(payload.AnchorID[:]),
		common.BytesToHash(payload.StreamID[:]),
		common.BytesToHash(publisher.Bytes()),
	}
	if len(event.Topics) != len(expectedTopics) {
		return fmt.Errorf("AnchorPublished topic count = %d, want %d", len(event.Topics), len(expectedTopics))
	}
	for index := range expectedTopics {
		if event.Topics[index] != expectedTopics[index] {
			return fmt.Errorf("AnchorPublished topic %d does not match the submitted payload", index)
		}
	}
	var decoded anchorPublishedData
	if err := parsed.Unpack(&decoded, "AnchorPublished", event.Data); err != nil {
		return fmt.Errorf("decode AnchorPublished data: %w", err)
	}
	if decoded.TreeSize != payload.TreeSize ||
		decoded.RootHash != payload.RootHash ||
		decoded.SignedSTHDigest != payload.SignedSTHDigest ||
		decoded.PayloadVersion != payload.PayloadVersion {
		return errors.New("AnchorPublished data does not match the submitted payload")
	}
	return nil
}

func verifyStoredAnchor(
	ctx context.Context,
	c *client.Client,
	parsed abi.ABI,
	address common.Address,
	payload anchorPayload,
	publisher common.Address,
) error {
	input, err := parsed.Pack("getAnchor", payload.AnchorID)
	if err != nil {
		return fmt.Errorf("pack getAnchor call: %w", err)
	}
	output, err := c.CallContract(ctx, ethereum.CallMsg{
		From: publisher,
		To:   &address,
		Data: input,
	})
	if err != nil {
		return fmt.Errorf("call getAnchor: %w", err)
	}
	var record storedAnchorRecord
	if err := parsed.Unpack(&record, "getAnchor", output); err != nil {
		return fmt.Errorf("decode getAnchor result: %w", err)
	}
	if !record.Exists ||
		record.StreamID != payload.StreamID ||
		record.TreeSize != payload.TreeSize ||
		record.RootHash != payload.RootHash ||
		record.SignedSTHDigest != payload.SignedSTHDigest ||
		record.Publisher != publisher ||
		record.PayloadVersion != payload.PayloadVersion {
		return errors.New("getAnchor record does not match the submitted payload and publisher")
	}
	return nil
}

func newAnchorPayloadEvidence(payload anchorPayload, publisher common.Address) *anchorPayloadEvidence {
	return &anchorPayloadEvidence{
		AnchorID:        common.BytesToHash(payload.AnchorID[:]).Hex(),
		StreamID:        common.BytesToHash(payload.StreamID[:]).Hex(),
		TreeSize:        payload.TreeSize,
		RootHash:        common.BytesToHash(payload.RootHash[:]).Hex(),
		SignedSTHDigest: common.BytesToHash(payload.SignedSTHDigest[:]).Hex(),
		PayloadVersion:  payload.PayloadVersion,
		Publisher:       publisher.Hex(),
	}
}

func performanceRunBinding(mode string, input performanceEvidence) (string, error) {
	hash := sha256.New()
	_, _ = hash.Write([]byte("trustdb.fisco-bcos.performance.v1\x00"))
	if err := writeBindingString(hash, mode); err != nil {
		return "", err
	}
	var counts [8]byte
	binary.BigEndian.PutUint32(counts[:4], uint32(input.WarmupCount))
	binary.BigEndian.PutUint32(counts[4:], uint32(input.SampleCount))
	_, _ = hash.Write(counts[:])
	samples := make(
		[]performanceVerificationSample,
		0,
		len(input.WarmupVerificationSamples)+len(input.VerificationSamples),
	)
	samples = append(samples, input.WarmupVerificationSamples...)
	samples = append(samples, input.VerificationSamples...)
	for index, sample := range samples {
		if sample.Receipt == nil || sample.Block == nil {
			return "", fmt.Errorf("performance binding sample %d is incomplete", index)
		}
		if err := writeBindingString(hash, strings.ToLower(sample.Receipt.TransactionHash)); err != nil {
			return "", err
		}
		if err := writeBindingString(hash, strings.ToLower(sample.Block.Hash)); err != nil {
			return "", err
		}
	}
	for index, sample := range input.TimingSamples {
		values := [...]int64{
			sample.PrepareSignEncodeNS,
			sample.SubmitToReceiptNS,
			sample.ReceiptProofRetrievalNS,
			sample.TransactionProofRetrievalNS,
			sample.BlockRetrievalNS,
		}
		for stage, value := range values {
			if value < 0 {
				return "", fmt.Errorf("performance timing sample %d stage %d is negative", index, stage)
			}
			var encoded [8]byte
			binary.BigEndian.PutUint64(encoded[:], uint64(value))
			_, _ = hash.Write(encoded[:])
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type bindingWriter interface {
	Write([]byte) (int, error)
}

func writeBindingString(destination bindingWriter, value string) error {
	if value == "" || len(value) > 1<<16 {
		return errors.New("performance binding value is empty or oversized")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	if _, err := destination.Write(size[:]); err != nil {
		return err
	}
	_, err := destination.Write([]byte(value))
	return err
}

const consensusPrecompileABI = `[{"inputs":[{"internalType":"string","name":"nodeID","type":"string"},{"internalType":"uint256","name":"weight","type":"uint256"}],"name":"setWeight","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"nonpayable","type":"function"}]`

func scenarioAnchorPayload(label string, treeSize uint64) anchorPayload {
	return anchorPayload{
		AnchorID:        deterministicDigest(label+"-anchor", int(treeSize)),
		StreamID:        deterministicDigest("qualification-stream", 0),
		TreeSize:        treeSize,
		RootHash:        deterministicDigest(label+"-root", int(treeSize)),
		SignedSTHDigest: deterministicDigest(label+"-sth", int(treeSize)),
		PayloadVersion:  1,
	}
}

func awaitScenarioGate(ctx context.Context, directory, name string) error {
	if directory == "" {
		return nil
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create scenario directory: %w", err)
	}
	ready := filepath.Join(directory, name+".ready")
	proceed := filepath.Join(directory, name+".continue")
	if err := os.WriteFile(ready, []byte(name+"\n"), 0o600); err != nil {
		return fmt.Errorf("write scenario marker %s: %w", name, err)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(proceed); err == nil {
			if err := os.Remove(proceed); err != nil {
				return fmt.Errorf("consume scenario marker %s: %w", name, err)
			}
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect scenario marker %s: %w", name, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for scenario %s: %w", name, ctx.Err())
		case <-ticker.C:
		}
	}
}

func submitScenarioAnchor(
	ctx context.Context,
	c *client.Client,
	parsed abi.ABI,
	address common.Address,
	payload anchorPayload,
) (txEvidence, error) {
	input, err := packAnchorCall(parsed, payload)
	if err != nil {
		return txEvidence{}, err
	}
	height, err := c.GetBlockNumber(ctx)
	if err != nil {
		return txEvidence{}, fmt.Errorf("get scenario block limit: %w", err)
	}
	hash, receipt, phases, err := sendEncoded(ctx, c, &address, input, "", height+600)
	if err != nil {
		return txEvidence{}, err
	}
	if receipt == nil || receipt.Status != types.Success {
		status := -1
		if receipt != nil {
			status = receipt.Status
		}
		return txEvidence{}, fmt.Errorf("scenario anchor receipt status: %d", status)
	}
	evidence, err := collectTxEvidence(ctx, c, hash, receipt, phases)
	if err != nil {
		return txEvidence{}, err
	}
	if err := verifyStoredAnchor(ctx, c, parsed, address, payload, c.GetTransactOpts().From); err != nil {
		return txEvidence{}, err
	}
	return evidence, nil
}

func setValidatorWeight(
	ctx context.Context,
	c *client.Client,
	mode string,
	nodeID string,
	weight uint,
) (txEvidence, error) {
	parsed, err := abi.JSON(strings.NewReader(consensusPrecompileABI))
	if err != nil {
		return txEvidence{}, fmt.Errorf("parse consensus precompile ABI: %w", err)
	}
	if mode == "guomi" {
		parsed.SetSMCrypto()
	}
	input, err := parsed.Pack("setWeight", nodeID, new(big.Int).SetUint64(uint64(weight)))
	if err != nil {
		return txEvidence{}, fmt.Errorf("pack setWeight: %w", err)
	}
	height, err := c.GetBlockNumber(ctx)
	if err != nil {
		return txEvidence{}, fmt.Errorf("get setWeight block limit: %w", err)
	}
	address := common.HexToAddress("0x0000000000000000000000000000000000001003")
	hash, receipt, phases, err := sendEncoded(ctx, c, &address, input, "", height+600)
	if err != nil {
		return txEvidence{}, fmt.Errorf("submit setWeight: %w", err)
	}
	if receipt == nil || receipt.Status != types.Success {
		status := -1
		if receipt != nil {
			status = receipt.Status
		}
		return txEvidence{}, fmt.Errorf("setWeight receipt status: %d", status)
	}
	code, err := precompiled.ParseBigIntFromOutput(receipt)
	if err != nil {
		return txEvidence{}, fmt.Errorf("decode setWeight return value: %w", err)
	}
	if code.Sign() != 0 {
		return txEvidence{}, fmt.Errorf("setWeight return code: %s", code)
	}
	return collectTxEvidence(ctx, c, hash, receipt, phases)
}

func waitForValidatorWeight(
	ctx context.Context,
	c *client.Client,
	nodeID string,
	weight uint,
) ([]client.ConsensusNodeInfo, error) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		sealers, err := c.GetSealerList(ctx)
		if err == nil {
			for _, sealer := range sealers {
				if sealer.ID == nodeID && sealer.Weight == weight {
					return sealers, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for validator %s weight %d: %w", nodeID, weight, ctx.Err())
		case <-ticker.C:
		}
	}
}

func waitForRestartedNodeCatchup(
	ctx context.Context,
	reference *client.Client,
	cfg config,
	contract common.Address,
) (int64, int64, error) {
	restartConfig := cfg
	restartConfig.Port = cfg.RestartPort
	sdkCfg, err := sdkConfig(restartConfig)
	if err != nil {
		return 0, 0, fmt.Errorf("configure restarted-node SDK: %w", err)
	}
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	restarted, err := client.DialContext(dialCtx, sdkCfg)
	if err != nil {
		return 0, 0, fmt.Errorf("dial restarted validator on port %d: %w", cfg.RestartPort, err)
	}
	defer restarted.Close()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		referenceHeight, referenceErr := reference.GetBlockNumber(ctx)
		restartedHeight, restartedErr := restarted.GetBlockNumber(ctx)
		sealers, sealersErr := restarted.GetSealerList(ctx)
		referenceCode, referenceCodeErr := reference.GetCode(ctx, contract)
		restartedCode, restartedCodeErr := restarted.GetCode(ctx, contract)
		if referenceErr == nil && restartedErr == nil && sealersErr == nil &&
			referenceCodeErr == nil && restartedCodeErr == nil &&
			len(sealers) == 4 && restartedHeight >= referenceHeight &&
			bytes.Equal(referenceCode, restartedCode) {
			return restartedHeight, referenceHeight, nil
		}
		select {
		case <-ctx.Done():
			return 0, 0, fmt.Errorf("wait for restarted validator catch-up: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func runQualificationScenarios(
	ctx context.Context,
	c *client.Client,
	cfg config,
	parsed abi.ABI,
	address common.Address,
	initialSealers []client.ConsensusNodeInfo,
) (*qualificationEvidence, error) {
	if cfg.ScenarioDir == "" {
		return nil, nil
	}
	if len(initialSealers) != 4 {
		return nil, fmt.Errorf("qualification requires four initial sealers, got %d", len(initialSealers))
	}
	if err := awaitScenarioGate(ctx, cfg.ScenarioDir, "node-loss"); err != nil {
		return nil, err
	}
	nodeLoss, err := submitScenarioAnchor(
		ctx,
		c,
		parsed,
		address,
		scenarioAnchorPayload("node-loss", 10_001),
	)
	if err != nil {
		return nil, fmt.Errorf("submit with one validator offline: %w", err)
	}
	if err := awaitScenarioGate(ctx, cfg.ScenarioDir, "node-restart"); err != nil {
		return nil, err
	}
	restartedHeight, referenceHeight, err := waitForRestartedNodeCatchup(ctx, c, cfg, address)
	if err != nil {
		return nil, err
	}
	postRestart, err := submitScenarioAnchor(
		ctx,
		c,
		parsed,
		address,
		scenarioAnchorPayload("post-restart", 10_002),
	)
	if err != nil {
		return nil, fmt.Errorf("submit after validator restart: %w", err)
	}

	target := initialSealers[len(initialSealers)-1]
	changedWeight := target.Weight + 1
	changedTransaction, err := setValidatorWeight(ctx, c, cfg.Mode, target.ID, changedWeight)
	if err != nil {
		return nil, fmt.Errorf("increase validator weight: %w", err)
	}
	sealersAfterChange, err := waitForValidatorWeight(ctx, c, target.ID, changedWeight)
	if err != nil {
		return nil, err
	}
	restoredTransaction, err := setValidatorWeight(ctx, c, cfg.Mode, target.ID, target.Weight)
	if err != nil {
		return nil, fmt.Errorf("restore validator weight: %w", err)
	}
	sealersAfterRestore, err := waitForValidatorWeight(ctx, c, target.ID, target.Weight)
	if err != nil {
		return nil, err
	}
	return &qualificationEvidence{
		NodeLossTransaction:    nodeLoss,
		PostRestartTransaction: postRestart,
		RestartedNodeHeight:    restartedHeight,
		ReferenceNodeHeight:    referenceHeight,
		ValidatorTransition: validatorTransitionEvidence{
			NodeID:              target.ID,
			InitialWeight:       target.Weight,
			ChangedWeight:       changedWeight,
			RestoredWeight:      target.Weight,
			ChangedTransaction:  changedTransaction,
			RestoredTransaction: restoredTransaction,
			SealersAfterChange:  sealersAfterChange,
			SealersAfterRestore: sealersAfterRestore,
		},
	}, nil
}

func main() {
	cfg := parseFlags()
	parsed, contractBin, abiJSON := readContract(cfg)

	timeout := 8 * time.Minute
	if cfg.ScenarioDir != "" {
		timeout = 12 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	sdkCfg, err := sdkConfig(cfg)
	if err != nil {
		fatalf("configure Go SDK: %v", err)
	}
	c, err := client.DialContext(ctx, sdkCfg)
	if err != nil {
		fatalf("dial Go SDK: %v", err)
	}
	if c.SMCrypto() != (cfg.Mode == "guomi") {
		fatalf("negotiated crypto mode mismatch: want %s, sm=%v", cfg.Mode, c.SMCrypto())
	}

	initial, err := c.GetBlockNumber(ctx)
	if err != nil {
		fatalf("get initial block number: %v", err)
	}
	chainID, err := c.GetChainID(ctx)
	if err != nil || chainID == "" {
		fatalf("get chain ID: %v", err)
	}
	genesisHash, err := c.GetBlockHashByNumber(ctx, 0)
	if err != nil || genesisHash == nil {
		fatalf("get genesis hash: %v", err)
	}
	constructorArgs := []any{}
	if cfg.AnchorV1Constructor {
		publisher := c.GetTransactOpts().From
		constructorArgs = append(constructorArgs, publisher, []common.Address{publisher})
	}
	constructor, err := parsed.Pack("", constructorArgs...)
	if err != nil {
		fatalf("pack constructor: %v", err)
	}
	deployInput := append(common.FromHex(contractBin), constructor...)
	deployHash, deployReceipt, deployPhases, err := sendEncoded(ctx, c, nil, deployInput, abiJSON, initial+600)
	if err != nil {
		fatalf("deploy transaction: %v", err)
	}
	if deployReceipt.Status != types.Success {
		fatalf("deploy receipt status: %d (%s)", deployReceipt.Status, deployReceipt.GetErrorMessage())
	}
	deployEvidence, err := collectTxEvidence(ctx, c, deployHash, deployReceipt, deployPhases)
	if err != nil {
		fatalf("collect deploy evidence: %v", err)
	}
	if !deployEvidence.ReceiptProofPresent || !deployEvidence.TxProofPresent {
		fatalf("proof fields are absent from deploy transaction response")
	}
	checkpointHash, err := c.GetBlockHashByNumber(ctx, int64(deployReceipt.BlockNumber))
	if err != nil || checkpointHash == nil {
		fatalf("get trusted checkpoint hash at block %d: %v", deployReceipt.BlockNumber, err)
	}

	address := common.HexToAddress(deployReceipt.ContractAddress)
	contractCodeHash, err := observedContractCodeHash(ctx, c, cfg.Mode, address)
	if err != nil {
		fatalf("hash deployed contract code: %v", err)
	}
	publisher := c.GetTransactOpts().From
	functionalPayload := functionalAnchorPayload()
	var publishedEvent *abi.Event
	eventTopics := []string{}
	if !cfg.RawEVM {
		var ok bool
		publishedEvent, ok = parsed.Events["AnchorPublished"]
		if !ok {
			fatalf("compiled ABI does not contain AnchorPublished event")
		}
		eventTopics = []string{publishedEvent.ID().Hex()}
	}
	eventChannel := make(chan types.Log, 1)
	fromBlock := int64(deployReceipt.BlockNumber)
	taskID, err := c.SubscribeEventLogs(ctx, types.EventLogParams{
		FromBlock: fromBlock,
		ToBlock:   -1,
		Addresses: []string{strings.ToLower(address.Hex())},
		Topics:    eventTopics,
	}, func(status int, logs []types.Log) {
		if status == 0 && len(logs) > 0 {
			select {
			case eventChannel <- logs[0]:
			default:
			}
		}
	})
	if err != nil {
		fatalf("subscribe event: %v", err)
	}
	callInput := []byte{1}
	if !cfg.RawEVM {
		callInput, err = packAnchorCall(parsed, functionalPayload)
		if err != nil {
			fatalf("pack production publish call: %v", err)
		}
	}
	current, err := c.GetBlockNumber(ctx)
	if err != nil {
		fatalf("get block number before event transaction: %v", err)
	}
	eventHash, eventReceipt, eventPhases, err := sendEncoded(ctx, c, &address, callInput, "", current+600)
	if err != nil {
		fatalf("event transaction: %v", err)
	}
	if eventReceipt.Status != types.Success {
		fatalf("event receipt status: %d (%s)", eventReceipt.Status, eventReceipt.GetErrorMessage())
	}
	eventEvidence, err := collectTxEvidence(ctx, c, eventHash, eventReceipt, eventPhases)
	if err != nil {
		fatalf("collect event transaction evidence: %v", err)
	}
	if !eventEvidence.ReceiptProofPresent || !eventEvidence.TxProofPresent {
		fatalf("proof fields are absent from event transaction response")
	}
	queriedEventReceipt, err := c.GetTransactionReceipt(ctx, eventHash, true)
	if err != nil {
		fatalf("query event receipt for consensus hash: %v", err)
	}

	var event types.Log
	select {
	case event = <-eventChannel:
	case <-time.After(10 * time.Second):
		fatalf("timed out waiting for AnchorPublished event")
	}
	if event.TxHash != eventHash {
		fatalf("event transaction mismatch: want %s, got %s", eventHash.Hex(), event.TxHash.Hex())
	}
	if event.Address != address {
		fatalf("event address mismatch: want %s, got %s", address.Hex(), event.Address.Hex())
	}
	if cfg.RawEVM {
		if len(event.Topics) != 0 || len(event.Data) != 0 {
			fatalf("raw EVM fixture emitted unexpected topics or data")
		}
	} else {
		if err := verifyAnchorPublishedEvent(parsed, event, functionalPayload, publisher); err != nil {
			fatalf("verify production AnchorPublished event: %v", err)
		}
		if err := verifyStoredAnchor(
			ctx,
			c,
			parsed,
			address,
			functionalPayload,
			publisher,
		); err != nil {
			fatalf("verify production getAnchor record: %v", err)
		}
	}
	if err := c.UnSubscribeEventLogs(context.Background(), taskID); err != nil {
		fatalf("unsubscribe event logs: %v", err)
	}
	// The native event unsubscription has no completion callback. Drain it
	// before sampling so its background work does not contaminate the
	// post-warmup comparison.
	time.Sleep(time.Second)

	block, err := c.GetBlockByNumber(ctx, int64(eventReceipt.BlockNumber), false, true)
	if err != nil {
		fatalf("get containing block: %v", err)
	}
	if block.Hash == "" || block.TxsRoot == "" || block.ReceiptsRoot == "" || len(block.SignatureList) == 0 {
		fatalf("containing block lacks hash, roots, or signatures")
	}
	consensus, err := c.GetConsensusStatus(ctx)
	if err != nil {
		fatalf("get consensus status: %v", err)
	}
	sealers, err := c.GetSealerList(ctx)
	if err != nil {
		fatalf("get sealer list: %v", err)
	}
	if len(sealers) != 4 {
		fatalf("expected four sealers, got %d", len(sealers))
	}
	qualification, err := runQualificationScenarios(ctx, c, cfg, parsed, address, sealers)
	if err != nil {
		fatalf("run four-node qualification scenarios: %v", err)
	}
	performance, err := runPerformanceSamples(ctx, c, cfg, parsed, address)
	if err != nil {
		fatalf("collect post-warmup performance evidence: %v", err)
	}

	finalBlock, err := c.GetBlockNumber(ctx)
	if err != nil {
		fatalf("get final block number: %v", err)
	}
	staleLimit := finalBlock - 1
	if staleLimit < 0 {
		staleLimit = 0
	}
	_, staleReceipt, _, staleErr := sendEncoded(ctx, c, &address, callInput, "", staleLimit)
	staleRejected := staleErr != nil || (staleReceipt != nil && staleReceipt.Status == types.BlockLimitCheckFail)
	if !staleRejected {
		status := -1
		if staleReceipt != nil {
			status = staleReceipt.Status
		}
		fatalf("stale blockLimit=%d was not rejected; receipt status=%d", staleLimit, status)
	}
	staleError := ""
	if staleErr != nil {
		staleError = staleErr.Error()
	}

	output := evidence{
		SchemaVersion:   1,
		TimingSemantics: "single_sample_diagnostic_not_benchmark",
		Mode:            cfg.Mode,
		SMCrypto:        c.SMCrypto(),
		ChainID:         chainID,
		GenesisHash:     genesisHash.Hex(),
		TrustedCheckpoint: trustedCheckpointEvidence{
			BlockNumber: uint64(deployReceipt.BlockNumber),
			BlockHash:   checkpointHash.Hex(),
		},
		ContractCodeHash:    contractCodeHash,
		InitialBlockNumber:  initial,
		FinalBlockNumber:    finalBlock,
		Deployment:          deployEvidence,
		EventTransaction:    eventEvidence,
		EventReceipt:        queriedEventReceipt,
		Event:               event,
		Block:               block,
		ConsensusStatus:     consensus,
		Sealers:             sealers,
		StaleBlockLimit:     staleLimit,
		StaleLimitRejected:  staleRejected,
		StaleRejectionError: staleError,
		Performance:         performance,
		Qualification:       qualification,
		ProbeSource: func() string {
			if cfg.RawEVM {
				return "compiler-independent-raw-evm-log0"
			}
			return "pinned-solidity-compiler"
		}(),
	}
	if !cfg.RawEVM {
		output.AnchorPayload = newAnchorPayloadEvidence(functionalPayload, publisher)
		output.ProductionPublish = true
	}
	c.Close()
	output.CleanTeardown = true
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(output); err != nil {
		fatalf("encode evidence: %v", err)
	}
}
