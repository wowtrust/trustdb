package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/FISCO-BCOS/go-sdk/v3/abi"
	"github.com/FISCO-BCOS/go-sdk/v3/client"
	"github.com/FISCO-BCOS/go-sdk/v3/types"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

type config struct {
	Mode               string
	Host               string
	Port               int
	CertDir            string
	ABIPath            string
	BINPath            string
	RawEVM             bool
	PerformanceWarmup  int
	PerformanceSamples int
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
	WarmupCount               int                             `json:"warmup_count"`
	SampleCount               int                             `json:"sample_count"`
	Payload                   string                          `json:"payload"`
	DeploymentExcluded        bool                            `json:"deployment_excluded"`
	TimingSamples             []performanceTimingSample       `json:"timing_samples"`
	WarmupVerificationSamples []performanceVerificationSample `json:"warmup_verification_samples"`
	VerificationSamples       []performanceVerificationSample `json:"verification_samples"`
}

type evidence struct {
	SchemaVersion       int                        `json:"schema_version"`
	TimingSemantics     string                     `json:"timing_semantics"`
	Mode                string                     `json:"mode"`
	SMCrypto            bool                       `json:"sm_crypto"`
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
	ProbeSource         string                     `json:"probe_source"`
	Performance         performanceEvidence        `json:"performance"`
	CleanTeardown       bool                       `json:"clean_teardown"`
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
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral smoke key: %w", err)
	}
	result := &client.Config{
		IsSMCrypto: cfg.Mode == "guomi",
		PrivateKey: ethcrypto.FromECDSA(privateKey),
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
	address common.Address,
	callInput []byte,
) (performanceEvidence, error) {
	current, err := c.GetBlockNumber(ctx)
	if err != nil {
		return performanceEvidence{}, fmt.Errorf("get performance block limit: %w", err)
	}
	result := performanceEvidence{
		WarmupCount:        cfg.PerformanceWarmup,
		SampleCount:        cfg.PerformanceSamples,
		DeploymentExcluded: true,
		Payload:            "fixed anchor(bytes32) call with one 32-byte digest",
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
		result.Payload = "fixed raw-EVM call with one input byte"
	}
	total := cfg.PerformanceWarmup + cfg.PerformanceSamples
	for index := 0; index < total; index++ {
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
		timing, verification, err := collectPerformanceEvidence(ctx, c, hash, receipt, phases)
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
	return result, nil
}

func main() {
	cfg := parseFlags()
	parsed, contractBin, abiJSON := readContract(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
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
	constructor, err := parsed.Pack("")
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

	address := common.HexToAddress(deployReceipt.ContractAddress)
	var anchoredEvent *abi.Event
	eventTopics := []string{}
	if !cfg.RawEVM {
		var ok bool
		anchoredEvent, ok = parsed.Events["Anchored"]
		if !ok {
			fatalf("compiled ABI does not contain Anchored event")
		}
		eventTopics = []string{anchoredEvent.ID().Hex()}
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
	var expectedDigest [32]byte
	if !cfg.RawEVM {
		copy(expectedDigest[:], []byte("trustdb-fisco-compatibility-probe"))
		callInput, err = parsed.Pack("anchor", expectedDigest)
		if err != nil {
			fatalf("pack anchor call: %v", err)
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
		fatalf("timed out waiting for Anchored event")
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
		expectedTopics := []common.Hash{
			anchoredEvent.ID(),
			common.BytesToHash(expectedDigest[:]),
		}
		if len(event.Topics) != len(expectedTopics) || event.Topics[0] != expectedTopics[0] || event.Topics[1] != expectedTopics[1] {
			fatalf("Anchored event topics do not match the ABI signature and submitted digest")
		}
		if len(event.Data) != 0 {
			fatalf("Anchored event unexpectedly contains non-indexed data")
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
	performance, err := runPerformanceSamples(ctx, c, cfg, address, callInput)
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
		SchemaVersion:       1,
		TimingSemantics:     "single_sample_diagnostic_not_benchmark",
		Mode:                cfg.Mode,
		SMCrypto:            c.SMCrypto(),
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
		ProbeSource: func() string {
			if cfg.RawEVM {
				return "compiler-independent-raw-evm-log0"
			}
			return "pinned-solidity-compiler"
		}(),
	}
	c.Close()
	output.CleanTeardown = true
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(output); err != nil {
		fatalf("encode evidence: %v", err)
	}
}
