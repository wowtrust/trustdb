//go:build fiscobcos_sdk && cgo

package standardsdk

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FISCO-BCOS/go-sdk/v3/client"
	"github.com/FISCO-BCOS/go-sdk/v3/types"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
)

const (
	maxCertificateBytes         = 4 << 20
	maxSDKRuntimeCodeBytes      = 4 << 20
	maxSDKRawTransactionBytes   = 4 << 20
	maxSDKRawReceiptBytes       = 4 << 20
	maxSDKRawHeaderBytes        = 2 << 20
	maxSDKDecodedEventBytes     = 1 << 20
	maxSDKProofNodeBytes        = 128 << 10
	maxSDKProofNodes            = 512
	maxSDKCommitSignatures      = 1024
	maxSDKValidators            = 1024
	maxSDKReceiptLogs           = 1024
	maxSDKLogTopics             = 16
	maxSDKSignatureBytes        = 1024
	maxSDKConfigStringBytes     = 4096
	maxSDKTransactionsPerBlock  = 65536
	maxSDKParentBlocks          = 1024
	maxSDKConsensusWeights      = 1024
	maxSDKTransactionNonceBytes = 1024
	supportedNativeVersion      = "3.6.0"
	supportedNativeCommit       = "53240138c396c10cb0e1a2b7b4d5c0cdaa0ac539"
)

type nativeDriver struct {
	endpoint   string
	client     *client.Client
	trust      fiscobcos.TrustConfig
	signer     AccountSigner
	publicKey  []byte
	sender     []byte
	clock      func() time.Time
	sdkVersion string
}

func (NativeFactory) NewDrivers(ctx context.Context, config Config) ([]fiscobcos.Driver, error) {
	canonical, err := canonicalStandardTrust(config.TrustConfig)
	if err != nil {
		return nil, err
	}
	sdkVersion, err := observeAndVerifyNativeRuntime()
	if err != nil {
		return nil, err
	}
	if err := verifyCertificateReferences(canonical, config.AccountSigner == nil); err != nil {
		return nil, err
	}
	caPath, err := localPath(canonical.Certificates.TrustedCAReferences[0])
	if err != nil {
		return nil, err
	}
	certPath, err := localPath(canonical.Certificates.ClientSigningCertificateRef)
	if err != nil {
		return nil, err
	}
	tlsKeyPath, err := localPath(canonical.Certificates.ClientSigningKeyRef)
	if err != nil {
		return nil, err
	}
	signer := config.AccountSigner
	if signer == nil {
		signer, err = newSoftwareAccountSigner(canonical.AccountProvider)
		if err != nil {
			return nil, err
		}
	}
	publicKey, err := signer.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("read FISCO BCOS account public key: %w", err)
	}
	if len(publicKey) != 65 || publicKey[0] != 0x04 {
		return nil, errors.New("FISCO BCOS account signer returned a non-canonical secp256k1 public key")
	}
	sender := accountAddress(publicKey)
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	drivers := make([]fiscobcos.Driver, 0, len(canonical.Endpoints))
	for _, endpoint := range canonical.Endpoints {
		host, port, err := parseEndpoint(endpoint)
		if err != nil {
			closeDrivers(drivers)
			return nil, err
		}
		ephemeral, err := ethcrypto.GenerateKey()
		if err != nil {
			closeDrivers(drivers)
			return nil, fmt.Errorf("initialize FISCO BCOS SDK account placeholder: %w", err)
		}
		sdkConfig := &client.Config{
			IsSMCrypto:  false,
			PrivateKey:  ethcrypto.FromECDSA(ephemeral),
			GroupID:     canonical.GroupID,
			Host:        host,
			Port:        port,
			DisableSsl:  false,
			TLSCaFile:   caPath,
			TLSCertFile: certPath,
			TLSKeyFile:  tlsKeyPath,
		}
		sdkClient, err := client.DialContext(ctx, sdkConfig)
		if err != nil {
			closeDrivers(drivers)
			return nil, fmt.Errorf("dial FISCO BCOS endpoint %q: %w", endpoint, err)
		}
		if sdkClient.SMCrypto() {
			sdkClient.Close()
			closeDrivers(drivers)
			return nil, fmt.Errorf("%w: endpoint %q negotiated Guomi mode", fiscobcos.ErrWrongNetwork, endpoint)
		}
		drivers = append(drivers, &nativeDriver{
			endpoint: endpoint, client: sdkClient, trust: canonical, signer: signer,
			publicKey: append([]byte(nil), publicKey...),
			sender:    append([]byte(nil), sender...), clock: clock,
			sdkVersion: sdkVersion,
		})
	}
	return drivers, nil
}

func (d *nativeDriver) Endpoint() string { return d.endpoint }

func (d *nativeDriver) ProbeChain(ctx context.Context) (fiscobcos.ChainProbe, error) {
	chainID, err := d.client.GetChainID(ctx)
	if err != nil {
		return fiscobcos.ChainProbe{}, err
	}
	height, err := d.client.GetBlockNumber(ctx)
	if err != nil {
		return fiscobcos.ChainProbe{}, err
	}
	if height < 0 {
		return fiscobcos.ChainProbe{}, fiscobcos.ErrDriverInvalid
	}
	genesis, err := d.client.GetBlockHashByNumber(ctx, 0)
	if err != nil {
		return fiscobcos.ChainProbe{}, err
	}
	checkpoint, err := d.client.GetBlockHashByNumber(ctx, int64(d.trust.TrustedCheckpoint.BlockNumber))
	if err != nil {
		return fiscobcos.ChainProbe{}, err
	}
	codeJSON, err := d.client.GetCode(ctx, common.BytesToAddress(d.trust.Contract.Address))
	if err != nil {
		return fiscobcos.ChainProbe{}, err
	}
	code, err := decodeSDKHexJSON(codeJSON, maxSDKRuntimeCodeBytes)
	if err != nil {
		return fiscobcos.ChainProbe{}, fmt.Errorf("decode contract runtime: %w", err)
	}
	codeHash := legacyKeccak(code)
	return fiscobcos.ChainProbe{
		Endpoint: d.endpoint, SDKVersion: d.sdkVersion,
		CryptoMode: fiscobcos.CryptoModeStandard, ChainID: chainID,
		GroupID: d.client.GetGroupID(), GenesisHash: genesis.Bytes(),
		CheckpointHash: checkpoint.Bytes(), Height: uint64(height),
		ContractCodeHash: codeHash,
	}, nil
}

func (d *nativeDriver) SubmitAnchor(ctx context.Context, request fiscobcos.SubmitRequest) (fiscobcos.Submission, error) {
	canonical, err := fiscobcos.MarshalPayload(request.Payload)
	if err != nil || !bytes.Equal(canonical, request.CanonicalPayload) {
		return fiscobcos.Submission{}, fiscobcos.ErrInvalidPayload
	}
	callData, err := fiscobcos.PublishCallData(request.Payload)
	if err != nil {
		return fiscobcos.Submission{}, err
	}
	height, err := d.client.GetBlockNumber(ctx)
	if err != nil {
		return fiscobcos.Submission{}, err
	}
	if height < 0 {
		return fiscobcos.Submission{}, fiscobcos.ErrDriverInvalid
	}
	blockLimit := height + client.BlockLimit
	address := common.BytesToAddress(d.trust.Contract.Address)
	txData, digest, err := d.client.CreateEncodedTransactionDataV1(&address, callData, blockLimit, "")
	if err != nil {
		return fiscobcos.Submission{}, err
	}
	signature, err := d.signer.SignDigest(ctx, append([]byte(nil), digest...))
	if err != nil {
		return fiscobcos.Submission{}, fmt.Errorf("sign FISCO BCOS transaction digest: %w", err)
	}
	if err := validateSignerSignature(digest, signature, d.publicKey); err != nil {
		return fiscobcos.Submission{}, &fiscobcos.DriverError{
			Operation: "sign_anchor", Endpoint: d.endpoint,
			Class: fiscobcos.FailurePermanent, Kind: err,
		}
	}
	encoded, err := d.client.CreateEncodedTransaction(txData, digest, signature, 0, "")
	if err != nil {
		return fiscobcos.Submission{}, err
	}
	if len(encoded) == 0 || len(encoded) > maxSDKRawTransactionBytes {
		return fiscobcos.Submission{}, fiscobcos.ErrDriverInvalid
	}
	// #464 deliberately does not claim durable recovery of this exact attempt
	// when the transport loses the response. #465 persists attempts and #470
	// performs deterministic lookup/rebroadcast before any replacement.
	receipt, err := d.client.SendEncodedTransaction(ctx, encoded, true)
	if err != nil {
		return fiscobcos.Submission{}, &fiscobcos.DriverError{
			Operation: "submit_anchor", Endpoint: d.endpoint,
			Class: fiscobcos.FailureAmbiguous, Kind: err,
		}
	}
	if receipt == nil {
		return fiscobcos.Submission{}, &fiscobcos.DriverError{
			Operation: "submit_anchor", Endpoint: d.endpoint,
			Class: fiscobcos.FailureAmbiguous, Kind: fiscobcos.ErrIncompleteChainEvidence,
		}
	}
	if err := validateReceiptRPCBounds(receipt); err != nil {
		return fiscobcos.Submission{}, &fiscobcos.DriverError{
			Operation: "submit_anchor_receipt", Endpoint: d.endpoint,
			Class: fiscobcos.FailureAmbiguous, Kind: err,
		}
	}
	if err := validateSubmittedReceipt(receipt, digest, d.sender, d.trust.Contract.Address, callData); err != nil {
		statusErr := fiscobcos.NewReceiptStatusError(receipt.Status)
		if !errors.Is(err, fiscobcos.ErrInvalidReceiptStatus) {
			statusErr = nil
		}
		class := fiscobcos.FailureAmbiguous
		if statusErr != nil {
			class = statusErr.FailureClass()
			err = statusErr
		}
		return fiscobcos.Submission{}, &fiscobcos.DriverError{
			Operation: "submit_anchor_receipt", Endpoint: d.endpoint,
			Class: class, Kind: err,
		}
	}
	return fiscobcos.Submission{Attempt: fiscobcos.TransactionSubmission{
		EncodedTransaction: append([]byte(nil), encoded...),
		ChainID:            d.trust.ChainID,
		GroupID:            d.trust.GroupID,
		To:                 append([]byte(nil), d.trust.Contract.Address...),
		Input:              append([]byte(nil), callData...),
		Signature:          append([]byte(nil), signature...),
		Sender:             append([]byte(nil), d.sender...),
		TransactionHash:    append([]byte(nil), digest...),
		BlockLimit:         uint64(blockLimit),
		SubmittedAtUnixN:   d.clock().UTC().UnixNano(),
	}}, nil
}

func (d *nativeDriver) ReadAnchor(ctx context.Context, anchorID []byte) (fiscobcos.AnchorRecord, error) {
	input, err := fiscobcos.GetAnchorCallData(anchorID)
	if err != nil {
		return fiscobcos.AnchorRecord{}, err
	}
	address := common.BytesToAddress(d.trust.Contract.Address)
	output, err := d.client.CallContract(ctx, ethereum.CallMsg{
		From: common.BytesToAddress(d.sender),
		To:   &address,
		Data: input,
	})
	if err != nil {
		return fiscobcos.AnchorRecord{}, err
	}
	return fiscobcos.DecodeAnchorRecord(output)
}

func (d *nativeDriver) GetReceiptWithProof(ctx context.Context, attempt fiscobcos.TransactionSubmission) (fiscobcos.ReceiptWithProof, error) {
	hash, err := strictHash(attempt.TransactionHash)
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	receipt, err := d.client.GetTransactionReceipt(ctx, hash, true)
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	transaction, err := d.client.GetTransactionByHash(ctx, hash, true)
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	if receipt == nil || transaction == nil || receipt.ReceiptProof == nil || transaction.TransactionProof == nil {
		return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
	}
	if err := validateReceiptRPCBounds(receipt); err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	if err := validateTransactionRPCBounds(transaction); err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	if err := validateReceiptTransactionIdentity(receipt, transaction, attempt, d.trust); err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	if receipt.BlockNumber <= 0 {
		return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
	}
	blockHash, err := d.client.GetBlockHashByNumber(ctx, int64(receipt.BlockNumber))
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	event, err := decodeAnchorEvent(receipt, d.trust.Contract)
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	record := fiscobcos.AnchorRecord{
		StreamID: append([]byte(nil), event.StreamID...), TreeSize: event.TreeSize,
		RootHash:        append([]byte(nil), event.RootHash...),
		SignedSTHDigest: append([]byte(nil), event.SignedSTHDigest...),
		Publisher:       append([]byte(nil), event.Publisher...),
		PayloadVersion:  event.PayloadVersion, Exists: true,
	}
	rawReceipt, err := json.Marshal(receipt)
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	if len(rawReceipt) == 0 || len(rawReceipt) > maxSDKRawReceiptBytes {
		return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrDriverInvalid
	}
	receiptHash, err := strictHex32(receipt.Hash)
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, fmt.Errorf("%w: receipt hash: %v", fiscobcos.ErrIncompleteChainEvidence, err)
	}
	transactionPath, err := decodeProofNodes(transaction.TransactionProof)
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	receiptPath, err := decodeProofNodes(receipt.ReceiptProof)
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	txIndex, err := d.transactionIndex(ctx, uint64(receipt.BlockNumber), hash)
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	return fiscobcos.ReceiptWithProof{
		Status: receipt.Status, StatusMessage: boundedReceiptStatus(receipt.Status),
		BlockNumber: uint64(receipt.BlockNumber), BlockHash: blockHash.Bytes(),
		Record: record, Event: event,
		Observation: fiscobcos.ReceiptRPCObservation{
			NormalizedRPCReceipt: rawReceipt,
			Status:               receipt.Status,
			StatusMessage:        boundedReceiptStatus(receipt.Status),
			BlockNumber:          uint64(receipt.BlockNumber),
			BlockHashClaim:       blockHash.Bytes(),
			ReceiptHashClaim:     receiptHash,
			TransactionHash:      hash.Bytes(), TransactionIndex: txIndex,
			TransactionProofRPC: transactionPath, ReceiptIndex: txIndex,
			ReceiptProofRPC: receiptPath, AnchorLogIndex: event.LogIndex,
		},
	}, nil
}

func (d *nativeDriver) GetBlockHeader(ctx context.Context, blockNumber uint64) (fiscobcos.BlockHeader, error) {
	block, err := d.client.GetBlockByNumber(ctx, int64(blockNumber), true, true)
	if err != nil {
		return fiscobcos.BlockHeader{}, err
	}
	if block == nil || block.Number != blockNumber {
		return fiscobcos.BlockHeader{}, fiscobcos.ErrIncompleteChainEvidence
	}
	if err := validateBlockRPCBounds(block); err != nil {
		return fiscobcos.BlockHeader{}, err
	}
	hash, err := strictHex32(block.Hash)
	if err != nil {
		return fiscobcos.BlockHeader{}, err
	}
	raw, err := json.Marshal(block)
	if err != nil {
		return fiscobcos.BlockHeader{}, err
	}
	if len(raw) == 0 || len(raw) > maxSDKRawHeaderBytes {
		return fiscobcos.BlockHeader{}, fiscobcos.ErrDriverInvalid
	}
	return fiscobcos.BlockHeader{Observation: fiscobcos.BlockRPCObservation{
		NormalizedRPCHeader: raw, BlockHashClaim: hash, BlockNumber: blockNumber,
	}}, nil
}

func (d *nativeDriver) GetConsensusSnapshot(ctx context.Context, blockNumber uint64) (fiscobcos.ConsensusSnapshot, error) {
	block, err := d.client.GetBlockByNumber(ctx, int64(blockNumber), true, true)
	if err != nil {
		return fiscobcos.ConsensusSnapshot{}, err
	}
	if block == nil || block.Number != blockNumber || len(block.SignatureList) == 0 || len(block.SealerList) == 0 {
		return fiscobcos.ConsensusSnapshot{}, fiscobcos.ErrIncompleteChainEvidence
	}
	if err := validateBlockRPCBounds(block); err != nil {
		return fiscobcos.ConsensusSnapshot{}, err
	}
	hash, err := strictHex32(block.Hash)
	if err != nil {
		return fiscobcos.ConsensusSnapshot{}, err
	}
	signatures := make([]fiscobcos.CommitSignature, 0, len(block.SignatureList))
	for _, signature := range block.SignatureList {
		if signature.SealerIndex >= uint64(len(block.SealerList)) {
			return fiscobcos.ConsensusSnapshot{}, fiscobcos.ErrIncompleteChainEvidence
		}
		value, err := decodeHexBounded(signature.Signature, maxSDKSignatureBytes)
		if err != nil || len(value) == 0 {
			return fiscobcos.ConsensusSnapshot{}, fiscobcos.ErrIncompleteChainEvidence
		}
		signatures = append(signatures, fiscobcos.CommitSignature{
			ValidatorNodeID: block.SealerList[signature.SealerIndex],
			Signature:       value,
		})
	}
	sort.Slice(signatures, func(i, j int) bool { return signatures[i].ValidatorNodeID < signatures[j].ValidatorNodeID })
	return fiscobcos.ConsensusSnapshot{
		BlockNumber: blockNumber, BlockHash: hash,
		Finality: fiscobcos.ConsensusFinalityObservation{
			// getPbftView reports the endpoint's latest live consensus view and
			// cannot be queried at blockNumber. Recording it here would falsely
			// bind live state to this historical block.
			View: nil, Round: nil, Signatures: signatures,
		},
	}, nil
}

func (d *nativeDriver) Close() error {
	if d.client != nil {
		d.client.Close()
		d.client = nil
	}
	return nil
}

func (d *nativeDriver) transactionIndex(ctx context.Context, blockNumber uint64, hash common.Hash) (uint64, error) {
	block, err := d.client.GetBlockByNumber(ctx, int64(blockNumber), false, true)
	if err != nil {
		return 0, err
	}
	if block == nil || len(block.Transactions) > maxSDKTransactionsPerBlock {
		return 0, fiscobcos.ErrDriverInvalid
	}
	for index, item := range block.Transactions {
		text, ok := item.(string)
		if !ok || validateTransactionHashText(text) != nil {
			return 0, fiscobcos.ErrDriverInvalid
		}
		if strings.EqualFold(text, hash.Hex()) {
			return uint64(index), nil
		}
	}
	return 0, fiscobcos.ErrIncompleteChainEvidence
}

func validateTransactionHashText(value string) error {
	if len(value) != 2+common.HashLength*2 || !strings.HasPrefix(value, "0x") {
		return fiscobcos.ErrDriverInvalid
	}
	return validateHexText(value, common.HashLength, false)
}

func validateSignerSignature(digest, signature, expectedPublicKey []byte) error {
	if len(digest) != 32 || len(signature) != 65 || len(expectedPublicKey) != 65 ||
		expectedPublicKey[0] != 0x04 {
		return errors.New("FISCO BCOS account signer returned non-canonical signature material")
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])
	if !ethcrypto.ValidateSignatureValues(signature[64], r, s, true) {
		return errors.New("FISCO BCOS account signer returned invalid secp256k1 signature values")
	}
	recovered, err := ethcrypto.SigToPub(digest, signature)
	if err != nil || !bytes.Equal(ethcrypto.FromECDSAPub(recovered), expectedPublicKey) {
		return errors.New("FISCO BCOS account signature does not match the configured signer public key")
	}
	return nil
}

func validateSubmittedReceipt(receipt *types.Receipt, digest, sender, contract, callData []byte) error {
	if receipt == nil {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	if receipt.Status != types.Success {
		return fiscobcos.NewReceiptStatusError(receipt.Status)
	}
	transactionHash, err := strictHex32(receipt.TransactionHash)
	if err != nil || !bytes.Equal(transactionHash, digest) {
		return fiscobcos.ErrContractMismatch
	}
	from, err := strictHexBytes(receipt.From, 20)
	if err != nil || !bytes.Equal(from, sender) {
		return fiscobcos.ErrContractMismatch
	}
	to, err := strictHexBytes(receipt.To, 20)
	if err != nil || !bytes.Equal(to, contract) {
		return fiscobcos.ErrContractMismatch
	}
	input, err := decodeHexBounded(receipt.Input, fiscobcos.MaxPayloadBytes+4)
	if err != nil || !bytes.Equal(input, callData) {
		return fiscobcos.ErrContractMismatch
	}
	return nil
}

func validateReceiptTransactionIdentity(receipt *types.Receipt, transaction *types.TransactionDetail, attempt fiscobcos.TransactionSubmission, trust fiscobcos.TrustConfig) error {
	if receipt == nil || transaction == nil {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	expectedHash, err := strictHash(attempt.TransactionHash)
	if err != nil ||
		attempt.ChainID != trust.ChainID ||
		attempt.GroupID != trust.GroupID ||
		len(attempt.EncodedTransaction) == 0 ||
		len(attempt.Sender) != 20 ||
		len(attempt.To) != 20 ||
		!bytes.Equal(attempt.To, trust.Contract.Address) ||
		len(attempt.Input) == 0 ||
		len(attempt.Signature) != 65 ||
		attempt.BlockLimit == 0 {
		return fiscobcos.ErrContractMismatch
	}
	if transaction.ChainID != attempt.ChainID ||
		transaction.GroupID != attempt.GroupID ||
		transaction.BlockLimit <= 0 ||
		uint64(transaction.BlockLimit) != attempt.BlockLimit {
		return fiscobcos.ErrContractMismatch
	}
	signature, err := strictHexBytes(transaction.Signature, len(attempt.Signature))
	if err != nil || !bytes.Equal(signature, attempt.Signature) {
		return fiscobcos.ErrContractMismatch
	}
	receiptHash, err := strictHex32(receipt.TransactionHash)
	if err != nil || !bytes.Equal(receiptHash, expectedHash.Bytes()) {
		return fiscobcos.ErrContractMismatch
	}
	transactionHash, err := strictHex32(transaction.Hash)
	if err != nil || !bytes.Equal(transactionHash, expectedHash.Bytes()) {
		return fiscobcos.ErrContractMismatch
	}
	receiptFrom, err := strictHexBytes(receipt.From, 20)
	if err != nil || !bytes.Equal(receiptFrom, attempt.Sender) {
		return fiscobcos.ErrContractMismatch
	}
	transactionFrom, err := strictHexBytes(transaction.From, 20)
	if err != nil || !bytes.Equal(transactionFrom, attempt.Sender) {
		return fiscobcos.ErrContractMismatch
	}
	receiptTo, err := strictHexBytes(receipt.To, 20)
	if err != nil || !bytes.Equal(receiptTo, attempt.To) {
		return fiscobcos.ErrContractMismatch
	}
	transactionTo, err := strictHexBytes(transaction.To, 20)
	if err != nil || !bytes.Equal(transactionTo, attempt.To) {
		return fiscobcos.ErrContractMismatch
	}
	receiptInput, err := decodeHexBounded(receipt.Input, fiscobcos.MaxPayloadBytes+4)
	if err != nil || !bytes.Equal(receiptInput, attempt.Input) {
		return fiscobcos.ErrContractMismatch
	}
	transactionInput, err := decodeHexBounded(transaction.Input, fiscobcos.MaxPayloadBytes+4)
	if err != nil || !bytes.Equal(transactionInput, attempt.Input) {
		return fiscobcos.ErrContractMismatch
	}
	return nil
}

func boundedReceiptStatus(status int) string {
	switch status {
	case types.Success:
		return "success"
	case types.BlockLimitCheckFail:
		return "block_limit_check_failed"
	case types.TxPoolIsFull:
		return "transaction_pool_full"
	case types.AlreadyInTxPool, types.AlreadyInTxPoolAndAccept:
		return "transaction_already_in_pool"
	case types.TxAlreadyInChain:
		return "transaction_already_in_chain"
	case types.InvalidChainId:
		return "invalid_chain_id"
	case types.InvalidGroupId:
		return "invalid_group_id"
	case types.InvalidSignature:
		return "invalid_signature"
	default:
		return fmt.Sprintf("status_%d", status)
	}
}

type softwareAccountSigner struct{ key *ecdsa.PrivateKey }

func newSoftwareAccountSigner(config fiscobcos.AccountProviderConfig) (AccountSigner, error) {
	if config.Provider != "software" {
		return nil, fmt.Errorf("FISCO BCOS account provider %q requires an injected non-exportable AccountSigner", config.Provider)
	}
	path, err := localPath(config.KeyReference)
	if err != nil {
		return nil, err
	}
	data, err := readBoundedRegularFile(path, true)
	if err != nil {
		return nil, fmt.Errorf("load FISCO BCOS software account key: %w", err)
	}
	defer clear(data)
	encoded := bytes.TrimSpace(data)
	if len(encoded) != 64 {
		return nil, errors.New("FISCO BCOS software account key must contain exactly 32 hex-encoded bytes")
	}
	keyBytes := make([]byte, hex.DecodedLen(len(encoded)))
	defer clear(keyBytes)
	decoded, err := hex.Decode(keyBytes, encoded)
	if err != nil || decoded != 32 {
		return nil, errors.New("FISCO BCOS software account key is not valid hex")
	}
	key, err := ethcrypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse FISCO BCOS software account key: %w", err)
	}
	return &softwareAccountSigner{key: key}, nil
}

func (s *softwareAccountSigner) PublicKey(context.Context) ([]byte, error) {
	if s == nil || s.key == nil {
		return nil, errors.New("FISCO BCOS software account signer is closed")
	}
	return ethcrypto.FromECDSAPub(&s.key.PublicKey), nil
}

func (s *softwareAccountSigner) SignDigest(_ context.Context, digest []byte) ([]byte, error) {
	if s == nil || s.key == nil {
		return nil, errors.New("FISCO BCOS software account signer is closed")
	}
	if len(digest) != 32 {
		return nil, errors.New("FISCO BCOS transaction digest must be 32 bytes")
	}
	return ethcrypto.Sign(digest, s.key)
}

func canonicalStandardTrust(config fiscobcos.TrustConfig) (fiscobcos.TrustConfig, error) {
	data, err := fiscobcos.MarshalTrustConfig(config)
	if err != nil {
		return fiscobcos.TrustConfig{}, err
	}
	canonical, err := fiscobcos.UnmarshalTrustConfig(data)
	if err != nil {
		return fiscobcos.TrustConfig{}, err
	}
	if canonical.CryptoMode != fiscobcos.CryptoModeStandard {
		return fiscobcos.TrustConfig{}, fmt.Errorf("%w: native standard SDK requires crypto_mode=standard", fiscobcos.ErrWrongNetwork)
	}
	if len(canonical.Certificates.TrustedCAReferences) != 1 {
		return fiscobcos.TrustConfig{}, errors.New("native standard SDK requires exactly one trusted CA reference")
	}
	if len(canonical.Certificates.PinnedPeerCertificateHashes) != 0 {
		return fiscobcos.TrustConfig{}, errors.New("pinned peer certificates are unsupported by the pinned Go SDK")
	}
	return canonical, nil
}

func verifyCertificateReferences(config fiscobcos.TrustConfig, requireSoftwareAccountKey bool) error {
	caPath, err := localPath(config.Certificates.TrustedCAReferences[0])
	if err != nil {
		return err
	}
	ca, err := readBoundedRegularFile(caPath, false)
	if err != nil {
		return fmt.Errorf("read FISCO BCOS CA certificate: %w", err)
	}
	digest := sha256.Sum256(ca)
	matched := false
	for _, expected := range config.Certificates.TrustedCACertificateHashes {
		if bytes.Equal(digest[:], expected) {
			matched = true
			break
		}
	}
	if !matched {
		return errors.New("FISCO BCOS CA certificate digest does not match TrustConfig")
	}
	type localReference struct {
		value      string
		privateKey bool
	}
	references := []localReference{
		{value: config.Certificates.ClientSigningCertificateRef},
		{value: config.Certificates.ClientSigningKeyRef, privateKey: true},
	}
	if requireSoftwareAccountKey {
		if config.AccountProvider.Provider != "software" {
			return fmt.Errorf("FISCO BCOS account provider %q requires an injected non-exportable AccountSigner", config.AccountProvider.Provider)
		}
		references = append(references, localReference{value: config.AccountProvider.KeyReference, privateKey: true})
	}
	for _, reference := range references {
		path, err := localPath(reference.value)
		if err != nil {
			return err
		}
		if err := checkBoundedRegularFile(path, reference.privateKey); err != nil {
			return fmt.Errorf("verify FISCO BCOS local reference: %w", err)
		}
	}
	return nil
}

func decodeAnchorEvent(receipt *types.Receipt, contract fiscobcos.ContractBinding) (fiscobcos.AnchorPublishedEvent, error) {
	if err := validateReceiptLogBounds(receipt.Logs); err != nil {
		return fiscobcos.AnchorPublishedEvent{}, err
	}
	eventID := legacyKeccak([]byte(contract.EventSignature))
	address := common.BytesToAddress(contract.Address)
	var matched *types.NewLog
	var matchedIndex uint64
	for index, entry := range receipt.Logs {
		if entry == nil || !strings.EqualFold(entry.Address, address.Hex()) ||
			len(entry.Topics) != 4 {
			continue
		}
		topic0, err := strictHex32(entry.Topics[0])
		if err != nil || !bytes.Equal(topic0, eventID) {
			continue
		}
		if matched != nil {
			return fiscobcos.AnchorPublishedEvent{}, fiscobcos.ErrContractMismatch
		}
		matched, matchedIndex = entry, uint64(index)
	}
	if matched == nil {
		return fiscobcos.AnchorPublishedEvent{}, fiscobcos.ErrContractMismatch
	}
	anchorID, err := strictHex32(matched.Topics[1])
	if err != nil {
		return fiscobcos.AnchorPublishedEvent{}, err
	}
	_ = anchorID
	streamID, err := strictHex32(matched.Topics[2])
	if err != nil {
		return fiscobcos.AnchorPublishedEvent{}, err
	}
	publisherWord, err := strictHex32(matched.Topics[3])
	if err != nil || !bytes.Equal(publisherWord[:12], make([]byte, 12)) {
		return fiscobcos.AnchorPublishedEvent{}, fiscobcos.ErrContractMismatch
	}
	data, err := strictHexBytes(matched.Data, 4*32)
	if err != nil || !bytes.Equal(data[:24], make([]byte, 24)) ||
		!bytes.Equal(data[3*32:3*32+30], make([]byte, 30)) {
		return fiscobcos.AnchorPublishedEvent{}, fiscobcos.ErrContractMismatch
	}
	event := fiscobcos.AnchorPublishedEvent{
		ContractAddress: append([]byte(nil), contract.Address...),
		AnchorID:        anchorID, StreamID: streamID, TreeSize: bytesToUint64(data[24:32]),
		RootHash:        append([]byte(nil), data[32:64]...),
		SignedSTHDigest: append([]byte(nil), data[64:96]...),
		Publisher:       append([]byte(nil), publisherWord[12:]...),
		PayloadVersion:  uint16(data[3*32+30])<<8 | uint16(data[3*32+31]),
		LogIndex:        matchedIndex,
	}
	decoded, err := json.Marshal(matched)
	if err != nil {
		return fiscobcos.AnchorPublishedEvent{}, err
	}
	if len(decoded) == 0 || len(decoded) > maxSDKDecodedEventBytes {
		return fiscobcos.AnchorPublishedEvent{}, fiscobcos.ErrDriverInvalid
	}
	event.NormalizedRPCLog = decoded
	return event, nil
}

func decodeProofNodes(values []string) ([][]byte, error) {
	if values == nil || len(values) > maxSDKProofNodes {
		return nil, fiscobcos.ErrIncompleteChainEvidence
	}
	out := make([][]byte, len(values))
	for i, value := range values {
		decoded, err := decodeHexBounded(value, maxSDKProofNodeBytes)
		if err != nil || len(decoded) == 0 {
			return nil, fiscobcos.ErrIncompleteChainEvidence
		}
		out[i] = decoded
	}
	return out, nil
}

func validateReceiptRPCBounds(receipt *types.Receipt) error {
	if receipt == nil {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	budget := 0
	if err := addPlainRPCBudget(&budget, receipt.Message, maxSDKConfigStringBytes, maxSDKRawReceiptBytes); err != nil {
		return err
	}
	for _, field := range []struct {
		value string
		limit int
	}{
		{receipt.ContractAddress, 20},
		{receipt.From, 20},
		{receipt.GasUsed, 32},
		{receipt.Hash, 32},
		{receipt.Input, fiscobcos.MaxPayloadBytes + 4},
		{receipt.Output, maxSDKDecodedEventBytes},
		{receipt.To, 20},
		{receipt.TransactionHash, 32},
	} {
		if err := addHexRPCBudget(&budget, field.value, field.limit, true, maxSDKRawReceiptBytes); err != nil {
			return err
		}
	}
	if receipt.ReceiptProof != nil {
		if err := addProofRPCBudget(&budget, receipt.ReceiptProof, maxSDKRawReceiptBytes); err != nil {
			return err
		}
	}
	if err := addReceiptLogRPCBudget(&budget, receipt.Logs, maxSDKRawReceiptBytes); err != nil {
		return err
	}
	return nil
}

func validateTransactionRPCBounds(transaction *types.TransactionDetail) error {
	if transaction == nil {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	budget := 0
	for _, value := range []string{transaction.Abi, transaction.ChainID, transaction.GroupID} {
		if err := addPlainRPCBudget(&budget, value, maxSDKConfigStringBytes, maxSDKRawTransactionBytes); err != nil {
			return err
		}
	}
	for _, field := range []struct {
		value string
		limit int
	}{
		{transaction.From, 20},
		{transaction.Hash, 32},
		{transaction.Input, fiscobcos.MaxPayloadBytes + 4},
		{transaction.Nonce, maxSDKTransactionNonceBytes},
		{transaction.Signature, maxSDKSignatureBytes},
		{transaction.To, 20},
	} {
		if err := addHexRPCBudget(&budget, field.value, field.limit, true, maxSDKRawTransactionBytes); err != nil {
			return err
		}
	}
	return addProofRPCBudget(&budget, transaction.TransactionProof, maxSDKRawTransactionBytes)
}

func validateBlockRPCBounds(block *types.Block) error {
	if block == nil {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	if len(block.ParentInfo) > maxSDKParentBlocks ||
		len(block.SealerList) > maxSDKValidators ||
		len(block.SignatureList) > maxSDKCommitSignatures ||
		len(block.ConsensusWeights) > maxSDKConsensusWeights ||
		len(block.Transactions) != 0 {
		return fiscobcos.ErrDriverInvalid
	}
	budget := 0
	if err := addPlainRPCBudget(&budget, block.ExtraData, maxSDKDecodedEventBytes, maxSDKRawHeaderBytes); err != nil {
		return err
	}
	for _, field := range []struct {
		value string
		limit int
	}{
		{block.GasLimit, 32},
		{block.GasUsed, 32},
		{block.Hash, 32},
		{block.ReceiptsRoot, 32},
		{block.StateRoot, 32},
		{block.TxsRoot, 32},
	} {
		if err := addHexRPCBudget(&budget, field.value, field.limit, true, maxSDKRawHeaderBytes); err != nil {
			return err
		}
	}
	for _, parent := range block.ParentInfo {
		if err := addHexRPCBudget(&budget, parent.BlockHash, 32, false, maxSDKRawHeaderBytes); err != nil {
			return err
		}
	}
	for _, nodeID := range block.SealerList {
		if err := addHexRPCBudget(&budget, nodeID, maxSDKConfigStringBytes/2, false, maxSDKRawHeaderBytes); err != nil {
			return err
		}
	}
	for _, signature := range block.SignatureList {
		if err := addHexRPCBudget(&budget, signature.Signature, maxSDKSignatureBytes, false, maxSDKRawHeaderBytes); err != nil {
			return err
		}
	}
	return nil
}

func validateReceiptLogBounds(logs []*types.NewLog) error {
	budget := 0
	return addReceiptLogRPCBudget(&budget, logs, maxSDKRawReceiptBytes)
}

func addReceiptLogRPCBudget(budget *int, logs []*types.NewLog, limit int) error {
	if len(logs) > maxSDKReceiptLogs {
		return fiscobcos.ErrDriverInvalid
	}
	for _, entry := range logs {
		if entry == nil || len(entry.Topics) > maxSDKLogTopics {
			return fiscobcos.ErrDriverInvalid
		}
		if err := addHexRPCBudget(budget, entry.BlockNumber, 32, true, limit); err != nil {
			return err
		}
		if err := addHexRPCBudget(budget, entry.Address, 20, false, limit); err != nil {
			return err
		}
		if err := addHexRPCBudget(budget, entry.Data, maxSDKDecodedEventBytes, true, limit); err != nil {
			return err
		}
		for _, topic := range entry.Topics {
			if err := addHexRPCBudget(budget, topic, 32, false, limit); err != nil {
				return err
			}
		}
		if err := addRPCBudget(budget, 128+8*len(entry.Topics), limit); err != nil {
			return err
		}
	}
	return nil
}

func addProofRPCBudget(budget *int, values []string, limit int) error {
	if values == nil || len(values) > maxSDKProofNodes {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	for _, value := range values {
		if err := addHexRPCBudget(budget, value, maxSDKProofNodeBytes, false, limit); err != nil {
			return err
		}
	}
	return addRPCBudget(budget, 8*len(values), limit)
}

func addPlainRPCBudget(budget *int, value string, fieldLimit, totalLimit int) error {
	if len(value) > fieldLimit {
		return fiscobcos.ErrDriverInvalid
	}
	// JSON may expand arbitrary text by as much as six bytes per source byte.
	if len(value) > (totalLimit-*budget)/6 {
		return fiscobcos.ErrDriverInvalid
	}
	return addRPCBudget(budget, len(value)*6, totalLimit)
}

func addHexRPCBudget(budget *int, value string, decodedLimit int, allowEmpty bool, totalLimit int) error {
	if err := validateHexText(value, decodedLimit, allowEmpty); err != nil {
		return err
	}
	return addRPCBudget(budget, len(value), totalLimit)
}

func addRPCBudget(budget *int, amount, limit int) error {
	if budget == nil || amount < 0 || *budget < 0 || *budget > limit-amount {
		return fiscobcos.ErrDriverInvalid
	}
	*budget += amount
	return nil
}

func validateHexText(value string, decodedLimit int, allowEmpty bool) error {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "0x")
	if value == "" {
		if allowEmpty {
			return nil
		}
		return fiscobcos.ErrDriverInvalid
	}
	if decodedLimit < 0 || len(value)%2 != 0 || len(value) > decodedLimit*2 {
		return fiscobcos.ErrDriverInvalid
	}
	for index := 0; index < len(value); index++ {
		item := value[index]
		if !('0' <= item && item <= '9') &&
			!('a' <= item && item <= 'f') &&
			!('A' <= item && item <= 'F') {
			return fiscobcos.ErrDriverInvalid
		}
	}
	return nil
}

func parseEndpoint(endpoint string) (string, int, error) {
	value := strings.TrimSpace(endpoint)
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.User != nil || parsed.Path != "" && parsed.Path != "/" ||
			(parsed.Scheme != "tls" && parsed.Scheme != "https") {
			return "", 0, fmt.Errorf("invalid FISCO BCOS standard TLS endpoint %q", endpoint)
		}
		value = parsed.Host
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil || strings.TrimSpace(host) == "" {
		return "", 0, fmt.Errorf("invalid FISCO BCOS endpoint %q", endpoint)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid FISCO BCOS endpoint port")
	}
	return host, port, nil
}

func localPath(reference string) (string, error) {
	value := strings.TrimSpace(reference)
	if strings.HasPrefix(value, "file://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host != "" || parsed.Path == "" {
			return "", errors.New("invalid local file reference")
		}
		value = parsed.Path
	} else if strings.Contains(value, "://") {
		return "", errors.New("FISCO BCOS SDK references must be local files")
	}
	if value == "" {
		return "", errors.New("FISCO BCOS SDK local file reference is empty")
	}
	value = filepath.Clean(value)
	if !filepath.IsAbs(value) {
		return "", errors.New("FISCO BCOS SDK local file reference must be absolute")
	}
	return value, nil
}

func readBoundedRegularFile(path string, privateKey bool) ([]byte, error) {
	file, size, err := openBoundedRegularFile(path, privateKey)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data := make([]byte, size)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, err
	}
	return data, nil
}

func checkBoundedRegularFile(path string, privateKey bool) error {
	file, _, err := openBoundedRegularFile(path, privateKey)
	if err != nil {
		return err
	}
	return file.Close()
}

func openBoundedRegularFile(path string, privateKey bool) (*os.File, int64, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, 0, errors.New("file is not a regular non-symlink file")
	}
	if privateKey && runtime.GOOS != "windows" && before.Mode().Perm()&0o077 != 0 {
		return nil, 0, errors.New("private key file permissions must deny group and other access")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(before, info) || !info.Mode().IsRegular() ||
		info.Size() <= 0 || info.Size() > maxCertificateBytes {
		file.Close()
		return nil, 0, errors.New("file is empty, oversized, changed during open, or not regular")
	}
	return file, info.Size(), nil
}

func decodeSDKHexJSON(data []byte, decodedLimit int) ([]byte, error) {
	if decodedLimit < 0 || len(data) == 0 || len(data) > decodedLimit*2+64 {
		return nil, fiscobcos.ErrDriverInvalid
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return decodeHexBounded(value, decodedLimit)
}

func strictHash(value []byte) (common.Hash, error) {
	if len(value) != 32 {
		return common.Hash{}, errors.New("hash must be 32 bytes")
	}
	return common.BytesToHash(value), nil
}

func strictHex32(value string) ([]byte, error) {
	return strictHexBytes(value, 32)
}

func strictHexBytes(value string, size int) ([]byte, error) {
	decoded, err := decodeHexBounded(value, size)
	if err != nil || len(decoded) != size {
		return nil, fmt.Errorf("hex value must encode %d bytes", size)
	}
	return decoded, nil
}

func decodeHexBounded(value string, decodedLimit int) ([]byte, error) {
	if err := validateHexText(value, decodedLimit, false); err != nil {
		return nil, err
	}
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	return hex.DecodeString(value)
}

func legacyKeccak(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write(data)
	return hash.Sum(nil)
}

func accountAddress(publicKey []byte) []byte {
	digest := legacyKeccak(publicKey[1:])
	return append([]byte(nil), digest[len(digest)-20:]...)
}

func bytesToUint64(data []byte) uint64 {
	var value uint64
	for _, item := range data {
		value = value<<8 | uint64(item)
	}
	return value
}

func closeDrivers(drivers []fiscobcos.Driver) {
	for _, driver := range drivers {
		_ = driver.Close()
	}
}
