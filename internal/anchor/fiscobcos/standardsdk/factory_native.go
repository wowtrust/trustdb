//go:build fiscobcos_sdk && cgo

package standardsdk

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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
	bcossm "github.com/FISCO-BCOS/go-sdk/v3/smcrypto"
	"github.com/FISCO-BCOS/go-sdk/v3/types"
	"github.com/TarsCloud/TarsGo/tars/protocol/codec"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/tlcpprofile"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
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
	canonical, err := canonicalNativeTrust(config.TrustConfig)
	if err != nil {
		return nil, err
	}
	sdkVersion, err := observeAndVerifyNativeRuntime()
	if err != nil {
		return nil, err
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	if err := verifyCertificateReferences(canonical, config.AccountSigner == nil, clock().UTC()); err != nil {
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
	if err := validateAccountPublicKey(canonical.CryptoMode, publicKey); err != nil {
		return nil, err
	}
	sender, err := accountAddress(canonical.CryptoMode, publicKey)
	if err != nil {
		return nil, err
	}
	drivers := make([]fiscobcos.Driver, 0, len(canonical.Endpoints))
	for _, endpoint := range canonical.Endpoints {
		host, port, err := parseEndpoint(endpoint, canonical.Certificates.TransportMode)
		if err != nil {
			closeDrivers(drivers)
			return nil, err
		}
		placeholder, err := sdkPlaceholderKey(canonical.CryptoMode)
		if err != nil {
			closeDrivers(drivers)
			return nil, err
		}
		sdkConfig := &client.Config{
			IsSMCrypto:  canonical.CryptoMode == fiscobcos.CryptoModeGuomi,
			PrivateKey:  placeholder,
			GroupID:     canonical.GroupID,
			Host:        host,
			Port:        port,
			DisableSsl:  false,
			TLSCaFile:   caPath,
			TLSCertFile: certPath,
			TLSKeyFile:  tlsKeyPath,
		}
		if canonical.CryptoMode == fiscobcos.CryptoModeGuomi {
			sdkConfig.TLSSmEnCertFile, err = localPath(canonical.Certificates.ClientEncryptionCertificateRef)
			if err != nil {
				closeDrivers(drivers)
				return nil, err
			}
			sdkConfig.TLSSmEnKeyFile, err = localPath(canonical.Certificates.ClientEncryptionKeyRef)
			if err != nil {
				closeDrivers(drivers)
				return nil, err
			}
		}
		sdkClient, err := client.DialContext(ctx, sdkConfig)
		if err != nil {
			closeDrivers(drivers)
			return nil, fmt.Errorf("dial FISCO BCOS endpoint %q: %w", endpoint, err)
		}
		if sdkClient.SMCrypto() != (canonical.CryptoMode == fiscobcos.CryptoModeGuomi) {
			sdkClient.Close()
			closeDrivers(drivers)
			return nil, fmt.Errorf("%w: endpoint %q crypto mode differs from TrustConfig", fiscobcos.ErrWrongNetwork, endpoint)
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
	codeHash, err := chainHash(d.trust.CryptoMode, code)
	if err != nil {
		return fiscobcos.ChainProbe{}, err
	}
	return fiscobcos.ChainProbe{
		Endpoint: d.endpoint, SDKVersion: d.sdkVersion,
		CryptoMode: d.trust.CryptoMode, ChainID: chainID,
		GroupID: d.client.GetGroupID(), GenesisHash: genesis.Bytes(),
		CheckpointHash: checkpoint.Bytes(), Height: uint64(height),
		ContractCodeHash: codeHash,
	}, nil
}

func (d *nativeDriver) PrepareAnchor(ctx context.Context, request fiscobcos.SubmitRequest) (fiscobcos.TransactionSubmission, error) {
	canonical, err := fiscobcos.MarshalPayload(request.Payload)
	if err != nil || !bytes.Equal(canonical, request.CanonicalPayload) {
		return fiscobcos.TransactionSubmission{}, fiscobcos.ErrInvalidPayload
	}
	callData, err := fiscobcos.PublishCallDataForMode(d.trust.CryptoMode, request.Payload)
	if err != nil {
		return fiscobcos.TransactionSubmission{}, err
	}
	height, err := d.client.GetBlockNumber(ctx)
	if err != nil {
		return fiscobcos.TransactionSubmission{}, err
	}
	if height < 0 {
		return fiscobcos.TransactionSubmission{}, fiscobcos.ErrDriverInvalid
	}
	if height > math.MaxInt64-client.BlockLimit {
		return fiscobcos.TransactionSubmission{}, fiscobcos.ErrDriverInvalid
	}
	blockLimit := height + client.BlockLimit
	address := common.BytesToAddress(d.trust.Contract.Address)
	txData, digest, err := d.client.CreateEncodedTransactionDataV1(&address, callData, blockLimit, "")
	if err != nil {
		return fiscobcos.TransactionSubmission{}, err
	}
	providerSignature, err := d.signer.SignDigest(ctx, append([]byte(nil), digest...))
	if err != nil {
		return fiscobcos.TransactionSubmission{}, fmt.Errorf("sign FISCO BCOS transaction digest: %w", err)
	}
	signature, err := nativeSignerSignature(d.trust, digest, providerSignature, d.publicKey)
	if err != nil {
		return fiscobcos.TransactionSubmission{}, &fiscobcos.DriverError{
			Operation: "sign_anchor", Endpoint: d.endpoint,
			Class: fiscobcos.FailurePermanent, Kind: err,
		}
	}
	encoded, err := d.client.CreateEncodedTransaction(txData, digest, signature, 0, "")
	if err != nil {
		return fiscobcos.TransactionSubmission{}, err
	}
	if len(encoded) == 0 || len(encoded) > maxSDKRawTransactionBytes {
		return fiscobcos.TransactionSubmission{}, fiscobcos.ErrDriverInvalid
	}
	return fiscobcos.TransactionSubmission{
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
	}, nil
}

func (d *nativeDriver) SubmitPreparedAnchor(ctx context.Context, attempt fiscobcos.TransactionSubmission) (fiscobcos.SubmissionOutcome, error) {
	if err := validatePreparedSubmission(attempt, d.trust, d.sender, d.publicKey); err != nil {
		return fiscobcos.SubmissionOutcome{}, &fiscobcos.DriverError{
			Operation: "validate_prepared_anchor", Endpoint: d.endpoint,
			Class: fiscobcos.FailurePermanent, Kind: err,
		}
	}
	receipt, err := d.client.SendEncodedTransaction(ctx, attempt.EncodedTransaction, true)
	if err != nil {
		return fiscobcos.SubmissionOutcome{}, &fiscobcos.DriverError{
			Operation: "submit_anchor", Endpoint: d.endpoint,
			Class: fiscobcos.FailureAmbiguous, Kind: err,
		}
	}
	if receipt == nil {
		return fiscobcos.SubmissionOutcome{}, &fiscobcos.DriverError{
			Operation: "submit_anchor", Endpoint: d.endpoint,
			Class: fiscobcos.FailureAmbiguous, Kind: fiscobcos.ErrIncompleteChainEvidence,
		}
	}
	if err := validateReceiptRPCBounds(receipt); err != nil {
		return fiscobcos.SubmissionOutcome{}, &fiscobcos.DriverError{
			Operation: "submit_anchor_receipt", Endpoint: d.endpoint,
			Class: fiscobcos.FailureAmbiguous, Kind: err,
		}
	}
	if err := validateSubmittedReceiptIdentity(receipt, attempt); err != nil {
		return fiscobcos.SubmissionOutcome{}, &fiscobcos.DriverError{
			Operation: "submit_anchor_receipt", Endpoint: d.endpoint,
			Class: fiscobcos.FailureAmbiguous, Kind: err,
		}
	}
	return fiscobcos.SubmissionOutcome{
		Status:          receipt.Status,
		StatusMessage:   boundedReceiptStatus(receipt.Status),
		ObservedAtUnixN: d.clock().UTC().UnixNano(),
	}, nil
}

func (d *nativeDriver) ReadAnchor(ctx context.Context, anchorID []byte) (fiscobcos.AnchorRecord, error) {
	input, err := fiscobcos.GetAnchorCallDataForMode(d.trust.CryptoMode, anchorID)
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
	// Recovery consumes persisted, untrusted bytes. Decode the signed
	// transaction again and rebind every field before using its hash in RPC.
	if err := validatePreparedSubmission(attempt, d.trust, d.sender, d.publicKey); err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	hash, err := strictHash(attempt.TransactionHash)
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	receipt, err := d.client.GetTransactionReceipt(ctx, hash, true)
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	if receipt == nil {
		return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrTransactionNotFound
	}
	transaction, err := d.client.GetTransactionByHash(ctx, hash, true)
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	if transaction == nil {
		return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrTransactionNotFound
	}
	if receipt.ReceiptProof == nil || transaction.TransactionProof == nil {
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
	var event fiscobcos.AnchorPublishedEvent
	if receipt.Status == types.Success {
		event, err = decodeAnchorEvent(receipt, d.trust.CryptoMode, d.trust.Contract)
		if err != nil {
			return fiscobcos.ReceiptWithProof{}, err
		}
	}
	if receipt.Version > math.MaxInt32 || receipt.Status < math.MinInt32 || receipt.Status > math.MaxInt32 {
		return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
	}
	if receipt.Version >= 1 || receipt.ContractAddress != "" {
		// The pinned Go SDK does not expose effectiveGasPrice, and RPC
		// normalizes non-empty creation addresses so their exact native field
		// bytes cannot be reconstructed.
		return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
	}
	if !encodedHexFits(receipt.Output, fiscobcos.MaxNativeEvidenceFieldBytes) {
		return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
	}
	output, err := decodeHexBoundedOptional(receipt.Output, fiscobcos.MaxNativeEvidenceFieldBytes)
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
	}
	if len(receipt.Logs) > fiscobcos.MaxCanonicalLogs {
		return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
	}
	receiptAggregate := len(output)
	for _, log := range receipt.Logs {
		if log == nil ||
			!encodedHexFits(log.Address, 20) ||
			!encodedHexFits(log.Data, fiscobcos.MaxProofNodeBytes) ||
			len(log.Topics) > fiscobcos.MaxNativeEvidenceItems {
			return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
		}
		receiptAggregate += decodedHexLength(log.Address) + decodedHexLength(log.Data)
		for _, topic := range log.Topics {
			if !encodedHexFits(topic, 32) {
				return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
			}
			receiptAggregate += 32
		}
		if receiptAggregate > fiscobcos.MaxReceiptAggregate {
			return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
		}
	}
	nativeLogs := make([]fiscobcos.NativeLogFields, len(receipt.Logs))
	for index, log := range receipt.Logs {
		if log == nil {
			return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
		}
		if !encodedHexFits(log.Address, 20) ||
			!encodedHexFits(log.Data, fiscobcos.MaxNativeEvidenceFieldBytes) {
			return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
		}
		if len(log.Address) != 40 {
			return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
		}
		if _, err := strictHexBytes(log.Address, 20); err != nil {
			return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
		}
		if len(log.Topics) > fiscobcos.MaxNativeEvidenceItems {
			return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
		}
		topics := make([][]byte, len(log.Topics))
		for topicIndex, topic := range log.Topics {
			topics[topicIndex], err = strictHex32(topic)
			if err != nil {
				return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
			}
		}
		data, err := decodeHexBoundedOptional(log.Data, fiscobcos.MaxProofNodeBytes)
		if err != nil {
			return fiscobcos.ReceiptWithProof{}, fiscobcos.ErrIncompleteChainEvidence
		}
		nativeLogs[index] = fiscobcos.NativeLogFields{
			Address: log.Address,
			Topics:  topics,
			Data:    data,
		}
	}
	receiptFields := fiscobcos.NativeReceiptFields{
		Version:         int32(receipt.Version),
		GasUsed:         receipt.GasUsed,
		ContractAddress: receipt.ContractAddress,
		Status:          int32(receipt.Status),
		Output:          output,
		Logs:            nativeLogs,
		BlockNumber:     int64(receipt.BlockNumber),
	}
	rawCanonicalReceipt, canonicalLogs, err := fiscobcos.MarshalNativeReceiptPreimage(receiptFields)
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	computedReceiptHash, err := fiscobcos.HashNativeEvidence(d.trust.ChainHashAlgorithm, rawCanonicalReceipt)
	if err != nil {
		return fiscobcos.ReceiptWithProof{}, err
	}
	var record fiscobcos.AnchorRecord
	if receipt.Status == types.Success {
		record = fiscobcos.AnchorRecord{
			StreamID: append([]byte(nil), event.StreamID...), TreeSize: event.TreeSize,
			RootHash:        append([]byte(nil), event.RootHash...),
			SignedSTHDigest: append([]byte(nil), event.SignedSTHDigest...),
			Publisher:       append([]byte(nil), event.Publisher...),
			PayloadVersion:  event.PayloadVersion, Exists: true,
		}
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
	if !bytes.Equal(receiptHash, computedReceiptHash) {
		return fiscobcos.ReceiptWithProof{}, fmt.Errorf("%w: receipt consensus hash mismatch", fiscobcos.ErrIncompleteChainEvidence)
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
	var decodedEvent []byte
	if receipt.Status == types.Success {
		decodedEvent, err = fiscobcos.MarshalNativeAnchorEvent(event)
		if err != nil {
			return fiscobcos.ReceiptWithProof{}, err
		}
	}
	return fiscobcos.ReceiptWithProof{
		Status: receipt.Status, StatusMessage: boundedReceiptStatus(receipt.Status),
		BlockNumber: uint64(receipt.BlockNumber), BlockHash: blockHash.Bytes(),
		Record: record, Event: event,
		Evidence: fiscobcos.ReceiptEvidence{
			Fields:              receiptFields,
			RawCanonicalReceipt: rawCanonicalReceipt,
			Status:              int64(receipt.Status),
			StatusMessage:       boundedReceiptStatus(receipt.Status),
			CanonicalLogs:       canonicalLogs,
			ReceiptHash:         receiptHash,
			TransactionHash:     hash.Bytes(),
			TransactionIndex:    txIndex,
			TransactionProof:    transactionPath,
			ReceiptIndex:        txIndex,
			ReceiptProof:        receiptPath,
			AnchorLogIndex:      event.LogIndex,
			DecodedAnchorEvent:  decodedEvent,
		},
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
	if block.Version > math.MaxInt32 {
		return fiscobcos.BlockHeader{}, fiscobcos.ErrIncompleteChainEvidence
	}
	blockNumberValue, err := fiscobcos.Uint64ToConsensusInt64(block.Number)
	if err != nil {
		return fiscobcos.BlockHeader{}, err
	}
	timestamp, err := fiscobcos.Uint64ToConsensusInt64(block.Timestamp)
	if err != nil {
		return fiscobcos.BlockHeader{}, err
	}
	sealer, err := fiscobcos.Uint64ToConsensusInt64(block.Sealer)
	if err != nil {
		return fiscobcos.BlockHeader{}, err
	}
	if len(block.ParentInfo) > fiscobcos.MaxNativeEvidenceItems ||
		len(block.SealerList) > fiscobcos.MaxNativeEvidenceItems ||
		len(block.ConsensusWeights) > fiscobcos.MaxNativeEvidenceItems {
		return fiscobcos.BlockHeader{}, fiscobcos.ErrIncompleteChainEvidence
	}
	parents := make([]fiscobcos.NativeParentInfo, len(block.ParentInfo))
	for index, parent := range block.ParentInfo {
		number, err := fiscobcos.Uint64ToConsensusInt64(parent.BlockNumber)
		if err != nil {
			return fiscobcos.BlockHeader{}, err
		}
		parentHash, err := strictHex32(parent.BlockHash)
		if err != nil {
			return fiscobcos.BlockHeader{}, fiscobcos.ErrIncompleteChainEvidence
		}
		parents[index] = fiscobcos.NativeParentInfo{BlockNumber: number, BlockHash: parentHash}
	}
	txsRoot, err := strictHex32(block.TxsRoot)
	if err != nil {
		return fiscobcos.BlockHeader{}, fiscobcos.ErrIncompleteChainEvidence
	}
	receiptsRoot, err := strictHex32(block.ReceiptsRoot)
	if err != nil {
		return fiscobcos.BlockHeader{}, fiscobcos.ErrIncompleteChainEvidence
	}
	stateRoot, err := strictHex32(block.StateRoot)
	if err != nil {
		return fiscobcos.BlockHeader{}, fiscobcos.ErrIncompleteChainEvidence
	}
	sealerList := make([][]byte, len(block.SealerList))
	for index, nodeID := range block.SealerList {
		if !encodedHexFits(nodeID, fiscobcos.MaxNativeEvidenceFieldBytes) {
			return fiscobcos.BlockHeader{}, fiscobcos.ErrIncompleteChainEvidence
		}
		sealerList[index], err = decodeHexBounded(nodeID, fiscobcos.MaxNativeEvidenceFieldBytes)
		if err != nil || len(sealerList[index]) == 0 {
			return fiscobcos.BlockHeader{}, fiscobcos.ErrIncompleteChainEvidence
		}
	}
	if !encodedHexFits(block.ExtraData, fiscobcos.MaxNativeEvidenceFieldBytes) {
		return fiscobcos.BlockHeader{}, fiscobcos.ErrIncompleteChainEvidence
	}
	extraData, err := decodeHexBoundedOptional(block.ExtraData, fiscobcos.MaxNativeEvidenceFieldBytes)
	if err != nil {
		return fiscobcos.BlockHeader{}, fiscobcos.ErrIncompleteChainEvidence
	}
	weights := make([]int64, len(block.ConsensusWeights))
	for index, weight := range block.ConsensusWeights {
		weights[index], err = fiscobcos.Uint64ToConsensusInt64(weight)
		if err != nil {
			return fiscobcos.BlockHeader{}, err
		}
	}
	rawCanonicalHeader, err := fiscobcos.MarshalNativeBlockHeaderPreimage(fiscobcos.NativeBlockHeaderFields{
		Version:          int32(block.Version),
		ParentInfo:       parents,
		TransactionsRoot: txsRoot,
		ReceiptsRoot:     receiptsRoot,
		StateRoot:        stateRoot,
		BlockNumber:      blockNumberValue,
		GasUsed:          block.GasUsed,
		Timestamp:        timestamp,
		Sealer:           sealer,
		SealerList:       sealerList,
		ExtraData:        extraData,
		ConsensusWeights: weights,
	})
	if err != nil {
		return fiscobcos.BlockHeader{}, err
	}
	computedHash, err := fiscobcos.HashNativeEvidence(d.trust.ChainHashAlgorithm, rawCanonicalHeader)
	if err != nil {
		return fiscobcos.BlockHeader{}, err
	}
	if !bytes.Equal(hash, computedHash) {
		return fiscobcos.BlockHeader{}, fmt.Errorf("%w: block header consensus hash mismatch", fiscobcos.ErrIncompleteChainEvidence)
	}
	raw, err := json.Marshal(block)
	if err != nil {
		return fiscobcos.BlockHeader{}, err
	}
	if len(raw) == 0 || len(raw) > maxSDKRawHeaderBytes {
		return fiscobcos.BlockHeader{}, fiscobcos.ErrDriverInvalid
	}
	return fiscobcos.BlockHeader{
		Evidence: fiscobcos.BlockEvidence{
			Fields: fiscobcos.NativeBlockHeaderFields{
				Version:          int32(block.Version),
				ParentInfo:       parents,
				TransactionsRoot: txsRoot,
				ReceiptsRoot:     receiptsRoot,
				StateRoot:        stateRoot,
				BlockNumber:      blockNumberValue,
				GasUsed:          block.GasUsed,
				Timestamp:        timestamp,
				Sealer:           sealer,
				SealerList:       sealerList,
				ExtraData:        extraData,
				ConsensusWeights: weights,
			},
			RawCanonicalHeader: rawCanonicalHeader,
			BlockHash:          hash,
			BlockNumber:        blockNumber,
		},
		Observation: fiscobcos.BlockRPCObservation{
			NormalizedRPCHeader: raw, BlockHashClaim: hash, BlockNumber: blockNumber,
		},
	}, nil
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
	if len(block.SignatureList) > fiscobcos.MaxCommitSignatures ||
		len(block.SealerList) > fiscobcos.MaxNativeEvidenceItems {
		return fiscobcos.ConsensusSnapshot{}, fiscobcos.ErrIncompleteChainEvidence
	}
	signatures := make([]fiscobcos.CommitSignature, 0, len(block.SignatureList))
	for _, signature := range block.SignatureList {
		if signature.SealerIndex >= uint64(len(block.SealerList)) {
			return fiscobcos.ConsensusSnapshot{}, fiscobcos.ErrIncompleteChainEvidence
		}
		if len(block.SealerList[signature.SealerIndex]) > 4096 {
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
		Finality: fiscobcos.FinalityEvidence{
			// getPbftView reports the endpoint's latest live consensus view and
			// cannot be queried at blockNumber. Recording it here would falsely
			// bind live state to this historical block.
			Signatures: signatures,
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

func validateStandardSignerSignature(digest, signature, expectedPublicKey []byte) error {
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

type sm2DERSignature struct {
	R *big.Int
	S *big.Int
}

func nativeSignerSignature(
	trust fiscobcos.TrustConfig,
	digest, providerSignature, expectedPublicKey []byte,
) ([]byte, error) {
	switch trust.CryptoMode {
	case fiscobcos.CryptoModeStandard:
		if err := validateStandardSignerSignature(digest, providerSignature, expectedPublicKey); err != nil {
			return nil, err
		}
		return append([]byte(nil), providerSignature...), nil
	case fiscobcos.CryptoModeGuomi:
		if err := trustcrypto.ValidateSM2SignatureDER(providerSignature); err != nil {
			return nil, fmt.Errorf("FISCO BCOS account signer returned invalid SM2 DER signature: %w", err)
		}
		publicKey, err := sm2.NewPublicKey(expectedPublicKey)
		if err != nil || !sm2.VerifyASN1WithSM2(publicKey, []byte(trust.SM2UserID), digest, providerSignature) {
			return nil, errors.New("FISCO BCOS account SM2 signature does not match the configured signer public key")
		}
		var parsed sm2DERSignature
		rest, err := asn1.Unmarshal(providerSignature, &parsed)
		if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
			return nil, errors.New("FISCO BCOS account signer returned malformed SM2 signature")
		}
		native := make([]byte, 128)
		parsed.R.FillBytes(native[:32])
		parsed.S.FillBytes(native[32:64])
		copy(native[64:], expectedPublicKey[1:])
		return native, nil
	default:
		return nil, fiscobcos.ErrWrongNetwork
	}
}

func validateNativeSignature(
	trust fiscobcos.TrustConfig,
	digest, signature, expectedPublicKey []byte,
) error {
	switch trust.CryptoMode {
	case fiscobcos.CryptoModeStandard:
		return validateStandardSignerSignature(digest, signature, expectedPublicKey)
	case fiscobcos.CryptoModeGuomi:
		if len(digest) != 32 || len(signature) != 128 ||
			len(expectedPublicKey) != 65 || expectedPublicKey[0] != 0x04 ||
			!bytes.Equal(signature[64:], expectedPublicKey[1:]) {
			return errors.New("FISCO BCOS account signer returned non-canonical Guomi signature material")
		}
		der, err := asn1.Marshal(sm2DERSignature{
			R: new(big.Int).SetBytes(signature[:32]),
			S: new(big.Int).SetBytes(signature[32:64]),
		})
		if err != nil || trustcrypto.ValidateSM2SignatureDER(der) != nil {
			return errors.New("FISCO BCOS account signer returned invalid SM2 signature values")
		}
		publicKey, err := sm2.NewPublicKey(expectedPublicKey)
		if err != nil || !sm2.VerifyASN1WithSM2(publicKey, []byte(trust.SM2UserID), digest, der) {
			return errors.New("FISCO BCOS account SM2 signature does not match the configured signer public key")
		}
		return nil
	default:
		return fiscobcos.ErrWrongNetwork
	}
}

func validatePreparedSubmission(
	attempt fiscobcos.TransactionSubmission,
	trust fiscobcos.TrustConfig,
	sender []byte,
	publicKey []byte,
) error {
	signatureBytes, err := fiscobcos.NativeTransactionSignatureBytes(trust.CryptoMode)
	if err != nil {
		return err
	}
	if len(attempt.EncodedTransaction) == 0 ||
		len(attempt.EncodedTransaction) > maxSDKRawTransactionBytes ||
		attempt.ChainID != trust.ChainID ||
		attempt.GroupID != trust.GroupID ||
		!bytes.Equal(attempt.To, trust.Contract.Address) ||
		!bytes.Equal(attempt.Sender, sender) ||
		len(attempt.Input) == 0 ||
		len(attempt.TransactionHash) != 32 ||
		len(attempt.Signature) != signatureBytes ||
		attempt.BlockLimit == 0 ||
		attempt.BlockLimit > math.MaxInt64 {
		return fiscobcos.ErrContractMismatch
	}
	var transaction types.Transaction
	if err := transaction.ReadFrom(codec.NewReader(attempt.EncodedTransaction)); err != nil ||
		!bytes.Equal(transaction.Bytes(), attempt.EncodedTransaction) ||
		transaction.Data.ChainID != attempt.ChainID ||
		transaction.Data.GroupID != attempt.GroupID ||
		transaction.Data.BlockLimit != int64(attempt.BlockLimit) ||
		transaction.Data.To == nil ||
		!bytes.Equal(transaction.Data.To.Bytes(), attempt.To) ||
		!bytes.Equal(transaction.Data.Input, attempt.Input) ||
		!bytes.Equal(transaction.Signature, attempt.Signature) {
		return fiscobcos.ErrContractMismatch
	}
	transaction.SMCrypto = trust.CryptoMode == fiscobcos.CryptoModeGuomi
	if !bytes.Equal(transaction.Hash().Bytes(), attempt.TransactionHash) {
		return fiscobcos.ErrContractMismatch
	}
	if err := validateNativeSignature(trust, attempt.TransactionHash, attempt.Signature, publicKey); err != nil {
		return err
	}
	return nil
}

func validateSubmittedReceiptIdentity(receipt *types.Receipt, attempt fiscobcos.TransactionSubmission) error {
	if receipt == nil {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	transactionHash, err := strictHex32(receipt.TransactionHash)
	if err != nil || !bytes.Equal(transactionHash, attempt.TransactionHash) {
		return fiscobcos.ErrContractMismatch
	}
	from, err := strictHexBytes(receipt.From, 20)
	if err != nil || !bytes.Equal(from, attempt.Sender) {
		return fiscobcos.ErrContractMismatch
	}
	to, err := strictHexBytes(receipt.To, 20)
	if err != nil || !bytes.Equal(to, attempt.To) {
		return fiscobcos.ErrContractMismatch
	}
	input, err := decodeHexBounded(receipt.Input, fiscobcos.MaxPayloadBytes+4)
	if err != nil || !bytes.Equal(input, attempt.Input) {
		return fiscobcos.ErrContractMismatch
	}
	return nil
}

func validateReceiptTransactionIdentity(receipt *types.Receipt, transaction *types.TransactionDetail, attempt fiscobcos.TransactionSubmission, trust fiscobcos.TrustConfig) error {
	if receipt == nil || transaction == nil {
		return fiscobcos.ErrIncompleteChainEvidence
	}
	signatureBytes, modeErr := fiscobcos.NativeTransactionSignatureBytes(trust.CryptoMode)
	if modeErr != nil {
		return modeErr
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
		len(attempt.Signature) != signatureBytes ||
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

type softwareAccountSigner struct {
	mode        fiscobcos.CryptoMode
	standardKey *ecdsa.PrivateKey
	guomiKey    *sm2.PrivateKey
}

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
	signer := &softwareAccountSigner{mode: configModeForAccountAlgorithm(config.Algorithm)}
	switch signer.mode {
	case fiscobcos.CryptoModeStandard:
		signer.standardKey, err = ethcrypto.ToECDSA(keyBytes)
	case fiscobcos.CryptoModeGuomi:
		signer.guomiKey, err = sm2.NewPrivateKey(keyBytes)
	default:
		return nil, fmt.Errorf("unsupported FISCO BCOS account algorithm %q", config.Algorithm)
	}
	if err != nil {
		return nil, fmt.Errorf("parse FISCO BCOS software account key: %w", err)
	}
	return signer, nil
}

func (s *softwareAccountSigner) PublicKey(context.Context) ([]byte, error) {
	if s == nil {
		return nil, errors.New("FISCO BCOS software account signer is closed")
	}
	switch s.mode {
	case fiscobcos.CryptoModeStandard:
		if s.standardKey == nil {
			return nil, errors.New("FISCO BCOS software account signer is closed")
		}
		return ethcrypto.FromECDSAPub(&s.standardKey.PublicKey), nil
	case fiscobcos.CryptoModeGuomi:
		if s.guomiKey == nil {
			return nil, errors.New("FISCO BCOS software account signer is closed")
		}
		return elliptic.Marshal(sm2.P256(), s.guomiKey.X, s.guomiKey.Y), nil
	default:
		return nil, fiscobcos.ErrWrongNetwork
	}
}

func (s *softwareAccountSigner) SignDigest(_ context.Context, digest []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("FISCO BCOS software account signer is closed")
	}
	if len(digest) != 32 {
		return nil, errors.New("FISCO BCOS transaction digest must be 32 bytes")
	}
	switch s.mode {
	case fiscobcos.CryptoModeStandard:
		if s.standardKey == nil {
			return nil, errors.New("FISCO BCOS software account signer is closed")
		}
		return ethcrypto.Sign(digest, s.standardKey)
	case fiscobcos.CryptoModeGuomi:
		if s.guomiKey == nil {
			return nil, errors.New("FISCO BCOS software account signer is closed")
		}
		signature, err := s.guomiKey.SignWithSM2(rand.Reader, []byte(cryptosuite.SM2DefaultUserID), digest)
		if err != nil {
			return nil, err
		}
		return signature, trustcrypto.ValidateSM2SignatureDER(signature)
	default:
		return nil, fiscobcos.ErrWrongNetwork
	}
}

func configModeForAccountAlgorithm(algorithm string) fiscobcos.CryptoMode {
	switch algorithm {
	case fiscobcos.StandardAccountAlg:
		return fiscobcos.CryptoModeStandard
	case fiscobcos.GuomiAccountAlg:
		return fiscobcos.CryptoModeGuomi
	default:
		return ""
	}
}

func canonicalNativeTrust(config fiscobcos.TrustConfig) (fiscobcos.TrustConfig, error) {
	data, err := fiscobcos.MarshalTrustConfig(config)
	if err != nil {
		return fiscobcos.TrustConfig{}, err
	}
	canonical, err := fiscobcos.UnmarshalTrustConfig(data)
	if err != nil {
		return fiscobcos.TrustConfig{}, err
	}
	if len(canonical.Certificates.TrustedCAReferences) != 1 {
		return fiscobcos.TrustConfig{}, errors.New("native FISCO BCOS SDK requires exactly one trusted CA reference")
	}
	if len(canonical.Certificates.PinnedPeerCertificateHashes) != 0 {
		return fiscobcos.TrustConfig{}, errors.New("pinned peer certificates are unsupported by the pinned Go SDK")
	}
	return canonical, nil
}

func verifyCertificateReferences(config fiscobcos.TrustConfig, requireSoftwareAccountKey bool, now time.Time) error {
	caPath, err := localPath(config.Certificates.TrustedCAReferences[0])
	if err != nil {
		return err
	}
	ca, err := readBoundedRegularFile(caPath, false)
	if err != nil {
		return fmt.Errorf("read FISCO BCOS CA certificate: %w", err)
	}
	var digest []byte
	switch config.CryptoMode {
	case fiscobcos.CryptoModeStandard:
		sum := sha256.Sum256(ca)
		digest = sum[:]
	case fiscobcos.CryptoModeGuomi:
		sum := sm3.Sum(ca)
		digest = sum[:]
	default:
		return fiscobcos.ErrWrongNetwork
	}
	matched := false
	for _, expected := range config.Certificates.TrustedCACertificateHashes {
		if bytes.Equal(digest, expected) {
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
	if config.CryptoMode == fiscobcos.CryptoModeGuomi {
		references = append(references,
			localReference{value: config.Certificates.ClientEncryptionCertificateRef},
			localReference{value: config.Certificates.ClientEncryptionKeyRef, privateKey: true},
		)
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
	if config.CryptoMode == fiscobcos.CryptoModeGuomi {
		signingCertificate, _ := localPath(config.Certificates.ClientSigningCertificateRef)
		signingKey, _ := localPath(config.Certificates.ClientSigningKeyRef)
		encryptionCertificate, _ := localPath(config.Certificates.ClientEncryptionCertificateRef)
		encryptionKey, _ := localPath(config.Certificates.ClientEncryptionKeyRef)
		if err := requireDistinctFiles(
			signingCertificate,
			signingKey,
			encryptionCertificate,
			encryptionKey,
		); err != nil {
			return err
		}
		if err := tlcpprofile.ValidateSM2ClientDualCertificateFiles(
			caPath,
			signingCertificate,
			signingKey,
			encryptionCertificate,
			encryptionKey,
			now,
		); err != nil {
			return fmt.Errorf("validate FISCO BCOS Guomi transport identity: %w", err)
		}
	}
	return nil
}

func requireDistinctFiles(paths ...string) error {
	identities := make([]os.FileInfo, len(paths))
	for index, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("FISCO BCOS transport identity path is not a regular non-symlink file")
		}
		identities[index] = info
		for previous := 0; previous < index; previous++ {
			if os.SameFile(identities[previous], info) {
				return errors.New("FISCO BCOS Guomi signing and encryption roles must use distinct files")
			}
		}
	}
	return nil
}

func decodeAnchorEvent(receipt *types.Receipt, mode fiscobcos.CryptoMode, contract fiscobcos.ContractBinding) (fiscobcos.AnchorPublishedEvent, error) {
	if err := validateReceiptLogBounds(receipt.Logs); err != nil {
		return fiscobcos.AnchorPublishedEvent{}, err
	}
	eventID, err := fiscobcos.EventTopicForMode(mode, contract.EventSignature)
	if err != nil {
		return fiscobcos.AnchorPublishedEvent{}, err
	}
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
	aggregate := 0
	for _, value := range values {
		// Hex expands one proof node to at most twice its decoded size plus 0x.
		if len(value) > fiscobcos.MaxProofNodeBytes*2+2 {
			return nil, fiscobcos.ErrIncompleteChainEvidence
		}
		aggregate += decodedHexLength(value)
		if aggregate > fiscobcos.MaxReceiptAggregate {
			return nil, fiscobcos.ErrIncompleteChainEvidence
		}
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

func encodedHexFits(value string, decodedLimit int) bool {
	encodedLength := len(value)
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		encodedLength -= 2
	}
	return encodedLength >= 0 && encodedLength <= decodedLimit*2
}

func decodedHexLength(value string) int {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		value = value[2:]
	}
	return len(value) / 2
}

func parseEndpoint(endpoint, transportMode string) (string, int, error) {
	value := endpoint
	if strings.TrimSpace(value) != value {
		return "", 0, fmt.Errorf("invalid FISCO BCOS %s endpoint %q", transportMode, endpoint)
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		validScheme := parsed != nil && parsed.Scheme == transportMode
		if err != nil || parsed == nil || parsed.User != nil || parsed.Opaque != "" ||
			parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" ||
			parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" ||
			!validScheme {
			return "", 0, fmt.Errorf("invalid FISCO BCOS %s endpoint %q", transportMode, endpoint)
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
	return decodeHexBoundedValue(value, decodedLimit, false)
}

func decodeHexBoundedOptional(value string, decodedLimit int) ([]byte, error) {
	return decodeHexBoundedValue(value, decodedLimit, true)
}

func decodeHexBoundedValue(value string, decodedLimit int, allowEmpty bool) ([]byte, error) {
	if err := validateHexText(value, decodedLimit, allowEmpty); err != nil {
		return nil, err
	}
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	if value == "" {
		return []byte{}, nil
	}
	return hex.DecodeString(value)
}

func legacyKeccak(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write(data)
	return hash.Sum(nil)
}

func chainHash(mode fiscobcos.CryptoMode, data []byte) ([]byte, error) {
	switch mode {
	case fiscobcos.CryptoModeStandard:
		return legacyKeccak(data), nil
	case fiscobcos.CryptoModeGuomi:
		sum := sm3.Sum(data)
		return append([]byte(nil), sum[:]...), nil
	default:
		return nil, fiscobcos.ErrWrongNetwork
	}
}

func accountAddress(mode fiscobcos.CryptoMode, publicKey []byte) ([]byte, error) {
	digest, err := chainHash(mode, publicKey[1:])
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), digest[len(digest)-20:]...), nil
}

func validateAccountPublicKey(mode fiscobcos.CryptoMode, publicKey []byte) error {
	if len(publicKey) != 65 || publicKey[0] != 0x04 {
		return errors.New("FISCO BCOS account signer returned a non-canonical public key")
	}
	switch mode {
	case fiscobcos.CryptoModeStandard:
		if _, err := ethcrypto.UnmarshalPubkey(publicKey); err != nil {
			return errors.New("FISCO BCOS account signer returned an invalid secp256k1 public key")
		}
	case fiscobcos.CryptoModeGuomi:
		parsed, err := sm2.NewPublicKey(publicKey)
		if err != nil || !bytes.Equal(elliptic.Marshal(sm2.P256(), parsed.X, parsed.Y), publicKey) {
			return errors.New("FISCO BCOS account signer returned an invalid SM2 public key")
		}
	default:
		return fiscobcos.ErrWrongNetwork
	}
	return nil
}

func sdkPlaceholderKey(mode fiscobcos.CryptoMode) ([]byte, error) {
	switch mode {
	case fiscobcos.CryptoModeStandard:
		ephemeral, err := ethcrypto.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("initialize FISCO BCOS SDK account placeholder: %w", err)
		}
		return ethcrypto.FromECDSA(ephemeral), nil
	case fiscobcos.CryptoModeGuomi:
		ephemeral, err := bcossm.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("initialize FISCO BCOS Guomi SDK account placeholder: %w", err)
		}
		return ephemeral.D.FillBytes(make([]byte, 32)), nil
	default:
		return nil, fiscobcos.ErrWrongNetwork
	}
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
