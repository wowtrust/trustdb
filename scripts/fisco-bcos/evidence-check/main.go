package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/FISCO-BCOS/go-sdk/v3/types"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/tlcpprofile"
)

type smokeEvidence struct {
	Mode         string         `json:"mode"`
	EventReceipt *types.Receipt `json:"event_receipt"`
	Block        *types.Block   `json:"containing_block"`
}

type result struct {
	ReceiptConsensusHashMatched bool   `json:"receipt_consensus_hash_matched"`
	BlockConsensusHashMatched   bool   `json:"block_consensus_hash_matched"`
	PBFTCommitSignaturesValid   bool   `json:"pbft_commit_signatures_valid"`
	TimingSemantics             string `json:"timing_semantics"`
	ReceiptVerificationNS       int64  `json:"receipt_verification_ns"`
	BlockVerificationNS         int64  `json:"block_verification_ns"`
	PBFTVerificationNS          int64  `json:"pbft_verification_ns"`
}

func main() {
	var input string
	var certDir string
	flag.StringVar(&input, "input", "", "smoke-client evidence JSON")
	flag.StringVar(&certDir, "cert-dir", "", "generated SDK certificate directory")
	flag.Parse()
	if input == "" {
		fatalf("--input is required")
	}
	if certDir == "" {
		fatalf("--cert-dir is required")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		fatalf("read evidence: %v", err)
	}
	var evidence smokeEvidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		fatalf("decode evidence: %v", err)
	}
	if evidence.Mode != "standard" && evidence.Mode != "guomi" {
		fatalf("unsupported crypto mode %q", evidence.Mode)
	}
	if evidence.Mode == "guomi" {
		if err := tlcpprofile.ValidateSM2ClientDualCertificateFiles(
			filepath.Join(certDir, "sm_ca.crt"),
			filepath.Join(certDir, "sm_sdk.crt"),
			filepath.Join(certDir, "sm_sdk.key"),
			filepath.Join(certDir, "sm_ensdk.crt"),
			filepath.Join(certDir, "sm_ensdk.key"),
			time.Now().UTC(),
		); err != nil {
			fatalf("validate Guomi SDK dual-certificate identity: %v", err)
		}
	}
	receiptStarted := time.Now()
	if err := verifyReceiptConsensusHash(evidence.EventReceipt, evidence.Mode); err != nil {
		fatalf("verify receipt consensus hash: %v", err)
	}
	receiptElapsed := time.Since(receiptStarted)
	blockStarted := time.Now()
	if err := verifyBlockConsensusHash(evidence.Block, evidence.Mode); err != nil {
		fatalf("verify block consensus hash: %v", err)
	}
	blockElapsed := time.Since(blockStarted)
	pbftStarted := time.Now()
	if err := verifyPBFTCommitSignatures(evidence.Block, evidence.Mode); err != nil {
		fatalf("verify PBFT commit signatures: %v", err)
	}
	pbftElapsed := time.Since(pbftStarted)
	if err := json.NewEncoder(os.Stdout).Encode(result{
		ReceiptConsensusHashMatched: true,
		BlockConsensusHashMatched:   true,
		PBFTCommitSignaturesValid:   true,
		TimingSemantics:             "single_sample_diagnostic_not_benchmark",
		ReceiptVerificationNS:       receiptElapsed.Nanoseconds(),
		BlockVerificationNS:         blockElapsed.Nanoseconds(),
		PBFTVerificationNS:          pbftElapsed.Nanoseconds(),
	}); err != nil {
		fatalf("encode result: %v", err)
	}
}

func verifyPBFTCommitSignatures(block *types.Block, mode string) error {
	if block == nil || len(block.SealerList) == 0 ||
		len(block.SignatureList) == 0 ||
		len(block.ConsensusWeights) != len(block.SealerList) {
		return errors.New("block lacks a complete PBFT validator snapshot")
	}
	cryptoMode := fiscobcos.CryptoModeStandard
	sm2UserID := ""
	if mode == "guomi" {
		cryptoMode = fiscobcos.CryptoModeGuomi
		sm2UserID = cryptosuite.SM2DefaultUserID
	}
	blockHash, err := decodeRPCBytes(block.Hash)
	if err != nil || len(blockHash) != 32 {
		return errors.New("block hash is not 32 bytes")
	}
	for index, weight := range block.ConsensusWeights {
		if weight != 1 {
			return fmt.Errorf("validator %d has unsupported PBFT weight %d", index, weight)
		}
	}
	seen := make(map[uint64]struct{}, len(block.SignatureList))
	for index, commit := range block.SignatureList {
		if commit.SealerIndex >= uint64(len(block.SealerList)) {
			return fmt.Errorf("commit %d has out-of-range sealer index", index)
		}
		if _, duplicate := seen[commit.SealerIndex]; duplicate {
			return fmt.Errorf("commit %d duplicates sealer index %d", index, commit.SealerIndex)
		}
		seen[commit.SealerIndex] = struct{}{}
		rawPublicKey, err := decodeRPCBytes(block.SealerList[commit.SealerIndex])
		if err != nil || len(rawPublicKey) != 64 {
			return fmt.Errorf("commit %d sealer public key is not 64 bytes", index)
		}
		signature, err := decodeRPCBytes(commit.Signature)
		if err != nil {
			return fmt.Errorf("decode commit %d signature: %w", index, err)
		}
		publicKey := append([]byte{0x04}, rawPublicKey...)
		if err := fiscobcos.VerifyPBFTCommitSignature(
			cryptoMode,
			sm2UserID,
			publicKey,
			blockHash,
			signature,
		); err != nil {
			return fmt.Errorf("commit %d: %w", index, err)
		}
	}
	total := uint64(len(block.SealerList))
	required := total - (total-1)/3
	if uint64(len(seen)) < required {
		return fmt.Errorf("PBFT commit quorum has %d signatures, requires %d of %d", len(seen), required, total)
	}
	return nil
}

func verifyReceiptConsensusHash(receipt *types.Receipt, mode string) error {
	if receipt == nil || receipt.Version > math.MaxInt32 ||
		receipt.Status < math.MinInt32 || receipt.Status > math.MaxInt32 ||
		receipt.BlockNumber < 0 ||
		len(receipt.Logs) > fiscobcos.MaxCanonicalLogs {
		return errors.New("receipt fields exceed consensus representation")
	}
	if receipt.Version >= 1 || receipt.ContractAddress != "" {
		return errors.New("receipt contains fields the pinned SDK cannot reconstruct exactly")
	}
	output, err := decodeRPCBytes(receipt.Output)
	if err != nil {
		return err
	}
	logs := make([]fiscobcos.NativeLogFields, len(receipt.Logs))
	for index, log := range receipt.Logs {
		if log == nil || len(log.Topics) > fiscobcos.MaxNativeEvidenceItems {
			return errors.New("receipt log exceeds consensus representation")
		}
		topics := make([][]byte, len(log.Topics))
		for topicIndex, topic := range log.Topics {
			topics[topicIndex], err = decodeRPCBytes(topic)
			if err != nil || len(topics[topicIndex]) != 32 {
				return errors.New("receipt contains a non-32-byte topic")
			}
		}
		data, err := decodeRPCBytes(log.Data)
		if err != nil {
			return err
		}
		address, err := decodeRPCBytes(log.Address)
		if err != nil || len(address) != 20 || len(log.Address) != 40 {
			return errors.New("receipt contains a non-20-byte log address")
		}
		logs[index] = fiscobcos.NativeLogFields{Address: log.Address, Topics: topics, Data: data}
	}
	preimage, _, err := fiscobcos.MarshalNativeReceiptPreimage(fiscobcos.NativeReceiptFields{
		Version:         int32(receipt.Version),
		GasUsed:         receipt.GasUsed,
		ContractAddress: receipt.ContractAddress,
		Status:          int32(receipt.Status),
		Output:          output,
		Logs:            logs,
		BlockNumber:     int64(receipt.BlockNumber),
	})
	if err != nil {
		return err
	}
	return compareConsensusHash(mode, preimage, receipt.Hash, "receipt")
}

func verifyBlockConsensusHash(block *types.Block, mode string) error {
	if block == nil || block.Version > math.MaxInt32 ||
		block.Number > math.MaxInt64 || block.Timestamp > math.MaxInt64 ||
		block.Sealer > math.MaxInt64 ||
		len(block.ParentInfo) > fiscobcos.MaxNativeEvidenceItems ||
		len(block.SealerList) > fiscobcos.MaxNativeEvidenceItems ||
		len(block.ConsensusWeights) > fiscobcos.MaxNativeEvidenceItems {
		return errors.New("block fields exceed consensus representation")
	}
	parents := make([]fiscobcos.NativeParentInfo, len(block.ParentInfo))
	for index, parent := range block.ParentInfo {
		if parent.BlockNumber > math.MaxInt64 {
			return errors.New("parent block number exceeds consensus representation")
		}
		hash, err := decodeRPCBytes(parent.BlockHash)
		if err != nil || len(hash) != 32 {
			return errors.New("parent block hash is invalid")
		}
		parents[index] = fiscobcos.NativeParentInfo{BlockNumber: int64(parent.BlockNumber), BlockHash: hash}
	}
	txsRoot, err := decodeRPCBytes(block.TxsRoot)
	if err != nil {
		return err
	}
	receiptsRoot, err := decodeRPCBytes(block.ReceiptsRoot)
	if err != nil {
		return err
	}
	stateRoot, err := decodeRPCBytes(block.StateRoot)
	if err != nil {
		return err
	}
	sealers := make([][]byte, len(block.SealerList))
	for index, value := range block.SealerList {
		sealers[index], err = decodeRPCBytes(value)
		if err != nil {
			return err
		}
	}
	extra, err := decodeRPCBytes(block.ExtraData)
	if err != nil {
		return err
	}
	weights := make([]int64, len(block.ConsensusWeights))
	for index, value := range block.ConsensusWeights {
		if value > math.MaxInt64 {
			return errors.New("consensus weight exceeds consensus representation")
		}
		weights[index] = int64(value)
	}
	preimage, err := fiscobcos.MarshalNativeBlockHeaderPreimage(fiscobcos.NativeBlockHeaderFields{
		Version:          int32(block.Version),
		ParentInfo:       parents,
		TransactionsRoot: txsRoot,
		ReceiptsRoot:     receiptsRoot,
		StateRoot:        stateRoot,
		BlockNumber:      int64(block.Number),
		GasUsed:          block.GasUsed,
		Timestamp:        int64(block.Timestamp),
		Sealer:           int64(block.Sealer),
		SealerList:       sealers,
		ExtraData:        extra,
		ConsensusWeights: weights,
	})
	if err != nil {
		return err
	}
	return compareConsensusHash(mode, preimage, block.Hash, "block")
}

func compareConsensusHash(mode string, preimage []byte, claimedHex, object string) error {
	algorithm := fiscobcos.HashKeccak256
	if mode == "guomi" {
		algorithm = "sm3"
	}
	computed, err := fiscobcos.HashNativeEvidence(algorithm, preimage)
	if err != nil {
		return err
	}
	claimed, err := decodeRPCBytes(claimedHex)
	if err != nil || len(claimed) != 32 || !bytes.Equal(computed, claimed) {
		return fmt.Errorf(
			"%s TARS preimage hash %x does not match node hash %x",
			object,
			computed,
			claimed,
		)
	}
	return nil
}

func decodeRPCBytes(value string) ([]byte, error) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	if len(value)%2 != 0 {
		return nil, errors.New("hex value has odd length")
	}
	return hex.DecodeString(value)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
