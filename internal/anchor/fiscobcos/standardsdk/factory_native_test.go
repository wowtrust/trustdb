//go:build fiscobcos_sdk && cgo

package standardsdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/FISCO-BCOS/go-sdk/v3/types"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
)

func TestValidateSignerSignatureRequiresConfiguredPublicKey(t *testing.T) {
	t.Parallel()
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("transaction"))
	signature, err := ethcrypto.Sign(digest[:], key)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := ethcrypto.FromECDSAPub(&key.PublicKey)
	if err := validateSignerSignature(digest[:], signature, publicKey); err != nil {
		t.Fatal(err)
	}
	other, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSignerSignature(digest[:], signature, ethcrypto.FromECDSAPub(&other.PublicKey)); err == nil {
		t.Fatal("accepted signature from a different account")
	}
}

func TestSubmittedReceiptBindingAndBoundedStatusArePanicFree(t *testing.T) {
	t.Parallel()
	digest := bytes.Repeat([]byte{0x11}, 32)
	sender := bytes.Repeat([]byte{0x22}, 20)
	contract := bytes.Repeat([]byte{0x33}, 20)
	input := []byte{1, 2, 3, 4}
	receipt := &types.Receipt{
		Status:          types.Success,
		TransactionHash: "0x" + hex.EncodeToString(digest),
		From:            "0x" + hex.EncodeToString(sender),
		To:              "0x" + hex.EncodeToString(contract),
		Input:           "0x" + hex.EncodeToString(input),
	}
	if err := validateSubmittedReceipt(receipt, digest, sender, contract, input); err != nil {
		t.Fatal(err)
	}
	receipt.TransactionHash = "0x" + strings.Repeat("44", 32)
	if err := validateSubmittedReceipt(receipt, digest, sender, contract, input); err == nil {
		t.Fatal("accepted mismatched transaction hash")
	}
	for _, status := range []int{types.Success, types.BlockLimitCheckFail, -1, int(^uint(0) >> 1)} {
		if got := boundedReceiptStatus(status); got == "" || len(got) > 64 {
			t.Fatalf("boundedReceiptStatus(%d)=%q", status, got)
		}
	}
}

func TestReceiptTransactionIdentityChecksEveryField(t *testing.T) {
	t.Parallel()
	hash := common.BytesToHash(bytes.Repeat([]byte{0x51}, 32))
	sender := bytes.Repeat([]byte{0x52}, 20)
	contract := bytes.Repeat([]byte{0x53}, 20)
	input := []byte{0x54, 0x55}
	signature := bytes.Repeat([]byte{0x56}, 65)
	attempt := fiscobcos.TransactionSubmission{
		EncodedTransaction: []byte{0x01},
		ChainID:            "chain0",
		GroupID:            "group0",
		To:                 contract,
		Input:              input,
		Signature:          signature,
		Sender:             sender,
		TransactionHash:    hash.Bytes(),
		BlockLimit:         500,
	}
	trust := fiscobcos.TrustConfig{
		ChainID: "chain0", GroupID: "group0",
		Contract: fiscobcos.ContractBinding{Address: contract},
	}
	receipt := &types.Receipt{
		TransactionHash: hash.Hex(),
		From:            "0x" + hex.EncodeToString(sender),
		To:              "0x" + hex.EncodeToString(contract),
		Input:           "0x" + hex.EncodeToString(input),
	}
	transaction := &types.TransactionDetail{
		Hash: hash.Hex(), From: receipt.From, To: receipt.To, Input: receipt.Input,
		ChainID: "chain0", GroupID: "group0", BlockLimit: 500,
		Signature: "0x" + hex.EncodeToString(signature),
	}
	if err := validateReceiptTransactionIdentity(receipt, transaction, attempt, trust); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []struct {
		name string
		fn   func(*types.TransactionDetail)
	}{
		{name: "input", fn: func(tx *types.TransactionDetail) { tx.Input = "0x00" }},
		{name: "chain", fn: func(tx *types.TransactionDetail) { tx.ChainID = "wrong-chain" }},
		{name: "group", fn: func(tx *types.TransactionDetail) { tx.GroupID = "wrong-group" }},
		{name: "block limit", fn: func(tx *types.TransactionDetail) { tx.BlockLimit++ }},
		{name: "signature", fn: func(tx *types.TransactionDetail) { tx.Signature = "0x00" }},
	} {
		tx := *transaction
		mutate.fn(&tx)
		if err := validateReceiptTransactionIdentity(receipt, &tx, attempt, trust); err == nil {
			t.Fatalf("accepted mismatched %s", mutate.name)
		}
	}
}

func TestLocalReferencesAreAbsoluteRegularAndPrivate(t *testing.T) {
	t.Parallel()
	if _, err := localPath("relative/key.pem"); err == nil {
		t.Fatal("accepted a relative local reference")
	}
	root := t.TempDir()
	caPath := filepath.Join(root, "ca.crt")
	certPath := filepath.Join(root, "sdk.crt")
	keyPath := filepath.Join(root, "sdk.key")
	for path, mode := range map[string]os.FileMode{caPath: 0o644, certPath: 0o644, keyPath: 0o600} {
		if err := os.WriteFile(path, []byte("not-empty"), mode); err != nil {
			t.Fatal(err)
		}
	}
	caDigest := sha256.Sum256([]byte("not-empty"))
	config := fiscobcos.TrustConfig{
		AccountProvider: fiscobcos.AccountProviderConfig{
			Provider: "sdf", KeyReference: "sdf://slot/7",
		},
		Certificates: fiscobcos.CertificateConfig{
			TrustedCAReferences:         []string{caPath},
			TrustedCACertificateHashes:  [][]byte{caDigest[:]},
			ClientSigningCertificateRef: certPath,
			ClientSigningKeyRef:         keyPath,
		},
	}
	if err := verifyCertificateReferences(config, false); err != nil {
		t.Fatalf("injected signer should not read opaque account key reference: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(keyPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := verifyCertificateReferences(config, false); err == nil {
			t.Fatal("accepted group-readable TLS private key")
		}
		if err := os.Chmod(keyPath, 0o600); err != nil {
			t.Fatal(err)
		}
		linkPath := filepath.Join(root, "key-link")
		if err := os.Symlink(keyPath, linkPath); err != nil {
			t.Fatal(err)
		}
		if _, err := readBoundedRegularFile(linkPath, true); err == nil {
			t.Fatal("accepted symlinked private key")
		}
	}
}

func TestNativeRPCBoundsRejectHostileEndpointValuesBeforeDecode(t *testing.T) {
	t.Parallel()

	if _, err := decodeSDKHexJSON(
		[]byte(`"0x`+strings.Repeat("00", 17)+`"`),
		16,
	); err == nil {
		t.Fatal("accepted oversized contract code JSON")
	}
	if _, err := strictHexBytes("0x"+strings.Repeat("00", 33), 32); err == nil {
		t.Fatal("accepted oversized fixed-width hash")
	}
	if _, err := decodeProofNodes(make([]string, maxSDKProofNodes+1)); err == nil {
		t.Fatal("allocated an oversized proof path")
	}
	if _, err := decodeProofNodes([]string{
		"0x" + strings.Repeat("00", maxSDKProofNodeBytes+1),
	}); err == nil {
		t.Fatal("decoded an oversized proof node")
	}

	receipt := &types.Receipt{ReceiptProof: []string{}}
	if err := validateReceiptRPCBounds(receipt); err != nil {
		t.Fatalf("compact receipt rejected: %v", err)
	}
	receipt.Message = strings.Repeat("x", maxSDKConfigStringBytes+1)
	if err := validateReceiptRPCBounds(receipt); err == nil {
		t.Fatal("accepted oversized receipt message")
	}
	receipt.Message = ""
	receipt.ReceiptProof = make([]string, maxSDKProofNodes+1)
	if err := validateReceiptRPCBounds(receipt); err == nil {
		t.Fatal("accepted oversized receipt proof path")
	}
	receipt.ReceiptProof = []string{}
	receipt.Logs = make([]*types.NewLog, maxSDKReceiptLogs+1)
	if err := validateReceiptRPCBounds(receipt); err == nil {
		t.Fatal("accepted oversized receipt log collection")
	}
	receipt.Logs = []*types.NewLog{{
		Address: "0x" + strings.Repeat("00", 20),
		Data:    "0x" + strings.Repeat("00", maxSDKDecodedEventBytes+1),
		Topics:  []string{"0x" + strings.Repeat("00", 32)},
	}}
	if err := validateReceiptRPCBounds(receipt); err == nil {
		t.Fatal("accepted oversized receipt log data")
	}

	transaction := &types.TransactionDetail{TransactionProof: []string{}}
	if err := validateTransactionRPCBounds(transaction); err != nil {
		t.Fatalf("compact transaction rejected: %v", err)
	}
	transaction.TransactionProof = make([]string, maxSDKProofNodes+1)
	if err := validateTransactionRPCBounds(transaction); err == nil {
		t.Fatal("accepted oversized transaction proof path")
	}
	transaction.TransactionProof = []string{}
	transaction.Input = "0x" + strings.Repeat("00", fiscobcos.MaxPayloadBytes+5)
	if err := validateTransactionRPCBounds(transaction); err == nil {
		t.Fatal("accepted oversized transaction input")
	}

	block := &types.Block{}
	if err := validateBlockRPCBounds(block); err != nil {
		t.Fatalf("compact header rejected: %v", err)
	}
	block.SignatureList = make([]types.Signature, maxSDKCommitSignatures+1)
	if err := validateBlockRPCBounds(block); err == nil {
		t.Fatal("accepted oversized block signature collection")
	}
	block.SignatureList = nil
	block.SealerList = []string{"0x" + strings.Repeat("00", maxSDKConfigStringBytes/2+1)}
	if err := validateBlockRPCBounds(block); err == nil {
		t.Fatal("accepted oversized validator node ID")
	}
	block.SealerList = nil
	block.Transactions = make([]interface{}, 1)
	if err := validateBlockRPCBounds(block); err == nil {
		t.Fatal("accepted transaction bodies in a header-only response")
	}
}
