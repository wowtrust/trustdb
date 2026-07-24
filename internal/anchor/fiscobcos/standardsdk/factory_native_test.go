//go:build fiscobcos_sdk && cgo

package standardsdk

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/FISCO-BCOS/go-sdk/v3/types"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
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
	if err := validateStandardSignerSignature(digest[:], signature, publicKey); err != nil {
		t.Fatal(err)
	}
	other, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStandardSignerSignature(digest[:], signature, ethcrypto.FromECDSAPub(&other.PublicKey)); err == nil {
		t.Fatal("accepted signature from a different account")
	}
}

func TestParseEndpointRejectsIgnoredURLComponents(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{
		"gm-tls://127.0.0.1:20200?alias=second",
		"gm-tls://127.0.0.1:20200/",
		"gm-tls://127.0.0.1:20200#second",
		" gm-tls://127.0.0.1:20200",
		"gm-tls://127.1:20200",
		"gm-tls://2130706433:20200",
		"gm-tls://127.000.000.001:20200",
		"gm-tls://0x7f000001:20200",
	} {
		if _, _, err := parseEndpoint(endpoint, fiscobcos.GuomiTransport); err == nil {
			t.Fatalf("parseEndpoint(%q) accepted an ignored URL component", endpoint)
		}
	}
	host, port, err := parseEndpoint(
		"gm-tls://127.0.0.1:20200",
		fiscobcos.GuomiTransport,
	)
	if err != nil || host != "127.0.0.1" || port != 20200 {
		t.Fatalf("parseEndpoint(valid) = %q, %d, %v", host, port, err)
	}
}

func TestGuomiSignerMaterialIsVerifiedAndConvertedToNativeFormat(t *testing.T) {
	t.Parallel()

	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := elliptic.Marshal(sm2.P256(), key.X, key.Y)
	digest := sha256.Sum256([]byte("FISCO BCOS Guomi transaction digest"))
	der, err := key.SignWithSM2(rand.Reader, []byte(cryptosuite.SM2DefaultUserID), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	trust := fiscobcos.TrustConfig{
		CryptoMode: fiscobcos.CryptoModeGuomi,
		SM2UserID:  cryptosuite.SM2DefaultUserID,
	}
	native, err := nativeSignerSignature(trust, digest[:], der, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(native) != 128 || !bytes.Equal(native[64:], publicKey[1:]) {
		t.Fatalf("native Guomi signature is not R||S||pub: %x", native)
	}
	if err := validateNativeSignature(trust, digest[:], native, publicKey); err != nil {
		t.Fatalf("native Guomi signature rejected: %v", err)
	}
	native[127] ^= 1
	if err := validateNativeSignature(trust, digest[:], native, publicKey); err == nil {
		t.Fatal("Guomi signature accepted a substituted embedded public key")
	}
	native[127] ^= 1
	other, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic := elliptic.Marshal(sm2.P256(), other.X, other.Y)
	if _, err := nativeSignerSignature(trust, digest[:], der, otherPublic); err == nil {
		t.Fatal("Guomi provider signature accepted a different configured public key")
	}

	address, err := accountAddress(fiscobcos.CryptoModeGuomi, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sm3.Sum(publicKey[1:])
	if !bytes.Equal(address, sum[12:]) {
		t.Fatalf("Guomi account address = %x, want %x", address, sum[12:])
	}
}

func TestGuomiPreparedTransactionRoundTripsWithSM3ModeBinding(t *testing.T) {
	t.Parallel()

	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := elliptic.Marshal(sm2.P256(), key.X, key.Y)
	contract := common.BytesToAddress(bytes.Repeat([]byte{0x42}, 20))
	input := bytes.Repeat([]byte{0x51}, 68)
	transaction := types.NewTransaction(
		contract,
		nil,
		0,
		nil,
		9000,
		input,
		"guomi-nonce",
		"chain0",
		"group0",
		"",
		true,
	)
	digest := transaction.Hash().Bytes()
	der, err := key.SignWithSM2(rand.Reader, []byte(cryptosuite.SM2DefaultUserID), digest)
	if err != nil {
		t.Fatal(err)
	}
	trust := fiscobcos.TrustConfig{
		CryptoMode: fiscobcos.CryptoModeGuomi,
		SM2UserID:  cryptosuite.SM2DefaultUserID,
		ChainID:    "chain0",
		GroupID:    "group0",
		Contract:   fiscobcos.ContractBinding{Address: contract.Bytes()},
	}
	native, err := nativeSignerSignature(trust, digest, der, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	transaction.Signature = native
	sender, err := accountAddress(fiscobcos.CryptoModeGuomi, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	senderAddress := common.BytesToAddress(sender)
	transaction.Sender = &senderAddress
	attempt := fiscobcos.TransactionSubmission{
		EncodedTransaction: transaction.Bytes(),
		ChainID:            "chain0",
		GroupID:            "group0",
		To:                 contract.Bytes(),
		Input:              input,
		Signature:          native,
		Sender:             sender,
		TransactionHash:    digest,
		BlockLimit:         9000,
	}
	if err := validatePreparedSubmission(attempt, trust, sender, publicKey); err != nil {
		t.Fatalf("Guomi prepared transaction rejected: %v", err)
	}
	standardTrust := trust
	standardTrust.CryptoMode = fiscobcos.CryptoModeStandard
	standardTrust.SM2UserID = ""
	if err := validatePreparedSubmission(attempt, standardTrust, sender, publicKey); err == nil {
		t.Fatal("Guomi prepared transaction accepted under standard mode")
	}
	attempt.TransactionHash = append([]byte(nil), attempt.TransactionHash...)
	attempt.TransactionHash[0] ^= 1
	if err := validatePreparedSubmission(attempt, trust, sender, publicKey); err == nil {
		t.Fatal("Guomi prepared transaction accepted a substituted transaction hash")
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
	attempt := fiscobcos.TransactionSubmission{
		TransactionHash: digest, Sender: sender, To: contract, Input: input,
	}
	if err := validateSubmittedReceiptIdentity(receipt, attempt); err != nil {
		t.Fatal(err)
	}
	receipt.TransactionHash = "0x" + strings.Repeat("44", 32)
	if err := validateSubmittedReceiptIdentity(receipt, attempt); err == nil {
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
		CryptoMode: fiscobcos.CryptoModeStandard,
		ChainID:    "chain0", GroupID: "group0",
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
		CryptoMode: fiscobcos.CryptoModeStandard,
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
	if err := verifyCertificateReferences(config, false, time.Now()); err != nil {
		t.Fatalf("injected signer should not read opaque account key reference: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(keyPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := verifyCertificateReferences(config, false, time.Now()); err == nil {
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

func TestBoundedHexDecodersPreserveOptionalNativeFields(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "0x"} {
		decoded, err := decodeHexBoundedOptional(value, 2)
		if err != nil || len(decoded) != 0 {
			t.Fatalf("decodeHexBoundedOptional(%q)=%x err=%v", value, decoded, err)
		}
	}
	decoded, err := decodeHexBoundedOptional("0x00ff", 2)
	if err != nil || !bytes.Equal(decoded, []byte{0x00, 0xff}) {
		t.Fatalf("decodeHexBoundedOptional(valid)=%x err=%v", decoded, err)
	}
	for _, value := range []string{"0x0", "0xzz", "0x000001"} {
		if _, err := decodeHexBoundedOptional(value, 2); err == nil {
			t.Fatalf("decodeHexBoundedOptional(%q) accepted invalid or oversized input", value)
		}
	}
	if _, err := decodeHexBounded("", 2); err == nil {
		t.Fatal("decodeHexBounded accepted an empty required field")
	}
}
