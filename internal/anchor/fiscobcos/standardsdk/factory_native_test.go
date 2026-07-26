//go:build fiscobcos_sdk && cgo

package standardsdk

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

	"github.com/wowtrust/trustdb/v2/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
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

type nativeRPCError struct {
	code int
	text string
}

func (e nativeRPCError) Error() string  { return e.text }
func (e nativeRPCError) ErrorCode() int { return e.code }

func TestNormalizeTransactionLookupErrorRetriesLedgerGetStorageError(t *testing.T) {
	t.Parallel()

	missing := nativeRPCError{code: sdkLedgerGetStorageErrorCode, text: "GetTransactionReceiptByHash"}
	err := normalizeTransactionLookupError(missing)
	if !errors.Is(err, fiscobcos.ErrTransactionNotFound) {
		t.Fatalf("ledger lookup error was not classified as temporarily unobservable: %v", err)
	}
	var preserved nativeRPCError
	if !errors.As(err, &preserved) || preserved.code != sdkLedgerGetStorageErrorCode {
		t.Fatalf("ledger RPC error was not preserved: %v", err)
	}

	other := nativeRPCError{code: 3009, text: "different ledger error"}
	err = normalizeTransactionLookupError(other)
	if errors.Is(err, fiscobcos.ErrTransactionNotFound) {
		t.Fatalf("unrelated RPC error was classified as temporarily unobservable: %v", err)
	}
	if !errors.As(err, &preserved) || preserved.code != other.code {
		t.Fatalf("unrelated RPC error was not returned unchanged: %v", err)
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
		"[fe80::1%1]:20200",
		"gm-tls://[fe80::1%251]:20200",
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

	receipt := &types.Receipt{GasUsed: "97255", ReceiptProof: []string{}}
	if err := validateReceiptRPCBounds(receipt); err != nil {
		t.Fatalf("compact receipt rejected: %v", err)
	}
	receipt.GasUsed = "0x17be7"
	if err := validateReceiptRPCBounds(receipt); err == nil {
		t.Fatal("accepted non-decimal receipt gasUsed")
	}
	receipt.GasUsed = "97255"
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

	block := &types.Block{GasUsed: "97255", GasLimit: "3000000000"}
	if err := validateBlockRPCBounds(block); err != nil {
		t.Fatalf("compact header rejected: %v", err)
	}
	block.GasUsed = strings.Repeat("9", maxSDKUnsignedDecimalDigits+1)
	if err := validateBlockRPCBounds(block); err == nil {
		t.Fatal("accepted oversized block gasUsed")
	}
	block.GasUsed = "97255"
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

func TestDecodeAnchorEventAcceptsNativeAddressWithoutHexPrefix(t *testing.T) {
	t.Parallel()

	contractAddress := bytes.Repeat([]byte{0x42}, 20)
	contract := fiscobcos.ContractBinding{
		Address:        contractAddress,
		EventSignature: fiscobcos.TrustDBAnchorV1EventSignature,
	}
	eventID, err := fiscobcos.EventTopicForMode(fiscobcos.CryptoModeStandard, contract.EventSignature)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4*32)
	data[31] = 7
	copy(data[32:64], bytes.Repeat([]byte{0x51}, 32))
	copy(data[64:96], bytes.Repeat([]byte{0x52}, 32))
	data[127] = 1
	publisherWord := append(make([]byte, 12), bytes.Repeat([]byte{0x53}, 20)...)
	receipt := &types.Receipt{Logs: []*types.NewLog{{
		Address: hex.EncodeToString(contractAddress),
		Data:    "0x" + hex.EncodeToString(data),
		Topics: []string{
			"0x" + hex.EncodeToString(eventID),
			"0x" + strings.Repeat("54", 32),
			"0x" + strings.Repeat("55", 32),
			"0x" + hex.EncodeToString(publisherWord),
		},
	}}}

	event, err := decodeAnchorEvent(receipt, fiscobcos.CryptoModeStandard, contract)
	if err != nil {
		t.Fatalf("decode native event: %v", err)
	}
	if event.TreeSize != 7 || event.PayloadVersion != 1 ||
		!bytes.Equal(event.ContractAddress, contractAddress) ||
		!bytes.Equal(event.Publisher, bytes.Repeat([]byte{0x53}, 20)) {
		t.Fatalf("decoded event does not match native log: %+v", event)
	}

	receipt.Logs[0].Address = strings.Repeat("ff", 20)
	if _, err := decodeAnchorEvent(receipt, fiscobcos.CryptoModeStandard, contract); !errors.Is(err, fiscobcos.ErrContractMismatch) {
		t.Fatalf("wrong contract address error=%v, want contract mismatch", err)
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

func TestTransitionTransactionEvidenceDecodesRPCNonceHex(t *testing.T) {
	t.Parallel()

	// Recorded from a live v3.16.3 four-node Air network: the JSON-RPC
	// getTransactionByHash nonce is toHex(raw nonce string) without a 0x
	// prefix, while the consensus transaction hash covers the raw nonce
	// string bytes. The expected hash is the on-chain transaction hash of
	// the setWeight consensus precompile call in block 5.
	const (
		rawNonce  = "1470614449897024475616799902516882132264"
		rpcNonce  = "31343730363134343439383937303234343735363136373939393032353136383832313332323634"
		rpcTo     = "0000000000000000000000000000000000001003"
		rpcInput  = "0xce6fa5c50000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000806430666361313838656333306331353234653161303666316235623730646262316261663336316536643739363761306332633034366363303733646364636530366434383564303764656636336135363362666132616636326365376361666231653436316261663433633737373562346435313930316530353239636536"
		chainHash = "0x11096782747441dfc1f15b1989c99a89f02c0b3c61419dcd5709d732c1b09786"
	)
	if hex.EncodeToString([]byte(rawNonce)) != rpcNonce {
		t.Fatal("test fixture nonce encoding is inconsistent")
	}
	driver := &nativeDriver{trust: fiscobcos.TrustConfig{
		ChainID: "chain0", GroupID: "group0",
		ChainHashAlgorithm: fiscobcos.HashKeccak256,
	}}
	transaction := &types.TransactionDetail{
		Version: 0, ChainID: "chain0", GroupID: "group0",
		BlockLimit: 604, Nonce: rpcNonce,
		To: rpcTo, Input: rpcInput, Hash: chainHash,
	}
	evidence, err := driver.transitionTransactionEvidence(transaction, common.HexToHash(chainHash))
	if err != nil {
		t.Fatalf("decode live-recorded transition transaction: %v", err)
	}
	if evidence.Fields.Nonce != rawNonce {
		t.Fatalf("nonce=%q, want the raw string %q", evidence.Fields.Nonce, rawNonce)
	}
	if !bytes.Equal(evidence.TransactionHash, common.HexToHash(chainHash).Bytes()) {
		t.Fatalf("transaction hash %x does not match the on-chain hash", evidence.TransactionHash)
	}

	// A verbatim nonce string (not hex-encoded) is the pre-fix wire shape:
	// the recomputed hash must not match and the evidence must fail closed.
	stale := *transaction
	stale.Nonce = rawNonce
	if _, err := driver.transitionTransactionEvidence(&stale, common.HexToHash(chainHash)); !errors.Is(err, fiscobcos.ErrIncompleteChainEvidence) {
		t.Fatalf("verbatim nonce error=%v, want incomplete chain evidence", err)
	}

	// Non-hex nonce text is outside the pinned RPC contract and must fail.
	hostile := *transaction
	hostile.Nonce = "zz"
	if _, err := driver.transitionTransactionEvidence(&hostile, common.HexToHash(chainHash)); !errors.Is(err, fiscobcos.ErrIncompleteChainEvidence) {
		t.Fatalf("non-hex nonce error=%v, want incomplete chain evidence", err)
	}
}
