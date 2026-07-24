package contracttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm3"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

const (
	chainID        = 1337
	transactionGas = 1_000_000
)

type testChain struct {
	backend  *backends.SimulatedBackend
	contract *bind.BoundContract
	parsed   abi.ABI
	keys     []*ecdsa.PrivateKey
	address  common.Address
}

type anchorRecord struct {
	StreamID        [32]byte
	TreeSize        uint64
	RootHash        [32]byte
	SignedSTHDigest [32]byte
	Publisher       common.Address
	PayloadVersion  uint16
	Exists          bool
}

type streamHead struct {
	TreeSize uint64
	RootHash [32]byte
	Exists   bool
}

type anchorPublishedData struct {
	TreeSize        uint64
	RootHash        [32]byte
	SignedSTHDigest [32]byte
	PayloadVersion  uint16
}

func artifactPath(parts ...string) string {
	all := append([]string{"..", "..", "..", "contracts", "fisco-bcos"}, parts...)
	return filepath.Join(all...)
}

func newTestChain(t *testing.T) *testChain {
	t.Helper()
	abiBytes, err := os.ReadFile(artifactPath("artifacts", "standard", "TrustDBAnchorV1.abi"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := abi.JSON(strings.NewReader(string(abiBytes)))
	if err != nil {
		t.Fatal(err)
	}
	binHex, err := os.ReadFile(artifactPath("artifacts", "standard", "TrustDBAnchorV1.bin"))
	if err != nil {
		t.Fatal(err)
	}
	bytecode, err := hex.DecodeString(strings.TrimSpace(string(binHex)))
	if err != nil {
		t.Fatal(err)
	}

	keys := make([]*ecdsa.PrivateKey, 4)
	allocation := make(core.GenesisAlloc)
	for i := range keys {
		keys[i], err = crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		allocation[crypto.PubkeyToAddress(keys[i].PublicKey)] = core.GenesisAccount{
			Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil),
		}
	}
	backend := backends.NewSimulatedBackend(allocation, 15_000_000)
	admin := crypto.PubkeyToAddress(keys[0].PublicKey)
	initialPublishers := []common.Address{
		crypto.PubkeyToAddress(keys[1].PublicKey),
		crypto.PubkeyToAddress(keys[2].PublicKey),
	}
	auth := transactor(t, keys[0], 0)
	address, deployment, contract, err := bind.DeployContract(
		auth, parsed, bytecode, backend, admin, initialPublishers,
	)
	if err != nil {
		t.Fatal(err)
	}
	backend.Commit()
	receipt, err := backend.TransactionReceipt(context.Background(), deployment.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatal("contract deployment reverted")
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close simulated backend: %v", err)
		}
	})
	return &testChain{
		backend:  backend,
		contract: contract,
		parsed:   parsed,
		keys:     keys,
		address:  address,
	}
}

func transactor(t testing.TB, key *ecdsa.PrivateKey, gasLimit uint64) *bind.TransactOpts {
	t.Helper()
	auth, err := bind.NewKeyedTransactorWithChainID(key, big.NewInt(chainID))
	if err != nil {
		t.Fatal(err)
	}
	auth.GasLimit = gasLimit
	return auth
}

func digest(label string) [32]byte {
	return crypto.Keccak256Hash([]byte(label))
}

func (chain *testChain) publish(
	t testing.TB,
	key int,
	anchorID, streamID [32]byte,
	treeSize uint64,
	rootHash, sthDigest [32]byte,
	commit bool,
) *types.Transaction {
	t.Helper()
	return chain.publishVersion(
		t, key, anchorID, streamID, treeSize, rootHash, sthDigest, 1, commit,
	)
}

func (chain *testChain) publishVersion(
	t testing.TB,
	key int,
	anchorID, streamID [32]byte,
	treeSize uint64,
	rootHash, sthDigest [32]byte,
	payloadVersion uint16,
	commit bool,
) *types.Transaction {
	t.Helper()
	transaction, err := chain.contract.Transact(
		transactor(t, chain.keys[key], transactionGas),
		"publish",
		anchorID,
		streamID,
		treeSize,
		rootHash,
		sthDigest,
		payloadVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	if commit {
		chain.backend.Commit()
	}
	return transaction
}

func (chain *testChain) call(t testing.TB, method string, arguments ...any) []any {
	t.Helper()
	var output []any
	if err := chain.contract.Call(&bind.CallOpts{}, &output, method, arguments...); err != nil {
		t.Fatal(err)
	}
	return output
}

func (chain *testChain) receipt(t testing.TB, transaction *types.Transaction) *types.Receipt {
	t.Helper()
	receipt, err := chain.backend.TransactionReceipt(context.Background(), transaction.Hash())
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func requireStatus(t testing.TB, receipt *types.Receipt, status uint64) {
	t.Helper()
	if receipt.Status != status {
		t.Fatalf("receipt status = %d, want %d", receipt.Status, status)
	}
}

func TestPublishIsIdempotentAcrossPublishersAndReordering(t *testing.T) {
	chain := newTestChain(t)
	streamID := digest("stream")
	anchorID := digest("anchor-10")
	rootHash := digest("root-10")
	sthDigest := digest("sth-10")

	first := chain.publish(t, 1, anchorID, streamID, 10, rootHash, sthDigest, true)
	firstReceipt := chain.receipt(t, first)
	requireStatus(t, firstReceipt, types.ReceiptStatusSuccessful)
	if len(firstReceipt.Logs) != 1 {
		t.Fatalf("first publish emitted %d logs, want 1", len(firstReceipt.Logs))
	}
	event := chain.parsed.Events["AnchorPublished"]
	if firstReceipt.Logs[0].Topics[0] != event.ID ||
		firstReceipt.Logs[0].Topics[1] != anchorID ||
		firstReceipt.Logs[0].Topics[2] != streamID ||
		firstReceipt.Logs[0].Topics[3] != common.BytesToHash(
			common.LeftPadBytes(crypto.PubkeyToAddress(chain.keys[1].PublicKey).Bytes(), 32),
		) {
		t.Fatal("AnchorPublished indexed fields do not match the submitted anchor")
	}
	var eventData anchorPublishedData
	if err := chain.parsed.UnpackIntoInterface(
		&eventData, "AnchorPublished", firstReceipt.Logs[0].Data,
	); err != nil {
		t.Fatal(err)
	}
	if eventData.TreeSize != 10 ||
		eventData.RootHash != rootHash ||
		eventData.SignedSTHDigest != sthDigest ||
		eventData.PayloadVersion != 1 {
		t.Fatalf("AnchorPublished data = %+v", eventData)
	}

	otherPublisherRetry := chain.publish(t, 2, anchorID, streamID, 10, rootHash, sthDigest, true)
	retryReceipt := chain.receipt(t, otherPublisherRetry)
	requireStatus(t, retryReceipt, types.ReceiptStatusSuccessful)
	if len(retryReceipt.Logs) != 0 {
		t.Fatalf("exact duplicate emitted %d logs, want 0", len(retryReceipt.Logs))
	}
	record := *abi.ConvertType(chain.call(t, "getAnchor", anchorID)[0], new(anchorRecord)).(*anchorRecord)
	if record.StreamID != streamID ||
		record.TreeSize != 10 ||
		record.RootHash != rootHash ||
		record.SignedSTHDigest != sthDigest ||
		record.Publisher != crypto.PubkeyToAddress(chain.keys[1].PublicKey) ||
		record.PayloadVersion != 1 ||
		!record.Exists {
		t.Fatalf("stored anchor record changed after retry: %+v", record)
	}

	newer := chain.publish(
		t, 1, digest("anchor-20"), streamID, 20, digest("root-20"), digest("sth-20"), true,
	)
	requireStatus(t, chain.receipt(t, newer), types.ReceiptStatusSuccessful)
	head := *abi.ConvertType(chain.call(t, "getStreamHead", streamID)[0], new(streamHead)).(*streamHead)
	if head.TreeSize != 20 || head.RootHash != digest("root-20") || !head.Exists {
		t.Fatalf("stream head = %+v", head)
	}
	reorderedRetry := chain.publish(t, 2, anchorID, streamID, 10, rootHash, sthDigest, true)
	requireStatus(t, chain.receipt(t, reorderedRetry), types.ReceiptStatusSuccessful)
}

func TestPublishRejectsInvalidInput(t *testing.T) {
	chain := newTestChain(t)
	validAnchor := digest("anchor")
	validStream := digest("stream")
	validRoot := digest("root")
	validSTH := digest("sth")
	tests := []struct {
		name           string
		anchorID       [32]byte
		streamID       [32]byte
		treeSize       uint64
		rootHash       [32]byte
		sthDigest      [32]byte
		payloadVersion uint16
	}{
		{"zero anchor ID", [32]byte{}, validStream, 1, validRoot, validSTH, 1},
		{"zero stream ID", validAnchor, [32]byte{}, 1, validRoot, validSTH, 1},
		{"zero tree size", validAnchor, validStream, 0, validRoot, validSTH, 1},
		{"zero root hash", validAnchor, validStream, 1, [32]byte{}, validSTH, 1},
		{"zero STH digest", validAnchor, validStream, 1, validRoot, [32]byte{}, 1},
		{"unknown payload version", validAnchor, validStream, 1, validRoot, validSTH, 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transaction := chain.publishVersion(
				t,
				1,
				test.anchorID,
				test.streamID,
				test.treeSize,
				test.rootHash,
				test.sthDigest,
				test.payloadVersion,
				true,
			)
			requireStatus(t, chain.receipt(t, transaction), types.ReceiptStatusFailed)
		})
	}
}

func TestPublishRejectsConflictsAndRegression(t *testing.T) {
	chain := newTestChain(t)
	streamID := digest("stream")
	anchorID := digest("anchor")
	rootHash := digest("root")
	sthDigest := digest("sth")
	requireStatus(
		t,
		chain.receipt(t, chain.publish(t, 1, anchorID, streamID, 12, rootHash, sthDigest, true)),
		types.ReceiptStatusSuccessful,
	)

	tests := []struct {
		name      string
		anchorID  [32]byte
		treeSize  uint64
		rootHash  [32]byte
		sthDigest [32]byte
	}{
		{"same ID different STH", anchorID, 12, rootHash, digest("different-sth")},
		{"tree size regression", digest("old"), 11, digest("old-root"), digest("old-sth")},
		{"same size different root", digest("fork"), 12, digest("fork-root"), digest("fork-sth")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transaction := chain.publish(
				t, 1, test.anchorID, streamID, test.treeSize, test.rootHash, test.sthDigest, true,
			)
			requireStatus(t, chain.receipt(t, transaction), types.ReceiptStatusFailed)
		})
	}

	// The protocol permits another exact Signed STH at the same size and root.
	sameRoot := chain.publish(
		t, 2, digest("same-size-new-sth"), streamID, 12, rootHash, digest("new-sth"), true,
	)
	requireStatus(t, chain.receipt(t, sameRoot), types.ReceiptStatusSuccessful)
}

func TestAuthorizationAndLastPublisherGuard(t *testing.T) {
	chain := newTestChain(t)
	unauthorized := chain.publish(
		t, 3, digest("unauthorized"), digest("stream"), 1, digest("root"), digest("sth"), true,
	)
	requireStatus(t, chain.receipt(t, unauthorized), types.ReceiptStatusFailed)

	admin := transactor(t, chain.keys[0], transactionGas)
	third := crypto.PubkeyToAddress(chain.keys[3].PublicKey)
	authorized, err := chain.contract.Transact(admin, "setPublisher", third, true)
	if err != nil {
		t.Fatal(err)
	}
	chain.backend.Commit()
	requireStatus(t, chain.receipt(t, authorized), types.ReceiptStatusSuccessful)
	if len(chain.receipt(t, authorized).Logs) != 1 {
		t.Fatal("new publisher authorization did not emit exactly one event")
	}
	noChange, err := chain.contract.Transact(
		transactor(t, chain.keys[0], transactionGas), "setPublisher", third, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	chain.backend.Commit()
	requireStatus(t, chain.receipt(t, noChange), types.ReceiptStatusSuccessful)
	if len(chain.receipt(t, noChange).Logs) != 0 {
		t.Fatal("idempotent publisher authorization emitted an event")
	}
	requireStatus(
		t,
		chain.receipt(
			t,
			chain.publish(
				t, 3, digest("authorized"), digest("stream"), 1, digest("root"), digest("sth"), true,
			),
		),
		types.ReceiptStatusSuccessful,
	)

	nonAdmin, err := chain.contract.Transact(
		transactor(t, chain.keys[1], transactionGas), "setPublisher", third, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	chain.backend.Commit()
	requireStatus(t, chain.receipt(t, nonAdmin), types.ReceiptStatusFailed)

	for _, key := range []int{1, 2} {
		transaction, err := chain.contract.Transact(
			transactor(t, chain.keys[0], transactionGas),
			"setPublisher",
			crypto.PubkeyToAddress(chain.keys[key].PublicKey),
			false,
		)
		if err != nil {
			t.Fatal(err)
		}
		chain.backend.Commit()
		requireStatus(t, chain.receipt(t, transaction), types.ReceiptStatusSuccessful)
	}
	last, err := chain.contract.Transact(
		transactor(t, chain.keys[0], transactionGas), "setPublisher", third, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	chain.backend.Commit()
	requireStatus(t, chain.receipt(t, last), types.ReceiptStatusFailed)
	count := *abi.ConvertType(chain.call(t, "publisherCount")[0], new(*big.Int)).(**big.Int)
	if count.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("publisherCount = %s, want 1", count)
	}
	stillAuthorized := *abi.ConvertType(chain.call(t, "publishers", third)[0], new(bool)).(*bool)
	if !stillAuthorized {
		t.Fatal("last publisher was revoked despite failed transaction")
	}
}

func TestSameBlockRetriesAndConflictAreSerialized(t *testing.T) {
	chain := newTestChain(t)
	streamID := digest("stream")
	anchorID := digest("same-block")
	rootHash := digest("same-block-root")
	sthDigest := digest("same-block-sth")

	first := chain.publish(t, 1, anchorID, streamID, 10, rootHash, sthDigest, false)
	retry := chain.publish(t, 2, anchorID, streamID, 10, rootHash, sthDigest, false)
	chain.backend.Commit()
	requireStatus(t, chain.receipt(t, first), types.ReceiptStatusSuccessful)
	requireStatus(t, chain.receipt(t, retry), types.ReceiptStatusSuccessful)
	if len(chain.receipt(t, first).Logs) != 1 || len(chain.receipt(t, retry).Logs) != 0 {
		t.Fatal("same-block duplicate did not preserve exactly-once event semantics")
	}

	winner := chain.publish(
		t, 1, digest("winner"), streamID, 11, digest("winner-root"), digest("winner-sth"), false,
	)
	conflict := chain.publish(
		t, 2, digest("conflict"), streamID, 11, digest("conflict-root"), digest("conflict-sth"), false,
	)
	chain.backend.Commit()
	requireStatus(t, chain.receipt(t, winner), types.ReceiptStatusSuccessful)
	requireStatus(t, chain.receipt(t, conflict), types.ReceiptStatusFailed)
}

func TestPublishGasCeilings(t *testing.T) {
	chain := newTestChain(t)
	streamID := digest("stream")
	first := chain.publish(
		t, 1, digest("first"), streamID, 1, digest("root-1"), digest("sth-1"), true,
	)
	firstReceipt := chain.receipt(t, first)
	requireStatus(t, firstReceipt, types.ReceiptStatusSuccessful)
	if firstReceipt.GasUsed > 300_000 {
		t.Fatalf("first publish gas = %d, ceiling 300000", firstReceipt.GasUsed)
	}
	retry := chain.publish(
		t, 2, digest("first"), streamID, 1, digest("root-1"), digest("sth-1"), true,
	)
	retryReceipt := chain.receipt(t, retry)
	requireStatus(t, retryReceipt, types.ReceiptStatusSuccessful)
	if retryReceipt.GasUsed > 100_000 {
		t.Fatalf("duplicate publish gas = %d, ceiling 100000", retryReceipt.GasUsed)
	}
	advance := chain.publish(
		t, 1, digest("second"), streamID, 2, digest("root-2"), digest("sth-2"), true,
	)
	advanceReceipt := chain.receipt(t, advance)
	requireStatus(t, advanceReceipt, types.ReceiptStatusSuccessful)
	if advanceReceipt.GasUsed > 220_000 {
		t.Fatalf("advancing publish gas = %d, ceiling 220000", advanceReceipt.GasUsed)
	}
	t.Logf(
		"gas: first=%d duplicate=%d advance=%d",
		firstReceipt.GasUsed,
		retryReceipt.GasUsed,
		advanceReceipt.GasUsed,
	)
}

func FuzzExactDuplicateIsIdempotent(f *testing.F) {
	f.Add([]byte("anchor-a"), []byte("stream-a"), uint64(1))
	f.Add([]byte("anchor-b"), []byte("stream-b"), uint64(128))
	f.Fuzz(func(t *testing.T, anchorSeed, streamSeed []byte, treeSize uint64) {
		if treeSize == 0 {
			treeSize = 1
		}
		chain := newTestChain(t)
		anchorID := crypto.Keccak256Hash(anchorSeed)
		streamID := crypto.Keccak256Hash(streamSeed)
		if anchorID == ([32]byte{}) {
			anchorID[0] = 1
		}
		if streamID == ([32]byte{}) {
			streamID[0] = 1
		}
		rootHash := crypto.Keccak256Hash(append([]byte("root"), anchorSeed...))
		sthDigest := crypto.Keccak256Hash(append([]byte("sth"), streamSeed...))
		first := chain.publish(t, 1, anchorID, streamID, treeSize, rootHash, sthDigest, true)
		retry := chain.publish(t, 2, anchorID, streamID, treeSize, rootHash, sthDigest, true)
		requireStatus(t, chain.receipt(t, first), types.ReceiptStatusSuccessful)
		requireStatus(t, chain.receipt(t, retry), types.ReceiptStatusSuccessful)
		if len(chain.receipt(t, retry).Logs) != 0 {
			t.Fatal("duplicate emitted an event")
		}
	})
}

func TestArtifactManifestAndNativeCodeHashes(t *testing.T) {
	manifestBytes, err := os.ReadFile(artifactPath("artifacts", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		CanonicalEvent string `json:"canonical_event"`
		Source         struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"source"`
		Modes map[string]struct {
			ABI                string `json:"abi_sha256"`
			Creation           string `json:"creation_bytecode_sha256"`
			Runtime            string `json:"runtime_bytecode_sha256"`
			RuntimeCodeHash    string `json:"runtime_code_hash"`
			RuntimeCodeHashAlg string `json:"runtime_code_hash_algorithm"`
			CreationByteCount  int    `json:"creation_byte_count"`
			RuntimeByteCount   int    `json:"runtime_byte_count"`
		} `json:"modes"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(artifactPath("TrustDBAnchorV1.sol"))
	if err != nil {
		t.Fatal(err)
	}
	sourceSum := sha256.Sum256(source)
	if hex.EncodeToString(sourceSum[:]) != manifest.Source.SHA256 {
		t.Fatal("source SHA-256 does not match manifest")
	}

	var standardABI []byte
	for _, mode := range []string{"standard", "guomi"} {
		details := manifest.Modes[mode]
		abiBytes, err := os.ReadFile(artifactPath("artifacts", mode, "TrustDBAnchorV1.abi"))
		if err != nil {
			t.Fatal(err)
		}
		abiSum := sha256.Sum256(abiBytes)
		if hex.EncodeToString(abiSum[:]) != details.ABI {
			t.Fatalf("%s ABI hash mismatch", mode)
		}
		if mode == "standard" {
			standardABI = abiBytes
		} else if string(standardABI) != string(abiBytes) {
			t.Fatal("standard and Guomi ABIs differ")
		}
		parsed, err := abi.JSON(strings.NewReader(string(abiBytes)))
		if err != nil {
			t.Fatal(err)
		}
		event, exists := parsed.Events["AnchorPublished"]
		if !exists || event.Sig != manifest.CanonicalEvent {
			t.Fatalf("%s canonical AnchorPublished signature mismatch", mode)
		}
		for _, artifact := range []struct {
			label, suffix, expected string
			expectedCount           int
		}{
			{"creation", "bin", details.Creation, details.CreationByteCount},
			{"runtime", "bin-runtime", details.Runtime, details.RuntimeByteCount},
		} {
			encoded, err := os.ReadFile(
				artifactPath("artifacts", mode, "TrustDBAnchorV1."+artifact.suffix),
			)
			if err != nil {
				t.Fatal(err)
			}
			code, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(code)
			if hex.EncodeToString(sum[:]) != artifact.expected || len(code) != artifact.expectedCount {
				t.Fatalf("%s %s artifact identity mismatch", mode, artifact.label)
			}
			if artifact.label == "runtime" {
				var native []byte
				if details.RuntimeCodeHashAlg == "keccak256" {
					hash := sha3.NewLegacyKeccak256()
					_, _ = hash.Write(code)
					native = hash.Sum(nil)
				} else if details.RuntimeCodeHashAlg == "sm3" {
					sum := sm3.Sum(code)
					native = sum[:]
				} else {
					t.Fatalf("%s has unsupported native code hash algorithm", mode)
				}
				if hex.EncodeToString(native) != details.RuntimeCodeHash {
					t.Fatalf("%s native runtime code hash mismatch", mode)
				}
			}
		}
	}
}

func TestDeploymentRecordAndRoleMetadata(t *testing.T) {
	deploymentBytes, err := os.ReadFile(
		artifactPath("deployments", "deployment-record.template.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	var deployment struct {
		Schema         string `json:"schema"`
		Contract       string `json:"contract"`
		Protocol       string `json:"contract_protocol_version"`
		EventSignature string `json:"contract_event_signature"`
		PayloadVersion uint16 `json:"payload_version"`
	}
	if err := json.Unmarshal(deploymentBytes, &deployment); err != nil {
		t.Fatal(err)
	}
	if deployment.Schema != "trustdb.fisco-bcos-contract-deployment.v1" ||
		deployment.Contract != "TrustDBAnchorV1" ||
		deployment.Protocol != "trustdb-anchor-v1" ||
		deployment.EventSignature !=
			"AnchorPublished(bytes32,bytes32,uint64,bytes32,bytes32,address,uint16)" ||
		deployment.PayloadVersion != 1 {
		t.Fatalf("deployment record protocol identity = %+v", deployment)
	}

	rolesBytes, err := os.ReadFile(artifactPath("roles.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var roles struct {
		Schema string                     `json:"schema"`
		Roles  map[string]json.RawMessage `json:"roles"`
	}
	if err := json.Unmarshal(rolesBytes, &roles); err != nil {
		t.Fatal(err)
	}
	if roles.Schema != "trustdb.fisco-bcos-contract-roles.v1" ||
		roles.Roles["administrator"] == nil ||
		roles.Roles["publisher"] == nil {
		t.Fatal("role metadata does not define the V1 administrator and publisher")
	}
}
