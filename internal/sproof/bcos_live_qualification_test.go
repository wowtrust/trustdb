//go:build fiscobcos_sdk && cgo

package sproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm3"

	"github.com/wowtrust/trustdb/internal/anchor"
	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos/standardsdk"
	"github.com/wowtrust/trustdb/internal/backup"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/scripts/fisco-bcos/qualificationformat"
)

type liveBCOSClientEvidence struct {
	Mode              string `json:"mode"`
	ChainID           string `json:"chain_id"`
	GenesisHash       string `json:"genesis_hash"`
	ContractCodeHash  string `json:"contract_code_hash"`
	TrustedCheckpoint struct {
		BlockNumber uint64 `json:"block_number"`
		BlockHash   string `json:"block_hash"`
	} `json:"trusted_checkpoint"`
	Deployment struct {
		ContractAddress string `json:"contract_address"`
	} `json:"deployment"`
	Sealers []struct {
		NodeID string `json:"nodeID"`
		Weight uint64 `json:"weight"`
	} `json:"sealers"`
}

type liveBCOSQualificationReport struct {
	Schema                     string `json:"schema"`
	Mode                       string `json:"mode"`
	ProofPath                  string `json:"proof_path"`
	TrustRootsPath             string `json:"trust_roots_path"`
	BackupPath                 string `json:"backup_path,omitempty"`
	BackupRestoreVerified      bool   `json:"backup_restore_verified"`
	BackupFailClosedReason     string `json:"backup_fail_closed_reason,omitempty"`
	DurableReplayVerified      bool   `json:"durable_replay_verified"`
	ProviderFailureStage       string `json:"provider_failure_stage"`
	TransportFailureStage      string `json:"transport_failure_stage"`
	StorageFailureStage        string `json:"storage_failure_stage,omitempty"`
	UnknownOutcomeInjected     bool   `json:"unknown_outcome_injected"`
	UnknownOutcomeRecovered    bool   `json:"unknown_outcome_recovered"`
	AnchorID                   string `json:"anchor_id"`
	AnchorBlockNumber          uint64 `json:"anchor_block_number"`
	ValidatorHistoryBlockCount int    `json:"validator_history_block_count"`
}

type qualificationUnknownOutcomeDriver struct {
	fiscobcos.Driver
	injected *atomic.Bool
}

func (d qualificationUnknownOutcomeDriver) SubmitPreparedAnchor(
	ctx context.Context,
	attempt fiscobcos.TransactionSubmission,
) (fiscobcos.SubmissionOutcome, error) {
	outcome, err := d.Driver.SubmitPreparedAnchor(ctx, attempt)
	if err == nil && d.injected.CompareAndSwap(false, true) {
		return fiscobcos.SubmissionOutcome{}, errors.New("injected transport loss after successful BCOS submission")
	}
	return outcome, err
}

func (d qualificationUnknownOutcomeDriver) GetValidatorHistoryBlock(
	ctx context.Context,
	blockNumber uint64,
	includeTransitions bool,
) (fiscobcos.ValidatorHistoryBlock, error) {
	driver, ok := d.Driver.(fiscobcos.ValidatorHistoryDriver)
	if !ok {
		return fiscobcos.ValidatorHistoryBlock{}, fiscobcos.ErrIncompleteChainEvidence
	}
	return driver.GetValidatorHistoryBlock(ctx, blockNumber, includeTransitions)
}

func TestLiveBCOSFourNodeQualification(t *testing.T) {
	if os.Getenv("TRUSTDB_BCOS_QUALIFICATION") != "1" {
		t.Skip("set TRUSTDB_BCOS_QUALIFICATION=1 inside the pinned four-node Air harness")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	evidencePath := requiredQualificationEnv(t, "TRUSTDB_BCOS_CLIENT_EVIDENCE")
	certDir := requiredQualificationEnv(t, "TRUSTDB_BCOS_CERT_DIR")
	accountKey := requiredQualificationEnv(t, "TRUSTDB_BCOS_ACCOUNT_KEY")
	outputDir := requiredQualificationEnv(t, "TRUSTDB_BCOS_OUTPUT_DIR")
	rpcPort, err := strconv.Atoi(requiredQualificationEnv(t, "TRUSTDB_BCOS_RPC_PORT"))
	if err != nil || rpcPort < 1 || rpcPort > 65532 {
		t.Fatalf("invalid TRUSTDB_BCOS_RPC_PORT")
	}
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		t.Fatal(err)
	}

	var live liveBCOSClientEvidence
	readQualificationJSON(t, evidencePath, &live)
	mode, suiteID := qualificationModeAndSuite(t, live.Mode)
	fixture := newOfflineE2EFixture(t, suiteID)
	trust := liveBCOSTrustConfig(t, live, mode, certDir, accountKey, rpcPort)

	providerError := requireQualificationFactoryFailure(
		t,
		ctx,
		func(config *fiscobcos.TrustConfig) {
			config.AccountProvider.KeyReference = filepath.Join(outputDir, "missing-publisher.key")
		},
		trust,
	)
	transportError := requireQualificationFactoryFailure(
		t,
		ctx,
		func(config *fiscobcos.TrustConfig) {
			config.Certificates.TrustedCACertificateHashes[0][0] ^= 1
		},
		trust,
	)

	drivers, err := (standardsdk.NativeFactory{}).NewDrivers(ctx, standardsdk.Config{TrustConfig: trust})
	if err != nil {
		t.Fatalf("create native BCOS drivers: %v", err)
	}
	var unknownOutcomeInjected atomic.Bool
	for index := range drivers {
		drivers[index] = qualificationUnknownOutcomeDriver{
			Driver:   drivers[index],
			injected: &unknownOutcomeInjected,
		}
	}
	sink, err := anchor.NewFISCOBCOSStandardSink(anchor.FISCOBCOSStandardSinkConfig{
		TrustConfig: trust,
		Drivers:     drivers,
	})
	if err != nil {
		for _, driver := range drivers {
			_ = driver.Close()
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	providerState := []byte(nil)
	unknownOutcomeCheckpointed := false
	checkpoint := func(_ context.Context, expected, next []byte) error {
		if !bytes.Equal(expected, providerState) {
			return errors.New("stale qualification provider-state checkpoint")
		}
		journal, err := fiscobcos.UnmarshalAttemptJournal(next)
		if err != nil {
			return fmt.Errorf("decode qualification provider-state checkpoint: %w", err)
		}
		for _, journalAttempt := range journal.Attempts {
			if journalAttempt.Outcome == fiscobcos.AttemptOutcomeSubmitUnknown {
				unknownOutcomeCheckpointed = true
			}
		}
		providerState = append(providerState[:0], next...)
		return nil
	}
	attempt := model.STHAnchorAttempt{
		Generation: 1,
		Target:     fixture.proof.GlobalProof.STH,
	}
	result, err := publishBCOSQualificationDurably(ctx, sink, attempt, checkpoint, &providerState)
	if err != nil {
		t.Fatalf("publish real Signed STH: %v", err)
	}
	if len(providerState) == 0 {
		t.Fatal("durable publication did not checkpoint provider state")
	}
	if !unknownOutcomeInjected.Load() || !unknownOutcomeCheckpointed {
		t.Fatal("durable publication did not checkpoint and recover the injected unknown outcome")
	}
	replayAttempt := attempt
	replayAttempt.ProviderState = append([]byte(nil), providerState...)
	replayed, err := sink.PublishDurable(ctx, replayAttempt, checkpoint)
	if err != nil {
		t.Fatalf("replay completed durable publication: %v", err)
	}
	if !reflect.DeepEqual(result, replayed) {
		t.Fatal("durable replay changed the immutable anchor result")
	}
	if err := fiscobcos.ValidateProofAgainstTrustConfig(attempt.Target, result, trust); err != nil {
		t.Fatalf("validate live BCOS anchor proof: %v", err)
	}
	rawBCOSProof, err := fiscobcos.UnmarshalProof(result.Proof)
	if err != nil {
		t.Fatal(err)
	}

	fixture.proof.AnchorResult = &result
	fixture.proof.ProofLevel = Level(fixture.proof).String()
	proofPath := filepath.Join(outputDir, "portable.sproof")
	contentPath := filepath.Join(outputDir, "content.bin")
	trustPath := filepath.Join(outputDir, "trust-roots.json")
	if err := WriteFile(proofPath, fixture.proof); err != nil {
		t.Fatalf("write complete sproof: %v", err)
	}
	if err := os.WriteFile(contentPath, fixture.content, 0o600); err != nil {
		t.Fatal(err)
	}
	roots := qualificationformat.TrustRoots{
		Schema:           qualificationformat.TrustRootsSchema,
		CryptoSuite:      suiteID,
		ClientPublicKeys: append([]trustcrypto.PublicKeyDescriptor(nil), fixture.trust.Identity.ClientPublicKeys...),
		ServerPublicKeys: append([]trustcrypto.PublicKeyDescriptor(nil), fixture.trust.Identity.ServerPublicKeys...),
		FISCOBCOS:        trust,
		ExpectedRecordID: fixture.proof.RecordID,
	}
	writeQualificationJSON(t, trustPath, roots)

	store, err := proofstore.OpenLocalStore(
		filepath.Join(outputDir, "proofstore-source"),
		suiteID,
		attempt.Target.NodeID,
		attempt.Target.LogID,
		"bcos-four-node-qualification",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	for index := range fixture.bundles {
		if err := store.PutBundle(ctx, fixture.bundles[index]); err != nil {
			t.Fatalf("persist proof bundle: %v", err)
		}
	}
	// The logical backup only carries proof bundles that a committed batch
	// manifest references. Register the fixture batch so the backup covers
	// the bundles exactly as a committed production batch would.
	recordIDs := make([]string, len(fixture.bundles))
	for index := range fixture.bundles {
		recordIDs[index] = fixture.bundles[index].RecordID
	}
	if err := store.PutManifest(ctx, model.BatchManifest{
		SchemaVersion:    model.SchemaBatchManifest,
		CryptoSuite:      suiteID,
		BatchID:          fixture.batchRoot.BatchID,
		State:            model.BatchStateCommitted,
		TreeAlg:          fixture.batchRoot.TreeAlg(),
		TreeSize:         fixture.batchRoot.TreeSize,
		BatchRoot:        append([]byte(nil), fixture.batchRoot.BatchRoot...),
		RecordIDs:        recordIDs,
		ClosedAtUnixN:    fixture.batchRoot.ClosedAtUnixN,
		CommittedAtUnixN: fixture.batchRoot.ClosedAtUnixN,
	}); err != nil {
		t.Fatalf("persist committed batch manifest: %v", err)
	}
	if err := store.PutSignedTreeHead(ctx, attempt.Target); err != nil {
		t.Fatalf("persist signed tree head: %v", err)
	}
	if err := proofstore.STHAnchorResultWriter(store).PutSTHAnchorResult(ctx, result); err != nil {
		t.Fatalf("persist immutable anchor result: %v", err)
	}

	report := liveBCOSQualificationReport{
		Schema:                     "trustdb.fisco-bcos-live-qualification-report.v1",
		Mode:                       live.Mode,
		ProofPath:                  filepath.Base(proofPath),
		TrustRootsPath:             filepath.Base(trustPath),
		DurableReplayVerified:      true,
		ProviderFailureStage:       providerError,
		TransportFailureStage:      transportError,
		UnknownOutcomeInjected:     unknownOutcomeInjected.Load(),
		UnknownOutcomeRecovered:    unknownOutcomeCheckpointed,
		AnchorID:                   result.AnchorID,
		AnchorBlockNumber:          rawBCOSProof.Block.BlockNumber,
		ValidatorHistoryBlockCount: len(rawBCOSProof.ValidatorHistory),
	}
	backupPath := filepath.Join(outputDir, "proofstore.tdbackup")
	if suiteID == cryptosuite.INTLV1 {
		if _, err := backup.Create(ctx, store, backupPath, backup.Options{Compression: "gzip"}); err != nil {
			t.Fatalf("create logical backup: %v", err)
		}
		if _, err := backup.Verify(ctx, backupPath); err != nil {
			t.Fatalf("verify logical backup: %v", err)
		}
		restored, err := proofstore.OpenLocalStore(
			filepath.Join(outputDir, "proofstore-restored"),
			suiteID,
			attempt.Target.NodeID,
			attempt.Target.LogID,
			"bcos-four-node-qualification-restored",
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = restored.Close() })
		if _, err := backup.Restore(ctx, restored, backupPath); err != nil {
			t.Fatalf("restore logical backup: %v", err)
		}
		restoredResult, ok, err := restored.GetSTHAnchorResult(ctx, result.TreeSize)
		if err != nil || !ok {
			t.Fatalf("read restored anchor result: present=%v error=%v", ok, err)
		}
		originalBytes, _ := cborx.Marshal(result)
		restoredBytes, _ := cborx.Marshal(restoredResult)
		if !bytes.Equal(originalBytes, restoredBytes) {
			t.Fatal("logical restore changed immutable BCOS evidence")
		}
		if _, err := restored.GetBundle(ctx, fixture.proof.RecordID); err != nil {
			t.Fatalf("read restored proof bundle: %v", err)
		}
		report.BackupPath = filepath.Base(backupPath)
		report.BackupRestoreVerified = true
	} else {
		_, backupErr := backup.Create(ctx, store, backupPath, backup.Options{Compression: "gzip"})
		if backupErr == nil {
			t.Fatal("CN_SM_V1 unexpectedly wrote the legacy unauthenticated backup format")
		}
		report.StorageFailureStage = "backup_v5_unavailable"
		report.BackupFailClosedReason = backupErr.Error()
	}
	writeQualificationJSON(t, filepath.Join(outputDir, "live-qualification.json"), report)
}

func publishBCOSQualificationDurably(
	ctx context.Context,
	sink *anchor.FISCOBCOSStandardSink,
	attempt model.STHAnchorAttempt,
	checkpoint anchor.ProviderStateCheckpoint,
	providerState *[]byte,
) (model.STHAnchorResult, error) {
	deadline := time.NewTimer(2 * time.Minute)
	defer deadline.Stop()
	retry := time.NewTicker(250 * time.Millisecond)
	defer retry.Stop()

	var lastErr error
	incompleteEvidenceRetries := 0
	for {
		attempt.ProviderState = append(attempt.ProviderState[:0], (*providerState)...)
		result, err := sink.PublishDurable(ctx, attempt, checkpoint)
		if err == nil {
			return result, nil
		}
		if errors.Is(err, anchor.ErrPermanent) {
			return model.STHAnchorResult{}, err
		}
		if errors.Is(err, fiscobcos.ErrDriverInvalid) ||
			errors.Is(err, fiscobcos.ErrContractMismatch) ||
			errors.Is(err, fiscobcos.ErrWrongNetwork) ||
			errors.Is(err, fiscobcos.ErrUnsupportedSDK) {
			return model.STHAnchorResult{}, err
		}
		if errors.Is(err, fiscobcos.ErrIncompleteChainEvidence) {
			incompleteEvidenceRetries++
			if incompleteEvidenceRetries >= 20 {
				return model.STHAnchorResult{}, fmt.Errorf("BCOS evidence remained incomplete after bounded retries: %w", err)
			}
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return model.STHAnchorResult{}, errors.Join(lastErr, ctx.Err())
		case <-deadline.C:
			return model.STHAnchorResult{}, fmt.Errorf("durable BCOS publication did not converge: %w", lastErr)
		case <-retry.C:
		}
	}
}

func liveBCOSTrustConfig(
	t *testing.T,
	live liveBCOSClientEvidence,
	mode fiscobcos.CryptoMode,
	certDir string,
	accountKey string,
	rpcPort int,
) fiscobcos.TrustConfig {
	t.Helper()
	config, err := fiscobcos.NewTrustConfig(mode)
	if err != nil {
		t.Fatal(err)
	}
	params, err := fiscobcos.ParametersForMode(mode)
	if err != nil {
		t.Fatal(err)
	}
	genesisHash := qualificationHex(t, "genesis hash", live.GenesisHash, 32)
	config.ChainID = live.ChainID
	config.GroupID = "group0"
	config.GenesisHash = genesisHash
	if live.TrustedCheckpoint.BlockNumber == 0 {
		t.Fatal("live evidence trusted checkpoint must be a post-genesis block")
	}
	config.TrustedCheckpoint = fiscobcos.BlockCheckpoint{
		BlockNumber: live.TrustedCheckpoint.BlockNumber,
		BlockHash: qualificationHex(
			t,
			"trusted checkpoint hash",
			live.TrustedCheckpoint.BlockHash,
			32,
		),
	}
	config.Contract = fiscobcos.ContractBinding{
		Address:         qualificationHex(t, "contract address", live.Deployment.ContractAddress, 20),
		CodeHash:        qualificationHex(t, "deployed contract runtime code hash", live.ContractCodeHash, 32),
		ProtocolVersion: fiscobcos.TrustDBAnchorV1ProtocolVersion,
		EventSignature:  fiscobcos.TrustDBAnchorV1EventSignature,
	}
	config.Endpoints = make([]string, 4)
	for index := range config.Endpoints {
		config.Endpoints[index] = fmt.Sprintf("%s://127.0.0.1:%d", params.TransportMode, rpcPort+index)
	}
	config.ReadQuorum = 3
	config.AccountProvider = fiscobcos.AccountProviderConfig{
		Provider:     "software",
		KeyID:        "bcos-qualification-publisher",
		KeyReference: accountKey,
		Algorithm:    params.ChainSignatureAlgorithm,
	}
	caName := "ca.crt"
	config.Certificates.ClientSigningCertificateRef = filepath.Join(certDir, "sdk.crt")
	config.Certificates.ClientSigningKeyRef = filepath.Join(certDir, "sdk.key")
	if mode == fiscobcos.CryptoModeGuomi {
		caName = "sm_ca.crt"
		config.Certificates.ClientSigningCertificateRef = filepath.Join(certDir, "sm_sdk.crt")
		config.Certificates.ClientSigningKeyRef = filepath.Join(certDir, "sm_sdk.key")
		config.Certificates.ClientEncryptionCertificateRef = filepath.Join(certDir, "sm_ensdk.crt")
		config.Certificates.ClientEncryptionKeyRef = filepath.Join(certDir, "sm_ensdk.key")
	}
	caPath := filepath.Join(certDir, caName)
	config.Certificates.TrustedCAReferences = []string{caPath}
	config.Certificates.TrustedCACertificateHashes = [][]byte{qualificationCertificateHash(t, mode, caPath)}
	config.ValidatorTransitionPolicy = fiscobcos.ValidatorPolicyTransitions
	if len(live.Sealers) != 4 {
		t.Fatalf("live evidence has %d sealers, want 4", len(live.Sealers))
	}
	config.Validators = make([]fiscobcos.ValidatorDescriptor, len(live.Sealers))
	for index, sealer := range live.Sealers {
		publicKey := qualificationHex(t, fmt.Sprintf("validator %d", index), sealer.NodeID, 64)
		publicKey = append([]byte{4}, publicKey...)
		config.Validators[index] = fiscobcos.ValidatorDescriptor{
			NodeID:            "0x" + strings.ToLower(strings.TrimPrefix(sealer.NodeID, "0x")),
			Algorithm:         params.ChainSignatureAlgorithm,
			PublicKeyEncoding: params.PublicKeyEncoding,
			PublicKey:         publicKey,
			VoteWeight:        sealer.Weight,
		}
	}
	canonical, err := fiscobcos.MarshalTrustConfig(config)
	if err != nil {
		t.Fatalf("validate live trust config: %v", err)
	}
	config, err = fiscobcos.UnmarshalTrustConfig(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func qualificationModeAndSuite(t *testing.T, value string) (fiscobcos.CryptoMode, cryptosuite.ID) {
	t.Helper()
	switch value {
	case "standard":
		return fiscobcos.CryptoModeStandard, cryptosuite.INTLV1
	case "guomi":
		return fiscobcos.CryptoModeGuomi, cryptosuite.CNSMV1
	default:
		t.Fatalf("unsupported live BCOS mode %q", value)
		return "", ""
	}
}

func qualificationCertificateHash(t *testing.T, mode fiscobcos.CryptoMode, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode == fiscobcos.CryptoModeGuomi {
		digest := sm3.Sum(data)
		return digest[:]
	}
	digest := sha256.Sum256(data)
	return digest[:]
}

func qualificationHex(t *testing.T, name, value string, size int) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil || len(decoded) != size {
		t.Fatalf("%s has %d decoded bytes, want %d: %v", name, len(decoded), size, err)
	}
	return decoded
}

func requireQualificationFactoryFailure(
	t *testing.T,
	ctx context.Context,
	mutate func(*fiscobcos.TrustConfig),
	base fiscobcos.TrustConfig,
) string {
	t.Helper()
	encoded, err := fiscobcos.MarshalTrustConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	cloned, err := fiscobcos.UnmarshalTrustConfig(encoded)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&cloned)
	drivers, err := (standardsdk.NativeFactory{}).NewDrivers(ctx, standardsdk.Config{TrustConfig: cloned})
	for _, driver := range drivers {
		_ = driver.Close()
	}
	if err == nil {
		t.Fatal("mutated native BCOS configuration unexpectedly succeeded")
	}
	return err.Error()
}

func requiredQualificationEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func readQualificationJSON(t *testing.T, path string, destination any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func writeQualificationJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
