package sproof

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FISCO-BCOS/go-sdk/v3/types"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/wowtrust/trustdb/v2/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/v2/internal/app"
	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/internal/claim"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/globallog"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/proofstore"
	"github.com/wowtrust/trustdb/v2/internal/receipt"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
	"github.com/wowtrust/trustdb/v2/internal/verify"
	"github.com/wowtrust/trustdb/v2/internal/wal"
)

func TestOfflineV2EndToEndAcrossSuitesAndTampering(t *testing.T) {
	t.Parallel()

	for _, suiteID := range []cryptosuite.ID{cryptosuite.INTLV1, cryptosuite.CNSMV1} {
		suiteID := suiteID
		t.Run(string(suiteID), func(t *testing.T) {
			t.Parallel()

			fixture := newOfflineE2EFixture(t, suiteID)
			result, err := VerifyOffline(
				bytes.NewReader(fixture.content),
				fixture.proof,
				fixture.trust,
				OfflineOptions{},
			)
			if err != nil {
				t.Fatalf("VerifyOffline() error = %v", err)
			}
			if !result.Valid || result.ProofLevel != "L4" ||
				result.ExternalNetworkAccess || result.ExternalProviderAccess {
				t.Fatalf("VerifyOffline() result = %+v", result)
			}
			if result.Identity.EvidenceCount != 4 ||
				result.Identity.PublicKeyBindingsVerified != 4 {
				t.Fatalf("VerifyOffline() identity report = %+v", result.Identity)
			}
			for _, stage := range result.Stages {
				if stage.Status == OfflineStageFailed {
					t.Fatalf("VerifyOffline() stage = %+v, no carried stage may fail", stage)
				}
			}

			path := filepath.Join(t.TempDir(), "portable.sproof")
			if err := WriteFile(path, fixture.proof); err != nil {
				t.Fatal(err)
			}
			loaded, err := ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			equal, err := EqualEncoded(fixture.proof, loaded)
			if err != nil || !equal {
				t.Fatalf("EqualEncoded() = %v, %v", equal, err)
			}

			t.Run("content", func(t *testing.T) {
				tamperedContent := append([]byte(nil), fixture.content...)
				tamperedContent[0] ^= 1
				assertOfflineFailureStage(
					t,
					tamperedContent,
					fixture.proof,
					fixture.trust,
					verify.StageContent,
				)
			})

			t.Run("batch path", func(t *testing.T) {
				tampered := cloneOfflineProof(t, fixture.proof)
				if len(tampered.ProofBundle.BatchProof.AuditPath) == 0 {
					t.Fatal("fixture batch proof has no audit path")
				}
				tampered.ProofBundle.BatchProof.AuditPath[0][0] ^= 1
				assertOfflineFailureStage(
					t,
					fixture.content,
					tampered,
					fixture.trust,
					verify.StageBatchMerkle,
				)
			})

			t.Run("global path", func(t *testing.T) {
				tampered := cloneOfflineProof(t, fixture.proof)
				tampered.GlobalProof.InclusionPath = append(
					tampered.GlobalProof.InclusionPath,
					bytes.Repeat([]byte{0x5a}, cryptosuite.DigestSize),
				)
				assertOfflineFailureStage(
					t,
					fixture.content,
					tampered,
					fixture.trust,
					verify.StageGlobalLog,
				)
			})

			t.Run("global namespace", func(t *testing.T) {
				tampered := cloneOfflineProof(t, fixture.proof)
				tampered.GlobalProof.NodeID = ""
				assertOfflineFailureStage(
					t,
					fixture.content,
					tampered,
					fixture.trust,
					verify.StageGlobalLog,
				)
			})

			t.Run("suite", func(t *testing.T) {
				tampered := cloneOfflineProof(t, fixture.proof)
				if suiteID == cryptosuite.CNSMV1 {
					tampered.CryptoSuite = cryptosuite.INTLV1
				} else {
					tampered.CryptoSuite = cryptosuite.CNSMV1
				}
				assertOfflineContainerFailure(t, fixture.content, tampered, fixture.trust, "crypto")
			})

			t.Run("client signature", func(t *testing.T) {
				tampered := cloneOfflineProof(t, fixture.proof)
				tampered.ProofBundle.SignedClaim.Signature.Signature[0] ^= 1
				assertOfflineFailureStage(
					t,
					fixture.content,
					tampered,
					fixture.trust,
					verify.StageClientClaim,
				)
			})

			t.Run("STH", func(t *testing.T) {
				tampered := cloneOfflineProof(t, fixture.proof)
				tampered.GlobalProof.STH.RootHash[0] ^= 1
				assertOfflineFailureStage(
					t,
					fixture.content,
					tampered,
					fixture.trust,
					verify.StageGlobalLog,
				)
			})

			if suiteID == cryptosuite.CNSMV1 {
				t.Run("SM2 user ID", func(t *testing.T) {
					tampered := cloneOfflineProof(t, fixture.proof)
					descriptor, err := keydescriptor.Unmarshal(tampered.IdentityEvidence[0].KeyDescriptor)
					if err != nil {
						t.Fatal(err)
					}
					descriptor.SM2UserID = "different-sm2-user-id"
					tampered.IdentityEvidence[0].KeyDescriptor, err = cborx.Marshal(descriptor)
					if err != nil {
						t.Fatal(err)
					}
					result, verifyErr := VerifyOffline(
						bytes.NewReader(fixture.content),
						tampered,
						fixture.trust,
						OfflineOptions{},
					)
					if verifyErr == nil || !strings.Contains(verifyErr.Error(), "sm2_user_id") {
						t.Fatalf("VerifyOffline() error = %v, want sm2_user_id", verifyErr)
					}
					assertOfflineStage(t, result, OfflineStageIdentity, OfflineStageFailed)
				})
			}
		})
	}
}

func TestOfflineRawBCOSStagesRequireTrustAndReachL5(t *testing.T) {
	t.Parallel()

	fixture := newOfflineE2EFixture(t, cryptosuite.INTLV1)
	bcosTrust := attachStructuralRawBCOSEvidence(t, &fixture.proof)
	if got := Level(fixture.proof).String(); got != "L4" {
		t.Fatalf("Level(raw BCOS evidence) = %s, want L4", got)
	}
	fixture.proof.ProofLevel = "L4"

	result, err := VerifyOffline(
		bytes.NewReader(fixture.content),
		fixture.proof,
		fixture.trust,
		OfflineOptions{},
	)
	if err == nil || !strings.Contains(err.Error(), "verifier-local FISCO BCOS trust config") {
		t.Fatalf("VerifyOffline() error = %v", err)
	}
	if result.Valid || result.ProofLevel != "L4" {
		t.Fatalf("VerifyOffline() result = %+v", result)
	}
	assertOfflineStage(t, result, string(verify.StageAnchor), OfflineStageNotPresent)
	assertOfflineStage(t, result, OfflineStageBCOSReceiptInclusion, OfflineStageFailed)
	assertOfflineStage(t, result, OfflineStageBCOSPBFTFinality, OfflineStageNotRun)
	assertOfflineStage(t, result, OfflineStageBCOSAnchorBinding, OfflineStageNotRun)

	result, err = VerifyOffline(
		bytes.NewReader(fixture.content),
		fixture.proof,
		fixture.trust,
		OfflineOptions{SkipAnchor: true},
	)
	if err != nil || !result.Valid || result.ProofLevel != "L4" {
		t.Fatalf("VerifyOffline(skip BCOS) result=%+v error=%v", result, err)
	}
	assertOfflineStage(t, result, string(verify.StageAnchor), OfflineStageNotPresent)
	assertOfflineStage(t, result, OfflineStageBCOSReceiptInclusion, OfflineStageSkipped)
	assertOfflineStage(t, result, OfflineStageBCOSPBFTFinality, OfflineStageSkipped)
	assertOfflineStage(t, result, OfflineStageBCOSAnchorBinding, OfflineStageSkipped)

	fixture.trust.FISCOBCOS = &bcosTrust
	result, err = VerifyOffline(
		bytes.NewReader(fixture.content),
		fixture.proof,
		fixture.trust,
		OfflineOptions{},
	)
	if err != nil || !result.Valid || result.ProofLevel != "L5" {
		t.Fatalf("VerifyOffline(static PBFT) result=%+v error=%v", result, err)
	}
	if result.ExternalNetworkAccess || result.ExternalProviderAccess {
		t.Fatalf("VerifyOffline(static PBFT) used external access: %+v", result)
	}
	assertOfflineStage(t, result, OfflineStageBCOSReceiptInclusion, OfflineStagePassed)
	assertOfflineStage(t, result, OfflineStageBCOSPBFTFinality, OfflineStagePassed)
	assertOfflineStage(t, result, OfflineStageBCOSAnchorBinding, OfflineStagePassed)
}

func attachStructuralRawBCOSEvidence(
	t *testing.T,
	proof *model.SingleProof,
) fiscobcos.TrustConfig {
	t.Helper()
	config, err := fiscobcos.NewTrustConfig(fiscobcos.CryptoModeStandard)
	if err != nil {
		t.Fatal(err)
	}
	config.ChainID = "chain0"
	config.GroupID = "group0"
	config.GenesisHash = bytes.Repeat([]byte{0x01}, 32)
	config.TrustedCheckpoint = fiscobcos.BlockCheckpoint{
		BlockNumber: 1,
		BlockHash:   bytes.Repeat([]byte{0x02}, 32),
	}
	config.Contract = fiscobcos.ContractBinding{
		Address:         bytes.Repeat([]byte{0x03}, 20),
		CodeHash:        bytes.Repeat([]byte{0x04}, 32),
		ProtocolVersion: fiscobcos.TrustDBAnchorV1ProtocolVersion,
		EventSignature:  fiscobcos.TrustDBAnchorV1EventSignature,
	}
	config.Endpoints = []string{"127.0.0.1:20200"}
	config.ReadQuorum = 1
	config.AccountProvider = fiscobcos.AccountProviderConfig{
		Provider:     "test",
		KeyID:        "publisher",
		KeyReference: "missing/publisher",
		Algorithm:    fiscobcos.StandardAccountAlg,
	}
	config.Certificates = fiscobcos.CertificateConfig{
		TransportMode:               fiscobcos.StandardTransport,
		TrustedCAReferences:         []string{"missing/root.pem"},
		TrustedCACertificateHashes:  [][]byte{bytes.Repeat([]byte{0x05}, 32)},
		ClientSigningCertificateRef: "missing/client.pem",
		ClientSigningKeyRef:         "missing/client.key",
	}
	validatorPrivate, err := ethcrypto.ToECDSA(bytes.Repeat([]byte{0x02}, 32))
	if err != nil {
		t.Fatal(err)
	}
	validatorKey := ethcrypto.FromECDSAPub(&validatorPrivate.PublicKey)
	validatorNodeID := "0x" + hex.EncodeToString(validatorKey[1:])
	config.Validators = []fiscobcos.ValidatorDescriptor{{
		NodeID:            validatorNodeID,
		Algorithm:         fiscobcos.StandardAccountAlg,
		PublicKeyEncoding: fiscobcos.StandardKeyEncoding,
		PublicKey:         validatorKey,
		VoteWeight:        1,
	}}
	payload, err := fiscobcos.NewAnchorPayload(proof.CryptoSuite, proof.GlobalProof.STH)
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes, err := fiscobcos.MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	callData, err := fiscobcos.PublishCallData(payload)
	if err != nil {
		t.Fatal(err)
	}

	to := common.BytesToAddress(config.Contract.Address)
	transaction := types.NewSimpleTx(&to, callData, "", "offline-bcos", "", false)
	transaction.Data.Version = 0
	transaction.Data.ChainID = config.ChainID
	transaction.Data.GroupID = config.GroupID
	transaction.Data.BlockLimit = 100
	txHash := transaction.Hash().Bytes()
	publisherPrivate, err := ethcrypto.ToECDSA(bytes.Repeat([]byte{0x01}, 32))
	if err != nil {
		t.Fatal(err)
	}
	transactionSignature, err := ethcrypto.Sign(txHash, publisherPrivate)
	if err != nil {
		t.Fatal(err)
	}
	publisher := ethcrypto.PubkeyToAddress(publisherPrivate.PublicKey).Bytes()
	transaction.Signature = transactionSignature
	senderAddress := common.BytesToAddress(publisher)
	transaction.Sender = &senderAddress
	rawTransaction := transaction.Bytes()

	eventTopic, err := fiscobcos.EventTopicForMode(
		fiscobcos.CryptoModeStandard,
		config.Contract.EventSignature,
	)
	if err != nil {
		t.Fatal(err)
	}
	publisherTopic := make([]byte, 32)
	copy(publisherTopic[12:], publisher)
	eventData := make([]byte, 4*32)
	binary.BigEndian.PutUint64(eventData[24:32], payload.TreeSize)
	copy(eventData[32:64], payload.RootHash)
	copy(eventData[64:96], payload.SignedSTHDigest)
	binary.BigEndian.PutUint16(eventData[126:128], payload.Version)
	decodedEvent, err := fiscobcos.MarshalNativeAnchorEvent(fiscobcos.AnchorPublishedEvent{
		ContractAddress: config.Contract.Address,
		AnchorID:        payload.AnchorID,
		StreamID:        payload.StreamID,
		TreeSize:        payload.TreeSize,
		RootHash:        payload.RootHash,
		SignedSTHDigest: payload.SignedSTHDigest,
		Publisher:       publisher,
		PayloadVersion:  payload.Version,
		LogIndex:        0,
	})
	if err != nil {
		t.Fatal(err)
	}
	receiptFields := fiscobcos.NativeReceiptFields{
		Version: 0, GasUsed: "21000", Status: fiscobcos.ReceiptStatusOK,
		Logs: []fiscobcos.NativeLogFields{{
			Address: hex.EncodeToString(config.Contract.Address),
			Topics:  [][]byte{eventTopic, payload.AnchorID, payload.StreamID, publisherTopic},
			Data:    eventData,
		}},
		BlockNumber: 2,
	}
	rawReceipt, logs, err := fiscobcos.MarshalNativeReceiptPreimage(receiptFields)
	if err != nil {
		t.Fatal(err)
	}
	receiptHash, err := fiscobcos.HashNativeEvidence(fiscobcos.HashKeccak256, rawReceipt)
	if err != nil {
		t.Fatal(err)
	}
	blockFields := fiscobcos.NativeBlockHeaderFields{
		Version:          0,
		ParentInfo:       []fiscobcos.NativeParentInfo{{BlockNumber: 1, BlockHash: bytes.Repeat([]byte{0x13}, 32)}},
		TransactionsRoot: append([]byte(nil), txHash...),
		ReceiptsRoot:     append([]byte(nil), receiptHash...),
		StateRoot:        bytes.Repeat([]byte{0x16}, 32),
		BlockNumber:      2,
		GasUsed:          "21000",
		Timestamp:        1,
		SealerList:       [][]byte{append([]byte(nil), validatorKey[1:]...)},
		ConsensusWeights: []int64{1},
	}
	rawHeader, err := fiscobcos.MarshalNativeBlockHeaderPreimage(blockFields)
	if err != nil {
		t.Fatal(err)
	}
	blockHash, err := fiscobcos.HashNativeEvidence(fiscobcos.HashKeccak256, rawHeader)
	if err != nil {
		t.Fatal(err)
	}
	finalitySignature, err := ethcrypto.Sign(blockHash, validatorPrivate)
	if err != nil {
		t.Fatal(err)
	}
	contextID, err := fiscobcos.ChainContextID(config)
	if err != nil {
		t.Fatal(err)
	}
	bcosProof := fiscobcos.AnchorProof{
		SchemaVersion:             fiscobcos.SchemaAnchorProof,
		FormatVersion:             fiscobcos.ProofVersion,
		CryptoMode:                fiscobcos.CryptoModeStandard,
		ProtocolHashAlgorithm:     "sha256",
		ChainHashAlgorithm:        fiscobcos.HashKeccak256,
		ChainSignatureAlgorithm:   fiscobcos.StandardAccountAlg,
		ChainID:                   config.ChainID,
		GroupID:                   config.GroupID,
		GenesisHash:               config.GenesisHash,
		TrustedCheckpoint:         config.TrustedCheckpoint,
		Contract:                  config.Contract,
		ChainContextID:            contextID,
		CanonicalPayload:          payloadBytes,
		SuccessfulAttemptOrdinal:  1,
		SuccessfulTransactionHash: txHash,
		TransactionAttempts: []fiscobcos.TransactionAttempt{{
			Ordinal: 1, RawCanonicalTransaction: rawTransaction,
			ChainID: config.ChainID, GroupID: config.GroupID,
			To: config.Contract.Address, Input: callData,
			Signature: transactionSignature,
			Sender:    publisher, TransactionHash: txHash,
			BlockLimit: 100, SubmittedAtUnixN: 1,
			Outcome: fiscobcos.AttemptOutcomeReceiptSuccess,
		}},
		Receipt: fiscobcos.ReceiptEvidence{
			Fields: receiptFields, RawCanonicalReceipt: rawReceipt,
			Status: fiscobcos.ReceiptStatusOK, StatusMessage: "success",
			CanonicalLogs: logs, ReceiptHash: receiptHash, TransactionHash: txHash,
			TransactionProof:   [][]byte{append([]byte(nil), txHash...)},
			ReceiptProof:       [][]byte{append([]byte(nil), receiptHash...)},
			DecodedAnchorEvent: decodedEvent,
		},
		Block: fiscobcos.BlockEvidence{
			Fields: blockFields, RawCanonicalHeader: rawHeader,
			BlockHash: blockHash, BlockNumber: 2,
		},
		Finality: fiscobcos.FinalityEvidence{Signatures: []fiscobcos.CommitSignature{{
			ValidatorNodeID: validatorNodeID, Signature: finalitySignature,
		}}},
	}
	encodedProof, err := fiscobcos.MarshalProof(bcosProof)
	if err != nil {
		t.Fatal(err)
	}
	proof.AnchorResult = &model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		CryptoSuite:      proof.CryptoSuite,
		EvidenceStage:    model.AnchorEvidenceStageRaw,
		NodeID:           proof.NodeID,
		LogID:            proof.LogID,
		TreeSize:         proof.GlobalProof.STH.TreeSize,
		SinkName:         fiscobcos.SinkName,
		AnchorID:         fiscobcos.AnchorIDString(payload),
		RootHash:         append([]byte(nil), proof.GlobalProof.STH.RootHash...),
		STH:              proof.GlobalProof.STH,
		Proof:            encodedProof,
		PublishedAtUnixN: 1,
	}
	return config
}

type offlineE2EFixture struct {
	content   []byte
	proof     model.SingleProof
	trust     OfflineTrust
	batchRoot model.BatchRoot
	bundles   []model.ProofBundle
}

func newOfflineE2EFixture(t *testing.T, suiteID cryptosuite.ID) offlineE2EFixture {
	t.Helper()

	ctx := context.Background()
	provider, err := trustcrypto.ProviderForSuite(suiteID)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, clientPublic := offlineE2EKey(t, suiteID, "client-key")
	acceptedSigner, acceptedPublic := offlineE2EKey(t, suiteID, "server-accepted")
	committedSigner, committedPublic := offlineE2EKey(t, suiteID, "server-committed")
	sthSigner, sthPublic := offlineE2EKey(t, suiteID, "server-sth")
	suite, err := cryptosuite.RequireAvailable(suiteID)
	if err != nil {
		t.Fatal(err)
	}
	contents := [][]byte{
		[]byte("portable TrustDB national cryptography evidence"),
		[]byte("second record creates a non-empty batch audit path"),
	}
	signedClaims := make([]model.SignedClaim, len(contents))
	for index := range contents {
		contentHash, err := trustcrypto.HashBytesWithProvider(
			provider,
			suite.ContentHash.Algorithm,
			contents[index],
		)
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := claim.NewFileClaimForSuite(
			suiteID,
			"tenant-offline",
			"client-offline",
			"client-key",
			time.Unix(100+int64(index), 0),
			bytes.Repeat([]byte{byte(index + 1)}, 16),
			fmt.Sprintf("offline-%d", index),
			model.Content{
				HashAlg:       suite.ContentHash.Algorithm,
				ContentHash:   contentHash,
				ContentLength: int64(len(contents[index])),
			},
			model.Metadata{EventType: "offline.evidence"},
		)
		if err != nil {
			t.Fatal(err)
		}
		signedClaims[index], err = claim.SignWithProvider(ctx, provider, unsigned, clientSigner)
		if err != nil {
			t.Fatal(err)
		}
	}

	walPath := filepath.Join(t.TempDir(), "records.wal")
	writer, err := wal.OpenWriterWithOptions(walPath, 1, wal.Options{
		CryptoSuite: suiteID,
		NodeID:      "node-offline",
		LogID:       "log-offline",
		NamespaceID: "wal:" + walPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	engine := app.LocalEngine{
		ServerID:        "node-offline",
		LogID:           "log-offline",
		ServerKeyID:     "server-accepted",
		ClientPublicKey: clientPublic,
		ServerSigner:    acceptedSigner,
		CryptoProvider:  provider,
		WAL:             writer,
		Now:             func() time.Time { return time.Unix(200, 0) },
	}
	records := make([]model.ServerRecord, len(signedClaims))
	accepted := make([]model.AcceptedReceipt, len(signedClaims))
	for index := range signedClaims {
		records[index], accepted[index], _, err = engine.Submit(ctx, signedClaims[index])
		if err != nil {
			t.Fatal(err)
		}
	}
	commit, err := engine.ComputeBatch(
		ctx,
		"batch-offline",
		time.Unix(300, 0),
		signedClaims,
		records,
		accepted,
		model.BatchComputeOptions{Mode: model.BatchComputeMaterialized},
	)
	if err != nil {
		t.Fatal(err)
	}
	for index := range commit.Bundles {
		commit.Bundles[index].CommittedReceipt, err = receipt.SignCommittedWithProvider(
			ctx,
			provider,
			commit.Bundles[index].CommittedReceipt,
			committedSigner,
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	store, err := proofstore.OpenLocalStore(
		t.TempDir(),
		suiteID,
		"node-offline",
		"log-offline",
		"offline-e2e",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	global, err := globallog.New(globallog.Options{
		Store:          store,
		NodeID:         "node-offline",
		LogID:          "log-offline",
		Signer:         sthSigner,
		CryptoProvider: provider,
		Clock:          func() time.Time { return time.Unix(400, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	sth, err := global.AppendBatchRoot(ctx, commit.Root)
	if err != nil {
		t.Fatal(err)
	}
	globalProof, err := global.InclusionProof(ctx, commit.Root.BatchID, sth.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	identityEvidence := []model.ProofIdentityEvidence{
		offlineE2EIdentity(t, suiteID, model.ProofIdentityRoleClient, clientPublic),
		offlineE2EIdentity(t, suiteID, model.ProofIdentityRoleServer, acceptedPublic),
		offlineE2EIdentity(t, suiteID, model.ProofIdentityRoleServer, committedPublic),
		offlineE2EIdentity(t, suiteID, model.ProofIdentityRoleServer, sthPublic),
	}
	proof, err := New(commit.Bundles[0], Options{
		GlobalProof:      &globalProof,
		IdentityEvidence: identityEvidence,
		ExportedAtUnixN:  time.Unix(500, 0).UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return offlineE2EFixture{
		content:   contents[0],
		proof:     proof,
		batchRoot: commit.Root,
		bundles:   append([]model.ProofBundle(nil), commit.Bundles...),
		trust: OfflineTrust{
			Proof: verify.TrustedKeys{
				ClientPublicKey: clientPublic,
				ServerPublicKey: acceptedPublic,
				CryptoProvider:  provider,
			},
			Identity: IdentityTrust{
				ClientPublicKeys: []trustcrypto.PublicKeyDescriptor{clientPublic},
				ServerPublicKeys: []trustcrypto.PublicKeyDescriptor{
					acceptedPublic,
					committedPublic,
					sthPublic,
				},
				RequireEvidence: true,
			},
		},
	}
}

func offlineE2EKey(
	t *testing.T,
	suiteID cryptosuite.ID,
	keyID string,
) (trustcrypto.Signer, trustcrypto.PublicKeyDescriptor) {
	t.Helper()

	switch suiteID {
	case cryptosuite.INTLV1:
		publicKey, privateKey, err := trustcrypto.GenerateEd25519Key()
		if err != nil {
			t.Fatal(err)
		}
		signer, err := trustcrypto.NewEd25519Signer(keyID, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := trustcrypto.NewEd25519PublicKey(keyID, publicKey)
		if err != nil {
			t.Fatal(err)
		}
		return signer, descriptor
	case cryptosuite.CNSMV1:
		publicKey, privateKey, err := trustcrypto.GenerateSM2Key()
		if err != nil {
			t.Fatal(err)
		}
		signer, err := trustcrypto.NewSM2Signer(keyID, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := trustcrypto.NewSM2PublicKey(keyID, publicKey)
		if err != nil {
			t.Fatal(err)
		}
		return signer, descriptor
	default:
		t.Fatalf("unsupported suite %s", suiteID)
		return nil, trustcrypto.PublicKeyDescriptor{}
	}
}

func offlineE2EIdentity(
	t *testing.T,
	suiteID cryptosuite.ID,
	role string,
	publicKey trustcrypto.PublicKeyDescriptor,
) model.ProofIdentityEvidence {
	t.Helper()

	descriptor := keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindVerifier,
		Provider:      keydescriptor.ProviderPublic,
		CryptoSuite:   suiteID,
		KeyID:         publicKey.KeyID,
		Algorithm:     publicKey.Algorithm,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: publicKey.Encoding,
			Bytes:    append([]byte(nil), publicKey.Bytes...),
		},
	}
	if suiteID == cryptosuite.CNSMV1 {
		descriptor.SM2UserID = cryptosuite.SM2DefaultUserID
	}
	encoded, err := keydescriptor.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	return model.ProofIdentityEvidence{
		SchemaVersion: model.SchemaProofIdentity,
		CryptoSuite:   suiteID,
		Role:          role,
		KeyID:         publicKey.KeyID,
		KeyDescriptor: encoded,
	}
}

func cloneOfflineProof(t *testing.T, proof model.SingleProof) model.SingleProof {
	t.Helper()
	encoded, err := Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	cloned, err := Unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return cloned
}

func assertOfflineFailureStage(
	t *testing.T,
	content []byte,
	proof model.SingleProof,
	trust OfflineTrust,
	want verify.Stage,
) {
	t.Helper()
	result, err := VerifyOffline(bytes.NewReader(content), proof, trust, OfflineOptions{})
	if err == nil {
		t.Fatalf("VerifyOffline() error = nil, want stage %s", want)
	}
	assertOfflineStage(t, result, string(want), OfflineStageFailed)
}

func assertOfflineContainerFailure(
	t *testing.T,
	content []byte,
	proof model.SingleProof,
	trust OfflineTrust,
	wantError string,
) {
	t.Helper()
	result, err := VerifyOffline(bytes.NewReader(content), proof, trust, OfflineOptions{})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(wantError)) {
		t.Fatalf("VerifyOffline() error = %v, want %q", err, wantError)
	}
	assertOfflineStage(t, result, OfflineStageContainer, OfflineStageFailed)
}
