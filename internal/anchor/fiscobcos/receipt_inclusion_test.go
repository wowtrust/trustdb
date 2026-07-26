package fiscobcos

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/FISCO-BCOS/go-sdk/v3/smcrypto"
	"github.com/FISCO-BCOS/go-sdk/v3/types"
	"github.com/TarsCloud/TarsGo/tars/protocol/codec"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/model"
)

func TestVerifyReceiptInclusionStandardAndGuomiOffline(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		mode  CryptoMode
		suite cryptosuite.ID
	}{
		// Deliberately cross the BCOS and TrustDB suites: the BCOS chain mode
		// must never select or constrain the TrustDB proof suite.
		{name: "standard_chain_cn_sm_trustdb", mode: CryptoModeStandard, suite: cryptosuite.CNSMV1},
		{name: "guomi_chain_intl_trustdb", mode: CryptoModeGuomi, suite: cryptosuite.INTLV1},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sth, result, trust := validReceiptInclusionFixture(t, tc.mode, tc.suite)
			// These local references and endpoints intentionally do not exist.
			// Inclusion verification must compare their committed config only;
			// it must not perform DNS, network, provider, CA, or file access.
			trust.Endpoints = []string{"203.0.113.1:65535"}
			trust.ReadQuorum = 1
			trust.AccountProvider.KeyReference = "missing/provider/key"
			trust.Certificates.TrustedCAReferences = []string{"missing/root.pem"}
			trust.Certificates.ClientSigningCertificateRef = "missing/client.pem"
			trust.Certificates.ClientSigningKeyRef = "missing/client.key"
			if tc.mode == CryptoModeGuomi {
				trust.Certificates.ClientEncryptionCertificateRef = "missing/client-encryption.pem"
				trust.Certificates.ClientEncryptionKeyRef = "missing/client-encryption.key"
			}
			// References/endpoints are excluded from ChainContextID, so changing
			// them after capture is a supported local operational rotation.
			if err := VerifyReceiptInclusion(sth, result, trust); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVerifyReceiptInclusionRejectsMutationAndWrongMode(t *testing.T) {
	t.Parallel()

	sth, result, trust := validReceiptInclusionFixture(t, CryptoModeStandard, cryptosuite.INTLV1)
	proof, err := UnmarshalProof(result.Proof)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(*AnchorProof)
	}{
		{name: "transaction_bytes", mutate: func(p *AnchorProof) {
			last := len(p.TransactionAttempts[0].RawCanonicalTransaction) - 1
			p.TransactionAttempts[0].RawCanonicalTransaction[last] ^= 1
		}},
		{name: "transaction_sender", mutate: func(p *AnchorProof) { p.TransactionAttempts[0].Sender[0] ^= 1 }},
		{name: "receipt_status_message", mutate: func(p *AnchorProof) { p.Receipt.StatusMessage = "status_0" }},
		{name: "transaction_index", mutate: func(p *AnchorProof) { p.Receipt.TransactionIndex = 1 }},
		{name: "receipt_index", mutate: func(p *AnchorProof) { p.Receipt.ReceiptIndex = 1 }},
		{name: "transaction_path", mutate: func(p *AnchorProof) { p.Receipt.TransactionProof[0][0] ^= 1 }},
		{name: "receipt_path", mutate: func(p *AnchorProof) { p.Receipt.ReceiptProof[0][0] ^= 1 }},
		{name: "event_publisher", mutate: func(p *AnchorProof) { p.Receipt.Fields.Logs[0].Topics[3][31] ^= 1 }},
		{name: "event_root", mutate: func(p *AnchorProof) { p.Receipt.Fields.Logs[0].Data[32] ^= 1 }},
		{name: "anchor_log_index", mutate: func(p *AnchorProof) { p.Receipt.AnchorLogIndex = 1 }},
	}
	for _, tc := range mutations {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			candidate := cloneAnchorProofForMutation(t, proof)
			tc.mutate(&candidate)
			encoded, marshalErr := MarshalProof(candidate)
			if marshalErr == nil {
				mutatedResult := result
				mutatedResult.Proof = encoded
				if verifyErr := VerifyReceiptInclusion(sth, mutatedResult, trust); verifyErr == nil {
					t.Fatal("mutated evidence verified")
				}
			}
			// A mutation rejected by the strict proof container is also a
			// fail-closed result and needs no inclusion-stage execution.
		})
	}

	wrongMode := testTrustConfig(t, CryptoModeGuomi)
	wrongMode.ChainID = trust.ChainID
	wrongMode.GroupID = trust.GroupID
	wrongMode.GenesisHash = append([]byte(nil), trust.GenesisHash...)
	wrongMode.TrustedCheckpoint = trust.TrustedCheckpoint
	wrongMode.Contract = trust.Contract
	if err := VerifyReceiptInclusion(sth, result, wrongMode); err == nil {
		t.Fatal("standard evidence verified under local Guomi mode")
	}
	wrongContract := cloneTrustConfig(trust)
	wrongContract.Contract.Address[0] ^= 1
	if err := VerifyReceiptInclusion(sth, result, wrongContract); err == nil {
		t.Fatal("evidence verified under the wrong local contract")
	}

	notRaw := result
	notRaw.EvidenceStage = model.AnchorEvidenceStageOfflineVerified
	if err := VerifyReceiptInclusion(sth, notRaw, trust); err == nil {
		t.Fatal("receipt inclusion accepted a non-raw evidence stage")
	}
	driftedSTH := result
	driftedSTH.STH.CryptoSuite = cryptosuite.CNSMV1
	if err := VerifyReceiptInclusion(sth, driftedSTH, trust); err == nil {
		t.Fatal("receipt inclusion accepted a non-exact signed STH crypto suite")
	}
}

func TestBCOSMerkleProofStrictEncodingAndIndex(t *testing.T) {
	t.Parallel()

	left := bytes.Repeat([]byte{0x11}, 32)
	right := bytes.Repeat([]byte{0x22}, 32)
	preimage := append(append([]byte(nil), left...), right...)
	root, err := HashNativeEvidence(HashKeccak256, preimage)
	if err != nil {
		t.Fatal(err)
	}
	path := [][]byte{uint32Node(2), left, right}
	if err := verifyBCOSMerklePath("transaction", right, path, 1, root, HashKeccak256); err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][][]byte{
		"missing_count":       {left, right},
		"wide_group":          {uint32Node(3), left, right, left},
		"truncated_group":     {uint32Node(2), left},
		"trailing_count":      {uint32Node(2), left, right, uint32Node(1)},
		"duplicate_current":   {uint32Node(2), right, right},
		"noncanonical_count":  {{0, 2}, left, right},
		"noncanonical_digest": {uint32Node(2), left[:31], right},
	} {
		if err := verifyBCOSMerklePath("transaction", right, candidate, 1, root, HashKeccak256); err == nil {
			t.Fatalf("%s proof verified", name)
		}
	}
	if err := verifyBCOSMerklePath("transaction", right, path, 0, root, HashKeccak256); err == nil {
		t.Fatal("proof verified with the wrong transaction index")
	}
}

func TestBCOSReceiptInclusionFormatDerivedVectors(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"fisco-bcos-receipt-inclusion-standard-v1.json",
		"fisco-bcos-receipt-inclusion-guomi-v1.json",
	} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "vectors", name))
			if err != nil {
				t.Fatal(err)
			}
			var vector struct {
				SchemaVersion    string     `json:"schema_version"`
				FixtureOrigin    string     `json:"fixture_origin"`
				Source           string     `json:"source"`
				CryptoMode       CryptoMode `json:"crypto_mode"`
				ChainHash        string     `json:"chain_hash_algorithm"`
				LeafIndex        uint64     `json:"leaf_index"`
				LeafHash         string     `json:"leaf_hash"`
				Proof            []string   `json:"proof"`
				RootHash         string     `json:"root_hash"`
				PublishSelector  string     `json:"publish_selector"`
				AnchorEventTopic string     `json:"anchor_event_topic"`
			}
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&vector); err != nil {
				t.Fatal(err)
			}
			if vector.SchemaVersion != "trustdb.test.fisco-bcos-receipt-inclusion.v1" ||
				vector.FixtureOrigin != "trustdb-derived-conformance-vector" ||
				vector.Source != "https://github.com/FISCO-BCOS/FISCO-BCOS/blob/v3.16.3/bcos-crypto/bcos-crypto/merkle/Merkle.h" {
				t.Fatal("derived vector does not identify its origin and the pinned v3.16.3 Merkle source")
			}
			leaf := mustDecodeHex(t, vector.LeafHash)
			root := mustDecodeHex(t, vector.RootHash)
			path := make([][]byte, len(vector.Proof))
			for i := range vector.Proof {
				path[i] = mustDecodeHex(t, vector.Proof[i])
			}
			if err := verifyBCOSMerklePath(
				"format-derived",
				leaf,
				path,
				vector.LeafIndex,
				root,
				vector.ChainHash,
			); err != nil {
				t.Fatal(err)
			}
			selector, err := ABISelectorForMode(vector.CryptoMode, publishSignature)
			if err != nil || hex.EncodeToString(selector) != vector.PublishSelector {
				t.Fatalf("publish selector=%x error=%v", selector, err)
			}
			topic, err := EventTopicForMode(vector.CryptoMode, TrustDBAnchorV1EventSignature)
			if err != nil || hex.EncodeToString(topic) != vector.AnchorEventTopic {
				t.Fatalf("event topic=%x error=%v", topic, err)
			}
		})
	}
}

func TestCanonicalTransactionDecoderRejectsFixedArrayOverflowWithoutPanic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		tag   byte
		count int32
	}{
		{name: "data_hash_list_33", tag: transactionDataHashTag, count: transactionHashBytes + 1},
		{name: "sender_list_21", tag: transactionSenderTag, count: transactionSenderBytes + 1},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			encoded := tarsByteList(t, tc.tag, tc.count)
			if err := validateBoundedTARS(encoded); err != nil {
				t.Fatalf("generic bounds unexpectedly rejected regression input: %v", err)
			}
			if _, err := decodeCanonicalTransaction(encoded); err == nil {
				t.Fatal("fixed-array overflow encoding was accepted")
			}
		})
	}
}

func TestCanonicalTransactionDecoderRequiresExactFixedSimpleListLengths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tag    byte
		length int32
	}{
		{name: "short_data_hash", tag: transactionDataHashTag, length: transactionHashBytes - 1},
		{name: "long_data_hash", tag: transactionDataHashTag, length: transactionHashBytes + 1},
		{name: "short_sender", tag: transactionSenderTag, length: transactionSenderBytes - 1},
		{name: "long_sender", tag: transactionSenderTag, length: transactionSenderBytes + 1},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			encoded := tarsByteSimpleList(t, tc.tag, tc.length)
			if _, err := decodeCanonicalTransaction(encoded); err == nil {
				t.Fatal("noncanonical fixed-width SimpleList was accepted")
			}
		})
	}
}

func TestCanonicalTransactionDecoderVersionGate(t *testing.T) {
	t.Parallel()

	for _, version := range []int32{
		minSupportedBCOSTransactionVersion,
		maxSupportedBCOSTransactionVersion,
	} {
		transaction, err := decodeCanonicalTransaction(canonicalTransactionForVersion(t, version))
		if err != nil {
			t.Fatalf("supported transaction data version %d failed: %v", version, err)
		}
		if transaction.Sender != nil {
			t.Fatalf("supported transaction data version %d unexpectedly requires an encoded sender", version)
		}
	}
	for _, version := range []int32{-1, 2} {
		if _, err := decodeCanonicalTransaction(canonicalTransactionForVersion(t, version)); err == nil {
			t.Fatalf("unsupported transaction data version %d was accepted", version)
		}
	}
}

func TestCanonicalTransactionDecoderAcceptsAbsentOptionalSender(t *testing.T) {
	t.Parallel()

	raw := canonicalTransactionForVersion(t, minSupportedBCOSTransactionVersion)
	transaction, err := decodeCanonicalTransaction(raw)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.Sender != nil {
		t.Fatal("canonical transaction unexpectedly gained an encoded sender")
	}
	canonical, err := encodeCanonicalTransaction(transaction)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, raw) {
		t.Fatal("canonical transaction without sender did not round-trip byte for byte")
	}
}

func TestCanonicalTransactionEncoderMatchesPinnedSDKWithSender(t *testing.T) {
	t.Parallel()

	transaction, err := decodeCanonicalTransaction(
		canonicalTransactionForVersion(t, minSupportedBCOSTransactionVersion),
	)
	if err != nil {
		t.Fatal(err)
	}
	sender := common.BytesToAddress(bytes.Repeat([]byte{0x52}, transactionSenderBytes))
	transaction.Sender = &sender
	canonical, err := encodeCanonicalTransaction(transaction)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, transaction.Bytes()) {
		t.Fatal("TrustDB canonical encoder differs from the pinned SDK when sender is present")
	}
	decoded, err := decodeCanonicalTransaction(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Sender == nil || !bytes.Equal(decoded.Sender.Bytes(), sender.Bytes()) {
		t.Fatal("canonical encoded sender was not preserved exactly")
	}
}

func FuzzBCOSMerkleProofParser(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2})
	f.Add([]byte{0, 0, 0, 1})
	f.Add([]byte{0, 2})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, _ = decodeBCOSMerkleGroupCount(encoded)
	})
}

func FuzzBoundedTARSPreflight(f *testing.F) {
	f.Add([]byte{0x0c})
	f.Add([]byte{0xd0, 0x00, 0x02, 0xff})
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > maxRawTransactionBytes {
			t.Skip()
		}
		_ = validateBoundedTARS(encoded)
		_, _ = decodeCanonicalTransaction(encoded)
	})
}

func tarsByteList(t *testing.T, tag byte, count int32) []byte {
	t.Helper()
	buffer := codec.NewBuffer()
	mustTARSEncode(t, buffer.WriteHead(codec.LIST, tag))
	mustTARSEncode(t, buffer.WriteInt32(count, 0))
	for i := int32(0); i < count; i++ {
		mustTARSEncode(t, buffer.WriteUint8(1, 0))
	}
	return buffer.ToBytes()
}

func tarsByteSimpleList(t *testing.T, tag byte, length int32) []byte {
	t.Helper()
	buffer := codec.NewBuffer()
	mustTARSEncode(t, buffer.WriteHead(codec.SimpleList, tag))
	mustTARSEncode(t, buffer.WriteHead(codec.BYTE, 0))
	mustTARSEncode(t, buffer.WriteInt32(length, 0))
	mustTARSEncode(t, buffer.WriteSliceUint8(bytes.Repeat([]byte{1}, int(length))))
	return buffer.ToBytes()
}

func canonicalTransactionForVersion(t *testing.T, version int32) []byte {
	t.Helper()
	to := common.BytesToAddress(bytes.Repeat([]byte{0x51}, transactionSenderBytes))
	transaction := types.NewSimpleTx(&to, []byte{0x01, 0x02}, "", "version-gate", "", false)
	transaction.Data.Version = version
	transaction.Data.ChainID = "chain0"
	transaction.Data.GroupID = "group0"
	transaction.Data.BlockLimit = 5100
	transaction.Hash()
	encoded, err := encodeCanonicalTransaction(*transaction)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func validReceiptInclusionFixture(
	t testing.TB,
	mode CryptoMode,
	suite cryptosuite.ID,
) (model.SignedTreeHead, model.STHAnchorResult, TrustConfig) {
	t.Helper()
	sth := testSTH(suite)
	trust := testTrustConfig(t, mode)
	payload, err := NewAnchorPayload(suite, sth)
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes, err := MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	callData, err := PublishCallDataForMode(mode, payload)
	if err != nil {
		t.Fatal(err)
	}
	to := common.BytesToAddress(trust.Contract.Address)
	transaction := types.NewSimpleTx(&to, callData, "", "fixture-nonce", "", mode == CryptoModeGuomi)
	transaction.Data.Version = 0
	transaction.Data.ChainID = trust.ChainID
	transaction.Data.GroupID = trust.GroupID
	transaction.Data.BlockLimit = 5100
	transactionHash := transaction.Hash().Bytes()
	var signature, sender []byte
	switch mode {
	case CryptoModeStandard:
		privateKey, err := ethcrypto.ToECDSA(bytes.Repeat([]byte{0x01}, 32))
		if err != nil {
			t.Fatal(err)
		}
		signature, err = ethcrypto.Sign(transactionHash, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		sender = ethcrypto.PubkeyToAddress(privateKey.PublicKey).Bytes()
	case CryptoModeGuomi:
		privateKey := bytes.Repeat([]byte{0x02}, 32)
		signature, err = smcrypto.Sign(transactionHash, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		sender = smcrypto.SM2KeyToAddress(privateKey).Bytes()
	default:
		t.Fatal("unsupported fixture mode")
	}
	transaction.Signature = append([]byte(nil), signature...)
	senderAddress := common.BytesToAddress(sender)
	transaction.Sender = &senderAddress
	rawTransaction := transaction.Bytes()

	eventTopic, err := EventTopicForMode(mode, trust.Contract.EventSignature)
	if err != nil {
		t.Fatal(err)
	}
	publisherTopic := make([]byte, 32)
	copy(publisherTopic[12:], sender)
	eventData := make([]byte, 4*32)
	binary.BigEndian.PutUint64(eventData[24:32], payload.TreeSize)
	copy(eventData[32:64], payload.RootHash)
	copy(eventData[64:96], payload.SignedSTHDigest)
	binary.BigEndian.PutUint16(eventData[126:128], payload.Version)
	event := AnchorPublishedEvent{
		ContractAddress: trust.Contract.Address,
		AnchorID:        payload.AnchorID,
		StreamID:        payload.StreamID,
		TreeSize:        payload.TreeSize,
		RootHash:        payload.RootHash,
		SignedSTHDigest: payload.SignedSTHDigest,
		Publisher:       sender,
		PayloadVersion:  payload.Version,
		LogIndex:        0,
	}
	decodedEvent, err := MarshalNativeAnchorEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	receiptFields := NativeReceiptFields{
		Version:         0,
		GasUsed:         "21000",
		ContractAddress: "",
		Status:          ReceiptStatusOK,
		Output:          nil,
		Logs: []NativeLogFields{{
			Address: hex.EncodeToString(trust.Contract.Address),
			Topics:  [][]byte{eventTopic, payload.AnchorID, payload.StreamID, publisherTopic},
			Data:    eventData,
		}},
		BlockNumber: 4200,
	}
	rawReceipt, canonicalLogs, err := MarshalNativeReceiptPreimage(receiptFields)
	if err != nil {
		t.Fatal(err)
	}
	receiptHash, err := HashNativeEvidence(trust.ChainHashAlgorithm, rawReceipt)
	if err != nil {
		t.Fatal(err)
	}
	blockFields := NativeBlockHeaderFields{
		Version:          0,
		ParentInfo:       []NativeParentInfo{{BlockNumber: 4199, BlockHash: bytes.Repeat([]byte{0x70}, 32)}},
		TransactionsRoot: append([]byte(nil), transactionHash...),
		ReceiptsRoot:     append([]byte(nil), receiptHash...),
		StateRoot:        bytes.Repeat([]byte{0x83}, 32),
		BlockNumber:      4200,
		GasUsed:          "21000",
		Timestamp:        100,
		Sealer:           0,
		SealerList:       [][]byte{[]byte("validator-a")},
		ConsensusWeights: []int64{1},
	}
	rawHeader, err := MarshalNativeBlockHeaderPreimage(blockFields)
	if err != nil {
		t.Fatal(err)
	}
	blockHash, err := HashNativeEvidence(trust.ChainHashAlgorithm, rawHeader)
	if err != nil {
		t.Fatal(err)
	}
	contextID, err := ChainContextID(trust)
	if err != nil {
		t.Fatal(err)
	}
	proof := AnchorProof{
		SchemaVersion:             SchemaAnchorProof,
		FormatVersion:             ProofVersion,
		CryptoMode:                mode,
		ProtocolHashAlgorithm:     trust.ProtocolHashAlgorithm,
		ChainHashAlgorithm:        trust.ChainHashAlgorithm,
		ChainSignatureAlgorithm:   trust.ChainSignatureAlgorithm,
		ChainID:                   trust.ChainID,
		GroupID:                   trust.GroupID,
		GenesisHash:               append([]byte(nil), trust.GenesisHash...),
		TrustedCheckpoint:         trust.TrustedCheckpoint,
		Contract:                  trust.Contract,
		ChainContextID:            contextID,
		CanonicalPayload:          payloadBytes,
		SuccessfulAttemptOrdinal:  1,
		SuccessfulTransactionHash: append([]byte(nil), transactionHash...),
		TransactionAttempts: []TransactionAttempt{{
			Ordinal:                 1,
			RawCanonicalTransaction: rawTransaction,
			ChainID:                 trust.ChainID,
			GroupID:                 trust.GroupID,
			To:                      append([]byte(nil), trust.Contract.Address...),
			Input:                   callData,
			Signature:               signature,
			Sender:                  sender,
			TransactionHash:         append([]byte(nil), transactionHash...),
			BlockLimit:              5100,
			SubmittedAtUnixN:        1,
			Outcome:                 AttemptOutcomeReceiptSuccess,
		}},
		Receipt: ReceiptEvidence{
			Fields:              receiptFields,
			RawCanonicalReceipt: rawReceipt,
			Status:              ReceiptStatusOK,
			StatusMessage:       "success",
			CanonicalLogs:       canonicalLogs,
			ReceiptHash:         receiptHash,
			TransactionHash:     append([]byte(nil), transactionHash...),
			TransactionIndex:    0,
			TransactionProof:    [][]byte{append([]byte(nil), transactionHash...)},
			ReceiptIndex:        0,
			ReceiptProof:        [][]byte{append([]byte(nil), receiptHash...)},
			AnchorLogIndex:      0,
			DecodedAnchorEvent:  decodedEvent,
		},
		Block: BlockEvidence{
			Fields:             blockFields,
			RawCanonicalHeader: rawHeader,
			BlockHash:          blockHash,
			BlockNumber:        4200,
		},
		Finality: FinalityEvidence{Signatures: []CommitSignature{{
			ValidatorNodeID: "validator-a",
			Signature:       bytes.Repeat([]byte{0x99}, 64),
		}}},
	}
	proofBytes, err := MarshalProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	result := model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		EvidenceStage:    model.AnchorEvidenceStageRaw,
		NodeID:           sth.NodeID,
		LogID:            sth.LogID,
		TreeSize:         sth.TreeSize,
		SinkName:         SinkName,
		AnchorID:         AnchorIDString(payload),
		RootHash:         append([]byte(nil), sth.RootHash...),
		STH:              sth,
		Proof:            proofBytes,
		PublishedAtUnixN: 3,
	}
	return sth, result, trust
}

func cloneAnchorProofForMutation(t *testing.T, proof AnchorProof) AnchorProof {
	t.Helper()
	encoded, err := MarshalProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	cloned, err := UnmarshalProof(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return cloned
}

func uint32Node(value uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, value)
	return out
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
