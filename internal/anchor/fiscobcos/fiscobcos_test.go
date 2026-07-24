package fiscobcos

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
)

func TestAnchorPayloadGoldenVectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		suite             cryptosuite.ID
		wantPayloadSHA256 string
		wantSTHDigest     string
		wantStreamID      string
		wantAnchorID      string
	}{
		{name: "standard", suite: cryptosuite.INTLV1, wantPayloadSHA256: "ed69775dcfeac2bc756fe7ff3c035dacedcf8f3906615dcdc87b5d4ad1199733", wantSTHDigest: "8a5f4fde3339f606453489c1e4be138d1415c908284461cf166aebb3721ba0de", wantStreamID: "5fae452509ee4290e834a64502d815cacb76928cf9371809daccd6e0e365687e", wantAnchorID: "4eb7b800ae3ddeaab852923ccb860dbe07413dc9797e13e60a828cf789328271"},
		{name: "cn-sm", suite: cryptosuite.CNSMV1, wantPayloadSHA256: "e1b6aa24589c25f96687e0d2cf661767fc455ade3be799fe1a95c28f8446aa5e", wantSTHDigest: "e11951fc0d59d2e980510b9866db40d141c0d94d9ebdf2ffb68d137841b05d8e", wantStreamID: "41aea4cb28ac7183cdeede08da326b50a28d1589b48b33976c37d681b6e53d8d", wantAnchorID: "29efbb254846b8808c2db4b7856c4c4d3d0dc7f47e7a07a13679e18c492aa03f"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			payload, err := NewAnchorPayload(tc.suite, testSTH(tc.suite))
			if err != nil {
				t.Fatalf("NewAnchorPayload() error = %v", err)
			}
			first, err := MarshalPayload(payload)
			if err != nil {
				t.Fatalf("MarshalPayload() error = %v", err)
			}
			second, err := MarshalPayload(payload)
			if err != nil || !bytes.Equal(first, second) {
				t.Fatalf("MarshalPayload() is not deterministic: error=%v", err)
			}
			sum := sha256.Sum256(first)
			assertHex(t, "payload sha256", sum[:], tc.wantPayloadSHA256)
			assertHex(t, "signed STH digest", payload.SignedSTHDigest, tc.wantSTHDigest)
			assertHex(t, "stream ID", payload.StreamID, tc.wantStreamID)
			assertHex(t, "anchor ID", payload.AnchorID, tc.wantAnchorID)
			decoded, err := UnmarshalPayload(first)
			if err != nil {
				t.Fatalf("UnmarshalPayload() error = %v", err)
			}
			roundTrip, _ := MarshalPayload(decoded)
			if !bytes.Equal(first, roundTrip) {
				t.Fatal("payload did not round-trip byte-identically")
			}
		})
	}
}

func TestPublishedGoldenVectorFilesMatchImplementation(t *testing.T) {
	t.Parallel()

	type payloadVector struct {
		CryptoSuite            cryptosuite.ID `json:"crypto_suite"`
		TreeAlgorithm          string         `json:"tree_algorithm"`
		SignatureAlgorithm     string         `json:"signature_algorithm"`
		CanonicalPayloadHex    string         `json:"canonical_payload_hex"`
		CanonicalPayloadSHA256 string         `json:"canonical_payload_sha256"`
		SignedSTHDigest        string         `json:"signed_sth_digest"`
		StreamID               string         `json:"stream_id"`
		AnchorID               string         `json:"anchor_id"`
	}
	var payloadFile struct {
		Schema           string          `json:"schema"`
		Description      string          `json:"description"`
		SignedSTHFixture json.RawMessage `json:"signed_sth_fixture"`
		Vectors          []payloadVector `json:"vectors"`
	}
	readJSONVector(t, "fisco-bcos-anchor-payload-v1.json", &payloadFile)
	if len(payloadFile.Vectors) != 2 {
		t.Fatalf("payload vector count=%d, want 2", len(payloadFile.Vectors))
	}
	for _, vector := range payloadFile.Vectors {
		payload, err := NewAnchorPayload(vector.CryptoSuite, testSTH(vector.CryptoSuite))
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := MarshalPayload(payload)
		sum := sha256.Sum256(encoded)
		assertHex(t, "published payload", encoded, vector.CanonicalPayloadHex)
		assertHex(t, "published payload sha256", sum[:], vector.CanonicalPayloadSHA256)
		assertHex(t, "published signed STH digest", payload.SignedSTHDigest, vector.SignedSTHDigest)
		assertHex(t, "published stream ID", payload.StreamID, vector.StreamID)
		assertHex(t, "published anchor ID", payload.AnchorID, vector.AnchorID)
	}

	type trustVector struct {
		CryptoMode              CryptoMode `json:"crypto_mode"`
		ProtocolHashAlgorithm   string     `json:"protocol_hash_algorithm"`
		ChainHashAlgorithm      string     `json:"chain_hash_algorithm"`
		ChainSignatureAlgorithm string     `json:"chain_signature_algorithm"`
		TransportMode           string     `json:"transport_mode"`
		SM2UserID               string     `json:"sm2_user_id,omitempty"`
		CanonicalCBORSHA256     string     `json:"canonical_cbor_sha256"`
		TrustConfigDigest       string     `json:"trust_config_digest"`
		ChainContextID          string     `json:"chain_context_id"`
	}
	var trustFile struct {
		Schema      string          `json:"schema"`
		Description string          `json:"description"`
		Fixture     json.RawMessage `json:"fixture"`
		Vectors     []trustVector   `json:"vectors"`
	}
	readJSONVector(t, "fisco-bcos-trust-config-v1.json", &trustFile)
	if len(trustFile.Vectors) != 2 {
		t.Fatalf("trust vector count=%d, want 2", len(trustFile.Vectors))
	}
	for _, vector := range trustFile.Vectors {
		config := testTrustConfig(t, vector.CryptoMode)
		encoded, _ := MarshalTrustConfig(config)
		sum := sha256.Sum256(encoded)
		digest, _ := TrustConfigDigest(config)
		contextID, _ := ChainContextID(config)
		assertHex(t, "published trust config CBOR sha256", sum[:], vector.CanonicalCBORSHA256)
		assertHex(t, "published trust config digest", digest, vector.TrustConfigDigest)
		assertHex(t, "published chain context ID", contextID, vector.ChainContextID)
	}
}

func TestPayloadIsChainNeutralButExactSTHBound(t *testing.T) {
	t.Parallel()

	sth := testSTH(cryptosuite.INTLV1)
	payload, err := NewAnchorPayload(cryptosuite.INTLV1, sth)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := MarshalPayload(payload)
	standard := testTrustConfig(t, CryptoModeStandard)
	guomi := testTrustConfig(t, CryptoModeGuomi)
	standardProof := testProof(t, standard, encoded, sth)
	guomiProof := testProof(t, guomi, encoded, sth)
	if !bytes.Equal(standardProof.CanonicalPayload, guomiProof.CanonicalPayload) {
		t.Fatal("chain mode changed the opaque TrustDB anchor payload")
	}
	if bytes.Equal(standardProof.ChainContextID, guomiProof.ChainContextID) {
		t.Fatal("standard and Guomi chain contexts unexpectedly match")
	}
	if err := ValidateProofAgainstTrustConfig(sth, testResult(t, standardProof, sth), guomi); err == nil {
		t.Fatal("standard evidence was accepted by Guomi trust config")
	}
}

func TestPayloadRejectsCrossSuiteAndTampering(t *testing.T) {
	t.Parallel()

	sth := testSTH(cryptosuite.CNSMV1)
	if _, err := NewAnchorPayload(cryptosuite.INTLV1, sth); err == nil {
		t.Fatal("INTL_V1 accepted an RFC6962-SM3/SM2 STH")
	}
	payload, err := NewAnchorPayload(cryptosuite.CNSMV1, sth)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := MarshalPayload(payload)
	if _, err := UnmarshalPayload(append(encoded, 0)); err == nil {
		t.Fatal("payload decoder accepted trailing data")
	}

	mutations := []func(*AnchorPayload){
		func(p *AnchorPayload) { p.NodeID += "-other" },
		func(p *AnchorPayload) { p.LogID += "-other" },
		func(p *AnchorPayload) { p.TreeSize++ },
		func(p *AnchorPayload) { p.RootHash[0] ^= 0xff },
		func(p *AnchorPayload) { p.SignedSTHDigest[0] ^= 0xff },
	}
	for i, mutate := range mutations {
		candidate := clonePayload(payload)
		mutate(&candidate)
		if _, err := MarshalPayload(candidate); err == nil {
			t.Fatalf("mutation %d retained stale IDs", i)
		}
	}
	altered := sth
	altered.TimestampUnixN++
	if err := ValidatePayloadAgainstSTH(payload, altered); err == nil {
		t.Fatal("payload accepted a different canonical Signed STH")
	}
}

func TestTrustConfigGoldenVectorsAndCanonicalOrdering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode          CryptoMode
		wantCBORSHA   string
		wantDigest    string
		wantContextID string
	}{
		{mode: CryptoModeStandard, wantCBORSHA: "16bdc483dcd290ef4a98571e45a10675157e572845a5389da081347da75143d6", wantDigest: "bd9f616ecee5b175c4c0ab77d824cca5723693e7f4433851e3393f8d8bd20da4", wantContextID: "d0dd44454afa34e20ab27bff972906fb5b39c304508c0f6caa5c4e546a9b0ee5"},
		{mode: CryptoModeGuomi, wantCBORSHA: "138ce174ad392da687124a434c5aa40ea74541ab8ef3f0045b36178f67fb2174", wantDigest: "0a2b3c2296136e237cde52c6d8ef5ba8aaaacc1ca18220251e44c2abc78fc207", wantContextID: "445718702bb699b5e32a6b4cfaac5605382850ed74b7707124f3a1db3e60df53"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(string(tc.mode), func(t *testing.T) {
			t.Parallel()
			config := testTrustConfig(t, tc.mode)
			canonical, err := MarshalTrustConfig(config)
			if err != nil {
				t.Fatalf("MarshalTrustConfig() error = %v", err)
			}
			sum := sha256.Sum256(canonical)
			assertHex(t, "trust config CBOR sha256", sum[:], tc.wantCBORSHA)
			digest, err := TrustConfigDigest(config)
			if err != nil {
				t.Fatal(err)
			}
			assertHex(t, "trust config digest", digest, tc.wantDigest)
			contextID, err := ChainContextID(config)
			if err != nil {
				t.Fatal(err)
			}
			assertHex(t, "chain context ID", contextID, tc.wantContextID)

			reordered := cloneTrustConfig(config)
			reverseStrings(reordered.Endpoints)
			reverseValidators(reordered.Validators)
			reordered.Certificates.TrustedCACertificateHashes[0], reordered.Certificates.TrustedCACertificateHashes[1] = reordered.Certificates.TrustedCACertificateHashes[1], reordered.Certificates.TrustedCACertificateHashes[0]
			reorderedBytes, err := MarshalTrustConfig(reordered)
			if err != nil || !bytes.Equal(canonical, reorderedBytes) {
				t.Fatalf("set ordering changed canonical config: error=%v", err)
			}
			decoded, err := UnmarshalTrustConfig(canonical)
			if err != nil {
				t.Fatalf("UnmarshalTrustConfig() error = %v", err)
			}
			roundTrip, _ := MarshalTrustConfig(decoded)
			if !bytes.Equal(canonical, roundTrip) {
				t.Fatal("trust config did not round-trip byte-identically")
			}
		})
	}
}

func TestTrustConfigRejectsInferredOrMixedModeParameters(t *testing.T) {
	t.Parallel()

	standard := testTrustConfig(t, CryptoModeStandard)
	standard.ChainHashAlgorithm = "sm3"
	if _, err := MarshalTrustConfig(standard); err == nil {
		t.Fatal("standard config accepted SM3 chain hashing")
	}
	guomi := testTrustConfig(t, CryptoModeGuomi)
	guomi.Certificates.TransportMode = StandardTransport
	if _, err := MarshalTrustConfig(guomi); err == nil {
		t.Fatal("Guomi config accepted standard TLS")
	}
	guomi = testTrustConfig(t, CryptoModeGuomi)
	guomi.Certificates.ClientEncryptionKeyRef = ""
	if _, err := MarshalTrustConfig(guomi); err == nil {
		t.Fatal("Guomi config accepted a missing encryption key reference")
	}
	standard = testTrustConfig(t, CryptoModeStandard)
	standard.SM2UserID = cryptosuite.SM2DefaultUserID
	if _, err := MarshalTrustConfig(standard); err == nil {
		t.Fatal("standard config accepted an SM2 user ID")
	}
}

func TestStrictCBORRejectsUnknownTrustAndProofFields(t *testing.T) {
	t.Parallel()

	config := testTrustConfig(t, CryptoModeStandard)
	configBytes, err := MarshalTrustConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalTrustConfig(withUnknownField(t, configBytes)); err == nil {
		t.Fatal("trust config accepted an unknown field")
	}
	sth := testSTH(cryptosuite.INTLV1)
	payload, _ := NewAnchorPayload(cryptosuite.INTLV1, sth)
	payloadBytes, _ := MarshalPayload(payload)
	proof := testProof(t, config, payloadBytes, sth)
	proofBytes, err := MarshalProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalProof(withUnknownField(t, proofBytes)); err == nil {
		t.Fatal("anchor proof accepted an unknown field")
	}
}

func TestUnmarshalProofRejectsNonCanonicalDeterministicCBOR(t *testing.T) {
	t.Parallel()

	sth := testSTH(cryptosuite.INTLV1)
	payload, err := NewAnchorPayload(cryptosuite.INTLV1, sth)
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes, err := MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	proof := testProof(t, testTrustConfig(t, CryptoModeStandard), payloadBytes, sth)
	canonical, err := MarshalProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	options := cbor.CoreDetEncOptions()
	options.Sort = cbor.SortNone
	mode, err := options.EncMode()
	if err != nil {
		t.Fatal(err)
	}
	nonCanonical, err := mode.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(nonCanonical, canonical) {
		t.Fatal("non-canonical test encoder unexpectedly matched canonical bytes")
	}
	if _, err := UnmarshalProof(nonCanonical); err == nil || !strings.Contains(err.Error(), "non-canonical") {
		t.Fatalf("UnmarshalProof(non-canonical) error = %v", err)
	}
}

func TestProofUsesLocalTrustConfigAndRejectsWrongChainOrContract(t *testing.T) {
	t.Parallel()

	sth := testSTH(cryptosuite.INTLV1)
	payload, _ := NewAnchorPayload(cryptosuite.INTLV1, sth)
	payloadBytes, _ := MarshalPayload(payload)
	config := testTrustConfig(t, CryptoModeStandard)
	proof := testProof(t, config, payloadBytes, sth)
	result := testResult(t, proof, sth)
	if err := ValidateProofAgainstTrustConfig(sth, result, config); err != nil {
		t.Fatalf("ValidateProofAgainstTrustConfig() error = %v", err)
	}

	wrongChain := cloneTrustConfig(config)
	wrongChain.ChainID = "chain-other"
	if err := ValidateProofAgainstTrustConfig(sth, result, wrongChain); err == nil {
		t.Fatal("proof was accepted by the wrong local chain pin")
	}
	wrongContract := cloneTrustConfig(config)
	wrongContract.Contract.Address[0] ^= 0xff
	if err := ValidateProofAgainstTrustConfig(sth, result, wrongContract); err == nil {
		t.Fatal("proof was accepted by the wrong local contract pin")
	}
	wrongValidators := cloneTrustConfig(config)
	wrongValidators.Validators[0].PublicKey[1] ^= 0xff
	if err := ValidateProofAgainstTrustConfig(sth, result, wrongValidators); err == nil {
		t.Fatal("proof overrode the locally pinned validator set")
	}
	wrongCertificates := cloneTrustConfig(config)
	wrongCertificates.Certificates.TrustedCACertificateHashes[0][0] ^= 0xff
	if err := ValidateProofAgainstTrustConfig(sth, result, wrongCertificates); err != nil {
		t.Fatalf("transport certificate rotation changed offline chain context: %v", err)
	}
}

func TestProofStructureRejectsDuplicateAttemptsAndSigners(t *testing.T) {
	t.Parallel()

	sth := testSTH(cryptosuite.INTLV1)
	payload, _ := NewAnchorPayload(cryptosuite.INTLV1, sth)
	payloadBytes, _ := MarshalPayload(payload)
	proof := testProof(t, testTrustConfig(t, CryptoModeStandard), payloadBytes, sth)
	proof.TransactionAttempts[1].TransactionHash = append([]byte(nil), proof.TransactionAttempts[0].TransactionHash...)
	proof.SuccessfulTransactionHash = append([]byte(nil), proof.TransactionAttempts[0].TransactionHash...)
	if _, err := MarshalProof(proof); err == nil {
		t.Fatal("proof accepted duplicate transaction attempts")
	}
	proof = testProof(t, testTrustConfig(t, CryptoModeStandard), payloadBytes, sth)
	proof.Finality.Signatures[1].ValidatorNodeID = proof.Finality.Signatures[0].ValidatorNodeID
	if _, err := MarshalProof(proof); err == nil {
		t.Fatal("proof accepted duplicate finality signers")
	}
}

func testSTH(suiteID cryptosuite.ID) model.SignedTreeHead {
	treeAlg := cryptosuite.MerkleRFC6962SHA256
	signatureAlg := cryptosuite.SignatureEd25519
	if suiteID == cryptosuite.CNSMV1 {
		treeAlg = cryptosuite.MerkleRFC6962SM3
		signatureAlg = cryptosuite.SignatureSM2SM3
	}
	return model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		CryptoSuite:    suiteID,
		TreeAlg:        treeAlg,
		TreeSize:       0x0102030405060708,
		RootHash:       sequenceBytes(0x10, 32),
		TimestampUnixN: 1_735_689_600_123_456_789,
		NodeID:         "node-cn-east-1",
		LogID:          "global-log-2026",
		Signature: model.Signature{
			Alg: signatureAlg, KeyID: "server-signing-key-01", Signature: sequenceBytes(0x80, 64),
		},
	}
}

func testTrustConfig(t *testing.T, mode CryptoMode) TrustConfig {
	t.Helper()
	config, err := NewTrustConfig(mode)
	if err != nil {
		t.Fatal(err)
	}
	params, _ := ParametersForMode(mode)
	config.ChainID = "chain0"
	config.GroupID = "group0"
	config.GenesisHash = sequenceBytes(0x01, 32)
	config.TrustedCheckpoint = BlockCheckpoint{BlockNumber: 4096, BlockHash: sequenceBytes(0x21, 32)}
	config.Contract = ContractBinding{
		Address: sequenceBytes(0x41, 20), CodeHash: sequenceBytes(0x61, 32),
		ProtocolVersion: TrustDBAnchorV1ProtocolVersion,
		EventSignature:  TrustDBAnchorV1EventSignature,
	}
	config.Endpoints = []string{"127.0.0.1:20201", "127.0.0.1:20200", "https://bcos.example.test:20202"}
	config.ReadQuorum = 2
	config.AccountProvider = AccountProviderConfig{Provider: "keydescriptor", KeyID: "bcos-publisher-01", KeyReference: "keys/bcos-publisher-01.cbor", Algorithm: params.ChainSignatureAlgorithm}
	config.Certificates = CertificateConfig{
		TransportMode:               params.TransportMode,
		TrustedCAReferences:         []string{"certs/root-b.pem", "certs/root-a.pem"},
		TrustedCACertificateHashes:  [][]byte{sequenceBytes(0xb1, 32), sequenceBytes(0xa1, 32)},
		PinnedPeerCertificateHashes: [][]byte{sequenceBytes(0xc1, 32)},
		ClientSigningCertificateRef: "certs/sdk-signing.pem",
		ClientSigningKeyRef:         "keys/sdk-signing.keyref",
	}
	if mode == CryptoModeGuomi {
		config.Certificates.ClientEncryptionCertificateRef = "certs/sdk-encryption.pem"
		config.Certificates.ClientEncryptionKeyRef = "keys/sdk-encryption.keyref"
	}
	for i := 0; i < 4; i++ {
		publicKey := make([]byte, 65)
		publicKey[0] = 0x04
		copy(publicKey[1:], sequenceBytes(byte(0xd0+i), 64))
		config.Validators = append(config.Validators, ValidatorDescriptor{
			NodeID: "validator-" + string(rune('d'-i)), Algorithm: params.ChainSignatureAlgorithm,
			PublicKeyEncoding: params.PublicKeyEncoding, PublicKey: publicKey,
		})
	}
	return config
}

func TestPinnedReceiptStatusClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		status      int
		disposition ReceiptStatusDisposition
		failure     FailureClass
	}{
		{status: 0, disposition: ReceiptStatusSucceeded, failure: FailureAmbiguous},
		{status: 16, disposition: ReceiptStatusPermanent, failure: FailurePermanent},
		{status: 18, disposition: ReceiptStatusPermanent, failure: FailurePermanent},
		{status: 10001, disposition: ReceiptStatusBlockLimit, failure: FailureTransient},
		{status: 10002, disposition: ReceiptStatusRetryable, failure: FailureTransient},
		{status: 10000, disposition: ReceiptStatusDuplicate, failure: FailureAmbiguous},
		{status: 10004, disposition: ReceiptStatusDuplicate, failure: FailureAmbiguous},
		{status: 10005, disposition: ReceiptStatusDuplicate, failure: FailureAmbiguous},
		{status: 10006, disposition: ReceiptStatusPermanent, failure: FailurePermanent},
		{status: 10007, disposition: ReceiptStatusPermanent, failure: FailurePermanent},
		{status: 10008, disposition: ReceiptStatusPermanent, failure: FailurePermanent},
		{status: 10010, disposition: ReceiptStatusAmbiguous, failure: FailureAmbiguous},
		{status: 10011, disposition: ReceiptStatusDuplicate, failure: FailureAmbiguous},
		{status: -1, disposition: ReceiptStatusAmbiguous, failure: FailureAmbiguous},
		{status: 99999, disposition: ReceiptStatusAmbiguous, failure: FailureAmbiguous},
	}
	for _, test := range tests {
		statusErr := NewReceiptStatusError(test.status)
		if statusErr.Disposition != test.disposition || statusErr.FailureClass() != test.failure {
			t.Errorf("status %d classified as %s/%s, want %s/%s",
				test.status, statusErr.Disposition, statusErr.FailureClass(), test.disposition, test.failure)
		}
		if !errors.Is(statusErr, ErrInvalidReceiptStatus) {
			t.Errorf("status %d error does not wrap ErrInvalidReceiptStatus", test.status)
		}
	}
}

func testProof(t *testing.T, config TrustConfig, payload []byte, _ model.SignedTreeHead) AnchorProof {
	t.Helper()
	contextID, err := ChainContextID(config)
	if err != nil {
		t.Fatal(err)
	}
	firstHash := sequenceBytes(0x11, 32)
	successHash := sequenceBytes(0x31, 32)
	return AnchorProof{
		SchemaVersion: SchemaAnchorProof, FormatVersion: ProofVersion,
		CryptoMode: config.CryptoMode, ProtocolHashAlgorithm: config.ProtocolHashAlgorithm,
		ChainHashAlgorithm: config.ChainHashAlgorithm, ChainSignatureAlgorithm: config.ChainSignatureAlgorithm,
		ChainID: config.ChainID, GroupID: config.GroupID, GenesisHash: append([]byte(nil), config.GenesisHash...),
		TrustedCheckpoint: config.TrustedCheckpoint, Contract: config.Contract, ChainContextID: contextID,
		CanonicalPayload: append([]byte(nil), payload...),
		TransactionAttempts: []TransactionAttempt{
			{RawCanonicalTransaction: []byte("signed-transaction-attempt-1"), Signature: sequenceBytes(0x51, 64), Sender: sequenceBytes(0x91, 20), TransactionHash: firstHash, BlockLimit: 4500, SubmittedAtUnixN: 1},
			{RawCanonicalTransaction: []byte("signed-transaction-attempt-2"), Signature: sequenceBytes(0x52, 64), Sender: sequenceBytes(0x91, 20), TransactionHash: successHash, BlockLimit: 5100, SubmittedAtUnixN: 2},
		},
		SuccessfulTransactionHash: successHash,
		Receipt: ReceiptEvidence{
			RawCanonicalReceipt: []byte("canonical-success-receipt"), ReceiptHash: sequenceBytes(0x71, 32), TransactionHash: successHash,
			TransactionIndex: 1, TransactionProof: [][]byte{sequenceBytes(0x81, 32)}, ReceiptIndex: 1,
			ReceiptProof: [][]byte{sequenceBytes(0x82, 32)}, AnchorLogIndex: 0, DecodedAnchorEvent: []byte("canonical-anchor-event"),
		},
		Block: BlockEvidence{RawCanonicalHeader: []byte("canonical-block-header"), BlockHash: sequenceBytes(0xa1, 32), BlockNumber: 4200},
		Finality: FinalityEvidence{View: 9, Round: 2, Signatures: []CommitSignature{
			{ValidatorNodeID: "validator-a", Signature: sequenceBytes(0xb1, 64)},
			{ValidatorNodeID: "validator-b", Signature: sequenceBytes(0xb2, 64)},
			{ValidatorNodeID: "validator-c", Signature: sequenceBytes(0xb3, 64)},
		}},
	}
}

func testResult(t *testing.T, proof AnchorProof, sth model.SignedTreeHead) model.STHAnchorResult {
	t.Helper()
	payload, err := UnmarshalPayload(proof.CanonicalPayload)
	if err != nil {
		t.Fatal(err)
	}
	proofBytes, err := MarshalProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	return model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult, EvidenceStage: model.AnchorEvidenceStageOfflineVerified,
		NodeID: sth.NodeID, LogID: sth.LogID,
		TreeSize: sth.TreeSize, SinkName: SinkName, AnchorID: AnchorIDString(payload), RootHash: append([]byte(nil), sth.RootHash...),
		STH: sth, Proof: proofBytes, PublishedAtUnixN: 3,
	}
}

func withUnknownField(t *testing.T, data []byte) []byte {
	t.Helper()
	var object map[string]any
	if err := cborx.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = "must-fail-closed"
	out, err := cborx.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func readJSONVector(t *testing.T, name string, destination any) {
	t.Helper()
	path := filepath.Join("..", "..", "..", "test", "vectors", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

func assertHex(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	actual := hex.EncodeToString(got)
	if actual != strings.ToLower(want) {
		t.Fatalf("%s = %s, want %s", name, actual, want)
	}
}

func sequenceBytes(start byte, size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

func clonePayload(in AnchorPayload) AnchorPayload {
	out := in
	out.RootHash = append([]byte(nil), in.RootHash...)
	out.SignedSTHDigest = append([]byte(nil), in.SignedSTHDigest...)
	out.StreamID = append([]byte(nil), in.StreamID...)
	out.AnchorID = append([]byte(nil), in.AnchorID...)
	return out
}

func reverseStrings(values []string) {
	for i, j := 0, len(values)-1; i < j; i, j = i+1, j-1 {
		values[i], values[j] = values[j], values[i]
	}
}

func reverseValidators(values []ValidatorDescriptor) {
	for i, j := 0, len(values)-1; i < j; i, j = i+1, j-1 {
		values[i], values[j] = values[j], values[i]
	}
}
