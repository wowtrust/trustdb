package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/anchor/fiscobcos"
)

func TestFISCOBCOSTrustConfigCreateAndInspect(t *testing.T) {
	t.Parallel()

	config := testFISCOBCOSTrust(t)
	input := trustConfigInputForTest(config)
	input.Endpoints[0], input.Endpoints[1] = input.Endpoints[1], input.Endpoints[0]
	inputPath := filepath.Join(t.TempDir(), "trust-config.json")
	outputPath := filepath.Join(t.TempDir(), "trust-config.cbor")
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	command := newRootCommand(&out, &errOut)
	command.SetArgs([]string{
		"anchor", "fisco-bcos", "trust-config", "create",
		"--input", inputPath,
		"--out", outputPath,
	})
	if err := command.Execute(); err != nil {
		t.Fatalf("create TrustConfig: %v stderr=%s", err, errOut.String())
	}
	created, err := loadCanonicalFISCOBCOSTrustConfig(outputPath)
	if err != nil {
		t.Fatalf("load generated TrustConfig: %v", err)
	}
	if created.CryptoMode != fiscobcos.CryptoModeStandard ||
		created.Endpoints[0] != "tls://127.0.0.1:20200" {
		t.Fatalf("generated TrustConfig was not canonical: %+v", created)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(outputPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("generated mode = %o, want 600", info.Mode().Perm())
		}
	}
	var createReport fiscoBCOSTrustConfigReport
	if err := json.Unmarshal(out.Bytes(), &createReport); err != nil {
		t.Fatalf("decode create report %q: %v", out.String(), err)
	}
	if !strings.HasPrefix(createReport.TrustConfigDigest, "0x") ||
		!strings.HasPrefix(createReport.ChainContextID, "0x") {
		t.Fatalf("create report omitted trust identities: %+v", createReport)
	}

	out.Reset()
	errOut.Reset()
	command = newRootCommand(&out, &errOut)
	command.SetArgs([]string{
		"anchor", "fisco-bcos", "trust-config", "inspect",
		"--input", outputPath,
	})
	if err := command.Execute(); err != nil {
		t.Fatalf("inspect TrustConfig: %v stderr=%s", err, errOut.String())
	}
	var inspectReport fiscoBCOSTrustConfigReport
	if err := json.Unmarshal(out.Bytes(), &inspectReport); err != nil {
		t.Fatalf("decode inspect report %q: %v", out.String(), err)
	}
	if inspectReport.TrustConfigDigest != createReport.TrustConfigDigest ||
		inspectReport.ChainContextID != createReport.ChainContextID {
		t.Fatalf("create/inspect identities differ: create=%+v inspect=%+v", createReport, inspectReport)
	}
}

func TestFISCOBCOSTrustConfigCreateRejectsUnknownAndCrossModeFields(t *testing.T) {
	t.Parallel()

	config := testFISCOBCOSTrust(t)
	input := trustConfigInputForTest(config)
	inputPath := filepath.Join(t.TempDir(), "trust-config.json")
	outputPath := filepath.Join(t.TempDir(), "trust-config.cbor")
	cleanData, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	unknownData := append(
		append([]byte(nil), cleanData[:len(cleanData)-1]...),
		[]byte(`,"unexpected":true}`)...,
	)
	if err := os.WriteFile(inputPath, unknownData, 0o600); err != nil {
		t.Fatal(err)
	}
	command := newRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	command.SetArgs([]string{
		"anchor", "fisco-bcos", "trust-config", "create",
		"--input", inputPath,
		"--out", outputPath,
	})
	if err := command.Execute(); err == nil {
		t.Fatal("create accepted an unknown JSON field")
	}

	duplicate := bytes.Replace(
		cleanData,
		[]byte(`"crypto_mode":"standard"`),
		[]byte(`"crypto_mode":"standard","crypto_mode":"guomi"`),
		1,
	)
	if err := os.WriteFile(inputPath, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	command = newRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	command.SetArgs([]string{
		"anchor", "fisco-bcos", "trust-config", "create",
		"--input", inputPath,
		"--out", outputPath,
	})
	if err := command.Execute(); err == nil {
		t.Fatal("create accepted a duplicate JSON field")
	}

	caseFoldedAlias := bytes.Replace(
		cleanData,
		[]byte(`"crypto_mode":"standard"`),
		[]byte(`"crypto_mode":"standard","CRYPTO_MODE":"guomi"`),
		1,
	)
	if err := os.WriteFile(inputPath, caseFoldedAlias, 0o600); err != nil {
		t.Fatal(err)
	}
	command = newRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	command.SetArgs([]string{
		"anchor", "fisco-bcos", "trust-config", "create",
		"--input", inputPath,
		"--out", outputPath,
	})
	if err := command.Execute(); err == nil {
		t.Fatal("create accepted a case-folded JSON field alias")
	}

	nestedCaseFoldedAlias := bytes.Replace(
		cleanData,
		[]byte(`"block_number":100`),
		[]byte(`"block_number":100,"BLOCK_NUMBER":7`),
		1,
	)
	if bytes.Equal(nestedCaseFoldedAlias, cleanData) {
		t.Fatal("nested alias test did not modify the JSON fixture")
	}
	if err := os.WriteFile(inputPath, nestedCaseFoldedAlias, 0o600); err != nil {
		t.Fatal(err)
	}
	command = newRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	command.SetArgs([]string{
		"anchor", "fisco-bcos", "trust-config", "create",
		"--input", inputPath,
		"--out", outputPath,
	})
	if err := command.Execute(); err == nil {
		t.Fatal("create accepted a nested case-folded JSON field alias")
	}

	input = trustConfigInputForTest(config)
	input.CryptoMode = string(fiscobcos.CryptoModeGuomi)
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	command = newRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	command.SetArgs([]string{
		"anchor", "fisco-bcos", "trust-config", "create",
		"--input", inputPath,
		"--out", outputPath,
	})
	if err := command.Execute(); err == nil {
		t.Fatal("create accepted standard endpoints and validator keys under Guomi mode")
	}
}

func TestFISCOBCOSGuomiTrustConfigExampleIsCanonicalizable(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(
		"..",
		"..",
		"configs",
		"fisco-bcos-guomi-trust-config.example.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var input fiscoBCOSTrustConfigInput
	if err := decodeStrictJSON(data, &input); err != nil {
		t.Fatalf("decode committed Guomi TrustConfig example: %v", err)
	}
	config, err := input.trustConfig()
	if err != nil {
		t.Fatalf("validate committed Guomi TrustConfig example: %v", err)
	}
	canonical, err := fiscobcos.MarshalTrustConfig(config)
	if err != nil {
		t.Fatalf("canonicalize committed Guomi TrustConfig example: %v", err)
	}
	decoded, err := fiscobcos.UnmarshalTrustConfig(canonical)
	if err != nil {
		t.Fatalf("decode canonical committed Guomi TrustConfig example: %v", err)
	}
	if decoded.CryptoMode != fiscobcos.CryptoModeGuomi {
		t.Fatalf("example crypto mode = %q, want guomi", decoded.CryptoMode)
	}
}

func TestFISCOBCOSTrustConfigAdvanceRequiresInPlaceCAS(t *testing.T) {
	t.Parallel()

	config := testFISCOBCOSTrust(t)
	config.ValidatorTransitionPolicy = fiscobcos.ValidatorPolicyTransitions
	canonical, err := fiscobcos.MarshalTrustConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := fiscobcos.TrustConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "trust-config.cbor")
	if err := os.WriteFile(inputPath, canonical, 0o600); err != nil {
		t.Fatal(err)
	}
	wrongOutput := filepath.Join(directory, "forked-config.cbor")
	command := newRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	command.SetArgs([]string{
		"anchor", "fisco-bcos", "trust-config", "advance",
		"--input", inputPath,
		"--evidence", filepath.Join(directory, "missing.sproof"),
		"--out", wrongOutput,
		"--expect-current-digest", "0x" + hex.EncodeToString(digest),
	})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "same canonical TrustConfig file") {
		t.Fatalf("advance with forked output error = %v", err)
	}
	if _, err := os.Stat(wrongOutput); !os.IsNotExist(err) {
		t.Fatalf("forked output exists or stat failed: %v", err)
	}

	before, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	wrongDigest := append([]byte(nil), digest...)
	wrongDigest[0] ^= 0xff
	command = newRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	command.SetArgs([]string{
		"anchor", "fisco-bcos", "trust-config", "advance",
		"--input", inputPath,
		"--evidence", filepath.Join(directory, "missing.sproof"),
		"--out", inputPath,
		"--expect-current-digest", "0x" + hex.EncodeToString(wrongDigest),
	})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "digest changed") {
		t.Fatalf("advance with stale digest error = %v", err)
	}
	after, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("stale-digest advance modified the canonical TrustConfig")
	}
	if _, err := os.Stat(inputPath + ".advance.lock"); !os.IsNotExist(err) {
		t.Fatalf("advance lock was not cleaned up: %v", err)
	}
}

func TestFISCOBCOSTrustConfigAdvanceRejectsConcurrentLock(t *testing.T) {
	t.Parallel()

	config := testFISCOBCOSTrust(t)
	config.ValidatorTransitionPolicy = fiscobcos.ValidatorPolicyTransitions
	canonical, err := fiscobcos.MarshalTrustConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := fiscobcos.TrustConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "trust-config.cbor")
	if err := os.WriteFile(inputPath, canonical, 0o600); err != nil {
		t.Fatal(err)
	}
	lockPath := inputPath + ".advance.lock"
	if err := os.WriteFile(lockPath, []byte("operator-owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := newRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	command.SetArgs([]string{
		"anchor", "fisco-bcos", "trust-config", "advance",
		"--input", inputPath,
		"--evidence", filepath.Join(directory, "missing.sproof"),
		"--out", inputPath,
		"--expect-current-digest", "0x" + hex.EncodeToString(digest),
	})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "acquire exclusive") {
		t.Fatalf("advance with concurrent lock error = %v", err)
	}
	lockBytes, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(lockBytes) != "operator-owned\n" {
		t.Fatalf("concurrent lock changed to %q", lockBytes)
	}
}

func trustConfigInputForTest(config fiscobcos.TrustConfig) fiscoBCOSTrustConfigInput {
	validators := make([]fiscoBCOSValidatorDescriptorInput, len(config.Validators))
	for index, validator := range config.Validators {
		validators[index] = fiscoBCOSValidatorDescriptorInput{
			NodeID:       validator.NodeID,
			PublicKeyHex: "0x" + hex.EncodeToString(validator.PublicKey),
			VoteWeight:   validator.VoteWeight,
		}
	}
	caHashes := make([]string, len(config.Certificates.TrustedCACertificateHashes))
	for index, hash := range config.Certificates.TrustedCACertificateHashes {
		caHashes[index] = "0x" + hex.EncodeToString(hash)
	}
	peerHashes := make([]string, len(config.Certificates.PinnedPeerCertificateHashes))
	for index, hash := range config.Certificates.PinnedPeerCertificateHashes {
		peerHashes[index] = "0x" + hex.EncodeToString(hash)
	}
	return fiscoBCOSTrustConfigInput{
		CryptoMode:     string(config.CryptoMode),
		ChainID:        config.ChainID,
		GroupID:        config.GroupID,
		GenesisHashHex: "0x" + hex.EncodeToString(config.GenesisHash),
		TrustedCheckpoint: fiscoBCOSCheckpointInput{
			BlockNumber:  config.TrustedCheckpoint.BlockNumber,
			BlockHashHex: "0x" + hex.EncodeToString(config.TrustedCheckpoint.BlockHash),
		},
		Contract: fiscoBCOSContractInput{
			AddressHex:      "0x" + hex.EncodeToString(config.Contract.Address),
			CodeHashHex:     "0x" + hex.EncodeToString(config.Contract.CodeHash),
			ProtocolVersion: config.Contract.ProtocolVersion,
			EventSignature:  config.Contract.EventSignature,
		},
		Endpoints:                 append([]string(nil), config.Endpoints...),
		ReadQuorum:                config.ReadQuorum,
		ValidatorTransitionPolicy: config.ValidatorTransitionPolicy,
		AccountProvider: fiscoBCOSAccountProviderInput{
			Provider:     config.AccountProvider.Provider,
			KeyID:        config.AccountProvider.KeyID,
			KeyReference: config.AccountProvider.KeyReference,
		},
		Certificates: fiscoBCOSCertificateInput{
			TrustedCAReferences:            append([]string(nil), config.Certificates.TrustedCAReferences...),
			TrustedCACertificateHashesHex:  caHashes,
			PinnedPeerCertificateHashesHex: peerHashes,
			ClientSigningCertificateRef:    config.Certificates.ClientSigningCertificateRef,
			ClientSigningKeyRef:            config.Certificates.ClientSigningKeyRef,
			ClientEncryptionCertificateRef: config.Certificates.ClientEncryptionCertificateRef,
			ClientEncryptionKeyRef:         config.Certificates.ClientEncryptionKeyRef,
		},
		Validators: validators,
	}
}
