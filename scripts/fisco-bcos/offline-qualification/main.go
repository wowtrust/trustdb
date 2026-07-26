package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wowtrust/trustdb/v2/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/sproof"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
	"github.com/wowtrust/trustdb/v2/internal/verify"
	"github.com/wowtrust/trustdb/v2/scripts/fisco-bcos/qualificationformat"
)

type verificationCase struct {
	Name          string                      `json:"name"`
	Valid         bool                        `json:"valid"`
	ProofLevel    string                      `json:"proof_level,omitempty"`
	ExpectedStage string                      `json:"expected_stage,omitempty"`
	Stages        []sproof.OfflineStageResult `json:"stages"`
	Error         string                      `json:"error,omitempty"`
}

type verificationReport struct {
	Schema                 string             `json:"schema"`
	NetworkDisabledByGate  bool               `json:"network_disabled_by_gate"`
	ExternalNetworkAccess  bool               `json:"external_network_access"`
	ExternalProviderAccess bool               `json:"external_provider_access"`
	Cases                  []verificationCase `json:"cases"`
}

func main() {
	var proofPath string
	var contentPath string
	var trustPath string
	var outputPath string
	flag.StringVar(&proofPath, "proof", "", "complete .sproof file")
	flag.StringVar(&contentPath, "content", "", "original content file")
	flag.StringVar(&trustPath, "trust-roots", "", "verifier-local trust roots JSON")
	flag.StringVar(&outputPath, "output", "", "stage report JSON")
	flag.Parse()
	if proofPath == "" || contentPath == "" || trustPath == "" || outputPath == "" {
		fatalf("--proof, --content, --trust-roots and --output are required")
	}

	proof, err := sproof.ReadFileForVerification(proofPath)
	if err != nil {
		fatalf("read proof: %v", err)
	}
	content, err := os.ReadFile(contentPath)
	if err != nil {
		fatalf("read content: %v", err)
	}
	var roots qualificationformat.TrustRoots
	if err := readJSON(trustPath, &roots); err != nil {
		fatalf("read trust roots: %v", err)
	}
	if roots.Schema != qualificationformat.TrustRootsSchema || roots.CryptoSuite != proof.CryptoSuite {
		fatalf("trust roots schema or crypto suite does not match the proof")
	}
	provider, err := trustcrypto.ProviderForSuite(roots.CryptoSuite)
	if err != nil {
		fatalf("load offline crypto provider: %v", err)
	}
	if len(roots.ClientPublicKeys) == 0 || len(roots.ServerPublicKeys) == 0 {
		fatalf("trust roots do not contain client and server public keys")
	}
	trust := sproof.OfflineTrust{
		Proof: verify.TrustedKeys{
			ClientPublicKey: roots.ClientPublicKeys[0],
			ServerPublicKey: roots.ServerPublicKeys[0],
			CryptoProvider:  provider,
		},
		Identity: sproof.IdentityTrust{
			ClientPublicKeys: roots.ClientPublicKeys,
			ServerPublicKeys: roots.ServerPublicKeys,
			RequireEvidence:  true,
		},
		FISCOBCOS: &roots.FISCOBCOS,
	}

	report := verificationReport{
		Schema:                "trustdb.fisco-bcos-offline-qualification-report.v1",
		NetworkDisabledByGate: os.Getenv("TRUSTDB_NETWORK_DISABLED") == "1",
	}
	base, err := sproof.VerifyOffline(bytes.NewReader(content), proof, trust, sproof.OfflineOptions{})
	if err != nil || !base.Valid || base.ProofLevel != "L5" || base.RecordID != roots.ExpectedRecordID {
		fatalf("offline L5 verification failed: result=%+v error=%v", base, err)
	}
	if base.ExternalNetworkAccess || base.ExternalProviderAccess {
		fatalf("offline verifier reported external access: %+v", base)
	}
	requireStage(base, sproof.OfflineStageBCOSReceiptInclusion, sproof.OfflineStagePassed)
	requireStage(base, sproof.OfflineStageBCOSPBFTFinality, sproof.OfflineStagePassed)
	requireStage(base, sproof.OfflineStageBCOSAnchorBinding, sproof.OfflineStagePassed)
	report.Cases = append(report.Cases, verificationCase{
		Name: "complete_l5", Valid: true, ProofLevel: base.ProofLevel, Stages: base.Stages,
	})

	tamperedContent := append([]byte(nil), content...)
	if len(tamperedContent) == 0 {
		fatalf("qualification content is empty")
	}
	tamperedContent[0] ^= 1
	report.Cases = append(report.Cases, expectFailure(
		"content_tamper", tamperedContent, proof, trust, string(verify.StageContent),
	))
	report.Cases = append(report.Cases, expectBCOSTamper(
		"receipt_inclusion_tamper", content, proof, trust,
		sproof.OfflineStageBCOSReceiptInclusion,
		// MarshalProof is fail-closed: it recomputes the receipt consensus
		// hash from the canonical fields, so a tampered ReceiptHash cannot be
		// re-encoded at all. Corrupt one Merkle path node instead; structural
		// validation accepts the 32-byte node and the inclusion stage must be
		// the one to reject it.
		func(raw *fiscobcos.AnchorProof) { raw.Receipt.ReceiptProof[0][0] ^= 1 },
	))
	report.Cases = append(report.Cases, expectBCOSTamper(
		"pbft_finality_tamper", content, proof, trust,
		sproof.OfflineStageBCOSPBFTFinality,
		func(raw *fiscobcos.AnchorProof) { raw.Finality.Signatures[0].Signature[0] ^= 1 },
	))
	report.Cases = append(report.Cases, expectBCOSTamper(
		"exact_binding_tamper", content, proof, trust,
		sproof.OfflineStageBCOSAnchorBinding,
		func(raw *fiscobcos.AnchorProof) { raw.Receipt.DecodedAnchorEvent[0] ^= 1 },
	))
	report.ExternalNetworkAccess = base.ExternalNetworkAccess
	report.ExternalProviderAccess = base.ExternalProviderAccess
	if err := writeJSON(outputPath, report); err != nil {
		fatalf("write report: %v", err)
	}
}

func expectBCOSTamper(
	name string,
	content []byte,
	proof model.SingleProof,
	trust sproof.OfflineTrust,
	stage string,
	mutate func(*fiscobcos.AnchorProof),
) verificationCase {
	cloned := cloneProof(proof)
	if cloned.AnchorResult == nil {
		fatalf("%s: proof has no anchor result", name)
	}
	raw, err := fiscobcos.UnmarshalProof(cloned.AnchorResult.Proof)
	if err != nil {
		fatalf("%s: decode BCOS proof: %v", name, err)
	}
	mutate(&raw)
	cloned.AnchorResult.Proof, err = fiscobcos.MarshalProof(raw)
	if err != nil {
		fatalf("%s: re-encode BCOS proof: %v", name, err)
	}
	return expectFailure(name, content, cloned, trust, stage)
}

func expectFailure(
	name string,
	content []byte,
	proof model.SingleProof,
	trust sproof.OfflineTrust,
	stage string,
) verificationCase {
	result, err := sproof.VerifyOffline(bytes.NewReader(content), proof, trust, sproof.OfflineOptions{})
	if err == nil || result.Valid {
		fatalf("%s unexpectedly verified", name)
	}
	requireStage(result, stage, sproof.OfflineStageFailed)
	return verificationCase{
		Name: name, Valid: false, ExpectedStage: stage, Stages: result.Stages, Error: err.Error(),
	}
}

func requireStage(result sproof.OfflineResult, name string, status sproof.OfflineStageStatus) {
	for _, stage := range result.Stages {
		if stage.Name == name {
			if stage.Status != status {
				fatalf("stage %s=%s, want %s", name, stage.Status, status)
			}
			return
		}
	}
	fatalf("stage %s is missing", name)
}

func cloneProof(proof model.SingleProof) model.SingleProof {
	encoded, err := sproof.Marshal(proof)
	if err != nil {
		fatalf("clone proof encode: %v", err)
	}
	cloned, err := sproof.Unmarshal(encoded)
	if err != nil {
		fatalf("clone proof decode: %v", err)
	}
	return cloned
}

func readJSON(path string, destination any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, strings.TrimSpace(format)+"\n", arguments...)
	os.Exit(1)
}
