package sproof

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/formatregistry"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/modelsuite"
	"github.com/wowtrust/trustdb/internal/prooflevel"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"github.com/wowtrust/trustdb/internal/verify"
)

const (
	FormatVersion = 2
	MaxBytes      = formatregistry.MaxSingleProofBytesV2

	MaxIdentityEvidence       = 16
	MaxCertificateStatuses    = formatregistry.MaxCertificateCountV2
	MaxCertificateStatusBytes = 4 << 20
	MaxRegistryEvidenceBytes  = 8 << 20
	MaxCollectionElements     = 4096
	MaxMapPairs               = 4096
)

type Options struct {
	GlobalProof      *model.GlobalLogProof
	AnchorResult     *model.STHAnchorResult
	IdentityEvidence []model.ProofIdentityEvidence
	ExportedAtUnixN  int64
}

// New builds a stable .sproof v2 envelope. ProofLevel is descriptive only;
// verifiers must recompute the level from the bundled evidence.
func New(bundle model.ProofBundle, opts Options) (model.SingleProof, error) {
	if err := requireWritableGeneration(bundle.CryptoSuite); err != nil {
		return model.SingleProof{}, err
	}
	proof := model.SingleProof{
		SchemaVersion:    model.SchemaSingleProof,
		FormatVersion:    FormatVersion,
		CryptoSuite:      bundle.CryptoSuite,
		RecordID:         bundle.RecordID,
		ProofBundle:      bundle,
		NodeID:           bundle.NodeID,
		LogID:            bundle.LogID,
		GlobalProof:      opts.GlobalProof,
		AnchorResult:     opts.AnchorResult,
		IdentityEvidence: cloneIdentityEvidence(opts.IdentityEvidence),
		ExportedAtUnixN:  opts.ExportedAtUnixN,
	}
	proof.ProofLevel = Level(proof).String()
	if err := Validate(proof); err != nil {
		return model.SingleProof{}, err
	}
	return proof, nil
}

func Level(proof model.SingleProof) prooflevel.Level {
	evidence := prooflevel.EvidenceFor(prooflevel.L3)
	if proof.GlobalProof != nil {
		evidence.GlobalLogProof = true
	}
	if proof.AnchorResult != nil && model.AnchorResultProvidesOfflineL5(*proof.AnchorResult) {
		evidence.STHAnchorResult = true
	}
	return prooflevel.Evaluate(evidence)
}

func Validate(proof model.SingleProof) error {
	if err := validateContainer(proof); err != nil {
		return err
	}
	if err := validateGlobalEvidence(proof); err != nil {
		return err
	}
	if err := validateAnchorEvidence(proof); err != nil {
		return err
	}
	if err := validateIdentityEvidenceDetails(proof); err != nil {
		return err
	}
	return nil
}

// validateContainer enforces only the format boundary needed before staged
// offline verification: schema, suite, namespace envelope, component presence,
// and allocation limits. Cryptographic and identity semantics are deliberately
// left to their named verification stages.
func validateContainer(proof model.SingleProof) error {
	if proof.SchemaVersion != model.SchemaSingleProof {
		return fmt.Errorf("sproof: unexpected schema_version %q", proof.SchemaVersion)
	}
	if proof.FormatVersion != FormatVersion {
		return fmt.Errorf("sproof: unsupported format_version %d", proof.FormatVersion)
	}
	if err := requireWritableGeneration(proof.CryptoSuite); err != nil {
		return err
	}
	if proof.ProofBundle.SchemaVersion != model.SchemaProofBundle {
		return fmt.Errorf("sproof: proof_bundle schema_version=%q, want %q",
			proof.ProofBundle.SchemaVersion,
			model.SchemaProofBundle,
		)
	}
	if err := modelsuite.Require(proof.CryptoSuite, proof.ProofBundle); err != nil {
		return fmt.Errorf("sproof: proof_bundle crypto_suite: %w", err)
	}
	if proof.ProofBundle.RecordID == "" {
		return errors.New("sproof: proof_bundle record_id is required")
	}
	if proof.RecordID == "" {
		return errors.New("sproof: record_id is required")
	}
	if proof.RecordID != proof.ProofBundle.RecordID {
		return fmt.Errorf("sproof: record_id mismatch: envelope=%s proof_bundle=%s",
			proof.RecordID,
			proof.ProofBundle.RecordID,
		)
	}
	if proof.NodeID == "" || proof.LogID == "" {
		return errors.New("sproof: node_id and log_id are required")
	}
	if proof.ProofBundle.NodeID == "" || proof.ProofBundle.NodeID != proof.NodeID {
		return fmt.Errorf("sproof: node_id mismatch: envelope=%s proof_bundle=%s", proof.NodeID, proof.ProofBundle.NodeID)
	}
	if proof.ProofBundle.LogID == "" || proof.ProofBundle.LogID != proof.LogID {
		return fmt.Errorf("sproof: log_id mismatch: envelope=%s proof_bundle=%s", proof.LogID, proof.ProofBundle.LogID)
	}
	if proof.AnchorResult != nil && len(proof.AnchorResult.Proof) > formatregistry.MaxAnchorEvidenceBytesV2 {
		return fmt.Errorf(
			"sproof: anchor_result proof exceeds %d bytes",
			formatregistry.MaxAnchorEvidenceBytesV2,
		)
	}
	if proof.ProofLevel != "" && proof.ProofLevel != Level(proof).String() {
		return fmt.Errorf("sproof: proof_level=%s does not match embedded evidence level=%s",
			proof.ProofLevel,
			Level(proof),
		)
	}
	if proof.GlobalProof != nil {
		if proof.GlobalProof.SchemaVersion != model.SchemaGlobalLogProof {
			return fmt.Errorf("sproof: global_proof schema_version=%q, want %q",
				proof.GlobalProof.SchemaVersion,
				model.SchemaGlobalLogProof,
			)
		}
		if err := modelsuite.Require(proof.CryptoSuite, *proof.GlobalProof); err != nil {
			return fmt.Errorf("sproof: global_proof crypto_suite: %w", err)
		}
	}
	if proof.AnchorResult != nil {
		if proof.AnchorResult.SchemaVersion != model.SchemaSTHAnchorResult {
			return fmt.Errorf("sproof: anchor_result schema_version=%q, want %q",
				proof.AnchorResult.SchemaVersion,
				model.SchemaSTHAnchorResult,
			)
		}
		if proof.GlobalProof == nil {
			return errors.New("sproof: anchor_result requires global_proof")
		}
		if err := modelsuite.Require(proof.CryptoSuite, *proof.AnchorResult); err != nil {
			return fmt.Errorf("sproof: anchor_result crypto_suite: %w", err)
		}
		if proof.AnchorResult.SinkName == fiscobcos.SinkName {
			if _, err := fiscobcos.UnmarshalProof(proof.AnchorResult.Proof); err != nil {
				return fmt.Errorf("sproof: FISCO BCOS anchor_result container: %w", err)
			}
		}
	}
	if err := validateIdentityEvidenceEnvelope(proof); err != nil {
		return err
	}
	return nil
}

func validateGlobalEvidence(proof model.SingleProof) error {
	if proof.GlobalProof == nil {
		return nil
	}
	if proof.GlobalProof.NodeID == "" || proof.GlobalProof.NodeID != proof.NodeID ||
		proof.GlobalProof.STH.NodeID == "" || proof.GlobalProof.STH.NodeID != proof.NodeID {
		return errors.New("sproof: global_proof node_id does not exactly match the envelope")
	}
	if proof.GlobalProof.LogID == "" || proof.GlobalProof.LogID != proof.LogID ||
		proof.GlobalProof.STH.LogID == "" || proof.GlobalProof.STH.LogID != proof.LogID {
		return errors.New("sproof: global_proof log_id does not exactly match the envelope")
	}
	if err := verify.GlobalLogConsistencyForSuite(proof.ProofBundle, *proof.GlobalProof); err != nil {
		return fmt.Errorf("sproof: global_proof: %w", err)
	}
	return nil
}

func validateAnchorEvidence(proof model.SingleProof) error {
	if proof.AnchorResult == nil {
		return nil
	}
	if proof.AnchorResult.NodeID == "" || proof.AnchorResult.NodeID != proof.NodeID ||
		proof.AnchorResult.STH.NodeID == "" || proof.AnchorResult.STH.NodeID != proof.NodeID {
		return errors.New("sproof: anchor_result node_id does not exactly match the envelope")
	}
	if proof.AnchorResult.LogID == "" || proof.AnchorResult.LogID != proof.LogID ||
		proof.AnchorResult.STH.LogID == "" || proof.AnchorResult.STH.LogID != proof.LogID {
		return errors.New("sproof: anchor_result log_id does not exactly match the envelope")
	}
	if isRawFISCOBCOSProof(proof) {
		if err := fiscobcos.ValidateProofContainer(proof.GlobalProof.STH, *proof.AnchorResult); err != nil {
			return fmt.Errorf("sproof: FISCO BCOS anchor_result: %w", err)
		}
		return nil
	}
	if err := verify.AnchorContainerConsistency(*proof.GlobalProof, *proof.AnchorResult); err != nil {
		return fmt.Errorf("sproof: anchor_result: %w", err)
	}
	if proof.AnchorResult.SinkName == fiscobcos.SinkName {
		if err := fiscobcos.ValidateProofContainer(proof.GlobalProof.STH, *proof.AnchorResult); err != nil {
			return fmt.Errorf("sproof: FISCO BCOS anchor_result: %w", err)
		}
	}
	return nil
}

func isRawFISCOBCOSProof(proof model.SingleProof) bool {
	return proof.AnchorResult != nil &&
		proof.AnchorResult.SinkName == fiscobcos.SinkName &&
		proof.AnchorResult.EvidenceStage == model.AnchorEvidenceStageRaw
}

func validateIdentityEvidenceEnvelope(proof model.SingleProof) error {
	if len(proof.IdentityEvidence) > MaxIdentityEvidence {
		return fmt.Errorf("sproof: identity_evidence count exceeds %d", MaxIdentityEvidence)
	}
	clientKeys := map[string]struct{}{
		proof.ProofBundle.SignedClaim.Signature.KeyID: {},
	}
	serverKeys := map[string]struct{}{
		proof.ProofBundle.AcceptedReceipt.ServerSig.KeyID:  {},
		proof.ProofBundle.CommittedReceipt.ServerSig.KeyID: {},
	}
	if proof.GlobalProof != nil {
		serverKeys[proof.GlobalProof.STH.Signature.KeyID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(proof.IdentityEvidence))
	for index := range proof.IdentityEvidence {
		evidence := proof.IdentityEvidence[index]
		if evidence.SchemaVersion != model.SchemaProofIdentity {
			return fmt.Errorf("sproof: identity_evidence[%d] has unexpected schema_version %q", index, evidence.SchemaVersion)
		}
		if err := cryptosuite.RequireSame(proof.CryptoSuite, evidence.CryptoSuite); err != nil {
			return fmt.Errorf("sproof: identity_evidence[%d] crypto_suite: %w", index, err)
		}
		if evidence.KeyID == "" {
			return fmt.Errorf("sproof: identity_evidence[%d] key_id is required", index)
		}
		var expected map[string]struct{}
		switch evidence.Role {
		case model.ProofIdentityRoleClient:
			expected = clientKeys
		case model.ProofIdentityRoleServer:
			expected = serverKeys
		default:
			return fmt.Errorf("sproof: identity_evidence[%d] role %q is unsupported", index, evidence.Role)
		}
		if _, ok := expected[evidence.KeyID]; !ok {
			return fmt.Errorf("sproof: identity_evidence[%d] key_id %q is not referenced by the %s signatures", index, evidence.KeyID, evidence.Role)
		}
		identityKey := evidence.Role + "\x00" + evidence.KeyID
		if _, duplicate := seen[identityKey]; duplicate {
			return fmt.Errorf("sproof: duplicate identity evidence for %s key %q", evidence.Role, evidence.KeyID)
		}
		seen[identityKey] = struct{}{}

		if len(evidence.RegistryV2) > MaxRegistryEvidenceBytes {
			return fmt.Errorf("sproof: identity_evidence[%d] registry_v2 exceeds %d bytes", index, MaxRegistryEvidenceBytes)
		}
		if len(evidence.RegistryV2) != 0 {
			if evidence.Role != model.ProofIdentityRoleClient {
				return fmt.Errorf("sproof: identity_evidence[%d] registry_v2 is allowed only for a client identity", index)
			}
			if !bytes.HasPrefix(evidence.RegistryV2, []byte("TDBKEYR2\n")) {
				return fmt.Errorf("sproof: identity_evidence[%d] registry_v2 has an unsupported format", index)
			}
		}
		if len(evidence.CertificateStatuses) > MaxCertificateStatuses {
			return fmt.Errorf("sproof: identity_evidence[%d] certificate status count exceeds %d", index, MaxCertificateStatuses)
		}
		statusIssuers := make(map[string]struct{}, len(evidence.CertificateStatuses))
		for statusIndex := range evidence.CertificateStatuses {
			status := evidence.CertificateStatuses[statusIndex]
			if status.SchemaVersion != model.SchemaCertificateStatus {
				return fmt.Errorf("sproof: identity_evidence[%d] certificate_statuses[%d] has unexpected schema_version %q", index, statusIndex, status.SchemaVersion)
			}
			if err := cryptosuite.RequireSame(proof.CryptoSuite, status.CryptoSuite); err != nil {
				return fmt.Errorf("sproof: identity_evidence[%d] certificate_statuses[%d] crypto_suite: %w", index, statusIndex, err)
			}
			if status.Type != model.CertificateStatusCRL {
				return fmt.Errorf("sproof: identity_evidence[%d] certificate_statuses[%d] type %q is unsupported", index, statusIndex, status.Type)
			}
			if len(status.IssuerFingerprint) != cryptosuite.DigestSize {
				return fmt.Errorf("sproof: identity_evidence[%d] certificate_statuses[%d] issuer fingerprint length is invalid", index, statusIndex)
			}
			if len(status.Status) == 0 || len(status.Status) > MaxCertificateStatusBytes {
				return fmt.Errorf("sproof: identity_evidence[%d] certificate_statuses[%d] status size is invalid", index, statusIndex)
			}
			issuerKey := string(status.IssuerFingerprint)
			if _, duplicate := statusIssuers[issuerKey]; duplicate {
				return fmt.Errorf("sproof: identity_evidence[%d] contains duplicate status for one certificate issuer", index)
			}
			statusIssuers[issuerKey] = struct{}{}
		}
	}
	return nil
}

func validateIdentityEvidenceDetails(proof model.SingleProof) error {
	for index := range proof.IdentityEvidence {
		evidence := proof.IdentityEvidence[index]
		descriptor, err := keydescriptor.Unmarshal(evidence.KeyDescriptor)
		if err != nil {
			return fmt.Errorf("sproof: identity_evidence[%d] key_descriptor: %w", index, err)
		}
		if descriptor.Kind != keydescriptor.KindVerifier || descriptor.Provider != keydescriptor.ProviderPublic {
			return fmt.Errorf("sproof: identity_evidence[%d] must contain a public verifier descriptor", index)
		}
		if descriptor.CryptoSuite != proof.CryptoSuite || descriptor.KeyID != evidence.KeyID {
			return fmt.Errorf("sproof: identity_evidence[%d] descriptor binding mismatch", index)
		}
		if len(evidence.CertificateStatuses) != 0 && len(descriptor.CertificateChain) == 0 {
			return fmt.Errorf("sproof: identity_evidence[%d] certificate statuses require a certificate chain", index)
		}
	}
	return nil
}

func cloneIdentityEvidence(in []model.ProofIdentityEvidence) []model.ProofIdentityEvidence {
	out := make([]model.ProofIdentityEvidence, len(in))
	for index := range in {
		out[index] = in[index]
		out[index].KeyDescriptor = append([]byte(nil), in[index].KeyDescriptor...)
		out[index].RegistryV2 = append([]byte(nil), in[index].RegistryV2...)
		out[index].CertificateStatuses = make([]model.CertificateStatusEvidence, len(in[index].CertificateStatuses))
		for statusIndex := range in[index].CertificateStatuses {
			out[index].CertificateStatuses[statusIndex] = in[index].CertificateStatuses[statusIndex]
			out[index].CertificateStatuses[statusIndex].IssuerFingerprint = append(
				[]byte(nil),
				in[index].CertificateStatuses[statusIndex].IssuerFingerprint...,
			)
			out[index].CertificateStatuses[statusIndex].Status = append(
				[]byte(nil),
				in[index].CertificateStatuses[statusIndex].Status...,
			)
		}
	}
	return out
}

func Marshal(proof model.SingleProof) ([]byte, error) {
	if err := requireWritableGeneration(proof.CryptoSuite); err != nil {
		return nil, err
	}
	if err := Validate(proof); err != nil {
		return nil, err
	}
	return cborx.Marshal(proof)
}

func requireWritableGeneration(suiteID cryptosuite.ID) error {
	if _, _, err := formatregistry.RequireWritable(formatregistry.SingleProofV2, suiteID); err != nil {
		return trusterr.Wrap(
			trusterr.CodeFailedPrecondition,
			"sproof v2 writer is unavailable for the selected cryptographic suite",
			err,
		)
	}
	return nil
}

func Unmarshal(data []byte) (model.SingleProof, error) {
	proof, err := unmarshalContainer(data)
	if err != nil {
		return model.SingleProof{}, err
	}
	if err := Validate(proof); err != nil {
		return model.SingleProof{}, err
	}
	return proof, nil
}

func unmarshalContainer(data []byte) (model.SingleProof, error) {
	var proof model.SingleProof
	if err := cborx.UnmarshalLimits(data, &proof, MaxBytes, MaxCollectionElements, MaxMapPairs); err != nil {
		return model.SingleProof{}, err
	}
	if err := validateContainer(proof); err != nil {
		return model.SingleProof{}, err
	}
	canonical, err := cborx.Marshal(proof)
	if err != nil {
		return model.SingleProof{}, err
	}
	if !bytes.Equal(data, canonical) {
		return model.SingleProof{}, errors.New("sproof: non-canonical v2 encoding")
	}
	return proof, nil
}

func ReadFile(path string) (model.SingleProof, error) {
	return readFile(path, Unmarshal)
}

// ReadFileForVerification preserves all V2 decoding, schema, suite, size, and
// canonical-encoding gates while deferring identity and cryptographic semantics
// to VerifyOffline so failures are attributed to their named stages.
func ReadFileForVerification(path string) (model.SingleProof, error) {
	return readFile(path, unmarshalContainer)
}

func readFile(
	path string,
	decode func([]byte) (model.SingleProof, error),
) (model.SingleProof, error) {
	f, err := os.Open(path)
	if err != nil {
		return model.SingleProof{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return model.SingleProof{}, fmt.Errorf("read sproof %s: %w", filepath.Base(path), err)
	}
	if len(data) > MaxBytes {
		return model.SingleProof{}, fmt.Errorf(
			"read sproof %s: payload too large: %d > %d",
			filepath.Base(path),
			len(data),
			MaxBytes,
		)
	}
	proof, err := decode(data)
	if err != nil {
		return model.SingleProof{}, fmt.Errorf("read sproof %s: %w", filepath.Base(path), err)
	}
	return proof, nil
}

func WriteFile(path string, proof model.SingleProof) error {
	data, err := Marshal(proof)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0o600)
}

func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := renameReplace(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func renameReplace(src, dst string) error {
	if err := rejectDirectoryTarget(dst); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		if os.IsExist(err) {
			if removeErr := os.Remove(dst); removeErr == nil {
				return os.Rename(src, dst)
			}
		}
		return err
	}
	return nil
}

func rejectDirectoryTarget(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return fmt.Errorf("%s is a directory", path)
		}
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func Digest(proof model.SingleProof) ([]byte, error) {
	data, err := Marshal(proof)
	if err != nil {
		return nil, err
	}
	suite, err := cryptosuite.RequireAvailable(proof.CryptoSuite)
	if err != nil {
		return nil, err
	}
	return trustcrypto.HashBytesForSuite(proof.CryptoSuite, suite.StorageIntegrityHash.Algorithm, data)
}

func EqualEncoded(a, b model.SingleProof) (bool, error) {
	left, err := Marshal(a)
	if err != nil {
		return false, err
	}
	right, err := Marshal(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(left, right), nil
}
