package sproof

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/prooflevel"
	"github.com/wowtrust/trustdb/internal/verify"
)

const (
	FormatVersion = 1
	MaxBytes      = 16 << 20
)

type Options struct {
	GlobalProof     *model.GlobalLogProof
	AnchorResult    *model.STHAnchorResult
	ExportedAtUnixN int64
}

// New builds a stable .sproof v1 envelope. ProofLevel is descriptive only;
// verifiers must recompute the level from the bundled evidence.
func New(bundle model.ProofBundle, opts Options) (model.SingleProof, error) {
	proof := model.SingleProof{
		SchemaVersion:   model.SchemaSingleProof,
		FormatVersion:   FormatVersion,
		RecordID:        bundle.RecordID,
		ProofBundle:     bundle,
		NodeID:          bundle.NodeID,
		LogID:           bundle.LogID,
		GlobalProof:     opts.GlobalProof,
		AnchorResult:    opts.AnchorResult,
		ExportedAtUnixN: opts.ExportedAtUnixN,
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
	if proof.AnchorResult != nil {
		evidence.STHAnchorResult = true
	}
	return prooflevel.Evaluate(evidence)
}

func Validate(proof model.SingleProof) error {
	if proof.SchemaVersion != model.SchemaSingleProof {
		return fmt.Errorf("sproof: unexpected schema_version %q", proof.SchemaVersion)
	}
	if proof.FormatVersion != FormatVersion {
		return fmt.Errorf("sproof: unsupported format_version %d", proof.FormatVersion)
	}
	if proof.ProofBundle.SchemaVersion != model.SchemaProofBundle {
		return fmt.Errorf("sproof: proof_bundle schema_version=%q, want %q",
			proof.ProofBundle.SchemaVersion,
			model.SchemaProofBundle,
		)
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
	if proof.NodeID != "" && proof.ProofBundle.NodeID != "" && proof.NodeID != proof.ProofBundle.NodeID {
		return fmt.Errorf("sproof: node_id mismatch: envelope=%s proof_bundle=%s", proof.NodeID, proof.ProofBundle.NodeID)
	}
	if proof.LogID != "" && proof.ProofBundle.LogID != "" && proof.LogID != proof.ProofBundle.LogID {
		return fmt.Errorf("sproof: log_id mismatch: envelope=%s proof_bundle=%s", proof.LogID, proof.ProofBundle.LogID)
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
		if err := verify.GlobalLogConsistency(proof.ProofBundle, *proof.GlobalProof); err != nil {
			return fmt.Errorf("sproof: global_proof: %w", err)
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
		if err := verify.AnchorConsistency(*proof.GlobalProof, *proof.AnchorResult); err != nil {
			return fmt.Errorf("sproof: anchor_result: %w", err)
		}
	}
	return nil
}

func Marshal(proof model.SingleProof) ([]byte, error) {
	if err := Validate(proof); err != nil {
		return nil, err
	}
	return cborx.Marshal(proof)
}

func Unmarshal(data []byte) (model.SingleProof, error) {
	var proof model.SingleProof
	if err := cborx.UnmarshalLimit(data, &proof, MaxBytes); err != nil {
		return model.SingleProof{}, err
	}
	if err := Validate(proof); err != nil {
		return model.SingleProof{}, err
	}
	return proof, nil
}

func ReadFile(path string) (model.SingleProof, error) {
	f, err := os.Open(path)
	if err != nil {
		return model.SingleProof{}, err
	}
	defer f.Close()
	var proof model.SingleProof
	if err := cborx.DecodeReaderLimit(f, &proof, MaxBytes); err != nil {
		return model.SingleProof{}, fmt.Errorf("read sproof %s: %w", filepath.Base(path), err)
	}
	if err := Validate(proof); err != nil {
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

func Digest(proof model.SingleProof) ([32]byte, error) {
	data, err := Marshal(proof)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
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
