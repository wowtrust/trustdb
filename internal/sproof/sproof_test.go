package sproof

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryan-wong-coder/trustdb/internal/model"
)

func TestNewL3SingleProof(t *testing.T) {
	t.Parallel()

	proof, err := New(vectorProof().ProofBundle, Options{ExportedAtUnixN: 1_700_000_000_000_000_000})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if proof.SchemaVersion != model.SchemaSingleProof {
		t.Fatalf("SchemaVersion = %q", proof.SchemaVersion)
	}
	if proof.FormatVersion != FormatVersion {
		t.Fatalf("FormatVersion = %d, want %d", proof.FormatVersion, FormatVersion)
	}
	if proof.RecordID != "rec-vector-1" || proof.ProofLevel != "L3" {
		t.Fatalf("proof metadata = %+v", proof)
	}
}

func TestValidateRejectsAnchorWithoutGlobalProof(t *testing.T) {
	t.Parallel()

	proof := vectorProof()
	proof.AnchorResult = &model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		TreeSize:      1,
		AnchorID:      "anchor-1",
	}
	if err := Validate(proof); err == nil || !strings.Contains(err.Error(), "requires global_proof") {
		t.Fatalf("Validate() error = %v, want global_proof requirement", err)
	}
}

func TestValidateRejectsDriftedEnvelopeMetadata(t *testing.T) {
	t.Parallel()

	proof := vectorProof()
	proof.RecordID = "other-record"
	if err := Validate(proof); err == nil || !strings.Contains(err.Error(), "record_id mismatch") {
		t.Fatalf("Validate() error = %v, want record_id mismatch", err)
	}

	proof = vectorProof()
	proof.ProofLevel = "L5"
	if err := Validate(proof); err == nil || !strings.Contains(err.Error(), "proof_level") {
		t.Fatalf("Validate() error = %v, want proof_level mismatch", err)
	}
}

func TestSProofV1L3Vector(t *testing.T) {
	t.Parallel()

	proof := vectorProof()
	data, err := Marshal(proof)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	vectorPath := filepath.Join("..", "..", "test", "vectors", "sproof-v1-l3.cbor")
	hashPath := filepath.Join("..", "..", "test", "vectors", "sproof-v1-l3.sha256")
	if os.Getenv("TRUSTDB_UPDATE_VECTORS") == "1" {
		if err := os.MkdirAll(filepath.Dir(vectorPath), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(vectorPath, data, 0o600); err != nil {
			t.Fatalf("write vector: %v", err)
		}
		sum := sha256.Sum256(data)
		if err := os.WriteFile(hashPath, []byte(hex.EncodeToString(sum[:])+"\n"), 0o600); err != nil {
			t.Fatalf("write vector hash: %v", err)
		}
	}

	fixture, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	if string(fixture) != string(data) {
		t.Fatal("encoded .sproof vector changed; update docs and run with TRUSTDB_UPDATE_VECTORS=1 if intentional")
	}
	wantHash, err := os.ReadFile(hashPath)
	if err != nil {
		t.Fatalf("read vector hash: %v", err)
	}
	sum := sha256.Sum256(fixture)
	if got := hex.EncodeToString(sum[:]); got != strings.TrimSpace(string(wantHash)) {
		t.Fatalf("vector sha256 = %s, want %s", got, strings.TrimSpace(string(wantHash)))
	}
	decoded, err := Unmarshal(fixture)
	if err != nil {
		t.Fatalf("Unmarshal(vector) error = %v", err)
	}
	equal, err := EqualEncoded(decoded, proof)
	if err != nil {
		t.Fatalf("EqualEncoded() error = %v", err)
	}
	if !equal {
		t.Fatal("decoded vector does not re-encode deterministically")
	}
}

func TestReadFileRejectsOversizedSingleProof(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "oversized.sproof")
	if err := os.WriteFile(path, make([]byte, MaxBytes+1), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := ReadFile(path); err == nil {
		t.Fatal("ReadFile() error = nil, want oversized invalid proof rejection")
	}
}

func vectorProof() model.SingleProof {
	return model.SingleProof{
		SchemaVersion:   model.SchemaSingleProof,
		FormatVersion:   FormatVersion,
		RecordID:        "rec-vector-1",
		ProofLevel:      "L3",
		ExportedAtUnixN: 1_700_000_000_000_000_000,
		ProofBundle: model.ProofBundle{
			SchemaVersion: model.SchemaProofBundle,
			RecordID:      "rec-vector-1",
		},
	}
}
