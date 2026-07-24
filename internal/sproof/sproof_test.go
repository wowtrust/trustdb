package sproof

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/globallog"
	"github.com/wowtrust/trustdb/internal/model"
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

func TestValidateStrictlyDecodesFISCOBCOSProviderProof(t *testing.T) {
	t.Parallel()

	proof := vectorProof()
	proof.ProofLevel = "L5"
	proof.NodeID = "node-1"
	proof.LogID = "log-1"
	proof.ProofBundle.NodeID = proof.NodeID
	proof.ProofBundle.LogID = proof.LogID
	proof.ProofBundle.CommittedReceipt = model.CommittedReceipt{
		BatchID: "batch-1", BatchRoot: make([]byte, 32), ClosedAtUnixN: 7,
	}
	proof.ProofBundle.BatchProof = model.BatchProof{TreeSize: 1}
	leaf := model.GlobalLogLeaf{
		SchemaVersion: model.SchemaGlobalLogLeaf, NodeID: proof.NodeID, LogID: proof.LogID,
		BatchID: "batch-1", BatchRoot: make([]byte, 32), BatchTreeSize: 1, BatchClosedAtUnixN: 7,
	}
	leafHash, err := globallog.HashLeaf(leaf)
	if err != nil {
		t.Fatal(err)
	}
	sth := model.SignedTreeHead{
		SchemaVersion: model.SchemaSignedTreeHead, TreeAlg: cryptosuite.MerkleRFC6962SHA256,
		TreeSize: 1, RootHash: leafHash, TimestampUnixN: 8, NodeID: proof.NodeID, LogID: proof.LogID,
		Signature: model.Signature{Alg: cryptosuite.SignatureEd25519, KeyID: "server", Signature: []byte{1}},
	}
	proof.GlobalProof = &model.GlobalLogProof{
		SchemaVersion: model.SchemaGlobalLogProof, NodeID: proof.NodeID, LogID: proof.LogID,
		BatchID: "batch-1", LeafIndex: 0, LeafHash: leafHash, TreeSize: 1, STH: sth,
	}
	proof.AnchorResult = &model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult, NodeID: proof.NodeID, LogID: proof.LogID,
		TreeSize: 1, SinkName: fiscobcos.SinkName, AnchorID: strings.Repeat("0", 64),
		RootHash: leafHash, STH: sth, Proof: []byte{0xa1, 0x61, 0x78, 0x01}, PublishedAtUnixN: 9,
	}
	if err := Validate(proof); err == nil || !strings.Contains(err.Error(), "FISCO BCOS") {
		t.Fatalf("Validate() error = %v, want strict FISCO BCOS proof decoding failure", err)
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

func TestWriteFileRoundTripUsesPrivateMode(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proof.sproof")
	proof := vectorProof()
	if err := WriteFile(path, proof); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	equal, err := EqualEncoded(got, proof)
	if err != nil {
		t.Fatalf("EqualEncoded() error = %v", err)
	}
	if !equal {
		t.Fatalf("decoded proof = %+v, want vector proof", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestWriteFileCleansTemporaryFileOnFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "existing-dir")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := WriteFile(target, vectorProof()); err == nil {
		t.Fatal("WriteFile() error = nil, want failure when target is a directory")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat(target) error = %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("target was replaced; mode=%s", info.Mode())
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".existing-dir.*.tmp"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files left behind: %v", matches)
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
