package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
)

func seedGlobalLogForCLI(t *testing.T, proofDir string) {
	t.Helper()
	store, err := proofstore.Open(proofstore.Config{Kind: proofstore.BackendFile, Path: proofDir})
	if err != nil {
		t.Fatalf("open file proofstore: %v", err)
	}
	ctx := context.Background()
	leafHash := bytes.Repeat([]byte{0x42}, 32)
	leaf := model.GlobalLogLeaf{
		SchemaVersion:      model.SchemaGlobalLogLeaf,
		BatchID:            "batch-1",
		BatchRoot:          bytes.Repeat([]byte{0x11}, 32),
		BatchTreeSize:      1,
		BatchClosedAtUnixN: 100,
		LeafIndex:          0,
		LeafHash:           leafHash,
		AppendedAtUnixN:    101,
	}
	if err := store.PutGlobalLeaf(ctx, leaf); err != nil {
		t.Fatalf("PutGlobalLeaf: %v", err)
	}
	sth := model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       1,
		RootHash:       leafHash,
		TimestampUnixN: 102,
		LogID:          "test-log",
	}
	if err := store.PutSignedTreeHead(ctx, sth); err != nil {
		t.Fatalf("PutSignedTreeHead: %v", err)
	}
}

func TestGlobalLogInclusionCommand_DefaultsToJSONStdout(t *testing.T) {
	t.Parallel()

	proofDir := filepath.Join(t.TempDir(), "proofs")
	seedGlobalLogForCLI(t, proofDir)

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{
		"global-log", "proof", "inclusion",
		"--batch-id", "batch-1",
		"--metastore-path", proofDir,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("global-log proof inclusion: %v stderr=%s", err, errOut.String())
	}
	var proof model.GlobalLogProof
	if err := json.Unmarshal(out.Bytes(), &proof); err != nil {
		t.Fatalf("stdout is not GlobalLogProof JSON: %q err=%v", out.String(), err)
	}
	if proof.SchemaVersion != model.SchemaGlobalLogProof || proof.BatchID != "batch-1" || proof.TreeSize != 1 {
		t.Fatalf("unexpected proof: %+v", proof)
	}
}

func TestGlobalLogInclusionCommand_ExportsCBORForOfflineVerify(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	proofDir := filepath.Join(tmp, "proofs")
	outPath := filepath.Join(tmp, "batch-1.tdgproof")
	seedGlobalLogForCLI(t, proofDir)

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{
		"global-log", "proof", "inclusion",
		"--batch-id", "batch-1",
		"--metastore-path", proofDir,
		"--out", outPath,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("global-log proof inclusion --out: %v stderr=%s", err, errOut.String())
	}
	var report struct {
		BatchID     string `json:"batch_id"`
		TreeSize    uint64 `json:"tree_size"`
		GlobalProof string `json:"global_proof"`
		Format      string `json:"format"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("report is not JSON: %q err=%v", out.String(), err)
	}
	if report.BatchID != "batch-1" || report.TreeSize != 1 || report.GlobalProof != outPath || report.Format != "cbor" {
		t.Fatalf("unexpected export report: %+v", report)
	}
	var proof model.GlobalLogProof
	if err := readCBORFile(outPath, &proof); err != nil {
		t.Fatalf("read exported cbor proof: %v", err)
	}
	if proof.SchemaVersion != model.SchemaGlobalLogProof || proof.BatchID != "batch-1" || proof.TreeSize != 1 {
		t.Fatalf("exported proof = %+v", proof)
	}
}
