package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
)

func TestReadGlobalProofFileExplainsAnchorResultMixup(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sth-1.tdanchor-result")
	writeCBORForTest(t, path, model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		TreeSize:      1,
		SinkName:      "ots",
		AnchorID:      "ots-test",
		RootHash:      []byte{1, 2, 3},
		STH: model.SignedTreeHead{
			SchemaVersion: model.SchemaSignedTreeHead,
			TreeSize:      1,
			RootHash:      []byte{1, 2, 3},
		},
	})

	var proof model.GlobalLogProof
	err := readGlobalProofFile(path, &proof)
	if err == nil {
		t.Fatal("readGlobalProofFile() error = nil, want type hint")
	}
	msg := err.Error()
	if !strings.Contains(msg, "STHAnchorResult") || !strings.Contains(msg, ".tdanchor-result") || !strings.Contains(msg, ".tdgproof") {
		t.Fatalf("error message = %q, want actionable file type hint", msg)
	}
}

func TestReadGlobalProofFileExplainsLegacyBatchAnchorMixup(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "batch-old.tdanchor-result")
	writeCBORForTest(t, path, map[string]any{
		"anchor_id":  "ots-old",
		"batch_root": []byte{1, 2, 3},
		"proof":      []byte(`{"schema_version":"trustdb.anchor-ots-proof.v1"}`),
	})

	var proof model.GlobalLogProof
	err := readGlobalProofFile(path, &proof)
	if err == nil {
		t.Fatal("readGlobalProofFile() error = nil, want legacy hint")
	}
	msg := err.Error()
	if !strings.Contains(msg, "legacy batch anchor") || !strings.Contains(msg, "GlobalLogProof") {
		t.Fatalf("error message = %q, want legacy batch-anchor hint", msg)
	}
}

func TestReadSingleProofFileRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sample.sproof")
	writeCBORForTest(t, path, model.SingleProof{
		SchemaVersion:   model.SchemaSingleProof,
		FormatVersion:   1,
		RecordID:        "rec-1",
		ProofLevel:      "L3",
		ExportedAtUnixN: 1,
		ProofBundle: model.ProofBundle{
			SchemaVersion: model.SchemaProofBundle,
			RecordID:      "rec-1",
		},
	})

	var proof model.SingleProof
	if err := readSingleProofFile(path, &proof); err != nil {
		t.Fatalf("readSingleProofFile() error = %v", err)
	}
	if proof.SchemaVersion != model.SchemaSingleProof || proof.RecordID != "rec-1" || proof.ProofBundle.RecordID != "rec-1" {
		t.Fatalf("decoded single proof = %+v, want bundled artefacts", proof)
	}
}

func TestReadProofBundleFileExplainsSingleProofMixup(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sample.sproof")
	writeCBORForTest(t, path, model.SingleProof{
		SchemaVersion: model.SchemaSingleProof,
		FormatVersion: 1,
		RecordID:      "rec-1",
		ProofLevel:    "L3",
		ProofBundle: model.ProofBundle{
			SchemaVersion: model.SchemaProofBundle,
			RecordID:      "rec-1",
		},
	})

	var bundle model.ProofBundle
	err := readProofBundleFile(path, &bundle)
	if err == nil {
		t.Fatal("readProofBundleFile() error = nil, want single-proof hint")
	}
	msg := err.Error()
	if !strings.Contains(msg, ".sproof") || !strings.Contains(msg, "main .sproof input") {
		t.Fatalf("error message = %q, want single-proof hint", msg)
	}
}

func TestReadProofBundleFileRejectsOversizedInput(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "oversized.tdproof")
	if err := os.WriteFile(path, make([]byte, cborx.DefaultMaxBytes+1), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var bundle model.ProofBundle
	err := readProofBundleFile(path, &bundle)
	if err == nil || !strings.Contains(err.Error(), "payload too large") {
		t.Fatalf("readProofBundleFile() error = %v, want payload too large", err)
	}
}

func writeCBORForTest(t *testing.T, path string, v any) {
	t.Helper()
	data, err := cborx.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
