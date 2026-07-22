package proofstore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestOpenFileBackendInitializesAndRequiresCurrentSchema(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "proofs")

	if _, err := Open(Config{Kind: BackendFile, Path: root}); err != nil {
		t.Fatalf("Open(file) error = %v", err)
	}
	data, err := readStoredFileLimit(filepath.Join(root, localStorageSchemaFile), 1024)
	if err != nil {
		t.Fatalf("read schema marker: %v", err)
	}
	var schema string
	if err := cborx.UnmarshalLimit(data, &schema, 1024); err != nil {
		t.Fatalf("decode schema marker: %v", err)
	}
	if schema != localStorageSchemaV4 {
		t.Fatalf("schema = %q, want %q", schema, localStorageSchemaV4)
	}
	if _, err := Open(Config{Kind: BackendFile, Path: root}); err != nil {
		t.Fatalf("reopen current file schema: %v", err)
	}
}

func TestOpenFileBackendRejectsUnversionedData(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "proofs")
	legacyPath := filepath.Join(root, "anchor", "sth-outbox", "pending", "00000000000000000001.tdsth-anchor")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o755); err != nil {
		t.Fatalf("create legacy directory: %v", err)
	}
	if err := os.WriteFile(legacyPath, []byte("legacy"), 0o600); err != nil {
		t.Fatalf("seed legacy queue item: %v", err)
	}

	if _, err := Open(Config{Kind: BackendFile, Path: root}); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("Open(unversioned file) code=%s err=%v, want failed_precondition", trusterr.CodeOf(err), err)
	}
}

func TestOpenFileBackendRejectsLegacySchema(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "proofs")
	if err := writeCBORAtomic(filepath.Join(root, localStorageSchemaFile), "trustdb-proofstore-v3"); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}

	if _, err := Open(Config{Kind: BackendFile, Path: root}); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("Open(v3 file) code=%s err=%v, want failed_precondition", trusterr.CodeOf(err), err)
	}
}

func TestOpenTiKVBackendRequiresPDEndpoints(t *testing.T) {
	t.Parallel()

	if _, err := Open(Config{Kind: BackendTiKV}); trusterr.CodeOf(err) != trusterr.CodeInvalidArgument {
		t.Fatalf("Open(tikv without PD) error code = %s, want %s", trusterr.CodeOf(err), trusterr.CodeInvalidArgument)
	}
}
