package proofstore

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/proofstoremeta"
	"github.com/wowtrust/trustdb/internal/proofstoremeta/proofstoremetatest"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestFileSuiteBindingConformance(t *testing.T) {
	proofstoremetatest.Run(t, func(t *testing.T) proofstoremetatest.Harness {
		root := filepath.Join(t.TempDir(), "proofs")
		return proofstoremetatest.Harness{
			Open: func(suiteID cryptosuite.ID) (cryptosuite.ID, error) {
				store, err := Open(Config{Kind: BackendFile, Path: root, CryptoSuite: suiteID})
				if err != nil {
					return "", err
				}
				defer store.Close()
				return BoundCryptoSuite(store)
			},
			SeedUnbound: func() error {
				if err := os.MkdirAll(root, 0o755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(root, "unbound"), []byte("data"), 0o600)
			},
			WriteRawMarker: func(data []byte) error {
				if err := os.MkdirAll(root, 0o755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(root, localStorageSchemaFile), data, 0o600)
			},
		}
	})
}

func TestOpenFileBackendInitializesAndRequiresCurrentSchema(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "proofs")

	if _, err := Open(Config{Kind: BackendFile, Path: root}); err != nil {
		t.Fatalf("Open(file) error = %v", err)
	}
	data, err := readStoredFileLimit(filepath.Join(root, localStorageSchemaFile), proofstoremeta.MaxMarkerBytes)
	if err != nil {
		t.Fatalf("read schema marker: %v", err)
	}
	var marker proofstoremeta.Marker
	if err := cborx.UnmarshalLimit(data, &marker, proofstoremeta.MaxMarkerBytes); err != nil {
		t.Fatalf("decode schema marker: %v", err)
	}
	if err := proofstoremeta.Validate(marker, cryptosuite.INTLV1); err != nil {
		t.Fatalf("marker = %+v: %v", marker, err)
	}
	store, err := Open(Config{Kind: BackendFile, Path: root})
	if err != nil {
		t.Fatalf("reopen current file schema: %v", err)
	}
	defer store.Close()
	if suite, err := BoundCryptoSuite(store); err != nil || suite != cryptosuite.INTLV1 {
		t.Fatalf("BoundCryptoSuite = %q, %v", suite, err)
	}
}

func TestOpenFileBackendRejectsMissingCorruptUnknownAndMismatchedMarkers(t *testing.T) {
	t.Parallel()
	t.Run("missing on non-empty store", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "proofs")
		store, err := Open(Config{Kind: BackendFile, Path: root})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		_ = store.Close()
		if err := os.WriteFile(filepath.Join(root, "data"), []byte("present"), 0o600); err != nil {
			t.Fatalf("seed data: %v", err)
		}
		if err := os.Remove(filepath.Join(root, localStorageSchemaFile)); err != nil {
			t.Fatalf("remove marker: %v", err)
		}
		if _, err := Open(Config{Kind: BackendFile, Path: root}); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("Open missing marker code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
	t.Run("corrupt", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "proofs")
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, localStorageSchemaFile), []byte{0xff}, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(Config{Kind: BackendFile, Path: root}); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
			t.Fatalf("Open corrupt marker code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "proofs")
		marker, _ := proofstoremeta.New(cryptosuite.INTLV1)
		marker.CryptoSuite = cryptosuite.ID("UNKNOWN")
		if err := writeCBORAtomic(filepath.Join(root, localStorageSchemaFile), marker); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(Config{Kind: BackendFile, Path: root}); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("Open unknown marker code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "proofs")
		store, err := Open(Config{Kind: BackendFile, Path: root, CryptoSuite: cryptosuite.INTLV1})
		if err != nil {
			t.Fatal(err)
		}
		_ = store.Close()
		if _, err := Open(Config{Kind: BackendFile, Path: root, CryptoSuite: cryptosuite.CNSMV1}); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("Open mismatched marker code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
}

func TestOpenFileBackendRecoversInterruptedMarkerTemp(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "proofs")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	tempPath := filepath.Join(root, "."+localStorageSchemaFile+".crash.tmp")
	if err := os.WriteFile(tempPath, []byte{0xff}, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(Config{Kind: BackendFile, Path: root})
	if err != nil {
		t.Fatalf("Open after interrupted temp: %v", err)
	}
	defer store.Close()
	if _, err := os.Stat(tempPath); !os.IsNotExist(err) {
		t.Fatalf("interrupted temp still exists: %v", err)
	}
}

func TestOpenFileBackendSerializesConflictingConcurrentInitialization(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "proofs")
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, suiteID := range []cryptosuite.ID{cryptosuite.INTLV1, cryptosuite.CNSMV1} {
		suiteID := suiteID
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			store, err := Open(Config{Kind: BackendFile, Path: root, CryptoSuite: suiteID})
			if err == nil {
				err = store.Close()
			}
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var successes, mismatches int
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		switch trusterr.CodeOf(err) {
		case trusterr.CodeFailedPrecondition:
			mismatches++
		default:
			t.Fatalf("unexpected concurrent open error: %v", err)
		}
	}
	if successes != 1 || mismatches != 1 {
		t.Fatalf("successes=%d mismatches=%d", successes, mismatches)
	}
}

func TestOpenRejectsUnknownConfiguredSuite(t *testing.T) {
	t.Parallel()
	if _, err := Open(Config{Kind: BackendFile, Path: t.TempDir(), CryptoSuite: cryptosuite.ID("unknown")}); trusterr.CodeOf(err) != trusterr.CodeInvalidArgument {
		t.Fatalf("Open unknown configured suite code=%s err=%v", trusterr.CodeOf(err), err)
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
