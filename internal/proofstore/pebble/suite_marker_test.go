package pebble

import (
	"sync"
	"testing"

	pdb "github.com/cockroachdb/pebble"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/proofstoremeta"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestPebbleSuiteMarkerInitializesAtomicallyAndReopens(t *testing.T) {
	db, err := pdb.Open(t.TempDir(), &pdb.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	marker, err := ensureStorageSchema(db, cryptosuite.INTLV1)
	if err != nil {
		t.Fatalf("ensureStorageSchema: %v", err)
	}
	if err := proofstoremeta.Validate(marker, cryptosuite.INTLV1); err != nil {
		t.Fatalf("marker: %v", err)
	}
	if _, closer, err := db.Get([]byte(idempotencyReadyKey)); err != nil {
		t.Fatalf("read atomic readiness marker: %v", err)
	} else {
		_ = closer.Close()
	}
	if _, err := ensureStorageSchema(db, cryptosuite.INTLV1); err != nil {
		t.Fatalf("reopen marker: %v", err)
	}
	if _, err := ensureStorageSchema(db, cryptosuite.CNSMV1); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("mismatch code=%s err=%v", trusterr.CodeOf(err), err)
	}
}

func TestPebbleSuiteMarkerRejectsMissingCorruptAndUnknownState(t *testing.T) {
	t.Parallel()
	t.Run("missing", func(t *testing.T) {
		db, err := pdb.Open(t.TempDir(), &pdb.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if err := db.Set([]byte("data"), []byte("present"), pdb.Sync); err != nil {
			t.Fatal(err)
		}
		if _, err := ensureStorageSchema(db, cryptosuite.INTLV1); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("missing marker code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
	t.Run("partial initialization", func(t *testing.T) {
		db, err := pdb.Open(t.TempDir(), &pdb.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if err := db.Set([]byte(idempotencyReadyKey), []byte(idempotencyReadyV1), pdb.Sync); err != nil {
			t.Fatal(err)
		}
		if _, err := ensureStorageSchema(db, cryptosuite.INTLV1); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("partial marker code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
	t.Run("corrupt", func(t *testing.T) {
		db, err := pdb.Open(t.TempDir(), &pdb.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if err := db.Set([]byte(storageSchemaKey), []byte{0xff}, pdb.Sync); err != nil {
			t.Fatal(err)
		}
		if _, err := ensureStorageSchema(db, cryptosuite.INTLV1); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
			t.Fatalf("corrupt marker code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		db, err := pdb.Open(t.TempDir(), &pdb.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		marker, _ := proofstoremeta.New(cryptosuite.INTLV1)
		marker.CryptoSuite = cryptosuite.ID("UNKNOWN")
		data, _ := cborx.Marshal(marker)
		if err := db.Set([]byte(storageSchemaKey), data, pdb.Sync); err != nil {
			t.Fatal(err)
		}
		if _, err := ensureStorageSchema(db, cryptosuite.INTLV1); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("unknown marker code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
}

func TestPebbleSuiteMarkerSerializesConcurrentInitialization(t *testing.T) {
	db, err := pdb.Open(t.TempDir(), &pdb.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, suiteID := range []cryptosuite.ID{cryptosuite.INTLV1, cryptosuite.CNSMV1} {
		suiteID := suiteID
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := ensureStorageSchema(db, suiteID)
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
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if successes != 1 || mismatches != 1 {
		t.Fatalf("successes=%d mismatches=%d", successes, mismatches)
	}
}
