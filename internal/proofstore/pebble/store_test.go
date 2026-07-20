package pebble_test

import (
	"testing"

	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
	pebblestore "github.com/ryan-wong-coder/trustdb/internal/proofstore/pebble"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore/proofstoretest"
)

// TestPebbleStoreConformance exercises every Store contract against a
// Pebble-backed implementation so it stays byte-equivalent to the file
// backend under file/pebble switchover.
func TestPebbleStoreConformance(t *testing.T) {
	t.Parallel()
	proofstoretest.RunConformance(t, func(t *testing.T) (proofstore.Store, func()) {
		store, err := pebblestore.Open(t.TempDir())
		if err != nil {
			t.Fatalf("pebble Open: %v", err)
		}
		return store, func() { _ = store.Close() }
	})
}

func TestPebbleRetainsWALUntilDurableRestartIdempotency(t *testing.T) {
	t.Parallel()
	store, err := pebblestore.Open(t.TempDir())
	if err != nil {
		t.Fatalf("pebble Open: %v", err)
	}
	defer store.Close()
	if proofstore.WALCheckpointPruneSafe(store) {
		t.Fatal("Pebble store opted into pruning before durable restart idempotency is available")
	}
}
