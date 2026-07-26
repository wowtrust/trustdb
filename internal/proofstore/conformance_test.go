package proofstore_test

import (
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/proofstore"
	"github.com/wowtrust/trustdb/v2/internal/proofstore/proofstoretest"
)

// TestLocalStoreConformance runs the shared conformance suite against
// the file-backed LocalStore to guarantee the two backends observe
// identical semantics for every method in proofstore.Store.
func TestLocalStoreConformance(t *testing.T) {
	t.Parallel()
	proofstoretest.RunConformance(t, func(t *testing.T) (proofstore.Store, func()) {
		store, err := proofstore.OpenLocalStore(t.TempDir(), cryptosuite.INTLV1, "test-node", "test-log", "test-local")
		if err != nil {
			t.Fatalf("open local proofstore: %v", err)
		}
		return store, func() { _ = store.Close() }
	})
}
