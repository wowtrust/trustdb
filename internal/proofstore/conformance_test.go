package proofstore_test

import (
	"testing"

	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/proofstore/proofstoretest"
)

// TestLocalStoreConformance runs the shared conformance suite against
// the file-backed LocalStore to guarantee the two backends observe
// identical semantics for every method in proofstore.Store.
func TestLocalStoreConformance(t *testing.T) {
	t.Parallel()
	proofstoretest.RunConformance(t, func(t *testing.T) (proofstore.Store, func()) {
		store := &proofstore.LocalStore{Root: t.TempDir()}
		return store, func() { _ = store.Close() }
	})
}
