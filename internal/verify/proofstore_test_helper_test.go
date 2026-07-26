package verify

import (
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/proofstore"
)

func newBoundTestLocalStore(t testing.TB, root string) proofstore.LocalStore {
	t.Helper()
	store, err := proofstore.OpenLocalStore(root, cryptosuite.INTLV1, "test-node", "test-log", "test-local")
	if err != nil {
		t.Fatalf("open test local proofstore: %v", err)
	}
	return *store
}
