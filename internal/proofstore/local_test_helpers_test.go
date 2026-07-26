package proofstore

import (
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
)

func testLocalStore(root string) LocalStore {
	store, err := OpenLocalStore(root, cryptosuite.INTLV1, "test-node", "test-log", "test-local")
	if err != nil {
		panic(err)
	}
	return *store
}
