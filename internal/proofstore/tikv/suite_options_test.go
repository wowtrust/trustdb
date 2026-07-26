package tikv

import (
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/proofstoremeta"
)

func testStoreBinding() proofstoremeta.Marker {
	binding, err := proofstoremeta.New(cryptosuite.INTLV1, "test-node", "test-log", "test-tikv")
	if err != nil {
		panic(err)
	}
	return binding
}
