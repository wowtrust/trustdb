package grpcapi

import (
	"strings"
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/cborx"
)

func TestCBORCodecRejectsOversizedCollections(t *testing.T) {
	t.Parallel()

	oversizedArray := make([]uint64, MaxCBORArrayElements+1)
	raw, err := cborx.Marshal(oversizedArray)
	if err != nil {
		t.Fatal(err)
	}
	var decodedArray []uint64
	if err := (cborCodec{}).Unmarshal(raw, &decodedArray); err == nil ||
		!strings.Contains(err.Error(), "max number of elements") {
		t.Fatalf("oversized array error = %v", err)
	}

	oversizedMap := make(map[uint64]uint64, MaxCBORMapPairs+1)
	for i := uint64(0); i <= MaxCBORMapPairs; i++ {
		oversizedMap[i] = i
	}
	raw, err = cborx.Marshal(oversizedMap)
	if err != nil {
		t.Fatal(err)
	}
	var decodedMap map[uint64]uint64
	if err := (cborCodec{}).Unmarshal(raw, &decodedMap); err == nil ||
		!strings.Contains(err.Error(), "max number of key-value pairs") {
		t.Fatalf("oversized map error = %v", err)
	}
}
