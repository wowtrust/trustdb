package trustcrypto

import (
	"bytes"
	"testing"

	"github.com/wowtrust/trustdb/internal/model"
)

func BenchmarkHashBytes1KiB(b *testing.B) {
	raw := bytes.Repeat([]byte("trustdb"), 1024/len("trustdb"))
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHash, benchmarkHashErr = HashBytes(model.DefaultHashAlg, raw)
	}
	if benchmarkHashErr != nil {
		b.Fatal(benchmarkHashErr)
	}
}

var (
	benchmarkHash    []byte
	benchmarkHashErr error
)
