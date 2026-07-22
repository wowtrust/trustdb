package merkle

import (
	"fmt"
	"testing"

	"github.com/wowtrust/trustdb/internal/model"
)

func BenchmarkBuild1024(b *testing.B) {
	records := make([]model.ServerRecord, 1024)
	for i := range records {
		records[i] = record(fmt.Sprintf("record-%04d", i))
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Build(records); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyProof1024(b *testing.B) {
	records := make([]model.ServerRecord, 1024)
	for i := range records {
		records[i] = record(fmt.Sprintf("record-%04d", i))
	}
	tree, err := Build(records)
	if err != nil {
		b.Fatal(err)
	}
	leaf, err := tree.LeafHash(777)
	if err != nil {
		b.Fatal(err)
	}
	proof, err := tree.Proof(777)
	if err != nil {
		b.Fatal(err)
	}
	root := tree.Root()
	b.ReportAllocs()
	for b.Loop() {
		if !Verify(leaf, 777, uint64(len(records)), proof, root) {
			b.Fatal("verify failed")
		}
	}
}
