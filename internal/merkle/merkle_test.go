package merkle

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/ryan-wong-coder/trustdb/internal/model"
)

func TestBuildProofAndVerify(t *testing.T) {
	t.Parallel()

	records := []model.ServerRecord{
		record("a"),
		record("b"),
		record("c"),
		record("d"),
		record("e"),
	}
	tree, err := Build(records)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	root := tree.Root()
	if len(root) == 0 {
		t.Fatal("Build() returned empty root")
	}

	for i := range records {
		i := i
		t.Run(records[i].RecordID, func(t *testing.T) {
			t.Parallel()
			leaf, err := tree.LeafHash(i)
			if err != nil {
				t.Fatalf("LeafHash() error = %v", err)
			}
			proof, err := tree.Proof(i)
			if err != nil {
				t.Fatalf("Proof() error = %v", err)
			}
			if !Verify(leaf, uint64(i), uint64(len(records)), proof, root) {
				t.Fatalf("Verify() = false for leaf %d", i)
			}
		})
	}
}

func TestBuildProofAndVerifyManySizes(t *testing.T) {
	t.Parallel()

	for _, size := range []int{1, 2, 3, 4, 5, 8, 16, 31, 32, 33, 1024} {
		size := size
		t.Run(fmt.Sprintf("n=%d", size), func(t *testing.T) {
			t.Parallel()

			records := make([]model.ServerRecord, size)
			for i := range records {
				records[i] = record(fmt.Sprintf("rec-%04d", i))
			}
			tree, err := Build(records)
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			root := tree.Root()
			if len(root) == 0 {
				t.Fatal("Build() returned empty root")
			}
			proofs := tree.Proofs()
			if len(proofs) != size {
				t.Fatalf("Proofs() len = %d, want %d", len(proofs), size)
			}
			for i := range records {
				leaf, err := tree.LeafHash(i)
				if err != nil {
					t.Fatalf("LeafHash(%d) error = %v", i, err)
				}
				if !Verify(leaf, uint64(i), uint64(len(records)), proofs[i], root) {
					t.Fatalf("Verify() = false for leaf %d of %d", i, size)
				}
			}
		})
	}
}

func TestVerifyRejectsWrongRoot(t *testing.T) {
	t.Parallel()

	records := []model.ServerRecord{record("a"), record("b"), record("c")}
	tree, err := Build(records)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	leaf, err := tree.LeafHash(1)
	if err != nil {
		t.Fatalf("LeafHash() error = %v", err)
	}
	proof, err := tree.Proof(1)
	if err != nil {
		t.Fatalf("Proof() error = %v", err)
	}
	badRoot := bytes.Repeat([]byte{9}, 32)
	if Verify(leaf, 1, uint64(len(records)), proof, badRoot) {
		t.Fatal("Verify() = true, want false for bad root")
	}
}

func TestVerifyDoesNotAllocate(t *testing.T) {
	records := make([]model.ServerRecord, 1024)
	for i := range records {
		records[i] = record(fmt.Sprintf("rec-%04d", i))
	}
	tree, err := Build(records)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	leaf, err := tree.LeafHash(777)
	if err != nil {
		t.Fatalf("LeafHash() error = %v", err)
	}
	proof, err := tree.Proof(777)
	if err != nil {
		t.Fatalf("Proof() error = %v", err)
	}
	root := tree.Root()

	allocs := testing.AllocsPerRun(1_000, func() {
		if !Verify(leaf, 777, uint64(len(records)), proof, root) {
			panic("Verify() = false")
		}
	})
	if allocs != 0 {
		t.Fatalf("Verify() allocations = %v, want 0", allocs)
	}
}

func TestVerifyRejectsMalformedInputs(t *testing.T) {
	t.Parallel()

	records := []model.ServerRecord{record("a"), record("b"), record("c"), record("d")}
	tree, err := Build(records)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	leaf, err := tree.LeafHash(2)
	if err != nil {
		t.Fatalf("LeafHash() error = %v", err)
	}
	proof, err := tree.Proof(2)
	if err != nil {
		t.Fatalf("Proof() error = %v", err)
	}
	root := tree.Root()
	shortNodeProof := append([][]byte(nil), proof...)
	shortNodeProof[0] = shortNodeProof[0][:len(shortNodeProof[0])-1]

	tests := []struct {
		name     string
		leaf     []byte
		index    uint64
		treeSize uint64
		proof    [][]byte
		root     []byte
	}{
		{name: "short leaf", leaf: leaf[:len(leaf)-1], index: 2, treeSize: 4, proof: proof, root: root},
		{name: "short root", leaf: leaf, index: 2, treeSize: 4, proof: proof, root: root[:len(root)-1]},
		{name: "empty tree", leaf: leaf, index: 0, treeSize: 0, proof: nil, root: root},
		{name: "index out of range", leaf: leaf, index: 4, treeSize: 4, proof: proof, root: root},
		{name: "extra proof node", leaf: leaf, index: 2, treeSize: 4, proof: append(append([][]byte(nil), proof...), bytes.Repeat([]byte{1}, 32)), root: root},
		{name: "short proof node", leaf: leaf, index: 2, treeSize: 4, proof: shortNodeProof, root: root},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if Verify(test.leaf, test.index, test.treeSize, test.proof, test.root) {
				t.Fatal("Verify() = true, want false")
			}
		})
	}
}

func TestTreeLeavesAndNodesExposeStableSnapshot(t *testing.T) {
	t.Parallel()

	records := []model.ServerRecord{record("a"), record("b"), record("c")}
	tree, err := Build(records)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	leaves := tree.Leaves()
	if len(leaves) != 3 {
		t.Fatalf("Leaves() len = %d, want 3", len(leaves))
	}
	for i := range leaves {
		if leaves[i].Index != uint64(i) || len(leaves[i].Hash) != 32 {
			t.Fatalf("leaf %d = %+v", i, leaves[i])
		}
	}
	nodes := tree.Nodes()
	if len(nodes) != 5 {
		t.Fatalf("Nodes() len = %d, want 5", len(nodes))
	}
	var rootNodeFound bool
	for _, node := range nodes {
		if node.StartIndex == 0 && node.Width == 3 {
			rootNodeFound = true
			if node.Level != 2 || !bytes.Equal(node.Hash, tree.Root()) {
				t.Fatalf("root node = %+v", node)
			}
		}
	}
	if !rootNodeFound {
		t.Fatalf("Nodes() missing root node: %+v", nodes)
	}
}

func TestBuildRejectsEmptyRecords(t *testing.T) {
	t.Parallel()

	if _, err := Build(nil); err == nil {
		t.Fatal("Build(nil) error = nil, want error")
	}
}

func record(id string) model.ServerRecord {
	return model.ServerRecord{
		SchemaVersion:       model.SchemaServerRecord,
		RecordID:            id,
		TenantID:            "tenant",
		ClientID:            "client",
		KeyID:               "key",
		ClaimHash:           bytes.Repeat([]byte(id), 32)[:32],
		ClientSignatureHash: bytes.Repeat([]byte{1}, 32),
		ReceivedAtUnixN:     100,
		Validation: model.Validation{
			PolicyVersion:       model.DefaultValidationPolicy,
			HashAlgAllowed:      true,
			SignatureAlgAllowed: true,
			KeyStatus:           "valid",
		},
	}
}
