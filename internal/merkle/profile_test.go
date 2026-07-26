package merkle

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/bits"
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/model"
)

func TestRFC6962SM3CanonicalVectors(t *testing.T) {
	t.Parallel()
	empty, err := EmptyRootForSuite(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SM3)
	if err != nil {
		t.Fatal(err)
	}
	assertDigestHex(t, empty, "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b")

	alpha, err := HashLeafPayloadForSuite(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SM3, []byte("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	assertDigestHex(t, alpha, "8f305348d6bcdb9a12c3ddf6a57f15b0a6dccb6f65844c7697480796f72c7ce3")
	beta, err := HashLeafPayloadForSuite(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SM3, []byte("beta"))
	if err != nil {
		t.Fatal(err)
	}
	assertDigestHex(t, beta, "4d90e49bb5066d85b0b0d860111f96b357cddd919146ff82e263f3213dcff5f6")

	root, err := RootFromLeavesForSuite(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SM3, [][]byte{alpha, beta})
	if err != nil {
		t.Fatal(err)
	}
	assertDigestHex(t, root, "dd2c9f9eaa2bddde1dc837ae282f04b9301e668afb98d3281a4b0b0eb49ce1cf")
	node, err := HashNodeForSuite(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SM3, alpha, beta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(node, root) {
		t.Fatalf("node = %x, root = %x", node, root)
	}
}

func TestRFC6962SM3BuildProofAndVerifyManySizes(t *testing.T) {
	t.Parallel()
	for _, size := range []int{1, 2, 3, 4, 5, 8, 16, 31, 32, 33, 1024, 4096} {
		size := size
		t.Run(fmt.Sprintf("n=%d", size), func(t *testing.T) {
			t.Parallel()
			records := make([]model.ServerRecord, size)
			for i := range records {
				records[i] = record(fmt.Sprintf("sm3-record-%05d", i))
				records[i].CryptoSuite = cryptosuite.CNSMV1
			}
			tree, err := BuildForSuite(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SM3, records)
			if err != nil {
				t.Fatal(err)
			}
			if tree.Suite() != cryptosuite.CNSMV1 || tree.Algorithm() != cryptosuite.MerkleRFC6962SM3 {
				t.Fatalf("tree profile = (%s, %s)", tree.Suite(), tree.Algorithm())
			}
			root := tree.Root()
			for i := range records {
				leaf, err := tree.LeafHash(i)
				if err != nil {
					t.Fatal(err)
				}
				proof, err := tree.Proof(i)
				if err != nil {
					t.Fatal(err)
				}
				if len(proof) > bits.Len(uint(size-1)) {
					t.Fatalf("proof length %d exceeds O(log N) bound %d for size %d", len(proof), bits.Len(uint(size-1)), size)
				}
				ok, err := VerifyForSuite(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SM3, leaf, uint64(i), uint64(size), proof, root)
				if err != nil || !ok {
					t.Fatalf("VerifyForSuite(%d/%d) = %v, %v", i, size, ok, err)
				}
			}
		})
	}
}

func TestINTLV1SuiteProfileIsByteIdenticalToLegacyAPI(t *testing.T) {
	t.Parallel()

	records := []model.ServerRecord{record("intl-a"), record("intl-b"), record("intl-c")}
	legacy, err := Build(records)
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := BuildForSuite(cryptosuite.INTLV1, cryptosuite.MerkleRFC6962SHA256, records)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legacy.Root(), explicit.Root()) {
		t.Fatalf("INTL_V1 root changed: legacy=%x explicit=%x", legacy.Root(), explicit.Root())
	}
	for i := range records {
		legacyLeaf, _ := legacy.LeafHash(i)
		explicitLeaf, _ := explicit.LeafHash(i)
		legacyProof, _ := legacy.Proof(i)
		explicitProof, _ := explicit.Proof(i)
		if !bytes.Equal(legacyLeaf, explicitLeaf) || !equalPaths(legacyProof, explicitProof) {
			t.Fatalf("INTL_V1 leaf or proof changed at index %d", i)
		}
	}
}

func TestVerifyForSuiteSM3DoesNotAllocate(t *testing.T) {
	records := make([]model.ServerRecord, 1024)
	for i := range records {
		records[i] = record(fmt.Sprintf("sm3-alloc-%04d", i))
		records[i].CryptoSuite = cryptosuite.CNSMV1
	}
	tree, err := BuildForSuite(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SM3, records)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := tree.LeafHash(777)
	proof, _ := tree.Proof(777)
	root := tree.Root()
	allocs := testing.AllocsPerRun(1_000, func() {
		ok, err := VerifyForSuite(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SM3, leaf, 777, 1024, proof, root)
		if err != nil || !ok {
			panic("SM3 verification failed")
		}
	})
	if allocs != 0 {
		t.Fatalf("VerifyForSuite(SM3) allocations = %v, want 0", allocs)
	}
}

func TestMerkleProfilesRejectWrongSuiteAndAlgorithm(t *testing.T) {
	t.Parallel()
	if _, err := ProfileForAlgorithm(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SHA256); err == nil {
		t.Fatal("CN_SM_V1 accepted the SHA-256 tree algorithm")
	}
	if _, err := ProfileForAlgorithm(cryptosuite.INTLV1, cryptosuite.MerkleRFC6962SM3); err == nil {
		t.Fatal("INTL_V1 accepted the SM3 tree algorithm")
	}

	records := []model.ServerRecord{record("suite-a"), record("suite-b"), record("suite-c")}
	for i := range records {
		records[i].CryptoSuite = cryptosuite.CNSMV1
	}
	tree, err := BuildForSuite(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SM3, records)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := tree.LeafHash(1)
	proof, _ := tree.Proof(1)
	if ok, err := VerifyForSuite(cryptosuite.INTLV1, cryptosuite.MerkleRFC6962SHA256, leaf, 1, 3, proof, tree.Root()); err != nil || ok {
		t.Fatalf("INTL_V1 verification of an SM3 tree = %v, %v", ok, err)
	}
	if ok, err := VerifyForSuite(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SHA256, leaf, 1, 3, proof, tree.Root()); err == nil || ok {
		t.Fatalf("mismatched tree algorithm verification = %v, %v", ok, err)
	}
}

func FuzzRFC6962SuiteProofs(f *testing.F) {
	f.Add([]byte("alpha|beta|gamma"), uint8(1))
	f.Add([]byte("one"), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, requested uint8) {
		if len(raw) == 0 || len(raw) > 4096 {
			t.Skip()
		}
		parts := bytes.Split(raw, []byte{'|'})
		if len(parts) > 64 {
			parts = parts[:64]
		}
		leaves := make([][]byte, len(parts))
		for i := range parts {
			var err error
			leaves[i], err = HashLeafPayloadForSuite(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SM3, parts[i])
			if err != nil {
				t.Fatal(err)
			}
		}
		index := uint64(requested) % uint64(len(leaves))
		root, err := RootFromLeavesForSuite(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SM3, leaves)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := AuditPathFromLeavesForSuite(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SM3, leaves, index)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := VerifyForSuite(cryptosuite.CNSMV1, cryptosuite.MerkleRFC6962SM3, leaves[index], index, uint64(len(leaves)), proof, root)
		if err != nil || !ok {
			t.Fatalf("valid proof = %v, %v", ok, err)
		}
		if ok, err := VerifyForSuite(cryptosuite.INTLV1, cryptosuite.MerkleRFC6962SM3, leaves[index], index, uint64(len(leaves)), proof, root); err == nil || ok {
			t.Fatalf("cross-suite proof = %v, %v", ok, err)
		}
	})
}

func assertDigestHex(t *testing.T, got []byte, wantHex string) {
	t.Helper()
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("digest = %x, want %x", got, want)
	}
}

func equalPaths(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if !bytes.Equal(left[i], right[i]) {
			return false
		}
	}
	return true
}
