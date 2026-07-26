package merkle

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/modelsuite"
)

const maxLeafBufferCapacity = 1 << 20

var leafBufferPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

type Tree struct {
	profile    Profile
	leafHashes []digest
	root       digest
	nodeIndex  map[nodeRange]int
	nodeHashes []digest
}

type Leaf struct {
	Index uint64
	Hash  []byte
}

type Node struct {
	Level      uint64
	StartIndex uint64
	Width      uint64
	Hash       []byte
}

type CompactNode struct {
	Level      uint64
	StartIndex uint64
	Width      uint64
	Hash       [DigestSize]byte
}

func Build(records []model.ServerRecord) (Tree, error) {
	return BuildForSuite(cryptosuite.INTLV1, cryptosuite.MerkleRFC6962SHA256, records)
}

func BuildForSuite(suiteID cryptosuite.ID, treeAlgorithm string, records []model.ServerRecord) (Tree, error) {
	profile, err := ProfileForAlgorithm(suiteID, treeAlgorithm)
	if err != nil {
		return Tree{}, err
	}
	if len(records) == 0 {
		return Tree{}, errors.New("merkle: cannot build empty tree")
	}
	leaves := make([]digest, len(records))
	for i := range records {
		if err := modelsuite.Require(suiteID, records[i]); err != nil {
			return Tree{}, fmt.Errorf("merkle: record %d crypto_suite: %w", i, err)
		}
		leaf, err := hashLeafArray(profile, &records[i])
		if err != nil {
			return Tree{}, fmt.Errorf("merkle: hash leaf %d: %w", i, err)
		}
		leaves[i] = leaf
	}
	return buildFromLeafHashes(profile, leaves), nil
}

func HashLeaf(record model.ServerRecord) ([]byte, error) {
	return HashLeafForSuite(cryptosuite.INTLV1, cryptosuite.MerkleRFC6962SHA256, record)
}

func HashLeafForSuite(suiteID cryptosuite.ID, treeAlgorithm string, record model.ServerRecord) ([]byte, error) {
	profile, err := ProfileForAlgorithm(suiteID, treeAlgorithm)
	if err != nil {
		return nil, err
	}
	if err := modelsuite.Require(suiteID, record); err != nil {
		return nil, fmt.Errorf("merkle: record crypto_suite: %w", err)
	}
	leaf, err := hashLeafArray(profile, &record)
	if err != nil {
		return nil, err
	}
	return cloneHash(leaf), nil
}

func hashLeafArray(profile Profile, record *model.ServerRecord) (digest, error) {
	buf := leafBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.WriteByte(profile.leafPrefix)
	if err := cborx.MarshalBuffer(buf, record); err != nil {
		releaseLeafBuffer(buf)
		return digest{}, err
	}
	out := profile.hashBytes(buf.Bytes())
	releaseLeafBuffer(buf)
	return out, nil
}

func releaseLeafBuffer(buf *bytes.Buffer) {
	if buf == nil || buf.Cap() > maxLeafBufferCapacity {
		return
	}
	buf.Reset()
	leafBufferPool.Put(buf)
}

func RootFromLeaves(leaves [][]byte) ([]byte, error) {
	return RootFromLeavesForSuite(cryptosuite.INTLV1, cryptosuite.MerkleRFC6962SHA256, leaves)
}

func RootFromLeavesForSuite(suiteID cryptosuite.ID, treeAlgorithm string, leaves [][]byte) ([]byte, error) {
	profile, err := ProfileForAlgorithm(suiteID, treeAlgorithm)
	if err != nil {
		return nil, err
	}
	if len(leaves) == 0 {
		return nil, errors.New("merkle: empty leaves")
	}
	copied := make([]digest, len(leaves))
	for i := range leaves {
		if len(leaves[i]) != profile.Size() {
			return nil, fmt.Errorf("merkle: leaf %d has size %d", i, len(leaves[i]))
		}
		copy(copied[i][:], leaves[i])
	}
	tree := buildFromLeafHashes(profile, copied)
	return tree.Root(), nil
}

func AuditPathFromLeaves(leaves [][]byte, index uint64) ([][]byte, error) {
	return AuditPathFromLeavesForSuite(cryptosuite.INTLV1, cryptosuite.MerkleRFC6962SHA256, leaves, index)
}

func AuditPathFromLeavesForSuite(suiteID cryptosuite.ID, treeAlgorithm string, leaves [][]byte, index uint64) ([][]byte, error) {
	profile, err := ProfileForAlgorithm(suiteID, treeAlgorithm)
	if err != nil {
		return nil, err
	}
	if len(leaves) == 0 {
		return nil, errors.New("merkle: empty leaves")
	}
	if index >= uint64(len(leaves)) {
		return nil, fmt.Errorf("merkle: leaf index out of range: %d", index)
	}
	copied := make([]digest, len(leaves))
	for i := range leaves {
		if len(leaves[i]) != profile.Size() {
			return nil, fmt.Errorf("merkle: leaf %d has size %d", i, len(leaves[i]))
		}
		copy(copied[i][:], leaves[i])
	}
	tree := buildFromLeafHashes(profile, copied)
	return tree.Proof(int(index))
}

func (t Tree) Suite() cryptosuite.ID { return t.profile.Suite() }
func (t Tree) Algorithm() string     { return t.profile.Algorithm() }

func (t Tree) Root() []byte {
	return cloneHash(t.root)
}

func (t Tree) LeafHash(index int) ([]byte, error) {
	if index < 0 || index >= len(t.leafHashes) {
		return nil, fmt.Errorf("merkle: leaf index out of range: %d", index)
	}
	return cloneHash(t.leafHashes[index]), nil
}

func (t Tree) LeafHashView(index int) ([]byte, error) {
	if index < 0 || index >= len(t.leafHashes) {
		return nil, fmt.Errorf("merkle: leaf index out of range: %d", index)
	}
	return t.leafHashes[index][:], nil
}

func (t Tree) CompactLeaves() [][DigestSize]byte {
	return t.leafHashes
}

func (t Tree) CompactNodes() []CompactNode {
	out := make([]CompactNode, 0, len(t.nodeIndex))
	for r, index := range t.nodeIndex {
		out = append(out, CompactNode{
			Level:      rangeLevel(r.size),
			StartIndex: uint64(r.start),
			Width:      uint64(r.size),
			Hash:       t.nodeHashes[index],
		})
	}
	return out
}

func (t Tree) Leaves() []Leaf {
	out := make([]Leaf, len(t.leafHashes))
	for i := range t.leafHashes {
		out[i] = Leaf{
			Index: uint64(i),
			Hash:  cloneHash(t.leafHashes[i]),
		}
	}
	return out
}

func (t Tree) Nodes() []Node {
	out := make([]Node, 0, len(t.nodeIndex))
	for r, index := range t.nodeIndex {
		out = append(out, Node{
			Level:      rangeLevel(r.size),
			StartIndex: uint64(r.start),
			Width:      uint64(r.size),
			Hash:       cloneHash(t.nodeHashes[index]),
		})
	}
	return out
}

func (t Tree) Proof(index int) ([][]byte, error) {
	if index < 0 || index >= len(t.leafHashes) {
		return nil, fmt.Errorf("merkle: leaf index out of range: %d", index)
	}
	path := t.auditPath(index)
	out := make([][]byte, len(path))
	for i := range path {
		out[i] = cloneHash(path[i])
	}
	return out, nil
}

func (t Tree) Proofs() [][][]byte {
	out := make([][][]byte, len(t.leafHashes))
	for i := range t.leafHashes {
		path := t.auditPath(i)
		out[i] = make([][]byte, len(path))
		for j := range path {
			out[i][j] = cloneHash(path[j])
		}
	}
	return out
}

// ProofView returns a read-only audit path view backed by the tree's compact
// hash storage. Callers must not mutate the returned byte slices; use Proof
// when mutable copies are required.
func (t Tree) ProofView(index int) ([][]byte, error) {
	if index < 0 || index >= len(t.leafHashes) {
		return nil, fmt.Errorf("merkle: leaf index out of range: %d", index)
	}
	ranges := make([]nodeRange, 0, merklePathLen(len(t.leafHashes)))
	t.appendAuditPathRanges(&ranges, 0, len(t.leafHashes), index)
	out := make([][]byte, len(ranges))
	for i := range ranges {
		nodeIndex := t.nodeIndex[ranges[i]]
		out[i] = t.nodeHashes[nodeIndex][:]
	}
	return out, nil
}

func Verify(leafHash []byte, index, treeSize uint64, auditPath [][]byte, root []byte) bool {
	return verifyWithProfile(defaultProfile, leafHash, index, treeSize, auditPath, root)
}

func VerifyForSuite(suiteID cryptosuite.ID, treeAlgorithm string, leafHash []byte, index, treeSize uint64, auditPath [][]byte, root []byte) (bool, error) {
	profile, err := ProfileForAlgorithm(suiteID, treeAlgorithm)
	if err != nil {
		return false, err
	}
	return verifyWithProfile(profile, leafHash, index, treeSize, auditPath, root), nil
}

func verifyWithProfile(profile Profile, leafHash []byte, index, treeSize uint64, auditPath [][]byte, root []byte) bool {
	if len(leafHash) != profile.Size() || len(root) != profile.Size() || treeSize == 0 || index >= treeSize {
		return false
	}
	pos := 0
	got, ok := rebuild(profile, leafHash, int(index), int(treeSize), auditPath, &pos)
	if !ok || pos != len(auditPath) {
		return false
	}
	return bytes.Equal(got[:], root)
}

func HashNode(left, right []byte) ([]byte, error) {
	return HashNodeForSuite(cryptosuite.INTLV1, cryptosuite.MerkleRFC6962SHA256, left, right)
}

func HashNodeForSuite(suiteID cryptosuite.ID, treeAlgorithm string, left, right []byte) ([]byte, error) {
	profile, err := ProfileForAlgorithm(suiteID, treeAlgorithm)
	if err != nil {
		return nil, err
	}
	if len(left) != profile.Size() {
		return nil, fmt.Errorf("merkle: left node has size %d", len(left))
	}
	if len(right) != profile.Size() {
		return nil, fmt.Errorf("merkle: right node has size %d", len(right))
	}
	leftHash := bytesToHash(left)
	rightHash := bytesToHash(right)
	node := hashNode(profile, leftHash, rightHash)
	return cloneHash(node), nil
}

type nodeRange struct {
	start int
	size  int
}

func buildFromLeafHashes(profile Profile, leaves []digest) Tree {
	nodeIndex := make(map[nodeRange]int, len(leaves)*2)
	nodeHashes := make([]digest, 0, len(leaves)*2)
	root := buildRange(profile, leaves, nodeIndex, &nodeHashes, 0, len(leaves))
	return Tree{profile: profile, leafHashes: leaves, root: root, nodeIndex: nodeIndex, nodeHashes: nodeHashes}
}

func buildRange(profile Profile, leaves []digest, nodeIndex map[nodeRange]int, nodeHashes *[]digest, start, size int) digest {
	key := nodeRange{start: start, size: size}
	var out digest
	if size == 1 {
		out = leaves[start]
	} else {
		k := largestPowerOfTwoLessThan(size)
		left := buildRange(profile, leaves, nodeIndex, nodeHashes, start, k)
		right := buildRange(profile, leaves, nodeIndex, nodeHashes, start+k, size-k)
		out = hashNode(profile, left, right)
	}
	nodeIndex[key] = len(*nodeHashes)
	*nodeHashes = append(*nodeHashes, out)
	return out
}

func (t Tree) auditPath(index int) []digest {
	path := make([]digest, 0, merklePathLen(len(t.leafHashes)))
	t.appendAuditPath(&path, 0, len(t.leafHashes), index)
	return path
}

func (t Tree) appendAuditPath(path *[]digest, start, size, index int) {
	if size == 1 {
		return
	}
	k := largestPowerOfTwoLessThan(size)
	if index < k {
		t.appendAuditPath(path, start, k, index)
		*path = append(*path, t.nodeHashes[t.nodeIndex[nodeRange{start: start + k, size: size - k}]])
		return
	}
	t.appendAuditPath(path, start+k, size-k, index-k)
	*path = append(*path, t.nodeHashes[t.nodeIndex[nodeRange{start: start, size: k}]])
}

func (t Tree) appendAuditPathRanges(path *[]nodeRange, start, size, index int) {
	if size == 1 {
		return
	}
	k := largestPowerOfTwoLessThan(size)
	if index < k {
		t.appendAuditPathRanges(path, start, k, index)
		*path = append(*path, nodeRange{start: start + k, size: size - k})
		return
	}
	t.appendAuditPathRanges(path, start+k, size-k, index-k)
	*path = append(*path, nodeRange{start: start, size: k})
}

func rebuild(profile Profile, leafHash []byte, index, treeSize int, path [][]byte, pos *int) (digest, bool) {
	if treeSize == 1 {
		return bytesToHash(leafHash), true
	}
	k := largestPowerOfTwoLessThan(treeSize)
	if index < k {
		left, ok := rebuild(profile, leafHash, index, k, path, pos)
		if !ok || *pos >= len(path) {
			return digest{}, false
		}
		right := path[*pos]
		*pos = *pos + 1
		if len(right) != profile.Size() {
			return digest{}, false
		}
		return hashNode(profile, left, bytesToHash(right)), true
	}
	right, ok := rebuild(profile, leafHash, index-k, treeSize-k, path, pos)
	if !ok || *pos >= len(path) {
		return digest{}, false
	}
	left := path[*pos]
	*pos = *pos + 1
	if len(left) != profile.Size() {
		return digest{}, false
	}
	return hashNode(profile, bytesToHash(left), right), true
}

func hashNode(profile Profile, left, right digest) digest {
	var buf [1 + DigestSize*2]byte
	buf[0] = profile.nodePrefix
	copy(buf[1:1+DigestSize], left[:])
	copy(buf[1+DigestSize:], right[:])
	return profile.hashBytes(buf[:])
}

func bytesToHash(in []byte) digest {
	var out digest
	copy(out[:], in)
	return out
}

func cloneHash(in digest) []byte {
	out := make([]byte, DigestSize)
	copy(out, in[:])
	return out
}

func merklePathLen(n int) int {
	if n <= 1 {
		return 0
	}
	return 1 + merklePathLen(largestPowerOfTwoLessThan(n))
}

func largestPowerOfTwoLessThan(n int) int {
	if n < 2 {
		return 0
	}
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func rangeLevel(size int) uint64 {
	if size <= 1 {
		return 0
	}
	level := uint64(0)
	width := 1
	for width < size {
		width <<= 1
		level++
	}
	return level
}
