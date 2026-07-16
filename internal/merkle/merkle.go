package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/model"
)

const maxLeafBufferCapacity = 1 << 20

var leafBufferPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

type Tree struct {
	leafHashes [][sha256.Size]byte
	root       [sha256.Size]byte
	nodeIndex  map[nodeRange]int
	nodeHashes [][sha256.Size]byte
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
	Hash       [sha256.Size]byte
}

func Build(records []model.ServerRecord) (Tree, error) {
	if len(records) == 0 {
		return Tree{}, errors.New("merkle: cannot build empty tree")
	}
	leaves := make([][sha256.Size]byte, len(records))
	for i := range records {
		leaf, err := hashLeafArray(records[i])
		if err != nil {
			return Tree{}, fmt.Errorf("merkle: hash leaf %d: %w", i, err)
		}
		leaves[i] = leaf
	}
	return buildFromLeafHashes(leaves), nil
}

func HashLeaf(record model.ServerRecord) ([]byte, error) {
	leaf, err := hashLeafArray(record)
	if err != nil {
		return nil, err
	}
	return cloneHash(leaf), nil
}

func hashLeafArray(record model.ServerRecord) ([sha256.Size]byte, error) {
	buf := leafBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.WriteByte(0)
	if err := cborx.MarshalBuffer(buf, record); err != nil {
		releaseLeafBuffer(buf)
		return [sha256.Size]byte{}, err
	}
	out := sha256.Sum256(buf.Bytes())
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
	if len(leaves) == 0 {
		return nil, errors.New("merkle: empty leaves")
	}
	copied := make([][sha256.Size]byte, len(leaves))
	for i := range leaves {
		if len(leaves[i]) != sha256.Size {
			return nil, fmt.Errorf("merkle: leaf %d has size %d", i, len(leaves[i]))
		}
		copy(copied[i][:], leaves[i])
	}
	tree := buildFromLeafHashes(copied)
	return tree.Root(), nil
}

func AuditPathFromLeaves(leaves [][]byte, index uint64) ([][]byte, error) {
	if len(leaves) == 0 {
		return nil, errors.New("merkle: empty leaves")
	}
	if index >= uint64(len(leaves)) {
		return nil, fmt.Errorf("merkle: leaf index out of range: %d", index)
	}
	copied := make([][sha256.Size]byte, len(leaves))
	for i := range leaves {
		if len(leaves[i]) != sha256.Size {
			return nil, fmt.Errorf("merkle: leaf %d has size %d", i, len(leaves[i]))
		}
		copy(copied[i][:], leaves[i])
	}
	tree := buildFromLeafHashes(copied)
	return tree.Proof(int(index))
}

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

func (t Tree) CompactLeaves() [][sha256.Size]byte {
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

// ProofView returns an immutable audit path backed by the tree's compact hash
// storage. Callers must not mutate the returned byte slices.
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
	if len(leafHash) != sha256.Size || len(root) != sha256.Size || treeSize == 0 || index >= treeSize {
		return false
	}
	pos := 0
	got, ok := rebuild(leafHash, int(index), int(treeSize), auditPath, &pos)
	if !ok || pos != len(auditPath) {
		return false
	}
	return bytes.Equal(got, root)
}

func HashNode(left, right []byte) ([]byte, error) {
	if len(left) != sha256.Size {
		return nil, fmt.Errorf("merkle: left node has size %d", len(left))
	}
	if len(right) != sha256.Size {
		return nil, fmt.Errorf("merkle: right node has size %d", len(right))
	}
	leftHash := bytesToHash(left)
	rightHash := bytesToHash(right)
	node := hashNode(leftHash, rightHash)
	return cloneHash(node), nil
}

type nodeRange struct {
	start int
	size  int
}

func buildFromLeafHashes(leaves [][sha256.Size]byte) Tree {
	nodeIndex := make(map[nodeRange]int, len(leaves)*2)
	nodeHashes := make([][sha256.Size]byte, 0, len(leaves)*2)
	root := buildRange(leaves, nodeIndex, &nodeHashes, 0, len(leaves))
	return Tree{leafHashes: leaves, root: root, nodeIndex: nodeIndex, nodeHashes: nodeHashes}
}

func buildRange(leaves [][sha256.Size]byte, nodeIndex map[nodeRange]int, nodeHashes *[][sha256.Size]byte, start, size int) [sha256.Size]byte {
	key := nodeRange{start: start, size: size}
	var out [sha256.Size]byte
	if size == 1 {
		out = leaves[start]
	} else {
		k := largestPowerOfTwoLessThan(size)
		left := buildRange(leaves, nodeIndex, nodeHashes, start, k)
		right := buildRange(leaves, nodeIndex, nodeHashes, start+k, size-k)
		out = hashNode(left, right)
	}
	nodeIndex[key] = len(*nodeHashes)
	*nodeHashes = append(*nodeHashes, out)
	return out
}

func (t Tree) auditPath(index int) [][sha256.Size]byte {
	path := make([][sha256.Size]byte, 0, merklePathLen(len(t.leafHashes)))
	t.appendAuditPath(&path, 0, len(t.leafHashes), index)
	return path
}

func (t Tree) appendAuditPath(path *[][sha256.Size]byte, start, size, index int) {
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

func rebuild(leafHash []byte, index, treeSize int, path [][]byte, pos *int) ([]byte, bool) {
	if treeSize == 1 {
		return append([]byte(nil), leafHash...), true
	}
	if *pos >= len(path) {
		return nil, false
	}
	k := largestPowerOfTwoLessThan(treeSize)
	if index < k {
		left, ok := rebuild(leafHash, index, k, path, pos)
		if !ok {
			return nil, false
		}
		right := path[*pos]
		*pos = *pos + 1
		if len(right) != sha256.Size {
			return nil, false
		}
		return hashNodeBytes(left, right), true
	}
	right, ok := rebuild(leafHash, index-k, treeSize-k, path, pos)
	if !ok {
		return nil, false
	}
	left := path[*pos]
	*pos = *pos + 1
	if len(left) != sha256.Size {
		return nil, false
	}
	return hashNodeBytes(left, right), true
}

func hashNodeBytes(left, right []byte) []byte {
	leftHash := bytesToHash(left)
	rightHash := bytesToHash(right)
	node := hashNode(leftHash, rightHash)
	return cloneHash(node)
}

func hashNode(left, right [sha256.Size]byte) [sha256.Size]byte {
	var buf [1 + sha256.Size*2]byte
	buf[0] = 1
	copy(buf[1:1+sha256.Size], left[:])
	copy(buf[1+sha256.Size:], right[:])
	return sha256.Sum256(buf[:])
}

func bytesToHash(in []byte) [sha256.Size]byte {
	var out [sha256.Size]byte
	copy(out[:], in)
	return out
}

func cloneHash(in [sha256.Size]byte) []byte {
	out := make([]byte, sha256.Size)
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
