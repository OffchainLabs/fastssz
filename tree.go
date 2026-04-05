package ssz

import (
	"encoding/binary"
	"errors"
	"sync"

	"github.com/minio/sha256-simd"
)

// Proof represents a merkle proof against a general index.
type Proof struct {
	Index  int
	Leaf   []byte
	Hashes [][]byte
}

// Multiproof represents a merkle proof of several leaves.
type Multiproof struct {
	Indices []int
	Leaves  [][]byte
	Hashes  [][]byte
}

// Compress returns a new proof with zero hashes omitted.
// See `CompressedMultiproof` for more info.
func (p *Multiproof) Compress() *CompressedMultiproof {
	compressed := &CompressedMultiproof{
		Indices:    p.Indices,
		Leaves:     p.Leaves,
		Hashes:     make([][]byte, 0, len(p.Hashes)),
		ZeroLevels: make([]int, 0, len(p.Hashes)),
	}

	for _, h := range p.Hashes {
		// Only exact 32-byte zero hashes are encoded as nil entries. Every other
		// hash is preserved as-is so decompression can rebuild the original proof.
		hashKey, ok := bytesToHashKey(h)
		if ok {
			if level, found := zeroHashLevels[hashKey]; found {
				compressed.ZeroLevels = append(compressed.ZeroLevels, level)
				compressed.Hashes = append(compressed.Hashes, nil)
				continue
			}
		}

		compressed.Hashes = append(compressed.Hashes, h)
	}

	return compressed
}

// CompressedMultiproof represents a compressed merkle proof of several leaves.
// Compression is achieved by omitting zero hashes (and their hashes). `ZeroLevels`
// contains information which helps the verifier fill in those hashes.
type CompressedMultiproof struct {
	Indices    []int
	Leaves     [][]byte
	Hashes     [][]byte
	ZeroLevels []int // Stores the level for every omitted zero hash in the proof
}

// Decompress returns a new multiproof, filling in the omitted
// zero hashes. See `CompressedMultiProof` for more info.
func (c *CompressedMultiproof) Decompress() *Multiproof {
	p := &Multiproof{
		Indices: c.Indices,
		Leaves:  c.Leaves,
		Hashes:  make([][]byte, len(c.Hashes)),
	}

	zeroLevelIndex := 0
	for i, h := range c.Hashes {
		if h == nil {
			p.Hashes[i] = zeroHashes[c.ZeroLevels[zeroLevelIndex]][:]
			zeroLevelIndex++
		} else {
			p.Hashes[i] = c.Hashes[i]
		}
	}

	return p
}

// Node represents a node in the tree
// backing of a SSZ object.
type Node struct {
	left  *Node
	right *Node

	value []byte
}

// NewNodeWithValue initializes a leaf node.
func NewNodeWithValue(value []byte) *Node {
	return &Node{left: nil, right: nil, value: value}
}

// NewNodeWithLR initializes a branch node.
func NewNodeWithLR(left, right *Node) *Node {
	return &Node{left: left, right: right, value: nil}
}

// TreeFromChunks constructs a tree from leaf values.
// The number of leaves should be a power of 2.
func TreeFromChunks(chunks [][]byte) (*Node, error) {
	numLeaves := len(chunks)
	if numLeaves == 0 {
		return nil, errors.New("number of leaves should be greater than 0")
	}
	if !isPowerOfTwo(numLeaves) {
		return nil, errors.New("number of leaves should be a power of 2")
	}

	leaves := make([]*Node, numLeaves)
	for i, c := range chunks {
		leaves[i] = &Node{left: nil, right: nil, value: c}
	}
	return TreeFromNodes(leaves)
}

// TreeFromNodes constructs a tree from leaf nodes.
// This is useful for merging subtrees.
// The number of leaves should be a power of 2.
func TreeFromNodes(leaves []*Node) (*Node, error) {
	numLeaves := len(leaves)
	if numLeaves == 0 {
		return nil, errors.New("number of leaves should be greater than 0")
	}

	if numLeaves == 1 {
		return leaves[0], nil
	}
	if numLeaves == 2 {
		return NewNodeWithLR(leaves[0], leaves[1]), nil
	}

	if !isPowerOfTwo(numLeaves) {
		return nil, errors.New("number of leaves should be a power of 2")
	}

	numNodes := numLeaves*2 - 1
	nodes := make([]*Node, numNodes)
	for i := numNodes; i > 0; i-- {
		// Is a leaf
		if i > numNodes-numLeaves {
			nodes[i-1] = leaves[i-numLeaves]
		} else {
			// Is a branch node
			nodes[i-1] = &Node{left: nodes[(i*2)-1], right: nodes[(i*2+1)-1], value: nil}
		}
	}

	return nodes[0], nil
}

// TreeFromNodesWithMixin builds a subtree, pads it up to the limit, and then
// mixes in the logical item count as the right child.
func TreeFromNodesWithMixin(leaves []*Node, num, limit int) (*Node, error) {
	numLeaves := len(leaves)
	if limit <= 0 {
		return nil, errors.New("size of tree should be greater than 0")
	}
	if !isPowerOfTwo(limit) {
		return nil, errors.New("size of tree should be a power of 2")
	}
	if numLeaves > limit {
		return nil, errors.New("number of leaves exceeds tree limit")
	}

	allLeaves := make([]*Node, limit)
	emptyLeaf := NewNodeWithValue(make([]byte, 32))
	for i := 0; i < limit; i++ {
		if i < numLeaves {
			allLeaves[i] = leaves[i]
		} else {
			allLeaves[i] = emptyLeaf
		}
	}

	mainTree, err := TreeFromNodes(allLeaves)
	if err != nil {
		return nil, err
	}

	// Mixin len
	countLeaf := LeafFromUint(uint64(num))
	return NewNodeWithLR(mainTree, countLeaf), nil
}

// Get fetches a node with the given general index.
func (n *Node) Get(index int) (*Node, error) {
	pathLen := getPathLength(index)
	cur := n
	for i := pathLen - 1; i >= 0; i-- {
		if isRight := getPosAtLevel(index, i); isRight {
			cur = cur.right
		} else {
			cur = cur.left
		}
		if cur == nil {
			return nil, errors.New("Node not found in tree")
		}
	}

	return cur, nil
}

// Hash returns the hash of the subtree with the given Node as its root.
// If root has no children, it returns root's value (not its hash).
func (n *Node) Hash() []byte {
	if n.left == nil && n.right == nil {
		return n.value
	}

	return subtreeHash(n)
}

// Prove returns a list of sibling values and hashes needed
// to compute the root hash for a given general index.
func (n *Node) Prove(index int) (*Proof, error) {
	pathLen := getPathLength(index)
	proof := &Proof{
		Index:  index,
		Hashes: make([][]byte, pathLen),
	}

	cur := n
	for i := pathLen - 1; i >= 0; i-- {
		var siblingHash []byte
		if isRight := getPosAtLevel(index, i); isRight {
			siblingHash = subtreeHash(cur.left)
			cur = cur.right
		} else {
			siblingHash = subtreeHash(cur.right)
			cur = cur.left
		}
		if cur == nil {
			return nil, errors.New("node not found in tree")
		}

		// Proof hashes are stored from leaf to root, so fill the slice backwards
		// instead of repeatedly prepending new slices.
		proof.Hashes[i] = siblingHash
	}

	proof.Leaf = cur.value

	return proof, nil
}

// ProveMulti returns the leaves and sibling hashes needed to verify
// multiple generalized indices against the same root.
func (n *Node) ProveMulti(indices []int) (*Multiproof, error) {
	requiredIndices := getRequiredIndices(indices)
	targetIndices := make([]int, 0, len(indices)+len(requiredIndices))
	targetIndices = append(targetIndices, indices...)
	targetIndices = append(targetIndices, requiredIndices...)

	targetNodes, err := collectNodes(n, targetIndices)
	if err != nil {
		return nil, err
	}

	proof := &Multiproof{
		Indices: indices,
		Leaves:  make([][]byte, len(indices)),
		Hashes:  make([][]byte, len(requiredIndices)),
	}

	for i, gi := range indices {
		node := targetNodes[gi]
		proof.Leaves[i] = node.value
	}

	for i, gi := range requiredIndices {
		cur := targetNodes[gi]
		proof.Hashes[i] = subtreeHash(cur)
	}

	return proof, nil
}

// Large complete subtrees benefit from batched merkleization. Smaller trees
// stay on the recursive path because the extra setup work is not worth it.
const subtreeBatchHashThreshold = 64

var subtreeBatchBufferPool sync.Pool

// subtreeHash picks the fastest safe hashing strategy for a subtree.
// Small or irregular subtrees use the normal recursive path. Large complete
// subtrees made of 32-byte leaves use the batched fast path.
func subtreeHash(n *Node) []byte {
	if hashed, ok := hashNodeBatched(n); ok {
		return hashed
	}
	return hashNode(n)
}

// hashNode recursively hashes a subtree using the generic path.
func hashNode(n *Node) []byte {
	// Leaf
	if n.left == nil && n.right == nil {
		return n.value
	}
	// Only one child
	if n.left == nil || n.right == nil {
		panic("Tree incomplete")
	}

	leftHash := hashNode(n.left)
	rightHash := hashNode(n.right)
	return hashPair(leftHash, rightHash)
}

// hashNodeBatched hashes complete 32-byte-leaf subtrees with the same
// merkleization engine that the hasher uses. This avoids recursive hashing
// work on large balanced subtrees.
func hashNodeBatched(n *Node) ([]byte, bool) {
	leafCount, ok := countFixed32Leaves(n)
	if !ok || leafCount < subtreeBatchHashThreshold {
		return nil, false
	}

	bufferSize := leafCount * len(zeroBytes)
	leaves := getSubtreeBatchBuffer(bufferSize)
	fillFixed32Leaves(n, leaves, 0)
	root, ok := merkleizeInputInPlace(leaves, 0)
	if !ok {
		root = merkleizeInput(leaves, 0)
	}

	// Copy the root before the scratch buffer goes back into the pool.
	hashed := cloneBytes(root)
	putSubtreeBatchBuffer(leaves)
	return hashed, true
}

// countFixed32Leaves returns the number of leaves in a subtree and whether
// every leaf is exactly one 32-byte SSZ chunk.
func countFixed32Leaves(n *Node) (int, bool) {
	if n.left == nil && n.right == nil {
		return 1, len(n.value) == len(zeroBytes)
	}
	if n.left == nil || n.right == nil {
		panic("Tree incomplete")
	}

	leftCount, leftOK := countFixed32Leaves(n.left)
	rightCount, rightOK := countFixed32Leaves(n.right)
	return leftCount + rightCount, leftOK && rightOK
}

// fillFixed32Leaves writes the subtree leaves from left to right into the
// flat scratch buffer used by the batched hashing path.
func fillFixed32Leaves(n *Node, leaves []byte, leafIndex int) int {
	if n.left == nil && n.right == nil {
		offset := leafIndex * len(zeroBytes)
		copy(leaves[offset:offset+len(zeroBytes)], n.value)
		return leafIndex + 1
	}

	leafIndex = fillFixed32Leaves(n.left, leaves, leafIndex)
	return fillFixed32Leaves(n.right, leaves, leafIndex)
}

// hashPair hashes two child digests into one parent digest.
func hashPair(left, right []byte) []byte {
	combinedLen := len(left) + len(right)
	if combinedLen <= 64 {
		var input [64]byte
		copy(input[:], left)
		copy(input[len(left):], right)
		sum := sha256.Sum256(input[:combinedLen])
		return sum[:]
	}

	data := make([]byte, combinedLen)
	copy(data, left)
	copy(data[len(left):], right)
	return hashFn(data)
}

// cloneBytes returns an owned copy of a digest before scratch buffers are reused.
func cloneBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func bytesToHashKey(src []byte) ([32]byte, bool) {
	if len(src) != len(zeroBytes) {
		return [32]byte{}, false
	}

	// A fixed-size array key is cheaper than converting the hash into a string
	// every time compression checks for a precomputed zero hash.
	var key [32]byte
	copy(key[:], src)
	return key, true
}

// getSubtreeBatchBuffer returns a scratch buffer with one extra chunk of
// capacity so the in-place merkleizer can append a zero hash when a layer is odd.
func getSubtreeBatchBuffer(size int) []byte {
	if buf, ok := subtreeBatchBufferPool.Get().([]byte); ok && cap(buf) >= size+len(zeroBytes) {
		return buf[:size]
	}
	return make([]byte, size, size+len(zeroBytes))
}

// putSubtreeBatchBuffer releases a scratch buffer back to the pool.
func putSubtreeBatchBuffer(buf []byte) {
	subtreeBatchBufferPool.Put(buf[:0])
}

// collectNodes walks only the branches needed to reach the requested
// generalized indices. This is faster than calling Get for every target.
func collectNodes(root *Node, indices []int) (map[int]*Node, error) {
	if len(indices) == 0 {
		return map[int]*Node{}, nil
	}

	targets := make(map[int]struct{}, len(indices))
	pathNodes := make(map[int]struct{}, len(indices)*2)
	for _, index := range indices {
		targets[index] = struct{}{}
		for current := index; current >= 1; current = getParent(current) {
			pathNodes[current] = struct{}{}
			if current == 1 {
				break
			}
		}
	}

	collectedNodes := make(map[int]*Node, len(indices))
	var walk func(node *Node, index int) error
	walk = func(node *Node, index int) error {
		if node == nil {
			return errors.New("node not found in tree")
		}
		if _, ok := targets[index]; ok {
			collectedNodes[index] = node
		}

		leftIndex := index << 1
		if _, ok := pathNodes[leftIndex]; ok {
			if err := walk(node.left, leftIndex); err != nil {
				return err
			}
		}

		rightIndex := leftIndex | 1
		if _, ok := pathNodes[rightIndex]; ok {
			if err := walk(node.right, rightIndex); err != nil {
				return err
			}
		}
		return nil
	}

	if err := walk(root, 1); err != nil {
		return nil, err
	}
	return collectedNodes, nil
}

// LeafFromUint returns a leaf node from a uint8, uint16, uint32, or uint64 value.
func LeafFromUint[T marshalUints](i T) *Node {
	buf := make([]byte, 32)
	copy(buf, MarshalUint(nil, i))
	return NewNodeWithValue(buf)
}

// LeafFromUint64 returns a leaf node from a uint64 value.
//
// Deprecated: use LeafFromUint instead.
func LeafFromUint64(i uint64) *Node {
	return LeafFromUint(i)
}

// LeafFromUint32 returns a leaf node from a uint32 value.
//
// Deprecated: use LeafFromUint instead.
func LeafFromUint32(i uint32) *Node {
	return LeafFromUint(i)
}

// LeafFromUint16 returns a leaf node from a uint16 value.
//
// Deprecated: use LeafFromUint instead.
func LeafFromUint16(i uint16) *Node {
	return LeafFromUint(i)
}

// LeafFromUint8 returns a leaf node from a uint8 value.
//
// Deprecated: use LeafFromUint instead.
func LeafFromUint8(i uint8) *Node {
	return LeafFromUint(i)
}

func LeafFromBool(b bool) *Node {
	buf := make([]byte, 32)
	if b {
		buf[0] = 1
	}
	return NewNodeWithValue(buf)
}

func LeafFromBytes(b []byte) *Node {
	l := len(b)
	if l > 32 {
		panic("Unimplemented")
	}

	if l == 32 {
		return NewNodeWithValue(b[:])
	}

	return NewNodeWithValue(append(b, zeroBytes[:32-l]...))
}

func EmptyLeaf() *Node {
	return NewNodeWithValue(zeroBytes[:32])
}

func LeavesFromUint64(items []uint64) []*Node {
	if len(items) == 0 {
		return []*Node{}
	}

	numLeaves := (len(items)*8 + 31) / 32
	buf := make([]byte, numLeaves*32)
	for i, v := range items {
		binary.LittleEndian.PutUint64(buf[i*8:(i+1)*8], v)
	}

	leaves := make([]*Node, numLeaves)
	for i := 0; i < numLeaves; i++ {
		v := buf[i*32 : (i+1)*32]
		leaves[i] = NewNodeWithValue(v)
	}

	return leaves
}

func isPowerOfTwo(n int) bool {
	return (n & (n - 1)) == 0
}
