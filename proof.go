package ssz

import (
	"bytes"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"sync"

	"github.com/minio/sha256-simd"
)

// VerifyProof verifies a single merkle branch. It's more
// efficient than VerifyMultiproof for proving one leaf.
func VerifyProof(root []byte, proof *Proof) (bool, error) {
	if len(proof.Hashes) != getPathLength(proof.Index) {
		return false, errors.New("invalid proof length")
	}
	if len(root) != len(zeroBytes) {
		return false, ErrRootSizeInvalid
	}

	// Proof verification always hashes 32-byte chunks, so we keep the
	// working buffers on the stack and reuse them for every level.
	var node [32]byte
	copy(node[:], proof.Leaf)
	var tmp [64]byte
	index := proof.Index
	for _, h := range proof.Hashes {
		if index&1 == 1 {
			copy(tmp[:32], h)
			copy(tmp[32:], node[:])
		} else {
			copy(tmp[:32], node[:])
			copy(tmp[32:], h)
		}
		node = sha256.Sum256(tmp[:])
		index >>= 1
	}

	var rootHash [32]byte
	copy(rootHash[:], root)
	return node == rootHash, nil
}

// VerifyMultiproof verifies a proof for multiple leaves against the given root.
func VerifyMultiproof(root []byte, proof [][]byte, leaves [][]byte, indices []int) (bool, error) {
	if len(leaves) != len(indices) {
		return false, errors.New("number of leaves and indices mismatch")
	}
	// When the caller already supplied every leaf of a complete tree, verifying
	// the proof is just a direct merkleization step and does not need the
	// generic map-based parent reconstruction below.
	if ok, valid := verifyFullTreeLeaves(root, proof, leaves, indices); ok {
		return valid, nil
	}

	requiredIndices := getRequiredIndices(indices)
	if len(requiredIndices) != len(proof) {
		return false, fmt.Errorf("number of proof hashes %d and required indices %d mismatch", len(proof), len(requiredIndices))
	}

	// The work queue grows as parent nodes are rebuilt, so reserve capacity for
	// both the input nodes and the parent indices appended during the walk.
	pendingIndices := make([]int, 0, 2*(len(indices)+len(requiredIndices)))
	// Store all nodes in a fixed-size format so parent hashes can be built
	// without allocating new byte slices on every merge.
	hashesByIndex := make(map[int][32]byte, len(indices)+len(requiredIndices))
	for i, leaf := range leaves {
		var leafHash [32]byte
		copy(leafHash[:], leaf)
		hashesByIndex[indices[i]] = leafHash
		pendingIndices = append(pendingIndices, indices[i])
	}
	for i, h := range proof {
		var proofHash [32]byte
		copy(proofHash[:], h)
		hashesByIndex[requiredIndices[i]] = proofHash
		pendingIndices = append(pendingIndices, requiredIndices[i])
	}
	sort.Sort(sort.Reverse(sort.IntSlice(pendingIndices)))

	position := 0
	var tmp [64]byte
	for position < len(pendingIndices) {
		index := pendingIndices[position]
		// Root has been reached
		if index == 1 {
			break
		}

		_, hasParent := hashesByIndex[getParent(index)]
		if hasParent {
			position++
			continue
		}

		left, hasLeft := hashesByIndex[(index|1)^1]
		right, hasRight := hashesByIndex[index|1]
		if !hasRight || !hasLeft {
			return false, fmt.Errorf("proof is missing required nodes, either %d or %d", (index|1)^1, index|1)
		}

		// The verifier rebuilds missing parents from the bottom up until the
		// root hash appears in the temporary database.
		copy(tmp[:32], left[:])
		copy(tmp[32:], right[:])
		parent := getParent(index)
		hashesByIndex[parent] = sha256.Sum256(tmp[:])
		pendingIndices = append(pendingIndices, parent)

		position++
	}

	res, ok := hashesByIndex[1]
	if !ok {
		return false, fmt.Errorf("root was not computed during proof verification")
	}

	return bytes.Equal(res[:], root), nil
}

var fullTreeLeafBufferPool sync.Pool

// verifyFullTreeLeaves fast-paths verification when the caller already
// supplied every leaf of a complete tree in left-to-right order.
func verifyFullTreeLeaves(root []byte, proof [][]byte, leaves [][]byte, indices []int) (bool, bool) {
	leafCount := len(leaves)
	if len(proof) != 0 || leafCount == 0 || leafCount != len(indices) || !isPowerOfTwo(leafCount) {
		return false, false
	}
	if !isFullTreeLeafRange(indices, leafCount) {
		return false, false
	}

	bufferSize := leafCount * len(zeroBytes)
	leafBuffer := getFullTreeLeafBuffer(bufferSize)
	for i, leaf := range leaves {
		// Leaves may be shorter than one SSZ chunk, so normalize them into
		// 32-byte chunks before hashing the whole tree in one pass.
		chunk := leafBuffer[i*len(zeroBytes) : (i+1)*len(zeroBytes)]
		copied := copy(chunk, leaf)
		for j := copied; j < len(chunk); j++ {
			chunk[j] = 0
		}
	}

	computedRoot, ok := merkleizeInputInPlace(leafBuffer, 0)
	if !ok {
		computedRoot = merkleizeInput(leafBuffer, 0)
	}
	valid := bytes.Equal(computedRoot, root)
	putFullTreeLeafBuffer(leafBuffer)
	return true, valid
}

func isFullTreeLeafRange(indices []int, leafCount int) bool {
	// The fast path is only correct for the canonical complete-tree leaf range:
	// leafCount, leafCount+1, ... leafCount+n-1.
	for i, index := range indices {
		if index != leafCount+i {
			return false
		}
	}
	return true
}

func getFullTreeLeafBuffer(size int) []byte {
	if buf, ok := fullTreeLeafBufferPool.Get().([]byte); ok && cap(buf) >= size+len(zeroBytes) {
		return buf[:size]
	}
	return make([]byte, size, size+len(zeroBytes))
}

func putFullTreeLeafBuffer(buf []byte) {
	fullTreeLeafBufferPool.Put(buf[:0])
}

// Returns the position (i.e. false for left, true for right)
// of an index at a given level.
// Level 0 is the actual index's level, Level 1 is the position
// of the parent, etc.
func getPosAtLevel(index int, level int) bool {
	return (index & (1 << level)) > 0
}

// Returns the length of the path to a node represented by its generalized index.
func getPathLength(index int) int {
	if index <= 1 {
		return 0
	}
	return bits.Len(uint(index)) - 1
}

// Returns the generalized index for a node's sibling.
func getSibling(index int) int {
	return index ^ 1
}

// Returns the generalized index for a node's parent.
func getParent(index int) int {
	return index >> 1
}

// Returns generalized indices for all nodes in the tree that are
// required to prove the given leaf indices. The returned indices
// are in a decreasing order.
func getRequiredIndices(leafIndices []int) []int {
	if len(leafIndices) == 0 {
		return nil
	}

	exists := struct{}{}
	// Sibling hashes needed for verification
	required := make(map[int]struct{}, len(leafIndices))
	// Set of hashes that will be computed
	// on the path from leaf to root.
	computed := make(map[int]struct{}, len(leafIndices))
	leaves := make(map[int]struct{}, len(leafIndices))

	for _, leaf := range leafIndices {
		leaves[leaf] = exists
		cur := leaf
		for cur > 1 {
			sibling := getSibling(cur)
			parent := getParent(cur)
			required[sibling] = exists
			computed[parent] = exists
			cur = parent
		}
	}

	requiredList := make([]int, 0, len(required))
	// Remove computed indices from required ones
	for r := range required {
		_, isComputed := computed[r]
		_, isLeaf := leaves[r]
		if !isComputed && !isLeaf {
			requiredList = append(requiredList, r)
		}
	}

	sort.Sort(sort.Reverse(sort.IntSlice(requiredList)))
	return requiredList
}

func hashFn(data []byte) []byte {
	res := sha256.Sum256(data)
	return res[:]
}
