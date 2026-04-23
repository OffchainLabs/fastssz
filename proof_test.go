package ssz

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func sha256Bytes(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func sha256Pair(left, right []byte) []byte {
	combined := make([]byte, 0, len(left)+len(right))
	combined = append(combined, left...)
	combined = append(combined, right...)
	return sha256Bytes(combined)
}

type proofFixture struct {
	root  []byte
	leaf0 []byte
	leaf1 []byte
	leaf2 []byte
	leaf3 []byte
	node0 []byte
	node1 []byte
}

func newProofFixture() *proofFixture {
	leaf0 := sha256Bytes([]byte("leaf0"))
	leaf1 := sha256Bytes([]byte("leaf1"))
	leaf2 := sha256Bytes([]byte("leaf2"))
	leaf3 := sha256Bytes([]byte("leaf3"))
	node0 := sha256Pair(leaf0, leaf1)
	node1 := sha256Pair(leaf2, leaf3)

	return &proofFixture{
		root:  sha256Pair(node0, node1),
		leaf0: leaf0,
		leaf1: leaf1,
		leaf2: leaf2,
		leaf3: leaf3,
		node0: node0,
		node1: node1,
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("failed to decode hex string: %v", err)
	}
	return decoded
}

// TestProve checks that a generated single proof contains the expected leaf and sibling hashes.
func TestProve(t *testing.T) {
	expectedProofHex := []string{
		"0000",
		"5db57a86b859d1c286b5f1f585048bf8f6b5e626573a8dc728ed5080f6f43e2c",
	}
	chunks := [][]byte{
		{0x01, 0x01},
		{0x02, 0x02},
		{0x03, 0x03},
		{0x00, 0x00},
	}

	root, err := TreeFromChunks(chunks)
	if err != nil {
		t.Fatalf("failed to construct tree: %v", err)
	}

	proof, err := root.Prove(6)
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	if proof.Index != 6 {
		t.Fatalf("proof has invalid index. expected %d, got %d", 6, proof.Index)
	}
	if !bytes.Equal(proof.Leaf, chunks[2]) {
		t.Fatalf("proof has invalid leaf. expected %v, got %v", chunks[2], proof.Leaf)
	}
	if len(proof.Hashes) != len(expectedProofHex) {
		t.Fatalf("proof has invalid length. expected %d, got %d", len(expectedProofHex), len(proof.Hashes))
	}

	for index, proofHash := range proof.Hashes {
		expectedHash := mustDecodeHex(t, expectedProofHex[index])
		if !bytes.Equal(expectedHash, proofHash) {
			t.Fatalf("invalid proof item. expected %s, got %s", expectedProofHex[index], hex.EncodeToString(proofHash))
		}
	}
}

// benchFixture holds prebuilt trees and proofs shared across all benchmarks.
type benchFixture struct {
	// Tree (1024 leaves)
	treeRoot    *Node
	merkleInput []byte

	// Proof tree (4096 leaves)
	proofRoot         *Node
	proofRootHash     []byte
	singleProof       *Proof
	multiProof        *Multiproof
	adjacentProof     *Multiproof
	fullTreeLeafProof *Multiproof
}

func newBenchFixture(b *testing.B) *benchFixture {
	b.Helper()

	// ---------- tree (1024 leaves) ----------
	const treeLeafCount = 1024
	treeLeaves := make([][]byte, treeLeafCount)
	merkleInput := make([]byte, 0, treeLeafCount*32)
	for i := range treeLeaves {
		leaf := make([]byte, 32)
		for j := range leaf {
			leaf[j] = byte(i + j)
		}
		treeLeaves[i] = leaf
		merkleInput = append(merkleInput, leaf...)
	}
	treeRoot, err := TreeFromChunks(treeLeaves)
	if err != nil {
		b.Fatalf("tree build: %v", err)
	}

	// ---------- proof tree (4096 leaves) ----------
	const proofLeafCount = 4096
	proofLeaves := make([][]byte, proofLeafCount)
	for i := range proofLeaves {
		leaf := make([]byte, 32)
		for j := range leaf {
			leaf[j] = byte(i + j)
		}
		proofLeaves[i] = leaf
	}
	proofRoot, err := TreeFromChunks(proofLeaves)
	if err != nil {
		b.Fatalf("proof tree build: %v", err)
	}

	singleProof, err := proofRoot.Prove(proofLeafCount + 513)
	if err != nil {
		b.Fatalf("single proof: %v", err)
	}
	multiProof, err := proofRoot.ProveMulti([]int{proofLeafCount + 513, proofLeafCount + 514})
	if err != nil {
		b.Fatalf("multi proof: %v", err)
	}
	adjacentProof, err := proofRoot.ProveMulti([]int{proofLeafCount + 256, proofLeafCount + 257})
	if err != nil {
		b.Fatalf("adjacent proof: %v", err)
	}

	fullIdx := make([]int, proofLeafCount)
	for i := range fullIdx {
		fullIdx[i] = proofLeafCount + i
	}
	fullTreeLeafProof, err := proofRoot.ProveMulti(fullIdx)
	if err != nil {
		b.Fatalf("full tree proof: %v", err)
	}

	return &benchFixture{
		treeRoot:          treeRoot,
		merkleInput:       merkleInput,
		proofRoot:         proofRoot,
		proofRootHash:     proofRoot.Hash(),
		singleProof:       singleProof,
		multiProof:        multiProof,
		adjacentProof:     adjacentProof,
		fullTreeLeafProof: fullTreeLeafProof,
	}
}

func BenchmarkNodeProve(b *testing.B) {
	f := newBenchFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.proofRoot.Prove(f.singleProof.Index); err != nil {
			b.Fatal(err)
		}
	}
}

// TestProveMulti checks that a generated multiproof includes only the hashes that are still required.
func TestProveMulti(t *testing.T) {
	chunks := [][]byte{
		{0x01, 0x01},
		{0x02, 0x02},
		{0x03, 0x03},
		{0x04, 0x04},
	}

	root, err := TreeFromChunks(chunks)
	if err != nil {
		t.Fatalf("failed to construct tree: %v", err)
	}

	proof, err := root.ProveMulti([]int{6, 7})
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	if len(proof.Hashes) != 1 {
		t.Fatalf("incorrect number of hashes in proof. expected 1, got %d", len(proof.Hashes))
	}
}

// TestVerifyProof checks valid, invalid, and malformed single-proof verification paths.
func TestVerifyProof(t *testing.T) {
	fixture := newProofFixture()

	tests := []struct {
		name        string
		root        []byte
		proof       *Proof
		expectValid bool
		expectError bool
	}{
		{
			name: "valid single leaf proof",
			root: fixture.root,
			proof: &Proof{
				Index:  4,
				Leaf:   fixture.leaf0,
				Hashes: [][]byte{fixture.leaf1, fixture.node1},
			},
			expectValid: true,
		},
		{
			name: "invalid proof wrong leaf",
			root: fixture.root,
			proof: &Proof{
				Index:  4,
				Leaf:   sha256Bytes([]byte("wrong_leaf")),
				Hashes: [][]byte{fixture.leaf1, fixture.node1},
			},
			expectValid: false,
		},
		{
			name: "invalid proof length",
			root: fixture.root,
			proof: &Proof{
				Index:  4,
				Leaf:   fixture.leaf0,
				Hashes: [][]byte{fixture.leaf1},
			},
			expectError: true,
		},
		{
			name: "valid rightmost leaf proof",
			root: fixture.root,
			proof: &Proof{
				Index:  7,
				Leaf:   fixture.leaf3,
				Hashes: [][]byte{fixture.leaf2, fixture.node0},
			},
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := VerifyProof(tt.root, tt.proof)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if valid != tt.expectValid {
				t.Fatalf("expected valid=%v, got %v", tt.expectValid, valid)
			}
		})
	}
}

// TestVerifyMultiproof checks valid, invalid, and malformed multiproof verification paths.
func TestVerifyMultiproof(t *testing.T) {
	fixture := newProofFixture()

	tests := []struct {
		name        string
		root        []byte
		proof       [][]byte
		leaves      [][]byte
		indices     []int
		expectValid bool
		expectError bool
	}{
		{
			name:        "valid multiproof for two leaves",
			root:        fixture.root,
			proof:       [][]byte{fixture.leaf2, fixture.leaf1},
			leaves:      [][]byte{fixture.leaf0, fixture.leaf3},
			indices:     []int{4, 7},
			expectValid: true,
		},
		{
			name:        "empty indices",
			root:        fixture.root,
			proof:       [][]byte{},
			leaves:      [][]byte{},
			indices:     []int{},
			expectError: true,
		},
		{
			name:        "mismatched leaves and indices",
			root:        fixture.root,
			proof:       nil,
			leaves:      [][]byte{fixture.leaf0, fixture.leaf1},
			indices:     []int{4},
			expectError: true,
		},
		{
			name:        "missing required proof nodes",
			root:        fixture.root,
			proof:       nil,
			leaves:      [][]byte{fixture.leaf0, fixture.leaf1},
			indices:     []int{4, 5},
			expectError: true,
		},
		{
			name:        "invalid multiproof wrong leaf data",
			root:        fixture.root,
			proof:       [][]byte{fixture.leaf2, fixture.leaf1},
			leaves:      [][]byte{sha256Bytes([]byte("wrong_leaf")), fixture.leaf3},
			indices:     []int{4, 7},
			expectValid: false,
		},
		{
			name:        "multiproof for all leaves",
			root:        fixture.root,
			proof:       nil,
			leaves:      [][]byte{fixture.leaf0, fixture.leaf1, fixture.leaf2, fixture.leaf3},
			indices:     []int{4, 5, 6, 7},
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := VerifyMultiproof(tt.root, tt.proof, tt.leaves, tt.indices)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if valid != tt.expectValid {
				t.Fatalf("expected valid=%v, got %v", tt.expectValid, valid)
			}
		})
	}
}

// TestGetPosAtLevel checks how generalized-index bits map to left and right branches.
func TestGetPosAtLevel(t *testing.T) {
	tests := []struct {
		name     string
		index    int
		level    int
		expected bool
	}{
		{name: "4 level 0", index: 4, level: 0, expected: false},
		{name: "4 level 2", index: 4, level: 2, expected: true},
		{name: "5 level 0", index: 5, level: 0, expected: true},
		{name: "7 level 1", index: 7, level: 1, expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := getPosAtLevel(tt.index, tt.level); result != tt.expected {
				t.Fatalf("getPosAtLevel(%d, %d) = %v, want %v", tt.index, tt.level, result, tt.expected)
			}
		})
	}
}

// TestGetPathLength checks that generalized indices map to the expected tree depth.
func TestGetPathLength(t *testing.T) {
	tests := []struct {
		name     string
		index    int
		expected int
	}{
		{name: "root", index: 1, expected: 0},
		{name: "level one", index: 2, expected: 1},
		{name: "level two", index: 7, expected: 2},
		{name: "level five", index: 32, expected: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := getPathLength(tt.index); result != tt.expected {
				t.Fatalf("getPathLength(%d) = %d, want %d", tt.index, result, tt.expected)
			}
		})
	}
}

// TestGetSibling checks that each generalized index maps to the expected sibling index.
func TestGetSibling(t *testing.T) {
	tests := []struct {
		name     string
		index    int
		expected int
	}{
		{name: "root", index: 1, expected: 0},
		{name: "left child", index: 2, expected: 3},
		{name: "right child", index: 7, expected: 6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := getSibling(tt.index); result != tt.expected {
				t.Fatalf("getSibling(%d) = %d, want %d", tt.index, result, tt.expected)
			}
		})
	}
}

// TestGetParent checks that each generalized index maps to the expected parent index.
func TestGetParent(t *testing.T) {
	tests := []struct {
		name     string
		index    int
		expected int
	}{
		{name: "root", index: 1, expected: 0},
		{name: "level one", index: 3, expected: 1},
		{name: "level three", index: 11, expected: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := getParent(tt.index); result != tt.expected {
				t.Fatalf("getParent(%d) = %d, want %d", tt.index, result, tt.expected)
			}
		})
	}
}

// TestGetRequiredIndices checks that multiproof verification requests only the missing sibling nodes.
func TestGetRequiredIndices(t *testing.T) {
	tests := []struct {
		name        string
		leafIndices []int
		expected    []int
	}{
		{name: "empty input", leafIndices: nil, expected: []int{}},
		{name: "existing regression case", leafIndices: []int{10, 48, 49}, expected: []int{25, 13, 11, 7, 4}},
		{name: "single leaf", leafIndices: []int{4}, expected: []int{5, 3}},
		{name: "adjacent leaves", leafIndices: []int{4, 5}, expected: []int{3}},
		{name: "all leaves", leafIndices: []int{4, 5, 6, 7}, expected: []int{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getRequiredIndices(tt.leafIndices)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d indices, got %d: %v", len(tt.expected), len(result), result)
			}
			for i := range tt.expected {
				if result[i] != tt.expected[i] {
					t.Fatalf("expected indices %v, got %v", tt.expected, result)
				}
			}
		})
	}
}

// TestMultiproofCompressionRoundTrip checks that zero-hash compression can be reversed without data loss.
func TestMultiproofCompressionRoundTrip(t *testing.T) {
	proof := &Multiproof{
		Indices: []int{4, 5},
		Leaves: [][]byte{
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 32),
		},
		Hashes: [][]byte{
			zeroHashes[0][:],
			bytes.Repeat([]byte{3}, 32),
			zeroHashes[1][:],
		},
	}

	compressed := proof.Compress()
	if compressed == nil {
		t.Fatal("expected compressed proof")
	}

	decompressed := compressed.Decompress()
	if len(decompressed.Hashes) != len(proof.Hashes) {
		t.Fatalf("unexpected decompressed hash count: got %d want %d", len(decompressed.Hashes), len(proof.Hashes))
	}

	for i := range proof.Hashes {
		if !bytes.Equal(decompressed.Hashes[i], proof.Hashes[i]) {
			t.Fatalf("hash %d mismatch after round trip", i)
		}
	}
}
func BenchmarkNodeProveMulti(b *testing.B) {
	f := newBenchFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.proofRoot.ProveMulti(f.multiProof.Indices); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyProof(b *testing.B) {
	f := newBenchFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := VerifyProof(f.proofRootHash, f.singleProof)
		if err != nil {
			b.Fatal(err)
		}
		if !ok {
			b.Fatal("proof did not verify")
		}
	}
}

func BenchmarkVerifyMultiproof(b *testing.B) {
	f := newBenchFixture(b)

	b.Run("adjacent_leaves", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ok, err := VerifyMultiproof(f.proofRootHash, f.adjacentProof.Hashes, f.adjacentProof.Leaves, f.adjacentProof.Indices)
			if err != nil {
				b.Fatal(err)
			}
			if !ok {
				b.Fatal("verify failed")
			}
		}
	})

	b.Run("all_leaves", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ok, err := VerifyMultiproof(f.proofRootHash, f.fullTreeLeafProof.Hashes, f.fullTreeLeafProof.Leaves, f.fullTreeLeafProof.Indices)
			if err != nil {
				b.Fatal(err)
			}
			if !ok {
				b.Fatal("verify failed")
			}
		}
	})
}
