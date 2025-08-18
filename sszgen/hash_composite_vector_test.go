package main

import (
	"bytes"
	"testing"

	ssz "github.com/prysmaticlabs/fastssz"
)

// Test struct for composite types
type TestComposite struct {
	Field1 uint64
	Field2 []byte `ssz-size:"32"`
}

// Test struct with vector of composite types
type TestVectorComposite struct {
	CompositeVector [3]TestComposite `ssz-size:"3"`
}

func (t *TestComposite) HashTreeRootWith(hh *ssz.Hasher) (err error) {
	indx := hh.Index()
	hh.PutUint64(t.Field1)
	hh.PutBytes(t.Field2)
	hh.Merkleize(indx)
	return
}

func (t *TestComposite) HashTreeRoot() ([32]byte, error) {
	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)
	err := t.HashTreeRootWith(hh)
	if err != nil {
		return [32]byte{}, err
	}
	return hh.HashRoot()
}

func (t *TestVectorComposite) HashTreeRootWith(hh *ssz.Hasher) (err error) {
	indx := hh.Index()

	// This tests the new code path for vectors of composite types
	{
		subIndx := hh.Index()
		for _, elem := range t.CompositeVector {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.Merkleize(subIndx)
	}

	hh.Merkleize(indx)
	return
}

func (t *TestVectorComposite) HashTreeRoot() ([32]byte, error) {
	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)
	err := t.HashTreeRootWith(hh)
	if err != nil {
		return [32]byte{}, err
	}
	return hh.HashRoot()
}

func TestVectorCompositeHashTreeRoot(t *testing.T) {
	// Create test data
	testData := &TestVectorComposite{
		CompositeVector: [3]TestComposite{
			{Field1: 1, Field2: make([]byte, 32)},
			{Field1: 2, Field2: make([]byte, 32)},
			{Field1: 3, Field2: make([]byte, 32)},
		},
	}

	// Fill field2 with test data
	for i := 0; i < 32; i++ {
		testData.CompositeVector[0].Field2[i] = byte(i)
		testData.CompositeVector[1].Field2[i] = byte(i + 32)
		testData.CompositeVector[2].Field2[i] = byte(i + 64)
	}

	// Test that HashTreeRoot doesn't return error
	root, err := testData.HashTreeRoot()
	if err != nil {
		t.Fatalf("HashTreeRoot failed: %v", err)
	}

	// Test that root is not empty
	emptyRoot := [32]byte{}
	if bytes.Equal(root[:], emptyRoot[:]) {
		t.Fatal("HashTreeRoot returned empty root")
	}

	// Test consistency - same input should produce same root
	root2, err := testData.HashTreeRoot()
	if err != nil {
		t.Fatalf("Second HashTreeRoot failed: %v", err)
	}

	if !bytes.Equal(root[:], root2[:]) {
		t.Fatal("HashTreeRoot is not consistent")
	}

	// Test that different data produces different root
	testData2 := &TestVectorComposite{
		CompositeVector: [3]TestComposite{
			{Field1: 4, Field2: make([]byte, 32)}, // Different field1
			{Field1: 2, Field2: make([]byte, 32)},
			{Field1: 3, Field2: make([]byte, 32)},
		},
	}

	root3, err := testData2.HashTreeRoot()
	if err != nil {
		t.Fatalf("Third HashTreeRoot failed: %v", err)
	}

	if bytes.Equal(root[:], root3[:]) {
		t.Fatal("Different inputs produced same hash root")
	}
}
