package ssz

import (
	"bytes"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

type treeSlot uint64

// TestTreeFromChunks checks that chunk-backed trees preserve leaf order and reject empty input.
func TestTreeFromChunks(t *testing.T) {
	t.Run("builds tree from chunks", func(t *testing.T) {
		// This case checks that leaves can be read back from their generalized indices.
		chunks := [][]byte{
			{0x01, 0x01},
			{0x02, 0x02},
			{0x03, 0x03},
			{0x00, 0x00},
		}

		r, err := TreeFromChunks(chunks)
		if err != nil {
			t.Fatalf("failed to construct tree: %v", err)
		}
		for i := 4; i < 8; i++ {
			l, err := r.Get(i)
			if err != nil {
				t.Fatalf("failed getting leaf: %v", err)
			}
			if !bytes.Equal(l.value, chunks[i-4]) {
				t.Fatalf("incorrect leaf at index %d", i)
			}
		}
	})

	t.Run("rejects empty input", func(t *testing.T) {
		// This case checks that callers get a clear error instead of a panic for empty input.
		if _, err := TreeFromChunks(nil); err == nil {
			t.Fatal("expected an error for empty chunks")
		}
	})
}

// TestHashTree checks that tree hashing stays stable for the existing regression fixture.
func TestHashTree(t *testing.T) {
	expectedRootHex := "6621edd5d039d27d1ced186d57691a04903ac79b389187c2d453b5d3cd65180e"
	expectedRoot, err := hex.DecodeString(expectedRootHex)
	if err != nil {
		t.Fatalf("failed to decode hex string: %v", err)
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

	rootHash := root.Hash()
	if !bytes.Equal(rootHash, expectedRoot) {
		t.Fatalf("computed hash is incorrect. expected %s, got %s", expectedRootHex, hex.EncodeToString(rootHash))
	}
}

// TestLeafFromUintAcceptsNamedUint64 checks that named uint64 types still work with the generic helper.
func TestLeafFromUintAcceptsNamedUint64(t *testing.T) {
	leaf := LeafFromUint(treeSlot(7))
	want := make([]byte, 32)
	want[0] = 7
	if !bytes.Equal(leaf.value, want) {
		t.Fatalf("unexpected leaf value: %v", leaf.value)
	}
}

// TestTreeFromNodes checks tree-builder error handling for invalid leaf collections and missing lookups.
func TestTreeFromNodes(t *testing.T) {
	t.Run("rejects empty leaves", func(t *testing.T) {
		// This case checks that an empty leaf list returns an error.
		if _, err := TreeFromNodes(nil); err == nil {
			t.Fatal("expected an error for empty leaves")
		}
	})

	t.Run("rejects missing node lookups", func(t *testing.T) {
		// This case checks that reading a node outside the tree returns an error.
		root, err := TreeFromChunks([][]byte{
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 32),
		})
		if err != nil {
			t.Fatalf("failed to build tree: %v", err)
		}

		if _, err := root.Get(8); err == nil {
			t.Fatal("expected an error for a missing node")
		}
	})
}

// TestTreeFromNodesWithMixin checks validation around mixin tree sizing rules.
func TestTreeFromNodesWithMixin(t *testing.T) {
	t.Run("rejects zero limit", func(t *testing.T) {
		// This case checks that the mixin tree requires a positive limit.
		if _, err := TreeFromNodesWithMixin(nil, 0, 0); err == nil {
			t.Fatal("expected an error for zero limit")
		}
	})

	t.Run("rejects leaf overflow", func(t *testing.T) {
		// This case checks that the builder rejects more leaves than the declared tree limit.
		leaves := []*Node{
			LeafFromUint8(1),
			LeafFromUint8(2),
			LeafFromUint8(3),
		}
		if _, err := TreeFromNodesWithMixin(leaves, len(leaves), 2); err == nil {
			t.Fatal("expected an error when leaves exceed the limit")
		}
	})
}

// TestLeafFromBytesPanicsForOversizedInput checks that oversized leaf input still fails loudly.
func TestLeafFromBytesPanicsForOversizedInput(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for oversized leaf input")
		}
	}()

	LeafFromBytes(bytes.Repeat([]byte{1}, 33))
}

// TestDeprecatedLeafWrappersCallLeafFromUint checks that deprecated wrappers still delegate to the generic helper.
func TestDeprecatedLeafWrappersCallLeafFromUint(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "tree.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"LeafFromUint64", "LeafFromUint32", "LeafFromUint16", "LeafFromUint8"} {
		found := false
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != name {
				continue
			}
			found = true
			if len(fn.Body.List) != 1 {
				t.Fatalf("expected %s to have exactly one statement", name)
			}
			ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				t.Fatalf("expected %s to return a direct call", name)
			}
			call, ok := ret.Results[0].(*ast.CallExpr)
			if !ok {
				t.Fatalf("expected %s to return a call", name)
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "LeafFromUint" {
				t.Fatalf("expected %s to call LeafFromUint", name)
			}
		}
		if !found {
			t.Fatalf("did not find %s", name)
		}
	}
}

// TestTreeInternalsUseGenericUintHelpers checks that mixin trees use the shared uint leaf helper.
func TestTreeInternalsUseGenericUintHelpers(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "tree.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "TreeFromNodesWithMixin" {
			continue
		}
		callsLeafFromUint := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if ok && ident.Name == "LeafFromUint" {
				callsLeafFromUint = true
			}
			return true
		})
		if !callsLeafFromUint {
			t.Fatal("expected TreeFromNodesWithMixin to use LeafFromUint")
		}
		return
	}
	t.Fatal("did not find TreeFromNodesWithMixin")
}

func BenchmarkNodeHash(b *testing.B) {
	f := newBenchFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = f.treeRoot.Hash()
	}
}
