package ssz

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

type validatorIndex uint64

func TestNextPowerOfTwo(t *testing.T) {
	cases := []struct {
		Num, Res uint64
	}{
		{0, 0},
		{1, 1},
		{2, 2},
		{3, 4},
		{4, 4},
		{5, 8},
		{6, 8},
		{7, 8},
		{8, 8},
		{9, 16},
		{10, 16},
		{11, 16},
		{13, 16},
	}
	for _, c := range cases {
		if next := nextPowerOfTwo(c.Num); uint64(next) != c.Res {
			t.Fatalf("num %d, expected %d but found %d", c.Num, c.Res, next)
		}
	}
}

func TestMerkleize8ByteVector(t *testing.T) {
	result := merkleizeInput([]byte{'1', '2', '3', '4', '5', '6', '7', '8'}, 0)
	if !bytes.Equal(result, []byte{49, 50, 51, 52, 53, 54, 55, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("Unexpected result: %v", result)
	}
}

func TestAppendUintAcceptsNamedUint64(t *testing.T) {
	var h Hasher
	AppendUint(&h, validatorIndex(7))

	want := MarshalUint64(nil, 7)
	if !bytes.Equal(h.buf, want) {
		t.Fatalf("unexpected result: %v", h.buf)
	}
}

func TestPutUintAcceptsNamedUint64(t *testing.T) {
	var h Hasher
	PutUint(&h, validatorIndex(7))

	want := make([]byte, 32)
	copy(want, MarshalUint64(nil, 7))
	if !bytes.Equal(h.buf, want) {
		t.Fatalf("unexpected result: %v", h.buf)
	}
}

func TestDeprecatedAppendWrappersCallAppendUint(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "hasher.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"AppendUint8", "AppendUint64"} {
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
			exprStmt, ok := fn.Body.List[0].(*ast.ExprStmt)
			if !ok {
				t.Fatalf("expected %s to delegate with a direct call", name)
			}
			call, ok := exprStmt.X.(*ast.CallExpr)
			if !ok {
				t.Fatalf("expected %s body to be a call", name)
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "AppendUint" {
				t.Fatalf("expected %s to call AppendUint", name)
			}
		}
		if !found {
			t.Fatalf("did not find %s", name)
		}
	}
}

func TestDeprecatedPutWrappersCallPutUint(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "hasher.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"PutUint64", "PutUint32", "PutUint16", "PutUint8"} {
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
			exprStmt, ok := fn.Body.List[0].(*ast.ExprStmt)
			if !ok {
				t.Fatalf("expected %s to delegate with a direct call", name)
			}
			call, ok := exprStmt.X.(*ast.CallExpr)
			if !ok {
				t.Fatalf("expected %s body to be a call", name)
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "PutUint" {
				t.Fatalf("expected %s to call PutUint", name)
			}
		}
		if !found {
			t.Fatalf("did not find %s", name)
		}
	}
}

func TestAppendUintUsesMarshalUintInternally(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "hasher.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "AppendUint" {
			continue
		}
		callsMarshalUint := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if ok && ident.Name == "MarshalUint" {
				callsMarshalUint = true
			}
			return true
		})
		if !callsMarshalUint {
			t.Fatal("expected AppendUint to use MarshalUint internally")
		}
		return
	}
	t.Fatal("did not find AppendUint")
}

func BenchmarkHasherMerkleize(b *testing.B) {
	f := newBenchFixture(b)
	hasher := NewHasher()

	b.ReportAllocs()
	b.SetBytes(int64(len(f.merkleInput)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.Reset()
		hasher.Append(f.merkleInput)
		hasher.Merkleize(0)
	}
}
