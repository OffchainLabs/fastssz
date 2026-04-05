package ssz

import (
	"errors"
	"fmt"
	"hash"
	"math/bits"
	"sync"

	"github.com/minio/sha256-simd"
	"github.com/prysmaticlabs/gohashtree"
)

var (
	// ErrIncorrectByteSize means that the byte size is incorrect
	ErrIncorrectByteSize = fmt.Errorf("incorrect byte size")
	// ErrIncorrectListSize means that the size of the list is incorrect
	ErrIncorrectListSize = fmt.Errorf("incorrect list size")
	ErrRootSizeInvalid   = errors.New("root must be 32 bytes")
)

var zeroHashes [65][32]byte

// zeroHashLevels lets proof compression detect precomputed zero hashes without
// allocating temporary strings for lookup keys.
var zeroHashLevels map[[32]byte]int
var trueBytes, falseBytes []byte

const (
	mask0 = ^uint64((1 << (1 << iota)) - 1)
	mask1
	mask2
	mask3
	mask4
	mask5
)

const (
	bit0 = uint8(1 << iota)
	bit1
	bit2
	bit3
	bit4
	bit5
)

func init() {
	falseBytes = make([]byte, 32)
	trueBytes = make([]byte, 32)
	trueBytes[0] = 1
	zeroHashLevels = make(map[[32]byte]int)
	zeroHashLevels[zeroHashes[0]] = 0

	tmp := [64]byte{}
	for i := 0; i < 64; i++ {
		copy(tmp[:32], zeroHashes[i][:])
		copy(tmp[32:], zeroHashes[i][:])
		zeroHashes[i+1] = sha256.Sum256(tmp[:])
		zeroHashLevels[zeroHashes[i+1]] = i + 1
	}
}

// HashWithDefaultHasher hashes a HashRoot object with a Hasher from
// the default HasherPool
func HashWithDefaultHasher(v HashRoot) ([32]byte, error) {
	hh := DefaultHasherPool.Get()
	if err := v.HashTreeRootWith(hh); err != nil {
		DefaultHasherPool.Put(hh)
		return [32]byte{}, err
	}
	root, err := hh.HashRoot()
	DefaultHasherPool.Put(hh)
	return root, err
}

var zeroBytes = make([]byte, 32)

// DefaultHasherPool is a default hasher pool
var DefaultHasherPool HasherPool

// Hasher is a utility tool to hash SSZ structs
type Hasher struct {
	// buffer array to store hashing values
	buf []byte

	// tmp array used for uint64 and bitlist processing
	tmp []byte

	// tmp array used during the merkleize process
	merkleizeTmp []byte

	// sha256 hash function
	hash hash.Hash
}

// NewHasher creates a new Hasher object
func NewHasher() *Hasher {
	return &Hasher{
		hash: sha256.New(),
		tmp:  make([]byte, 32),
	}
}

// NewHasherWithHash creates a new Hasher object with a custom hash function.
func NewHasherWithHash(hh hash.Hash) *Hasher {
	return &Hasher{
		hash: hh,
		tmp:  make([]byte, 32),
	}
}

// Reset resets the Hasher obj
func (h *Hasher) Reset() {
	h.buf = h.buf[:0]
	h.hash.Reset()
}

// AppendBytes32 appends bytes and pads them up to a full SSZ chunk.
func (h *Hasher) AppendBytes32(b []byte) {
	h.buf = append(h.buf, b...)
	if rest := len(b) % 32; rest != 0 {
		// pad zero bytes to the left
		h.buf = append(h.buf, zeroBytes[:32-rest]...)
	}
}

// PutUint appends a uint8, uint16, uint32, or uint64 in 32 bytes.
func PutUint[T appendUints](h *Hasher, i T) {
	h.AppendBytes32(MarshalUint(nil, i))
}

// PutUint64 appends a uint64 in 32 bytes.
//
// Deprecated: use PutUint instead.
func (h *Hasher) PutUint64(i uint64) {
	PutUint(h, i)
}

// PutUint32 appends a uint32 in 32 bytes.
//
// Deprecated: use PutUint instead.
func (h *Hasher) PutUint32(i uint32) {
	PutUint(h, i)
}

// PutUint16 appends a uint16 in 32 bytes.
//
// Deprecated: use PutUint instead.
func (h *Hasher) PutUint16(i uint16) {
	PutUint(h, i)
}

// PutUint8 appends a uint8 in 32 bytes.
//
// Deprecated: use PutUint instead.
func (h *Hasher) PutUint8(i uint8) {
	PutUint(h, i)
}

// CalculateLimit returns the number of 32-byte chunks needed for a list limit.
func CalculateLimit(maxCapacity, numItems, size uint64) uint64 {
	limit := (maxCapacity*size + 31) / 32
	if limit != 0 {
		return limit
	}
	if numItems == 0 {
		return 1
	}
	return numItems
}

// FillUpTo32 pads the buffered data so its length is aligned to 32 bytes.
func (h *Hasher) FillUpTo32() {
	// pad zero bytes to the left
	if rest := len(h.buf) % 32; rest != 0 {
		h.buf = append(h.buf, zeroBytes[:32-rest]...)
	}
}

type appendUints interface {
	~uint8 | ~uint16 | ~uint32 | ~uint64
}

// AppendUint appends a uint8, uint16, uint32, or uint64 value without 32-byte padding.
func AppendUint[T appendUints](h *Hasher, i T) {
	h.buf = MarshalUint(h.buf, i)
}

// AppendUint8 appends a uint8 without 32-byte padding.
//
// Deprecated: use AppendUint instead.
func (h *Hasher) AppendUint8(i uint8) {
	AppendUint(h, i)
}

// AppendUint64 appends a uint64 without 32-byte padding.
//
// Deprecated: use AppendUint instead.
func (h *Hasher) AppendUint64(i uint64) {
	AppendUint(h, i)
}

// Append appends raw bytes without SSZ chunk padding.
func (h *Hasher) Append(i []byte) {
	h.buf = append(h.buf, i...)
}

// PutRootVector appends an array of roots.
func (h *Hasher) PutRootVector(roots [][]byte, maxCapacity ...uint64) error {
	index := h.Index()
	for _, root := range roots {
		if len(root) != 32 {
			return ErrRootSizeInvalid
		}
		h.buf = append(h.buf, root...)
	}

	if len(maxCapacity) == 0 {
		h.Merkleize(index)
	} else {
		numItems := uint64(len(roots))
		limit := CalculateLimit(maxCapacity[0], numItems, 32)

		h.MerkleizeWithMixin(index, numItems, limit)
	}
	return nil
}

// PutUint64Array appends an array of uint64.
func (h *Hasher) PutUint64Array(values []uint64, maxCapacity ...uint64) {
	index := h.Index()
	for _, value := range values {
		h.buf = MarshalUint(h.buf, value)
	}

	// pad zero bytes to the left
	h.FillUpTo32()

	if len(maxCapacity) == 0 {
		// Array with fixed size
		h.Merkleize(index)
	} else {
		numItems := uint64(len(values))
		limit := CalculateLimit(maxCapacity[0], numItems, 8)

		h.MerkleizeWithMixin(index, numItems, limit)
	}
}

// parseBitlist removes the delimiter bit and returns the logical bit size.
func parseBitlist(dst, bitlist []byte) ([]byte, uint64) {
	msb := uint8(bits.Len8(bitlist[len(bitlist)-1])) - 1
	size := uint64(8*(len(bitlist)-1) + int(msb))

	dst = append(dst, bitlist...)
	dst[len(dst)-1] &^= uint8(1 << msb)

	newLen := len(dst)
	for i := len(dst) - 1; i >= 0; i-- {
		if dst[i] != 0x00 {
			break
		}
		newLen = i
	}
	res := dst[:newLen]
	return res, size
}

// PutBitlist appends an SSZ bitlist.
func (h *Hasher) PutBitlist(bitlist []byte, maxSize uint64) {
	var size uint64
	h.tmp, size = parseBitlist(h.tmp[:0], bitlist)

	// merkleize the content with mix in length
	index := h.Index()
	h.AppendBytes32(h.tmp)
	h.MerkleizeWithMixin(index, size, (maxSize+255)/256)
}

// PutBool appends a boolean.
func (h *Hasher) PutBool(b bool) {
	if b {
		h.buf = append(h.buf, trueBytes...)
	} else {
		h.buf = append(h.buf, falseBytes...)
	}
}

// PutBytes appends bytes.
func (h *Hasher) PutBytes(b []byte) {
	if len(b) <= 32 {
		h.AppendBytes32(b)
		return
	}

	// if the bytes are longer than 32 we have to
	// merkleize the content
	index := h.Index()
	h.AppendBytes32(b)
	h.Merkleize(index)
}

// Index marks the current buffer index.
func (h *Hasher) Index() int {
	return len(h.buf)
}

// Merkleize replaces the buffered tail that starts at index with its Merkle root.
func (h *Hasher) Merkleize(index int) {
	input := h.buf[index:]
	if root, ok := merkleizeInputInPlace(input, 0); ok {
		// When the buffer already has one spare chunk of capacity we can hash
		// directly inside it and avoid copying the subtree into scratch space.
		copy(h.buf[index:index+32], root)
		h.buf = h.buf[:index+32]
		return
	}

	h.buf = append(h.buf[:index], h.merkleizeInput(input, 0)...)
}

// MerkleizeWithMixin merkleizes the buffered tail and mixes the logical length
// into the final root. This is used for SSZ lists and bitlists.
func (h *Hasher) MerkleizeWithMixin(index int, num, limit uint64) {
	buf := h.buf[index:]
	input, ok := merkleizeInputInPlace(buf, limit)
	if !ok {
		input = h.merkleizeInput(buf, limit)
	}
	// mixin with the size
	sizemix := h.tmp[:32]
	for i := range sizemix {
		sizemix[i] = 0
	}
	MarshalUint(sizemix[:0], num)
	h.buf = append(h.buf[:index], h.doHash(input, input, sizemix)...)
}

// HashRoot returns the final 32-byte root currently stored in the buffer.
func (h *Hasher) HashRoot() (res [32]byte, err error) {
	if len(h.buf) != 32 {
		err = ErrRootSizeInvalid
		return
	}
	copy(res[:], h.buf)
	return
}

// HasherPool may be used for pooling Hashers for similarly typed SSZs.
type HasherPool struct {
	pool sync.Pool
}

// Get acquires a Hasher from the pool.
func (hh *HasherPool) Get() *Hasher {
	h := hh.pool.Get()
	if h == nil {
		return NewHasher()
	}
	return h.(*Hasher)
}

// Put releases the Hasher to the pool.
func (hh *HasherPool) Put(h *Hasher) {
	h.Reset()
	hh.pool.Put(h)
}

func nextPowerOfTwo(v uint64) uint {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v++
	return uint(v)
}

// doHash hashes two already-serialized 32-byte nodes into dst.
func (h *Hasher) doHash(dst []byte, a []byte, b []byte) []byte {
	h.hash.Write(a)
	h.hash.Write(b)
	h.hash.Sum(dst[:0])
	h.hash.Reset()
	return dst
}

// merkleizeInput hashes arbitrary input bytes by first chunking them into
// 32-byte leaves and then building the Merkle tree in scratch space.
func merkleizeInput(input []byte, limit uint64) []byte {
	return merkleizeInputInto(nil, input, limit)
}

// merkleizeInput hashes input bytes using the hasher's reusable scratch buffer.
func (h *Hasher) merkleizeInput(input []byte, limit uint64) []byte {
	h.merkleizeTmp = merkleizeInputInto(h.merkleizeTmp[:0], input, limit)
	return h.merkleizeTmp
}

// merkleizeInputInto builds the Merkle tree inside dst. The extra chunk of
// capacity allows odd layers to append one zero hash without reallocating.
func merkleizeInputInto(dst []byte, input []byte, limit uint64) []byte {
	chunkCount := (len(input) + 31) / 32
	treeSize := uint64(chunkCount)
	if limit != 0 {
		treeSize = limit
	}
	dep := depth(treeSize)

	// Empty inputs hash to the precomputed zero hash for the requested depth.
	if chunkCount == 0 {
		if cap(dst) < 32 {
			dst = make([]byte, 32)
		} else {
			dst = dst[:32]
		}
		copy(dst, zeroHashesRaw[dep][:])
		return dst
	}

	// Copy the chunks into a reusable byte buffer so hashing can happen in place.
	paddedLen := chunkCount * 32
	if cap(dst) < paddedLen+32 {
		dst = make([]byte, paddedLen, paddedLen+32)
	} else {
		dst = dst[:paddedLen]
	}
	copy(dst, input)
	for i := len(input); i < paddedLen; i++ {
		dst[i] = 0
	}

	layerLen := chunkCount
	for i := uint8(0); i < dep; i++ {
		if layerLen%2 == 1 {
			dst = append(dst[:layerLen*32], zeroHashesRaw[i][:]...)
			layerLen++
		} else {
			dst = dst[:layerLen*32]
		}

		outputLen := (layerLen / 2) * 32
		if err := gohashtree.HashByteSlice(dst[:outputLen], dst[:layerLen*32]); err != nil {
			panic(err)
		}

		layerLen /= 2
		dst = dst[:outputLen]
	}
	return dst[:32]
}

// merkleizeInputInPlace tries to reuse the caller's buffer as the Merkle tree
// workspace. It returns false when the buffer shape does not support safe
// in-place hashing.
func merkleizeInputInPlace(input []byte, limit uint64) ([]byte, bool) {
	chunkCount := len(input) / 32
	if len(input)%32 != 0 {
		return nil, false
	}

	treeSize := uint64(chunkCount)
	if limit != 0 {
		treeSize = limit
	}
	dep := depth(treeSize)

	if chunkCount == 0 {
		return zeroHashesRaw[dep][:], true
	}

	layer := input
	layerLen := chunkCount
	for i := uint8(0); i < dep; i++ {
		if layerLen%2 == 1 {
			if cap(layer) < layerLen*32+32 {
				return nil, false
			}
			layer = append(layer[:layerLen*32], zeroHashesRaw[i][:]...)
			layerLen++
		} else {
			layer = layer[:layerLen*32]
		}

		outputLen := (layerLen / 2) * 32
		if err := gohashtree.HashByteSlice(layer[:outputLen], layer[:layerLen*32]); err != nil {
			panic(err)
		}

		layerLen /= 2
		layer = layer[:outputLen]
	}
	return layer[:32], true
}

// Depth retrieves the appropriate depth for the provided trie size.
func depth(v uint64) (out uint8) {
	// bitmagic: binary search through a uint32, offset down by 1 to not round powers of 2 up.
	// Then adding 1 to it to not get the index of the first bit, but the length of the bits (depth of tree)
	// Zero is a special case, it has a 0 depth.
	// Example:
	//  (in out): (0 0), (1 0), (2 1), (3 2), (4 2), (5 3), (6 3), (7 3), (8 3), (9 4)
	if v <= 1 {
		return 0
	}
	v--
	if v&mask5 != 0 {
		v >>= bit5
		out |= bit5
	}
	if v&mask4 != 0 {
		v >>= bit4
		out |= bit4
	}
	if v&mask3 != 0 {
		v >>= bit3
		out |= bit3
	}
	if v&mask2 != 0 {
		v >>= bit2
		out |= bit2
	}
	if v&mask1 != 0 {
		v >>= bit1
		out |= bit1
	}
	if v&mask0 != 0 {
		out |= bit0
	}
	out++
	return
}
