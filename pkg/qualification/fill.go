// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package qualification

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
)

// The memory-hard fill: Lanes x Slices x
// BlocksPerSlice blocks of BlockSize bytes. Block (lane, column) is
// G(prev, ref): prev is the lane's previous block, ref a block chosen from
// prev's first 8 bytes over the Argon2-style reference set. Lanes of one
// slice are computed in parallel; a slice starts once the previous one is
// complete.
const (
	Slices    = 4
	BlockSize = 16 << 10

	fillDomain = "mcq-fill-v2"
	hashWords  = BlockSize / sha256.Size
)

var (
	blockBase64Length = base64.StdEncoding.EncodedLen(BlockSize)
)

// Position is the (lane, column) of a global fill index; indices are
// lane-major.
func (f Fill) Position(index int) (lane, column int) {
	width := Slices * f.BlocksPerSlice
	return index / width, index % width
}

// Index is the global fill index of (lane, column).
func (f Fill) Index(lane, column int) int { return lane*Slices*f.BlocksPerSlice + column }

// G is Expand(SHA-256(domain || 0x00 || nonce || u32be(lane) ||
// u32be(column) || (prev XOR ref))) XOR prev XOR ref, where Expand is the
// SHA-256 counter stream SHA-256(seed || u32be(k)), k = 0..511. Every byte
// of prev and ref enters both the seed and the output, so a block cannot be
// computed from digests of earlier blocks: their full bytes must be
// resident or recomputed. A lane's first block has neither; prev and ref
// are the zero block.
func G(prev, ref, nonce []byte, lane, column int) []byte {
	out := make([]byte, BlockSize)
	gInto(out, prev, ref, nonce, lane, column)
	return out
}

func gInto(out, prev, ref, nonce []byte, lane, column int) {
	mixed := make([]byte, BlockSize)
	if prev != nil {
		for i := range mixed {
			mixed[i] = prev[i] ^ ref[i]
		}
	}
	h := sha256.New()
	h.Write([]byte(fillDomain))
	h.Write([]byte{0})
	h.Write(nonce)
	var position [8]byte
	binary.BigEndian.PutUint32(position[0:4], uint32(lane))
	binary.BigEndian.PutUint32(position[4:8], uint32(column))
	h.Write(position[:])
	h.Write(mixed)
	var counter [sha256.Size + 4]byte
	h.Sum(counter[:0])
	for k := 0; k < hashWords; k++ {
		binary.BigEndian.PutUint32(counter[sha256.Size:], uint32(k))
		word := sha256.Sum256(counter[:])
		for i, b := range word {
			out[k*sha256.Size+i] = b ^ mixed[k*sha256.Size+i]
		}
	}
}

// RefIndex is the global index of the reference block of (lane, column),
// column >= 1, derived from the first 8 bytes of prev. J1 (bytes 0..3,
// big-endian) picks the position with Argon2's non-uniform map; J2 (bytes
// 4..7) the lane. In slice 0 the lane is always the block's own. The
// reference set is every earlier block of the same lane, or every block of
// the completed slices of another lane.
func RefIndex(prev []byte, f Fill, lane, column int) int {
	j1 := uint64(binary.BigEndian.Uint32(prev[0:4]))
	j2 := binary.BigEndian.Uint32(prev[4:8])
	slice := column / f.BlocksPerSlice
	refLane := lane
	if slice > 0 {
		refLane = int(j2 % uint32(f.Lanes))
	}
	size := column
	if refLane != lane {
		size = slice * f.BlocksPerSlice
	}
	x := (j1 * j1) >> 32
	y := (uint64(size) * x) >> 32
	return f.Index(refLane, size-1-int(y))
}

// LeafHash is the Merkle leaf SHA-256(0x00 || block).
func LeafHash(block []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(block)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func nodeHash(left, right [32]byte) [32]byte {
	var buffer [65]byte
	buffer[0] = 1
	copy(buffer[1:], left[:])
	copy(buffer[33:], right[:])
	return sha256.Sum256(buffer[:])
}

// MerkleLevels builds the tree over leaves; an unpaired last node is
// promoted unchanged. The last level holds the root.
func MerkleLevels(leaves [][32]byte) [][][32]byte {
	levels := [][][32]byte{leaves}
	for current := leaves; len(current) > 1; {
		next := make([][32]byte, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				next = append(next, nodeHash(current[i], current[i+1]))
			} else {
				next = append(next, current[i])
			}
		}
		levels = append(levels, next)
		current = next
	}
	return levels
}

// MerklePath is the sibling list of index, leaf to root.
func MerklePath(levels [][][32]byte, index int) []string {
	path := []string{}
	for _, level := range levels[:len(levels)-1] {
		if sibling := index ^ 1; sibling < len(level) {
			path = append(path, hexString(level[sibling]))
		}
		index /= 2
	}
	return path
}

// VerifyPath reports whether leaf at index of an n-leaf tree hashes up to
// root along path, consuming every path node.
func VerifyPath(index, n int, leaf [32]byte, path []string, root [32]byte) bool {
	if index < 0 || index >= n {
		return false
	}
	h, used := leaf, 0
	for width := n; width > 1; width = (width + 1) / 2 {
		if sibling := index ^ 1; sibling < width {
			if used >= len(path) {
				return false
			}
			node, ok := decodeHash(path[used])
			if !ok {
				return false
			}
			used++
			if index%2 == 0 {
				h = nodeHash(h, node)
			} else {
				h = nodeHash(node, h)
			}
		}
		index /= 2
	}
	return used == len(path) && h == root
}

func hexString(value [32]byte) string { return hex.EncodeToString(value[:]) }

func decodeHash(value string) ([32]byte, bool) {
	var out [32]byte
	if !hex64.MatchString(value) {
		return out, false
	}
	_, _ = hex.Decode(out[:], []byte(value))
	return out, true
}

func encodeBlock(block []byte) string { return base64.StdEncoding.EncodeToString(block) }

func decodeBlock(value string) ([]byte, error) {
	block, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(block) != BlockSize || base64.StdEncoding.EncodeToString(block) != value {
		return nil, errors.New("block must be canonical base64 of 16 KiB")
	}
	return block, nil
}

// fillChunkBlocks is how many blocks of a lane are allocated at once. A fill
// allocates lazily in chunks of 64 MiB, so zeroing a multi-GiB lane up front
// cannot overrun the deadline: the context is checked before every chunk.
const fillChunkBlocks = 4096

// Filled is a computed fill with its Merkle tree, held between the rounds.
type Filled struct {
	Fill Fill
	// lanes[lane][chunk] holds lane columns [chunk*fillChunkBlocks, ...).
	lanes  [][][]byte
	levels [][][32]byte
}

// Block is fill block index.
func (f *Filled) Block(index int) []byte {
	lane, column := f.Fill.Position(index)
	return f.laneBlock(lane, column)
}

func (f *Filled) laneBlock(lane, column int) []byte {
	offset := (column % fillChunkBlocks) * BlockSize
	return f.lanes[lane][column/fillChunkBlocks][offset : offset+BlockSize]
}

// Root is the Merkle root.
func (f *Filled) Root() [32]byte { return f.levels[len(f.levels)-1][0] }

// Path is the Merkle path of index.
func (f *Filled) Path(index int) []string { return MerklePath(f.levels, index) }

// Open builds the opening of index.
func (f *Filled) Open(index int) Opening {
	opening := Opening{Index: index, Block: encodeBlock(f.Block(index)), Path: f.Path(index)}
	lane, column := f.Fill.Position(index)
	if column > 0 {
		prev := f.Block(index - 1)
		ref := RefIndex(prev, f.Fill, lane, column)
		opening.Prev = &OpenedBlock{Index: index - 1, Block: encodeBlock(prev), Path: f.Path(index - 1)}
		opening.Ref = &OpenedBlock{Index: ref, Block: encodeBlock(f.Block(ref)), Path: f.Path(ref)}
	}
	return opening
}

// ComputeFill fills every block, one goroutine per lane and a barrier per
// slice, then hashes the leaves per lane and builds the tree. It returns
// ctx's error as soon as a lane observes it.
func ComputeFill(ctx context.Context, nonce []byte, f Fill) (*Filled, error) {
	width := Slices * f.BlocksPerSlice
	filled := &Filled{Fill: f, lanes: make([][][]byte, f.Lanes)}
	for lane := range filled.lanes {
		filled.lanes[lane] = make([][]byte, (width+fillChunkBlocks-1)/fillChunkBlocks)
	}
	parallel := func(work func(lane int)) error {
		var wg sync.WaitGroup
		for lane := range f.Lanes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				work(lane)
			}()
		}
		wg.Wait()
		return ctx.Err()
	}
	for slice := range Slices {
		err := parallel(func(lane int) {
			for column := slice * f.BlocksPerSlice; column < (slice+1)*f.BlocksPerSlice; column++ {
				if ctx.Err() != nil {
					return
				}
				if column%fillChunkBlocks == 0 {
					filled.lanes[lane][column/fillChunkBlocks] = make([]byte, min(fillChunkBlocks, width-column)*BlockSize)
				}
				out := filled.laneBlock(lane, column)
				if column == 0 {
					gInto(out, nil, nil, nonce, lane, 0)
					continue
				}
				prev := filled.laneBlock(lane, column-1)
				ref := filled.Block(RefIndex(prev, f, lane, column))
				gInto(out, prev, ref, nonce, lane, column)
			}
		})
		if err != nil {
			return nil, err
		}
	}
	leaves := make([][32]byte, f.Blocks())
	if err := parallel(func(lane int) {
		for column := 0; column < width && ctx.Err() == nil; column++ {
			index := f.Index(lane, column)
			leaves[index] = LeafHash(filled.Block(index))
		}
	}); err != nil {
		return nil, err
	}
	filled.levels = MerkleLevels(leaves)
	return filled, nil
}
