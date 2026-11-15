// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package qualification

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/misscomputer/mscomputer-miner/pkg/organic"
	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
)

// The disk plot. Each chunk is a
// stack of PlotLayers layers of n = 4 x B blocks of 16 KiB. Layer 0 is a
// chain; every block of layer l >= 1 is G of its predecessor XOR the block
// of the same index one layer down, with a reference drawn uniformly from
// the layer below. Every layer has its own Merkle tree; only the top layer
// is stored. A dropped top block can only be rebuilt by recomputing most of
// the stack under it.
//
// The seal (once per chunk, after the build) opens random blocks of the top
// layer and of one lower layer with their inputs, so the validator checks
// the G relation of every layer it picks. Spot reads (at qualification and
// on every recheck) then open stored blocks by Merkle path only, several per
// call under one latency bound.
const (
	PlotChallengeSchema   = organic.SchemaPrefix + "miner-qualification-plot-challenge.v1"
	PlotCommitmentSchema  = organic.SchemaPrefix + "miner-qualification-plot-commitment.v1"
	PlotSealRequestSchema = organic.SchemaPrefix + "miner-qualification-plot-seal-request.v1"
	PlotSealSchema        = organic.SchemaPrefix + "miner-qualification-plot-seal.v1"
	PlotSpotRequestSchema = organic.SchemaPrefix + "miner-qualification-plot-spot-request.v1"
	PlotSpotSchema        = organic.SchemaPrefix + "miner-qualification-plot-spot.v1"

	PlotCommitmentSigningDomain = organic.SchemaPrefix + "miner-qualification-plot-commitment/v1/ed25519"
	PlotSealSigningDomain       = organic.SchemaPrefix + "miner-qualification-plot-seal/v1/ed25519"
	PlotSpotSigningDomain       = organic.SchemaPrefix + "miner-qualification-plot-spot/v1/ed25519"

	plotDomain      = "mcq-plot-v3"
	plotLowerDomain = "mcq-plot-v3-lower"
)

// Plot bounds (PROVISIONAL; both languages enforce the same).
const (
	MaxPlotChunks = 4096
	// MaxPlotBlocksPerSlice makes a chunk 4 x 16384 blocks of 16 KiB: 1 GiB.
	MaxPlotBlocksPerSlice = 16384
	// MaxPlotBuildSeconds bounds a plot challenge's build window.
	MaxPlotBuildSeconds = 24 * 3600
	// PlotLayers is the number of layers of a chunk; only the top one is
	// stored.
	PlotLayers = 16
	// MaxSealTopOpenings is how many top-layer blocks a seal request opens
	// besides one block of every lower layer.
	MaxSealTopOpenings = 3
	// MaxSealOpenings bounds one seal request and answer: every lower layer
	// once plus the top openings (18; up to 4 blocks each).
	MaxSealOpenings = PlotLayers - 1 + MaxSealTopOpenings
	// MaxPlotSealBytes bounds one seal answer (about 1.7 MB at 18 openings)
	// on the bridge and in the agent's kept seal file.
	MaxPlotSealBytes = 4 << 20
	// MaxSpotPicks bounds one spot answer (one block per pick).
	MaxSpotPicks     = 8
	maxPlotElapsedMS = 2 * MaxPlotBuildSeconds * 1000
	maxPlotPath      = 12
)

// Stable plot rejection codes, shared with qualification_contracts.py. A
// signer or signature failure answers CodeSignerMismatch or
// CodeSignatureInvalid, as for the fill.
const (
	CodePlotChallengeInvalid  = "qualification_plot_challenge_invalid"
	CodePlotCommitmentInvalid = "qualification_plot_commitment_invalid"
	CodePlotRequestInvalid    = "qualification_plot_request_invalid"
	CodePlotAnswerInvalid     = "qualification_plot_answer_invalid"
	CodePlotChallengeMismatch = "qualification_plot_challenge_mismatch"
	CodePlotRootMismatch      = "qualification_plot_root_mismatch"
	CodePlotUnrequested       = "qualification_plot_unrequested"
	CodePlotChunkPathInvalid  = "qualification_plot_chunk_path_invalid"
	CodePlotPathInvalid       = "qualification_plot_block_path_invalid"
	CodePlotRefInvalid        = "qualification_plot_ref_invalid"
	CodePlotBlockInvalid      = "qualification_plot_block_invalid"
)

// PlotChallenge is miner-qualification-plot-challenge.v1. It is not signed;
// the commitment binds it by plot_challenge_sha256.
type PlotChallenge struct {
	Schema              string `json:"schema"`
	Network             string `json:"network"`
	NetUID              uint16 `json:"netuid"`
	ValidatorHotkey     string `json:"validator_hotkey"`
	MinerHotkey         string `json:"miner_hotkey"`
	MinerUID            uint16 `json:"miner_uid"`
	PlotID              string `json:"plot_id"`
	Seed                string `json:"seed"`
	Chunks              int    `json:"chunks"`
	ChunkBlocksPerSlice int    `json:"chunk_blocks_per_slice"`
	IssuedAtUnix        int64  `json:"issued_at_unix"`
	BuildExpiresAtUnix  int64  `json:"build_expires_at_unix"`
}

// BlocksPerChunk is the number of 16 KiB blocks of one layer of a chunk,
// which is the number of stored blocks.
func (c PlotChallenge) BlocksPerChunk() int { return Slices * c.ChunkBlocksPerSlice }

// PlotCommitment is the miner-signed plot root. BuildElapsedMS is a
// diagnostic; the validator times only the spot checks.
type PlotCommitment struct {
	Schema              string `json:"schema"`
	PlotChallengeSHA256 string `json:"plot_challenge_sha256"`
	PlotID              string `json:"plot_id"`
	Network             string `json:"network"`
	NetUID              uint16 `json:"netuid"`
	ValidatorHotkey     string `json:"validator_hotkey"`
	MinerHotkey         string `json:"miner_hotkey"`
	ServicePublicKey    string `json:"service_public_key"`
	Root                string `json:"root"`
	Chunks              int    `json:"chunks"`
	BlocksPerChunk      int    `json:"blocks_per_chunk"`
	BuildElapsedMS      int64  `json:"build_elapsed_ms"`
	Signature           string `json:"signature"`
}

// PlotSealPoint is one (layer, index) block of a chunk.
type PlotSealPoint struct {
	Layer int `json:"layer"`
	Index int `json:"index"`
}

// PlotSealRequest asks for the openings of up to MaxSealOpenings blocks of
// one chunk, chosen after the root: the driver asks for three top-layer
// blocks and one block of a uniform lower layer.
type PlotSealRequest struct {
	Schema              string          `json:"schema"`
	PlotID              string          `json:"plot_id"`
	PlotChallengeSHA256 string          `json:"plot_challenge_sha256"`
	Root                string          `json:"root"`
	RequestID           string          `json:"request_id"`
	Chunk               int             `json:"chunk"`
	Openings            []PlotSealPoint `json:"openings"`
}

// SealOpening is block (layer, index) with its inputs, each with its path
// into its layer's root: the predecessor (index-1 in the same layer, or for
// index 0 block n-1 of the layer below; none for block 0 of layer 0), and
// for layer >= 1 the block of the same index and the reference block of the
// layer below.
type SealOpening struct {
	Layer int          `json:"layer"`
	Index int          `json:"index"`
	Block string       `json:"block"`
	Path  []string     `json:"path"`
	Prev  *OpenedBlock `json:"prev"`
	Below *OpenedBlock `json:"below"`
	Ref   *OpenedBlock `json:"ref"`
}

// PlotSeal is the miner-signed seal answer.
type PlotSeal struct {
	Schema           string        `json:"schema"`
	RequestSHA256    string        `json:"request_sha256"`
	PlotID           string        `json:"plot_id"`
	ServicePublicKey string        `json:"service_public_key"`
	Root             string        `json:"root"`
	Chunk            int           `json:"chunk"`
	LayerRoots       []string      `json:"layer_roots"`
	ChunkPath        []string      `json:"chunk_path"`
	Openings         []SealOpening `json:"openings"`
	Signature        string        `json:"signature"`
}

// PlotPick is one (chunk, stored index) of a spot request.
type PlotPick struct {
	Chunk int `json:"chunk"`
	Index int `json:"index"`
}

// PlotSpotRequest is one validator spot read of up to MaxSpotPicks stored
// blocks, chosen after the root and answered under one latency bound.
type PlotSpotRequest struct {
	Schema              string     `json:"schema"`
	PlotID              string     `json:"plot_id"`
	PlotChallengeSHA256 string     `json:"plot_challenge_sha256"`
	Root                string     `json:"root"`
	RequestID           string     `json:"request_id"`
	Picks               []PlotPick `json:"picks"`
}

// PlotSpotItem is one stored (top-layer) block with its path to the plot
// root: the chunk leaf is LeafHash(lower_digest || top_root).
type PlotSpotItem struct {
	Chunk       int      `json:"chunk"`
	LowerDigest string   `json:"lower_digest"`
	TopRoot     string   `json:"top_root"`
	ChunkPath   []string `json:"chunk_path"`
	Index       int      `json:"index"`
	Block       string   `json:"block"`
	Path        []string `json:"path"`
}

// PlotSpot is the miner-signed spot answer.
type PlotSpot struct {
	Schema           string         `json:"schema"`
	RequestSHA256    string         `json:"request_sha256"`
	PlotID           string         `json:"plot_id"`
	ServicePublicKey string         `json:"service_public_key"`
	Root             string         `json:"root"`
	Items            []PlotSpotItem `json:"items"`
	Signature        string         `json:"signature"`
}

// Validate enforces every plot challenge bound; it reads no clock.
func (c PlotChallenge) Validate() error {
	bad := func(detail string) error { return reject(CodePlotChallengeInvalid, detail) }
	if c.Schema != PlotChallengeSchema {
		return bad("schema")
	}
	if !networkName.MatchString(c.Network) || !validHotkey(c.ValidatorHotkey) || !validHotkey(c.MinerHotkey) {
		return bad("identity")
	}
	if !hex64.MatchString(c.PlotID) || !hex64.MatchString(c.Seed) {
		return bad("plot_id and seed must be 32-byte lowercase hex")
	}
	if c.Chunks < 1 || c.Chunks > MaxPlotChunks || c.ChunkBlocksPerSlice < MinBlocksPerSlice ||
		c.ChunkBlocksPerSlice > MaxPlotBlocksPerSlice {
		return bad("plot size")
	}
	if c.IssuedAtUnix < 1 || c.BuildExpiresAtUnix <= c.IssuedAtUnix || c.BuildExpiresAtUnix > c.IssuedAtUnix+MaxPlotBuildSeconds {
		return bad("window")
	}
	return nil
}

// Validate checks a plot commitment's shape; the signature must be present.
func (c PlotCommitment) Validate() error {
	if !hex128.MatchString(c.Signature) {
		return reject(CodePlotCommitmentInvalid, "signature must be 128 lowercase hex")
	}
	return c.validateUnsigned()
}

func (c PlotCommitment) validateUnsigned() error {
	if c.Schema != PlotCommitmentSchema || !hex64.MatchString(c.PlotChallengeSHA256) || !hex64.MatchString(c.PlotID) ||
		!networkName.MatchString(c.Network) || !validHotkey(c.ValidatorHotkey) || !validHotkey(c.MinerHotkey) ||
		!hex64.MatchString(c.ServicePublicKey) || !hex64.MatchString(c.Root) || c.Chunks < 1 || c.Chunks > MaxPlotChunks ||
		c.BlocksPerChunk < Slices*MinBlocksPerSlice || c.BlocksPerChunk > Slices*MaxPlotBlocksPerSlice ||
		c.BuildElapsedMS < 0 || c.BuildElapsedMS > maxPlotElapsedMS {
		return reject(CodePlotCommitmentInvalid, "plot commitment members")
	}
	return nil
}

func validPlotHead(plotID, digest, root, requestID string) bool {
	return hex64.MatchString(plotID) && hex64.MatchString(digest) && hex64.MatchString(root) && hex64.MatchString(requestID)
}

// Validate checks a seal request's shape: 1..4 openings strictly ascending
// by (layer, index).
func (r PlotSealRequest) Validate() error {
	if r.Schema != PlotSealRequestSchema || !validPlotHead(r.PlotID, r.PlotChallengeSHA256, r.Root, r.RequestID) ||
		r.Chunk < 0 || r.Chunk >= MaxPlotChunks || len(r.Openings) < 1 || len(r.Openings) > MaxSealOpenings {
		return reject(CodePlotRequestInvalid, "seal request members")
	}
	for i, o := range r.Openings {
		if o.Layer < 0 || o.Layer >= PlotLayers || o.Index < 0 || o.Index >= Slices*MaxPlotBlocksPerSlice ||
			(i > 0 && !pointBefore(r.Openings[i-1], o)) {
			return reject(CodePlotRequestInvalid, "openings must be strictly ascending (layer, index) points")
		}
	}
	return nil
}

func pointBefore(a, b PlotSealPoint) bool {
	return a.Layer < b.Layer || (a.Layer == b.Layer && a.Index < b.Index)
}

// Validate checks a spot request's shape: 1..8 picks.
func (r PlotSpotRequest) Validate() error {
	if r.Schema != PlotSpotRequestSchema || !validPlotHead(r.PlotID, r.PlotChallengeSHA256, r.Root, r.RequestID) ||
		len(r.Picks) < 1 || len(r.Picks) > MaxSpotPicks {
		return reject(CodePlotRequestInvalid, "spot request members")
	}
	for _, pick := range r.Picks {
		if pick.Chunk < 0 || pick.Chunk >= MaxPlotChunks || pick.Index < 0 || pick.Index >= Slices*MaxPlotBlocksPerSlice {
			return reject(CodePlotRequestInvalid, "pick outside the plot bounds")
		}
	}
	return nil
}

func validChunkHead(chunk int, lower, top string, path []string) bool {
	return chunk >= 0 && chunk < MaxPlotChunks && hex64.MatchString(lower) && hex64.MatchString(top) && validPath(path) &&
		len(path) <= maxPlotPath
}

func validOptional(b *OpenedBlock) bool { return b == nil || b.valid() }

// Validate checks a seal answer's shape; the signature must be present.
func (s PlotSeal) Validate() error {
	if !hex128.MatchString(s.Signature) {
		return reject(CodePlotAnswerInvalid, "signature must be 128 lowercase hex")
	}
	return s.validateUnsigned()
}

func (s PlotSeal) validateUnsigned() error {
	bad := reject(CodePlotAnswerInvalid, "seal members")
	if s.Schema != PlotSealSchema || !hex64.MatchString(s.RequestSHA256) || !hex64.MatchString(s.PlotID) ||
		!hex64.MatchString(s.ServicePublicKey) || !hex64.MatchString(s.Root) || s.Chunk < 0 || s.Chunk >= MaxPlotChunks ||
		!validPath(s.ChunkPath) || len(s.ChunkPath) > maxPlotPath || len(s.LayerRoots) != PlotLayers ||
		len(s.Openings) < 1 || len(s.Openings) > MaxSealOpenings {
		return bad
	}
	for _, root := range s.LayerRoots {
		if !hex64.MatchString(root) {
			return bad
		}
	}
	for _, o := range s.Openings {
		head := OpenedBlock{Index: o.Index, Block: o.Block, Path: o.Path}
		if o.Layer < 0 || o.Layer >= PlotLayers || !head.valid() || !validOptional(o.Prev) || !validOptional(o.Below) ||
			!validOptional(o.Ref) {
			return bad
		}
	}
	return nil
}

// Validate checks a spot answer's shape; the signature must be present.
func (s PlotSpot) Validate() error {
	if !hex128.MatchString(s.Signature) {
		return reject(CodePlotAnswerInvalid, "signature must be 128 lowercase hex")
	}
	return s.validateUnsigned()
}

func (s PlotSpot) validateUnsigned() error {
	bad := reject(CodePlotAnswerInvalid, "spot members")
	if s.Schema != PlotSpotSchema || !hex64.MatchString(s.RequestSHA256) || !hex64.MatchString(s.PlotID) ||
		!hex64.MatchString(s.ServicePublicKey) || !hex64.MatchString(s.Root) || len(s.Items) < 1 || len(s.Items) > MaxSpotPicks {
		return bad
	}
	for _, item := range s.Items {
		block := OpenedBlock{Index: item.Index, Block: item.Block, Path: item.Path}
		if !validChunkHead(item.Chunk, item.LowerDigest, item.TopRoot, item.ChunkPath) || !block.valid() {
			return bad
		}
	}
	return nil
}

// PlotChallengeSHA256 is the lowercase hex SHA-256 of the canonical JSON.
func PlotChallengeSHA256(c PlotChallenge) (string, error) { return organic.DigestHex(c) }

// PlotRequestSHA256 is the lowercase hex SHA-256 of a seal or spot request.
func PlotRequestSHA256(r any) (string, error) { return organic.DigestHex(r) }

func decodeAs[T interface{ Validate() error }](raw []byte, code string) (T, error) {
	var out T
	if err := strictDecode(raw, &out); err != nil {
		var zero T
		return zero, reject(code, err.Error())
	}
	return out, out.Validate()
}

// DecodePlotChallenge strictly decodes and validates one plot challenge.
func DecodePlotChallenge(raw []byte) (PlotChallenge, error) {
	return decodeAs[PlotChallenge](raw, CodePlotChallengeInvalid)
}

// DecodePlotCommitment strictly decodes and validates one plot commitment.
func DecodePlotCommitment(raw []byte) (PlotCommitment, error) {
	return decodeAs[PlotCommitment](raw, CodePlotCommitmentInvalid)
}

// DecodePlotSealRequest strictly decodes and validates one seal request.
func DecodePlotSealRequest(raw []byte) (PlotSealRequest, error) {
	return decodeAs[PlotSealRequest](raw, CodePlotRequestInvalid)
}

// DecodePlotSeal strictly decodes and validates one seal answer.
func DecodePlotSeal(raw []byte) (PlotSeal, error) {
	return decodeAs[PlotSeal](raw, CodePlotAnswerInvalid)
}

// DecodePlotSpotRequest strictly decodes and validates one spot request.
func DecodePlotSpotRequest(raw []byte) (PlotSpotRequest, error) {
	return decodeAs[PlotSpotRequest](raw, CodePlotRequestInvalid)
}

// DecodePlotSpot strictly decodes and validates one spot answer.
func DecodePlotSpot(raw []byte) (PlotSpot, error) {
	return decodeAs[PlotSpot](raw, CodePlotAnswerInvalid)
}

// PlotChunkNonce is SHA256("mcq-plot-v3" || 0x00 || seed || u32be(chunk)).
func PlotChunkNonce(seed []byte, chunk int) []byte {
	message := make([]byte, 0, len(plotDomain)+1+len(seed)+4)
	message = append(append(message, plotDomain...), 0)
	message = append(message, seed...)
	message = binary.BigEndian.AppendUint32(message, uint32(chunk))
	sum := sha256.Sum256(message)
	return sum[:]
}

var zeroBlock = make([]byte, BlockSize)

// PlotRefIndex is the reference, in the layer below, of a block whose
// predecessor is prev: (u32be(prev[0..4]) * n) >> 32, uniform over n.
func PlotRefIndex(prev []byte, n int) int {
	return int(uint64(binary.BigEndian.Uint32(prev[0:4])) * uint64(n) >> 32)
}

// PlotBlock is block index of layer: for layer 0, G(prev, zero, nonce, 0,
// index) (prev is zero, passed as nil, for index 0); for layer >= 1,
// G(prev XOR below, ref, nonce, layer, index), where below is the block of
// the same index and ref the block PlotRefIndex(prev, n) of the layer below.
func PlotBlock(prev, below, ref, nonce []byte, layer, index int) []byte {
	out := make([]byte, BlockSize)
	plotBlockInto(out, make([]byte, BlockSize), prev, below, ref, nonce, layer, index)
	return out
}

func plotBlockInto(out, scratch, prev, below, ref, nonce []byte, layer, index int) {
	switch {
	case layer == 0 && prev == nil:
		gInto(out, nil, nil, nonce, 0, index)
	case layer == 0:
		gInto(out, prev, zeroBlock, nonce, 0, index)
	default:
		for i := range scratch {
			scratch[i] = prev[i] ^ below[i]
		}
		gInto(out, scratch, ref, nonce, layer, index)
	}
}

// PlotLowerDigest binds the roots of layers 0 .. PlotLayers-2:
// SHA256("mcq-plot-v3-lower" || 0x00 || root_0 || ... || root_{k-2}).
func PlotLowerDigest(lower [][32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(plotLowerDomain))
	h.Write([]byte{0})
	for _, root := range lower {
		h.Write(root[:])
	}
	return [32]byte(h.Sum(nil))
}

// ChunkLeaf is the plot-tree leaf of a chunk: LeafHash(lower_digest || top_root).
func ChunkLeaf(lower, top [32]byte) [32]byte { return LeafHash(append(lower[:], top[:]...)) }

// PlotChunk is one computed chunk: every layer root, the top layer and its
// tree, and the seal openings asked for when it was computed.
type PlotChunk struct {
	n         int
	roots     [][32]byte
	top       []byte
	topLevels [][][32]byte
	openings  []SealOpening
}

func blockAt(data []byte, index int) []byte { return data[index*BlockSize : (index+1)*BlockSize] }

// Top is stored block index.
func (p *PlotChunk) Top(index int) []byte { return blockAt(p.top, index) }

// Roots are the PlotLayers layer roots, layer 0 first.
func (p *PlotChunk) Roots() [][32]byte { return p.roots }

// TopRoot is the root of the stored layer.
func (p *PlotChunk) TopRoot() [32]byte { return p.roots[PlotLayers-1] }

// LowerDigest is PlotLowerDigest of the lower layers' roots.
func (p *PlotChunk) LowerDigest() [32]byte { return PlotLowerDigest(p.roots[:PlotLayers-1]) }

// Leaf is the chunk's plot-tree leaf.
func (p *PlotChunk) Leaf() [32]byte { return ChunkLeaf(p.LowerDigest(), p.TopRoot()) }

// Openings are the seal openings asked for, in the order asked.
func (p *PlotChunk) Openings() []SealOpening { return p.openings }

func treeOf(data []byte, n int) [][][32]byte {
	leaves := make([][32]byte, n)
	for i := range leaves {
		leaves[i] = LeafHash(blockAt(data, i))
	}
	return MerkleLevels(leaves)
}

// ComputePlotChunk computes every layer of one chunk, holding two layers
// in memory, and keeps the top layer, every root and the openings of
// points (each point's layer and index must be in range). It returns ctx's
// error as soon as it observes it.
func ComputePlotChunk(ctx context.Context, nonce []byte, blocksPerSlice int, points []PlotSealPoint) (*PlotChunk, error) {
	n := Slices * blocksPerSlice
	cur, below := make([]byte, n*BlockSize), make([]byte, n*BlockSize)
	scratch := make([]byte, BlockSize)
	chunk := &PlotChunk{n: n, roots: make([][32]byte, PlotLayers), openings: make([]SealOpening, len(points))}
	var curLevels, belowLevels [][][32]byte
	for layer := range PlotLayers {
		for index := range n {
			if index%256 == 0 && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var prev, under, ref []byte
			switch {
			case index > 0:
				prev = blockAt(cur, index-1)
			case layer > 0:
				prev = blockAt(below, n-1)
			}
			if layer > 0 {
				under, ref = blockAt(below, index), blockAt(below, PlotRefIndex(prev, n))
			}
			plotBlockInto(blockAt(cur, index), scratch, prev, under, ref, nonce, layer, index)
		}
		curLevels = treeOf(cur, n)
		chunk.roots[layer] = curLevels[len(curLevels)-1][0]
		for i, point := range points {
			if point.Layer == layer {
				chunk.openings[i] = layerOpening(layer, point.Index, n, cur, curLevels, below, belowLevels)
			}
		}
		if layer < PlotLayers-1 {
			cur, below, belowLevels = below, cur, curLevels
		}
	}
	chunk.top, chunk.topLevels = cur, curLevels
	return chunk, ctx.Err()
}

func openedAt(data []byte, levels [][][32]byte, index int) *OpenedBlock {
	return &OpenedBlock{Index: index, Block: encodeBlock(blockAt(data, index)), Path: MerklePath(levels, index)}
}

// layerOpening is the seal opening of block index of layer, given that
// layer and the one below it with their trees.
func layerOpening(layer, index, n int, cur []byte, curLevels [][][32]byte, below []byte, belowLevels [][][32]byte) SealOpening {
	o := SealOpening{Layer: layer, Index: index, Block: encodeBlock(blockAt(cur, index)), Path: MerklePath(curLevels, index)}
	var prev []byte
	switch {
	case index > 0:
		o.Prev, prev = openedAt(cur, curLevels, index-1), blockAt(cur, index-1)
	case layer > 0:
		o.Prev, prev = openedAt(below, belowLevels, n-1), blockAt(below, n-1)
	}
	if layer > 0 {
		o.Below, o.Ref = openedAt(below, belowLevels, index), openedAt(below, belowLevels, PlotRefIndex(prev, n))
	}
	return o
}

// TopPath is the path of stored block index under the top root.
func (p *PlotChunk) TopPath(index int) []string { return MerklePath(p.topLevels, index) }

// PlotLevels is the plot tree over the chunk leaves.
func PlotLevels(leaves [][32]byte) [][][32]byte { return MerkleLevels(leaves) }

// SignPlotCommitment fills c.Signature with the miner service key's signature.
func SignPlotCommitment(c *PlotCommitment, key ed25519.PrivateKey) error {
	if c == nil {
		return reject(CodePlotCommitmentInvalid, "invalid signing input")
	}
	return signPlot(PlotCommitmentSigningDomain, &c.Signature, c.ServicePublicKey, c.validateUnsigned, func() any { return *c }, key, CodePlotCommitmentInvalid)
}

// SignPlotSeal fills s.Signature.
func SignPlotSeal(s *PlotSeal, key ed25519.PrivateKey) error {
	if s == nil {
		return reject(CodePlotAnswerInvalid, "invalid signing input")
	}
	return signPlot(PlotSealSigningDomain, &s.Signature, s.ServicePublicKey, s.validateUnsigned, func() any { return *s }, key, CodePlotAnswerInvalid)
}

// SignPlotSpot fills s.Signature.
func SignPlotSpot(s *PlotSpot, key ed25519.PrivateKey) error {
	if s == nil {
		return reject(CodePlotAnswerInvalid, "invalid signing input")
	}
	return signPlot(PlotSpotSigningDomain, &s.Signature, s.ServicePublicKey, s.validateUnsigned, func() any { return *s }, key, CodePlotAnswerInvalid)
}

func signPlot(domain string, signature *string, signer string, validate func() error, document func() any, key ed25519.PrivateKey, code string) error {
	if len(key) != ed25519.PrivateKeySize {
		return reject(code, "invalid signing input")
	}
	if signer != signerKey(key) {
		return reject(CodeSignerMismatch, "service_public_key is not the signing key")
	}
	if err := validate(); err != nil {
		return err
	}
	value, err := protocol.SignDomainDocument(domain, document(), key)
	if err != nil {
		return err
	}
	*signature = value
	return nil
}

// VerifyPlotCommitment accepts c only as the bound miner key's plot root for
// exactly this challenge. It is not a qualification signal by itself; use
// the validator-side driver, which also seals and times the plot.
func VerifyPlotCommitment(c PlotCommitment, challenge PlotChallenge, boundServiceKeyHex string) error {
	if err := challenge.Validate(); err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	digest, err := PlotChallengeSHA256(challenge)
	if err != nil {
		return reject(CodePlotChallengeInvalid, err.Error())
	}
	if c.PlotChallengeSHA256 != digest || c.PlotID != challenge.PlotID || c.Network != challenge.Network ||
		c.NetUID != challenge.NetUID || c.ValidatorHotkey != challenge.ValidatorHotkey || c.MinerHotkey != challenge.MinerHotkey ||
		c.Chunks != challenge.Chunks || c.BlocksPerChunk != challenge.BlocksPerChunk() {
		return reject(CodePlotChallengeMismatch, "plot commitment does not answer the challenge")
	}
	return verifySigner(PlotCommitmentSigningDomain, c, c.ServicePublicKey, c.Signature, boundServiceKeyHex)
}

// verifyAnswerHead checks what seal and spot answers share, in order: the
// commitment, the plot id and digest of request and answer, the root, the
// request digest, then the signer.
func verifyAnswerHead(c PlotCommitment, challenge PlotChallenge, bound, reqPlotID, reqDigest, reqRoot, plotID, root, answeredDigest string, request any) error {
	if err := VerifyPlotCommitment(c, challenge, bound); err != nil {
		return err
	}
	if reqDigest != c.PlotChallengeSHA256 || reqPlotID != c.PlotID || plotID != c.PlotID {
		return reject(CodePlotChallengeMismatch, "answer does not answer the plot")
	}
	if root != c.Root || reqRoot != c.Root {
		return reject(CodePlotRootMismatch, "answer is not under the committed root")
	}
	digest, err := PlotRequestSHA256(request)
	if err != nil {
		return reject(CodePlotRequestInvalid, err.Error())
	}
	if answeredDigest != digest {
		return reject(CodePlotUnrequested, "answer is for another request")
	}
	return nil
}

func decodeRoot(value string) [32]byte {
	raw, _ := hex.DecodeString(value)
	return [32]byte(raw)
}

func verifyChunkPath(chunk int, lower, top [32]byte, path []string, c PlotCommitment) error {
	if !VerifyPath(chunk, c.Chunks, ChunkLeaf(lower, top), path, decodeRoot(c.Root)) {
		return reject(CodePlotChunkPathInvalid, "chunk path")
	}
	return nil
}

func decodePlotBlock(value string) ([]byte, error) {
	block, err := decodeBlock(value)
	if err != nil {
		return nil, reject(CodePlotAnswerInvalid, err.Error())
	}
	return block, nil
}

// VerifyPlotSeal accepts s only as the bound key's answer to request under
// the verified commitment c: the layer roots hashed to the chunk leaf and
// its path, then for each opening the block's path under its layer root,
// the predecessor (index-1 in the layer, or block n-1 of the layer below
// for index 0), the block below and the reference derived from the
// predecessor, each under the right layer root, and the G relation. It is
// not a qualification signal by itself.
func VerifyPlotSeal(s PlotSeal, request PlotSealRequest, c PlotCommitment, challenge PlotChallenge, boundServiceKeyHex string) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := s.Validate(); err != nil {
		return err
	}
	if err := verifyAnswerHead(c, challenge, boundServiceKeyHex, request.PlotID, request.PlotChallengeSHA256, request.Root,
		s.PlotID, s.Root, s.RequestSHA256, request); err != nil {
		return err
	}
	n := c.BlocksPerChunk
	if s.Chunk != request.Chunk || request.Chunk >= c.Chunks || len(s.Openings) != len(request.Openings) {
		return reject(CodePlotUnrequested, "seal answers another chunk")
	}
	for i, o := range s.Openings {
		if o.Layer != request.Openings[i].Layer || o.Index != request.Openings[i].Index || o.Index >= n {
			return reject(CodePlotUnrequested, "opening for a point that was not requested")
		}
	}
	if err := verifySigner(PlotSealSigningDomain, s, s.ServicePublicKey, s.Signature, boundServiceKeyHex); err != nil {
		return err
	}
	roots := make([][32]byte, PlotLayers)
	for i, root := range s.LayerRoots {
		roots[i] = decodeRoot(root)
	}
	if err := verifyChunkPath(s.Chunk, PlotLowerDigest(roots[:PlotLayers-1]), roots[PlotLayers-1], s.ChunkPath, c); err != nil {
		return err
	}
	seed, _ := hex.DecodeString(challenge.Seed)
	nonce := PlotChunkNonce(seed, s.Chunk)
	for _, o := range s.Openings {
		if err := verifySealOpening(o, n, roots, nonce); err != nil {
			return err
		}
	}
	return nil
}

// openedUnder decodes b and checks it is block index under root.
func openedUnder(b *OpenedBlock, index, n int, root [32]byte, what string) ([]byte, error) {
	if b.Index != index {
		return nil, reject(CodePlotRefInvalid, what+" index")
	}
	block, err := decodePlotBlock(b.Block)
	if err != nil {
		return nil, err
	}
	if !VerifyPath(index, n, LeafHash(block), b.Path, root) {
		return nil, reject(CodePlotPathInvalid, what+" path")
	}
	return block, nil
}

func verifySealOpening(o SealOpening, n int, roots [][32]byte, nonce []byte) error {
	block, err := decodePlotBlock(o.Block)
	if err != nil {
		return err
	}
	if !VerifyPath(o.Index, n, LeafHash(block), o.Path, roots[o.Layer]) {
		return reject(CodePlotPathInvalid, "block path")
	}
	first := o.Layer == 0 && o.Index == 0
	if (o.Prev == nil) != first || (o.Below == nil) != (o.Layer == 0) || (o.Ref == nil) != (o.Layer == 0) {
		return reject(CodePlotRefInvalid, "opening inputs do not match its position")
	}
	var prev, under, ref []byte
	if !first {
		prevIndex, prevRoot := o.Index-1, roots[o.Layer]
		if o.Index == 0 {
			prevIndex, prevRoot = n-1, roots[o.Layer-1]
		}
		if prev, err = openedUnder(o.Prev, prevIndex, n, prevRoot, "predecessor"); err != nil {
			return err
		}
	}
	if o.Layer > 0 {
		if under, err = openedUnder(o.Below, o.Index, n, roots[o.Layer-1], "block below"); err != nil {
			return err
		}
		if ref, err = openedUnder(o.Ref, PlotRefIndex(prev, n), n, roots[o.Layer-1], "reference"); err != nil {
			return err
		}
	}
	if !bytes.Equal(block, PlotBlock(prev, under, ref, nonce, o.Layer, o.Index)) {
		return reject(CodePlotBlockInvalid, "block is not G of its inputs")
	}
	return nil
}

// VerifyPlotSpot accepts s only as the bound key's answer to request under
// the verified commitment c: every pick answered in order, each block's
// path under its chunk's top root and each chunk's path under the plot
// root. Block content was proven by the seal; a spot proves the miner still
// holds it. It is not a qualification signal by itself; use the driver,
// which draws the picks after the root and times the call.
func VerifyPlotSpot(s PlotSpot, request PlotSpotRequest, c PlotCommitment, challenge PlotChallenge, boundServiceKeyHex string) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := s.Validate(); err != nil {
		return err
	}
	if err := verifyAnswerHead(c, challenge, boundServiceKeyHex, request.PlotID, request.PlotChallengeSHA256, request.Root,
		s.PlotID, s.Root, s.RequestSHA256, request); err != nil {
		return err
	}
	if len(s.Items) != len(request.Picks) {
		return reject(CodePlotUnrequested, "spot answers another request")
	}
	for i, item := range s.Items {
		pick := request.Picks[i]
		if item.Chunk != pick.Chunk || item.Index != pick.Index || pick.Chunk >= c.Chunks || pick.Index >= c.BlocksPerChunk {
			return reject(CodePlotUnrequested, "item for a pick that was not requested")
		}
	}
	if err := verifySigner(PlotSpotSigningDomain, s, s.ServicePublicKey, s.Signature, boundServiceKeyHex); err != nil {
		return err
	}
	for _, item := range s.Items {
		if err := verifyChunkPath(item.Chunk, decodeRoot(item.LowerDigest), decodeRoot(item.TopRoot), item.ChunkPath, c); err != nil {
			return err
		}
		block, err := decodePlotBlock(item.Block)
		if err != nil {
			return err
		}
		if !VerifyPath(item.Index, c.BlocksPerChunk, LeafHash(block), item.Path, decodeRoot(item.TopRoot)) {
			return reject(CodePlotPathInvalid, "block path")
		}
	}
	return nil
}
