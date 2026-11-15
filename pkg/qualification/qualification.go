// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

// Package qualification is the PROVISIONAL, default-off miner qualification
// protocol: the validator-built challenge, the
// memory-hard Merkle-committed fill the miner proves in two rounds, the
// miner-signed commitment and openings, and the network payload generator.
// Nothing in it is a miner-reported capacity: every document carries only
// what the validator can recompute or time itself. It holds no policy.
package qualification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/misscomputer/mscomputer-miner/pkg/organic"
	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
)

const (
	ChallengeSchema       = organic.SchemaPrefix + "miner-qualification-challenge.v1"
	CommitmentSchema      = organic.SchemaPrefix + "miner-qualification-commitment.v1"
	OpeningsRequestSchema = organic.SchemaPrefix + "miner-qualification-openings-request.v1"
	OpeningsSchema        = organic.SchemaPrefix + "miner-qualification-openings.v1"
	// Signing domains follow the static family: the schema name without
	// its version suffix, then /v1/ed25519.
	CommitmentSigningDomain = organic.SchemaPrefix + "miner-qualification-commitment/v1/ed25519"
	OpeningsSigningDomain   = organic.SchemaPrefix + "miner-qualification-openings/v1/ed25519"

	payloadDomain = "mcq-payload-v1"
)

// Bounds (PROVISIONAL; both languages enforce the same).
const (
	MaxWindowSeconds  = 300
	MaxLanes          = 64
	MinBlocksPerSlice = 2
	// MaxFillBlocks bounds lanes x 4 x blocks_per_slice: 2^21 blocks of
	// 16 KiB is 32 GiB.
	MaxFillBlocks = 1 << 21
	MaxOpenings   = 256
	// MaxOpeningsPerRequest keeps one openings answer (3 base64 blocks and
	// 3 Merkle paths each) inside the one-MiB bridge body.
	MaxOpeningsPerRequest = 8
	// MaxPayloadBytes is PROVISIONAL and kept low while the axon's per-
	// validator payload rate limit is the only other egress bound.
	MaxPayloadBytes = 64 << 20
	maxElapsedMS    = 3_600_000
)

// Stable rejection codes, shared with qualification_contracts.py.
const (
	CodeChallengeInvalid  = "qualification_challenge_invalid"
	CodeCommitmentInvalid = "qualification_commitment_invalid"
	CodeRequestInvalid    = "qualification_openings_request_invalid"
	CodeOpeningsInvalid   = "qualification_openings_invalid"
	CodeChallengeMismatch = "qualification_challenge_mismatch"
	CodeRootMismatch      = "qualification_root_mismatch"
	CodeUnrequested       = "qualification_opening_unrequested"
	CodeSignerMismatch    = "qualification_signer_mismatch"
	CodeSignatureInvalid  = "qualification_signature_invalid"
	CodePathInvalid       = "qualification_opening_path_invalid"
	CodeRefInvalid        = "qualification_opening_ref_invalid"
	CodeBlockInvalid      = "qualification_opening_block_invalid"
)

// Error is a rejection with a stable code.
type Error struct{ Code, Detail string }

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

func reject(code, detail string) error { return &Error{Code: code, Detail: detail} }

// CodeOf returns err's stable code, or "" for another error.
func CodeOf(err error) string {
	var exact *Error
	if errors.As(err, &exact) {
		return exact.Code
	}
	return ""
}

// Fill sizes the memory-hard fill: Lanes x 4 slices x BlocksPerSlice blocks.
type Fill struct {
	Lanes          int `json:"lanes"`
	BlocksPerSlice int `json:"blocks_per_slice"`
}

// Blocks is the total number of fill blocks.
func (f Fill) Blocks() int { return f.Lanes * Slices * f.BlocksPerSlice }

// Challenge is miner-qualification-challenge.v1. It is not signed; the
// commitment binds it by challenge_sha256.
type Challenge struct {
	Schema          string `json:"schema"`
	Network         string `json:"network"`
	NetUID          uint16 `json:"netuid"`
	ValidatorHotkey string `json:"validator_hotkey"`
	MinerHotkey     string `json:"miner_hotkey"`
	MinerUID        uint16 `json:"miner_uid"`
	ChallengeID     string `json:"challenge_id"`
	Nonce           string `json:"nonce"`
	IssuedAtUnix    int64  `json:"issued_at_unix"`
	ExpiresAtUnix   int64  `json:"expires_at_unix"`
	Fill            Fill   `json:"fill"`
	// Openings is how many block indices the validator will open in round
	// two; the miner frees the fill once it has served that many.
	Openings     int   `json:"openings"`
	PayloadBytes int64 `json:"payload_bytes"`
}

// Commitment is the miner-signed round-one answer: the Merkle root of the
// fill. FillElapsedMS is a diagnostic; the validator times the request.
type Commitment struct {
	Schema           string `json:"schema"`
	ChallengeSHA256  string `json:"challenge_sha256"`
	ChallengeID      string `json:"challenge_id"`
	Network          string `json:"network"`
	NetUID           uint16 `json:"netuid"`
	ValidatorHotkey  string `json:"validator_hotkey"`
	MinerHotkey      string `json:"miner_hotkey"`
	ServicePublicKey string `json:"service_public_key"`
	Root             string `json:"root"`
	Blocks           int    `json:"blocks"`
	FillElapsedMS    int64  `json:"fill_elapsed_ms"`
	Signature        string `json:"signature"`
}

// OpeningsRequest is the validator's round-two request, chosen after it
// received the root. It is not signed; the openings bind it by
// request_sha256.
type OpeningsRequest struct {
	Schema          string `json:"schema"`
	ChallengeID     string `json:"challenge_id"`
	ChallengeSHA256 string `json:"challenge_sha256"`
	Root            string `json:"root"`
	Indices         []int  `json:"indices"`
}

// OpenedBlock is one block with its Merkle path.
type OpenedBlock struct {
	Index int      `json:"index"`
	Block string   `json:"block"`
	Path  []string `json:"path"`
}

// Opening is one opened index: the block, and for every block but a lane's
// first its predecessor and its reference block.
type Opening struct {
	Index int          `json:"index"`
	Block string       `json:"block"`
	Path  []string     `json:"path"`
	Prev  *OpenedBlock `json:"prev"`
	Ref   *OpenedBlock `json:"ref"`
}

// Openings is the miner-signed round-two answer.
type Openings struct {
	Schema           string    `json:"schema"`
	ChallengeSHA256  string    `json:"challenge_sha256"`
	ChallengeID      string    `json:"challenge_id"`
	ServicePublicKey string    `json:"service_public_key"`
	Root             string    `json:"root"`
	RequestSHA256    string    `json:"request_sha256"`
	Openings         []Opening `json:"openings"`
	Signature        string    `json:"signature"`
}

var (
	hex64       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex128      = regexp.MustCompile(`^[0-9a-f]{128}$`)
	networkName = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
	// ss58 is the base58 alphabet at SS58 address length.
	ss58 = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{46,48}$`)
)

func validHotkey(value string) bool { return ss58.MatchString(value) }

// Validate enforces every challenge bound; it reads no clock.
func (c Challenge) Validate() error {
	bad := func(detail string) error { return reject(CodeChallengeInvalid, detail) }
	if c.Schema != ChallengeSchema {
		return bad("schema")
	}
	if !networkName.MatchString(c.Network) || !validHotkey(c.ValidatorHotkey) || !validHotkey(c.MinerHotkey) {
		return bad("identity")
	}
	if !hex64.MatchString(c.ChallengeID) || !hex64.MatchString(c.Nonce) {
		return bad("challenge_id and nonce must be 32-byte lowercase hex")
	}
	if c.IssuedAtUnix < 1 || c.ExpiresAtUnix <= c.IssuedAtUnix || c.ExpiresAtUnix > c.IssuedAtUnix+MaxWindowSeconds {
		return bad("window")
	}
	f := c.Fill
	if f.Lanes < 1 || f.Lanes > MaxLanes || f.BlocksPerSlice < MinBlocksPerSlice || f.BlocksPerSlice > MaxFillBlocks ||
		f.Blocks() > MaxFillBlocks {
		return bad("fill")
	}
	if c.Openings < 1 || c.Openings > MaxOpenings || c.Openings > f.Blocks() {
		return bad("openings")
	}
	if c.PayloadBytes < 1 || c.PayloadBytes > MaxPayloadBytes {
		return bad("payload_bytes")
	}
	return nil
}

// ChallengeSHA256 is the lowercase hex SHA-256 of the challenge's canonical
// JSON.
func ChallengeSHA256(c Challenge) (string, error) { return organic.DigestHex(c) }

// RequestSHA256 is the lowercase hex SHA-256 of the request's canonical JSON.
func RequestSHA256(r OpeningsRequest) (string, error) { return organic.DigestHex(r) }

// strictDecode refuses unknown, missing and non-canonically typed members:
// the typed value must re-encode to exactly the members that were sent.
func strictDecode(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	generic := json.NewDecoder(bytes.NewReader(raw))
	generic.UseNumber()
	var members any
	if err := generic.Decode(&members); err != nil {
		return err
	}
	sent, err := organic.Canonical(members)
	if err != nil {
		return err
	}
	typed, err := organic.Canonical(out)
	if err != nil {
		return err
	}
	if !bytes.Equal(sent, typed) {
		return errors.New("members are missing, null or not canonical")
	}
	return nil
}

// DecodeChallenge strictly decodes and validates one challenge.
func DecodeChallenge(raw []byte) (Challenge, error) {
	var c Challenge
	if err := strictDecode(raw, &c); err != nil {
		return Challenge{}, reject(CodeChallengeInvalid, err.Error())
	}
	return c, c.Validate()
}

// DecodeCommitment strictly decodes and validates one commitment.
func DecodeCommitment(raw []byte) (Commitment, error) {
	var c Commitment
	if err := strictDecode(raw, &c); err != nil {
		return Commitment{}, reject(CodeCommitmentInvalid, err.Error())
	}
	return c, c.Validate()
}

// DecodeOpeningsRequest strictly decodes and validates one request.
func DecodeOpeningsRequest(raw []byte) (OpeningsRequest, error) {
	var r OpeningsRequest
	if err := strictDecode(raw, &r); err != nil {
		return OpeningsRequest{}, reject(CodeRequestInvalid, err.Error())
	}
	return r, r.Validate()
}

// DecodeOpenings strictly decodes and validates one openings answer.
func DecodeOpenings(raw []byte) (Openings, error) {
	var o Openings
	if err := strictDecode(raw, &o); err != nil {
		return Openings{}, reject(CodeOpeningsInvalid, err.Error())
	}
	return o, o.Validate()
}

// Validate checks a commitment's shape; the signature must be present.
func (c Commitment) Validate() error {
	if !hex128.MatchString(c.Signature) {
		return reject(CodeCommitmentInvalid, "signature must be 128 lowercase hex")
	}
	return c.validateUnsigned()
}

func (c Commitment) validateUnsigned() error {
	if c.Schema != CommitmentSchema || !hex64.MatchString(c.ChallengeSHA256) || !hex64.MatchString(c.ChallengeID) ||
		!networkName.MatchString(c.Network) || !validHotkey(c.ValidatorHotkey) || !validHotkey(c.MinerHotkey) ||
		!hex64.MatchString(c.ServicePublicKey) || !hex64.MatchString(c.Root) || c.Blocks < 1 || c.Blocks > MaxFillBlocks ||
		c.FillElapsedMS < 0 || c.FillElapsedMS > maxElapsedMS {
		return reject(CodeCommitmentInvalid, "commitment members")
	}
	return nil
}

// Validate checks a request's shape: 1..8 strictly ascending indices.
func (r OpeningsRequest) Validate() error {
	if r.Schema != OpeningsRequestSchema || !hex64.MatchString(r.ChallengeID) || !hex64.MatchString(r.ChallengeSHA256) ||
		!hex64.MatchString(r.Root) || len(r.Indices) < 1 || len(r.Indices) > MaxOpeningsPerRequest {
		return reject(CodeRequestInvalid, "request members")
	}
	for i, index := range r.Indices {
		if index < 0 || index >= MaxFillBlocks || (i > 0 && index <= r.Indices[i-1]) {
			return reject(CodeRequestInvalid, "indices must be strictly ascending fill indices")
		}
	}
	return nil
}

func validPath(path []string) bool {
	if path == nil || len(path) > 32 {
		return false
	}
	for _, node := range path {
		if !hex64.MatchString(node) {
			return false
		}
	}
	return true
}

func (b OpenedBlock) valid() bool {
	return b.Index >= 0 && b.Index < MaxFillBlocks && len(b.Block) == blockBase64Length && validPath(b.Path)
}

// Validate checks an openings answer's shape; the signature must be present.
func (o Openings) Validate() error {
	if !hex128.MatchString(o.Signature) {
		return reject(CodeOpeningsInvalid, "signature must be 128 lowercase hex")
	}
	return o.validateUnsigned()
}

func (o Openings) validateUnsigned() error {
	bad := func(detail string) error { return reject(CodeOpeningsInvalid, detail) }
	if o.Schema != OpeningsSchema || !hex64.MatchString(o.ChallengeSHA256) || !hex64.MatchString(o.ChallengeID) ||
		!hex64.MatchString(o.ServicePublicKey) || !hex64.MatchString(o.Root) || !hex64.MatchString(o.RequestSHA256) {
		return bad("openings members")
	}
	if len(o.Openings) < 1 || len(o.Openings) > MaxOpeningsPerRequest {
		return bad("openings count")
	}
	for _, opening := range o.Openings {
		head := OpenedBlock{Index: opening.Index, Block: opening.Block, Path: opening.Path}
		if !head.valid() || (opening.Prev == nil) != (opening.Ref == nil) ||
			(opening.Prev != nil && (!opening.Prev.valid() || !opening.Ref.valid())) {
			return bad("opening shape")
		}
	}
	return nil
}

func signerKey(key ed25519.PrivateKey) string {
	return hex.EncodeToString(key.Public().(ed25519.PublicKey))
}

// SignCommitment fills c.Signature with the miner service key's signature.
func SignCommitment(c *Commitment, key ed25519.PrivateKey) error {
	if c == nil || len(key) != ed25519.PrivateKeySize {
		return reject(CodeCommitmentInvalid, "invalid signing input")
	}
	if c.ServicePublicKey != signerKey(key) {
		return reject(CodeSignerMismatch, "service_public_key is not the signing key")
	}
	if err := c.validateUnsigned(); err != nil {
		return err
	}
	signature, err := protocol.SignDomainDocument(CommitmentSigningDomain, *c, key)
	if err != nil {
		return err
	}
	c.Signature = signature
	return nil
}

// SignOpenings fills o.Signature with the miner service key's signature.
func SignOpenings(o *Openings, key ed25519.PrivateKey) error {
	if o == nil || len(key) != ed25519.PrivateKeySize {
		return reject(CodeOpeningsInvalid, "invalid signing input")
	}
	if o.ServicePublicKey != signerKey(key) {
		return reject(CodeSignerMismatch, "service_public_key is not the signing key")
	}
	if err := o.validateUnsigned(); err != nil {
		return err
	}
	signature, err := protocol.SignDomainDocument(OpeningsSigningDomain, *o, key)
	if err != nil {
		return err
	}
	o.Signature = signature
	return nil
}

func verifySigner(domain string, document any, signer, signature, bound string) error {
	if !hex64.MatchString(bound) || signer != bound {
		return reject(CodeSignerMismatch, "signer is not the bound miner service key")
	}
	key, _ := hex.DecodeString(bound)
	if err := protocol.VerifyDomainDocument(domain, document, signature, ed25519.PublicKey(key)); err != nil {
		return reject(CodeSignatureInvalid, err.Error())
	}
	return nil
}

// VerifyCommitment accepts c only as the bound miner key's round-one answer
// to exactly this challenge. It is not a qualification signal by itself;
// use the validator-side driver, which also times round one
// against D1 and chooses the openings.
func VerifyCommitment(c Commitment, challenge Challenge, boundServiceKeyHex string) error {
	if err := challenge.Validate(); err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	digest, err := ChallengeSHA256(challenge)
	if err != nil {
		return reject(CodeChallengeInvalid, err.Error())
	}
	if c.ChallengeSHA256 != digest || c.ChallengeID != challenge.ChallengeID || c.Network != challenge.Network ||
		c.NetUID != challenge.NetUID || c.ValidatorHotkey != challenge.ValidatorHotkey || c.MinerHotkey != challenge.MinerHotkey ||
		c.Blocks != challenge.Fill.Blocks() {
		return reject(CodeChallengeMismatch, "commitment does not answer the challenge")
	}
	return verifySigner(CommitmentSigningDomain, c, c.ServicePublicKey, c.Signature, boundServiceKeyHex)
}

// VerifyOpenings accepts o only as the bound miner key's answer to request,
// under the root of the verified commitment c for challenge, and checks
// every opening: Merkle paths, reference derivation and G. It is not a
// qualification signal by itself; use the validator-side driver,
// which also draws uniform indices after the root, enforces the openings
// budget and times round two against D2.
func VerifyOpenings(o Openings, request OpeningsRequest, c Commitment, challenge Challenge, boundServiceKeyHex string) error {
	if err := VerifyCommitment(c, challenge, boundServiceKeyHex); err != nil {
		return err
	}
	if err := request.Validate(); err != nil {
		return err
	}
	if err := o.Validate(); err != nil {
		return err
	}
	if o.ChallengeSHA256 != c.ChallengeSHA256 || o.ChallengeID != c.ChallengeID || request.ChallengeID != c.ChallengeID ||
		request.ChallengeSHA256 != c.ChallengeSHA256 {
		return reject(CodeChallengeMismatch, "openings do not answer the challenge")
	}
	if o.Root != c.Root || request.Root != c.Root {
		return reject(CodeRootMismatch, "openings are not under the committed root")
	}
	requestDigest, err := RequestSHA256(request)
	if err != nil {
		return reject(CodeRequestInvalid, err.Error())
	}
	if o.RequestSHA256 != requestDigest || len(o.Openings) != len(request.Indices) {
		return reject(CodeUnrequested, "openings answer another request")
	}
	for i, opening := range o.Openings {
		if opening.Index != request.Indices[i] {
			return reject(CodeUnrequested, "opening for an index that was not requested")
		}
	}
	if err := verifySigner(OpeningsSigningDomain, o, o.ServicePublicKey, o.Signature, boundServiceKeyHex); err != nil {
		return err
	}
	root, _ := hex.DecodeString(c.Root)
	nonce, _ := hex.DecodeString(challenge.Nonce)
	for _, opening := range o.Openings {
		if err := verifyOpening(opening, challenge.Fill, nonce, [32]byte(root)); err != nil {
			return err
		}
	}
	return nil
}

func verifyOpening(o Opening, f Fill, nonce []byte, root [32]byte) error {
	n := f.Blocks()
	if o.Index >= n {
		return reject(CodeUnrequested, "index outside the fill")
	}
	lane, column := f.Position(o.Index)
	block, err := decodeBlock(o.Block)
	if err != nil {
		return reject(CodeOpeningsInvalid, err.Error())
	}
	if !VerifyPath(o.Index, n, LeafHash(block), o.Path, root) {
		return reject(CodePathInvalid, "block path")
	}
	if column == 0 {
		if o.Prev != nil || o.Ref != nil {
			return reject(CodeRefInvalid, "a lane's first block has no predecessor or reference")
		}
		if !bytes.Equal(block, G(nil, nil, nonce, lane, 0)) {
			return reject(CodeBlockInvalid, "block is not G of its inputs")
		}
		return nil
	}
	if o.Prev == nil || o.Ref == nil {
		return reject(CodeRefInvalid, "predecessor or reference missing")
	}
	prev, prevErr := decodeBlock(o.Prev.Block)
	ref, refErr := decodeBlock(o.Ref.Block)
	if prevErr != nil || refErr != nil {
		return reject(CodeOpeningsInvalid, "block encoding")
	}
	if o.Prev.Index != o.Index-1 {
		return reject(CodeRefInvalid, "predecessor index")
	}
	if want := RefIndex(prev, f, lane, column); o.Ref.Index != want {
		return reject(CodeRefInvalid, "reference index is not derived from the predecessor")
	}
	if !VerifyPath(o.Prev.Index, n, LeafHash(prev), o.Prev.Path, root) || !VerifyPath(o.Ref.Index, n, LeafHash(ref), o.Ref.Path, root) {
		return reject(CodePathInvalid, "predecessor or reference path")
	}
	if !bytes.Equal(block, G(prev, ref, nonce, lane, column)) {
		return reject(CodeBlockInvalid, "block is not G of its inputs")
	}
	return nil
}

// PayloadBlock is block i of the payload stream:
// SHA256("mcq-payload-v1" || 0x00 || nonce || u64be(i)).
func PayloadBlock(nonce []byte, index uint64) [32]byte {
	message := make([]byte, 0, len(payloadDomain)+1+len(nonce)+8)
	message = append(append(message, payloadDomain...), 0)
	message = append(message, nonce...)
	message = binary.BigEndian.AppendUint64(message, index)
	return sha256.Sum256(message)
}

// WritePayload writes the first size bytes of the payload stream.
func WritePayload(w io.Writer, nonce []byte, size int64) error {
	buffer := make([]byte, 0, 64<<10)
	for index := uint64(0); size > 0; index++ {
		block := PayloadBlock(nonce, index)
		take := min(size, int64(len(block)))
		buffer = append(buffer, block[:take]...)
		size -= take
		if len(buffer) == cap(buffer) || size == 0 {
			if _, err := w.Write(buffer); err != nil {
				return err
			}
			buffer = buffer[:0]
		}
	}
	return nil
}
