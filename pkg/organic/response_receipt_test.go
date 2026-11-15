// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package organic

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateResponseReceiptVectors = flag.Bool("update-response-receipt-vectors", false, "rewrite testdata/response-receipt-v2-vectors.json")

const responseReceiptVectorsPath = "testdata/response-receipt-v2-vectors.json"

// rfc6962Root is the recursive MTH of RFC 6962 §2.1, the reference the
// iterative implementation must equal.
func rfc6962Root(leaves [][32]byte) [32]byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := splitPoint(len(leaves))
	return receiptNodeHash(rfc6962Root(leaves[:k]), rfc6962Root(leaves[k:]))
}

func syntheticLeafHashes(n int, seed byte) [][32]byte {
	out := make([][32]byte, n)
	for index := range out {
		out[index] = sha256.Sum256([]byte{seed, byte(index >> 16), byte(index >> 8), byte(index)})
	}
	return out
}

func pickLeaf(rng *rand.Rand) ResponseReceiptLeaf {
	leaf := ResponseReceiptLeaf{
		Kind: ReceiptKindDynamic, EndpointID: "ep-test-g7-abcdef", Generation: 7,
		ResponseStatus: 200, ResponseBodyLen: uint64(rng.Intn(1 << 24)), Completion: ReceiptCompletionComplete,
		FinishedAtUnixMS: 1_762_000_000_000 + uint64(rng.Intn(1000)),
	}
	if rng.Intn(2) == 0 {
		leaf.Kind = ReceiptKindStatic
	}
	leaf.Completion = uint8(rng.Intn(4))
	leaf.ResponseStatus = uint16(100 + rng.Intn(500))
	if rng.Intn(10) == 0 {
		leaf.ResponseStatus = 0
	}
	for _, field := range [][]byte{leaf.TicketDigest[:], leaf.EdgeRequestID[:], leaf.RequestDigest[:], leaf.ResponseHeaderSHA256[:], leaf.ResponseBodySHA256[:]} {
		rng.Read(field)
	}
	return leaf
}

func TestReceiptMerkleMatchesRFC6962AndEveryProofVerifies(t *testing.T) {
	for n := 1; n <= 70; n++ {
		leaves := syntheticLeafHashes(n, byte(n))
		root, err := ReceiptMerkleRoot(leaves)
		if err != nil || root != rfc6962Root(leaves) {
			t.Fatalf("n=%d: iterative root differs from RFC 6962 MTH", n)
		}
		for index := 0; index < n; index++ {
			proof, err := ReceiptInclusionProof(leaves, index)
			if err != nil {
				t.Fatal(err)
			}
			if len(proof) > bitsCeilLog2(n) {
				t.Fatalf("n=%d i=%d: proof length %d exceeds ceil(log2 n)", n, index, len(proof))
			}
			if !VerifyReceiptInclusion(leaves[index], uint64(index), uint64(n), proof, root) {
				t.Fatalf("n=%d i=%d: valid proof rejected", n, index)
			}
			// A proof never verifies for another index, size, leaf or root.
			if n > 1 && VerifyReceiptInclusion(leaves[index], uint64((index+1)%n), uint64(n), proof, root) {
				t.Fatalf("n=%d i=%d: proof verified at the wrong index", n, index)
			}
			other := leaves[index]
			other[0] ^= 1
			if VerifyReceiptInclusion(other, uint64(index), uint64(n), proof, root) {
				t.Fatalf("n=%d i=%d: proof verified a different leaf", n, index)
			}
			if len(proof) > 0 {
				tampered := append([][32]byte(nil), proof...)
				tampered[len(tampered)-1][31] ^= 1
				if VerifyReceiptInclusion(leaves[index], uint64(index), uint64(n), tampered, root) {
					t.Fatalf("n=%d i=%d: tampered proof verified", n, index)
				}
				if VerifyReceiptInclusion(leaves[index], uint64(index), uint64(n), proof[:len(proof)-1], root) {
					t.Fatalf("n=%d i=%d: truncated proof verified", n, index)
				}
			}
			if VerifyReceiptInclusion(leaves[index], uint64(index), uint64(n), append(append([][32]byte(nil), proof...), root), root) {
				t.Fatalf("n=%d i=%d: extended proof verified", n, index)
			}
		}
	}
	if _, err := ReceiptMerkleRoot(nil); err == nil {
		t.Fatal("empty tree must have no root")
	}
}

func bitsCeilLog2(n int) int {
	length := 0
	for (1 << length) < n {
		length++
	}
	return length
}

func TestReceiptMerkleRejectsDuplicateLeafAmbiguity(t *testing.T) {
	// CVE-2012-2459: duplicating the odd last leaf must change the root.
	leaves := syntheticLeafHashes(3, 9)
	root, _ := ReceiptMerkleRoot(leaves)
	duplicated, _ := ReceiptMerkleRoot(append(leaves, leaves[2]))
	if root == duplicated {
		t.Fatal("odd leaf duplication produced the same root")
	}
	// A leaf hash can never be confused with an interior node.
	single, _ := ReceiptMerkleRoot(syntheticLeafHashes(2, 4))
	if single == ReceiptLeafHash(append(append([]byte{}, syntheticLeafHashes(2, 4)[0][:]...), syntheticLeafHashes(2, 4)[1][:]...)) {
		t.Fatal("leaf and node domains collide")
	}
}

func TestResponseReceiptLeafRoundTripProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iteration := 0; iteration < 2000; iteration++ {
		leaf := pickLeaf(rng)
		preimage, err := leaf.Encode()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeResponseReceiptLeaf(preimage)
		if err != nil || decoded != leaf {
			t.Fatalf("round trip failed: %v", err)
		}
		// Every single-byte flip either fails to decode or changes the hash.
		position := rng.Intn(len(preimage))
		mutated := append([]byte(nil), preimage...)
		mutated[position] ^= byte(1 + rng.Intn(255))
		if other, err := DecodeResponseReceiptLeaf(mutated); err == nil {
			if other == leaf || ReceiptLeafHash(mutated) == ReceiptLeafHash(preimage) {
				t.Fatalf("byte %d flip was not found", position)
			}
		}
		if _, err := DecodeResponseReceiptLeaf(append(preimage, 0)); err == nil {
			t.Fatal("trailing byte accepted")
		}
		if _, err := DecodeResponseReceiptLeaf(preimage[:len(preimage)-1]); err == nil {
			t.Fatal("truncated leaf accepted")
		}
	}
}

func TestResponseReceiptLeafRejectsInvalidFields(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for name, mutate := range map[string]func(*ResponseReceiptLeaf){
		"kind":       func(l *ResponseReceiptLeaf) { l.Kind = 3 },
		"kind zero":  func(l *ResponseReceiptLeaf) { l.Kind = 0 },
		"endpoint":   func(l *ResponseReceiptLeaf) { l.EndpointID = "bad/id" },
		"empty id":   func(l *ResponseReceiptLeaf) { l.EndpointID = "" },
		"generation": func(l *ResponseReceiptLeaf) { l.Generation = 0 },
		"status":     func(l *ResponseReceiptLeaf) { l.ResponseStatus = 99 },
		"status hi":  func(l *ResponseReceiptLeaf) { l.ResponseStatus = 600 },
		"completion": func(l *ResponseReceiptLeaf) { l.Completion = 4 },
	} {
		leaf := pickLeaf(rng)
		mutate(&leaf)
		if _, err := leaf.Encode(); err == nil {
			t.Fatalf("%s: invalid leaf encoded", name)
		}
	}
}

func vectorKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("response-receipt-v1 test vector miner service key"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func signedBatch(t testing.TB, key ed25519.PrivateKey, sequence uint64, prev string, hashes [][32]byte) ResponseReceiptBatch {
	root, err := ReceiptMerkleRoot(hashes)
	if err != nil {
		t.Fatal(err)
	}
	batch := ResponseReceiptBatch{
		Schema: ResponseReceiptBatchSchema, SchemaVersion: ResponseReceiptBatchSchemaVersion,
		MinerServiceKey: hex.EncodeToString(key.Public().(ed25519.PublicKey)), AgentBootID: "00112233445566778899aabbccddeeff",
		Sequence: sequence, PrevBatchDigest: prev, WindowStartUnix: 1_762_000_000,
		LeafCount: uint32(len(hashes)), MerkleRoot: hex.EncodeToString(root[:]),
	}
	if err := SignResponseReceiptBatch(&batch, key); err != nil {
		t.Fatal(err)
	}
	return batch
}

func TestResponseReceiptBatchSignVerifyAndEnvelope(t *testing.T) {
	key := vectorKey()
	public := key.Public().(ed25519.PublicKey)
	rng := rand.New(rand.NewSource(3))
	leaves := make([]ResponseReceiptLeaf, 5)
	for index := range leaves {
		leaves[index] = pickLeaf(rng)
	}
	SortReceiptLeaves(leaves)
	envelope := ResponseReceiptBatchEnvelope{}
	hashes := make([][32]byte, len(leaves))
	for index, leaf := range leaves {
		hashes[index], _ = leaf.Hash()
		envelope.Entries = append(envelope.Entries, ResponseReceiptEntry{
			EdgeRequestID: hex.EncodeToString(leaf.EdgeRequestID[:]), FinishedAtUnixMS: leaf.FinishedAtUnixMS,
			LeafHash: hex.EncodeToString(hashes[index][:]),
		})
	}
	envelope.Batch = signedBatch(t, key, 1, zeroBatchDigest, hashes)
	indexed, err := VerifyResponseReceiptBatchEnvelope(envelope, public)
	if err != nil || len(indexed) != len(leaves) {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	for index, leaf := range leaves {
		if got := indexed[leaf.EdgeRequestID]; got.Index != uint64(index) || got.Hash != hashes[index] {
			t.Fatal("indexed leaf mismatch")
		}
	}
	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	cases := map[string]func(*ResponseReceiptBatchEnvelope) ed25519.PublicKey{
		"wrong key": func(*ResponseReceiptBatchEnvelope) ed25519.PublicKey { return otherKey.Public().(ed25519.PublicKey) },
		"sequence":  func(e *ResponseReceiptBatchEnvelope) ed25519.PublicKey { e.Batch.Sequence = 2; return public },
		"window":    func(e *ResponseReceiptBatchEnvelope) ed25519.PublicKey { e.Batch.WindowStartUnix++; return public },
		"boot": func(e *ResponseReceiptBatchEnvelope) ed25519.PublicKey {
			e.Batch.AgentBootID = "ff112233445566778899aabbccddeeff"
			return public
		},
		"dropped entry": func(e *ResponseReceiptBatchEnvelope) ed25519.PublicKey { e.Entries = e.Entries[1:]; return public },
		"reordered": func(e *ResponseReceiptBatchEnvelope) ed25519.PublicKey {
			e.Entries[0], e.Entries[1] = e.Entries[1], e.Entries[0]
			return public
		},
		"swapped leaf": func(e *ResponseReceiptBatchEnvelope) ed25519.PublicKey {
			e.Entries[2].LeafHash = e.Entries[3].LeafHash
			return public
		},
		"duplicate id": func(e *ResponseReceiptBatchEnvelope) ed25519.PublicKey {
			e.Entries[1].EdgeRequestID = e.Entries[0].EdgeRequestID
			return public
		},
		"uppercase hex": func(e *ResponseReceiptBatchEnvelope) ed25519.PublicKey {
			e.Entries[0].LeafHash = "A" + e.Entries[0].LeafHash[1:]
			return public
		},
		"unsigned":  func(e *ResponseReceiptBatchEnvelope) ed25519.PublicKey { e.Batch.SignatureHex = ""; return public },
		"schema v1": func(e *ResponseReceiptBatchEnvelope) ed25519.PublicKey { e.Batch.SchemaVersion = 1; return public },
		"schema v3": func(e *ResponseReceiptBatchEnvelope) ed25519.PublicKey { e.Batch.SchemaVersion = 3; return public },
		"chain start": func(e *ResponseReceiptBatchEnvelope) ed25519.PublicKey {
			e.Batch.PrevBatchDigest = hashesHex(hashes[0])
			return public
		},
	}
	for name, mutate := range cases {
		copyEnvelope := ResponseReceiptBatchEnvelope{Batch: envelope.Batch, Entries: append([]ResponseReceiptEntry(nil), envelope.Entries...)}
		key := mutate(&copyEnvelope)
		if _, err := VerifyResponseReceiptBatchEnvelope(copyEnvelope, key); err == nil {
			t.Fatalf("%s: tampered envelope verified", name)
		}
	}
	digest, err := ResponseReceiptBatchDigest(envelope.Batch)
	if err != nil {
		t.Fatal(err)
	}
	next := signedBatch(t, key, 2, digest, hashes[:1])
	if err := VerifyResponseReceiptBatch(next, public); err != nil {
		t.Fatal(err)
	}
	bad := ResponseReceiptBatch{}
	if err := SignResponseReceiptBatch(&bad, key); err == nil {
		t.Fatal("invalid batch signed")
	}
	wrongNamed := envelope.Batch
	wrongNamed.SignatureHex = ""
	wrongNamed.MinerServiceKey = hex.EncodeToString(otherKey.Public().(ed25519.PublicKey))
	if err := SignResponseReceiptBatch(&wrongNamed, key); err == nil {
		t.Fatal("batch signed under a key it does not name")
	}
}

func hashesHex(value [32]byte) string { return hex.EncodeToString(value[:]) }

func TestReceiptPullSignatureIsDomainSeparated(t *testing.T) {
	key := vectorKey()
	public := key.Public().(ed25519.PublicKey)
	request := EdgeRuntimeRequest{BodySHA256: hex.EncodeToString(sha256.New().Sum(nil)), EndpointID: "ep-g1-abc", Method: "GET",
		Nonce: strings.Repeat("ab", 16), Path: "/.ms-receipts/v1/batches", Query: "after_sequence=0&boot=", Timestamp: 1}
	signature, err := SignReceiptPull(request, key)
	if err != nil || VerifyReceiptPull(request, signature, public) != nil {
		t.Fatalf("valid pull signature rejected: %v", err)
	}
	// The edge-runtime-request signature over the same fields is not a
	// pull authorization, and the pull signature binds every field.
	edgeHeader, _ := SignEdgeRuntimeRequest(request, key)
	edgeSignature := edgeHeader[strings.LastIndex(edgeHeader, "sig=")+4:]
	if VerifyReceiptPull(request, edgeSignature, public) == nil {
		t.Fatal("edge request signature accepted as a pull authorization")
	}
	for name, mutate := range map[string]func(*EdgeRuntimeRequest){
		"endpoint": func(r *EdgeRuntimeRequest) { r.EndpointID = "ep-g1-abd" },
		"path":     func(r *EdgeRuntimeRequest) { r.Path = "/.ms-receipts/v1/leaf/00" },
		"query":    func(r *EdgeRuntimeRequest) { r.Query = "after_sequence=1&boot=" },
		"nonce":    func(r *EdgeRuntimeRequest) { r.Nonce = strings.Repeat("cd", 16) },
	} {
		mutated := request
		mutate(&mutated)
		if VerifyReceiptPull(mutated, signature, public) == nil {
			t.Fatalf("%s change kept the pull signature valid", name)
		}
	}
	if VerifyReceiptPull(request, strings.ToUpper(signature), public) == nil {
		t.Fatal("non-canonical signature accepted")
	}
}

func TestReceiptTicketDigest(t *testing.T) {
	digest, err := ReceiptTicketDigest("sha256:" + strings.Repeat("ab", 32))
	if err != nil || digest[0] != 0xab || digest[31] != 0xab {
		t.Fatal("valid ticket digest rejected")
	}
	for _, invalid := range []string{"", strings.Repeat("ab", 32), "sha256:" + strings.Repeat("AB", 32), "sha256:" + strings.Repeat("ab", 31)} {
		if _, err := ReceiptTicketDigest(invalid); err == nil {
			t.Fatalf("invalid ticket digest %q accepted", invalid)
		}
	}
}

func TestReceiptSelectedRateAndBlindness(t *testing.T) {
	key := []byte("edge-private-sample-key")
	var id [16]byte
	hits := 0
	const draws = 200000
	for index := 0; index < draws; index++ {
		binary.BigEndian.PutUint64(id[8:], uint64(index))
		if ReceiptSelected(key, id, 1000) {
			hits++
		}
	}
	if hits < 140 || hits > 260 {
		t.Fatalf("1/1000 pick hit %d of %d", hits, draws)
	}
	if ReceiptSelected(key, id, 0) || ReceiptSelected(nil, id, 1) || !ReceiptSelected(key, id, 1) {
		t.Fatal("pick edge cases wrong")
	}
	// Changing the key changes which requests are selected.
	same := 0
	for index := 0; index < draws; index++ {
		binary.BigEndian.PutUint64(id[8:], uint64(index))
		if ReceiptSelected(key, id, 1000) && ReceiptSelected([]byte("other key"), id, 1000) {
			same++
		}
	}
	if same > 5 {
		t.Fatalf("two keys agreed on %d picks", same)
	}
}

// responseReceiptVectors is shared verbatim with the subnet Python verifier.
type responseReceiptVectors struct {
	Description          string               `json:"description"`
	MinerServiceKey      string               `json:"miner_service_key"`
	EdgeRequest          EdgeRuntimeRequest   `json:"edge_request"`
	RequestDigest        string               `json:"request_digest"`
	Leaves               []vectorLeaf         `json:"leaves"`
	Trees                []vectorTree         `json:"trees"`
	Batches              []vectorBatch        `json:"batches"`
	InvalidLeaves        []string             `json:"invalid_leaf_preimages"`
	InvalidBatches       []vectorBatch        `json:"invalid_batches"`
	Picks                []vectorPick         `json:"samples"`
	HeaderDigests        []vectorHeaderDigest `json:"header_digests"`
	ReceiptHeaderDigests []vectorHeaderDigest `json:"receipt_header_digests"`
	PullSignatures       []vectorPull         `json:"pull_signatures"`
}

type vectorLeaf struct {
	Kind                 uint8  `json:"kind"`
	EndpointID           string `json:"endpoint_id"`
	Generation           uint64 `json:"generation"`
	TicketDigest         string `json:"ticket_digest"`
	EdgeRequestID        string `json:"edge_request_id"`
	RequestDigest        string `json:"request_digest"`
	ResponseStatus       uint16 `json:"response_status"`
	ResponseHeaderSHA256 string `json:"response_header_sha256"`
	ResponseBodyLen      uint64 `json:"response_body_len"`
	ResponseBodySHA256   string `json:"response_body_sha256"`
	Completion           uint8  `json:"completion"`
	FinishedAtUnixMS     uint64 `json:"finished_at_unix_ms"`
	Preimage             string `json:"preimage"`
	LeafHash             string `json:"leaf_hash"`
}

type vectorTree struct {
	LeafHashes []string   `json:"leaf_hashes"`
	Root       string     `json:"root"`
	Proofs     [][]string `json:"proofs"`
}

type vectorBatch struct {
	Envelope    ResponseReceiptBatchEnvelope `json:"envelope"`
	Message     string                       `json:"signed_message,omitempty"`
	BatchDigest string                       `json:"batch_digest,omitempty"`
	Reason      string                       `json:"reason,omitempty"`
}

type vectorPull struct {
	Request   EdgeRuntimeRequest `json:"request"`
	Message   string             `json:"message"`
	Signature string             `json:"signature"`
}

type vectorPick struct {
	Key           string `json:"key"`
	EdgeRequestID string `json:"edge_request_id"`
	Denominator   uint64 `json:"denominator"`
	Selected      bool   `json:"sampled"`
}

type vectorHeaderDigest struct {
	Headers [][2]string `json:"headers"`
	Digest  string      `json:"digest"`
}

func fromVectorLeaf(v vectorLeaf) ResponseReceiptLeaf {
	leaf := ResponseReceiptLeaf{Kind: v.Kind, EndpointID: v.EndpointID, Generation: v.Generation,
		ResponseStatus: v.ResponseStatus, ResponseBodyLen: v.ResponseBodyLen, Completion: v.Completion, FinishedAtUnixMS: v.FinishedAtUnixMS}
	for _, pair := range []struct {
		dst []byte
		src string
	}{{leaf.TicketDigest[:], v.TicketDigest}, {leaf.EdgeRequestID[:], v.EdgeRequestID}, {leaf.RequestDigest[:], v.RequestDigest},
		{leaf.ResponseHeaderSHA256[:], v.ResponseHeaderSHA256}, {leaf.ResponseBodySHA256[:], v.ResponseBodySHA256}} {
		decoded, _ := hex.DecodeString(pair.src)
		copy(pair.dst, decoded)
	}
	return leaf
}

func toVectorLeaf(t *testing.T, leaf ResponseReceiptLeaf) vectorLeaf {
	preimage, err := leaf.Encode()
	if err != nil {
		t.Fatal(err)
	}
	hash := ReceiptLeafHash(preimage)
	return vectorLeaf{Kind: leaf.Kind, EndpointID: leaf.EndpointID, Generation: leaf.Generation,
		TicketDigest: hex.EncodeToString(leaf.TicketDigest[:]), EdgeRequestID: hex.EncodeToString(leaf.EdgeRequestID[:]),
		RequestDigest: hex.EncodeToString(leaf.RequestDigest[:]), ResponseStatus: leaf.ResponseStatus,
		ResponseHeaderSHA256: hex.EncodeToString(leaf.ResponseHeaderSHA256[:]), ResponseBodyLen: leaf.ResponseBodyLen,
		ResponseBodySHA256: hex.EncodeToString(leaf.ResponseBodySHA256[:]), Completion: leaf.Completion,
		FinishedAtUnixMS: leaf.FinishedAtUnixMS, Preimage: hex.EncodeToString(preimage), LeafHash: hex.EncodeToString(hash[:])}
}

func buildResponseReceiptVectors(t *testing.T) responseReceiptVectors {
	key := vectorKey()
	request := EdgeRuntimeRequest{BodySHA256: hex.EncodeToString(sha256.New().Sum(nil)), EndpointID: "ep-vec-g3-0123abcd",
		Method: "GET", Nonce: "0f1e2d3c4b5a69788796a5b4c3d2e1f0", Path: "/index.html", Query: "a=1", Timestamp: 1_762_000_000_123_456_789}
	requestDigest, err := ReceiptRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	headers := [][2]string{{"Content-Type", "text/html"}, {"ETag", "\"abc\""}, {"cache-control", "no-store"}}
	headerDigest, err := ResponseHeaderSHA256(headers)
	if err != nil {
		t.Fatal(err)
	}
	// The miner digests the application's raw headers; the edge digests
	// what arrives after Go net/http trimmed values and dropped or added
	// server headers and a CDN tunnel front added its own.
	minerHeaders := [][2]string{{"Content-Type", " text/html;\tcharset=utf-8 "}, {"Location", "/next\r\n"},
		{"Set-Cookie", "sid=1; Path=/"}, {"Set-Cookie", "theme=dark"}, {"ETag", "\"abc\""}, {"cache-control", "no-store"}}
	edgeHeaders := [][2]string{{"content-type", "text/html; charset=utf-8"}, {"location", "/next"},
		{"set-cookie", "sid=1; Path=/"}, {"set-cookie", "__cf_bm=x; HttpOnly"}, {"set-cookie", "theme=dark"},
		{"etag", "W/\"abc\""}, {"date", "Wed, 11 Nov 2026 03:00:00 GMT"}, {"content-length", "0"},
		{"cf-ray", "8e0f1a2b3c4d5e6f-FRA"}, {"cf-cache-status", "DYNAMIC"}, {"server", "cdn-front"},
		{"vary", "Accept-Encoding"}, {"nel", "{}"}, {"report-to", "{}"}, {"alt-svc", "h3=\":443\""},
		{"X-Ms-Reserved-Answer", "x"}, {"cache-control", "private, no-store"}}
	receiptHeaderDigest, err := ReceiptHeaderSHA256(minerHeaders)
	if err != nil {
		t.Fatal(err)
	}
	if edgeDigest, _ := ReceiptHeaderSHA256(edgeHeaders); edgeDigest != receiptHeaderDigest {
		t.Fatal("receipt header digest must survive transport normalisation and CDN headers")
	}
	changed := append([][2]string{{"Content-Type", "text/plain"}}, minerHeaders[1:]...)
	changedDigest, _ := ReceiptHeaderSHA256(changed)
	if changedDigest == receiptHeaderDigest {
		t.Fatal("a committed header change must change the receipt header digest")
	}
	receiptHex := hex.EncodeToString(receiptHeaderDigest[:])
	changedHex := hex.EncodeToString(changedDigest[:])
	vectors := responseReceiptVectors{
		Description:     "response-receipt-v2 cross-language vectors; regenerate with go test ./pkg/organic -run TestResponseReceiptVectors -update-response-receipt-vectors",
		MinerServiceKey: hex.EncodeToString(key.Public().(ed25519.PublicKey)), EdgeRequest: request,
		RequestDigest: hex.EncodeToString(requestDigest[:]),
		HeaderDigests: []vectorHeaderDigest{{Headers: headers, Digest: headerDigest}},
		ReceiptHeaderDigests: []vectorHeaderDigest{{Headers: minerHeaders, Digest: receiptHex},
			{Headers: edgeHeaders, Digest: receiptHex}, {Headers: changed, Digest: changedHex}},
	}
	first := ResponseReceiptLeaf{Kind: ReceiptKindStatic, EndpointID: request.EndpointID, Generation: 3,
		RequestDigest: requestDigest, ResponseStatus: 200, ResponseBodyLen: 0, Completion: ReceiptCompletionComplete,
		FinishedAtUnixMS: 1_762_000_000_200}
	copy(first.TicketDigest[:], bytes.Repeat([]byte{0xab}, 32))
	nonce, _ := hex.DecodeString(request.Nonce)
	copy(first.EdgeRequestID[:], nonce)
	first.ResponseHeaderSHA256 = receiptHeaderDigest
	first.ResponseBodySHA256 = sha256.Sum256(nil)
	leaves := []ResponseReceiptLeaf{first}
	rng := rand.New(rand.NewSource(42))
	for len(leaves) < 7 {
		leaves = append(leaves, pickLeaf(rng))
	}
	SortReceiptLeaves(leaves)
	hashes := make([][32]byte, len(leaves))
	for index, leaf := range leaves {
		vectors.Leaves = append(vectors.Leaves, toVectorLeaf(t, leaf))
		hashes[index], _ = leaf.Hash()
	}
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 9, 13} {
		tree := syntheticLeafHashes(n, byte(0x40+n))
		root, _ := ReceiptMerkleRoot(tree)
		entry := vectorTree{Root: hex.EncodeToString(root[:])}
		for index := range tree {
			entry.LeafHashes = append(entry.LeafHashes, hex.EncodeToString(tree[index][:]))
			proof, _ := ReceiptInclusionProof(tree, index)
			encoded := []string{}
			for _, node := range proof {
				encoded = append(encoded, hex.EncodeToString(node[:]))
			}
			entry.Proofs = append(entry.Proofs, encoded)
		}
		vectors.Trees = append(vectors.Trees, entry)
	}
	prev := zeroBatchDigest
	for sequence, span := range [][2]int{{0, 4}, {4, 7}} {
		batchHashes := hashes[span[0]:span[1]]
		batch := signedBatch(t, key, uint64(sequence+1), prev, batchHashes)
		envelope := ResponseReceiptBatchEnvelope{Batch: batch}
		for index := span[0]; index < span[1]; index++ {
			envelope.Entries = append(envelope.Entries, ResponseReceiptEntry{EdgeRequestID: vectors.Leaves[index].EdgeRequestID,
				FinishedAtUnixMS: vectors.Leaves[index].FinishedAtUnixMS, LeafHash: vectors.Leaves[index].LeafHash})
		}
		message, _ := ResponseReceiptBatchMessage(batch)
		digest, _ := ResponseReceiptBatchDigest(batch)
		vectors.Batches = append(vectors.Batches, vectorBatch{Envelope: envelope, Message: hex.EncodeToString(message), BatchDigest: digest})
		prev = digest
	}
	good := vectors.Batches[0].Envelope
	mutations := []struct {
		reason string
		apply  func(*ResponseReceiptBatchEnvelope)
	}{
		{"receipt_batch_signature_invalid", func(e *ResponseReceiptBatchEnvelope) { e.Batch.WindowStartUnix++ }},
		{"receipt_batch_entry_order_invalid", func(e *ResponseReceiptBatchEnvelope) { e.Entries[0], e.Entries[1] = e.Entries[1], e.Entries[0] }},
		{"receipt_batch_root_mismatch", func(e *ResponseReceiptBatchEnvelope) { e.Entries[1].LeafHash = e.Entries[2].LeafHash }},
		{"receipt_batch_root_mismatch", func(e *ResponseReceiptBatchEnvelope) {
			e.Entries[3].FinishedAtUnixMS++
			e.Entries[3].LeafHash = strings.Repeat("0", 64)
		}},
		{"receipt_batch_entry_count_mismatch", func(e *ResponseReceiptBatchEnvelope) { e.Entries = e.Entries[:3] }},
		{"receipt_batch_entry_duplicate", func(e *ResponseReceiptBatchEnvelope) { e.Entries[1].EdgeRequestID = e.Entries[0].EdgeRequestID }},
		{"receipt_batch_fields_invalid", func(e *ResponseReceiptBatchEnvelope) { e.Batch.LeafCount = 0 }},
		{"receipt_batch_entry_window_invalid", func(e *ResponseReceiptBatchEnvelope) { e.Entries[3].FinishedAtUnixMS += 1000 }},
	}
	for _, mutation := range mutations {
		envelope := ResponseReceiptBatchEnvelope{Batch: good.Batch, Entries: append([]ResponseReceiptEntry(nil), good.Entries...)}
		mutation.apply(&envelope)
		if _, err := VerifyResponseReceiptBatchEnvelope(envelope, key.Public().(ed25519.PublicKey)); err == nil {
			t.Fatalf("%s mutation verified", mutation.reason)
		}
		vectors.InvalidBatches = append(vectors.InvalidBatches, vectorBatch{Envelope: envelope, Reason: mutation.reason})
	}
	pull := request
	pull.Path, pull.Query = "/.ms-receipts/v1/batches", "after_sequence=0&boot="
	pullMessage, _ := ReceiptPullMessage(pull)
	pullSignature, _ := SignReceiptPull(pull, key)
	vectors.PullSignatures = []vectorPull{{Request: pull, Message: hex.EncodeToString(pullMessage), Signature: pullSignature}}
	validPreimage, _ := hex.DecodeString(vectors.Leaves[0].Preimage)
	for _, invalid := range [][]byte{
		append(append([]byte(nil), validPreimage...), 0),
		validPreimage[:len(validPreimage)-1],
		func() []byte {
			b := append([]byte(nil), validPreimage...)
			b[len(responseReceiptLeafDomain)+1] = 9
			return b
		}(),
		func() []byte { b := append([]byte(nil), validPreimage...); b[0] ^= 1; return b }(),
	} {
		vectors.InvalidLeaves = append(vectors.InvalidLeaves, hex.EncodeToString(invalid))
	}
	pickKey := []byte("edge-private-sample-key")
	for index := 0; index < 4000; index++ {
		var id [16]byte
		binary.BigEndian.PutUint64(id[8:], uint64(index))
		selected := ReceiptSelected(pickKey, id, 1000)
		if selected || index < 3 {
			vectors.Picks = append(vectors.Picks, vectorPick{Key: hex.EncodeToString(pickKey), EdgeRequestID: hex.EncodeToString(id[:]), Denominator: 1000, Selected: selected})
		}
	}
	return vectors
}

func TestResponseReceiptVectors(t *testing.T) {
	vectors := buildResponseReceiptVectors(t)
	encoded, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if *updateResponseReceiptVectors {
		if err := os.MkdirAll(filepath.Dir(responseReceiptVectorsPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(responseReceiptVectorsPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(responseReceiptVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, encoded) {
		t.Fatal("stored response receipt vectors differ from the implementation")
	}
	// Independently verify the stored file, not just regenerate it.
	var parsed responseReceiptVectors
	if err := json.Unmarshal(stored, &parsed); err != nil {
		t.Fatal(err)
	}
	keyBytes, _ := hex.DecodeString(parsed.MinerServiceKey)
	for _, leaf := range parsed.Leaves {
		preimage, _ := hex.DecodeString(leaf.Preimage)
		decoded, err := DecodeResponseReceiptLeaf(preimage)
		hash := ReceiptLeafHash(preimage)
		if err != nil || decoded != fromVectorLeaf(leaf) || hex.EncodeToString(hash[:]) != leaf.LeafHash {
			t.Fatal("stored leaf vector does not verify")
		}
	}
	for _, invalid := range parsed.InvalidLeaves {
		preimage, _ := hex.DecodeString(invalid)
		if _, err := DecodeResponseReceiptLeaf(preimage); err == nil {
			t.Fatal("stored invalid leaf decodes")
		}
	}
	for _, batch := range parsed.Batches {
		if _, err := VerifyResponseReceiptBatchEnvelope(batch.Envelope, ed25519.PublicKey(keyBytes)); err != nil {
			t.Fatalf("stored batch does not verify: %v", err)
		}
	}
	for _, batch := range parsed.InvalidBatches {
		if _, err := VerifyResponseReceiptBatchEnvelope(batch.Envelope, ed25519.PublicKey(keyBytes)); err == nil {
			t.Fatalf("stored invalid batch %s verifies", batch.Reason)
		}
	}
}

// BenchmarkResponseReceiptPerResponse measures the miner's per-response
// cost of design §4.2 at a 20 KiB body: body hash, leaf build and hash.
func BenchmarkResponseReceiptPerResponse(b *testing.B) {
	body := bytes.Repeat([]byte{'x'}, 20<<10)
	leaf := pickLeaf(rand.New(rand.NewSource(5)))
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		leaf.ResponseBodySHA256 = sha256.Sum256(body)
		leaf.FinishedAtUnixMS++
		if _, err := leaf.Hash(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkResponseReceiptBatch1000 measures one per-second batch of 1000
// leaves: Merkle root plus one ed25519 signature (§4.2 tree + signature).
func BenchmarkResponseReceiptBatch1000(b *testing.B) {
	key := vectorKey()
	hashes := syntheticLeafHashes(1000, 1)
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		signedBatch(b, key, 1, zeroBatchDigest, hashes)
	}
}

// BenchmarkResponseReceiptEdgeVerify1000 measures the edge side of one
// 1000-leaf batch: signature verify plus Merkle rebuild (§4.3).
func BenchmarkResponseReceiptEdgeVerify1000(b *testing.B) {
	key := vectorKey()
	hashes := syntheticLeafHashes(1000, 2)
	envelope := ResponseReceiptBatchEnvelope{Batch: signedBatch(b, key, 1, zeroBatchDigest, hashes)}
	for index, hash := range hashes {
		var id [16]byte
		binary.BigEndian.PutUint64(id[8:], uint64(index))
		envelope.Entries = append(envelope.Entries, ResponseReceiptEntry{EdgeRequestID: hex.EncodeToString(id[:]), FinishedAtUnixMS: 1_762_000_000_000, LeafHash: hex.EncodeToString(hash[:])})
	}
	public := key.Public().(ed25519.PublicKey)
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if _, err := VerifyResponseReceiptBatchEnvelope(envelope, public); err != nil {
			b.Fatal(err)
		}
	}
}
