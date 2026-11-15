// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package organic

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"regexp"
	"sort"
	"strings"
)

// Response receipts v2: the miner commits to every response it serves
// through the edge with one binary leaf per response, batched per second
// into an RFC 6962 Merkle tree whose root the miner service key signs. The
// edge pulls batches out of band and recomputes each leaf from what it
// observed, so a miner cannot tell which responses are audited.

const (
	// ResponseReceiptsCapability is the miner capability the edge reads
	// before it pulls receipts from a bound miner.
	ResponseReceiptsCapability = "response-receipts-v2"

	ResponseReceiptBatchSchema        = "ms.computer/mscomputer-subnet/response-receipt-batch"
	ResponseReceiptBatchSchemaVersion = 2
	// MaxResponseReceiptBatchLeaves bounds one per-second batch.
	MaxResponseReceiptBatchLeaves = 65536

	ReceiptKindDynamic uint8 = 1
	ReceiptKindStatic  uint8 = 2

	ReceiptCompletionComplete       uint8 = 0
	ReceiptCompletionAbortedByMiner uint8 = 1
	ReceiptCompletionClientGone     uint8 = 2
	ReceiptCompletionOverLimit      uint8 = 3
)

var (
	responseReceiptLeafDomain     = []byte("ms.computer/mscomputer-subnet/response-receipt-leaf/v2")
	responseReceiptBatchDomain    = []byte("ms.computer/mscomputer-subnet/response-receipt-batch/v2/ed25519")
	responseReceiptEvidenceDomain = []byte("ms.computer/mscomputer-subnet/response-receipt-evidence/v1")
	responseReceiptPullDomain     = []byte("ms.computer/mscomputer-subnet/response-receipt-pull/v1/ed25519")
	receiptEndpointIDPattern      = regexp.MustCompile(`^[A-Za-z0-9-]{1,320}$`)
	zeroBatchDigest               = strings.Repeat("0", 64)
)

// ResponseReceiptLeaf is one ReceiptLeafV2. Digests are raw SHA-256 bytes.
type ResponseReceiptLeaf struct {
	Kind                 uint8
	EndpointID           string
	Generation           uint64
	TicketDigest         [32]byte
	EdgeRequestID        [16]byte
	RequestDigest        [32]byte
	ResponseStatus       uint16
	ResponseHeaderSHA256 [32]byte
	ResponseBodyLen      uint64
	ResponseBodySHA256   [32]byte
	Completion           uint8
	FinishedAtUnixMS     uint64
}

func (l ResponseReceiptLeaf) Validate() error {
	if l.Kind != ReceiptKindDynamic && l.Kind != ReceiptKindStatic {
		return errors.New("receipt_leaf_kind_invalid")
	}
	if !receiptEndpointIDPattern.MatchString(l.EndpointID) || l.Generation < 1 {
		return errors.New("receipt_leaf_incarnation_invalid")
	}
	if l.ResponseStatus != 0 && (l.ResponseStatus < 100 || l.ResponseStatus > 599) {
		return errors.New("receipt_leaf_status_invalid")
	}
	if l.Completion > ReceiptCompletionOverLimit {
		return errors.New("receipt_leaf_completion_invalid")
	}
	return nil
}

// Encode returns the ReceiptLeafV2 preimage: domain || 0x00 || fixed
// big-endian fields with a u16 length prefix on endpoint_id.
func (l ResponseReceiptLeaf) Encode() ([]byte, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(responseReceiptLeafDomain)+1+1+2+len(l.EndpointID)+8+32+16+32+2+32+8+32+1+8)
	out = append(out, responseReceiptLeafDomain...)
	out = append(out, 0, l.Kind)
	out = binary.BigEndian.AppendUint16(out, uint16(len(l.EndpointID)))
	out = append(out, l.EndpointID...)
	out = binary.BigEndian.AppendUint64(out, l.Generation)
	out = append(out, l.TicketDigest[:]...)
	out = append(out, l.EdgeRequestID[:]...)
	out = append(out, l.RequestDigest[:]...)
	out = binary.BigEndian.AppendUint16(out, l.ResponseStatus)
	out = append(out, l.ResponseHeaderSHA256[:]...)
	out = binary.BigEndian.AppendUint64(out, l.ResponseBodyLen)
	out = append(out, l.ResponseBodySHA256[:]...)
	out = append(out, l.Completion)
	out = binary.BigEndian.AppendUint64(out, l.FinishedAtUnixMS)
	return out, nil
}

// DecodeResponseReceiptLeaf parses an exact preimage; anything that does not
// re-encode to the same bytes fails.
func DecodeResponseReceiptLeaf(preimage []byte) (ResponseReceiptLeaf, error) {
	fail := func() (ResponseReceiptLeaf, error) {
		return ResponseReceiptLeaf{}, errors.New("receipt_leaf_malformed")
	}
	prefix := len(responseReceiptLeafDomain) + 1
	if len(preimage) < prefix+3 || string(preimage[:prefix-1]) != string(responseReceiptLeafDomain) || preimage[prefix-1] != 0 {
		return fail()
	}
	var l ResponseReceiptLeaf
	rest := preimage[prefix:]
	l.Kind = rest[0]
	idLen := int(binary.BigEndian.Uint16(rest[1:3]))
	rest = rest[3:]
	const tail = 8 + 32 + 16 + 32 + 2 + 32 + 8 + 32 + 1 + 8
	if len(rest) != idLen+tail {
		return fail()
	}
	l.EndpointID, rest = string(rest[:idLen]), rest[idLen:]
	l.Generation, rest = binary.BigEndian.Uint64(rest), rest[8:]
	rest = rest[copy(l.TicketDigest[:], rest):]
	rest = rest[copy(l.EdgeRequestID[:], rest):]
	rest = rest[copy(l.RequestDigest[:], rest):]
	l.ResponseStatus, rest = binary.BigEndian.Uint16(rest), rest[2:]
	rest = rest[copy(l.ResponseHeaderSHA256[:], rest):]
	l.ResponseBodyLen, rest = binary.BigEndian.Uint64(rest), rest[8:]
	rest = rest[copy(l.ResponseBodySHA256[:], rest):]
	l.Completion, rest = rest[0], rest[1:]
	l.FinishedAtUnixMS = binary.BigEndian.Uint64(rest)
	if err := l.Validate(); err != nil {
		return fail()
	}
	return l, nil
}

// Hash is SHA-256(0x00 || preimage), the RFC 6962 leaf hash.
func (l ResponseReceiptLeaf) Hash() ([32]byte, error) {
	preimage, err := l.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return ReceiptLeafHash(preimage), nil
}

// ReceiptLeafHash hashes an already encoded leaf preimage.
func ReceiptLeafHash(preimage []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(preimage)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func receiptNodeHash(left, right [32]byte) [32]byte {
	var buffer [65]byte
	buffer[0] = 1
	copy(buffer[1:33], left[:])
	copy(buffer[33:], right[:])
	return sha256.Sum256(buffer[:])
}

// ReceiptRequestDigest is SHA-256 of the exact signed edge-runtime-request
// message (domain || 0x00 || canonical request, nonce and timestamp set).
func ReceiptRequestDigest(request EdgeRuntimeRequest) ([32]byte, error) {
	message, err := EdgeRuntimeRequestMessage(request)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(message), nil
}

// receiptCommittedHeaders is the response_header_sha256 committed set
// (receipts v2). Only these headers enter the digest; every other header is
// ignored on both sides. A header is committed when it changes what a client
// does with the response and no hop between the miner and the edge sets or
// rewrites it by default: neither Go net/http (Date, Content-Length,
// Connection, Transfer-Encoding, sniffed Content-Type, hop-by-hop removal)
// nor a CDN or tunnel front (cf-ray, cf-cache-status,
// Server, Vary, ETag weakening, Last-Modified removal, NEL/Report-To,
// Alt-Svc). Cache-Control is not committed: the edge replaces it on every
// dynamic response before the client sees it. Headers a zone can opt into
// adding (managed security headers such as X-Content-Type-Options, HSTS,
// X-Frame-Options, Referrer-Policy) are left out so an honest miner behind
// such a front still matches; the edge sets its own policy for those. The
// body is committed separately by body_len and body_sha256, and
// Content-Encoding by its own entry here.
var receiptCommittedHeaders = map[string]bool{
	"access-control-allow-credentials": true, "access-control-allow-headers": true,
	"access-control-allow-methods": true, "access-control-allow-origin": true,
	"access-control-expose-headers": true, "access-control-max-age": true,
	"content-disposition": true, "content-encoding": true, "content-language": true,
	"content-location": true, "content-range": true, "content-type": true, "location": true,
	"refresh": true, "retry-after": true, "set-cookie": true, "www-authenticate": true,
}

// receiptCDNCookies are the Set-Cookie names the CDN front adds on its own;
// receiptCDNCookiePrefixes cover its numbered families. They are left out
// of the digest on both sides. Any other cookie, whatever its name, is
// committed.
var (
	receiptCDNCookies = map[string]bool{
		"__cf_bm": true, "__cflb": true, "__cfruid": true, "_cfuvid": true, "cf_clearance": true,
		"__cfwaitingroom": true, "cf_ob_info": true, "cf_use_ob": true,
	}
	receiptCDNCookiePrefixes = []string{"__cfseq-", "cf_chl_"}
)

// ReceiptHeaderValue is the value normalisation of the committed set,
// equal to what an HTTP/1.1 Go server puts on the wire and any proxy keeps:
// CR and LF become spaces, runs of spaces and tabs collapse to one space,
// and leading and trailing spaces and tabs are trimmed. It is idempotent,
// so the miner (raw values) and the edge (received values) agree.
func ReceiptHeaderValue(value string) string {
	var out strings.Builder
	out.Grow(len(value))
	pending := false
	for i := 0; i < len(value); i++ {
		switch c := value[i]; c {
		case ' ', '\t', '\r', '\n':
			pending = out.Len() > 0
		default:
			if pending {
				out.WriteByte(' ')
				pending = false
			}
			out.WriteByte(c)
		}
	}
	return out.String()
}

func receiptCDNCookie(value string) bool {
	name, _, _ := strings.Cut(value, "=")
	name, _, _ = strings.Cut(name, ";")
	name = strings.ToLower(strings.TrimSpace(name))
	if receiptCDNCookies[name] {
		return true
	}
	for _, prefix := range receiptCDNCookiePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// ReceiptHeaderSHA256 is the leaf's response_header_sha256 (receipts v2):
// ResponseHeaderSHA256 over the (lower-cased name, ReceiptHeaderValue)
// pairs whose name is in the committed set, minus CDN-added cookies, in
// their original order within a name. The miner digests the application's
// headers at its digest point; the edge digests the headers as received,
// before any of its own header mutations. Both sides get the same digest
// whatever the transport trimmed or added outside the committed set.
func ReceiptHeaderSHA256(headers [][2]string) ([32]byte, error) {
	kept := make([][2]string, 0, len(headers))
	for _, header := range headers {
		name := strings.ToLower(header[0])
		if !receiptCommittedHeaders[name] {
			continue
		}
		value := ReceiptHeaderValue(header[1])
		if name == "set-cookie" && receiptCDNCookie(value) {
			continue
		}
		kept = append(kept, [2]string{name, value})
	}
	var out [32]byte
	encoded, err := ResponseHeaderSHA256(kept)
	if err != nil {
		return out, err
	}
	_, err = hex.Decode(out[:], []byte(encoded))
	return out, err
}

// ReceiptHTTPHeaderSHA256 is ReceiptHeaderSHA256 over every (name, value)
// of a header map. The miner and the edge both digest through it.
func ReceiptHTTPHeaderSHA256(header map[string][]string) ([32]byte, error) {
	var pairs [][2]string
	for name, values := range header {
		for _, value := range values {
			pairs = append(pairs, [2]string{name, value})
		}
	}
	return ReceiptHeaderSHA256(pairs)
}

// ReceiptPullAuthorizationHeader carries the edge's second signature on a
// receipt pull: the same edge-runtime-request fields (nonce and timestamp
// of the accompanying X-Ms-Edge-Authorization) under the receipt-pull
// domain. The edge never produces it for forwarded customer traffic, so an
// ordinary request can neither read receipts nor be diverted from the app.
const ReceiptPullAuthorizationHeader = "X-Ms-Receipt-Pull-Authorization"

// ReceiptPullMessage is pull-domain || 0x00 || canonical(request).
func ReceiptPullMessage(request EdgeRuntimeRequest) ([]byte, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	encoded, err := Canonical(request)
	if err != nil {
		return nil, err
	}
	return append(append(append([]byte{}, responseReceiptPullDomain...), 0), encoded...), nil
}

// SignReceiptPull returns the ReceiptPullAuthorizationHeader value.
func SignReceiptPull(request EdgeRuntimeRequest, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("invalid receipt pull signing key")
	}
	message, err := ReceiptPullMessage(request)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ed25519.Sign(key, message)), nil
}

// VerifyReceiptPull checks a pull signature over the already verified edge
// request (nonce and timestamp set).
func VerifyReceiptPull(request EdgeRuntimeRequest, value string, key ed25519.PublicKey) error {
	message, err := ReceiptPullMessage(request)
	if err != nil {
		return err
	}
	signature, err := hex.DecodeString(value)
	if err != nil || !signaturePattern.MatchString(value) || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message, signature) {
		return errors.New("receipt_pull_authorization_invalid")
	}
	return nil
}

// ReceiptTicketDigest converts a "sha256:<hex>" ticket digest
// (TicketDigestV4, StaticTicketDigestV1) to the leaf's raw bytes.
func ReceiptTicketDigest(digest string) ([32]byte, error) {
	var out [32]byte
	if !ValidDigest(digest) {
		return out, errors.New("receipt_ticket_digest_invalid")
	}
	_, err := hex.Decode(out[:], []byte(strings.TrimPrefix(digest, "sha256:")))
	return out, err
}

// splitPoint is RFC 6962's k: the largest power of two strictly below n.
func splitPoint(n int) int {
	return 1 << (bits.Len(uint(n-1)) - 1)
}

// ReceiptMerkleRoot is the RFC 6962 Merkle tree hash over leaf hashes. An
// empty tree has no root in this protocol (batches are never empty).
func ReceiptMerkleRoot(leaves [][32]byte) ([32]byte, error) {
	if len(leaves) == 0 {
		return [32]byte{}, errors.New("receipt_tree_empty")
	}
	return merkleRoot(leaves), nil
}

func merkleRoot(leaves [][32]byte) [32]byte {
	// Iterative form of RFC 6962 MTH: combining adjacent pairs level by
	// level and promoting an odd last node yields the same tree.
	level := append([][32]byte(nil), leaves...)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for index := 0; index+1 < len(level); index += 2 {
			next = append(next, receiptNodeHash(level[index], level[index+1]))
		}
		if len(level)%2 == 1 {
			next = append(next, level[len(level)-1])
		}
		level = next
	}
	return level[0]
}

// ReceiptInclusionProof is the RFC 6962 audit path for leaves[index].
func ReceiptInclusionProof(leaves [][32]byte, index int) ([][32]byte, error) {
	if index < 0 || index >= len(leaves) {
		return nil, errors.New("receipt_proof_index_invalid")
	}
	return auditPath(leaves, index), nil
}

func auditPath(leaves [][32]byte, index int) [][32]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := splitPoint(len(leaves))
	if index < k {
		return append(auditPath(leaves[:k], index), merkleRoot(leaves[k:]))
	}
	return append(auditPath(leaves[k:], index-k), merkleRoot(leaves[:k]))
}

// VerifyReceiptInclusion checks an audit path (RFC 9162 §2.1.3.2).
func VerifyReceiptInclusion(leafHash [32]byte, index, size uint64, proof [][32]byte, root [32]byte) bool {
	if index >= size {
		return false
	}
	fn, sn := index, size-1
	r := leafHash
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = receiptNodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = receiptNodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && r == root
}

// ResponseReceiptBatch is one signed per-second statement of one agent boot.
type ResponseReceiptBatch struct {
	Schema          string `json:"schema"`
	SchemaVersion   int    `json:"schema_version"`
	MinerServiceKey string `json:"miner_service_key"`
	AgentBootID     string `json:"agent_boot_id"`
	Sequence        uint64 `json:"sequence"`
	PrevBatchDigest string `json:"prev_batch_digest"`
	WindowStartUnix uint64 `json:"window_start_unix"`
	LeafCount       uint32 `json:"leaf_count"`
	MerkleRoot      string `json:"merkle_root"`
	SignatureHex    string `json:"signature_hex"`
}

func (b ResponseReceiptBatch) Validate() error {
	if b.Schema != ResponseReceiptBatchSchema || b.SchemaVersion != ResponseReceiptBatchSchemaVersion {
		return errors.New("receipt_batch_schema_unsupported")
	}
	if !ValidHex64(b.MinerServiceKey) || !hex32Pattern.MatchString(b.AgentBootID) || b.Sequence < 1 ||
		!ValidHex64(b.PrevBatchDigest) || b.WindowStartUnix < 1 || b.LeafCount < 1 ||
		b.LeafCount > MaxResponseReceiptBatchLeaves || !ValidHex64(b.MerkleRoot) ||
		(b.SignatureHex != "" && !signaturePattern.MatchString(b.SignatureHex)) {
		return errors.New("receipt_batch_fields_invalid")
	}
	if (b.Sequence == 1) != (b.PrevBatchDigest == zeroBatchDigest) {
		return errors.New("receipt_batch_chain_start_invalid")
	}
	return nil
}

// ResponseReceiptBatchMessage is domain || 0x00 || canonical(every field
// except schema, schema_version and signature_hex).
func ResponseReceiptBatchMessage(b ResponseReceiptBatch) ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	encoded, err := Canonical(map[string]any{
		"agent_boot_id": b.AgentBootID, "leaf_count": b.LeafCount, "merkle_root": b.MerkleRoot,
		"miner_service_key": b.MinerServiceKey, "prev_batch_digest": b.PrevBatchDigest,
		"sequence": b.Sequence, "window_start_unix": b.WindowStartUnix,
	})
	if err != nil {
		return nil, err
	}
	return append(append(append([]byte{}, responseReceiptBatchDomain...), 0), encoded...), nil
}

// SignResponseReceiptBatch signs an unsigned batch in place; the key must be
// the one named by miner_service_key.
func SignResponseReceiptBatch(b *ResponseReceiptBatch, key ed25519.PrivateKey) error {
	if b == nil || len(key) != ed25519.PrivateKeySize || b.SignatureHex != "" ||
		b.MinerServiceKey != hex.EncodeToString(key.Public().(ed25519.PublicKey)) {
		return errors.New("invalid receipt batch signing input")
	}
	message, err := ResponseReceiptBatchMessage(*b)
	if err != nil {
		return err
	}
	b.SignatureHex = hex.EncodeToString(ed25519.Sign(key, message))
	return nil
}

// VerifyResponseReceiptBatch checks the signature under the expected
// published miner service key; the batch must name that same key.
func VerifyResponseReceiptBatch(b ResponseReceiptBatch, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize || b.MinerServiceKey != hex.EncodeToString(key) || b.SignatureHex == "" {
		return errors.New("receipt_batch_key_mismatch")
	}
	message, err := ResponseReceiptBatchMessage(b)
	if err != nil {
		return err
	}
	signature, err := hex.DecodeString(b.SignatureHex)
	if err != nil || !ed25519.Verify(key, message, signature) {
		return errors.New("receipt_batch_signature_invalid")
	}
	return nil
}

// ResponseReceiptBatchDigest is SHA-256 of the full canonical signed batch;
// it is the next batch's prev_batch_digest.
func ResponseReceiptBatchDigest(b ResponseReceiptBatch) (string, error) {
	if b.SignatureHex == "" {
		return "", errors.New("receipt batch is unsigned")
	}
	if err := b.Validate(); err != nil {
		return "", err
	}
	return DigestHex(b)
}

// ResponseReceiptEntry names one leaf of a batch, in tree order. It
// carries finished_at_unix_ms, the one leaf field only the miner knows, so
// the edge can rebuild the leaf from its own observation without fetching
// the preimage.
type ResponseReceiptEntry struct {
	EdgeRequestID    string `json:"edge_request_id"`
	FinishedAtUnixMS uint64 `json:"finished_at_unix_ms"`
	LeafHash         string `json:"leaf_hash"`
}

// ResponseReceiptBatchEnvelope is what the agent serves to the edge.
type ResponseReceiptBatchEnvelope struct {
	Batch   ResponseReceiptBatch   `json:"batch"`
	Entries []ResponseReceiptEntry `json:"entries"`
}

// VerifyResponseReceiptBatchEnvelope verifies the signature, that the entry
// list has exactly leaf_count unique request ids in tree order (by
// finished_at_unix_ms, then edge_request_id), all finished inside the
// batch's window second, and that the entries' leaf hashes rebuild the
// signed Merkle root. It returns the decoded leaf
// hashes keyed by edge request id with their tree index.
func VerifyResponseReceiptBatchEnvelope(envelope ResponseReceiptBatchEnvelope, key ed25519.PublicKey) (map[[16]byte]ReceiptIndexedLeaf, error) {
	if err := VerifyResponseReceiptBatch(envelope.Batch, key); err != nil {
		return nil, err
	}
	if len(envelope.Entries) != int(envelope.Batch.LeafCount) {
		return nil, errors.New("receipt_batch_entry_count_mismatch")
	}
	hashes := make([][32]byte, len(envelope.Entries))
	out := make(map[[16]byte]ReceiptIndexedLeaf, len(envelope.Entries))
	for index, entry := range envelope.Entries {
		var id [16]byte
		if !hex32Pattern.MatchString(entry.EdgeRequestID) || !ValidHex64(entry.LeafHash) {
			return nil, errors.New("receipt_batch_entry_invalid")
		}
		hex.Decode(id[:], []byte(entry.EdgeRequestID))
		hex.Decode(hashes[index][:], []byte(entry.LeafHash))
		if _, duplicate := out[id]; duplicate {
			return nil, errors.New("receipt_batch_entry_duplicate")
		}
		if entry.FinishedAtUnixMS/1000 != envelope.Batch.WindowStartUnix {
			return nil, errors.New("receipt_batch_entry_window_invalid")
		}
		if index > 0 {
			previous := envelope.Entries[index-1]
			if entry.FinishedAtUnixMS < previous.FinishedAtUnixMS ||
				(entry.FinishedAtUnixMS == previous.FinishedAtUnixMS && entry.EdgeRequestID < previous.EdgeRequestID) {
				return nil, errors.New("receipt_batch_entry_order_invalid")
			}
		}
		out[id] = ReceiptIndexedLeaf{Index: uint64(index), Hash: hashes[index], FinishedAtUnixMS: entry.FinishedAtUnixMS}
	}
	root := merkleRoot(hashes)
	if hex.EncodeToString(root[:]) != envelope.Batch.MerkleRoot {
		return nil, errors.New("receipt_batch_root_mismatch")
	}
	return out, nil
}

// ReceiptIndexedLeaf is one leaf hash at its tree index.
type ReceiptIndexedLeaf struct {
	Index            uint64
	Hash             [32]byte
	FinishedAtUnixMS uint64
}

// SortReceiptLeaves orders leaves by finished_at_unix_ms then
// edge_request_id, the deterministic tree order.
func SortReceiptLeaves(leaves []ResponseReceiptLeaf) {
	sort.SliceStable(leaves, func(i, j int) bool {
		if leaves[i].FinishedAtUnixMS != leaves[j].FinishedAtUnixMS {
			return leaves[i].FinishedAtUnixMS < leaves[j].FinishedAtUnixMS
		}
		return string(leaves[i].EdgeRequestID[:]) < string(leaves[j].EdgeRequestID[:])
	})
}

// ReceiptSelected is the edge's blind customer pick:
// HMAC-SHA256(key, edge_request_id) read as a big-endian u64 < 2^64/denominator.
// A denominator of 0 picks nothing; 1 picks everything.
func ReceiptSelected(key []byte, edgeRequestID [16]byte, denominator uint64) bool {
	if denominator == 0 || len(key) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(edgeRequestID[:])
	value := binary.BigEndian.Uint64(mac.Sum(nil)[:8])
	if denominator == 1 {
		return true
	}
	return value < ^uint64(0)/denominator
}

// ResponseReceiptEvidenceDigest is the unsigned digest of one edge evidence
// record: SHA-256(domain || 0x00 || canonical(record)).
func ResponseReceiptEvidenceDigest(record any) (string, error) {
	encoded, err := Canonical(record)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append(append(append([]byte{}, responseReceiptEvidenceDomain...), 0), encoded...))
	return hex.EncodeToString(sum[:]), nil
}

// String names a leaf for logs without its digests.
func (l ResponseReceiptLeaf) String() string {
	return fmt.Sprintf("receipt(%s g%d %x)", l.EndpointID, l.Generation, l.EdgeRequestID)
}
