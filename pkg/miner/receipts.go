// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/organic"
)

// Response receipts v1 (miner side). When an agent has a ReceiptRecorder,
// every edge-authorized runtime response gets one leaf; leaves are sealed
// into one signed Merkle batch per finished second and served to the edge.
// A nil recorder (the default) changes nothing.

// ReceiptsPathPrefix is the path of the receipt pull routes. The agent
// answers it only for a request that also carries a valid
// ReceiptPullAuthorizationHeader; without that header the path is an
// ordinary application path and is forwarded like any other.
const ReceiptsPathPrefix = "/.ms-receipts/v1/"

var (
	errReceiptRingFull  = errors.New("response receipt ring is full")
	errReceiptDuplicate = errors.New("response receipt edge request id already recorded")
)

type retainedLeaf struct {
	endpointID string
	preimage   []byte
	hash       [32]byte
	sequence   uint64 // 0 until sealed
	index      int
	expires    time.Time
}

type sealedBatch struct {
	envelope organic.ResponseReceiptBatchEnvelope
	hashes   [][32]byte
	expires  time.Time
}

// ReceiptRecorder holds unsealed leaves, retained leaf preimages and signed
// batches of one agent boot.
type ReceiptRecorder struct {
	key    ed25519.PrivateKey
	policy ReceiptRecorderConfig
	bootID string
	now    func() time.Time

	mu       sync.Mutex
	reserved uint64 // admitted requests whose leaf is not recorded yet
	pending  []organic.ResponseReceiptLeaf
	retained map[[16]byte]*retainedLeaf
	batches  []sealedBatch
	sequence uint64
	prev     string
	closed   bool
	// pulled is the highest sequence an authorized pull of this boot said
	// the edge already holds (after_sequence); loss is set at shutdown.
	pulled uint64
	loss   *ReceiptShutdownLoss
}

// ReceiptShutdownLoss counts the leaves a restart, shutdown timeout or
// upgrade loses: the ring is in memory, so a new boot owes nothing for
// them and the edge sees them as receipt_missing. It does not count
// batches that expired from memory (leaf retention) before the edge pulled
// them: those were already gone before shutdown and are not in the ring.
type ReceiptShutdownLoss struct {
	// InFlight responses were admitted but still running at shutdown (the
	// server flush timed out); their leaves are never recorded.
	InFlight uint64 `json:"in_flight"`
	// Unsealed leaves were recorded but could not be signed.
	Unsealed uint64 `json:"unsealed"`
	// Unpulled leaves were signed into batches past the edge's last
	// acknowledged sequence.
	Unpulled uint64 `json:"unpulled"`
	// UnpulledBatches is the number of those batches.
	UnpulledBatches uint64 `json:"unpulled_batches"`
	// PulledThrough is the last sequence the edge acknowledged.
	PulledThrough uint64 `json:"pulled_through"`
	Sequence      uint64 `json:"sequence"`
}

// Lost is the total number of leaves the edge will never receive.
func (l ReceiptShutdownLoss) Lost() uint64 { return l.InFlight + l.Unsealed + l.Unpulled }

// ShutdownLoss reports the loss counted when Run stopped; ok is false
// while the recorder is still running.
func (r *ReceiptRecorder) ShutdownLoss() (ReceiptShutdownLoss, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loss == nil {
		return ReceiptShutdownLoss{}, false
	}
	return *r.loss, true
}

// closeLocked flushes every pending leaf, stops admission and counts what
// the edge can no longer pull.
func (r *ReceiptRecorder) closeLocked(now time.Time) ReceiptShutdownLoss {
	_ = r.sealLocked(now, true)
	r.closed = true
	loss := ReceiptShutdownLoss{InFlight: r.reserved, Unsealed: uint64(len(r.pending)), PulledThrough: r.pulled, Sequence: r.sequence}
	for _, sealed := range r.batches {
		if sealed.envelope.Batch.Sequence > r.pulled {
			loss.Unpulled += uint64(sealed.envelope.Batch.LeafCount)
			loss.UnpulledBatches++
		}
	}
	r.loss = &loss
	return loss
}

// ReceiptRecorderConfig carries the only receipt bounds the miner reads: how
// long a leaf preimage is retained, how many leaves are retained at once and
// how many batches one pull returns. The edge and validator policy
// is not the miner's concern.
type ReceiptRecorderConfig struct {
	LeafRetentionS    uint64
	MaxRetainedLeaves uint64
	MaxBatchesPerPoll uint64
}

// DefaultReceiptRecorderConfig returns the miner bounds of the network's
// default response receipt policy.
func DefaultReceiptRecorderConfig() ReceiptRecorderConfig {
	return ReceiptRecorderConfig{LeafRetentionS: 900, MaxRetainedLeaves: 1 << 20, MaxBatchesPerPoll: 64}
}

// Validate rejects bounds the recorder cannot run with.
func (c ReceiptRecorderConfig) Validate() error {
	switch {
	case c.LeafRetentionS < 1:
		return errors.New("receipt policy timing is invalid")
	case c.MaxRetainedLeaves < 1 || c.MaxBatchesPerPoll < 1:
		return errors.New("receipt policy bounds are invalid")
	}
	return nil
}

// NewReceiptRecorder starts a new boot with a random boot id.
func NewReceiptRecorder(key ed25519.PrivateKey, policy ReceiptRecorderConfig) (*ReceiptRecorder, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("response receipts require the miner service key")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	var boot [16]byte
	if _, err := rand.Read(boot[:]); err != nil {
		return nil, err
	}
	return &ReceiptRecorder{
		key: key, policy: policy, bootID: hex.EncodeToString(boot[:]), now: time.Now,
		retained: make(map[[16]byte]*retainedLeaf), prev: strings.Repeat("0", 64),
	}, nil
}

// BootID names this recorder's batch chain.
func (r *ReceiptRecorder) BootID() string { return r.bootID }

// Admit reserves a leaf slot for a new request, or refuses it when the
// ring is full: the agent answers 503 instead of dropping a leaf it would
// owe the edge. Every admitted request must end in Record.
func (r *ReceiptRecorder) Admit() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(r.now())
	if r.closed || uint64(len(r.retained))+r.reserved >= r.policy.MaxRetainedLeaves {
		return errReceiptRingFull
	}
	r.reserved++
	return nil
}

// Record adds one finished response leaf to the current second and
// releases the slot its Admit reserved.
func (r *ReceiptRecorder) Record(leaf organic.ResponseReceiptLeaf) error {
	preimage, err := leaf.Encode()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.reserved > 0 {
		r.reserved--
	}
	if err != nil {
		return err
	}
	if r.closed {
		return errReceiptRingFull
	}
	if _, exists := r.retained[leaf.EdgeRequestID]; exists {
		return errReceiptDuplicate
	}
	r.retained[leaf.EdgeRequestID] = &retainedLeaf{
		endpointID: leaf.EndpointID, preimage: preimage, hash: organic.ReceiptLeafHash(preimage),
	}
	r.pending = append(r.pending, leaf)
	return nil
}

// Seal signs one batch for every finished second with leaves (and, with
// all set, for the current second too: the shutdown flush).
func (r *ReceiptRecorder) Seal(all bool) error {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sealLocked(now, all)
}

func (r *ReceiptRecorder) sealLocked(now time.Time, all bool) error {
	r.expireLocked(now)
	if len(r.pending) == 0 {
		return nil
	}
	current := uint64(now.Unix())
	organic.SortReceiptLeaves(r.pending)
	keep := r.pending[:0:0]
	for start := 0; start < len(r.pending); {
		second := r.pending[start].FinishedAtUnixMS / 1000
		end := start
		for end < len(r.pending) && r.pending[end].FinishedAtUnixMS/1000 == second && end-start < organic.MaxResponseReceiptBatchLeaves {
			end++
		}
		if second >= current && !all {
			keep = append(keep, r.pending[start:]...)
			break
		}
		if err := r.signLocked(second, r.pending[start:end], now); err != nil {
			// Leaves already sealed must not be signed again.
			r.pending = append(keep, r.pending[start:]...)
			return err
		}
		start = end
	}
	r.pending = keep
	return nil
}

func (r *ReceiptRecorder) signLocked(second uint64, leaves []organic.ResponseReceiptLeaf, now time.Time) error {
	hashes := make([][32]byte, len(leaves))
	entries := make([]organic.ResponseReceiptEntry, len(leaves))
	for index, leaf := range leaves {
		retained := r.retained[leaf.EdgeRequestID]
		hashes[index] = retained.hash
		entries[index] = organic.ResponseReceiptEntry{
			EdgeRequestID: hex.EncodeToString(leaf.EdgeRequestID[:]), FinishedAtUnixMS: leaf.FinishedAtUnixMS,
			LeafHash: hex.EncodeToString(retained.hash[:]),
		}
	}
	root, err := organic.ReceiptMerkleRoot(hashes)
	if err != nil {
		return err
	}
	batch := organic.ResponseReceiptBatch{
		Schema: organic.ResponseReceiptBatchSchema, SchemaVersion: organic.ResponseReceiptBatchSchemaVersion,
		MinerServiceKey: hex.EncodeToString(r.key.Public().(ed25519.PublicKey)), AgentBootID: r.bootID,
		Sequence: r.sequence + 1, PrevBatchDigest: r.prev, WindowStartUnix: second,
		LeafCount: uint32(len(leaves)), MerkleRoot: hex.EncodeToString(root[:]),
	}
	if err := organic.SignResponseReceiptBatch(&batch, r.key); err != nil {
		return err
	}
	digest, err := organic.ResponseReceiptBatchDigest(batch)
	if err != nil {
		return err
	}
	r.sequence, r.prev = batch.Sequence, digest
	for index, leaf := range leaves {
		retained := r.retained[leaf.EdgeRequestID]
		retained.sequence, retained.index = batch.Sequence, index
		retained.expires = now.Add(time.Duration(r.policy.LeafRetentionS) * time.Second)
	}
	r.batches = append(r.batches, sealedBatch{
		envelope: organic.ResponseReceiptBatchEnvelope{Batch: batch, Entries: entries}, hashes: hashes,
		expires: now.Add(time.Duration(r.policy.LeafRetentionS) * time.Second),
	})
	return nil
}

// expireLocked drops sealed leaves and batches past retention; unsealed
// leaves are never dropped.
func (r *ReceiptRecorder) expireLocked(now time.Time) {
	drop := 0
	for drop < len(r.batches) && !r.batches[drop].expires.After(now) {
		drop++
	}
	if drop > 0 {
		r.batches = append([]sealedBatch(nil), r.batches[drop:]...)
	}
	for id, leaf := range r.retained {
		if leaf.sequence != 0 && !leaf.expires.After(now) {
			delete(r.retained, id)
		}
	}
}

// Run seals finished seconds until ctx ends, then flushes every pending
// leaf so a planned restart leaves no request without a receipt.
func (r *ReceiptRecorder) Run(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.mu.Lock()
			loss := r.closeLocked(r.now())
			r.mu.Unlock()
			level := slog.LevelInfo
			if loss.Lost() > 0 {
				level = slog.LevelWarn
			}
			slog.Log(context.Background(), level, "response receipts shutdown leaf loss", "boot_id", r.bootID,
				"leaves_lost", loss.Lost(), "in_flight", loss.InFlight, "unsealed", loss.Unsealed,
				"unpulled", loss.Unpulled, "unpulled_batches", loss.UnpulledBatches,
				"pulled_through", loss.PulledThrough, "sequence", loss.Sequence)
			return
		case <-ticker.C:
			_ = r.Seal(false)
		}
	}
}

// receiptBatchesResponse is the pull answer: batches of the current boot
// after the requested sequence (from the start when boot differs).
type receiptBatchesResponse struct {
	AgentBootID string                                 `json:"agent_boot_id"`
	Batches     []organic.ResponseReceiptBatchEnvelope `json:"batches"`
}

// receiptLeafResponse is one leaf preimage with its batch and proof.
type receiptLeafResponse struct {
	Preimage string                       `json:"preimage"`
	Index    int                          `json:"index"`
	Proof    []string                     `json:"proof"`
	Batch    organic.ResponseReceiptBatch `json:"batch"`
}

func (r *ReceiptRecorder) batchesAfter(boot string, after uint64) receiptBatchesResponse {
	r.mu.Lock()
	defer r.mu.Unlock()
	if boot != r.bootID {
		after = 0
	} else if after > r.pulled {
		// The edge holds every batch through after; never past what exists.
		r.pulled = min(after, r.sequence)
	}
	out := receiptBatchesResponse{AgentBootID: r.bootID, Batches: []organic.ResponseReceiptBatchEnvelope{}}
	for _, sealed := range r.batches {
		if sealed.envelope.Batch.Sequence > after && uint64(len(out.Batches)) < r.policy.MaxBatchesPerPoll {
			out.Batches = append(out.Batches, sealed.envelope)
		}
	}
	return out
}

// leaf serves a preimage only to a pull authenticated for its own endpoint.
func (r *ReceiptRecorder) leaf(id [16]byte, endpointID string) (receiptLeafResponse, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	retained, ok := r.retained[id]
	if !ok || retained.sequence == 0 || retained.endpointID != endpointID {
		return receiptLeafResponse{}, false
	}
	for _, sealed := range r.batches {
		if sealed.envelope.Batch.Sequence != retained.sequence {
			continue
		}
		proof, err := organic.ReceiptInclusionProof(sealed.hashes, retained.index)
		if err != nil {
			return receiptLeafResponse{}, false
		}
		encoded := make([]string, len(proof))
		for index, node := range proof {
			encoded[index] = hex.EncodeToString(node[:])
		}
		return receiptLeafResponse{
			Preimage: hex.EncodeToString(retained.preimage), Index: retained.index, Proof: encoded, Batch: sealed.envelope.Batch,
		}, true
	}
	return receiptLeafResponse{}, false
}

// serveReceiptPull answers a request carrying the receipt pull header. The
// edge-runtime-request signature is already verified (ref); the pull
// header must be its exact twin under the receipt-pull domain and the
// path must be a receipt route. Anything else is 401.
func (r *ReceiptRecorder) serveReceiptPull(w http.ResponseWriter, req *http.Request, endpointID string, ref *edgeRequestRef) {
	values := req.Header.Values(organic.ReceiptPullAuthorizationHeader)
	path := req.URL.EscapedPath()
	if ref == nil || !ref.set || len(values) != 1 || !strings.HasPrefix(path, ReceiptsPathPrefix) ||
		organic.VerifyReceiptPull(ref.request, values[0], ref.key) != nil {
		http.Error(w, "receipt pull authorization rejected", http.StatusUnauthorized)
		return
	}
	r.serveReceipts(w, req, strings.TrimPrefix(path, ReceiptsPathPrefix), endpointID)
}

// serveReceipts answers an authorized pull: batches?boot=<id>&after_sequence=<n>
// or leaf/<edge_request_id>. Batches carry only request ids, leaf hashes
// and finish times; a leaf preimage is served only for its own endpoint.
func (r *ReceiptRecorder) serveReceipts(w http.ResponseWriter, req *http.Request, route, endpointID string) {
	if req.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case route == "batches":
		query := req.URL.Query()
		after, err := strconv.ParseUint(query.Get("after_sequence"), 10, 64)
		if query.Get("after_sequence") == "" {
			after, err = 0, nil
		}
		if err != nil {
			http.Error(w, "after_sequence is invalid", http.StatusBadRequest)
			return
		}
		writeReceiptJSON(w, r.batchesAfter(query.Get("boot"), after))
	case strings.HasPrefix(route, "leaf/"):
		var id [16]byte
		raw := strings.TrimPrefix(route, "leaf/")
		if len(raw) != 32 || strings.ToLower(raw) != raw {
			http.Error(w, "edge request id is invalid", http.StatusBadRequest)
			return
		}
		if _, err := hex.Decode(id[:], []byte(raw)); err != nil {
			http.Error(w, "edge request id is invalid", http.StatusBadRequest)
			return
		}
		answer, ok := r.leaf(id, endpointID)
		if !ok {
			http.NotFound(w, req)
			return
		}
		writeReceiptJSON(w, answer)
	default:
		http.NotFound(w, req)
	}
}

func writeReceiptJSON(w http.ResponseWriter, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "receipt encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(encoded)
}

// edgeRequestRef is the receipt identity of one verified edge request.
type edgeRequestRef struct {
	set     bool
	id      [16]byte
	digest  [32]byte
	request organic.EdgeRuntimeRequest
	key     ed25519.PublicKey
}

type edgeRequestRefKey struct{}

// withEdgeRequestRef installs a slot verifyEdgeRequest fills on success.
func withEdgeRequestRef(req *http.Request) (*http.Request, *edgeRequestRef) {
	ref := &edgeRequestRef{}
	return req.WithContext(context.WithValue(req.Context(), edgeRequestRefKey{}, ref)), ref
}

func fillEdgeRequestRef(req *http.Request, request organic.EdgeRuntimeRequest, key ed25519.PublicKey) {
	ref, ok := req.Context().Value(edgeRequestRefKey{}).(*edgeRequestRef)
	if !ok {
		return
	}
	digest, err := organic.ReceiptRequestDigest(request)
	if err != nil {
		return
	}
	if _, err := hex.Decode(ref.id[:], []byte(request.Nonce)); err != nil {
		return
	}
	ref.digest, ref.request, ref.key, ref.set = digest, request, key, true
}

// receiptTap observes exactly what the agent writes to the edge: status,
// body length and body SHA-256. The header digest is set at the v2 digest
// point (after sanitizing) when the
// application answered, else over the agent's own headers.
type receiptTap struct {
	http.ResponseWriter
	leaf         organic.ResponseReceiptLeaf
	body         hash.Hash
	headerDigest *[32]byte
	wroteHeader  bool
	writeFailed  bool
}

func newReceiptTap(w http.ResponseWriter, leaf organic.ResponseReceiptLeaf) *receiptTap {
	return &receiptTap{ResponseWriter: w, leaf: leaf, body: sha256.New()}
}

func (t *receiptTap) setHeaderDigest(header http.Header) {
	digest, err := receiptHeaderDigest(header)
	if err == nil {
		t.headerDigest = &digest
	}
}

func receiptHeaderDigest(header http.Header) ([32]byte, error) {
	return organic.ReceiptHTTPHeaderSHA256(header)
}

func (t *receiptTap) WriteHeader(status int) {
	if t.wroteHeader {
		return
	}
	t.wroteHeader = true
	if status >= 100 && status <= 599 {
		t.leaf.ResponseStatus = uint16(status)
	}
	// Without a Content-Type key the server would sniff one into the
	// response after the digest point; a nil entry suppresses that and
	// adds nothing to the digest or the wire.
	if _, typed := t.Header()["Content-Type"]; !typed {
		t.Header()["Content-Type"] = nil
	}
	if t.headerDigest == nil {
		t.setHeaderDigest(t.Header())
	}
	t.ResponseWriter.WriteHeader(status)
}

func (t *receiptTap) Write(payload []byte) (int, error) {
	if !t.wroteHeader {
		t.WriteHeader(http.StatusOK)
	}
	n, err := t.ResponseWriter.Write(payload)
	t.body.Write(payload[:n])
	t.leaf.ResponseBodyLen += uint64(n)
	if err != nil {
		t.writeFailed = true
	}
	return n, err
}

func (t *receiptTap) Flush() {
	if flusher, ok := t.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (t *receiptTap) Unwrap() http.ResponseWriter { return t.ResponseWriter }

// finish seals the leaf. aborted reports a handler abort (the reverse proxy
// panics with http.ErrAbortHandler when the body copy fails).
func (t *receiptTap) finish(recorder *ReceiptRecorder, aborted bool, now time.Time) error {
	if t.headerDigest != nil {
		t.leaf.ResponseHeaderSHA256 = *t.headerDigest
	} else if digest, err := receiptHeaderDigest(t.Header()); err == nil {
		t.leaf.ResponseHeaderSHA256 = digest
	}
	t.body.Sum(t.leaf.ResponseBodySHA256[:0])
	switch {
	case t.writeFailed:
		t.leaf.Completion = organic.ReceiptCompletionClientGone
	case aborted && t.leaf.ResponseBodyLen >= MaxRuntimeResponseBytes:
		t.leaf.Completion = organic.ReceiptCompletionOverLimit
	case aborted:
		t.leaf.Completion = organic.ReceiptCompletionAbortedByMiner
	default:
		t.leaf.Completion = organic.ReceiptCompletionComplete
	}
	t.leaf.FinishedAtUnixMS = uint64(now.UnixMilli())
	return recorder.Record(t.leaf)
}

type receiptTapKey struct{}

func receiptTapFrom(ctx context.Context) *receiptTap {
	tap, _ := ctx.Value(receiptTapKey{}).(*receiptTap)
	return tap
}
