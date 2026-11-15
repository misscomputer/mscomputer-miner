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
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/organic"
	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func testRecorder(t *testing.T, change func(*ReceiptRecorderConfig)) (*ReceiptRecorder, ed25519.PublicKey, *fakeClock) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := DefaultReceiptRecorderConfig()
	if change != nil {
		change(&policy)
	}
	recorder, err := NewReceiptRecorder(key, policy)
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{now: time.Unix(1_762_000_000, 0)}
	recorder.now = clock.Now
	return recorder, public, clock
}

func testLeaf(clock *fakeClock, id byte) organic.ResponseReceiptLeaf {
	leaf := organic.ResponseReceiptLeaf{
		Kind: organic.ReceiptKindDynamic, EndpointID: "ep-g1-test", Generation: 1, ResponseStatus: 200,
		FinishedAtUnixMS: uint64(clock.Now().UnixMilli()),
	}
	leaf.EdgeRequestID[15] = id
	leaf.RequestDigest = sha256.Sum256([]byte{id})
	return leaf
}

// verifyChain checks every pulled batch: signature, Merkle root, and that
// prev_batch_digest links each batch to its predecessor from sequence 1.
func verifyChain(t *testing.T, public ed25519.PublicKey, batches []organic.ResponseReceiptBatchEnvelope) map[[16]byte]organic.ReceiptIndexedLeaf {
	t.Helper()
	prev := strings.Repeat("0", 64)
	all := map[[16]byte]organic.ReceiptIndexedLeaf{}
	for index, envelope := range batches {
		if envelope.Batch.Sequence != uint64(index+1) || envelope.Batch.PrevBatchDigest != prev {
			t.Fatalf("batch %d breaks the chain", index)
		}
		leaves, err := organic.VerifyResponseReceiptBatchEnvelope(envelope, public)
		if err != nil {
			t.Fatalf("batch %d: %v", index, err)
		}
		for id, leaf := range leaves {
			all[id] = leaf
		}
		prev, err = organic.ResponseReceiptBatchDigest(envelope.Batch)
		if err != nil {
			t.Fatal(err)
		}
	}
	return all
}

func TestReceiptRecorderSealsOneChainedBatchPerFinishedSecond(t *testing.T) {
	recorder, public, clock := testRecorder(t, nil)
	for id := byte(1); id <= 3; id++ {
		if err := recorder.Record(testLeaf(clock, id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := recorder.Seal(false); err != nil {
		t.Fatal(err)
	}
	if got := recorder.batchesAfter(recorder.BootID(), 0).Batches; len(got) != 0 {
		t.Fatal("the current second was sealed early")
	}
	clock.Advance(time.Second)
	if err := recorder.Record(testLeaf(clock, 4)); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Seal(false); err != nil {
		t.Fatal(err)
	}
	clock.Advance(3 * time.Second) // an idle second produces no batch
	if err := recorder.Seal(false); err != nil {
		t.Fatal(err)
	}
	batches := recorder.batchesAfter(recorder.BootID(), 0).Batches
	if len(batches) != 2 || batches[0].Batch.LeafCount != 3 || batches[1].Batch.LeafCount != 1 ||
		batches[1].Batch.WindowStartUnix != batches[0].Batch.WindowStartUnix+1 {
		t.Fatalf("unexpected batches: %+v", batches)
	}
	leaves := verifyChain(t, public, batches)
	for id := byte(1); id <= 4; id++ {
		var key [16]byte
		key[15] = id
		answer, ok := recorder.leaf(key, "ep-g1-test")
		if !ok {
			t.Fatalf("leaf %d not served", id)
		}
		preimage, _ := hex.DecodeString(answer.Preimage)
		decoded, err := organic.DecodeResponseReceiptLeaf(preimage)
		if err != nil || decoded.EdgeRequestID != key {
			t.Fatalf("leaf %d preimage invalid", id)
		}
		proof := make([][32]byte, len(answer.Proof))
		for index, node := range answer.Proof {
			hex.Decode(proof[index][:], []byte(node))
		}
		var root [32]byte
		hex.Decode(root[:], []byte(answer.Batch.MerkleRoot))
		if !organic.VerifyReceiptInclusion(organic.ReceiptLeafHash(preimage), uint64(answer.Index), uint64(answer.Batch.LeafCount), proof, root) ||
			leaves[key].Hash != organic.ReceiptLeafHash(preimage) {
			t.Fatalf("leaf %d proof does not verify", id)
		}
	}
	if after := recorder.batchesAfter(recorder.BootID(), 1).Batches; len(after) != 1 || after[0].Batch.Sequence != 2 {
		t.Fatal("after_sequence not honoured")
	}
	if other := recorder.batchesAfter("ffffffffffffffffffffffffffffffff", 2).Batches; len(other) != 2 {
		t.Fatal("a different boot must restart from sequence 1")
	}
	if err := recorder.Record(testLeaf(clock, 1)); err != errReceiptDuplicate {
		t.Fatalf("duplicate edge request id recorded: %v", err)
	}
}

func TestReceiptRecorderRefusesWhenFullAndExpiresOnlySealedLeaves(t *testing.T) {
	recorder, _, clock := testRecorder(t, func(p *ReceiptRecorderConfig) { p.MaxRetainedLeaves = 2 })
	for id := byte(1); id <= 2; id++ {
		if err := recorder.Admit(); err != nil {
			t.Fatal(err)
		}
		if err := recorder.Record(testLeaf(clock, id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := recorder.Admit(); err != errReceiptRingFull {
		t.Fatalf("full ring admitted a request: %v", err)
	}
	// Unsealed leaves never expire, however old.
	clock.Advance(time.Hour)
	if err := recorder.Admit(); err != errReceiptRingFull {
		t.Fatal("unsealed leaves expired")
	}
	if err := recorder.Seal(false); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Admit(); err != errReceiptRingFull {
		t.Fatal("freshly sealed leaves expired before retention")
	}
	clock.Advance(16 * time.Minute)
	if err := recorder.Admit(); err != nil {
		t.Fatalf("expired leaves still held: %v", err)
	}
	if got := recorder.batchesAfter(recorder.BootID(), 0).Batches; len(got) != 0 {
		t.Fatal("expired batch still served")
	}
}

func TestReceiptRecorderRunFlushesPendingOnShutdown(t *testing.T) {
	recorder, public, clock := testRecorder(t, nil)
	if err := recorder.Record(testLeaf(clock, 9)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { recorder.Run(ctx); close(done) }()
	cancel()
	<-done
	batches := recorder.batchesAfter(recorder.BootID(), 0).Batches
	if len(batches) != 1 {
		t.Fatalf("shutdown left %d batches, want the flushed one", len(batches))
	}
	verifyChain(t, public, batches)
	if err := recorder.Admit(); err == nil {
		t.Fatal("closed recorder admitted a request")
	}
}

func TestReceiptRecorderSplitsOversizedSecond(t *testing.T) {
	recorder, public, clock := testRecorder(t, nil)
	recorder.pending = make([]organic.ResponseReceiptLeaf, 0, organic.MaxResponseReceiptBatchLeaves+1)
	for index := 0; index <= organic.MaxResponseReceiptBatchLeaves; index++ {
		leaf := testLeaf(clock, 0)
		leaf.EdgeRequestID[0], leaf.EdgeRequestID[1], leaf.EdgeRequestID[2] = byte(index>>16), byte(index>>8), byte(index)
		if err := recorder.Record(leaf); err != nil {
			t.Fatal(err)
		}
	}
	if err := recorder.Seal(true); err != nil {
		t.Fatal(err)
	}
	batches := recorder.batchesAfter(recorder.BootID(), 0).Batches
	if len(batches) != 2 || batches[0].Batch.LeafCount != organic.MaxResponseReceiptBatchLeaves || batches[1].Batch.LeafCount != 1 {
		t.Fatalf("oversized second not split: %d batches", len(batches))
	}
	verifyChain(t, public, batches)
}

// receiptIngressFixture is a bound organic endpoint behind the production
// runtime ingress with response receipts on.
type receiptIngressFixture struct {
	container  *httptest.Server
	endpointID string
	validator  ed25519.PrivateKey
	miner      ed25519.PublicKey
	ticket     protocol.TicketV4
	axon       *httptest.Server
	recorder   *ReceiptRecorder
	appPaths   chan string
}

func newReceiptIngressFixture(t *testing.T, receipts bool) *receiptIngressFixture {
	t.Helper()
	appPaths := make(chan string, 64)
	serving := new(atomic.Bool)
	container := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !serving.Load() {
			w.WriteHeader(http.StatusOK)
			return
		}
		appPaths <- req.URL.Path
		w.Header().Set("X-App", "1")
		w.Header().Set("X-Ms-Spoof", "dropped")
		switch req.URL.Path {
		case "/big":
			w.Header().Set("Content-Type", "application/octet-stream")
			chunk := strings.Repeat("z", 32<<10)
			for index := 0; index < 8; index++ {
				_, _ = io.WriteString(w, chunk)
				w.(http.Flusher).Flush()
			}
		case "/abort":
			_, _ = io.WriteString(w, "partial")
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		case "/huge":
			chunk := strings.Repeat("h", 1<<20)
			for index := 0; index <= MaxRuntimeResponseBytes>>20; index++ {
				if _, err := io.WriteString(w, chunk); err != nil {
					return
				}
			}
		case "/untyped":
			// No Content-Type: the agent's own server must not sniff one in
			// after the receipt header digest point.
			w.Header()["Content-Type"] = nil
			_, _ = io.WriteString(w, "<html>untyped</html>")
		case "/committed":
			w.Header().Set("Content-Type", "text/plain;\t charset=utf-8")
			w.Header().Set("Content-Language", "en")
			w.Header().Add("Set-Cookie", "sid=1; Path=/")
			w.Header().Set("Etag", `"v1"`)
			_, _ = io.WriteString(w, "committed")
		case "/teapot":
			w.WriteHeader(http.StatusTeapot)
			_, _ = io.WriteString(w, "short")
		default:
			_, _ = io.WriteString(w, "hello "+req.URL.Path)
		}
	}))
	t.Cleanup(container.Close)
	h := newOrganicHarness(t, container.URL)
	h.agent.HTTPClient = container.Client()
	axon := httptest.NewServer(h.agent.RuntimeIngressHandler("/runtime/"))
	t.Cleanup(axon.Close)
	h.agent.MinerTransport, h.agent.MinerTLSCertificateSHA256 = "http", ""
	ticket := h.ticket(t, strings.Repeat("e", 32), func(ticket *protocol.TicketV4) {
		ticket.Subnet.MinerAxonURL, ticket.Subnet.MinerTransport, ticket.Subnet.MinerTLSCertificateSHA256 = axon.URL, "http", nil
	})
	result, err := h.assign(ticket)
	if err != nil {
		t.Fatalf("organic assignment: %v", err)
	}
	fixture := &receiptIngressFixture{
		container:  container,
		endpointID: result.EndpointID, validator: h.validatorKey, miner: h.minerKey.Public().(ed25519.PublicKey),
		ticket: ticket, axon: axon, appPaths: appPaths,
	}
	if receipts {
		fixture.recorder, err = NewReceiptRecorder(h.minerKey, DefaultReceiptRecorderConfig())
		if err != nil {
			t.Fatal(err)
		}
		h.agent.Receipts = fixture.recorder
	}
	serving.Store(true)
	return fixture
}

// edgeCall is what an edge observes for one forwarded request: everything
// it needs to recompute the miner's leaf.
type edgeCall struct {
	request organic.EdgeRuntimeRequest
	status  int
	header  http.Header
	body    []byte
}

func (f *receiptIngressFixture) call(t *testing.T, method, path, query string) edgeCall {
	t.Helper()
	return f.do(t, method, path, query, "", false)
}

// pullCall is a receipt pull: the edge request plus its pull signature.
func (f *receiptIngressFixture) pullCall(t *testing.T, path, query string) edgeCall {
	t.Helper()
	return f.do(t, http.MethodGet, path, query, "valid", false)
}

// do sends one edge-signed request. pull is "", "valid" or "forged";
// partial tolerates a body cut short by the miner.
func (f *receiptIngressFixture) do(t *testing.T, method, path, query, pull string, partial bool) edgeCall {
	t.Helper()
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	empty := sha256.Sum256(nil)
	request := organic.EdgeRuntimeRequest{
		BodySHA256: hex.EncodeToString(empty[:]), EndpointID: f.endpointID, Method: method,
		Nonce: hex.EncodeToString(nonce), Path: path, Query: query, Timestamp: time.Now().UnixNano(),
	}
	header, err := organic.SignEdgeRuntimeRequest(request, f.validator)
	if err != nil {
		t.Fatal(err)
	}
	target := f.axon.URL + "/runtime/" + f.endpointID + path
	if query != "" {
		target += "?" + query
	}
	req, _ := http.NewRequest(method, target, nil)
	req.Header.Set(EdgeAuthorizationHeader, header)
	switch pull {
	case "valid", "forged":
		signer := f.validator
		if pull == "forged" {
			_, signer, _ = ed25519.GenerateKey(rand.Reader)
		}
		signature, err := organic.SignReceiptPull(request, signer)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(organic.ReceiptPullAuthorizationHeader, signature)
	}
	resp, err := f.axon.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil && !partial {
		t.Fatal(err)
	}
	if f.recorder != nil {
		waitLeavesRecorded(t, f.recorder)
	}
	return edgeCall{request: request, status: resp.StatusCode, header: resp.Header, body: body}
}

// edgeLeafHash recomputes the leaf from the edge's own observations: the
// header digest covers the end-to-end headers exactly as received, the
// point at which the edge must digest before it mutates any header.
func (f *receiptIngressFixture) edgeLeafHash(t *testing.T, call edgeCall, finishedAt uint64) [32]byte {
	t.Helper()
	return f.edgeLeafHashCompletion(t, call, finishedAt, organic.ReceiptCompletionComplete)
}

func (f *receiptIngressFixture) edgeLeafHashCompletion(t *testing.T, call edgeCall, finishedAt uint64, completion uint8) [32]byte {
	t.Helper()
	ticketDigest, err := protocol.TicketDigestV4(f.ticket)
	if err != nil {
		t.Fatal(err)
	}
	leaf := organic.ResponseReceiptLeaf{
		Kind: organic.ReceiptKindDynamic, EndpointID: f.endpointID, Generation: f.ticket.Generation,
		ResponseStatus: uint16(call.status), ResponseBodyLen: uint64(len(call.body)),
		ResponseBodySHA256: sha256.Sum256(call.body), FinishedAtUnixMS: finishedAt, Completion: completion,
	}
	if leaf.TicketDigest, err = organic.ReceiptTicketDigest(ticketDigest); err != nil {
		t.Fatal(err)
	}
	hex.Decode(leaf.EdgeRequestID[:], []byte(call.request.Nonce))
	if leaf.RequestDigest, err = organic.ReceiptRequestDigest(call.request); err != nil {
		t.Fatal(err)
	}
	if leaf.ResponseHeaderSHA256, err = receiptHeaderDigest(call.header); err != nil {
		t.Fatal(err)
	}
	hash, err := leaf.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func (f *receiptIngressFixture) pull(t *testing.T, boot string, after uint64) (int, receiptBatchesResponse) {
	t.Helper()
	call := f.pullCall(t, ReceiptsPathPrefix+"batches", "after_sequence="+strconv.FormatUint(after, 10)+"&boot="+boot)
	var answer receiptBatchesResponse
	if call.status == http.StatusOK {
		if err := json.Unmarshal(call.body, &answer); err != nil {
			t.Fatal(err)
		}
	}
	return call.status, answer
}

func TestRuntimeIngressRecordsAReceiptTheEdgeCanRecompute(t *testing.T) {
	f := newReceiptIngressFixture(t, true)
	calls := []edgeCall{
		f.call(t, http.MethodGet, "/a", ""),
		f.call(t, http.MethodGet, "/big", "x=1"),
		f.call(t, http.MethodHead, "/a", ""),
		f.call(t, http.MethodGet, "/teapot", ""),
	}
	if calls[3].status != http.StatusTeapot || len(calls[1].body) != 8*(32<<10) {
		t.Fatalf("fixture responses unexpected: %d %q %d %d", calls[0].status, calls[0].body, calls[3].status, len(calls[1].body))
	}
	if err := f.recorder.Seal(true); err != nil {
		t.Fatal(err)
	}
	status, answer := f.pull(t, "", 0)
	if status != http.StatusOK || answer.AgentBootID != f.recorder.BootID() {
		t.Fatalf("pull returned %d", status)
	}
	leaves := verifyChain(t, f.miner, answer.Batches)
	if len(leaves) != len(calls) {
		t.Fatalf("got %d leaves for %d responses (receipt pulls must not be receipted)", len(leaves), len(calls))
	}
	for _, call := range calls {
		var id [16]byte
		hex.Decode(id[:], []byte(call.request.Nonce))
		served, ok := f.recorder.leaf(id, f.endpointID)
		if !ok {
			t.Fatalf("no leaf for %s", call.request.Path)
		}
		preimage, _ := hex.DecodeString(served.Preimage)
		minerLeaf, err := organic.DecodeResponseReceiptLeaf(preimage)
		if err != nil {
			t.Fatal(err)
		}
		if minerLeaf.Completion != organic.ReceiptCompletionComplete {
			t.Fatalf("%s completion %d", call.request.Path, minerLeaf.Completion)
		}
		// The edge takes finished_at from the batch entry; everything else
		// it recomputes from its own observation.
		if minerLeaf.FinishedAtUnixMS != leaves[id].FinishedAtUnixMS {
			t.Fatal("entry finished_at differs from the leaf preimage")
		}
		if f.edgeLeafHash(t, call, leaves[id].FinishedAtUnixMS) != leaves[id].Hash {
			t.Fatalf("%s: edge-recomputed leaf differs from the miner's", call.request.Path)
		}
	}
	// A tampered observation never matches.
	tampered := calls[0]
	tampered.body = append([]byte(nil), tampered.body...)
	tampered.body[0] ^= 1
	var id [16]byte
	hex.Decode(id[:], []byte(tampered.request.Nonce))
	served, _ := f.recorder.leaf(id, f.endpointID)
	preimage, _ := hex.DecodeString(served.Preimage)
	minerLeaf, _ := organic.DecodeResponseReceiptLeaf(preimage)
	if f.edgeLeafHash(t, tampered, minerLeaf.FinishedAtUnixMS) == leaves[id].Hash {
		t.Fatal("tampered body still matched")
	}
	// Receipt routes are answered by the agent, never by the application.
	for len(f.appPaths) > 0 {
		if path := <-f.appPaths; strings.HasPrefix(path, ReceiptsPathPrefix) {
			t.Fatalf("receipt route reached the application: %s", path)
		}
	}
	leafCall := f.pullCall(t, ReceiptsPathPrefix+"leaf/"+calls[0].request.Nonce, "")
	if leafCall.status != http.StatusOK || !strings.Contains(string(leafCall.body), served.Preimage[:64]) {
		t.Fatalf("leaf route returned %d", leafCall.status)
	}
	if missing := f.pullCall(t, ReceiptsPathPrefix+"leaf/"+strings.Repeat("0", 32), ""); missing.status != http.StatusNotFound {
		t.Fatalf("unknown leaf returned %d", missing.status)
	}
	if bad := f.pullCall(t, ReceiptsPathPrefix+"leaf/XYZ", ""); bad.status != http.StatusBadRequest {
		t.Fatalf("malformed leaf id returned %d", bad.status)
	}
	if post := f.do(t, http.MethodPost, ReceiptsPathPrefix+"batches", "", "valid", false); post.status != http.StatusMethodNotAllowed {
		t.Fatalf("POST to receipts returned %d", post.status)
	}
}

func TestReceiptRoutesRequireEdgeAuthorization(t *testing.T) {
	f := newReceiptIngressFixture(t, true)
	resp, err := f.axon.Client().Get(f.axon.URL + "/runtime/" + f.endpointID + ReceiptsPathPrefix + "batches")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned receipt pull returned %d", resp.StatusCode)
	}
}

func TestReceiptsOffLeavesTheRuntimePathUnchanged(t *testing.T) {
	f := newReceiptIngressFixture(t, false)
	call := f.call(t, http.MethodGet, ReceiptsPathPrefix+"batches", "")
	if call.status != http.StatusOK || string(call.body) != "hello "+ReceiptsPathPrefix+"batches" {
		t.Fatalf("with receipts off the path must reach the application, got %d %q", call.status, call.body)
	}
}

func TestReceiptRingFullAnswers503WithoutContactingTheApp(t *testing.T) {
	f := newReceiptIngressFixture(t, true)
	f.recorder.policy.MaxRetainedLeaves = 1
	if first := f.call(t, http.MethodGet, "/a", ""); first.status != http.StatusOK {
		t.Fatal(first.status)
	}
	<-f.appPaths
	if second := f.call(t, http.MethodGet, "/a", ""); second.status != http.StatusServiceUnavailable {
		t.Fatalf("full ring returned %d", second.status)
	}
	if len(f.appPaths) != 0 {
		t.Fatal("application contacted while the ring was full")
	}
}

// waitLeavesRecorded waits until every admitted response has recorded its
// leaf. The agent records a leaf after its handler returns, which can be
// after the edge has read the whole response; a seal in between would
// leave that leaf for the next batch.
func waitLeavesRecorded(t *testing.T, recorder *ReceiptRecorder) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		recorder.mu.Lock()
		reserved := recorder.reserved
		recorder.mu.Unlock()
		if reserved == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d admitted responses never recorded a leaf", reserved)
		}
		time.Sleep(time.Millisecond)
	}
}

// minerLeaf returns the decoded leaf the miner recorded for one call.
func (f *receiptIngressFixture) minerLeaf(t *testing.T, call edgeCall) (organic.ResponseReceiptLeaf, [32]byte) {
	t.Helper()
	if err := f.recorder.Seal(true); err != nil {
		t.Fatal(err)
	}
	var id [16]byte
	hex.Decode(id[:], []byte(call.request.Nonce))
	served, ok := f.recorder.leaf(id, f.endpointID)
	if !ok {
		t.Fatalf("no leaf for %s", call.request.Path)
	}
	preimage, _ := hex.DecodeString(served.Preimage)
	leaf, err := organic.DecodeResponseReceiptLeaf(preimage)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, organic.ReceiptLeafHash(preimage)
}

func TestReceiptPullRequiresItsOwnSignatureAndNeverShadowsTheApp(t *testing.T) {
	f := newReceiptIngressFixture(t, true)
	// An ordinary (customer-shaped) edge request to the receipt path is
	// forwarded to the application and receipted like any other.
	customer := f.call(t, http.MethodGet, ReceiptsPathPrefix+"batches", "")
	if customer.status != http.StatusOK || string(customer.body) != "hello "+ReceiptsPathPrefix+"batches" {
		t.Fatalf("customer request to the receipt path: %d %q", customer.status, customer.body)
	}
	<-f.appPaths
	if leaf, hash := f.minerLeaf(t, customer); f.edgeLeafHash(t, customer, leaf.FinishedAtUnixMS) != hash {
		t.Fatal("customer request to the receipt path was not receipted")
	}
	if forged := f.do(t, http.MethodGet, ReceiptsPathPrefix+"batches", "", "forged", false); forged.status != http.StatusUnauthorized {
		t.Fatalf("forged pull signature returned %d", forged.status)
	}
	if other := f.pullCall(t, "/a", ""); other.status != http.StatusUnauthorized {
		t.Fatalf("pull signature on an app path returned %d", other.status)
	}
	if len(f.appPaths) != 0 {
		t.Fatal("a rejected pull reached the application")
	}
	// A leaf preimage is served only to a pull for its own endpoint.
	var id [16]byte
	hex.Decode(id[:], []byte(customer.request.Nonce))
	if _, ok := f.recorder.leaf(id, f.endpointID+"x"); ok {
		t.Fatal("leaf served for another endpoint")
	}
}

func TestReceiptTapRecordsAbortsOverLimitAndAgentErrors(t *testing.T) {
	f := newReceiptIngressFixture(t, true)
	aborted := f.do(t, http.MethodGet, "/abort", "", "", true)
	leaf, hash := f.minerLeaf(t, aborted)
	if leaf.Completion != organic.ReceiptCompletionAbortedByMiner {
		t.Fatalf("aborted response completion %d", leaf.Completion)
	}
	if f.edgeLeafHashCompletion(t, aborted, leaf.FinishedAtUnixMS, organic.ReceiptCompletionAbortedByMiner) != hash {
		t.Fatal("edge cannot recompute the aborted leaf from what it received")
	}
	huge := f.do(t, http.MethodGet, "/huge", "", "", true)
	leaf, hash = f.minerLeaf(t, huge)
	if leaf.Completion != organic.ReceiptCompletionOverLimit || leaf.ResponseBodyLen != MaxRuntimeResponseBytes {
		t.Fatalf("over-limit completion %d len %d", leaf.Completion, leaf.ResponseBodyLen)
	}
	if f.edgeLeafHashCompletion(t, huge, leaf.FinishedAtUnixMS, organic.ReceiptCompletionOverLimit) != hash {
		t.Fatal("edge cannot recompute the over-limit leaf")
	}
	// With the application gone the agent answers its own 502; the edge
	// still recomputes that leaf, server-added headers included.
	f.container.Close()
	down := f.call(t, http.MethodGet, "/a", "")
	leaf, hash = f.minerLeaf(t, down)
	if down.status != http.StatusBadGateway || leaf.ResponseStatus != http.StatusBadGateway ||
		f.edgeLeafHash(t, down, leaf.FinishedAtUnixMS) != hash {
		t.Fatalf("agent 502 leaf not recomputable: status %d", down.status)
	}
}

func TestCheckHeaderResponseIsAnOrdinaryReceiptedResponse(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("organic-ready"))
	}))
	defer app.Close()
	h := newOrganicHarness(t, app.URL)
	h.agent.HTTPClient = app.Client()
	ticket := h.ticket(t, strings.Repeat("e", 32), nil)
	if _, err := h.assign(ticket); err != nil {
		t.Fatal(err)
	}
	recorder, err := NewReceiptRecorder(h.minerKey, DefaultReceiptRecorderConfig())
	if err != nil {
		t.Fatal(err)
	}
	h.agent.Receipts = recorder
	endpointID := protocol.EndpointIDV4(ticket)
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	authorization := reservedCheck{EndpointID: endpointID, Method: "GET", Path: "/", Nonce: hex.EncodeToString(nonce)}
	check := edgeRequest{method: http.MethodGet, path: "/", check: checkHeader(t, authorization)}
	header := signEdge(t, h.validatorKey, endpointID, check, time.Now())
	req := httptest.NewRequest(http.MethodGet, "/api/", nil)
	req.URL.Path, req.URL.RawPath = "/", "/"
	req.Header.Set(organic.EdgeAuthorizationHeader, header)
	req.Header.Set(reservedCheckHeader, check.check)
	response := httptest.NewRecorder()
	h.agent.ProxyRuntime(response, req, endpointID)
	if response.Code != http.StatusOK || response.Header().Get(reservedAnswerHeader) != "" {
		t.Fatalf("check header changed serving: %d %v", response.Code, response.Header())
	}
	parsed, err := organic.ParseEdgeAuthorization(header)
	if err != nil {
		t.Fatal(err)
	}
	if err := recorder.Seal(true); err != nil {
		t.Fatal(err)
	}
	var id [16]byte
	hex.Decode(id[:], []byte(parsed.Nonce))
	served, ok := recorder.leaf(id, endpointID)
	if !ok {
		t.Fatal("check response has no receipt")
	}
	preimage, _ := hex.DecodeString(served.Preimage)
	leaf, err := organic.DecodeResponseReceiptLeaf(preimage)
	if err != nil {
		t.Fatal(err)
	}
	var pairs [][2]string
	for name, values := range response.Header() {
		for _, value := range values {
			pairs = append(pairs, [2]string{name, value})
		}
	}
	received, _ := organic.ReceiptHeaderSHA256(pairs)
	bodySum := sha256.Sum256(response.Body.Bytes())
	if leaf.ResponseBodySHA256 != bodySum || int(leaf.ResponseStatus) != response.Code ||
		leaf.ResponseHeaderSHA256 != received || leaf.Completion != organic.ReceiptCompletionComplete {
		t.Fatal("receipt does not commit to the response as received")
	}
}

func TestReceiptHeaderDigestHoldsForResponsesWithoutContentType(t *testing.T) {
	f := newReceiptIngressFixture(t, true)
	untyped := f.call(t, http.MethodGet, "/untyped", "")
	if untyped.status != http.StatusOK || string(untyped.body) != "<html>untyped</html>" {
		t.Fatalf("untyped response %d %q", untyped.status, untyped.body)
	}
	leaf, hash := f.minerLeaf(t, untyped)
	if f.edgeLeafHash(t, untyped, leaf.FinishedAtUnixMS) != hash {
		t.Fatalf("edge-recomputed leaf differs for a response without Content-Type (received %q)", untyped.header.Get("Content-Type"))
	}
}

// TestReceiptTapStopsContentTypeSniffing drives the tap directly on a real
// server without the proxy's early flush: Go's server would otherwise sniff
// a Content-Type into the response after the digest point.
func TestReceiptTapStopsContentTypeSniffing(t *testing.T) {
	recorder, _, _ := testRecorder(t, nil)
	leaves := make(chan organic.ResponseReceiptLeaf, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := recorder.Admit(); err != nil {
			t.Error(err)
		}
		tap := newReceiptTap(w, testLeaf(&fakeClock{now: time.Unix(1_762_000_000, 0)}, 1))
		_, _ = io.WriteString(tap, "<html>untyped</html>")
		_ = tap.finish(recorder, false, time.Unix(1_762_000_000, 0))
		leaves <- tap.leaf
	}))
	defer server.Close()
	resp, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	leaf := <-leaves
	received, err := receiptHeaderDigest(resp.Header)
	if err != nil {
		t.Fatal(err)
	}
	if received != leaf.ResponseHeaderSHA256 {
		t.Fatalf("server added headers after the digest point: %v", resp.Header)
	}
}

// TestReceiptLeafSurvivesACDNTunnelFront puts a stand-in for the
// CDN tunnel front between the agent and the edge: it adds its own
// headers and cookies, weakens the ETag and collapses value whitespace. The
// edge-recomputed leaf must still equal the agent's, and a front that
// changes the status, the body or a committed header must not.
func TestReceiptLeafSurvivesACDNTunnelFront(t *testing.T) {
	f := newReceiptIngressFixture(t, true)
	target, err := url.Parse(f.axon.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(target) },
		ModifyResponse: func(response *http.Response) error {
			h := response.Header
			h.Set("Cf-Ray", "8e0f1a2b3c4d5e6f-FRA")
			h.Set("Cf-Cache-Status", "DYNAMIC")
			h.Set("Server", "cdn-front")
			h.Add("Vary", "Accept-Encoding")
			h.Set("Nel", `{"max_age":604800}`)
			h.Add("Set-Cookie", "__cf_bm=abc; path=/; HttpOnly")
			if etag := h.Get("Etag"); etag != "" {
				h.Set("Etag", "W/"+etag)
			}
			if typ := h.Get("Content-Type"); typ != "" {
				h.Set("Content-Type", strings.Join(strings.Fields(typ), " "))
			}
			switch response.Request.URL.Query().Get("tamper") {
			case "status":
				response.StatusCode = http.StatusAccepted
			case "body":
				response.Body = io.NopCloser(strings.NewReader("tampered"))
				response.ContentLength = -1
				h.Del("Content-Length")
			case "type":
				h.Set("Content-Type", "text/html")
			case "cookie":
				h.Add("Set-Cookie", "session=attacker")
			}
			return nil
		},
	}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// the tunnel connector relays the origin's headers over its own framing;
		// unlike this net/http stand-in it never sniffs a Content-Type in.
		w.Header()["Content-Type"] = nil
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	f.axon = front

	for _, path := range []string{"/committed", "/a", "/untyped", "/teapot"} {
		call := f.call(t, http.MethodGet, path, "")
		if call.header.Get("Cf-Ray") == "" {
			t.Fatalf("%s did not pass the front", path)
		}
		leaf, hash := f.minerLeaf(t, call)
		if f.edgeLeafHash(t, call, leaf.FinishedAtUnixMS) != hash {
			t.Fatalf("%s: honest leaf mismatched behind the tunnel front: %v", path, call.header)
		}
	}
	for _, tamper := range []string{"status", "body", "type", "cookie"} {
		call := f.call(t, http.MethodGet, "/committed", "tamper="+tamper)
		leaf, hash := f.minerLeaf(t, call)
		if f.edgeLeafHash(t, call, leaf.FinishedAtUnixMS) == hash {
			t.Fatalf("front tampering with %s still matched the miner's leaf", tamper)
		}
	}
}
