// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/organic"
	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
)

// staticReceiptCall sends one edge-signed request to a static endpoint and
// keeps the signed request so the test can recompute the edge's leaf.
func staticReceiptCall(t *testing.T, h *staticHarness, endpointID, method, path, check, pull string) (organic.EdgeRuntimeRequest, *httptest.ResponseRecorder) {
	t.Helper()
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	empty := sha256.Sum256(nil)
	target, query, _ := strings.Cut(path, "?")
	request := organic.EdgeRuntimeRequest{
		BodySHA256: hex.EncodeToString(empty[:]), EndpointID: endpointID, Method: method,
		Nonce: hex.EncodeToString(nonce), Path: target, Query: query, Timestamp: time.Now().UnixNano(),
	}
	header, err := organic.SignEdgeRuntimeRequest(request, h.validatorKey)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, "/v1/runtime/"+endpointID+path, nil)
	req.Header.Set(organic.EdgeAuthorizationHeader, header)
	if check != "" {
		req.Header.Set(reservedCheckHeader, check)
	}
	if pull != "" {
		signature, err := organic.SignReceiptPull(request, h.validatorKey)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(organic.ReceiptPullAuthorizationHeader, signature)
	}
	recorder := httptest.NewRecorder()
	h.agent.RuntimeIngressHandler("/v1/runtime/").ServeHTTP(recorder, req)
	return request, recorder
}

func newStaticReceiptHarness(t *testing.T) (*staticHarness, protocol.StaticTicketV1, string) {
	t.Helper()
	h := newStaticHarness(t, nil)
	recorder, err := NewReceiptRecorder(h.minerKey, DefaultReceiptRecorderConfig())
	if err != nil {
		t.Fatal(err)
	}
	h.agent.Receipts = recorder
	ticket := h.staticTicket(t, nonceHex(t), nil)
	result, err := h.assignStatic(ticket)
	if err != nil {
		t.Fatal(err)
	}
	return h, ticket, result.EndpointID
}

// Every static response the edge forwards gets a static-site leaf the edge
// recomputes from its own observation, checks included; the receipt pull
// is answered on a static endpoint and is itself never receipted.
func TestStaticResponsesRecordLeavesTheEdgeCanRecompute(t *testing.T) {
	h, ticket, endpointID := newStaticReceiptHarness(t)
	authorization := reservedCheck{EndpointID: endpointID, Method: "GET", Path: "/app.js", Nonce: nonceHex(t) + nonceHex(t)}
	type sent struct {
		request organic.EdgeRuntimeRequest
		answer  *httptest.ResponseRecorder
	}
	var calls []sent
	for _, c := range []struct{ method, path, check string }{
		{http.MethodGet, "/docs/", ""},
		{http.MethodHead, "/index.html", ""},
		{http.MethodGet, "/missing?x=1", ""},
		{http.MethodGet, "/app.js", checkHeader(t, authorization)},
	} {
		request, answer := staticReceiptCall(t, h, endpointID, c.method, c.path, c.check, "")
		calls = append(calls, sent{request, answer})
	}
	if calls[0].answer.Code != http.StatusOK || calls[3].answer.Code != http.StatusOK || calls[3].answer.Header().Get(reservedAnswerHeader) != "" {
		t.Fatalf("fixture responses unexpected: %d %v", calls[0].answer.Code, calls[3].answer.Header())
	}
	if err := h.agent.Receipts.Seal(true); err != nil {
		t.Fatal(err)
	}
	_, pulled := staticReceiptCall(t, h, endpointID, http.MethodGet, ReceiptsPathPrefix+"batches?after_sequence=0&boot="+h.agent.Receipts.BootID(), "", "valid")
	var answer receiptBatchesResponse
	if pulled.Code != http.StatusOK || json.Unmarshal(pulled.Body.Bytes(), &answer) != nil {
		t.Fatalf("static pull returned %d %q", pulled.Code, pulled.Body.String())
	}
	leaves := verifyChain(t, h.minerKey.Public().(ed25519.PublicKey), answer.Batches)
	if len(leaves) != len(calls) {
		t.Fatalf("got %d leaves for %d static responses", len(leaves), len(calls))
	}
	ticketDigest, err := protocol.StaticTicketDigestV1(ticket)
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range calls {
		var id [16]byte
		hex.Decode(id[:], []byte(call.request.Nonce))
		indexed, ok := leaves[id]
		if !ok {
			t.Fatalf("no leaf for %s %s", call.request.Method, call.request.Path)
		}
		body := call.answer.Body.Bytes()
		leaf := organic.ResponseReceiptLeaf{
			Kind: organic.ReceiptKindStatic, EndpointID: endpointID, Generation: ticket.Generation, EdgeRequestID: id,
			ResponseStatus: uint16(call.answer.Code), ResponseBodyLen: uint64(len(body)), ResponseBodySHA256: sha256.Sum256(body),
			Completion: organic.ReceiptCompletionComplete, FinishedAtUnixMS: indexed.FinishedAtUnixMS,
		}
		if leaf.TicketDigest, err = organic.ReceiptTicketDigest(ticketDigest); err != nil {
			t.Fatal(err)
		}
		if leaf.RequestDigest, err = organic.ReceiptRequestDigest(call.request); err != nil {
			t.Fatal(err)
		}
		if leaf.ResponseHeaderSHA256, err = receiptHeaderDigest(call.answer.Header()); err != nil {
			t.Fatal(err)
		}
		hash, err := leaf.Hash()
		if err != nil {
			t.Fatal(err)
		}
		if hash != indexed.Hash {
			t.Fatalf("%s %s: edge-recomputed static leaf differs from the miner's", call.request.Method, call.request.Path)
		}
	}
	// The leaf route on a static endpoint serves the preimage.
	_, leafCall := staticReceiptCall(t, h, endpointID, http.MethodGet, ReceiptsPathPrefix+"leaf/"+calls[0].request.Nonce, "", "valid")
	if leafCall.Code != http.StatusOK {
		t.Fatalf("static leaf route returned %d", leafCall.Code)
	}
}

// A request refused because every serving slot is busy is availability,
// not a response: it gets no leaf and holds no receipt reservation.
func TestStaticSlotsFullAnswersWithoutALeaf(t *testing.T) {
	h, _, endpointID := newStaticReceiptHarness(t)
	endpoint := h.agent.Static.lookup(endpointID)
	for len(endpoint.slots) < cap(endpoint.slots) {
		endpoint.slots <- struct{}{}
	}
	_, answer := staticReceiptCall(t, h, endpointID, http.MethodGet, "/docs/", "", "")
	if answer.Code != http.StatusServiceUnavailable {
		t.Fatalf("slots-full request answered %d", answer.Code)
	}
	if err := h.agent.Receipts.Seal(true); err != nil {
		t.Fatal(err)
	}
	if batches := h.agent.Receipts.batchesAfter(h.agent.Receipts.BootID(), 0).Batches; len(batches) != 0 || h.agent.Receipts.reserved != 0 {
		t.Fatalf("slots-full request left %d batches and %d reservations", len(batches), h.agent.Receipts.reserved)
	}
}

// With receipts off a static endpoint ignores the pull header: the pull
// path is an ordinary (here unknown) site path.
func TestStaticReceiptsOffServesThePullPathAsASitePath(t *testing.T) {
	h := newStaticHarness(t, nil)
	result, err := h.assignStatic(h.staticTicket(t, nonceHex(t), nil))
	if err != nil {
		t.Fatal(err)
	}
	_, answer := staticReceiptCall(t, h, result.EndpointID, http.MethodGet, ReceiptsPathPrefix+"batches", "", "valid")
	if answer.Code != http.StatusNotFound || strings.Contains(answer.Body.String(), "agent_boot_id") {
		t.Fatalf("receipts-off static pull answered %d %q", answer.Code, answer.Body.String())
	}
}

// R7: shutdown counts every leaf the edge can no longer pull: admitted
// responses still running, and leaves in batches past the edge's last
// acknowledged sequence. Batches the edge acknowledged are not lost.
func TestReceiptRecorderCountsShutdownLeafLoss(t *testing.T) {
	recorder, _, clock := testRecorder(t, nil)
	for id := byte(1); id <= 2; id++ {
		if err := recorder.Record(testLeaf(clock, id)); err != nil {
			t.Fatal(err)
		}
	}
	clock.Advance(2 * time.Second)
	if err := recorder.Seal(false); err != nil {
		t.Fatal(err)
	}
	for id := byte(3); id <= 5; id++ {
		if err := recorder.Record(testLeaf(clock, id)); err != nil {
			t.Fatal(err)
		}
	}
	clock.Advance(2 * time.Second)
	if err := recorder.Seal(false); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record(testLeaf(clock, 6)); err != nil {
		t.Fatal(err)
	}
	// Two responses are still running when the flush gives up.
	for range 2 {
		if err := recorder.Admit(); err != nil {
			t.Fatal(err)
		}
	}
	// A pull for another boot or beyond the chain acknowledges nothing.
	recorder.batchesAfter("other", 2)
	recorder.batchesAfter(recorder.BootID(), 1)
	if _, ok := recorder.ShutdownLoss(); ok {
		t.Fatal("loss reported while running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { recorder.Run(ctx); close(done) }()
	cancel()
	<-done
	loss, ok := recorder.ShutdownLoss()
	want := ReceiptShutdownLoss{InFlight: 2, Unpulled: 4, UnpulledBatches: 2, PulledThrough: 1, Sequence: 3}
	if !ok || loss != want || loss.Lost() != 6 {
		t.Fatalf("shutdown loss %+v, want %+v", loss, want)
	}
	// A late finisher is refused; the count already holds it.
	if err := recorder.Record(testLeaf(clock, 7)); err == nil {
		t.Fatal("closed recorder recorded a leaf")
	}
	if after, _ := recorder.ShutdownLoss(); after != want {
		t.Fatalf("loss changed after close: %+v", after)
	}
}

// An edge claiming more than the chain holds cannot hide loss.
func TestReceiptPulledThroughNeverPassesTheChain(t *testing.T) {
	recorder, _, clock := testRecorder(t, nil)
	if err := recorder.Record(testLeaf(clock, 1)); err != nil {
		t.Fatal(err)
	}
	recorder.batchesAfter(recorder.BootID(), 99)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	recorder.Run(ctx)
	loss, _ := recorder.ShutdownLoss()
	if loss.PulledThrough != 0 || loss.Unpulled != 1 || loss.Lost() != 1 {
		t.Fatalf("over-claimed pull hid loss: %+v", loss)
	}
}

// A static body found corrupt after its headers went out aborts the
// response; the leaf still records it, as aborted by the miner, and the
// abort continues to the server.
func TestStaticBodyCorruptAfterHeadersRecordsAnAbortedLeaf(t *testing.T) {
	h, _, endpointID := newStaticReceiptHarness(t)
	path := filepath.Join(h.cacheRoot, "mscomputer-static-v1", "blobs", bodySHA(staticBodies["/app.js"]))
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.ToUpper(staticBodies["/app.js"]), 0o600); err != nil {
		t.Fatal(err)
	}
	var aborted any
	func() {
		defer func() { aborted = recover() }()
		staticReceiptCall(t, h, endpointID, http.MethodGet, "/app.js", "", "")
	}()
	if aborted != http.ErrAbortHandler {
		t.Fatalf("corrupt body did not abort the response: %v", aborted)
	}
	if h.agent.Static.lookup(endpointID) != nil {
		t.Fatal("corrupt endpoint still served")
	}
	if err := h.agent.Receipts.Seal(true); err != nil {
		t.Fatal(err)
	}
	leaves := verifyChain(t, h.minerKey.Public().(ed25519.PublicKey), h.agent.Receipts.batchesAfter(h.agent.Receipts.BootID(), 0).Batches)
	if len(leaves) != 1 {
		t.Fatalf("got %d leaves for one aborted static response", len(leaves))
	}
	var id [16]byte
	for id = range leaves {
	}
	served, ok := h.agent.Receipts.leaf(id, endpointID)
	if !ok {
		t.Fatal("no leaf for the aborted static response")
	}
	preimage, _ := hex.DecodeString(served.Preimage)
	leaf, err := organic.DecodeResponseReceiptLeaf(preimage)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Kind != organic.ReceiptKindStatic || leaf.Completion != organic.ReceiptCompletionAbortedByMiner ||
		leaf.ResponseStatus != http.StatusOK || h.agent.Receipts.reserved != 0 {
		t.Fatalf("aborted static leaf kind %d completion %d status %d, %d reservations",
			leaf.Kind, leaf.Completion, leaf.ResponseStatus, h.agent.Receipts.reserved)
	}
}
