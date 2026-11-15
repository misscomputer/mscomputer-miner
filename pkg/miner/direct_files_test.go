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
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxops"
)

// streamBackend is the ops test backend plus an in-memory streaming helper
// that speaks the real stream protocol: the request line is strictly
// decoded, a write consumes exactly limit body bytes, a read answers the
// size line before its bytes.
type streamBackend struct {
	*opsBackend
	mu      sync.Mutex
	files   map[string][]byte
	streams int
	// gate, when set, blocks each transfer until it is closed.
	gate chan struct{}
}

func (b *streamBackend) StreamHelper(ctx context.Context, instance string, encoded []byte, body io.Reader, sink io.Writer) ([]byte, int64, error) {
	request, err := sandboxops.DecodeRequest(encoded)
	if err != nil || request.Validate() != nil || !sandboxops.StreamOp(request.Op) {
		return nil, 0, fmt.Errorf("lane sent an invalid stream request: %v", err)
	}
	b.mu.Lock()
	b.streams++
	gate := b.gate
	b.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		}
	}
	answer := func(response sandboxops.Response) []byte {
		response.Protocol = sandboxops.Protocol
		line, _ := sandboxops.Encode(response)
		return append(line, '\n')
	}
	fail := func(code string) []byte { return answer(sandboxops.Failure(code)) }
	path := *request.Path
	if request.Op == sandboxops.OpFileStreamWrite {
		data := make([]byte, *request.Limit)
		if _, err := io.ReadFull(body, data); err != nil {
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}
			return fail("stream_short"), 0, nil
		}
		if request.SHA256 != nil {
			sum := sha256.Sum256(data)
			if hex.EncodeToString(sum[:]) != *request.SHA256 {
				return fail("sha256_mismatch"), 0, nil
			}
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		current := b.files[path]
		if uint64(len(current)) != *request.Offset {
			return fail("offset_mismatch"), 0, nil
		}
		b.files[path] = append(current[:len(current):len(current)], data...)
		size := uint64(len(b.files[path]))
		info := sandbox.FileInfo{Type: sandbox.FileTypeFile, Mode: 0o644, Size: size}
		return answer(sandboxops.Response{File: &info}), 0, nil
	}
	b.mu.Lock()
	data, found := b.files[path]
	b.mu.Unlock()
	if !found {
		return fail("path_not_found"), 0, nil
	}
	size := uint64(len(data))
	line := answer(sandboxops.Response{Size: &size})
	if head, ok := sink.(interface{ HelperAnswer([]byte) error }); ok {
		if err := head.HelperAnswer(line); err != nil {
			return nil, 0, err
		}
	}
	if *request.Offset >= size {
		return line, 0, nil
	}
	end := min(size, *request.Offset+*request.Limit)
	n, err := sink.Write(data[*request.Offset:end])
	return line, int64(n), err
}

type directFixture struct {
	*opsFixture
	stream *streamBackend
	nonce  int
}

func newDirectFixture(t *testing.T) *directFixture {
	t.Helper()
	return newDirectFixtureWith(t, DirectFilesConfig{PerSandbox: 1, PerAccount: 1, Global: 2, Grace: time.Minute, LeasePoll: 20 * time.Millisecond})
}

func newDirectFixtureWith(t *testing.T, config DirectFilesConfig) *directFixture {
	t.Helper()
	ops := newOpsFixture(t, testOpsConfig)
	stream := &streamBackend{opsBackend: ops.backend, files: map[string][]byte{}}
	ops.lane.backend = stream
	if err := ops.lane.EnableDirectFiles(config); err != nil {
		t.Fatal(err)
	}
	return &directFixture{opsFixture: ops, stream: stream}
}

func (f *directFixture) grant(op, path string, offset, maxBytes uint64, mutate func(*protocol.SandboxFileGrantV1)) protocol.SandboxFileGrantV1 {
	f.t.Helper()
	digest, err := protocol.SandboxDigestV1(f.lease)
	if err != nil {
		f.t.Fatal(err)
	}
	f.nonce++
	now := f.clock.Now()
	g := protocol.SandboxFileGrantV1{
		Account: fmt.Sprintf("%064x", 7), ExpiresAt: stamp(now.Add(10 * time.Minute)), Generation: f.lease.Generation,
		IssuedAt: stamp(now), LeaseDigest: digest, LeaseID: protocol.SandboxLeaseIDV1(f.lease), MaxBytes: maxBytes,
		MinerID: f.lease.MinerID, Nonce: fmt.Sprintf("%032x", f.nonce), Offset: offset, Op: op, Path: path,
		SandboxID: f.lease.SandboxID, Schema: protocol.SandboxFileGrantSchema, SchemaVersion: 1, Subnet: f.binding(),
	}
	if op == protocol.DirectFileUpload && offset == 0 {
		mode := uint32(0o644)
		g.Mode = &mode
	}
	if mutate != nil {
		mutate(&g)
	}
	if err := protocol.SignSandboxFileGrantV1(&g, f.validator); err != nil {
		f.t.Fatal(err)
	}
	return g
}

func (f *directFixture) upload(g protocol.SandboxFileGrantV1, data []byte) (protocol.SandboxFileReceiptV1, error) {
	return f.lane.DirectFile(context.Background(), DirectFileTransfer{Grant: g, Body: bytes.NewReader(data), Length: uint64(len(data))})
}

func (f *directFixture) download(g protocol.SandboxFileGrantV1, offset, length uint64) ([]byte, uint64, protocol.SandboxFileReceiptV1, error) {
	var out bytes.Buffer
	var announced uint64
	receipt, err := f.lane.DirectFile(context.Background(), DirectFileTransfer{Grant: g, Offset: offset, Length: length, Sink: &out,
		Start: func(_, length uint64) error { announced = length; return nil }})
	return out.Bytes(), announced, receipt, err
}

func directCode(err error) string {
	var direct *DirectFileError
	if errors.As(err, &direct) {
		return direct.Code
	}
	return fmt.Sprint(err)
}

func randomPart(t *testing.T, n int) []byte {
	t.Helper()
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return data
}

// Upload in two granted parts, ranged download, and miner-signed receipts
// that the broker check (SandboxFileReceiptAnswersV1) accepts.
func TestDirectFileUploadPartsAndRangedDownload(t *testing.T) {
	f := newDirectFixture(t)
	first, second := randomPart(t, 3<<20), randomPart(t, 1<<20+7)
	sum := sha256.Sum256(first)
	expected := hex.EncodeToString(sum[:])
	g1 := f.grant(protocol.DirectFileUpload, "/workspace/data.bin", 0, uint64(len(first)), func(g *protocol.SandboxFileGrantV1) { g.ExpectedSHA256 = &expected })
	r1, err := f.upload(g1, first)
	if err != nil {
		t.Fatalf("first part: %v", err)
	}
	minerKey := f.miner.Public().(ed25519.PublicKey)
	if err := protocol.VerifySandboxFileReceiptV1(r1, minerKey); err != nil {
		t.Fatalf("receipt signature: %v", err)
	}
	if err := protocol.SandboxFileReceiptAnswersV1(r1, g1); err != nil || r1.SHA256 != expected || r1.FileSize != uint64(len(first)) {
		t.Fatalf("first receipt %+v: %v", r1, err)
	}
	g2 := f.grant(protocol.DirectFileUpload, "/workspace/data.bin", uint64(len(first)), uint64(len(second)), nil)
	r2, err := f.upload(g2, second)
	if err != nil || protocol.SandboxFileReceiptAnswersV1(r2, g2) != nil || r2.FileSize != uint64(len(first)+len(second)) {
		t.Fatalf("second part %+v: %v", r2, err)
	}
	whole := append(append([]byte{}, first...), second...)
	dg := f.grant(protocol.DirectFileDownload, "/workspace/data.bin", 0, uint64(len(whole)), nil)
	got, announced, rd, err := f.download(dg, 1<<20, 2<<20)
	if err != nil || !bytes.Equal(got, whole[1<<20:3<<20]) || announced != 2<<20 {
		t.Fatalf("ranged download: %d bytes (announced %d) %v", len(got), announced, err)
	}
	gotSum := sha256.Sum256(got)
	if err := protocol.SandboxFileReceiptAnswersV1(rd, dg); err != nil {
		t.Fatalf("ranged receipt does not answer its grant: %v", err)
	}
	if rd.Offset != 1<<20 || rd.Bytes != 2<<20 || rd.SHA256 != hex.EncodeToString(gotSum[:]) || protocol.VerifySandboxFileReceiptV1(rd, minerKey) != nil {
		t.Fatalf("download receipt %+v", rd)
	}
	// Whole-window download past the end returns the tail.
	tail := f.grant(protocol.DirectFileDownload, "/workspace/data.bin", 4<<20, 1<<20, nil)
	got, _, rt, err := f.download(tail, 4<<20, 1<<20)
	if err != nil || !bytes.Equal(got, whole[4<<20:]) || protocol.SandboxFileReceiptAnswersV1(rt, tail) != nil {
		t.Fatalf("tail download: %d bytes %v", len(got), err)
	}
}

func TestDirectFileRefusesInvalidGrants(t *testing.T) {
	f := newDirectFixture(t)
	data := randomPart(t, 1024)
	ok := f.grant(protocol.DirectFileUpload, "/workspace/a", 0, 1024, nil)
	if _, err := f.upload(ok, data); err != nil {
		t.Fatal(err)
	}
	// Single use.
	if _, err := f.upload(ok, data); directCode(err) != "grant_replayed" {
		t.Fatalf("replayed grant: %v", err)
	}
	// Signed by another key (the miner's own).
	forged := f.grant(protocol.DirectFileUpload, "/workspace/a", 0, 1024, nil)
	if err := protocol.SignSandboxFileGrantV1(&forged, f.miner); err != nil {
		t.Fatal(err)
	}
	if _, err := f.upload(forged, data); directCode(err) != "grant_invalid" {
		t.Fatalf("forged grant: %v", err)
	}
	// Tampered after signing.
	tampered := f.grant(protocol.DirectFileUpload, "/workspace/a", 0, 1024, nil)
	tampered.Path = "/workspace/b"
	if _, err := f.upload(tampered, data); directCode(err) != "grant_invalid" {
		t.Fatalf("tampered grant: %v", err)
	}
	// Body length must equal the grant.
	if _, err := f.upload(f.grant(protocol.DirectFileUpload, "/workspace/a", 0, 1025, nil), data); directCode(err) != "length_mismatch" {
		t.Fatalf("short body: %v", err)
	}
	// Download window outside the grant.
	dg := f.grant(protocol.DirectFileDownload, "/workspace/a", 100, 100, nil)
	if _, _, _, err := f.download(dg, 0, 100); directCode(err) != "range_outside_grant" {
		t.Fatalf("range before grant: %v", err)
	}
	if _, _, _, err := f.download(f.grant(protocol.DirectFileDownload, "/workspace/a", 100, 100, nil), 150, 51); directCode(err) != "range_outside_grant" {
		t.Fatalf("range past grant: %v", err)
	}
	// Expired.
	expired := f.grant(protocol.DirectFileUpload, "/workspace/a", 0, 1024, nil)
	f.clock.Add(11 * time.Minute)
	if _, err := f.upload(expired, data); directCode(err) != "grant_invalid" {
		t.Fatalf("expired grant: %v", err)
	}
	f.clock.Add(-11 * time.Minute)
	// Expected digest mismatch is the helper's refusal.
	wrong := fmt.Sprintf("%064x", 1)
	if _, err := f.upload(f.grant(protocol.DirectFileUpload, "/workspace/c", 0, 1024, func(g *protocol.SandboxFileGrantV1) { g.ExpectedSHA256 = &wrong }), data); directCode(err) != "sha256_mismatch" {
		t.Fatalf("digest mismatch: %v", err)
	}
}

// Release is the kill switch: a grant for a released lease is refused, and
// a transfer in flight ends when the lease stops running.
func TestDirectFileEndsWithTheLease(t *testing.T) {
	f := newDirectFixture(t)
	f.stream.gate = make(chan struct{})
	pending := f.grant(protocol.DirectFileUpload, "/workspace/slow", 0, 4, nil)
	result := make(chan error, 1)
	go func() {
		_, err := f.lane.DirectFile(context.Background(), DirectFileTransfer{Grant: pending, Body: bytes.NewReader([]byte("data")), Length: 4})
		result <- err
	}()
	waitFor(t, "transfer started", func() bool { f.stream.mu.Lock(); defer f.stream.mu.Unlock(); return f.stream.streams == 1 })
	// The per-sandbox bound (1) refuses a second concurrent transfer.
	if _, err := f.upload(f.grant(protocol.DirectFileUpload, "/workspace/other", 0, 4, nil), []byte("more")); directCode(err) != "transfer_busy" {
		t.Fatalf("concurrent transfer: %v", err)
	}
	later := f.grant(protocol.DirectFileUpload, "/workspace/later", 0, 4, nil)
	if receipt, err := f.lane.Release(context.Background(), f.release, f.request()); err != nil {
		t.Fatalf("release: %+v %v", receipt, err)
	}
	select {
	case err := <-result:
		if code := directCode(err); code == "" || code == "client_gone" {
			t.Fatalf("in-flight transfer after release: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight transfer survived the release")
	}
	f.stream.gate = nil
	if _, err := f.upload(later, []byte("late")); directCode(err) == "" {
		t.Fatal("grant accepted after release")
	}
}

// A transfer ends mid-stream at its grant's expiry plus the grace, however
// slowly the client trickles; the slot is then free again.
func TestDirectFileEndsAtTheGrantDeadline(t *testing.T) {
	f := newDirectFixtureWith(t, DirectFilesConfig{PerSandbox: 1, PerAccount: 1, Global: 1, Grace: 100 * time.Millisecond, LeasePoll: time.Hour})
	f.stream.gate = make(chan struct{})
	short := f.grant(protocol.DirectFileUpload, "/workspace/slow", 0, 4, func(g *protocol.SandboxFileGrantV1) {
		g.ExpiresAt = stamp(f.clock.Now().Add(200 * time.Millisecond))
	})
	started := time.Now()
	_, err := f.lane.DirectFile(context.Background(), DirectFileTransfer{Grant: short, Body: bytes.NewReader([]byte("data")), Length: 4})
	if directCode(err) != "transfer_deadline" || time.Since(started) > 5*time.Second {
		t.Fatalf("trickling transfer: %v after %v", err, time.Since(started))
	}
	f.stream.gate = nil
	if _, err := f.upload(f.grant(protocol.DirectFileUpload, "/workspace/next", 0, 4, nil), []byte("next")); err != nil {
		t.Fatalf("slot not freed: %v", err)
	}
}

// One tenant account cannot hold more than its share of the miner's slots,
// across all its sandboxes; another account still gets one.
func TestDirectFilePerAccountSlots(t *testing.T) {
	f := newDirectFixtureWith(t, DirectFilesConfig{PerSandbox: 2, PerAccount: 1, Global: 4, Grace: time.Minute, LeasePoll: time.Hour})
	f.stream.gate = make(chan struct{})
	result := make(chan error, 1)
	first := f.grant(protocol.DirectFileUpload, "/workspace/a", 0, 4, nil)
	go func() {
		_, err := f.lane.DirectFile(context.Background(), DirectFileTransfer{Grant: first, Body: bytes.NewReader([]byte("data")), Length: 4})
		result <- err
	}()
	waitFor(t, "transfer started", func() bool { f.stream.mu.Lock(); defer f.stream.mu.Unlock(); return f.stream.streams == 1 })
	if _, err := f.upload(f.grant(protocol.DirectFileUpload, "/workspace/b", 0, 4, nil), []byte("more")); directCode(err) != "transfer_busy" {
		t.Fatalf("same account: %v", err)
	}
	other := f.grant(protocol.DirectFileUpload, "/workspace/c", 0, 4, func(g *protocol.SandboxFileGrantV1) { g.Account = fmt.Sprintf("%064x", 9) })
	done := make(chan error, 1)
	go func() { _, err := f.upload(other, []byte("othr")); done <- err }()
	waitFor(t, "second account admitted", func() bool { f.stream.mu.Lock(); defer f.stream.mu.Unlock(); return f.stream.streams == 2 })
	close(f.stream.gate)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// The validator's health check sends its direct_files_streams (4) parts to
// one sandbox at once; the default bounds must admit them all.
func TestDefaultDirectFilesConfigAdmitsTheHealthParts(t *testing.T) {
	c := DefaultDirectFilesConfig
	if c.PerSandbox < 4 || c.PerAccount < 4 || c.Global < 4 {
		t.Fatalf("default bounds %+v refuse four parallel parts to one sandbox", c)
	}
}
