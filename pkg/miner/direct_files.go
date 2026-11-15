// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/durable"
	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxops"
)

// Direct file transfers (sandbox-direct-files-v1). A tenant presents a
// validator-signed grant straight to the miner and streams one file part
// into or out of the lease's sandbox through one helper run. The lane checks
// the grant against the signed lease it names, claims its nonce durably,
// keeps the lease running for the whole transfer, and signs a receipt.

// SandboxStreamBackend is implemented by an ops backend that can run one
// streamed helper transfer (sandboxbackend.GVisor.StreamHelper).
type SandboxStreamBackend interface {
	StreamHelper(ctx context.Context, instanceID string, request []byte, body io.Reader, sink io.Writer) ([]byte, int64, error)
}

// DirectFilesConfig bounds concurrent direct transfers.
type DirectFilesConfig struct {
	// PerSandbox, PerAccount and Global bound transfers in flight; the
	// per-account bound (the grant's tenant account) keeps one tenant with
	// several sandboxes from holding every global slot.
	PerSandbox, PerAccount, Global int
	// Grace is how long a transfer may run past its grant's expires_at;
	// at expires_at + Grace it is cancelled mid-stream.
	Grace time.Duration
	// LeasePoll is how often a running transfer re-reads its lease state.
	LeasePoll time.Duration
}

// DefaultDirectFilesConfig is four transfers per sandbox (the health
// check's parallel parts, policy direct_files_streams), four per tenant
// account, eight per miner, a one-minute grace past the grant's expiry
// and a two-second lease re-check.
var DefaultDirectFilesConfig = DirectFilesConfig{PerSandbox: 4, PerAccount: 4, Global: 8, Grace: time.Minute, LeasePoll: 2 * time.Second}

// DirectFileError is a refusal or failure with the HTTP status the endpoint
// answers and a short code.
type DirectFileError struct {
	Status int
	Code   string
}

func (e *DirectFileError) Error() string { return "direct file transfer: " + e.Code }

func directErr(status int, code string) error { return &DirectFileError{Status: status, Code: code} }

// DirectFileTransfer is one transfer request. For an upload, Body carries
// exactly Length bytes (the Content-Length, which must equal the grant's
// max_bytes). For a download, [Offset, Offset+Length) must lie inside the
// granted window; Start is called once with the file size and the number of
// bytes that follow, before the first byte is written to Sink.
type DirectFileTransfer struct {
	Grant  protocol.SandboxFileGrantV1
	Body   io.Reader
	Offset uint64
	Length uint64
	Sink   io.Writer
	Start  func(fileSize, length uint64) error
}

type directFiles struct {
	backend SandboxStreamBackend
	config  DirectFilesConfig
	mu      sync.Mutex
	global  int
	perSbx  map[string]int
	perAcct map[string]int
}

// EnableDirectFiles turns on direct transfers. It needs ops (the same
// helper) and a backend that streams.
func (l *SandboxLane) EnableDirectFiles(config DirectFilesConfig) error {
	if l.ops == nil {
		return errors.New("direct file transfers need sandbox ops")
	}
	backend, ok := l.backend.(SandboxStreamBackend)
	if !ok {
		return errors.New("sandbox backend does not stream the ops helper")
	}
	if config.PerSandbox < 1 || config.PerAccount < 1 || config.Global < max(config.PerSandbox, config.PerAccount) || config.LeasePoll <= 0 ||
		config.Grace < 0 || config.Grace > 5*time.Minute {
		return errors.New("direct file transfer bounds are invalid")
	}
	l.direct = &directFiles{backend: backend, config: config, perSbx: map[string]int{}, perAcct: map[string]int{}}
	return nil
}

// DirectFilesEnabled reports whether EnableDirectFiles succeeded.
func (l *SandboxLane) DirectFilesEnabled() bool { return l.direct != nil }

func (d *directFiles) acquire(leaseID, account string) (func(), bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.global >= d.config.Global || d.perSbx[leaseID] >= d.config.PerSandbox || d.perAcct[account] >= d.config.PerAccount {
		return nil, false
	}
	d.global++
	d.perSbx[leaseID]++
	d.perAcct[account]++
	return func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.global--
		if d.perSbx[leaseID]--; d.perSbx[leaseID] == 0 {
			delete(d.perSbx, leaseID)
		}
		if d.perAcct[account]--; d.perAcct[account] == 0 {
			delete(d.perAcct, account)
		}
	}, true
}

// DirectFile performs one granted transfer and returns the signed receipt.
func (l *SandboxLane) DirectFile(ctx context.Context, t DirectFileTransfer) (protocol.SandboxFileReceiptV1, error) {
	d := l.direct
	if d == nil {
		return protocol.SandboxFileReceiptV1{}, directErr(404, "direct_files_disabled")
	}
	ctx, done, err := l.track(ctx)
	if err != nil {
		return protocol.SandboxFileReceiptV1{}, directErr(503, "miner_closing")
	}
	defer done()
	g := t.Grant
	if err := g.Validate(); err != nil {
		return protocol.SandboxFileReceiptV1{}, directErr(400, "grant_invalid")
	}
	if err := l.admit(g.Subnet, g.MinerID); err != nil {
		return protocol.SandboxFileReceiptV1{}, directErr(403, "grant_wrong_miner")
	}
	record, found, err := l.store.Lease(ctx, g.LeaseID)
	if err != nil {
		return protocol.SandboxFileReceiptV1{}, directErr(503, "state_unavailable")
	}
	if !found {
		return protocol.SandboxFileReceiptV1{}, directErr(404, "lease_not_found")
	}
	now := l.now().UTC()
	if err := protocol.VerifySandboxFileGrantForLeaseV1(g, record.Lease, now); err != nil {
		return protocol.SandboxFileReceiptV1{}, directErr(401, "grant_invalid")
	}
	switch g.Op {
	case protocol.DirectFileUpload:
		if t.Body == nil || t.Length != g.MaxBytes {
			return protocol.SandboxFileReceiptV1{}, directErr(400, "length_mismatch")
		}
	case protocol.DirectFileDownload:
		if t.Sink == nil || t.Length == 0 || t.Offset < g.Offset || t.Offset-g.Offset > g.MaxBytes || t.Length > g.MaxBytes-(t.Offset-g.Offset) {
			return protocol.SandboxFileReceiptV1{}, directErr(416, "range_outside_grant")
		}
	}
	release, ok := d.acquire(g.LeaseID, g.Account)
	if !ok {
		return protocol.SandboxFileReceiptV1{}, directErr(429, "transfer_busy")
	}
	defer release()
	expires, _ := time.Parse(time.RFC3339Nano, g.ExpiresAt)
	code, err := l.store.ClaimFileGrant(ctx, g.LeaseID, g.Nonce, expires, now)
	switch {
	case errors.Is(err, durable.ErrFileGrantReplayed):
		return protocol.SandboxFileReceiptV1{}, directErr(409, "grant_replayed")
	case err != nil:
		return protocol.SandboxFileReceiptV1{}, directErr(503, "state_unavailable")
	case code != "":
		return protocol.SandboxFileReceiptV1{}, directErr(410, code)
	}
	// The transfer ends as soon as the lease stops running (release is the
	// kill switch) or the lane closes.
	// It also ends, mid-stream, at the grant's expiry plus the grace: a
	// trickling client cannot hold a slot for the lease's whole life.
	bounded, stop := context.WithTimeoutCause(ctx, expires.Add(d.config.Grace).Sub(now), errTransferDeadline)
	defer stop()
	work, cancel := context.WithCancelCause(bounded)
	defer cancel(nil)
	go l.watchLease(work, cancel, g.LeaseID, d.config.LeasePoll)

	digest := sha256.New()
	var moved uint64
	var size uint64
	instance := SandboxInstanceName(g.LeaseID)
	path := g.Path
	if g.Op == protocol.DirectFileUpload {
		request := sandboxops.Request{Protocol: sandboxops.Protocol, Op: sandboxops.OpFileStreamWrite, Path: &path,
			Offset: &g.Offset, Limit: &t.Length, Mode: g.Mode, SHA256: g.ExpectedSHA256}
		counted := &countingReader{reader: io.TeeReader(t.Body, digest)}
		response, err := l.streamCall(work, d, instance, request, counted, nil)
		if err != nil {
			return protocol.SandboxFileReceiptV1{}, l.transferErr(work, err)
		}
		if counted.n != t.Length || response.File == nil || response.File.Size != g.Offset+t.Length {
			return protocol.SandboxFileReceiptV1{}, directErr(502, sandbox.OpCodeSandboxFailed)
		}
		moved, size = counted.n, response.File.Size
	} else {
		request := sandboxops.Request{Protocol: sandboxops.Protocol, Op: sandboxops.OpFileStreamRead, Path: &path,
			Offset: &t.Offset, Limit: &t.Length}
		sink := &startingWriter{sink: io.MultiWriter(t.Sink, digest), start: t.Start, offset: t.Offset, length: t.Length, request: request}
		response, err := l.streamCall(work, d, instance, request, nil, sink)
		if err != nil {
			return protocol.SandboxFileReceiptV1{}, l.transferErr(work, err)
		}
		size = *response.Size
		want := uint64(0)
		if t.Offset < size {
			want = min(t.Length, size-t.Offset)
		}
		if sink.n != want {
			return protocol.SandboxFileReceiptV1{}, directErr(502, "stream_short")
		}
		moved = sink.n
	}
	if cause := context.Cause(work); cause != nil {
		return protocol.SandboxFileReceiptV1{}, l.transferErr(work, cause)
	}
	grantDigest, err := protocol.SandboxFileDigestV1(g)
	if err != nil {
		return protocol.SandboxFileReceiptV1{}, directErr(500, "receipt_failed")
	}
	receipt := protocol.SandboxFileReceiptV1{
		Account: g.Account, Bytes: moved, CompletedAt: *protocol.StaticTime(l.now().UTC()), FileSize: size,
		Generation: g.Generation, GrantDigest: grantDigest, LeaseID: g.LeaseID, MinerID: g.MinerID, Nonce: g.Nonce,
		Offset: g.Offset, Op: g.Op, Path: g.Path, SandboxID: g.SandboxID, Schema: protocol.SandboxFileReceiptSchema,
		SchemaVersion: protocol.SandboxFilesDirectSchemaVersion, SHA256: hex.EncodeToString(digest.Sum(nil)), Subnet: g.Subnet,
	}
	if g.Op == protocol.DirectFileDownload {
		receipt.Offset = t.Offset
	}
	l.gate.Lock()
	defer l.gate.Unlock()
	if l.isClosed() {
		return protocol.SandboxFileReceiptV1{}, directErr(503, "miner_closing")
	}
	if err := protocol.SignSandboxFileReceiptV1(&receipt, l.agent.SigningKey); err != nil {
		return protocol.SandboxFileReceiptV1{}, directErr(500, "receipt_failed")
	}
	return receipt, nil
}

// errTransferDeadline is the cause of a transfer cut at its deadline.
var errTransferDeadline = errors.New("direct transfer passed its grant expiry plus grace")

// errLeaseEnded is the cancel cause of a transfer whose lease stopped.
type errLeaseEnded struct{ code string }

func (e *errLeaseEnded) Error() string { return "lease ended: " + e.code }

func (l *SandboxLane) watchLease(ctx context.Context, cancel context.CancelCauseFunc, leaseID string, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		code, err := l.store.LeaseRefusal(ctx, leaseID, l.now().UTC())
		if err == nil && code != "" {
			cancel(&errLeaseEnded{code: code})
			return
		}
	}
}

func (l *SandboxLane) streamCall(ctx context.Context, d *directFiles, instance string, request sandboxops.Request, body io.Reader, sink io.Writer) (sandboxops.Response, error) {
	encoded, err := sandboxops.Encode(request)
	if err != nil {
		return sandboxops.Response{}, directErr(500, sandbox.OpCodeSandboxFailed)
	}
	line, _, err := d.backend.StreamHelper(ctx, instance, encoded, body, sink)
	var unavailable *SandboxEngineUnavailable
	switch {
	case errors.Is(err, ErrSandboxNotRunning):
		return sandboxops.Response{}, directErr(410, "sandbox_exited")
	case errors.As(err, &unavailable):
		return sandboxops.Response{}, directErr(503, sandbox.OpCodeRuntimeFailed)
	case err != nil:
		return sandboxops.Response{}, err
	}
	response, err := sandboxops.DecodeResponse(line, request)
	if err != nil {
		return sandboxops.Response{}, directErr(502, sandbox.OpCodeSandboxFailed)
	}
	if response.Code != nil {
		return sandboxops.Response{}, directErr(helperStatus(*response.Code), *response.Code)
	}
	return response, nil
}

// transferErr names why a transfer ended without a helper answer.
func (l *SandboxLane) transferErr(ctx context.Context, err error) error {
	var direct *DirectFileError
	if errors.As(err, &direct) {
		return direct
	}
	var ended *errLeaseEnded
	if errors.As(context.Cause(ctx), &ended) {
		return directErr(410, ended.code)
	}
	if l.base.Err() != nil {
		return directErr(503, "miner_closing")
	}
	if errors.Is(context.Cause(ctx), errTransferDeadline) {
		return directErr(408, "transfer_deadline")
	}
	if ctx.Err() != nil {
		return directErr(499, "client_gone")
	}
	return directErr(502, sandbox.OpCodeSandboxFailed)
}

func helperStatus(code string) int {
	switch code {
	case "path_not_found":
		return 404
	case "offset_mismatch", "path_exists", "path_not_file", "path_not_directory":
		return 409
	case "permission_denied", "path_refused":
		return 403
	case "file_too_large":
		return 413
	case "sha256_mismatch", "stream_short":
		return 422
	case "no_space", sandbox.OpCodeResourcesExhausted:
		return 507
	}
	return 502
}

type countingReader struct {
	reader io.Reader
	n      uint64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	c.n += uint64(n)
	return n, err
}

// startingWriter sees the helper's answer line first (StreamHelper), calls
// start with the file size from it before the first byte, and refuses more
// bytes than the window holds.
type startingWriter struct {
	sink           io.Writer
	start          func(fileSize, length uint64) error
	offset, length uint64
	request        sandboxops.Request
	started        bool
	n              uint64
}

// HelperAnswer starts the download from a successful answer; a failure
// answer starts nothing and is reported by the caller.
func (s *startingWriter) HelperAnswer(line []byte) error {
	response, err := sandboxops.DecodeResponse(line, s.request)
	if err != nil || response.Code != nil || response.Size == nil {
		return nil
	}
	s.started = true
	if s.start == nil {
		return nil
	}
	fileSize := *response.Size
	length := uint64(0)
	if s.offset < fileSize {
		length = min(s.length, fileSize-s.offset)
	}
	return s.start(fileSize, length)
}

func (s *startingWriter) Write(p []byte) (int, error) {
	if s.n+uint64(len(p)) > s.length {
		return 0, errors.New("helper streamed more than the window")
	}
	if !s.started {
		return 0, errors.New("stream bytes arrived before the file size")
	}
	n, err := s.sink.Write(p)
	s.n += uint64(n)
	return n, err
}
