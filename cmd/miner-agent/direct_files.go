// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/miner"
	"github.com/misscomputer/mscomputer-miner/pkg/organic"
	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

// Direct file transfers (sandbox-direct-files-v1): the agent's own public
// TLS listener, serving exactly one route. It presents the same leaf the
// axon serves (the agent refuses a different one), so a client pins the
// leaf the validator already pins for this miner.

const (
	maxGrantHeaderBytes = 16 << 10
	directIdleTimeout   = 60 * time.Second
	// directFailureRate and directFailureBurst bound refused requests per
	// second from one source IP; past them that IP is answered 429 before
	// its grant is decoded. Other sources (the validator's checker, other
	// tenants) keep their own budget, so junk traffic cannot starve them.
	directFailureRate  = 20
	directFailureBurst = 40
	// maxFailureSources bounds the per-IP table.
	maxFailureSources = 4096
	// directReceiptTTL is how long the receipt of a completed download
	// stays fetchable; maxHeldReceipts bounds how many are held.
	directReceiptTTL = 2 * time.Minute
	maxHeldReceipts  = 4096
)

type directFilesSettings struct {
	bind        string
	certificate tls.Certificate
	config      miner.DirectFilesConfig
}

// loadDirectFiles reads the listener settings. An empty bind leaves the
// listener off; the miner then does not advertise the feature and fails the
// policy's direct-files requirement.
func loadDirectFiles(bind, certFile, keyFile, pin string, opsOn bool, perSandbox, global int) (*directFilesSettings, error) {
	if bind == "" {
		if certFile != "" || keyFile != "" {
			return nil, errors.New("--direct-files-tls-cert/--direct-files-tls-key require --direct-files-bind")
		}
		return nil, nil
	}
	if !opsOn {
		return nil, errors.New("--direct-files-bind requires --sandbox-ops on")
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("--direct-files-bind requires --direct-files-tls-cert and --direct-files-tls-key (the axon's files)")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("direct files TLS: %w", err)
	}
	leaf := sha256.Sum256(certificate.Certificate[0])
	if pin == "" || hex.EncodeToString(leaf[:]) != strings.ToLower(pin) {
		return nil, errors.New("direct files TLS leaf differs from --tls-certificate-sha256")
	}
	config := miner.DefaultDirectFilesConfig
	if perSandbox > 0 {
		config.PerSandbox = perSandbox
	}
	if global > 0 {
		config.Global = global
	}
	return &directFilesSettings{bind: bind, certificate: certificate, config: config}, nil
}

func newDirectFilesServer(settings *directFilesSettings, lane *miner.SandboxLane) *http.Server {
	handler := &directFilesHandler{lane: lane, failures: newSourceBuckets(directFailureRate, directFailureBurst, maxFailureSources, time.Now),
		receipts: newHeldReceipts(directReceiptTTL, maxHeldReceipts, time.Now)}
	return &http.Server{
		Addr: settings.bind, Handler: handler,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{settings.certificate}},
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: directIdleTimeout, MaxHeaderBytes: 32 << 10,
	}
}

type directFilesHandler struct {
	lane     *miner.SandboxLane
	failures *sourceBuckets
	receipts *heldReceipts
}

func (h *directFilesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if id, ok := strings.CutPrefix(r.URL.Path, sandbox.DirectFileReceiptsPath); ok {
		h.fetchReceipt(w, r, id)
		return
	}
	if r.URL.Path != sandbox.DirectFilesPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, PUT")
		h.refuse(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if !h.failures.ready(sourceIP(r)) {
		writeDirectError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	grant, ok := decodeGrantHeader(r.Header.Get(sandbox.DirectFileGrantHeader))
	if !ok {
		h.refuse(w, r, http.StatusBadRequest, "grant_invalid")
		return
	}
	switch {
	case r.Method == http.MethodPut && grant.Op == protocol.DirectFileUpload:
		h.upload(w, r, grant)
	case r.Method == http.MethodGet && grant.Op == protocol.DirectFileDownload:
		h.download(w, r, grant)
	default:
		h.refuse(w, r, http.StatusBadRequest, "method_does_not_match_grant")
	}
}

func (h *directFilesHandler) upload(w http.ResponseWriter, r *http.Request, grant protocol.SandboxFileGrantV1) {
	if r.ContentLength < 0 {
		h.refuse(w, r, http.StatusLengthRequired, "length_required")
		return
	}
	controller := http.NewResponseController(w)
	body := &idleReader{reader: r.Body, extend: func() { _ = controller.SetReadDeadline(time.Now().Add(directIdleTimeout)) }}
	started := time.Now()
	receipt, err := h.lane.DirectFile(r.Context(), miner.DirectFileTransfer{Grant: grant, Body: body, Length: uint64(r.ContentLength)})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	logTransfer(receipt, started)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(receipt)
}

func (h *directFilesHandler) download(w http.ResponseWriter, r *http.Request, grant protocol.SandboxFileGrantV1) {
	offset, length, ranged, ok := parseRange(r.Header.Get("Range"), grant)
	if !ok {
		h.refuse(w, r, http.StatusRequestedRangeNotSatisfiable, "range_invalid")
		return
	}
	controller := http.NewResponseController(w)
	sink := &idleWriter{writer: w, extend: func() { _ = controller.SetWriteDeadline(time.Now().Add(directIdleTimeout)) }}
	wroteHeader := false
	start := func(fileSize, length uint64) error {
		header := w.Header()
		header.Set("Content-Type", "application/octet-stream")
		// No Content-Length: HTTP/1.1 carries the receipt trailer only in
		// a chunked body. X-Transfer-Length announces the byte count.
		header.Set("X-Transfer-Length", strconv.FormatUint(length, 10))
		header.Set("X-File-Size", strconv.FormatUint(fileSize, 10))
		header.Set("Trailer", sandbox.DirectFileReceiptHeader)
		status := http.StatusOK
		switch {
		case ranged && length == 0:
			// The range starts at or past the end of the file (RFC 9110
			// 15.5.17); no bytes follow, the receipt still names 0 bytes.
			status = http.StatusRequestedRangeNotSatisfiable
			header.Set("Content-Range", fmt.Sprintf("bytes */%d", fileSize))
		case ranged:
			status = http.StatusPartialContent
			header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, offset+length-1, fileSize))
		}
		wroteHeader = true
		w.WriteHeader(status)
		return nil
	}
	started := time.Now()
	receipt, err := h.lane.DirectFile(r.Context(), miner.DirectFileTransfer{Grant: grant, Offset: offset, Length: length, Sink: sink, Start: start})
	if err != nil {
		if wroteHeader {
			// The status is gone; a truncated body is the only signal left.
			panic(http.ErrAbortHandler)
		}
		h.fail(w, r, err)
		return
	}
	// Every byte of the range was written: the receipt is also held for one
	// fetch by the same grant, for clients behind proxies that drop trailers.
	h.receipts.put(grant, receipt)
	encoded, err := encodeReceiptHeader(receipt)
	if err == nil {
		w.Header().Set(sandbox.DirectFileReceiptHeader, encoded)
	}
	logTransfer(receipt, started)
}

// fetchReceipt answers GET DirectFileReceiptsPath+nonce: the held receipt of
// the completed download whose grant (the same X-Ms-File-Grant, byte for
// byte as canonical JSON) has that nonce. It is answered once; a second
// fetch, another grant, an expired or never completed download get 404.
func (h *directFilesHandler) fetchReceipt(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		h.refuse(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if !h.failures.ready(sourceIP(r)) {
		writeDirectError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	grant, ok := decodeGrantHeader(r.Header.Get(sandbox.DirectFileGrantHeader))
	if !ok || grant.Op != protocol.DirectFileDownload || grant.Nonce != id {
		h.refuse(w, r, http.StatusBadRequest, "grant_invalid")
		return
	}
	receipt, ok := h.receipts.take(grant)
	if !ok {
		h.refuse(w, r, http.StatusNotFound, "receipt_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(receipt)
}

// heldReceipts keeps the receipts of completed downloads for one fetch each,
// keyed by grant nonce and bound to the digest of the whole signed grant.
type heldReceipts struct {
	mu      sync.Mutex
	ttl     time.Duration
	limit   int
	now     func() time.Time
	entries map[string]heldReceipt
}

type heldReceipt struct {
	grantDigest string
	receipt     protocol.SandboxFileReceiptV1
	expires     time.Time
}

func newHeldReceipts(ttl time.Duration, limit int, now func() time.Time) *heldReceipts {
	return &heldReceipts{ttl: ttl, limit: limit, now: now, entries: map[string]heldReceipt{}}
}

func (s *heldReceipts) put(grant protocol.SandboxFileGrantV1, receipt protocol.SandboxFileReceiptV1) {
	digest, err := protocol.SandboxFileDigestV1(grant)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.entries) >= s.limit {
		oldest := ""
		for key, entry := range s.entries {
			if !now.Before(entry.expires) {
				delete(s.entries, key)
			} else if oldest == "" || entry.expires.Before(s.entries[oldest].expires) {
				oldest = key
			}
		}
		if len(s.entries) >= s.limit {
			delete(s.entries, oldest)
		}
	}
	s.entries[grant.Nonce] = heldReceipt{grantDigest: digest, receipt: receipt, expires: now.Add(s.ttl)}
}

// take returns and forgets the receipt held for grant, if it is unexpired
// and was recorded for exactly this grant.
func (s *heldReceipts) take(grant protocol.SandboxFileGrantV1) (protocol.SandboxFileReceiptV1, bool) {
	digest, err := protocol.SandboxFileDigestV1(grant)
	if err != nil {
		return protocol.SandboxFileReceiptV1{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, found := s.entries[grant.Nonce]
	if !found || entry.grantDigest != digest {
		return protocol.SandboxFileReceiptV1{}, false
	}
	delete(s.entries, grant.Nonce)
	if !s.now().Before(entry.expires) {
		return protocol.SandboxFileReceiptV1{}, false
	}
	return entry.receipt, true
}

func (h *directFilesHandler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var direct *miner.DirectFileError
	if errors.As(err, &direct) {
		if direct.Status < 500 && direct.Status != http.StatusTooManyRequests {
			h.failures.take(sourceIP(r))
		}
		writeDirectError(w, direct.Status, direct.Code)
		return
	}
	writeDirectError(w, http.StatusBadGateway, sandbox.OpCodeSandboxFailed)
}

func (h *directFilesHandler) refuse(w http.ResponseWriter, r *http.Request, status int, code string) {
	h.failures.take(sourceIP(r))
	writeDirectError(w, status, code)
}

func writeDirectError(w http.ResponseWriter, status int, code string) {
	if status == 499 {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func logTransfer(receipt protocol.SandboxFileReceiptV1, started time.Time) {
	seconds := time.Since(started).Seconds()
	slog.Info("direct file transfer", "op", receipt.Op, "sandbox_id", receipt.SandboxID, "bytes", receipt.Bytes,
		"seconds", seconds, "mb_per_s", float64(receipt.Bytes)/1e6/max(seconds, 1e-9))
}

func decodeGrantHeader(value string) (protocol.SandboxFileGrantV1, bool) {
	var grant protocol.SandboxFileGrantV1
	if value == "" || len(value) > maxGrantHeaderBytes {
		return grant, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return grant, false
	}
	return grant, organic.DecodeStrict(payload, &grant) == nil
}

func encodeReceiptHeader(receipt protocol.SandboxFileReceiptV1) (string, error) {
	encoded, err := organic.Canonical(receipt)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

// parseRange reads one "bytes=a-b" or "bytes=a-" range inside the grant's
// window. Without a Range header the whole window is requested.
func parseRange(value string, grant protocol.SandboxFileGrantV1) (offset, length uint64, ranged, ok bool) {
	if value == "" {
		return grant.Offset, grant.MaxBytes, false, true
	}
	spec, found := strings.CutPrefix(value, "bytes=")
	if !found || strings.Contains(spec, ",") {
		return 0, 0, false, false
	}
	first, last, found := strings.Cut(spec, "-")
	if !found || first == "" {
		return 0, 0, false, false
	}
	start, err := strconv.ParseUint(first, 10, 64)
	if err != nil || start < grant.Offset || start-grant.Offset >= grant.MaxBytes {
		return 0, 0, false, false
	}
	windowEnd := grant.Offset + grant.MaxBytes - 1
	end := windowEnd
	if last != "" {
		if end, err = strconv.ParseUint(last, 10, 64); err != nil || end < start || end > windowEnd {
			return 0, 0, false, false
		}
	}
	return start, end - start + 1, true, true
}

// idleReader and idleWriter extend the connection deadline on every call,
// so a transfer may be long but never idle for more than directIdleTimeout.
type idleReader struct {
	reader io.Reader
	extend func()
}

func (i *idleReader) Read(p []byte) (int, error) {
	i.extend()
	return i.reader.Read(p)
}

type idleWriter struct {
	writer io.Writer
	extend func()
}

func (i *idleWriter) Write(p []byte) (int, error) {
	i.extend()
	return i.writer.Write(p)
}

// tokenBucket is a small rate limiter of refused requests.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newTokenBucket(rate, burst float64, now func() time.Time) *tokenBucket {
	return &tokenBucket{rate: rate, burst: burst, tokens: burst, last: now(), now: now}
}

func (b *tokenBucket) refill() {
	now := b.now()
	b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
}

// ready reports whether a request may be served (a token is left).
func (b *tokenBucket) ready() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	return b.tokens >= 1
}

// full reports whether the bucket has refilled completely.
func (b *tokenBucket) full() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	return b.tokens >= b.burst
}

// take charges one refused request.
func (b *tokenBucket) take() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	b.tokens = max(0, b.tokens-1)
}

// sourceIP is the peer address of r without its port.
func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// sourceBuckets keeps one refusal bucket per source IP, at most limit of
// them; when full, buckets that refilled completely are dropped first, and
// if none did the table starts over (losing only refusal history).
type sourceBuckets struct {
	mu          sync.Mutex
	rate, burst float64
	limit       int
	now         func() time.Time
	buckets     map[string]*tokenBucket
}

func newSourceBuckets(rate, burst float64, limit int, now func() time.Time) *sourceBuckets {
	return &sourceBuckets{rate: rate, burst: burst, limit: limit, now: now, buckets: map[string]*tokenBucket{}}
}

func (s *sourceBuckets) bucket(ip string, create bool) *tokenBucket {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.buckets[ip]; ok || !create {
		return b
	}
	if len(s.buckets) >= s.limit {
		for key, b := range s.buckets {
			if b.ready() && b.full() {
				delete(s.buckets, key)
			}
		}
		if len(s.buckets) >= s.limit {
			s.buckets = map[string]*tokenBucket{}
		}
	}
	b := newTokenBucket(s.rate, s.burst, s.now)
	s.buckets[ip] = b
	return b
}

func (s *sourceBuckets) ready(ip string) bool {
	b := s.bucket(ip, false)
	return b == nil || b.ready()
}

func (s *sourceBuckets) take(ip string) { s.bucket(ip, true).take() }

// serveDirectFiles runs the listener until ctx ends.
func serveDirectFiles(ctx context.Context, server *http.Server) error {
	errorsChannel := make(chan error, 1)
	go func() { errorsChannel <- server.ListenAndServeTLS("", "") }()
	select {
	case err := <-errorsChannel:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
