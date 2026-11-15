// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/durable"
	"github.com/misscomputer/mscomputer-miner/pkg/miner"
	"github.com/misscomputer/mscomputer-miner/pkg/neuron"
	"github.com/misscomputer/mscomputer-miner/pkg/organic"
	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxops"
)

// streamSandboxBackend keeps sandbox files in memory and speaks the helper
// stream protocol, so the endpoint, lane and receipts run unmodified.
type streamSandboxBackend struct {
	opsSandboxBackend
	mu    sync.Mutex
	files map[string][]byte
}

func (b *streamSandboxBackend) StreamHelper(_ context.Context, _ string, encoded []byte, body io.Reader, sink io.Writer) ([]byte, int64, error) {
	request, err := sandboxops.DecodeRequest(encoded)
	if err != nil {
		return nil, 0, err
	}
	answer := func(response sandboxops.Response) []byte {
		response.Protocol = sandboxops.Protocol
		line, _ := sandboxops.Encode(response)
		return append(line, '\n')
	}
	if request.Op == sandboxops.OpFileStreamWrite {
		data := make([]byte, *request.Limit)
		if _, err := io.ReadFull(body, data); err != nil {
			return answer(sandboxops.Failure("stream_short")), 0, nil
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		b.files[*request.Path] = append(b.files[*request.Path][:*request.Offset:*request.Offset], data...)
		info := sandbox.FileInfo{Type: sandbox.FileTypeFile, Mode: 0o644, Size: uint64(len(b.files[*request.Path]))}
		return answer(sandboxops.Response{File: &info}), 0, nil
	}
	b.mu.Lock()
	data := b.files[*request.Path]
	b.mu.Unlock()
	size := uint64(len(data))
	line := answer(sandboxops.Response{Size: &size})
	if head, ok := sink.(interface{ HelperAnswer([]byte) error }); ok {
		if err := head.HelperAnswer(line); err != nil {
			return nil, 0, err
		}
	}
	end := min(size, *request.Offset+*request.Limit)
	n, err := sink.Write(data[min(*request.Offset, size):end])
	return line, int64(n), err
}

type directHarness struct {
	t                 *testing.T
	validator         ed25519.PrivateKey
	minerPublic       ed25519.PublicKey
	lease             protocol.SandboxLeaseV1
	binding           *protocol.StaticSubnetBindingV1
	service           *api
	lane              *miner.SandboxLane
	client            *http.Client
	url               string
	nonce             int
	leasesForTeardown *durable.SandboxLeases
	handlerRef        *directFilesHandler
}

func newDirectHarness(t *testing.T) *directHarness {
	t.Helper()
	const (
		validatorHotkey = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
		minerHotkey     = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
	)
	ctx := context.Background()
	validatorPublic, validatorPrivate, _ := ed25519.GenerateKey(nil)
	minerPublic, minerPrivate, _ := ed25519.GenerateKey(nil)
	root := t.TempDir()
	dir := filepath.Join(root, "mc-sandboxes")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"cpu.max": "400000 100000\n", "memory.max": fmt.Sprint(8<<30) + "\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	statePath := filepath.Join(t.TempDir(), "state.db")
	state, err := durable.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Close() })
	leases, err := state.EnableSandboxLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	agent := miner.NewAgent(minerHotkey, nil, minerPrivate, nil, nil, nil)
	agent.MinerTransport = neuron.TransportHTTP
	backend := &streamSandboxBackend{opsSandboxBackend: opsSandboxBackend{sandboxBackend{live: map[string]bool{}}}, files: map[string][]byte{}}
	lane, err := miner.NewSandboxLane(ctx, agent, leases, backend, miner.SandboxLaneConfig{
		Budget: sandbox.Capacity{CPUMillis: 4000, MemoryMiB: 8192, DiskMiB: 40960, Sandboxes: 4}, CgroupRoot: root,
		AgentCgroup: "/system.slice/miner-agent.service", DeploymentCgroup: "/system.slice/deployment-v4.slice",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lane.Close(ctx) })
	service := &api{agent: agent, store: state, network: "mock", netuid: 24, hotkey: minerHotkey, public: minerPublic, sandbox: lane}
	now := time.Now().UTC()
	binding := &protocol.StaticSubnetBindingV1{
		Network: "mock", NetUID: 24, ValidatorHotkey: validatorHotkey, MinerHotkey: minerHotkey,
		MinerAxonURL: "http://127.0.0.1:8091", MinerTransport: neuron.TransportHTTP, ChainBlock: 100, Epoch: 1, ExpiresAtBlock: 112,
		ValidatorServicePublicKey: hex.EncodeToString(validatorPublic), MinerServicePublicKey: hex.EncodeToString(minerPublic),
	}
	request := miner.SandboxRequest{ValidatorKey: validatorPublic, CurrentBlock: 101, Network: "mock", NetUID: 24, CallerHotkey: validatorHotkey, MinerHotkey: minerHotkey}
	reservation := protocol.SandboxReservationV1{
		Generation: 1, HoldExpiresAt: *protocol.StaticTime(now.Add(time.Minute)), IssuedAt: *protocol.StaticTime(now), MinerID: minerHotkey,
		ReservationNonce: strings.Repeat("a1", 16), Resources: sandbox.Resources{CPUMillis: 1000, MemoryMiB: 2048, DiskMiB: 10240, PIDs: 512},
		SandboxID: "sbx-" + strings.Repeat("0", 31) + "1", Schema: protocol.SandboxReservationSchema, SchemaVersion: 1, Subnet: binding, WorkloadKind: sandbox.WorkloadKind,
	}
	if err := protocol.SignSandboxReservationV1(&reservation, validatorPrivate); err != nil {
		t.Fatal(err)
	}
	if _, err := lane.Reserve(ctx, reservation, request); err != nil {
		t.Fatal(err)
	}
	digest, _ := protocol.SandboxDigestV1(reservation)
	image := "sha256:" + strings.Repeat("c4", 32)
	lease := protocol.SandboxLeaseV1{
		AssignmentNonce: strings.Repeat("c3", 16), Env: map[string]string{}, Generation: 1, ImageDigest: image,
		ImageReference: "docker.io/library/python@" + image, Isolation: sandbox.IsolationGVisor, IssuedAt: *protocol.StaticTime(now),
		LeaseExpiresAt: *protocol.StaticTime(now.Add(10 * time.Minute)), MinerID: minerHotkey,
		Network:           sandbox.NetworkPolicy{Mode: sandbox.NetworkNone, Allow: []string{}},
		ReservationDigest: digest, Resources: reservation.Resources, SandboxID: reservation.SandboxID, Schema: protocol.SandboxLeaseSchema, SchemaVersion: 1,
		SecretEnv: sandbox.SecretEnv{Delivery: sandbox.SecretDeliveryNone, Names: []string{}}, Subnet: binding, WorkloadKind: sandbox.WorkloadKind,
	}
	if err := protocol.SignSandboxLeaseV1(&lease, validatorPrivate); err != nil {
		t.Fatal(err)
	}
	if receipt, err := lane.Commit(ctx, lease, request); err != nil || receipt.Stage != sandbox.StageReady {
		t.Fatalf("commit: %+v %v", receipt.Stage, err)
	}
	if slices.Contains(advertised(t, service), sandbox.DirectFilesCapabilityFeature) {
		t.Fatal("sandbox-direct-files-v1 advertised before it was enabled")
	}
	if err := enableSandboxOps(ctx, lane, state, &sandboxOpsSettings{config: miner.SandboxOpsConfig{
		StartResolution: time.Second, StateTimeout: time.Second, KillGrace: time.Second, MaxInFlight: 4, MaxInFlightBytes: 4 << 20, MaxOutcomes: 4,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := lane.EnableDirectFiles(miner.DefaultDirectFilesConfig); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(advertised(t, service), sandbox.DirectFilesCapabilityFeature) {
		t.Fatal("enabled direct files do not advertise sandbox-direct-files-v1")
	}
	certificate, _, _ := selfSigned(t)
	server := newDirectFilesServer(&directFilesSettings{bind: "127.0.0.1:0", certificate: certificate}, lane)
	listener := httptest.NewUnstartedServer(server.Handler)
	listener.TLS = server.TLSConfig
	listener.StartTLS()
	t.Cleanup(listener.Close)
	return &directHarness{t: t, validator: validatorPrivate, minerPublic: minerPublic, lease: lease, binding: binding, service: service,
		lane: lane, client: listener.Client(), url: listener.URL + sandbox.DirectFilesPath, leasesForTeardown: leases,
		handlerRef: server.Handler.(*directFilesHandler)}
}

func (h *directHarness) grant(op, path string, offset, maxBytes uint64) string {
	h.t.Helper()
	digest, _ := protocol.SandboxDigestV1(h.lease)
	h.nonce++
	now := time.Now().UTC()
	g := protocol.SandboxFileGrantV1{
		Account: strings.Repeat("ab", 32), ExpiresAt: *protocol.StaticTime(now.Add(10 * time.Minute)), Generation: 1,
		IssuedAt: *protocol.StaticTime(now), LeaseDigest: digest, LeaseID: protocol.SandboxLeaseIDV1(h.lease), MaxBytes: maxBytes,
		MinerID: h.lease.MinerID, Nonce: fmt.Sprintf("%032x", h.nonce), Offset: offset, Op: op, Path: path, SandboxID: h.lease.SandboxID,
		Schema: protocol.SandboxFileGrantSchema, SchemaVersion: 1, Subnet: h.binding,
	}
	if op == protocol.DirectFileUpload && offset == 0 {
		mode := uint32(0o644)
		g.Mode = &mode
	}
	if err := protocol.SignSandboxFileGrantV1(&g, h.validator); err != nil {
		h.t.Fatal(err)
	}
	encoded, err := organic.Canonical(g)
	if err != nil {
		h.t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func (h *directHarness) do(method, grant string, body []byte, header map[string]string) (*http.Response, []byte) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequest(method, h.url, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	if grant != "" {
		request.Header.Set(sandbox.DirectFileGrantHeader, grant)
	}
	for name, value := range header {
		request.Header.Set(name, value)
	}
	response, err := h.client.Do(request)
	if err != nil {
		h.t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return response, data
}

// Over real TLS: upload a part, append a part, ranged download with the
// receipt in the trailer, and verifiable receipts throughout.
func TestDirectFilesEndpointStreamsAndSignsReceipts(t *testing.T) {
	h := newDirectHarness(t)
	data := make([]byte, 2<<20+9)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	response, body := h.do(http.MethodPut, h.grant(protocol.DirectFileUpload, "/workspace/f.bin", 0, 1<<20), data[:1<<20], nil)
	var receipt protocol.SandboxFileReceiptV1
	if response.StatusCode != http.StatusOK || json.Unmarshal(body, &receipt) != nil {
		t.Fatalf("upload %d %s", response.StatusCode, body)
	}
	sum := sha256.Sum256(data[:1<<20])
	if receipt.SHA256 != hex.EncodeToString(sum[:]) || receipt.Bytes != 1<<20 || protocol.VerifySandboxFileReceiptV1(receipt, h.minerPublic) != nil {
		t.Fatalf("upload receipt %+v", receipt)
	}
	if response, body := h.do(http.MethodPut, h.grant(protocol.DirectFileUpload, "/workspace/f.bin", 1<<20, uint64(len(data)-1<<20)), data[1<<20:], nil); response.StatusCode != http.StatusOK {
		t.Fatalf("append %d %s", response.StatusCode, body)
	}
	response, got := h.do(http.MethodGet, h.grant(protocol.DirectFileDownload, "/workspace/f.bin", 0, uint64(len(data))), nil,
		map[string]string{"Range": "bytes=100-2097159"})
	if response.StatusCode != http.StatusPartialContent || !bytes.Equal(got, data[100:2097160]) ||
		response.Header.Get("Content-Range") != fmt.Sprintf("bytes 100-2097159/%d", len(data)) {
		t.Fatalf("ranged download %d, %d bytes, %q", response.StatusCode, len(got), response.Header.Get("Content-Range"))
	}
	trailer, err := base64.RawURLEncoding.DecodeString(response.Trailer.Get(sandbox.DirectFileReceiptHeader))
	var downloaded protocol.SandboxFileReceiptV1
	if err != nil || organic.DecodeStrict(trailer, &downloaded) != nil || protocol.VerifySandboxFileReceiptV1(downloaded, h.minerPublic) != nil {
		t.Fatalf("download receipt trailer: %v", err)
	}
	gotSum := sha256.Sum256(got)
	if downloaded.Bytes != uint64(len(got)) || downloaded.SHA256 != hex.EncodeToString(gotSum[:]) || downloaded.Offset != 100 {
		t.Fatalf("download receipt %+v", downloaded)
	}
	// A range starting past the end of the file (inside the grant): 416.
	past := h.grant(protocol.DirectFileDownload, "/workspace/f.bin", 0, uint64(len(data))+100)
	if response, got := h.do(http.MethodGet, past, nil, map[string]string{"Range": fmt.Sprintf("bytes=%d-", len(data)+10)}); response.StatusCode != http.StatusRequestedRangeNotSatisfiable ||
		len(got) != 0 || response.Header.Get("Content-Range") != fmt.Sprintf("bytes */%d", len(data)) {
		t.Fatalf("range past the end: %d, %d bytes, %q", response.StatusCode, len(got), response.Header.Get("Content-Range"))
	}
	// Whole window without Range: 200.
	if response, got := h.do(http.MethodGet, h.grant(protocol.DirectFileDownload, "/workspace/f.bin", 0, uint64(len(data))), nil, nil); response.StatusCode != http.StatusOK || !bytes.Equal(got, data) {
		t.Fatalf("whole download %d, %d bytes", response.StatusCode, len(got))
	}
}

func TestDirectFilesEndpointRefusals(t *testing.T) {
	h := newDirectHarness(t)
	upload := h.grant(protocol.DirectFileUpload, "/workspace/g", 0, 4)
	for name, tc := range map[string]struct {
		method, path, grant string
		body                []byte
		header              map[string]string
		status              int
	}{
		"no grant":            {http.MethodPut, sandbox.DirectFilesPath, "", []byte("data"), nil, http.StatusBadRequest},
		"garbage grant":       {http.MethodPut, sandbox.DirectFilesPath, "!!", []byte("data"), nil, http.StatusBadRequest},
		"oversized grant":     {http.MethodPut, sandbox.DirectFilesPath, strings.Repeat("A", maxGrantHeaderBytes+1), []byte("data"), nil, http.StatusBadRequest},
		"method mismatch":     {http.MethodGet, sandbox.DirectFilesPath, upload, nil, nil, http.StatusBadRequest},
		"wrong length":        {http.MethodPut, sandbox.DirectFilesPath, upload, []byte("toolong"), nil, http.StatusBadRequest},
		"other route":         {http.MethodPut, "/v1/sandbox/ops", upload, []byte("data"), nil, http.StatusNotFound},
		"method not allowed":  {http.MethodDelete, sandbox.DirectFilesPath, upload, nil, nil, http.StatusMethodNotAllowed},
		"range outside grant": {http.MethodGet, sandbox.DirectFilesPath, h.grant(protocol.DirectFileDownload, "/workspace/g", 10, 10), nil, map[string]string{"Range": "bytes=0-5"}, http.StatusRequestedRangeNotSatisfiable},
	} {
		request, _ := http.NewRequest(tc.method, strings.TrimSuffix(h.url, sandbox.DirectFilesPath)+tc.path, bytes.NewReader(tc.body))
		if tc.grant != "" {
			request.Header.Set(sandbox.DirectFileGrantHeader, tc.grant)
		}
		for key, value := range tc.header {
			request.Header.Set(key, value)
		}
		response, err := h.client.Do(request)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatalf("%s: status %d, want %d", name, response.StatusCode, tc.status)
		}
	}
	if response, body := h.do(http.MethodPut, upload, []byte("data"), nil); response.StatusCode != http.StatusOK {
		t.Fatalf("valid upload %d %s", response.StatusCode, body)
	}
	if response, body := h.do(http.MethodPut, upload, []byte("data"), nil); response.StatusCode != http.StatusConflict || !strings.Contains(string(body), "grant_replayed") {
		t.Fatalf("replay %d %s", response.StatusCode, body)
	}
}

// Refused requests flush the bucket of their source IP only: once it is
// empty that source gets 429 before anything is decoded, while another
// source (the checker, another tenant) is still served.
func TestDirectFilesFailureRateLimitIsPerSource(t *testing.T) {
	now := time.Unix(1000, 0)
	handler := &directFilesHandler{failures: newSourceBuckets(1, 3, 2, func() time.Time { return now })}
	status := func(ip string) int {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPut, sandbox.DirectFilesPath, nil)
		request.RemoteAddr = ip + ":40000"
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}
	for range 3 {
		if code := status("198.51.100.1"); code != http.StatusBadRequest {
			t.Fatalf("refusal answered %d", code)
		}
	}
	if code := status("198.51.100.1"); code != http.StatusTooManyRequests {
		t.Fatalf("exhausted source answered %d", code)
	}
	if code := status("203.0.113.7"); code != http.StatusBadRequest {
		t.Fatalf("another source was throttled: %d", code)
	}
	// A third source overflows the table (limit 2); nothing refilled, so
	// the table starts over rather than growing.
	if code := status("192.0.2.9"); code != http.StatusBadRequest || len(handler.failures.buckets) > 2 {
		t.Fatalf("table overflow: %d with %d buckets", code, len(handler.failures.buckets))
	}
	now = now.Add(time.Second)
	if code := status("198.51.100.1"); code != http.StatusBadRequest {
		t.Fatalf("refilled source answered %d", code)
	}
}

func TestParseRangeStaysInsideTheGrant(t *testing.T) {
	g := protocol.SandboxFileGrantV1{Offset: 100, MaxBytes: 50}
	for value, want := range map[string][3]uint64{"": {100, 50, 0}, "bytes=100-149": {100, 50, 1}, "bytes=120-": {120, 30, 1}, "bytes=149-149": {149, 1, 1}} {
		offset, length, ranged, ok := parseRange(value, g)
		if !ok || offset != want[0] || length != want[1] || ranged != (want[2] == 1) {
			t.Fatalf("%q = %d %d %v %v", value, offset, length, ranged, ok)
		}
	}
	for _, value := range []string{"bytes=99-120", "bytes=100-150", "bytes=150-", "bytes=-10", "bytes=110-105", "bytes=0-1,5-6", "items=1-2", "bytes=x-"} {
		if _, _, _, ok := parseRange(value, g); ok {
			t.Fatalf("%q accepted", value)
		}
	}
}

func selfSigned(t *testing.T) (tls.Certificate, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "miner"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, certFile, keyFile
}

func TestLoadDirectFilesRefusesIncompleteOrMismatchedSettings(t *testing.T) {
	certificate, certFile, keyFile := selfSigned(t)
	leaf := sha256.Sum256(certificate.Certificate[0])
	pin := hex.EncodeToString(leaf[:])
	if settings, err := loadDirectFiles("", "", "", pin, true, 0, 0); settings != nil || err != nil {
		t.Fatalf("off: %v %v", settings, err)
	}
	for name, args := range map[string]struct {
		bind, cert, key, pin string
		ops                  bool
	}{
		"cert without bind": {"", certFile, keyFile, pin, true},
		"no ops":            {":8094", certFile, keyFile, pin, false},
		"no key":            {":8094", certFile, "", pin, true},
		"other leaf":        {":8094", certFile, keyFile, strings.Repeat("0", 64), true},
		"no pin":            {":8094", certFile, keyFile, "", true},
	} {
		if _, err := loadDirectFiles(args.bind, args.cert, args.key, args.pin, args.ops, 0, 0); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	settings, err := loadDirectFiles(":8094", certFile, keyFile, strings.ToUpper(pin), true, 3, 9)
	if err != nil || settings.config.PerSandbox != 3 || settings.config.Global != 9 {
		t.Fatalf("valid settings: %+v %v", settings, err)
	}
}

// fetchReceipt GETs the held receipt of id with grant as the credential.
func (h *directHarness) fetchReceipt(id, grant string) (int, protocol.SandboxFileReceiptV1) {
	h.t.Helper()
	request, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(h.url, sandbox.DirectFilesPath)+sandbox.DirectFileReceiptsPath+id, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	if grant != "" {
		request.Header.Set(sandbox.DirectFileGrantHeader, grant)
	}
	response, err := h.client.Do(request)
	if err != nil {
		h.t.Fatal(err)
	}
	defer response.Body.Close()
	var receipt protocol.SandboxFileReceiptV1
	if response.StatusCode == http.StatusOK {
		data, _ := io.ReadAll(response.Body)
		if err := organic.DecodeStrict(bytes.TrimSpace(data), &receipt); err != nil {
			h.t.Fatalf("fetched receipt: %v", err)
		}
	}
	return response.StatusCode, receipt
}

func grantNonce(t *testing.T, encoded string) string {
	t.Helper()
	grant, ok := decodeGrantHeader(encoded)
	if !ok {
		t.Fatal("undecodable test grant")
	}
	return grant.Nonce
}

func (h *directHarness) upload(path string, data []byte) {
	h.t.Helper()
	if response, body := h.do(http.MethodPut, h.grant(protocol.DirectFileUpload, path, 0, uint64(len(data))), data, nil); response.StatusCode != http.StatusOK {
		h.t.Fatalf("upload %d %s", response.StatusCode, body)
	}
}

// A completed download's receipt is fetched once with the same grant; it is
// the trailer's receipt, binding the bytes served and the miner's key.
func TestDirectFileReceiptFetchedOnceAfterACompletedDownload(t *testing.T) {
	h := newDirectHarness(t)
	data := []byte("receipt fetch payload")
	h.upload("/workspace/r.bin", data)
	grant := h.grant(protocol.DirectFileDownload, "/workspace/r.bin", 0, uint64(len(data)))
	id := grantNonce(t, grant)
	if status, _ := h.fetchReceipt(id, grant); status != http.StatusNotFound {
		t.Fatalf("fetch before the download answered %d", status)
	}
	response, got := h.do(http.MethodGet, grant, nil, nil)
	if response.StatusCode != http.StatusOK || !bytes.Equal(got, data) {
		t.Fatalf("download %d", response.StatusCode)
	}
	trailer, _ := base64.RawURLEncoding.DecodeString(response.Trailer.Get(sandbox.DirectFileReceiptHeader))
	other := h.grant(protocol.DirectFileDownload, "/workspace/r.bin", 0, uint64(len(data)))
	if status, _ := h.fetchReceipt(grantNonce(t, other), other); status != http.StatusNotFound {
		t.Fatalf("an unused grant fetched %d", status)
	}
	if status, _ := h.fetchReceipt(id, other); status != http.StatusBadRequest {
		t.Fatalf("another grant under this id answered %d", status)
	}
	if status, _ := h.fetchReceipt(id, ""); status != http.StatusBadRequest {
		t.Fatalf("no grant answered %d", status)
	}
	// A different grant reusing the nonce (same id) is not the credential.
	h.nonce -= 2
	twin := h.grant(protocol.DirectFileDownload, "/workspace/r.bin", 0, uint64(len(data))+1)
	if grantNonce(t, twin) != id {
		t.Fatal("twin grant nonce")
	}
	if status, _ := h.fetchReceipt(id, twin); status != http.StatusNotFound {
		t.Fatalf("a twin grant fetched %d", status)
	}
	status, receipt := h.fetchReceipt(id, grant)
	if status != http.StatusOK || protocol.VerifySandboxFileReceiptV1(receipt, h.minerPublic) != nil {
		t.Fatalf("fetch %d", status)
	}
	sum := sha256.Sum256(got)
	digest, _ := protocol.SandboxFileDigestV1(func() protocol.SandboxFileGrantV1 { g, _ := decodeGrantHeader(grant); return g }())
	if receipt.Bytes != uint64(len(got)) || receipt.SHA256 != hex.EncodeToString(sum[:]) || receipt.Nonce != id ||
		receipt.GrantDigest != digest || receipt.MinerID != h.lease.MinerID {
		t.Fatalf("fetched receipt %+v", receipt)
	}
	if encoded, _ := organic.Canonical(receipt); !bytes.Equal(encoded, trailer) {
		t.Fatal("fetched receipt differs from the trailer's")
	}
	if status, _ := h.fetchReceipt(id, grant); status != http.StatusNotFound {
		t.Fatalf("replayed fetch answered %d", status)
	}
}

func TestDirectFileReceiptExpires(t *testing.T) {
	h := newDirectHarness(t)
	data := []byte("expiring")
	h.upload("/workspace/e.bin", data)
	now := time.Now()
	handler := h.handler()
	handler.receipts.now = func() time.Time { return now }
	grant := h.grant(protocol.DirectFileDownload, "/workspace/e.bin", 0, uint64(len(data)))
	if response, _ := h.do(http.MethodGet, grant, nil, nil); response.StatusCode != http.StatusOK {
		t.Fatalf("download %d", response.StatusCode)
	}
	now = now.Add(directReceiptTTL)
	if status, _ := h.fetchReceipt(grantNonce(t, grant), grant); status != http.StatusNotFound {
		t.Fatalf("expired receipt answered %d", status)
	}
}

// A download the client abandons mid-stream leaves nothing to fetch.
func TestDirectFileReceiptNotHeldForAPartialDownload(t *testing.T) {
	h := newDirectHarness(t)
	data := make([]byte, 64<<20)
	h.upload("/workspace/p.bin", data)
	grant := h.grant(protocol.DirectFileDownload, "/workspace/p.bin", 0, uint64(len(data)))
	request, _ := http.NewRequest(http.MethodGet, h.url, nil)
	request.Header.Set(sandbox.DirectFileGrantHeader, grant)
	response, err := h.client.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("download: %v", err)
	}
	if _, err := io.ReadFull(response.Body, make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	h.client.Transport.(*http.Transport).CloseIdleConnections()
	response.Body.Close()
	// The handler's next write fails on the closed connection.
	time.Sleep(time.Second)
	if status, _ := h.fetchReceipt(grantNonce(t, grant), grant); status != http.StatusNotFound {
		t.Fatalf("partial download's receipt answered %d", status)
	}
	if len(h.handler().receipts.entries) != 0 {
		t.Fatal("a partial download's receipt is held")
	}
}

func TestHeldReceiptsStayBounded(t *testing.T) {
	now := time.Unix(1000, 0)
	held := newHeldReceipts(time.Minute, 2, func() time.Time { return now })
	grant := func(n int) protocol.SandboxFileGrantV1 {
		return protocol.SandboxFileGrantV1{Nonce: fmt.Sprintf("%032x", n), Op: protocol.DirectFileDownload}
	}
	for n := range 3 {
		held.put(grant(n), protocol.SandboxFileReceiptV1{Bytes: uint64(n)})
		now = now.Add(time.Second)
	}
	if _, ok := held.take(grant(0)); ok || len(held.entries) != 2 {
		t.Fatalf("oldest not evicted: %d held", len(held.entries))
	}
	if receipt, ok := held.take(grant(2)); !ok || receipt.Bytes != 2 {
		t.Fatal("newest receipt lost")
	}
}

func (h *directHarness) handler() *directFilesHandler { return h.handlerRef }
