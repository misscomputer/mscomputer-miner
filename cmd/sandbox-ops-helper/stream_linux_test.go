// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

//go:build linux

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxops"
)

// streamCall runs one streamed request: the JSON line, then body on stdin.
// It returns the decoded response line and the raw bytes after it.
func (h *harness) streamCall(request sandboxops.Request, body []byte) (sandboxops.Response, []byte) {
	h.t.Helper()
	request.Protocol = sandboxops.Protocol
	encoded, err := sandboxops.Encode(request)
	if err != nil {
		h.t.Fatal(err)
	}
	var out bytes.Buffer
	if code := h.server.serve(io.MultiReader(bytes.NewReader(append(encoded, '\n')), bytes.NewReader(body)), &out); code != 0 {
		h.t.Fatalf("serve exit %d", code)
	}
	reader := bufio.NewReader(&out)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		h.t.Fatalf("no response line: %v", err)
	}
	response, err := sandboxops.DecodeResponse(line, request)
	if err != nil {
		h.t.Fatalf("response %q does not answer %s: %v", line, request.Op, err)
	}
	rest, _ := io.ReadAll(reader)
	return response, rest
}

func TestStreamWriteThenRangedStreamRead(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "stream.bin")
	data := make([]byte, 3<<20+5)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	mode := uint32(0o600)
	response, rest := h.streamCall(sandboxops.Request{Op: sandboxops.OpFileStreamWrite, Path: &path, Offset: u64(0), Limit: u64(uint64(len(data))), Mode: &mode}, data)
	if response.Code != nil || response.File == nil || response.File.Size != uint64(len(data)) || len(rest) != 0 {
		t.Fatalf("stream write answered %+v (+%d bytes)", response, len(rest))
	}
	if onDisk, _ := os.ReadFile(path); !bytes.Equal(onDisk, data) {
		t.Fatal("streamed file differs on disk")
	}
	response, rest = h.streamCall(sandboxops.Request{Op: sandboxops.OpFileStreamRead, Path: &path, Offset: u64(1 << 20), Limit: u64(1<<20 + 3)}, nil)
	if response.Code != nil || response.Size == nil || *response.Size != uint64(len(data)) || !bytes.Equal(rest, data[1<<20:2<<20+3]) {
		t.Fatalf("ranged read answered %+v with %d bytes", response, len(rest))
	}
	// A window past the end returns the tail only.
	_, rest = h.streamCall(sandboxops.Request{Op: sandboxops.OpFileStreamRead, Path: &path, Offset: u64(3 << 20), Limit: u64(1 << 20)}, nil)
	if !bytes.Equal(rest, data[3<<20:]) {
		t.Fatalf("tail read returned %d bytes", len(rest))
	}
}

func TestStreamWriteShortBodyFailsWithoutAFile(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "short.bin")
	mode := uint32(0o600)
	response, _ := h.streamCall(sandboxops.Request{Op: sandboxops.OpFileStreamWrite, Path: &path, Offset: u64(0), Limit: u64(1 << 20), Mode: &mode}, []byte("ten bytes!"))
	if response.Code == nil || *response.Code != "stream_short" {
		t.Fatalf("short body answered %+v", response)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("short body left a file: %v", err)
	}
}

// A non-stream op must still be the whole of stdin: trailing bytes after its
// line are refused, never ignored.
func TestNonStreamRequestRefusesTrailingBytes(t *testing.T) {
	h := newHarness(t)
	root := "/"
	request := sandboxops.Request{Protocol: sandboxops.Protocol, Op: sandbox.OpFileStat, Path: &root}
	encoded, err := sandboxops.Encode(request)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	h.server.serve(strings.NewReader(string(encoded)+"\nextra"), &out)
	if !strings.Contains(out.String(), `"code":"sandbox_op_failed"`) {
		t.Fatalf("trailing bytes answered %s", out.String())
	}
	out.Reset()
	h.server.serve(strings.NewReader(string(encoded)+"\n"), &out)
	if strings.Contains(out.String(), `"code"`+":\"sandbox_op_failed\"") {
		t.Fatalf("request with its newline refused: %s", out.String())
	}
}
