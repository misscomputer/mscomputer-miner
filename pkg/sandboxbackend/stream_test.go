// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/miner"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxops"
)

func streamBackend(t *testing.T) (*host, *GVisor, string) {
	t.Helper()
	helper := pinnedHelper(t, "helper binary")
	h := newHost(t)
	h.engine.applied = mountAsAsked(nil)
	b := h.backend()
	opsMode(t, b, helper)
	lease := testLease(nil)
	instance := instanceOf(lease)
	if err := b.Create(context.Background(), instance, lease); err != nil {
		t.Fatal(err)
	}
	return h, b, instance
}

// StreamHelper sends the request line and then the whole body as stdin of
// the same pinned helper exec, returns the first stdout line, and copies
// every later stdout byte (across frames, stderr dropped) to the sink.
func TestStreamHelperCarriesBodyAndStreamsStdout(t *testing.T) {
	h, b, instance := streamBackend(t)
	body := make([]byte, 3<<20+11)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	h.engine.ops = &fakeOpsEngine{helper: func(stdin []byte) ([]byte, []byte, int) {
		head, rest, _ := bytes.Cut(stdin, []byte("\n"))
		// Answer the head, then echo the body back after the line.
		return append(append(append([]byte{}, head...), '\n'), rest...), []byte("guest noise"), 0
	}}
	var sink bytes.Buffer
	line, copied, err := b.StreamHelper(context.Background(), instance, []byte(`{"op":"x"}`), bytes.NewReader(body), &sink)
	if err != nil || string(line) != "{\"op\":\"x\"}\n" || copied != int64(len(body)) || !bytes.Equal(sink.Bytes(), body) {
		t.Fatalf("StreamHelper = %q, %d, %v", line, copied, err)
	}
	if got := h.engine.ops.stdins[0]; !bytes.Equal(got, append([]byte("{\"op\":\"x\"}\n"), body...)) {
		t.Fatalf("helper stdin was %d bytes", len(got))
	}
	if body := h.engine.ops.bodies[0]; body["User"] != "" || body["Privileged"] != false {
		t.Fatalf("exec create body = %v", body)
	}
}

func TestStreamHelperRefusals(t *testing.T) {
	h, b, instance := streamBackend(t)
	h.engine.ops = &fakeOpsEngine{helper: func([]byte) ([]byte, []byte, int) { return []byte("answer\nextra"), nil, 0 }}
	if _, _, err := b.StreamHelper(context.Background(), instance, []byte("a\nb"), nil, nil); err == nil {
		t.Fatal("multi-line request accepted")
	}
	// No sink: bytes after the answer are a protocol break.
	if _, _, err := b.StreamHelper(context.Background(), instance, []byte("req"), nil, nil); err == nil {
		t.Fatal("bytes after the answer accepted without a sink")
	}
	h.engine.ops.helper = func([]byte) ([]byte, []byte, int) { return []byte("answer\n"), nil, 1 }
	if _, _, err := b.StreamHelper(context.Background(), instance, []byte("req"), nil, nil); err == nil {
		t.Fatal("nonzero helper exit accepted")
	}
	h.engine.ops.helper = func([]byte) ([]byte, []byte, int) { return nil, nil, 0 }
	if _, _, err := b.StreamHelper(context.Background(), instance, []byte("req"), nil, io.Discard); err == nil {
		t.Fatal("empty answer accepted")
	}
	h.engine.mu.Lock()
	h.engine.containers[instance].Status = "exited"
	h.engine.mu.Unlock()
	if _, _, err := b.StreamHelper(context.Background(), instance, []byte("req"), nil, nil); !errors.Is(err, miner.ErrSandboxNotRunning) {
		t.Fatalf("stopped sandbox: %v", err)
	}
	b.opsHelper = nil
	if _, _, err := b.StreamHelper(context.Background(), instance, []byte("req"), nil, nil); err == nil {
		t.Fatal("stream without ops mode accepted")
	}
}

// stdoutFrames joins stdout across frames, drops stderr within its bound,
// and refuses unknown frames, oversized stderr and truncated frames.
func TestStdoutFramesReader(t *testing.T) {
	frame := func(stream byte, data string) string {
		var header [8]byte
		header[0] = stream
		binary.BigEndian.PutUint32(header[4:], uint32(len(data)))
		return string(header[:]) + data
	}
	read := func(stream string) (string, error) {
		data, err := io.ReadAll(&stdoutFrames{reader: strings.NewReader(stream)})
		return string(data), err
	}
	if got, err := read(frame(1, "ab") + frame(2, "noise") + frame(1, "cd")); err != nil || got != "abcd" {
		t.Fatalf("frames = %q, %v", got, err)
	}
	for name, stream := range map[string]string{
		"unknown":   frame(3, "x"),
		"stderr":    frame(2, strings.Repeat("e", maxHelperStderrBytes+1)),
		"truncated": frame(1, "abcdef")[:10],
	} {
		if _, err := read(stream); err == nil {
			t.Fatalf("%s frame accepted", name)
		}
	}
	_ = sandboxops.MaxResponseBytes
}
