// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

//go:build linux

package fsroot

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return data
}

func readAll(t *testing.T, r *Root, path string) []byte {
	t.Helper()
	at, closer, size, err := r.OpenRead(context.Background(), path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer closer.Close()
	data, err := io.ReadAll(io.NewSectionReader(at, 0, int64(size)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A multi-buffer stream lands byte-exact with its mode; appending at the
// current size extends it; a wrong offset is refused.
func TestWriteStreamCreatesAndAppends(t *testing.T) {
	r, root, _ := hostileTree(t)
	ctx := context.Background()
	first := randomBytes(t, 3*StreamBufferBytes+17)
	mode := uint32(0o640)
	info, err := r.WriteStream(ctx, "/workspace/big.bin", 0, uint64(len(first)), bytes.NewReader(first), &mode, nil)
	if err != nil || info.Size != uint64(len(first)) || info.Mode != 0o640 {
		t.Fatalf("create: %+v %v", info, err)
	}
	second := randomBytes(t, StreamBufferBytes+1)
	if info, err = r.WriteStream(ctx, "/workspace/big.bin", uint64(len(first)), uint64(len(second)), bytes.NewReader(second), nil, nil); err != nil ||
		info.Size != uint64(len(first)+len(second)) {
		t.Fatalf("append: %+v %v", info, err)
	}
	if got := readAll(t, r, "/workspace/big.bin"); !bytes.Equal(got, append(first, second...)) {
		t.Fatal("streamed content differs")
	}
	if _, err := r.WriteStream(ctx, "/workspace/big.bin", 5, 1, strings.NewReader("x"), nil, nil); code(err) != "offset_mismatch" {
		t.Fatalf("wrong offset: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(root, "workspace")); len(entries) != 7 {
		t.Fatalf("temporary files left behind: %d entries", len(entries))
	}
}

// A short stream is all-or-nothing: no file at offset 0 (and an existing
// file is left untouched), and an append is truncated back to its offset.
func TestWriteStreamShortStreamLeavesNoPartialData(t *testing.T) {
	r, root, _ := hostileTree(t)
	ctx := context.Background()
	mode := uint32(0o644)
	if _, err := r.WriteStream(ctx, "/workspace/new.bin", 0, 100, strings.NewReader("only ten b"), &mode, nil); !errors.Is(err, ErrShortStream) ||
		code(err) != "stream_short" {
		t.Fatalf("short create: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "workspace", "new.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("short create left a file: %v", err)
	}
	if _, err := r.WriteStream(ctx, "/workspace/real.txt", 0, 100, strings.NewReader("short"), &mode, nil); !errors.Is(err, ErrShortStream) {
		t.Fatalf("short replace: %v", err)
	}
	if got := readAll(t, r, "/workspace/real.txt"); string(got) != "inside" {
		t.Fatalf("short replace changed the file: %q", got)
	}
	if _, err := r.WriteStream(ctx, "/workspace/real.txt", 6, 100, strings.NewReader("short"), nil, nil); !errors.Is(err, ErrShortStream) {
		t.Fatalf("short append: %v", err)
	}
	if got := readAll(t, r, "/workspace/real.txt"); string(got) != "inside" {
		t.Fatalf("short append was not truncated back: %q", got)
	}
	entries, _ := os.ReadDir(filepath.Join(root, "workspace"))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".sandbox-op-") {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}

// Streams resolve exactly like chunks: no symlink or ".." escape for reads
// or writes, the final component is never written through.
func TestStreamsStayInsideTheRoot(t *testing.T) {
	r, _, outside := hostileTree(t)
	ctx := context.Background()
	mode := uint32(0o644)
	for _, path := range []string{"/workspace/abs/secret", "/workspace/up/secret", "/workspace/hostdir/keep"} {
		if _, _, _, err := r.OpenRead(ctx, path); err == nil {
			t.Fatalf("read escaped through %s", path)
		}
		if _, err := r.WriteStream(ctx, path, 0, 4, strings.NewReader("evil"), &mode, nil); err == nil {
			t.Fatalf("write escaped through %s", path)
		}
	}
	// Final-component symlink: replaced by offset 0 (never written through),
	// refused for an append.
	if _, err := r.WriteStream(ctx, "/workspace/abssec", 4, 4, strings.NewReader("evil"), nil, nil); err == nil {
		t.Fatal("append wrote through a final symlink")
	}
	for _, path := range []string{"/workspace/../etc/passwd", "relative", "/"} {
		if _, err := r.WriteStream(ctx, path, 0, 1, strings.NewReader("x"), &mode, nil); err == nil {
			t.Fatalf("invalid path %q accepted", path)
		}
	}
	if secret, _ := os.ReadFile(filepath.Join(outside, "secret")); string(secret) != "host secret" {
		t.Fatalf("host file changed: %q", secret)
	}
	if _, _, _, err := r.OpenRead(ctx, "/workspace"); code(err) != "path_not_file" {
		t.Fatalf("directory read: %v", err)
	}
}

func TestWriteStreamBounds(t *testing.T) {
	r, _, _ := hostileTree(t)
	ctx := context.Background()
	mode := uint32(0o644)
	if _, err := r.WriteStream(ctx, "/workspace/x", 0, 0, strings.NewReader(""), &mode, nil); err == nil {
		t.Fatal("empty stream accepted")
	}
	if _, err := r.WriteStream(ctx, "/workspace/x", 0, 1<<40, strings.NewReader(""), &mode, nil); code(err) != "file_too_large" {
		t.Fatalf("oversized stream: %v", err)
	}
	if _, err := r.WriteStream(ctx, "/workspace/x", 0, 1, strings.NewReader("x"), nil, nil); err == nil {
		t.Fatal("offset 0 without mode accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := r.WriteStream(cancelled, "/workspace/x", 0, 1, strings.NewReader("x"), &mode, nil); code(err) != "op_deadline_exceeded" && err == nil {
		t.Fatalf("cancelled stream: %v", err)
	}
}

// An expected SHA-256 is checked before the write commits: a mismatch
// leaves no new file, keeps a replaced file, and truncates an append back.
func TestWriteStreamExpectedDigest(t *testing.T) {
	r, _, _ := hostileTree(t)
	ctx := context.Background()
	mode := uint32(0o644)
	data := randomBytes(t, StreamBufferBytes+3)
	right := sha256.Sum256(data)
	wrong := sha256.Sum256([]byte("other"))
	if _, err := r.WriteStream(ctx, "/workspace/real.txt", 0, uint64(len(data)), bytes.NewReader(data), &mode, wrong[:]); code(err) != "sha256_mismatch" {
		t.Fatalf("mismatched replace: %v", err)
	}
	if got := readAll(t, r, "/workspace/real.txt"); string(got) != "inside" {
		t.Fatalf("mismatched replace changed the file: %q", got)
	}
	if _, err := r.WriteStream(ctx, "/workspace/real.txt", 6, uint64(len(data)), bytes.NewReader(data), nil, wrong[:]); code(err) != "sha256_mismatch" {
		t.Fatalf("mismatched append: %v", err)
	}
	if got := readAll(t, r, "/workspace/real.txt"); string(got) != "inside" {
		t.Fatalf("mismatched append was not truncated: %q", got)
	}
	if _, err := r.WriteStream(ctx, "/workspace/real.txt", 6, uint64(len(data)), bytes.NewReader(data), nil, right[:]); err != nil {
		t.Fatalf("matching append: %v", err)
	}
	if got := readAll(t, r, "/workspace/real.txt"); !bytes.Equal(got, append([]byte("inside"), data...)) {
		t.Fatal("matching append content differs")
	}
}
