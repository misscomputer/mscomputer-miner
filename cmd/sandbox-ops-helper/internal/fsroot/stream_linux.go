// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

//go:build linux

package fsroot

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/sys/unix"

	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

// WriteStream writes exactly length bytes from in at offset of the regular
// file at path, with the same confinement and rules as WriteChunk: offset 0
// creates or atomically replaces the file with exactly mode (temporary file
// plus rename once every byte arrived); a later offset must equal the current
// size and appends. The write is all-or-nothing: a short or failed stream
// leaves no file (offset 0) or truncates the file back to offset, and so
// does a stream whose SHA-256 differs from expectedSHA256 when one is given.
func (r *Root) WriteStream(ctx context.Context, path string, offset, length uint64, in io.Reader, mode *uint32, expectedSHA256 []byte) (sandbox.FileInfo, error) {
	if err := checkPath(path, false); err != nil {
		return sandbox.FileInfo{}, err
	}
	if length == 0 || (offset == 0) != (mode != nil) || (mode != nil && *mode > sandbox.MaxFileModeBits) {
		return sandbox.FileInfo{}, errors.New("fsroot: stream length, offset or mode is invalid")
	}
	if expectedSHA256 != nil && len(expectedSHA256) != sha256.Size {
		return sandbox.FileInfo{}, errors.New("fsroot: expected sha256 is not 32 bytes")
	}
	if offset > sandbox.MaxFileWriteBytes || length > sandbox.MaxFileWriteBytes || offset+length > sandbox.MaxFileWriteBytes {
		return sandbox.FileInfo{}, ErrTooLarge
	}
	if err := ctx.Err(); err != nil {
		return sandbox.FileInfo{}, err
	}
	parent, name, err := r.openParent(path)
	if err != nil {
		return sandbox.FileInfo{}, err
	}
	defer unix.Close(parent)
	if offset == 0 {
		return createReplaceStream(ctx, parent, name, *mode, length, in, expectedSHA256)
	}
	fd, err := unix.Openat(parent, name, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ENXIO) {
		return sandbox.FileInfo{}, ErrNotFile
	}
	if err != nil {
		return sandbox.FileInfo{}, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return sandbox.FileInfo{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return sandbox.FileInfo{}, ErrNotFile
	}
	if uint64(st.Size) != offset {
		return sandbox.FileInfo{}, ErrOffsetMismatch
	}
	if err := copyIn(ctx, fd, int64(offset), length, in, expectedSHA256); err != nil {
		_ = unix.Ftruncate(fd, int64(offset))
		return sandbox.FileInfo{}, err
	}
	if err := unix.Fstat(fd, &st); err != nil {
		return sandbox.FileInfo{}, err
	}
	return fileInfo(&st), nil
}

func copyIn(ctx context.Context, fd int, offset int64, length uint64, in io.Reader, expectedSHA256 []byte) error {
	digest := sha256.New()
	buffer := make([]byte, min(uint64(StreamBufferBytes), length))
	for remaining := length; remaining > 0; {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := io.ReadFull(in, buffer[:min(uint64(len(buffer)), remaining)])
		if n > 0 {
			if werr := pwriteAll(fd, buffer[:n], offset); werr != nil {
				return werr
			}
			digest.Write(buffer[:n])
			offset += int64(n)
			remaining -= uint64(n)
		}
		if err != nil && remaining > 0 {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return ErrShortStream
			}
			return err
		}
	}
	if expectedSHA256 != nil && !bytes.Equal(digest.Sum(nil), expectedSHA256) {
		return ErrDigestMismatch
	}
	return nil
}

func createReplaceStream(ctx context.Context, parent int, name string, mode uint32, length uint64, in io.Reader, expectedSHA256 []byte) (sandbox.FileInfo, error) {
	var existing unix.Stat_t
	switch err := unix.Fstatat(parent, name, &existing, unix.AT_SYMLINK_NOFOLLOW); {
	case err == nil && existing.Mode&unix.S_IFMT != unix.S_IFREG:
		return sandbox.FileInfo{}, ErrNotFile
	case err != nil && !errors.Is(err, unix.ENOENT):
		return sandbox.FileInfo{}, err
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return sandbox.FileInfo{}, err
	}
	temporary := ".sandbox-op-" + hex.EncodeToString(random[:]) + ".tmp"
	fd, err := unix.Openat(parent, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return sandbox.FileInfo{}, err
	}
	committed := false
	defer func() {
		_ = unix.Close(fd)
		if !committed {
			_ = unix.Unlinkat(parent, temporary, 0)
		}
	}()
	if err := copyIn(ctx, fd, 0, length, in, expectedSHA256); err != nil {
		return sandbox.FileInfo{}, err
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return sandbox.FileInfo{}, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return sandbox.FileInfo{}, err
	}
	if err := unix.Renameat(parent, temporary, parent, name); err != nil {
		if errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ENOTEMPTY) || errors.Is(err, unix.EEXIST) {
			return sandbox.FileInfo{}, ErrNotFile
		}
		return sandbox.FileInfo{}, err
	}
	committed = true
	return fileInfo(&st), nil
}

// OpenRead opens the regular file at path for a streamed read with the same
// confinement as ReadAt (in-root, FIFOs, devices and sockets refused without
// blocking) and returns it with its size. The caller closes it.
func (r *Root) OpenRead(ctx context.Context, path string) (io.ReaderAt, io.Closer, uint64, error) {
	if err := checkPath(path, false); err != nil {
		return nil, nil, 0, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, 0, err
	}
	fd, err := r.openIn(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, 0, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, nil, 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, nil, 0, ErrNotFile
	}
	file := &descriptor{fd: fd}
	return file, file, uint64(max(st.Size, 0)), nil
}

type descriptor struct{ fd int }

func (d *descriptor) ReadAt(p []byte, offset int64) (int, error) {
	for {
		n, err := unix.Pread(d.fd, p, offset)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 && len(p) > 0 {
			return 0, io.EOF
		}
		return n, nil
	}
}

func (d *descriptor) Close() error { return unix.Close(d.fd) }
