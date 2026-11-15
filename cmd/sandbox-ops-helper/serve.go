// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"

	"github.com/misscomputer/mscomputer-miner/cmd/sandbox-ops-helper/internal/fsroot"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxops"
)

// captureRoot is the fixed in-sandbox exec capture directory.
const captureRoot = sandboxops.CaptureRoot

// server performs one helper request. openFS opens the sandbox root for file
// operations (fsroot.Open, only "/"); execs serves exec operations under
// their capture root.
type server struct {
	openFS func() (fsroot.FS, error)
	execs  execRunner
}

// execRunner is the exec half of the helper: exec_linux.go on Linux, and an
// ops_unsupported stub elsewhere.
type execRunner interface {
	start(execID string, spec sandboxops.ExecSpec) sandboxops.Response
	read(execID, stream string, offset, limit uint64) sandboxops.Response
	cancel(execID string, force bool) sandboxops.Response
	status(execID string) sandboxops.Response
}

func openRoot() (fsroot.FS, error) { return fsroot.Open() }

// serveProcess serves exactly one request from in to out. A request that
// does not decode is answered sandbox_op_failed: the miner wrote it, so this
// is never a guest-visible state.
func serveProcess(in io.Reader, out io.Writer) int {
	s := &server{openFS: openRoot, execs: newExecRunner(captureRoot, selfExecutable)}
	return s.serve(in, out)
}

func (s *server) serve(in io.Reader, out io.Writer) int {
	response := sandboxops.Failure(sandbox.OpCodeSandboxFailed)
	reader := bufio.NewReaderSize(in, 64<<10)
	payload, err := readRequestLine(reader)
	if err == nil {
		var request sandboxops.Request
		if request, err = sandboxops.DecodeRequest(payload); err == nil && sandboxops.StreamOp(request.Op) {
			return s.serveStream(request, reader, out)
		}
		// Every other op is the whole of stdin, exactly as before.
		var rest []byte
		if err == nil {
			rest, err = sandboxops.ReadBounded(reader, sandboxops.MaxRequestBytes-len(payload))
		}
		if err == nil && len(bytes.TrimSpace(rest)) == 0 {
			response = s.handle(request)
		}
	}
	return writeResponse(out, response)
}

// readRequestLine reads the request: everything up to the first newline (or
// the end of stdin), bounded by MaxRequestBytes. A canonical JSON request
// never contains a raw newline.
func readRequestLine(reader *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > sandboxops.MaxRequestBytes {
			return nil, errors.New("helper request exceeds its bound")
		}
		switch {
		case err == nil, errors.Is(err, io.EOF):
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return nil, err
		}
	}
}

func writeResponse(out io.Writer, response sandboxops.Response) int {
	encoded, err := sandboxops.Encode(response)
	if err != nil {
		encoded, _ = sandboxops.Encode(sandboxops.Failure(sandbox.OpCodeSandboxFailed))
	}
	if _, err := out.Write(append(encoded, '\n')); err != nil {
		return 1
	}
	return 0
}

func (s *server) handle(request sandboxops.Request) sandboxops.Response {
	switch request.Op {
	case sandbox.OpExecStart:
		return s.execs.start(*request.ExecID, *request.Exec)
	case sandbox.OpExecRead:
		return s.execs.read(*request.ExecID, *request.Stream, *request.Offset, *request.Limit)
	case sandbox.OpExecCancel:
		return s.execs.cancel(*request.ExecID, request.Force)
	case sandboxops.OpExecStatus:
		return s.execs.status(*request.ExecID)
	}
	fs, err := s.openFS()
	if err != nil {
		return sandboxops.Failure(fsroot.Code(err))
	}
	defer fs.Close()
	// The 30 s file-op budget (SyncOpBudget) is enforced here as well as by
	// the miner, so a slow walk reports op_deadline_exceeded itself.
	ctx, cancel := context.WithTimeout(context.Background(), sandbox.SyncOpBudget)
	defer cancel()
	response := sandboxops.Response{Protocol: sandboxops.Protocol}
	switch request.Op {
	case sandbox.OpFileStat:
		var info sandbox.FileInfo
		if info, err = fs.Stat(ctx, *request.Path); err == nil {
			response.File = &info
		}
	case sandbox.OpFileRead:
		var data []byte
		var size uint64
		if data, size, err = fs.ReadAt(ctx, *request.Path, *request.Offset, *request.Limit); err == nil {
			response.Data, response.Size = sandboxops.EncodeData(data), &size
		}
	case sandbox.OpFileWrite:
		var info sandbox.FileInfo
		if info, err = fs.WriteChunk(ctx, *request.Path, *request.Offset, request.Bytes(), request.Mode); err == nil {
			response.File = &info
		}
	case sandbox.OpFileList:
		var listing sandbox.ListResult
		var done bool
		if listing, done, err = fs.List(ctx, *request.Path, *request.Offset, *request.Limit); err == nil {
			response.Listing, response.EOF = &listing, done
		}
	case sandbox.OpFileRemove:
		err = fs.Remove(ctx, *request.Path, *request.Recursive)
	case sandbox.OpFileMkdir:
		var info sandbox.FileInfo
		if info, err = fs.Mkdir(ctx, *request.Path, *request.Mode, *request.Recursive); err == nil {
			response.File = &info
		}
	}
	if err != nil {
		return sandboxops.Failure(fsroot.Code(err))
	}
	return response
}

// serveStream serves one streamed transfer. A write takes exactly limit raw
// bytes after the request line and answers the file; a read answers the
// file size and then writes the raw bytes from offset, at most limit. The
// transfer has no helper-side deadline: the miner bounds it and ends it by
// closing the exec's streams.
func (s *server) serveStream(request sandboxops.Request, in io.Reader, out io.Writer) int {
	fs, err := s.openFS()
	if err != nil {
		return writeResponse(out, sandboxops.Failure(fsroot.Code(err)))
	}
	defer fs.Close()
	streams, ok := fs.(fsroot.StreamFS)
	if !ok {
		return writeResponse(out, sandboxops.Failure(sandbox.OpCodeOpsUnsupport))
	}
	ctx := context.Background()
	if request.Op == sandboxops.OpFileStreamWrite {
		var expected []byte
		if request.SHA256 != nil {
			expected, _ = hex.DecodeString(*request.SHA256)
		}
		info, err := streams.WriteStream(ctx, *request.Path, *request.Offset, *request.Limit, in, request.Mode, expected)
		if err != nil {
			return writeResponse(out, sandboxops.Failure(fsroot.Code(err)))
		}
		return writeResponse(out, sandboxops.Response{Protocol: sandboxops.Protocol, File: &info})
	}
	file, closer, size, err := streams.OpenRead(ctx, *request.Path)
	if err != nil {
		return writeResponse(out, sandboxops.Failure(fsroot.Code(err)))
	}
	defer closer.Close()
	if status := writeResponse(out, sandboxops.Response{Protocol: sandboxops.Protocol, Size: &size}); status != 0 {
		return status
	}
	if *request.Offset >= size {
		return 0
	}
	length := min(*request.Limit, size-*request.Offset)
	buffer := make([]byte, min(uint64(fsroot.StreamBufferBytes), length))
	if _, err := io.CopyBuffer(out, io.NewSectionReader(file, int64(*request.Offset), int64(length)), buffer); err != nil {
		return 1
	}
	return 0
}
