// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxops"
)

// runHelper answers like a helper whose exec runs for `polls` exec_read
// calls and then exits with the given output.
func runHelper(t *testing.T, polls int64, stdout, stderr []byte, running func() bool) func(context.Context, sandboxops.Request) ([]byte, error) {
	var reads atomic.Int64
	return func(_ context.Context, request sandboxops.Request) ([]byte, error) {
		zero := 0
		observation := sandboxops.ExecObservation{State: sandbox.ExecStateRunning}
		if request.Op == sandbox.OpExecRead {
			reads.Add(1)
		}
		if reads.Load() > polls && (running == nil || !running()) {
			observation = sandboxops.ExecObservation{State: sandbox.ExecStateExited, ExitCode: &zero,
				StdoutBytes: uint64(len(stdout)), StdoutRetained: uint64(len(stdout)),
				StderrBytes: uint64(len(stderr)), StderrRetained: uint64(len(stderr))}
		}
		if request.Op != sandbox.OpExecRead {
			return helperOut(t, sandboxops.Response{Exec: &observation}), nil
		}
		stream := stdout
		retained := observation.StdoutRetained
		if *request.Stream == sandbox.ExecStderr {
			stream, retained = stderr, observation.StderrRetained
		}
		from := min(*request.Offset, retained)
		data := stream[from:min(retained, from+*request.Limit)]
		return helperOut(t, sandboxops.Response{Exec: &observation, Data: sandboxops.EncodeData(data)}), nil
	}
}

func (f *opsFixture) execRun(timeoutMS, maxOutput uint64) protocol.SandboxOpRequestV1 {
	return f.op(sandbox.OpExecRun, func(r *protocol.SandboxOpRequestV1) {
		f.withPayload(r, execPayload)
		r.TimeoutMS, r.MaxOutputBytes = u64(timeoutMS), u64(maxOutput)
	})
}

// An exec_run whose exec ends inside the wait answers exited in one op, with
// stdout then stderr in its result and next_offset at stderr. Its exact
// replay starts nothing again. A result split differently is refused.
func TestSandboxExecRunAnswersAnExitedExecWithBothStreams(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.backend.answer = runHelper(t, 2, []byte("hi\n"), []byte("oops"), nil)
	run := f.execRun(60_000, 1024)
	receipt, result, err := f.run(run, execPayload)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, run, result, sandbox.OpStageExited, "")
	if string(result) != "hi\noops" || *receipt.NextOffset != 3 || !receipt.EOF || *receipt.Exec.ExitCode != 0 {
		t.Fatalf("result %q next=%d eof=%v exec=%+v", result, *receipt.NextOffset, receipt.EOF, receipt.Exec)
	}
	replay, replayResult, err := f.run(run, execPayload)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(replay, run, replayResult, sandbox.OpStageExited, "")
	if !bytes.Equal(replayResult, result) || f.backend.count(sandbox.OpExecStart) != 1 {
		t.Fatalf("replay %q, %d helper starts", replayResult, f.backend.count(sandbox.OpExecStart))
	}
	shifted := receipt
	next := uint64(4)
	shifted.NextOffset = &next
	if err := protocol.SandboxOpReceiptAnswersV1(shifted, run, result); err == nil {
		t.Fatal("a result split at the wrong offset was accepted")
	}
	noEOF := receipt
	noEOF.EOF = false
	if err := protocol.SandboxOpReceiptAnswersV1(noEOF, run, result); err == nil {
		t.Fatal("a complete result without eof was accepted")
	}
	// The exec stays readable under the run's own ID.
	read := f.execOp(sandbox.OpExecRead, protocol.SandboxOpIDV1(run))
	readReceipt, readResult, err := f.run(read, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(readReceipt, read, readResult, sandbox.OpStageExited, "")
	if string(readResult) != "hi\n" {
		t.Fatalf("read %q", readResult)
	}
}

// An exec still running when the wait ends answers running without output;
// it is then read, and resolved, like a started exec.
func TestSandboxExecRunAnswersRunningWhenTheWaitEnds(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	var hold atomic.Bool
	hold.Store(true)
	f.backend.answer = runHelper(t, 0, []byte("late\n"), nil, hold.Load)
	run := f.execRun(60_000, 1024)
	go func() {
		// Moves the lane's clock past the wait once the run is waiting.
		for f.backend.count(sandbox.OpExecRead) < 2 {
			time.Sleep(time.Millisecond)
		}
		f.clock.Add(sandbox.ExecRunWait + time.Second)
	}()
	receipt, result, err := f.run(run, execPayload)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, run, result, sandbox.OpStageRunning, "")
	if result != nil || receipt.ResultDigest != nil || receipt.NextOffset != nil {
		t.Fatalf("a running exec_run carried a result: %+v", receipt)
	}
	hold.Store(false)
	read := f.execOp(sandbox.OpExecRead, protocol.SandboxOpIDV1(run))
	readReceipt, readResult, err := f.run(read, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(readReceipt, read, readResult, sandbox.OpStageExited, "")
	if string(readResult) != "late\n" || !readReceipt.EOF {
		t.Fatalf("read %q eof=%v", readResult, readReceipt.EOF)
	}
}

// Each stream contributes at most ExecRunStreamBytes; a longer one leaves
// eof false so the rest is read with exec_read.
func TestSandboxExecRunCapsEachStream(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	stdout := bytes.Repeat([]byte("a"), sandbox.ExecRunStreamBytes+100)
	f.backend.answer = runHelper(t, 0, stdout, []byte("e"), nil)
	run := f.execRun(60_000, 1<<20)
	receipt, result, err := f.run(run, execPayload)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, run, result, sandbox.OpStageExited, "")
	if *receipt.NextOffset != sandbox.ExecRunStreamBytes || len(result) != sandbox.ExecRunStreamBytes+1 || receipt.EOF ||
		result[len(result)-1] != 'e' {
		t.Fatalf("next=%d len=%d eof=%v", *receipt.NextOffset, len(result), receipt.EOF)
	}
}
