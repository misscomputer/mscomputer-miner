// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxops"
)

func (f *opsFixture) leaseStatus() (protocol.SandboxOpRequestV1, protocol.SandboxOpReceiptV1, error) {
	request := f.op(sandbox.OpLeaseStatus, nil)
	receipt, result, err := f.run(request, nil)
	if result != nil {
		f.t.Fatalf("lease_status returned result bytes: %q", result)
	}
	return request, receipt, err
}

// noHelper fails the test if anything enters the guest.
func (f *opsFixture) noHelper() {
	f.t.Cleanup(func() {
		if runs := f.backend.helperRuns.Load(); runs != 0 {
			f.t.Errorf("lease_status entered the guest %d time(s)", runs)
		}
	})
	f.backend.answer = func(context.Context, sandboxops.Request) ([]byte, error) {
		f.t.Error("lease_status ran the in-sandbox helper")
		return nil, errors.New("no helper")
	}
}

func TestLeaseStatusAnswersRunningFromTheEngineOnly(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.noHelper()
	var inspected string
	f.backend.running = func(_ context.Context, instance string) (bool, error) {
		inspected = instance
		return true, nil
	}
	request, receipt, err := f.leaseStatus()
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, request, nil, sandbox.OpStageCompleted, "")
	if want := SandboxInstanceName(protocol.SandboxLeaseIDV1(f.lease)); inspected != want {
		t.Fatalf("inspected %q, want %q", inspected, want)
	}
	if len(f.backend.calls) != 0 {
		t.Fatalf("helper calls: %v", f.backend.calls)
	}
}

// The container stopped behind a lease the store still calls running: the
// answer must not be running, and Renew's store-only "ready" is no substitute.
func TestLeaseStatusOfAStoppedContainerIsNotRunning(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.noHelper()
	f.backend.running = func(context.Context, string) (bool, error) { return false, nil }
	request, receipt, err := f.leaseStatus()
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, request, nil, sandbox.OpStageRefused, "sandbox_exited")
}

func TestLeaseStatusOfAnEngineWithoutAnswerFails(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.noHelper()
	f.backend.running = func(context.Context, string) (bool, error) { return true, errors.New("no socket") }
	request, receipt, err := f.leaseStatus()
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, request, nil, sandbox.OpStageFailed, sandbox.OpCodeRuntimeFailed)
}

func TestLeaseStatusOfAHungInspectTimesOut(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.noHelper()
	f.backend.running = func(ctx context.Context, _ string) (bool, error) {
		<-ctx.Done()
		return true, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	request := f.op(sandbox.OpLeaseStatus, nil)
	receipt, _, err := f.lane.Op(ctx, request, nil, f.request())
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, request, nil, sandbox.OpStageTimedOut, sandbox.OpCodeDeadline)
}

// A released or expired lease is answered from the store; the engine is not
// asked about a sandbox the lane no longer owns.
func TestLeaseStatusOfAnEndedLeaseIsRefusedWithoutInspect(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.noHelper()
	receipt, err := f.lane.Release(context.Background(), f.release, f.request())
	f.check(receipt, err, protocol.SandboxReleaseSchema, f.release, sandbox.StageReleased, "")
	request, answer, err := f.leaseStatus()
	if err != nil {
		t.Fatal(err)
	}
	f.verify(answer, request, nil, sandbox.OpStageRefused, "released")
	if f.backend.inspects != 0 {
		t.Fatalf("inspects: %d", f.backend.inspects)
	}
}

// A tenant at the in-flight bound spends nothing of it, and a lease_status
// neither takes a slot nor waits for one.
func TestLeaseStatusNeedsNoInFlightSlot(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.noHelper()
	ops := f.lane.ops
	var held []func()
	for {
		release, ok := ops.reserve(1)
		if !ok {
			break
		}
		held = append(held, release)
	}
	defer func() {
		for _, release := range held {
			release()
		}
	}()
	request, receipt, err := f.leaseStatus()
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, request, nil, sandbox.OpStageCompleted, "")
	if _, _, err := f.run(f.op(sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) { r.Path = text("/") }), nil); !errors.Is(err, ErrSandboxOpsBusy) {
		t.Fatalf("ordinary op at the bound: %v", err)
	}
	ops.mu.Lock()
	inflight := ops.inflight
	ops.mu.Unlock()
	if inflight != testOpsConfig.MaxInFlight {
		t.Fatalf("lease_status moved the in-flight count to %d", inflight)
	}
}

// An exact replay reads again; it moves no lease and no exec.
func TestLeaseStatusLeavesTheLeaseAlone(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.noHelper()
	request := f.op(sandbox.OpLeaseStatus, nil)
	first, _, err := f.run(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Add(time.Second)
	second, _, err := f.run(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Stage != sandbox.OpStageCompleted || second.Stage != sandbox.OpStageCompleted || first.ObservedAt == second.ObservedAt {
		t.Fatalf("replay answers: %+v %+v", first, second)
	}
	if f.backend.inspects != 2 {
		t.Fatalf("a replay must inspect again: %d", f.backend.inspects)
	}
	// Past the unchanged lease expiry the same store answers expired.
	f.clock.Set(mustParseStamp(t, f.lease.LeaseExpiresAt).Add(time.Second))
	again := f.op(sandbox.OpLeaseStatus, nil)
	answer, _, err := f.run(again, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(answer, again, nil, sandbox.OpStageRefused, "lease_expired")
}

func mustParseStamp(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestLeaseStatusRefusesAPayload(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.noHelper()
	request := f.op(sandbox.OpLeaseStatus, nil)
	if _, _, err := f.run(request, []byte("x")); err == nil {
		t.Fatal("lease_status accepted a payload")
	}
	if f.backend.inspects != 0 {
		t.Fatalf("inspects: %d", f.backend.inspects)
	}
}
