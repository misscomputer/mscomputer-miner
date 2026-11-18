// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import (
	"context"
	"errors"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

func TestLeaseUsageAnswersTheBackendMeasurementWithoutEnteringTheGuest(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.noHelper()
	cpu, peak := 1.5, uint64(1<<20)
	var measured string
	f.backend.usage = func(_ context.Context, instance string) (sandbox.LeaseUsage, error) {
		measured = instance
		return sandbox.LeaseUsage{CPUSeconds: &cpu, MemoryPeakBytes: &peak}, nil
	}
	request := f.op(sandbox.OpLeaseUsage, nil)
	receipt, result, err := f.run(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, request, result, sandbox.OpStageCompleted, "")
	usage, err := sandbox.DecodeLeaseUsage(result)
	if err != nil || *usage.CPUSeconds != cpu || *usage.MemoryPeakBytes != peak || usage.DiskBytes != nil || usage.NetworkBytes != nil {
		t.Fatalf("usage %s: %v", result, err)
	}
	if want := SandboxInstanceName(protocol.SandboxLeaseIDV1(f.lease)); measured != want {
		t.Fatalf("measured %q, want %q", measured, want)
	}
}

func TestLeaseUsageOfAStoppedSandboxIsRefused(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.noHelper()
	f.backend.usage = func(context.Context, string) (sandbox.LeaseUsage, error) {
		return sandbox.LeaseUsage{}, ErrSandboxNotRunning
	}
	request := f.op(sandbox.OpLeaseUsage, nil)
	receipt, result, err := f.run(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, request, result, sandbox.OpStageRefused, "sandbox_exited")
}

func TestLeaseUsageOfAFailedMeasurementFails(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.noHelper()
	f.backend.usage = func(context.Context, string) (sandbox.LeaseUsage, error) {
		return sandbox.LeaseUsage{}, errors.New("engine gone")
	}
	request := f.op(sandbox.OpLeaseUsage, nil)
	receipt, result, err := f.run(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, request, result, sandbox.OpStageFailed, sandbox.OpCodeRuntimeFailed)
}
