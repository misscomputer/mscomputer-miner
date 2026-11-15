// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxhost

import (
	"strings"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

// The data filesystem floor of the network cap with the reference overheads
// is the reference value for a 10 GiB image.
func TestDataFSFloorOfTheNetworkCap(t *testing.T) {
	a := ProfileAggregate{LogMiB: 16, EngineOverheadMiB: 512, ImageReserveMiB: 512}
	if got := a.DataFSFloorMiB(sandbox.MaxTenantImageMiB); got != 31760 {
		t.Fatalf("data fs floor %d, want 31760", got)
	}
	if got := a.DataFSFloorMiB(1024); got != 7184 {
		t.Fatalf("testnet data fs floor %d, want 7184", got)
	}
}

func TestImageCapIsNetworkWideExceptOnATestnet(t *testing.T) {
	for _, test := range []struct {
		cap     int
		network string
		netuid  uint
		want    string
	}{
		{10240, "finney", 24, ""},
		{10240, "", 0, ""},
		{1024, "test", 581, ""},
		{4095, "test", 581, ""},
		{1024, "finney", 24, "only allowed on an allowlisted testnet"},
		{1024, "test", 24, "only allowed on an allowlisted testnet"},
		{1024, "local", 581, "only allowed on an allowlisted testnet"},
		{1024, "archive", 581, "only allowed on an allowlisted testnet"},
		{1024, "wss://test.finney.opentensor.ai:443", 581, "only allowed on an allowlisted testnet"},
		{1024, "", 581, "only allowed on an allowlisted testnet"},
		{1023, "test", 581, "must be 1024..10240"},
		{10241, "test", 581, "must be 1024..10240"},
	} {
		err := CheckImageCap(test.cap, test.network, test.netuid)
		if test.want == "" && err != nil || test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
			t.Errorf("CheckImageCap(%d, %q, %d) = %v, want %q", test.cap, test.network, test.netuid, err, test.want)
		}
	}
}

// The capacity floor is strictly above one standard sandbox in every
// dimension, and the standard sandbox (the capture lease) fits inside it.
func TestCapacityFloorIsAboveOneStandardSandbox(t *testing.T) {
	cpu, memory, disk := CapacityFloor(sandbox.MaxTenantImageMiB)
	if cpu != 2000 || memory != 6144 || disk != 20480 {
		t.Fatalf("capacity floor %d/%d/%d, want 2000/6144/20480", cpu, memory, disk)
	}
	scpu, smemory, sdisk := StandardSlot(sandbox.MaxTenantImageMiB)
	if scpu != 1000 || smemory != 4096 || sdisk != 10240 {
		t.Fatalf("standard sandbox %d/%d/%d, want 1000/4096/10240", scpu, smemory, sdisk)
	}
	if !(scpu < cpu && smemory < memory && sdisk < disk) {
		t.Fatal("the standard sandbox must be strictly below the capacity floor")
	}
	if err := (sandbox.Resources{CPUMillis: scpu, MemoryMiB: smemory, DiskMiB: sdisk, PIDs: sandbox.MinPIDs}).Validate(); err != nil {
		t.Fatalf("the standard sandbox is not a valid lease: %v", err)
	}
	// A testnet cap keeps the lease-class slot for both.
	if c, m, d := CapacityFloor(1024); c != 1000 || m != 1024 || d != 5120 {
		t.Fatalf("testnet floor %d/%d/%d", c, m, d)
	}
}
