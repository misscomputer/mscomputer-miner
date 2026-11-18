// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandbox

import "testing"

func TestDecodeLeaseUsage(t *testing.T) {
	good := `{"cpu_seconds":1.25,"disk_bytes":null,"memory_peak_bytes":4096,"network_bytes":0}`
	u, err := DecodeLeaseUsage([]byte(good))
	if err != nil || *u.CPUSeconds != 1.25 || u.DiskBytes != nil || *u.MemoryPeakBytes != 4096 || *u.NetworkBytes != 0 {
		t.Fatalf("%+v %v", u, err)
	}
	for _, bad := range []string{
		`{}`, `[]`, `null`,
		`{"cpu_seconds":1,"disk_bytes":null,"memory_peak_bytes":1}`,
		`{"cpu_seconds":1,"disk_bytes":null,"memory_peak_bytes":1,"network_bytes":1,"x":1}`,
		`{"cpu_seconds":-1,"disk_bytes":null,"memory_peak_bytes":1,"network_bytes":1}`,
		`{"cpu_seconds":1,"disk_bytes":-1,"memory_peak_bytes":1,"network_bytes":1}`,
		`{"cpu_seconds":1,"disk_bytes":9007199254740992,"memory_peak_bytes":1,"network_bytes":1}`,
		`{"cpu_seconds":"1","disk_bytes":null,"memory_peak_bytes":1,"network_bytes":1}`,
	} {
		if _, err := DecodeLeaseUsage([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
