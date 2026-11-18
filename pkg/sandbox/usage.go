// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
)

// MaxLeaseUsageBytes bounds an encoded LeaseUsage.
const MaxLeaseUsageBytes = 1024

// LeaseUsage is a miner's own measurement of one running sandbox, the result
// of a lease_usage. Each member is null when the miner could not measure it.
// It is informational: the miner reports it and could misreport it, so
// nothing scores, bills or limits by it.
type LeaseUsage struct {
	// CPUSeconds is the sandbox cgroup's cumulative CPU time.
	CPUSeconds *float64 `json:"cpu_seconds"`
	// MemoryPeakBytes is the sandbox cgroup's peak memory use.
	MemoryPeakBytes *uint64 `json:"memory_peak_bytes"`
	// DiskBytes is the size of the sandbox's writable root layer.
	DiskBytes *uint64 `json:"disk_bytes"`
	// NetworkBytes is the bytes received plus sent on the sandbox's
	// interfaces other than loopback.
	NetworkBytes *uint64 `json:"network_bytes"`
}

// DecodeLeaseUsage strictly decodes a lease_usage result: one bounded JSON
// object with exactly the LeaseUsage members, each null or a finite
// non-negative number within the JSON safe integer range.
func DecodeLeaseUsage(raw []byte) (LeaseUsage, error) {
	var u LeaseUsage
	if len(raw) > MaxLeaseUsageBytes {
		return u, errors.New("lease usage is too large")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || len(members) != 4 {
		return u, errors.New("lease usage is not an object of exactly its four members")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&u); err != nil {
		return LeaseUsage{}, errors.New("lease usage is invalid")
	}
	for _, v := range []*uint64{u.MemoryPeakBytes, u.DiskBytes, u.NetworkBytes} {
		if v != nil && *v > MaxSafeInteger {
			return LeaseUsage{}, errors.New("lease usage member is out of range")
		}
	}
	if c := u.CPUSeconds; c != nil && (math.IsNaN(*c) || *c < 0 || *c > MaxSafeInteger) {
		return LeaseUsage{}, errors.New("lease usage cpu_seconds is out of range")
	}
	return u, nil
}
