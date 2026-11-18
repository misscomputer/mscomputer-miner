// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/misscomputer/mscomputer-miner/pkg/miner"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

// Usage measures the running sandbox instanceID for lease_usage from the
// host side only: CPU time and peak memory from the sandbox process's cgroup
// below the slice, network bytes from that process's network namespace, and
// disk bytes from the engine's size of the container's writable layer. It
// starts no exec, so nothing enters the guest. A member it cannot read is
// null; only a sandbox that is not running is an error.
func (b *GVisor) Usage(ctx context.Context, instanceID string) (sandbox.LeaseUsage, error) {
	var c struct {
		SizeRw *int64 `json:"SizeRw"`
		State  struct {
			Running bool `json:"Running"`
			Pid     int  `json:"Pid"`
		} `json:"State"`
	}
	err := b.engine.call(ctx, http.MethodGet, "/containers/"+url.PathEscape(instanceID)+"/json", url.Values{"size": {"true"}}, nil, &c)
	if engineStatus(err) == http.StatusNotFound {
		return sandbox.LeaseUsage{}, miner.ErrSandboxNotRunning
	} else if err != nil {
		return sandbox.LeaseUsage{}, fmt.Errorf("inspect sandbox %s: %w", instanceID, err)
	}
	if !c.State.Running || c.State.Pid <= 0 {
		return sandbox.LeaseUsage{}, miner.ErrSandboxNotRunning
	}
	var u sandbox.LeaseUsage
	if c.SizeRw != nil && *c.SizeRw >= 0 {
		size := uint64(*c.SizeRw)
		u.DiskBytes = &size
	}
	proc := filepath.Join(b.config.ProcRoot, strconv.Itoa(c.State.Pid))
	if cgroup, err := processCgroup(filepath.Join(proc, "cgroup")); err == nil && strings.HasPrefix(cgroup, b.sliceCgroup+"/") {
		dir := filepath.Join(b.config.CgroupRoot, cgroup)
		if usec, err := cgroupKey(filepath.Join(dir, "cpu.stat"), "usage_usec"); err == nil {
			seconds := float64(usec) / 1e6
			u.CPUSeconds = &seconds
		}
		if raw, err := readSmall(filepath.Join(dir, "memory.peak")); err == nil {
			if peak, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64); err == nil {
				u.MemoryPeakBytes = &peak
			}
		}
	}
	if bytes, err := netDevBytes(filepath.Join(proc, "net", "dev")); err == nil {
		u.NetworkBytes = &bytes
	}
	return u, nil
}

// cgroupKey reads one "key value" line of a cgroup v2 flat-keyed file.
func cgroupKey(file, key string) (uint64, error) {
	raw, err := readSmall(file)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(raw, "\n") {
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == key {
			return strconv.ParseUint(fields[1], 10, 64)
		}
	}
	return 0, fmt.Errorf("%s has no %s", file, key)
}

// netDevBytes sums received and sent bytes of every interface but loopback
// in a /proc/<pid>/net/dev table.
func netDevBytes(file string) (uint64, error) {
	handle, err := os.Open(file)
	if err != nil {
		return 0, err
	}
	defer handle.Close()
	var total uint64
	rows := 0
	scanner := bufio.NewScanner(handle)
	for scanner.Scan() {
		name, counters, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(counters)
		if len(fields) < 16 {
			return 0, errors.New("net/dev row is short")
		}
		rows++
		if strings.TrimSpace(name) == "lo" {
			continue
		}
		rx, err1 := strconv.ParseUint(fields[0], 10, 64)
		tx, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			return 0, errors.New("net/dev counter is not a number")
		}
		total += rx + tx
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if rows == 0 {
		return 0, errors.New("net/dev has no interfaces")
	}
	return total, nil
}
