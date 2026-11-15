// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/misscomputer/mscomputer-miner/pkg/miner"
)

const mib = 1 << 20

// appBudgetOptions are the --app-* and reserve flags.
type appBudgetOptions struct {
	Config        miner.AppBudgetConfig
	CPUWeight     int
	HostMemoryMiB int
	HostVCPUs     int
	CgroupParent  string
}

// validSliceName accepts a plain systemd slice name: no escapes, no
// empty dash-separated segment.
func validSliceName(name string) bool {
	unit, ok := strings.CutSuffix(name, ".slice")
	if !ok || unit == "" || strings.ContainsAny(unit, "/\\") {
		return false
	}
	for _, part := range strings.Split(unit, "-") {
		if part == "" {
			return false
		}
	}
	return true
}

// appCgroupParent resolves --app-cgroup-parent. Empty derives the slice of
// --sandbox-deployment-cgroup when that is a top-level /<name>.slice, so
// replicas run where sandboxes are already proven disjoint from; "none"
// keeps Docker's default parent.
func appCgroupParent(flagValue, deploymentCgroup string) (string, error) {
	switch flagValue {
	case "none":
		return "", nil
	case "":
		if deploymentCgroup == "" {
			return "", nil
		}
		name := strings.TrimPrefix(deploymentCgroup, "/")
		if path.Clean(deploymentCgroup) != deploymentCgroup || !validSliceName(name) {
			return "", fmt.Errorf("--sandbox-deployment-cgroup %q is not a top-level slice; set --app-cgroup-parent explicitly (or none)", deploymentCgroup)
		}
		return name, nil
	default:
		if !validSliceName(flagValue) {
			return "", fmt.Errorf("--app-cgroup-parent %q must be a systemd slice name such as mcsbxdeploy.slice", flagValue)
		}
		return flagValue, nil
	}
}

// sliceCgroupPath is the cgroup v2 path of a systemd slice name: nested
// slices are spelled with dashes (a-b.slice is a.slice/a-b.slice).
func sliceCgroupPath(slice string) string {
	unit := strings.TrimSuffix(slice, ".slice")
	parts := strings.Split(unit, "-")
	segments := make([]string, 0, len(parts))
	for index := range parts {
		segments = append(segments, strings.Join(parts[:index+1], "-")+".slice")
	}
	return "/" + strings.Join(segments, "/")
}

// hostMemoryMiB reads MemTotal and rounds it up to a whole GiB, so a VM
// sold as 16 GiB (whose kernel reports slightly less) plans as 16 GiB.
func hostMemoryMiB(meminfo io.Reader) (int, error) {
	scanner := bufio.NewScanner(meminfo)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 3 && fields[0] == "MemTotal:" && fields[2] == "kB" {
			kib, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil || kib <= 0 {
				return 0, errors.New("malformed MemTotal")
			}
			const gibInKiB = 1 << 20
			return int((kib + gibInKiB - 1) / gibInKiB * 1024), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("MemTotal not found")
}

// planHostAppBudget sizes the app budget of this host, finding memory and
// vCPUs unless the flags override them.
func planHostAppBudget(options appBudgetOptions) (miner.AppBudgetPlan, error) {
	memory, vcpus := options.HostMemoryMiB, options.HostVCPUs
	if memory == 0 {
		file, err := os.Open("/proc/meminfo")
		if err != nil {
			return miner.AppBudgetPlan{}, err
		}
		memory, err = hostMemoryMiB(file)
		file.Close()
		if err != nil {
			return miner.AppBudgetPlan{}, fmt.Errorf("host memory: %w", err)
		}
	}
	if vcpus == 0 {
		vcpus = runtime.NumCPU()
	}
	if memory < 0 || vcpus < 0 {
		return miner.AppBudgetPlan{}, errors.New("--host-memory-mib and --host-vcpus must not be negative")
	}
	if options.CPUWeight < 1 || options.CPUWeight > 10000 {
		return miner.AppBudgetPlan{}, errors.New("--app-cpu-weight must be 1..10000")
	}
	return miner.PlanAppBudget(memory, vcpus, options.Config)
}

// sliceAppCopies bounds copies by the slice's memory.max: a slice whose
// hard limit is below the planned budget holds fewer copies. A missing or
// unlimited slice keeps the plan and is reported so the operator installs
// the slice limits.
func sliceAppCopies(cgroupRoot, slice string, plan miner.AppBudgetPlan, cpuWeight int) int {
	copies := plan.AppCopies
	if slice == "" {
		slog.Warn("app replicas run without an app slice; the app budget is enforced by admission only", "app_copies", copies)
		return copies
	}
	dir := filepath.Join(cgroupRoot, sliceCgroupPath(slice))
	raw, err := os.ReadFile(filepath.Join(dir, "memory.max"))
	value := strings.TrimSpace(string(raw))
	switch {
	case err != nil:
		slog.Warn("app slice is not present yet; Docker creates it without limits", "slice", slice, "want_memory_max_mib", plan.AppBudgetMiB)
	case value == "max":
		slog.Warn("app slice has no MemoryMax", "slice", slice, "want_memory_max_mib", plan.AppBudgetMiB)
	default:
		limit, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr == nil && limit >= 0 {
			if sliceCopies := int(limit / int64(plan.AppCopyMiB) / mib); sliceCopies < copies {
				slog.Warn("app slice MemoryMax is below the app budget; advertising fewer copies", "slice", slice, "memory_max_mib", limit/mib, "app_copies", sliceCopies)
				copies = sliceCopies
			}
		}
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "cpu.weight")); err == nil && strings.TrimSpace(string(raw)) != strconv.Itoa(cpuWeight) {
		slog.Warn("app slice CPUWeight differs from --app-cpu-weight", "slice", slice, "cpu_weight", strings.TrimSpace(string(raw)), "want", cpuWeight)
	}
	return copies
}

// appSliceDropIn is the systemd drop-in of the app slice for a plan.
func appSliceDropIn(plan miner.AppBudgetPlan, cpuWeight int) string {
	return fmt.Sprintf("[Slice]\nMemoryMax=%dM\nMemorySwapMax=0\nCPUWeight=%d\n", plan.AppBudgetMiB, cpuWeight)
}
