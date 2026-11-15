// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/miner"
)

func TestAppCgroupParentResolution(t *testing.T) {
	for _, test := range []struct {
		flag, deployment, want string
		fails                  bool
	}{
		{deployment: "/mcsbxdeploy.slice", want: "mcsbxdeploy.slice"},
		{deployment: "", want: ""},
		{flag: "none", deployment: "/mcsbxdeploy.slice", want: ""},
		{flag: "apps.slice", deployment: "/mcsbxdeploy.slice", want: "apps.slice"},
		{deployment: "/system.slice/apps.slice", fails: true},
		{deployment: "/mcsbxdeploy", fails: true},
		{flag: "/apps.slice", fails: true},
		{flag: "apps.service", fails: true},
		{flag: "-apps.slice", fails: true},
		{flag: "mc--apps.slice", fails: true},
		{flag: `mc\x2dapps.slice`, fails: true},
		{flag: ".slice", fails: true},
	} {
		got, err := appCgroupParent(test.flag, test.deployment)
		if (err != nil) != test.fails || got != test.want {
			t.Fatalf("appCgroupParent(%q, %q) = %q, %v", test.flag, test.deployment, got, err)
		}
	}
	if got := sliceCgroupPath("mcsbxdeploy.slice"); got != "/mcsbxdeploy.slice" {
		t.Fatalf("top-level slice path = %s", got)
	}
	if got := sliceCgroupPath("mc-apps.slice"); got != "/mc.slice/mc-apps.slice" {
		t.Fatalf("nested slice path = %s", got)
	}
}

func TestHostMemoryRoundsUpToWholeGiB(t *testing.T) {
	for _, test := range []struct {
		meminfo string
		want    int
	}{
		// A 16 GiB VM reporting 15993 MiB plans as the 16 GiB reference.
		{"MemFree: 1 kB\nMemTotal:       16376832 kB\n", 16384},
		{"MemTotal: 16777216 kB\n", 16384},
		{"MemTotal: 16777217 kB\n", 17408},
	} {
		got, err := hostMemoryMiB(strings.NewReader(test.meminfo))
		if err != nil || got != test.want {
			t.Fatalf("hostMemoryMiB(%q) = %d, %v", test.meminfo, got, err)
		}
	}
	for _, bad := range []string{"", "MemTotal: x kB\n", "MemTotal: 0 kB\n"} {
		if _, err := hostMemoryMiB(strings.NewReader(bad)); err == nil {
			t.Fatalf("meminfo %q accepted", bad)
		}
	}
}

func TestPlanHostAppBudgetDefaultsAndOverrides(t *testing.T) {
	options := appBudgetOptions{
		Config: miner.AppBudgetConfig{
			SystemReserveMiB: miner.DefaultSystemReserveMiB, SandboxReserveMiB: miner.DefaultSandboxReserveMiB,
			AppBudgetMiB: miner.DefaultAppBudgetMiB, AppCopyMiB: miner.DefaultAppCopyMiB,
		},
		CPUWeight: miner.DefaultAppCPUWeight, HostMemoryMiB: 16384, HostVCPUs: 4,
	}
	plan, err := planHostAppBudget(options)
	if err != nil || plan.AppBudgetMiB != 5120 || plan.AppCopies != 20 || plan.Sandboxes != 1 {
		t.Fatalf("reference plan = %+v, %v", plan, err)
	}
	if got := appSliceDropIn(plan, 50); got != "[Slice]\nMemoryMax=5120M\nMemorySwapMax=0\nCPUWeight=50\n" {
		t.Fatalf("drop-in = %q", got)
	}
	for _, weight := range []int{0, 10001} {
		bad := options
		bad.CPUWeight = weight
		if _, err := planHostAppBudget(bad); err == nil {
			t.Fatalf("cpu weight %d accepted", weight)
		}
	}
	bad := options
	bad.HostVCPUs = -1
	if _, err := planHostAppBudget(bad); err == nil {
		t.Fatal("negative vCPUs accepted")
	}
}

func TestSliceMemoryMaxBoundsAdvertisedCopies(t *testing.T) {
	plan := miner.AppBudgetPlan{AppBudgetMiB: 5120, AppCopyMiB: 256, AppCopies: 20}
	root := t.TempDir()
	slice := filepath.Join(root, "mcsbxdeploy.slice")
	if err := os.MkdirAll(slice, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(value string) {
		if err := os.WriteFile(filepath.Join(slice, "memory.max"), []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := sliceAppCopies(root, "absent.slice", plan, 50); got != 20 {
		t.Fatalf("absent slice copies = %d", got)
	}
	write("max")
	if got := sliceAppCopies(root, "mcsbxdeploy.slice", plan, 50); got != 20 {
		t.Fatalf("unlimited slice copies = %d", got)
	}
	write(fmt.Sprint(int64(2048) << 20))
	if got := sliceAppCopies(root, "mcsbxdeploy.slice", plan, 50); got != 8 {
		t.Fatalf("2 GiB slice copies = %d, want 8", got)
	}
	write(fmt.Sprint(int64(8192) << 20))
	if got := sliceAppCopies(root, "mcsbxdeploy.slice", plan, 50); got != 20 {
		t.Fatalf("a larger slice must not raise copies: %d", got)
	}
	if got := sliceAppCopies(root, "", plan, 50); got != 20 {
		t.Fatalf("no slice copies = %d", got)
	}
}

func TestAppBudgetRefusalIsRetryableCapacity(t *testing.T) {
	status, code, retryable := assignmentError(fmt.Errorf("assign: %w", miner.ErrAppBudgetExhausted))
	if status != http.StatusServiceUnavailable || code != "app_budget_exhausted" || !retryable {
		t.Fatalf("mapping = (%d,%q,%v)", status, code, retryable)
	}
}

func TestCapabilitiesAdvertiseAppCopiesOnlyWithABudget(t *testing.T) {
	agent := miner.NewAgent("miner", nil, nil, nil, unusedOCIRuntime{}, nil)
	server := &api{agent: agent}
	if slices.ContainsFunc(server.features(), func(feature string) bool { return strings.HasPrefix(feature, miner.AppCopiesFeaturePrefix) }) {
		t.Fatalf("features without a budget = %v", server.features())
	}
	agent.EnableAppBudget(20)
	if !slices.Contains(server.features(), "organic-app-copies-v1.20") {
		t.Fatalf("features = %v", server.features())
	}
	withoutOCI := &api{agent: miner.NewAgent("miner", nil, nil, nil, nil, nil)}
	withoutOCI.agent.EnableAppBudget(20)
	if slices.ContainsFunc(withoutOCI.features(), func(feature string) bool { return strings.HasPrefix(feature, miner.AppCopiesFeaturePrefix) }) {
		t.Fatalf("features without an organic runtime = %v", withoutOCI.features())
	}
}
