// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/organic"
)

// Every endpoint incarnation owns a distinct deterministic container name
// and state directory, so stopping an old generation can never touch a new
// one.
func TestCleanupIdentityIsEndpointIncarnationSafe(t *testing.T) {
	runtime := NewDockerOCIRuntime("docker", t.TempDir(), DefaultOrganicNetwork, DefaultOrganicBridge)
	first := "same-5Fminer-g1-" + strings.Repeat("a", 32)
	second := "same-5Fminer-g2-" + strings.Repeat("b", 32)
	firstPlan, err := PrepareCleanup(runtime, first)
	if err != nil {
		t.Fatal(err)
	}
	secondPlan, err := PrepareCleanup(runtime, second)
	if err != nil {
		t.Fatal(err)
	}
	if firstPlan.InstanceID != InstanceName(first) || secondPlan.InstanceID != InstanceName(second) {
		t.Fatalf("runtime IDs are not derived from endpoint IDs: %q %q", firstPlan.InstanceID, secondPlan.InstanceID)
	}
	if firstPlan.InstanceID == secondPlan.InstanceID || firstPlan.LayerPath == secondPlan.LayerPath {
		t.Fatalf("incarnations collided: %+v %+v", firstPlan, secondPlan)
	}
	if again, err := PrepareCleanup(runtime, first); err != nil || again != firstPlan {
		t.Fatalf("cleanup identity is not deterministic: %+v %v", again, err)
	}
}

func TestInstanceNameNormalizationRetainsCollisionResistance(t *testing.T) {
	first := InstanceName("deployment/miner")
	second := InstanceName("deployment?miner")
	if first == second {
		t.Fatalf("normalized endpoint IDs collided at %q", first)
	}
	valid := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]+$`)
	for _, name := range []string{first, second, InstanceName(strings.Repeat("long/", 100))} {
		if !valid.MatchString(name) || len(name) > 70 {
			t.Fatalf("invalid runtime name %q", name)
		}
	}
}

func TestRunArgsPlaceReplicasInTheAppSlice(t *testing.T) {
	profile, ok := LookupProfile(organic.RuntimeProfile)
	if !ok {
		t.Fatal("small-v1 profile missing")
	}
	launch := Launch{InstanceID: "replica", Profile: profile}
	launch.Workload.ContainerPort = 8080
	runtime := NewDockerOCIRuntime("docker", t.TempDir(), "net", "br")
	without := runtime.runArgs(launch, "sha256:image")
	if slices.Contains(without, "--cgroup-parent") {
		t.Fatalf("default args carry a cgroup parent: %v", without)
	}
	runtime.CgroupParent = "mcsbxdeploy.slice"
	with := runtime.runArgs(launch, "sha256:image")
	index := slices.Index(with, "--cgroup-parent")
	if index < 0 || with[index+1] != "mcsbxdeploy.slice" || with[len(with)-1] != "sha256:image" {
		t.Fatalf("args = %v", with)
	}
	// The per-replica memory limit stays as the burst ceiling.
	memory := slices.Index(with, "--memory")
	if memory < 0 || with[memory+1] != "1024m" || len(with) != len(without)+2 {
		t.Fatalf("args = %v", with)
	}
}

func TestVerifyCgroupParentRequiresTheSystemdDriver(t *testing.T) {
	fake := func(script string) string {
		path := filepath.Join(t.TempDir(), "docker")
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	runtime := NewDockerOCIRuntime(fake("exit 9"), t.TempDir(), "net", "br")
	if err := runtime.VerifyCgroupParent(context.Background()); err != nil {
		t.Fatalf("no parent must not consult the daemon: %v", err)
	}
	runtime.CgroupParent = "mcsbxdeploy.slice"
	for _, test := range []struct {
		script string
		ok     bool
	}{
		{"echo systemd", true},
		{"echo cgroupfs", false},
		{"echo boom >&2; exit 1", false},
	} {
		runtime.Binary = fake(test.script)
		if err := runtime.VerifyCgroupParent(context.Background()); (err == nil) != test.ok {
			t.Fatalf("%q: err = %v", test.script, err)
		}
	}
}
