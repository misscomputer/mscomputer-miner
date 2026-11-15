// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package main

import (
	"slices"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

// dockerSandboxBackend is a sandboxBackend whose host profile has docker.
type dockerSandboxBackend struct {
	sandboxBackend
	enabled bool
}

func (b *dockerSandboxBackend) DockerEnabled() bool { return b.enabled }

// sandbox-docker-v1 is advertised only by a backend that reports docker.
func TestSandboxDockerFeatureFollowsTheBackend(t *testing.T) {
	plain := advertised(t, laneService(t, &sandboxBackend{}))
	if slices.Contains(plain, sandbox.DockerCapabilityFeature) || !slices.Contains(plain, sandbox.CapabilityFeature) {
		t.Fatalf("backend without docker advertises %v", plain)
	}
	off := advertised(t, laneService(t, &dockerSandboxBackend{}))
	if slices.Contains(off, sandbox.DockerCapabilityFeature) {
		t.Fatalf("backend with docker off advertises %v", off)
	}
	on := advertised(t, laneService(t, &dockerSandboxBackend{enabled: true}))
	if !slices.Contains(on, sandbox.DockerCapabilityFeature) || !slices.Equal(slices.DeleteFunc(slices.Clone(on), func(f string) bool {
		return f == sandbox.DockerCapabilityFeature
	}), plain) {
		t.Fatalf("docker backend advertises %v, want %v plus %s", on, plain, sandbox.DockerCapabilityFeature)
	}
}
