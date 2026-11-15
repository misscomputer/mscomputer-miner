// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import (
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

// A lease asking for docker on a backend that does not report it is refused
// as capability_unsupported, a non-fault, before any create, even when the
// backend itself would not refuse it.
func TestSandboxDockerLeaseRefusedWithoutDockerBackend(t *testing.T) {
	f := newSBFixture(t)
	_, l, receipt, err := f.commitHeld(1, func(l *protocol.SandboxLeaseV1) { l.Capabilities = []string{sandbox.CapabilityDocker} })
	f.check(receipt, err, protocol.SandboxLeaseSchema, l, sandbox.StageFailed, sandbox.CapabilityUnsupported)
	if live, created, _ := f.backend.state(); live != 0 || len(created) != 0 {
		t.Fatalf("live=%d creates=%d", live, len(created))
	}
	if f.lane.DockerEnabled() {
		t.Fatal("lane without a docker backend reports docker")
	}
}
