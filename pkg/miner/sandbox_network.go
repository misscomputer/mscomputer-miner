// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

// SandboxNetworkBackend is implemented by an ops backend that can replace
// the egress policy of a running sandbox. SetNetwork returns nil only once
// the new rules are verified in the kernel. It returns
// ErrNetworkChangeUnsupported when the sandbox's confinement cannot be
// retargeted, ErrNetworkPolicyStale when a policy issued at or after
// issuedAt is already in force, and any other error when the change could
// not be verified; then the sandbox has been left reaching nothing.
type SandboxNetworkBackend interface {
	SetNetwork(ctx context.Context, instanceID, leaseID string, issuedAt time.Time, policy sandbox.NetworkPolicy) error
}

var (
	ErrNetworkChangeUnsupported = errors.New(sandbox.NetworkChangeUnsupported)
	ErrNetworkPolicyStale       = errors.New(sandbox.NetworkPolicyStale)
)

// networkSetBudget bounds one network_set on the miner: rule load plus the
// verification wait of the backend.
const networkSetBudget = 30 * time.Second

// networkSet answers a verified network_set. Like lease_status it takes no
// in-flight slot and records no op: the lease is fenced by the durable
// store, the policy by the backend, which orders changes by issued_at.
func (l *SandboxLane) networkSet(ctx context.Context, ops *sandboxOps, r protocol.SandboxOpRequestV1, payload []byte) (protocol.SandboxOpReceiptV1, error) {
	if l.isClosed() {
		return protocol.SandboxOpReceiptV1{}, ErrSandboxLaneClosed
	}
	policy, err := sandbox.DecodeNetworkPolicy(payload)
	if err != nil {
		return protocol.SandboxOpReceiptV1{}, fmt.Errorf("sandbox_op_payload_invalid: %w", err)
	}
	stateCtx, cancel := ops.state(ctx)
	status, err := ops.store.LeaseStatus(stateCtx, r)
	err = l.durableErr(stateCtx, err)
	cancel()
	if err != nil {
		return protocol.SandboxOpReceiptV1{}, err
	}
	if status.Unavailable != nil {
		return l.leaseRefusal(r, status.Unavailable, status.DecidedAt)
	}
	setter, ok := ops.backend.(SandboxNetworkBackend)
	if !ok {
		return l.opReceipt(r, sandbox.OpStageRefused, sandbox.NetworkChangeUnsupported, status.DecidedAt)
	}
	issued, _ := time.Parse(time.RFC3339Nano, r.IssuedAt)
	setCtx, cancel := context.WithTimeout(ctx, networkSetBudget)
	err = setter.SetNetwork(setCtx, SandboxInstanceName(r.LeaseID), r.LeaseID, issued, policy)
	expired := setCtx.Err() != nil
	cancel()
	if l.base.Err() != nil {
		return protocol.SandboxOpReceiptV1{}, ErrSandboxLaneClosed
	}
	observed := later(l.now().UTC(), status.DecidedAt)
	switch {
	case err == nil:
		return l.opReceipt(r, sandbox.OpStageCompleted, "", observed)
	case errors.Is(err, ErrNetworkChangeUnsupported):
		return l.opReceipt(r, sandbox.OpStageRefused, sandbox.NetworkChangeUnsupported, observed)
	case errors.Is(err, ErrNetworkPolicyStale):
		return l.opReceipt(r, sandbox.OpStageRefused, sandbox.NetworkPolicyStale, observed)
	case errors.Is(err, ErrSandboxNotRunning):
		return l.opReceipt(r, sandbox.OpStageRefused, "sandbox_exited", observed)
	case expired:
		return l.opReceipt(r, sandbox.OpStageTimedOut, sandbox.OpCodeDeadline, observed)
	}
	return l.opReceipt(r, sandbox.OpStageFailed, sandbox.OpCodeRuntimeFailed, observed)
}
