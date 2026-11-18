// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import (
	"strings"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

var noneNetwork = []byte(`{"allow":[],"mode":"none"}`)

func (f *opsFixture) networkSet(payload []byte) (protocol.SandboxOpRequestV1, protocol.SandboxOpReceiptV1, error) {
	request := f.op(sandbox.OpNetworkSet, func(r *protocol.SandboxOpRequestV1) { f.withPayload(r, payload) })
	receipt, result, err := f.run(request, payload)
	if result != nil {
		f.t.Fatalf("network_set returned result bytes: %q", result)
	}
	return request, receipt, err
}

// A backend that cannot retarget a sandbox's rules refuses network_set with
// a signed, stable code, without entering the guest.
func TestNetworkSetWithoutBackendSupportIsRefused(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.noHelper()
	request, receipt, err := f.networkSet(noneNetwork)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, request, nil, sandbox.OpStageRefused, sandbox.NetworkChangeUnsupported)
}

// A payload that is not a canonical valid policy has no receipt.
func TestNetworkSetRefusesInvalidPolicy(t *testing.T) {
	for _, payload := range []string{`{"mode":"none","allow":[]}`, `{"allow":["a.example","10.0.0.0/8x"],"mode":"allowlist"}`, `{"allow":["x.example"],"mode":"public"}`} {
		f := newOpsFixture(t, testOpsConfig)
		f.noHelper()
		if _, _, err := f.networkSet([]byte(payload)); err == nil || !strings.Contains(err.Error(), "payload") {
			t.Fatalf("payload %s = %v", payload, err)
		}
	}
	if _, err := sandbox.DecodeNetworkPolicy([]byte(`{"allow":["192.0.2.0/24","pypi.org"],"mode":"allowlist"}`)); err != nil {
		t.Fatal(err)
	}
}
