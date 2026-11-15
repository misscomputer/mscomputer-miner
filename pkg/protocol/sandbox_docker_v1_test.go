// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package protocol_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/organic"
	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

var updateSandboxDockerVectors = flag.Bool("update-sandbox-docker-vectors", false, "rewrite testdata/sandbox-docker-v1-vectors.json")

type sandboxDockerVector struct {
	Lease       json.RawMessage `json:"lease"`
	LeaseDigest string          `json:"lease_digest"`
}

// A lease with capability docker is pinned as its own vector; the lease
// vectors without capabilities stay byte-stable (golden test unchanged).
func TestSandboxDockerLeaseMatchesGoldenVector(t *testing.T) {
	validator, miner := sandboxKeys()
	reservation := sandboxReservation(t, validator, miner)
	lease := sandboxLease(t, validator, miner, reservation, func(l *protocol.SandboxLeaseV1) {
		l.Capabilities = []string{sandbox.CapabilityDocker}
	})
	digest, err := protocol.SandboxDigestV1(lease)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := json.MarshalIndent(sandboxDockerVector{Lease: canonicalJSON(t, lease), LeaseDigest: digest}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, '\n')
	path := filepath.Join("testdata", "sandbox-docker-v1-vectors.json")
	if *updateSandboxDockerVectors {
		if err := os.WriteFile(path, rendered, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, rendered) {
		t.Fatalf("docker lease vector changed\n%s", rendered)
	}
	var vector sandboxDockerVector
	if err := json.Unmarshal(want, &vector); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(canonicalJSON(t, vector.Lease), []byte(`"capabilities":["docker"]`)) {
		t.Fatalf("vector lacks capabilities: %s", vector.Lease)
	}
	var decoded protocol.SandboxLeaseV1
	if err := organic.DecodeStrict(vector.Lease, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifySandboxLeaseV1Signature(decoded, validator.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if got, _ := protocol.SandboxDigestV1(decoded); got != vector.LeaseDigest {
		t.Fatalf("digest %s, want %s", got, vector.LeaseDigest)
	}
}

func TestSandboxLeaseCapabilitiesOmittedWhenEmpty(t *testing.T) {
	validator, miner := sandboxKeys()
	reservation := sandboxReservation(t, validator, miner)
	plain := sandboxLease(t, validator, miner, reservation, nil)
	empty := sandboxLease(t, validator, miner, reservation, func(l *protocol.SandboxLeaseV1) { l.Capabilities = []string{} })
	if !bytes.Equal(canonicalJSON(t, plain), canonicalJSON(t, empty)) {
		t.Fatal("an empty capability list changed the canonical lease")
	}
	if strings.Contains(string(canonicalJSON(t, plain)), "capabilities") {
		t.Fatal("a lease without capabilities carries the member")
	}
}

func TestSandboxLeaseRejectsInvalidCapabilities(t *testing.T) {
	validator, miner := sandboxKeys()
	reservation := sandboxReservation(t, validator, miner)
	for name, capabilities := range map[string][]string{
		"unknown":   {"privileged"},
		"duplicate": {sandbox.CapabilityDocker, sandbox.CapabilityDocker},
		"unsorted":  {sandbox.CapabilityDocker, "aaa"},
		"empty":     {""},
		"case":      {"Docker"},
	} {
		lease := sandboxLease(t, validator, miner, reservation, nil)
		lease.Capabilities = capabilities
		if err := lease.Validate(); err == nil {
			t.Errorf("%s: lease with capabilities %q validated", name, capabilities)
		}
	}
}
