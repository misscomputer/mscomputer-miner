// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/durable"
	"github.com/misscomputer/mscomputer-miner/pkg/miner"
	"github.com/misscomputer/mscomputer-miner/pkg/neuron"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

// inventoryBackend is a sandboxBackend that keeps an image inventory.
type inventoryBackend struct {
	sandboxBackend
	digests []string
	err     error
}

func (b *inventoryBackend) CachedImages(context.Context) ([]string, error) { return b.digests, b.err }

func laneService(t *testing.T, backend miner.SandboxBackend) *api {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	dir := filepath.Join(root, "mc-sandboxes")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"cpu.max": "400000 100000\n", "memory.max": fmt.Sprint(8<<30) + "\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	state, err := durable.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Close() })
	leases, err := state.EnableSandboxLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	agent := miner.NewAgent("miner", nil, privateKey, nil, nil, nil)
	agent.MinerTransport = neuron.TransportHTTP
	lane, err := miner.NewSandboxLane(ctx, agent, leases, backend, miner.SandboxLaneConfig{
		Budget: sandbox.Capacity{CPUMillis: 4000, MemoryMiB: 8192, DiskMiB: 40960, Sandboxes: 4}, CgroupRoot: root,
		AgentCgroup: "/system.slice/miner-agent.service", DeploymentCgroup: "/system.slice/deployment-v4.slice",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lane.Close(ctx) })
	return &api{agent: agent, store: state, network: "mock", netuid: 24, hotkey: "miner", public: publicKey, sandbox: lane}
}

// reported is the raw cached_images member of /v1/capabilities, and
// whether it is present at all.
func reported(t *testing.T, service *api) ([]string, bool) {
	t.Helper()
	return reportedAt(t, service, "/v1/capabilities?cached_images=1")
}

func reportedAt(t *testing.T, service *api, target string) ([]string, bool) {
	t.Helper()
	response := serve(service.routes(), http.MethodGet, target, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("capabilities returned %d", response.Code)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	member, ok := raw["cached_images"]
	if !ok {
		return nil, false
	}
	var digests []string
	if err := json.Unmarshal(member, &digests); err != nil {
		t.Fatal(err)
	}
	return digests, true
}

// Asked for it, the capability response reports the backend's image
// inventory in its recency order, normalized to the contract; an empty,
// unreadable or absent inventory omits the member.
func TestCapabilitiesReportCachedImagesFromTheBackendInventory(t *testing.T) {
	digest := func(n int) string { return fmt.Sprintf("sha256:%064x", n) }
	inventory := []string{digest(7), digest(3), "sha256:" + strings.Repeat("A", 64), digest(7)}
	for n := 100; n < 200; n++ {
		inventory = append(inventory, digest(n))
	}
	service := laneService(t, &inventoryBackend{sandboxBackend: sandboxBackend{live: map[string]bool{}}, digests: inventory})
	// A neuron that does not ask gets the response it got before.
	for _, target := range []string{"/v1/capabilities", "/v1/capabilities?cached_images=0"} {
		if got, ok := reportedAt(t, service, target); ok {
			t.Fatalf("%s: cached_images = %v, want the member omitted", target, got)
		}
	}
	got, ok := reported(t, service)
	if !ok || len(got) != neuron.MaxCachedImages || got[0] != digest(7) || got[1] != digest(3) || got[2] != digest(100) {
		t.Fatalf("cached_images = %v (present %t)", got, ok)
	}
	if err := neuron.ValidateCachedImages(got); err != nil {
		t.Fatalf("reported cached_images fail validation: %v", err)
	}
	for name, backend := range map[string]miner.SandboxBackend{
		"empty":      &inventoryBackend{sandboxBackend: sandboxBackend{live: map[string]bool{}}},
		"unreadable": &inventoryBackend{sandboxBackend: sandboxBackend{live: map[string]bool{}}, digests: []string{digest(1)}, err: errors.New("engine down")},
		"no cache":   &sandboxBackend{live: map[string]bool{}},
		"only bogus": &inventoryBackend{sandboxBackend: sandboxBackend{live: map[string]bool{}}, digests: []string{"latest"}},
	} {
		if got, ok := reported(t, laneService(t, backend)); ok {
			t.Errorf("%s: cached_images = %v, want the member omitted", name, got)
		}
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	agent := miner.NewAgent("miner", nil, privateKey, nil, nil, nil)
	agent.MinerTransport = neuron.TransportHTTP
	if got, ok := reported(t, &api{agent: agent, network: "mock", netuid: 24, hotkey: "miner", public: publicKey}); ok {
		t.Fatalf("lane off: cached_images = %v", got)
	}
}
