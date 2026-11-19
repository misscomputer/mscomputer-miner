// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

// pfBackend is the fixture backend with an image cache: pulls block on
// release until the test lets them finish.
type pfBackend struct {
	*sbBackend
	mu        sync.Mutex
	cached    map[string]bool
	pulls     map[string]int
	release   chan struct{}
	supported bool
}

func (b *pfBackend) PrefetchSupported() bool { return b.supported }

func (b *pfBackend) ImageCached(_ context.Context, _, digest string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cached[digest]
}

func (b *pfBackend) PrefetchImage(ctx context.Context, _, digest string) error {
	b.mu.Lock()
	b.pulls[digest]++
	b.mu.Unlock()
	select {
	case <-b.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	b.mu.Lock()
	b.cached[digest] = true
	b.mu.Unlock()
	return nil
}

func newPFFixture(t *testing.T, supported bool) (*sbFixture, *pfBackend) {
	f := newSBFixture(t)
	backend := &pfBackend{sbBackend: f.backend, cached: map[string]bool{}, pulls: map[string]int{}, release: make(chan struct{}), supported: supported}
	lane, err := NewSandboxLane(context.Background(), f.agent(), f.store, backend, SandboxLaneConfig{Budget: sbBudget, CgroupRoot: f.root, AgentCgroup: "/system.slice/miner-agent.service", DeploymentCgroup: "/system.slice/deployment-v4.slice"})
	if err != nil {
		t.Fatal(err)
	}
	lane.now = func() time.Time { return f.now }
	f.lane = lane
	t.Cleanup(func() { close(backend.release) })
	return f, backend
}

func (f *sbFixture) prefetchRequest(n int) protocol.SandboxImagePrefetchV1 {
	f.t.Helper()
	digest := fmt.Sprintf("sha256:%064x", n)
	r := protocol.SandboxImagePrefetchV1{
		ExpiresAt: stamp(f.now.Add(time.Minute)), ImageDigest: digest, ImageReference: "mirror.example/library/python@" + digest,
		IssuedAt: stamp(f.now), MinerID: sbMinerHotkey, Nonce: fmt.Sprintf("%032x", n),
		Schema: protocol.SandboxImagePrefetchSchema, SchemaVersion: protocol.SandboxImagePrefetchSchemaVersion, Subnet: f.binding(),
	}
	if err := protocol.SignSandboxImagePrefetchV1(&r, f.validator); err != nil {
		f.t.Fatal(err)
	}
	return r
}

func (f *sbFixture) prefetchState(request protocol.SandboxImagePrefetchV1, state, code string) {
	f.t.Helper()
	receipt, err := f.lane.PrefetchImage(context.Background(), request, f.request())
	if err != nil {
		f.t.Fatal(err)
	}
	if err := protocol.VerifySandboxImagePrefetchReceiptV1(receipt, request, f.miner.Public().(ed25519.PublicKey)); err != nil {
		f.t.Fatalf("receipt does not verify: %v", err)
	}
	got := ""
	if receipt.ErrorCode != nil {
		got = *receipt.ErrorCode
	}
	if receipt.State != state || got != code {
		f.t.Fatalf("prefetch %s/%q, want %s/%q", receipt.State, got, state, code)
	}
}

func TestSandboxPrefetchPullsOnceThenAnswersCached(t *testing.T) {
	f, backend := newPFFixture(t, true)
	if !f.lane.ImagePrefetchEnabled() {
		t.Fatal("a cache backend must advertise prefetch")
	}
	request := f.prefetchRequest(1)
	f.prefetchState(request, protocol.ImagePrefetchPulling, "")
	// A repeat while the pull runs joins it.
	f.prefetchState(f.prefetchRequest(1), protocol.ImagePrefetchPulling, "")
	backend.release <- struct{}{}
	deadline := time.Now().Add(5 * time.Second)
	for !backend.ImageCached(context.Background(), "", request.ImageDigest) {
		if time.Now().After(deadline) {
			t.Fatal("prefetch never finished")
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.prefetchState(request, protocol.ImagePrefetchCached, "")
	if backend.pulls[request.ImageDigest] != 1 {
		t.Fatalf("pulls = %d, want 1", backend.pulls[request.ImageDigest])
	}
}

func TestSandboxPrefetchBoundsConcurrentPulls(t *testing.T) {
	f, _ := newPFFixture(t, true)
	for n := 1; n <= MaxConcurrentPrefetches; n++ {
		f.prefetchState(f.prefetchRequest(n), protocol.ImagePrefetchPulling, "")
	}
	f.prefetchState(f.prefetchRequest(99), protocol.ImagePrefetchRefused, "capacity_exhausted")
}

func TestSandboxPrefetchWithoutCacheIsRefusedUnsupported(t *testing.T) {
	f, _ := newPFFixture(t, false)
	if f.lane.ImagePrefetchEnabled() {
		t.Fatal("a backend without a cache must not advertise prefetch")
	}
	f.prefetchState(f.prefetchRequest(1), protocol.ImagePrefetchRefused, sandbox.CapabilityUnsupported)
}

func TestSandboxPrefetchRefusesForeignOrForgedRequests(t *testing.T) {
	f, _ := newPFFixture(t, true)
	forged := f.prefetchRequest(1)
	forged.ImageReference = "mirror.example/library/other@" + forged.ImageDigest
	if _, err := f.lane.PrefetchImage(context.Background(), forged, f.request()); err == nil {
		t.Fatal("an altered request was admitted")
	}
	other := f.prefetchRequest(2)
	other.Signature = strings.Repeat("0", 128)
	if _, err := f.lane.PrefetchImage(context.Background(), other, f.request()); err == nil {
		t.Fatal("an unsigned request was admitted")
	}
	stale := f.prefetchRequest(3)
	f.now = f.now.Add(2 * time.Minute)
	if _, err := f.lane.PrefetchImage(context.Background(), stale, f.request()); err == nil {
		t.Fatal("an expired request was admitted")
	}
}
