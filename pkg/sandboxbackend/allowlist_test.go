// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxhost"
)

// allowHost is an egress host whose allowlist loads and resolutions are
// recorded; the engine gives a started sandbox the MAC its create asked
// for (or wrongMAC).
type allowHost struct {
	*egressHost
	loads     [][]sandboxhost.TenantAllowlist
	resolves  map[string][]netip.Addr
	resolvers []string
	failLoad  error
	wrongMAC  string
	// containersAtLoad counts the engine's containers at each load.
	containersAtLoad []int
}

func newAllowHost(t *testing.T) *allowHost {
	h := &allowHost{egressHost: newEgressHost(t), resolves: map[string][]netip.Addr{}}
	apply, resolve := applyTenantAllowlists, resolveAllowHost
	t.Cleanup(func() { applyTenantAllowlists, resolveAllowHost = apply, resolve })
	applyTenantAllowlists = func(e sandboxhost.ProfileEgress, lists []sandboxhost.TenantAllowlist) error {
		if _, err := e.TenantAllowlistScript(lists); err != nil {
			t.Fatalf("invalid allowlists %v: %v", lists, err)
		}
		if h.failLoad != nil {
			return h.failLoad
		}
		h.loads = append(h.loads, lists)
		h.containersAtLoad = append(h.containersAtLoad, len(h.engine.containers))
		return nil
	}
	resolveAllowHost = func(_ context.Context, server, host string) ([]netip.Addr, error) {
		h.resolvers = append(h.resolvers, server)
		addrs, ok := h.resolves[server+" "+host]
		if !ok {
			return nil, errors.New("no such host")
		}
		return addrs, nil
	}
	h.engine.started = func(c *engineContainer) {
		mac := "02:42:0a:e7:00:02"
		if want := c.Labels[LabelNetworkAllow]; want != "" {
			mac = allowlistMAC(c.Labels[LabelLeaseID])
		}
		if h.wrongMAC != "" {
			mac = h.wrongMAC
		}
		c.Network = map[string]any{"Networks": map[string]any{"bridge": map[string]any{"IPAddress": "10.231.0.2", "MacAddress": mac}}}
	}
	return h
}

func allowLease(n int, allow ...string) protocol.SandboxLeaseV1 {
	return testLease(func(l *protocol.SandboxLeaseV1) {
		l.SandboxID = fmt.Sprintf("sbx-%032d", n)
		l.Network = sandbox.NetworkPolicy{Mode: sandbox.NetworkAllowlist, Allow: allow}
	})
}

func lastLoad(h *allowHost) string {
	if len(h.loads) == 0 {
		return "<none>"
	}
	return fmt.Sprint(h.loads[len(h.loads)-1])
}

// An allowlist sandbox's pairs are loaded before its container exists, and
// the container asks for its allowlist MAC: CIDRs as given, hostnames
// resolved through every profile resolver (union, refused addresses
// dropped), an unresolvable host admitting nothing. A public create loads
// nothing.
func TestCreateAllowlistLoadsPairsBeforeTheContainer(t *testing.T) {
	h := newAllowHost(t)
	h.resolves["1.1.1.1 pypi.org"] = []netip.Addr{netip.MustParseAddr("151.101.0.223"), netip.MustParseAddr("10.0.0.5")}
	h.resolves["8.8.8.8 pypi.org"] = []netip.Addr{netip.MustParseAddr("151.101.64.223")}
	b := h.backend()
	public := testLease(publicLease)
	if err := b.Create(context.Background(), instanceOf(public), public); err != nil {
		t.Fatal(err)
	}
	if len(h.loads) != 0 {
		t.Fatalf("a public create loaded allowlists %v", h.loads)
	}
	lease := allowLease(2, "140.82.112.0/20", "missing.invalid", "pypi.org")
	if err := b.Create(context.Background(), instanceOf(lease), lease); err != nil {
		t.Fatal(err)
	}
	mac := allowlistMAC(protocol.SandboxLeaseIDV1(lease))
	if !sandboxhost.AllowlistMAC(mac) {
		t.Fatalf("allowlist MAC %s is outside the confined range", mac)
	}
	want := fmt.Sprintf("[{%s [140.82.112.0/20 151.101.0.223/32 151.101.64.223/32]}]", mac)
	if len(h.loads) == 0 || fmt.Sprint(h.loads[0]) != want || h.containersAtLoad[0] != 1 {
		t.Fatalf("first load %v with %v containers, want %s before the container", h.loads, h.containersAtLoad, want)
	}
	created := h.engine.created[1]
	hostConfig := created["HostConfig"].(map[string]any)
	endpoint := fmt.Sprint(created["NetworkingConfig"])
	if hostConfig["NetworkMode"] != "bridge" || fmt.Sprint(hostConfig["Dns"]) != "[1.1.1.1 8.8.8.8]" || !strings.Contains(endpoint, mac) {
		t.Fatalf("allowlist sandbox network %v dns %v endpoint %s", hostConfig["NetworkMode"], hostConfig["Dns"], endpoint)
	}
	if err := b.Destroy(context.Background(), instanceOf(lease)); err != nil {
		t.Fatal(err)
	}
	if got := lastLoad(h); got != "[]" {
		t.Fatalf("allowlists after destroy %s", got)
	}
}

// A load that fails fails the create before any container exists; an
// engine that ignores the requested MAC (so the static rule would not
// confine the sandbox) gets the sandbox removed. Both are miner faults.
func TestCreateAllowlistFailsClosed(t *testing.T) {
	h := newAllowHost(t)
	h.failLoad = errors.New("nft failed")
	lease := allowLease(3, "140.82.112.0/20")
	err := h.backend().Create(context.Background(), instanceOf(lease), lease)
	if err == nil || refusalCode(err) != "" || !strings.Contains(err.Error(), sandbox.EgressFirewallUnavailable) || len(h.engine.created) != 0 {
		t.Fatalf("create with a failed load = %v, %d containers", err, len(h.engine.created))
	}

	h = newAllowHost(t)
	h.wrongMAC = "02:42:0a:e7:00:02"
	err = h.backend().Create(context.Background(), instanceOf(lease), lease)
	if err == nil || !strings.Contains(err.Error(), sandbox.EgressFirewallUnavailable) {
		t.Fatalf("create with the wrong MAC = %v", err)
	}
	if _, found := h.engine.containers[instanceOf(lease)]; found {
		t.Fatal("unconfined sandbox kept running")
	}
}

// Each egress check rebuilds the set from the engine's list: a reload of
// the table (which empties it) is refilled, and hostnames re-resolve. A
// failed rebuild leaves the host unhealthy (and the set as it was).
func TestEgressCheckRebuildsAllowlists(t *testing.T) {
	h := newAllowHost(t)
	b := h.backend()
	lease := allowLease(4, "pypi.org")
	h.resolves["1.1.1.1 pypi.org"] = []netip.Addr{netip.MustParseAddr("151.101.0.223")}
	if err := b.Create(context.Background(), instanceOf(lease), lease); err != nil {
		t.Fatal(err)
	}
	h.resolves["1.1.1.1 pypi.org"] = []netip.Addr{netip.MustParseAddr("151.101.64.223")}
	h.loaded = errors.New("table missing")
	if err := b.ensureEgress(); err != nil {
		t.Fatal(err)
	}
	mac := allowlistMAC(protocol.SandboxLeaseIDV1(lease))
	if got, want := lastLoad(h), fmt.Sprintf("[{%s [151.101.64.223/32]}]", mac); got != want || h.applied != 1 {
		t.Fatalf("after reload: allowlists %s (want %s), %d table loads", got, want, h.applied)
	}
	h.failLoad = errors.New("nft failed")
	if err := b.ensureEgress(); err == nil {
		t.Fatal("failed rebuild left the host healthy")
	}
}

// Allowlist pairs are keyed by lease: the MAC is stable for a lease and
// differs between leases.
func TestAllowlistMACIsPerLease(t *testing.T) {
	a, b := allowlistMAC("lease-a"), allowlistMAC("lease-b")
	if a != allowlistMAC("lease-a") || a == b || !sandboxhost.AllowlistMAC(a) || !sandboxhost.AllowlistMAC(b) {
		t.Fatalf("MACs %s %s", a, b)
	}
}

// collidingAllowLeases returns two allowlist leases whose allowlist MACs
// are equal (24 hash bits: a pair turns up within a few thousand leases).
func collidingAllowLeases(t *testing.T, allow ...string) (protocol.SandboxLeaseV1, protocol.SandboxLeaseV1) {
	t.Helper()
	seen := map[string]int{}
	for n := 1000; n < 1000+1<<16; n++ {
		mac := allowlistMAC(protocol.SandboxLeaseIDV1(allowLease(n)))
		if m, ok := seen[mac]; ok {
			return allowLease(m, allow...), allowLease(n, allow...)
		}
		seen[mac] = n
	}
	t.Fatal("no colliding leases")
	panic("unreachable")
}

// A lease whose allowlist MAC a live allowlist sandbox on the host holds
// is refused before its pairs load or its container exists, so two
// sandboxes never share one confinement; the live sandbox keeps its pairs.
func TestCreateAllowlistRefusesMACCollision(t *testing.T) {
	first, second := collidingAllowLeases(t)
	first.Network.Allow, second.Network.Allow = []string{"140.82.112.0/20"}, []string{"151.101.0.0/16"}
	h := newAllowHost(t)
	b := h.backend()
	if err := b.Create(context.Background(), instanceOf(first), first); err != nil {
		t.Fatal(err)
	}
	loads, containers := len(h.loads), len(h.engine.created)
	err := b.Create(context.Background(), instanceOf(second), second)
	if err == nil || !errors.Is(err, errAllowlistMACCollision) || !strings.Contains(err.Error(), sandbox.EgressFirewallUnavailable) {
		t.Fatalf("colliding create = %v", err)
	}
	if strings.Contains(fmt.Sprint(h.loads[loads:]), "151.101") || len(h.engine.created) != containers {
		t.Fatalf("colliding create loaded %v / created %d containers", h.loads[loads:], len(h.engine.created)-containers)
	}
	if err := b.ensureEgress(); err != nil {
		t.Fatal(err)
	}
	if got, want := lastLoad(h), fmt.Sprintf("[{%s [140.82.112.0/20]}]", allowlistMAC(protocol.SandboxLeaseIDV1(first))); got != want {
		t.Fatalf("allowlists after refusal %s, want %s", got, want)
	}
	// Once the first sandbox is gone, the address is free again.
	if err := b.Destroy(context.Background(), instanceOf(first)); err != nil {
		t.Fatal(err)
	}
	if err := b.Create(context.Background(), instanceOf(second), second); err != nil {
		t.Fatalf("create after the holder left = %v", err)
	}
}

// A create in flight (pairs loaded, container not yet listed) holds its
// address too, until the create returns.
func TestCreateAllowlistRefusesMACCollisionInFlight(t *testing.T) {
	first, second := collidingAllowLeases(t, "140.82.112.0/20")
	h := newAllowHost(t)
	b := h.backend()
	if err := b.syncAllowlists(context.Background(), pendingAllowlist{leaseID: protocol.SandboxLeaseIDV1(first), allow: first.Network.Allow}); err != nil {
		t.Fatal(err)
	}
	if err := b.Create(context.Background(), instanceOf(second), second); !errors.Is(err, errAllowlistMACCollision) {
		t.Fatalf("create colliding with an in-flight create = %v", err)
	}
	b.releaseAllowlist(protocol.SandboxLeaseIDV1(first))
	if err := b.Create(context.Background(), instanceOf(second), second); err != nil {
		t.Fatalf("create after the in-flight create returned = %v", err)
	}
}

// Two listed sandboxes that share a MAC (one placed by an older agent)
// load no pairs for it: neither reaches anything.
func TestAllowlistListedMACCollisionAdmitsNothing(t *testing.T) {
	first, second := collidingAllowLeases(t, "140.82.112.0/20")
	h := newAllowHost(t)
	b := h.backend()
	if err := b.Create(context.Background(), instanceOf(first), first); err != nil {
		t.Fatal(err)
	}
	// Plant the second as an older agent would have.
	c := *h.engine.containers[instanceOf(first)]
	c.Labels = map[string]string{}
	for k, v := range h.engine.containers[instanceOf(first)].Labels {
		c.Labels[k] = v
	}
	c.Labels[LabelLeaseID] = protocol.SandboxLeaseIDV1(second)
	h.engine.containers[instanceOf(second)] = &c
	if err := b.ensureEgress(); err != nil {
		t.Fatal(err)
	}
	if got, want := lastLoad(h), fmt.Sprintf("[{%s []}]", allowlistMAC(protocol.SandboxLeaseIDV1(first))); got != want {
		t.Fatalf("allowlists with a shared MAC %s, want %s", got, want)
	}
}
