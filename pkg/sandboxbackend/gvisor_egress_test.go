// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/miner"
	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxhost"
)

// egressHost is a scripted host whose profile has egress, with the host
// firewall hooks replaced: loaded reports the firewall state, listing its
// normalized listing, and applied counts loads, each of which restores
// listing to the ruleset's.
type egressHost struct {
	*host
	loaded  error
	listing string
	apply   error
	applied int
}

const egressRuleset = "table inet mcsbx_sandbox_egress { ... }"

func newEgressHost(t *testing.T) *egressHost {
	h := &egressHost{host: newHost(t)}
	h.config.Egress = &sandboxhost.ProfileEgress{Bridge: "mcsbxeg0", Subnet: "10.231.0.0/24", DNS: []string{"1.1.1.1", "8.8.8.8"},
		BandwidthMbit: 50, NewConnsPerSecond: 50, DenyCIDRs: []string{}}
	h.listing = egressRuleset
	listing, apply := tenantEgressListing, applyTenantEgress
	t.Cleanup(func() { tenantEgressListing, applyTenantEgress = listing, apply })
	tenantEgressListing = func(sandboxhost.ProfileEgress) (string, error) {
		if h.loaded != nil {
			return "", h.loaded
		}
		return h.listing, nil
	}
	applyTenantEgress = func(sandboxhost.ProfileEgress) error {
		h.applied++
		if h.apply == nil {
			h.loaded, h.listing = nil, egressRuleset
		}
		return h.apply
	}
	return h
}

func publicLease(l *protocol.SandboxLeaseV1) { l.Network.Mode = sandbox.NetworkPublic }

// On a host with egress a public lease joins the egress bridge with the
// profile's resolvers, and a lease in mode none keeps no network.
func TestCreatePublicLeaseJoinsTheEgressBridge(t *testing.T) {
	h := newEgressHost(t)
	b := h.backend()
	if !b.EgressEnabled() {
		t.Fatal("backend with an egress profile does not report egress")
	}
	var observedPublic []bool
	b.observeInstance = func(_ int, public bool) []sandboxhost.Check {
		observedPublic = append(observedPublic, public)
		return nil
	}
	ctx := context.Background()
	public := testLease(publicLease)
	if err := b.Create(ctx, instanceOf(public), public); err != nil {
		t.Fatal(err)
	}
	none := testLease(func(l *protocol.SandboxLeaseV1) { l.SandboxID = "sbx-" + strings.Repeat("0", 31) + "2" })
	if err := b.Create(ctx, instanceOf(none), none); err != nil {
		t.Fatal(err)
	}
	if len(h.engine.created) != 2 {
		t.Fatalf("engine created %d containers, want 2", len(h.engine.created))
	}
	for i, want := range []struct{ mode, dns string }{{"bridge", "[1.1.1.1 8.8.8.8]"}, {"none", "<nil>"}} {
		hostConfig := h.engine.created[i]["HostConfig"].(map[string]any)
		if hostConfig["NetworkMode"] != want.mode || fmt.Sprint(hostConfig["Dns"]) != want.dns {
			t.Errorf("container %d: NetworkMode %v Dns %v, want %s %s", i, hostConfig["NetworkMode"], hostConfig["Dns"], want.mode, want.dns)
		}
		if _, ports := hostConfig["PortBindings"]; ports || hostConfig["PublishAllPorts"] != false {
			t.Errorf("container %d publishes ports", i)
		}
	}
	if fmt.Sprint(observedPublic) != "[true false]" {
		t.Errorf("instance observations public=%v, want [true false]", observedPublic)
	}
	if h.applied != 0 {
		t.Errorf("loaded firewall was applied again %d times", h.applied)
	}
}

// A public lease starts only behind the firewall: a flushed ruleset is
// loaded again first, and one that cannot be loaded fails the create as a
// miner fault before any container exists.
func TestCreatePublicLeaseRequiresTheFirewall(t *testing.T) {
	h := newEgressHost(t)
	h.loaded = errors.New("table missing")
	lease := testLease(publicLease)
	if err := h.backend().Create(context.Background(), instanceOf(lease), lease); err != nil || h.applied != 1 {
		t.Fatalf("create after a flush = %v with %d loads, want success after 1", err, h.applied)
	}

	h = newEgressHost(t)
	h.loaded, h.apply = errors.New("table missing"), errors.New("nft failed")
	err := h.backend().Create(context.Background(), instanceOf(lease), lease)
	if err == nil || refusalCode(err) != "" || len(h.engine.created) != 0 {
		t.Fatalf("create without a firewall = %v (refusal %q), %d containers; want a miner fault and none", err, refusalCode(err), len(h.engine.created))
	}
}

// allowlist needs the egress member, and a lease with the docker
// capability (which could change its bridge address) is refused.
func TestAllowlistNeedsEgressAndNoCapability(t *testing.T) {
	allow := func(l *protocol.SandboxLeaseV1) {
		l.Network = sandbox.NetworkPolicy{Mode: sandbox.NetworkAllowlist, Allow: []string{"pypi.org"}}
	}
	if code := newEgressHost(t).backend().Unsupported(testLease(allow)); code != "" {
		t.Fatalf("allowlist on an egress host: %q", code)
	}
	if code := newHost(t).backend().Unsupported(testLease(allow)); code != "network_policy_unsupported" {
		t.Fatalf("allowlist without egress: %q", code)
	}
	docker := testLease(func(l *protocol.SandboxLeaseV1) { allow(l); l.Capabilities = []string{sandbox.CapabilityDocker} })
	if code := newEgressHost(t).backend().Unsupported(docker); code != "network_policy_unsupported" && code != sandbox.CapabilityUnsupported {
		t.Fatalf("allowlist with docker: %q", code)
	}
	if newHost(t).backend().EgressEnabled() {
		t.Fatal("backend without egress reports egress")
	}
}

// The readback binds the network to the lease: a public sandbox the engine
// left without its bridge or resolvers, and a none sandbox the engine
// attached to the bridge, are both miner faults.
func TestReadbackBindsNetworkToTheLease(t *testing.T) {
	for _, test := range []struct {
		name    string
		public  bool
		applied func(*engineContainer)
	}{
		{name: "public sandbox left without network", public: true, applied: func(c *engineContainer) { c.Host["NetworkMode"] = "none" }},
		{name: "public sandbox on another network", public: true, applied: func(c *engineContainer) { c.Host["NetworkMode"] = "host" }},
		{name: "public sandbox with other resolvers", public: true, applied: func(c *engineContainer) { c.Host["Dns"] = []any{"10.0.0.53"} }},
		{name: "none sandbox attached to the bridge", applied: func(c *engineContainer) { c.Host["NetworkMode"] = "bridge" }},
		{name: "none sandbox with resolvers", applied: func(c *engineContainer) { c.Host["Dns"] = []any{"1.1.1.1"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newEgressHost(t)
			h.engine.applied = test.applied
			lease := testLease(nil)
			if test.public {
				lease = testLease(publicLease)
			}
			err := h.backend().Create(context.Background(), instanceOf(lease), lease)
			if err == nil || refusalCode(err) != "" || !strings.Contains(err.Error(), "namespaces, ports") && !strings.Contains(err.Error(), "settings") {
				t.Fatalf("create = %v, want a readback miner fault", err)
			}
		})
	}
}

// With egress the daemon's default bridge must be the profile's bridge and
// the daemon still manages no firewall; without it the bridge stays none.
func TestDaemonFirewallOffFollowsTheEgressProfile(t *testing.T) {
	off, on := false, true
	base := daemonConfig{IPTables: &off, IP6Tables: &off, IPForward: &off, IPMasq: &off, Bridge: "none"}
	egress := &sandboxhost.ProfileEgress{Bridge: "mcsbxeg0"}
	withBridge := func(mutate func(*daemonConfig)) daemonConfig {
		c := base
		c.Bridge = "mcsbxeg0"
		mutate(&c)
		return c
	}
	for _, test := range []struct {
		name   string
		config daemonConfig
		egress *sandboxhost.ProfileEgress
		ok     bool
	}{
		{name: "no egress, bridge none", config: base, ok: true},
		{name: "no egress, a bridge", config: withBridge(func(*daemonConfig) {}), ok: false},
		{name: "egress bridge", config: withBridge(func(*daemonConfig) {}), egress: egress, ok: true},
		{name: "egress, bridge none", config: base, egress: egress, ok: false},
		{name: "egress, other bridge", config: withBridge(func(c *daemonConfig) { c.Bridge = "docker0" }), egress: egress, ok: false},
		{name: "egress, daemon iptables", config: withBridge(func(c *daemonConfig) { c.IPTables = &on }), egress: egress, ok: false},
		{name: "egress, daemon masquerade", config: withBridge(func(c *daemonConfig) { c.IPMasq = &on }), egress: egress, ok: false},
		{name: "egress, daemon bip", config: withBridge(func(c *daemonConfig) { c.BIP = "10.231.0.1/24" }), egress: egress, ok: false},
		{name: "egress, daemon icc", config: withBridge(func(c *daemonConfig) { c.ICC = &off }), egress: egress, ok: false},
	} {
		if err := test.config.firewallOff(test.egress); (err == nil) != test.ok {
			t.Errorf("%s: firewallOff = %v, want ok=%v", test.name, err, test.ok)
		}
	}
}

// The firewall is re-verified: once its listing is known, a flushed or
// edited table, or a missing DOCKER-USER accept, is loaded again before a
// public sandbox starts and on the sweep's health check; one that cannot be
// loaded again makes the miner unhealthy and fails public creates as the
// fault egress_firewall_unavailable, while sandbox-egress-v1 (a static
// promise of the profile) stays advertised.
func TestEgressFirewallIsReverified(t *testing.T) {
	h := newEgressHost(t)
	b := h.backend()
	ctx := context.Background()
	lease := testLease(publicLease)
	if !b.EgressHealthy() || h.applied != 0 {
		t.Fatalf("intact firewall: healthy %v after %d loads", b.EgressHealthy(), h.applied)
	}
	// An edited table lists differently from the one the agent loaded.
	h.listing = egressRuleset + " edited"
	if err := b.Create(ctx, instanceOf(lease), lease); err != nil || h.applied != 1 {
		t.Fatalf("create after an edit = %v with %d loads, want success after 1", err, h.applied)
	}
	// A missing DOCKER-USER accept fails the listing like a missing table.
	h.loaded, h.apply = errors.New("DOCKER-USER lacks the sandbox egress accept"), errors.New("iptables failed")
	b.egress.checked = time.Time{}
	if b.EgressHealthy() || h.applied != 2 {
		t.Fatalf("broken firewall still healthy (%d loads)", h.applied)
	}
	if !b.EgressEnabled() {
		t.Fatal("a broken firewall withdrew sandbox-egress-v1; the profile's promise must stay advertised")
	}
	// Within egressRecheck the last outcome stands without another check.
	if b.EgressHealthy() || h.applied != 2 {
		t.Fatalf("unhealthy firewall rechecked within egressRecheck: %d loads", h.applied)
	}
	second := testLease(func(l *protocol.SandboxLeaseV1) {
		publicLease(l)
		l.SandboxID = "sbx-" + strings.Repeat("0", 31) + "2"
	})
	var fault *miner.SandboxFault
	if err := b.Create(ctx, instanceOf(second), second); err == nil || refusalCode(err) != "" || !errors.As(err, &fault) || fault.Code != sandbox.EgressFirewallUnavailable || len(h.engine.created) != 1 {
		t.Fatalf("public create without a firewall = %v, %d containers; want the miner fault %s and no new one", err, len(h.engine.created), sandbox.EgressFirewallUnavailable)
	}
	if attributed, known := sandbox.ReceiptErrorAttribution[sandbox.EgressFirewallUnavailable]; !known || !attributed {
		t.Fatal("egress_firewall_unavailable is not a miner fault")
	}
	none := testLease(func(l *protocol.SandboxLeaseV1) { l.SandboxID = "sbx-" + strings.Repeat("0", 31) + "3" })
	if err := b.Create(ctx, instanceOf(none), none); err != nil {
		t.Fatalf("none create needs no firewall: %v", err)
	}
	// Restored by an operator: the next check after egressRecheck adopts
	// the reload and is healthy again.
	h.apply = nil
	b.egress.checked = time.Now().Add(-egressRecheck)
	if !b.EgressHealthy() || h.applied != 4 {
		t.Fatalf("restored firewall: healthy %v after %d loads", b.EgressHealthy(), h.applied)
	}
	if err := b.Create(ctx, instanceOf(second), second); err != nil {
		t.Fatalf("public create after the restore: %v", err)
	}
	if b := newHost(t).backend(); b.EgressEnabled() || b.EgressHealthy() {
		t.Fatal("backend without egress reports egress")
	}
}
