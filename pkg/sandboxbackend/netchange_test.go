// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/miner"
	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxhost"
)

// netHost is an allowHost whose kernel set honours NoResolvers.
func netHost(t *testing.T) (*allowHost, *GVisor, string) {
	h := newAllowHost(t)
	loadedTenantAllowlistPairs = func() (map[string][]netip.Prefix, map[string]bool, error) {
		h.reads++
		pairs := map[string][]netip.Prefix{}
		if len(h.loads) == 0 {
			return pairs, nil, nil
		}
		for _, list := range h.loads[len(h.loads)-1] {
			dests := append([]netip.Prefix(nil), list.Destinations...)
			if !list.NoResolvers {
				for _, server := range h.config.Egress.DNS {
					dests = append(dests, netip.PrefixFrom(netip.MustParseAddr(server), 32))
				}
			}
			if len(dests) != 0 {
				pairs[list.MAC] = sandboxhost.CollapsePrefixes(dests)
			}
		}
		return pairs, nil, nil
	}
	dir := filepath.Join(t.TempDir(), "net")
	b := h.backend()
	if err := b.EnableNetworkChanges(dir); err != nil {
		t.Fatal(err)
	}
	return h, b, dir
}

func lastPairs(t *testing.T, mac string) []netip.Prefix {
	pairs, _, err := loadedTenantAllowlistPairs()
	if err != nil {
		t.Fatal(err)
	}
	return pairs[mac]
}

// A running allowlist sandbox's policy changes to none, public and a new
// allowlist, each verified in the set before SetNetwork returns; the change
// survives a restart of the agent (a new backend on the same record).
func TestSetNetworkRetargetsAllowlist(t *testing.T) {
	h, b, dir := netHost(t)
	lease := allowLease(1, "140.82.112.0/20")
	id := protocol.SandboxLeaseIDV1(lease)
	mac := allowlistMAC(id)
	if err := b.Create(context.Background(), instanceOf(lease), lease); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	none := sandbox.NetworkPolicy{Mode: sandbox.NetworkNone, Allow: []string{}}
	if err := b.SetNetwork(context.Background(), instanceOf(lease), id, t0, none); err != nil {
		t.Fatal(err)
	}
	if got := lastPairs(t, mac); len(got) != 0 {
		t.Fatalf("none still reaches %v", got)
	}
	public := sandbox.NetworkPolicy{Mode: sandbox.NetworkPublic, Allow: []string{}}
	if err := b.SetNetwork(context.Background(), instanceOf(lease), id, t0.Add(time.Second), public); err != nil {
		t.Fatal(err)
	}
	if got := lastPairs(t, mac); len(got) != 1 || got[0].String() != "0.0.0.0/0" {
		t.Fatalf("public pairs %v", got)
	}
	// An older request is stale; the exact resend is idempotent.
	if err := b.SetNetwork(context.Background(), instanceOf(lease), id, t0, none); !errors.Is(err, miner.ErrNetworkPolicyStale) {
		t.Fatalf("stale set = %v", err)
	}
	if err := b.SetNetwork(context.Background(), instanceOf(lease), id, t0.Add(time.Second), public); err != nil {
		t.Fatalf("resend = %v", err)
	}
	allow := sandbox.NetworkPolicy{Mode: sandbox.NetworkAllowlist, Allow: []string{"192.0.2.0/24"}}
	if err := b.SetNetwork(context.Background(), instanceOf(lease), id, t0.Add(2*time.Second), allow); err != nil {
		t.Fatal(err)
	}
	if got := lastPairs(t, mac); len(got) != 3 || got[0].String() != "1.1.1.1/32" || got[2].String() != "192.0.2.0/24" {
		t.Fatalf("allowlist pairs %v", got)
	}
	// A restarted agent loads the changed policy, not the label.
	restarted := h.backend()
	if err := restarted.EnableNetworkChanges(dir); err != nil {
		t.Fatal(err)
	}
	if err := restarted.syncAllowlists(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := lastLoad(h); !strings.Contains(got, "192.0.2.0/24") || strings.Contains(got, "140.82.112.0/20") {
		t.Fatalf("restart loaded %s", got)
	}
	// An unreadable record confines the sandbox to nothing.
	if err := os.WriteFile(filepath.Join(dir, id+".json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	corrupt := h.backend()
	if err := corrupt.EnableNetworkChanges(dir); err != nil {
		t.Fatal(err)
	}
	if err := corrupt.syncAllowlists(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := lastPairs(t, mac); len(got) != 0 {
		t.Fatalf("unreadable record reaches %v", got)
	}
	// Destroy prunes the record.
	if err := corrupt.Destroy(context.Background(), instanceOf(lease)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, id+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("record after destroy: %v", err)
	}
}

// A public sandbox (no confined address), a backend without the feature,
// and a sandbox that is not running are refused; a change that cannot be
// verified leaves the sandbox reaching nothing.
func TestSetNetworkRefusesAndFailsClosed(t *testing.T) {
	_, b, _ := netHost(t)
	public := testLease(publicLease)
	if err := b.Create(context.Background(), instanceOf(public), public); err != nil {
		t.Fatal(err)
	}
	none := sandbox.NetworkPolicy{Mode: sandbox.NetworkNone, Allow: []string{}}
	now := time.Now()
	if err := b.SetNetwork(context.Background(), instanceOf(public), protocol.SandboxLeaseIDV1(public), now, none); !errors.Is(err, miner.ErrNetworkChangeUnsupported) {
		t.Fatalf("public sandbox = %v", err)
	}
	lease := allowLease(2, "140.82.112.0/20")
	id := protocol.SandboxLeaseIDV1(lease)
	if err := b.SetNetwork(context.Background(), instanceOf(lease), id, now, none); !errors.Is(err, miner.ErrSandboxNotRunning) {
		t.Fatalf("missing sandbox = %v", err)
	}
	plain := newAllowHost(t).backend()
	if err := plain.SetNetwork(context.Background(), "x", id, now, none); !errors.Is(err, miner.ErrNetworkChangeUnsupported) {
		t.Fatalf("feature off = %v", err)
	}

	h, b, _ := netHost(t)
	if err := b.Create(context.Background(), instanceOf(lease), lease); err != nil {
		t.Fatal(err)
	}
	read := loadedTenantAllowlistPairs
	loadedTenantAllowlistPairs = func() (map[string][]netip.Prefix, map[string]bool, error) {
		return map[string][]netip.Prefix{}, nil, nil // the public pair never shows up
	}
	publicPolicy := sandbox.NetworkPolicy{Mode: sandbox.NetworkPublic, Allow: []string{}}
	if err := b.SetNetwork(context.Background(), instanceOf(lease), id, now, publicPolicy); err == nil || !strings.Contains(err.Error(), "not verified") {
		t.Fatalf("unverified change = %v", err)
	}
	loadedTenantAllowlistPairs = read
	if got := lastLoad(h); strings.Contains(got, "0.0.0.0/0") || strings.Contains(got, "140.82.112.0/20") {
		t.Fatalf("after a failed change the sandbox may reach %s", got)
	}
}
