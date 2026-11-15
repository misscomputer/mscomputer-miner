// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/miner"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxhost"
)

// LabelNetworkAllow carries an allowlist lease's allow entries (a JSON
// array) on its container, so the agent rebuilds the firewall's allowlist
// set from the engine's container list alone, after a restart or a reload
// of the table.
const LabelNetworkAllow = "computer.ms.sandbox.network-allow"

const (
	allowlistTimeout = 10 * time.Second
	allowResolveWait = 2 * time.Second
)

var (
	applyTenantAllowlists = sandboxhost.ApplyTenantAllowlists
	// resolveAllowHost returns the IPv4 addresses of host from one of the
	// profile's public resolvers, the ones the sandbox itself is given.
	resolveAllowHost = func(ctx context.Context, server, host string) ([]netip.Addr, error) {
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(server, "53"))
		}}
		return resolver.LookupNetIP(ctx, "ip4", host)
	}
)

// allowlisted reports whether a lease in network mode runs confined to an
// allowlist.
func allowlisted(mode string) bool { return mode == sandbox.NetworkAllowlist }

// allowlistMAC is the interface address of a lease's sandbox: a fixed
// prefix the egress chain confines, and 24 bits of the lease ID's hash.
func allowlistMAC(leaseID string) string {
	sum := sha256.Sum256([]byte(leaseID))
	return fmt.Sprintf("%s:%02x:%02x:%02x", sandboxhost.TenantAllowlistMACFirst[:8], sum[0], sum[1], sum[2])
}

// pendingAllowlist is an allowlist sandbox whose pairs must be loaded
// before its container exists.
type pendingAllowlist struct {
	leaseID string
	allow   []string
}

// syncAllowlists rebuilds the egress table's allowlist set from every
// allowlist container the engine lists (whatever its state) plus pending,
// in one nft transaction. Hostnames are resolved again on every rebuild
// (each agent sweep) through each of the profile's resolvers, so a moved
// host follows its DNS; a name that does not resolve admits nothing. Any
// failure leaves the previous set, which fails closed: a sandbox missing
// from it reaches nothing.
func (b *GVisor) syncAllowlists(ctx context.Context, pending ...pendingAllowlist) error {
	if b.config.Egress == nil {
		return nil
	}
	b.allowlists.Lock()
	defer b.allowlists.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), allowlistTimeout)
	defer cancel()
	filters, _ := json.Marshal(map[string][]string{"label": {LabelNetworkAllow, LabelSandbox}})
	var containers []listedContainer
	if err := b.engine.call(ctx, http.MethodGet, "/containers/json", url.Values{"all": {"1"}, "filters": {string(filters)}}, nil, &containers); err != nil {
		return fmt.Errorf("list allowlist sandboxes: %w", err)
	}
	byMAC := map[string][]string{}
	owner := map[string]string{}
	collided := map[string]bool{}
	// claim records leaseID's allow entries under its MAC; a second lease
	// on the same MAC would share its confinement, so that MAC admits
	// nothing at all instead.
	claim := func(leaseID string, allow []string) {
		mac := allowlistMAC(leaseID)
		if prev, ok := owner[mac]; ok && prev != leaseID {
			collided[mac] = true
		}
		owner[mac] = leaseID
		byMAC[mac] = allow
	}
	for _, listed := range containers {
		raw, ok := listed.Labels[LabelNetworkAllow]
		if !ok {
			continue
		}
		var allow []string
		if err := json.Unmarshal([]byte(raw), &allow); err != nil {
			// Its pairs stay unloaded: the sandbox reaches nothing.
			slog.Warn("allowlist sandbox label is unreadable; it reaches nothing", "sandbox", firstName(listed), "error", err)
			continue
		}
		claim(listed.Labels[LabelLeaseID], allow)
	}
	for leaseID, allow := range b.allowPending {
		claim(leaseID, allow)
	}
	for _, p := range pending {
		// A new lease whose MAC another live allowlist lease on this host
		// holds is refused before its pairs or container exist.
		if prev, ok := owner[allowlistMAC(p.leaseID)]; ok && prev != p.leaseID {
			return fmt.Errorf("%w: lease %s and lease %s", errAllowlistMACCollision, p.leaseID, prev)
		}
		claim(p.leaseID, p.allow)
	}
	for mac := range collided {
		slog.Warn("allowlist sandboxes share an interface address; it admits nothing", "mac", mac)
		byMAC[mac] = nil
	}
	macs := make([]string, 0, len(byMAC))
	for mac := range byMAC {
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	lists := make([]sandboxhost.TenantAllowlist, 0, len(macs))
	resolved := map[string][]netip.Prefix{}
	for _, mac := range macs {
		list := sandboxhost.TenantAllowlist{MAC: mac}
		for _, entry := range byMAC[mac] {
			if prefix, err := netip.ParsePrefix(entry); err == nil {
				list.Destinations = append(list.Destinations, prefix)
				continue
			}
			prefixes, done := resolved[entry]
			if !done {
				prefixes = b.resolveAllowEntry(ctx, entry)
				resolved[entry] = prefixes
			}
			list.Destinations = append(list.Destinations, prefixes...)
		}
		lists = append(lists, list)
	}
	// A host without allowlist sandboxes runs no nft for them: a fresh or
	// reloaded table already holds the empty set. With any, the set is
	// loaded on every rebuild, so a flushed set is refilled within a sweep.
	if len(lists) == 0 && !b.allowFilled {
		return nil
	}
	if err := applyTenantAllowlists(*b.config.Egress, lists); err != nil {
		return err
	}
	b.allowFilled = len(lists) != 0
	for _, p := range pending {
		if b.allowPending == nil {
			b.allowPending = map[string][]string{}
		}
		b.allowPending[p.leaseID] = p.allow
	}
	return nil
}

// errAllowlistMACCollision refuses an allowlist lease whose interface
// address another live allowlist lease on the host already holds.
var errAllowlistMACCollision = errors.New("allowlist interface address is held by another lease")

// releaseAllowlist ends a create's reservation of its lease's allowlist
// address; from then on the engine's container list (if the container
// exists) holds it.
func (b *GVisor) releaseAllowlist(leaseID string) {
	b.allowlists.Lock()
	delete(b.allowPending, leaseID)
	b.allowlists.Unlock()
}

// resolveAllowEntry resolves one hostname through every profile resolver
// to host prefixes, dropping the addresses the egress chain refuses anyway.
func (b *GVisor) resolveAllowEntry(ctx context.Context, host string) []netip.Prefix {
	seen := map[netip.Addr]bool{}
	var prefixes []netip.Prefix
	for _, server := range b.config.Egress.DNS {
		lookup, cancel := context.WithTimeout(ctx, allowResolveWait)
		addrs, err := resolveAllowHost(lookup, server, host)
		cancel()
		if err != nil {
			slog.Debug("allowlist host does not resolve here", "host", host, "resolver", server, "error", err)
			continue
		}
		for _, addr := range addrs {
			addr = addr.Unmap()
			if addr.Is4() && !seen[addr] && !sandboxhost.TenantDestinationDenied(addr, b.config.Egress.DenyCIDRs) {
				seen[addr] = true
				prefixes = append(prefixes, netip.PrefixFrom(addr, 32))
			}
		}
	}
	if len(prefixes) == 0 {
		slog.Warn("allowlist host has no admissible IPv4 address; it admits nothing until it does", "host", host)
	}
	return prefixes
}

// verifyAllowlistMAC fails a started allowlist sandbox whose interface does
// not carry its allowlist address (the engine ignored the request), which
// the egress chain would not confine. It is removed; the create fails as a
// miner fault.
func (b *GVisor) verifyAllowlistMAC(ctx context.Context, instanceID string) error {
	c, found, err := b.inspect(ctx, instanceID)
	if err == nil && !found {
		err = fmt.Errorf("sandbox %s vanished", instanceID)
	}
	if err == nil {
		network, ok := c.NetworkSettings.Networks["bridge"]
		if want := allowlistMAC(c.Config.Labels[LabelLeaseID]); !ok || len(c.NetworkSettings.Networks) != 1 || strings.ToLower(network.MacAddress) != want {
			err = fmt.Errorf("sandbox %s interface address %q is not its allowlist address %s", instanceID, network.MacAddress, want)
		}
	}
	if err == nil {
		return nil
	}
	if removeErr := b.removeContainer(context.WithoutCancel(ctx), instanceID); removeErr != nil {
		err = fmt.Errorf("%w; remove it: %v", err, removeErr)
	}
	return fmt.Errorf("%w: %v", &miner.SandboxFault{Code: sandbox.EgressFirewallUnavailable}, err)
}
