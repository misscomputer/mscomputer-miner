// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxhost

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

// TenantAllowlistPairs is the egress table's set confining allowlist
// sandboxes. An allowlist sandbox's interface carries an address in
// TenantAllowlistMACFirst..TenantAllowlistMACLast, set before it starts,
// and the egress chain refuses such a source every destination not paired
// with its address in the set. The rule is static, so the set failing
// closed is the default: before the agent loads a sandbox's pairs, after a
// reload of the table (which empties the set) and when a rebuild fails,
// the sandbox reaches nothing. Every other refusal of the egress chain
// still applies, so an allowlist never widens what public may reach.
const (
	TenantAllowlistPairs    = "allow_dsts"
	TenantAllowlistMACFirst = "06:6d:73:00:00:00"
	TenantAllowlistMACLast  = "06:6d:73:ff:ff:ff"
)

// TenantAllowlist is one allowlist sandbox: its interface address and the
// IPv4 prefixes it may reach besides the profile's resolvers.
type TenantAllowlist struct {
	MAC          string
	Destinations []netip.Prefix
}

// AllowlistMAC reports whether mac is a canonical lower-case address of
// the allowlist range.
func AllowlistMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err == nil && len(hw) == 6 && hw.String() == mac && strings.HasPrefix(mac, TenantAllowlistMACFirst[:9])
}

// TenantAllowlistScript is the nft script that replaces the allowlist set
// in one transaction. Every sandbox may also reach e's resolvers, so
// hostnames resolve inside it. Prefixes are collapsed per sandbox (an
// interval set refuses overlapping elements); non-IPv4 ones are dropped.
func (e ProfileEgress) TenantAllowlistScript(lists []TenantAllowlist) (string, error) {
	var pairs []string
	seen := map[string]bool{}
	for _, list := range lists {
		if !AllowlistMAC(list.MAC) {
			return "", fmt.Errorf("allowlist sandbox address %q is not in %s-%s", list.MAC, TenantAllowlistMACFirst, TenantAllowlistMACLast)
		}
		if seen[list.MAC] {
			return "", fmt.Errorf("allowlist sandbox address %s is listed twice", list.MAC)
		}
		seen[list.MAC] = true
		dests := append([]netip.Prefix(nil), list.Destinations...)
		for _, server := range e.DNS {
			dests = append(dests, netip.PrefixFrom(netip.MustParseAddr(server), 32))
		}
		for _, prefix := range CollapsePrefixes(dests) {
			pairs = append(pairs, list.MAC+" . "+prefix.String())
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet %s %s\n", TenantEgressTable, TenantAllowlistPairs)
	if len(pairs) != 0 {
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", TenantEgressTable, TenantAllowlistPairs, strings.Join(pairs, ", "))
	}
	return b.String(), nil
}

// CollapsePrefixes returns the canonical IPv4 prefixes of prefixes sorted,
// without any prefix another one contains.
func CollapsePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	var v4 []netip.Prefix
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			v4 = append(v4, prefix.Masked())
		}
	}
	sort.Slice(v4, func(i, j int) bool {
		if c := v4[i].Addr().Compare(v4[j].Addr()); c != 0 {
			return c < 0
		}
		return v4[i].Bits() < v4[j].Bits()
	})
	var out []netip.Prefix
	for _, prefix := range v4 {
		if len(out) != 0 && out[len(out)-1].Contains(prefix.Addr()) && out[len(out)-1].Bits() <= prefix.Bits() {
			continue
		}
		out = append(out, prefix)
	}
	return out
}

// ApplyTenantAllowlists replaces the allowlist set with lists in one nft
// transaction: a failed load leaves the previous set.
func ApplyTenantAllowlists(e ProfileEgress, lists []TenantAllowlist) error {
	script, err := e.TenantAllowlistScript(lists)
	if err != nil {
		return err
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("load sandbox allowlists: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
