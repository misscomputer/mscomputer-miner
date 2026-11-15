// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxhost

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// TenantBindingTable is the bridge table of a host whose profile has the
// docker member. A docker sandbox's runtime admits raw and packet sockets
// (docs/sandbox-docker.md), so its guest can write any Ethernet frame onto
// the egress bridge: an ARP reply claiming a sibling sandbox's address, or an
// IPv4 packet from a foreign source to dodge the per-address rate limits.
// The table admits from a port of the egress bridge only IPv4 and ARP whose
// (port, Ethernet source, IPv4 or ARP sender) is a binding the backend
// installed for the live sandbox on that port, and drops every other frame
// from those ports, so a port without a binding passes nothing.
const TenantBindingTable = "mcsbx_sandbox_antispoof"

// TenantBindingDropCounter is the named counter of dropped frames.
const TenantBindingDropCounter = "spoofed"

// PortBinding is one sandbox's address on the egress bridge: the host end
// of its veth pair and the MAC and IPv4 address the engine gave it.
type PortBinding struct {
	Port string
	MAC  string
	IP   netip.Addr
}

var portName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// Validate requires an interface name, a unicast MAC in canonical lower-case
// form and an IPv4 address inside subnet.
func (p PortBinding) Validate(subnet netip.Prefix) error {
	if !portName.MatchString(p.Port) {
		return fmt.Errorf("binding port %q is not an interface name", p.Port)
	}
	mac, err := net.ParseMAC(p.MAC)
	if err != nil || len(mac) != 6 || mac.String() != p.MAC || mac[0]&1 != 0 {
		return fmt.Errorf("binding MAC %q is not a canonical unicast MAC", p.MAC)
	}
	if !p.IP.Is4() || !subnet.Contains(p.IP) || p.IP == subnet.Addr() || p.IP == subnet.Addr().Next() {
		return fmt.Errorf("binding address %s is not a sandbox address of %s", p.IP, subnet)
	}
	return nil
}

// TenantBindingRuleset is the nft script that atomically replaces the
// binding table with exactly bindings. Every port, MAC and address may be
// bound at most once.
func (e ProfileEgress) TenantBindingRuleset(bindings []PortBinding) (string, error) {
	subnet, err := netip.ParsePrefix(e.Subnet)
	if err != nil {
		return "", err
	}
	sorted := append([]PortBinding(nil), bindings...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Port < sorted[j].Port })
	seen := map[string]bool{}
	elements := make([]string, 0, len(sorted))
	for _, binding := range sorted {
		if err := binding.Validate(subnet); err != nil {
			return "", err
		}
		for _, key := range []string{"port " + binding.Port, "mac " + binding.MAC, "ip " + binding.IP.String()} {
			if seen[key] {
				return "", errors.New("binding " + key + " is bound twice")
			}
			seen[key] = true
		}
		elements = append(elements, fmt.Sprintf(`"%s" . %s . %s`, binding.Port, binding.MAC, binding.IP))
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("table bridge %s", TenantBindingTable)
	w("delete table bridge %s", TenantBindingTable)
	w("table bridge %s {", TenantBindingTable)
	w("  counter %s {", TenantBindingDropCounter)
	w("  }")
	w("  set bound {")
	w("    type ifname . ether_addr . ipv4_addr")
	if len(elements) != 0 {
		w("    elements = { %s }", strings.Join(elements, ", "))
	}
	w("  }")
	w("  chain prerouting {")
	w("    type filter hook prerouting priority -300; policy accept;")
	w(`    meta ibrname != "%s" accept`, e.Bridge)
	w("    ether type ip iifname . ether saddr . ip saddr @bound accept")
	// Both the Ethernet source and the ARP sender hardware address must be
	// the port's bound MAC, with the bound sender IP.
	w("    ether type arp arp htype 1 arp ptype 0x0800 arp hlen 6 arp plen 4 iifname . ether saddr . arp saddr ip @bound iifname . arp saddr ether . arp saddr ip @bound accept")
	w(`    counter name "%s" drop`, TenantBindingDropCounter)
	w("  }")
	w("}")
	return b.String(), nil
}

// ApplyTenantBindings loads the binding table with exactly bindings in one
// nft transaction.
func ApplyTenantBindings(e ProfileEgress, bindings []PortBinding) error {
	script, err := e.TenantBindingRuleset(bindings)
	if err != nil {
		return err
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("load sandbox port bindings: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
