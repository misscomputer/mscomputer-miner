// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxhost

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// ProfileEgress is the optional egress member of a host profile. Present,
// it lets leases in network mode public reach the internet: their
// containers join the daemon's default bridge (Bridge, a bridge the host
// creates with Subnet's first address before the daemon starts) and the
// gVisor netstack sends through it. The host firewall (TenantEgressRuleset)
// admits only new outbound connections from the bridge to public unicast
// addresses, refuses SMTP submission and relay ports, never lets a sandbox
// reach this host, its LAN or another sandbox, and polices each sandbox's
// bandwidth and new-connection rate. Leases in network mode none keep no
// network at all.
type ProfileEgress struct {
	Bridge string `json:"bridge"`
	Subnet string `json:"subnet"`
	// DNS are the public resolvers written to each public sandbox's
	// resolv.conf; the host resolver is not reachable from the bridge.
	DNS []string `json:"dns"`
	// BandwidthMbit bounds each sandbox's upload and, separately, its
	// download; NewConnsPerSecond bounds its new outbound connections.
	BandwidthMbit     int `json:"bandwidth_mbit"`
	NewConnsPerSecond int `json:"new_conns_per_second"`
	// DenyCIDRs are further IPv4 destinations to refuse, for example the
	// public addresses of the operator's other hosts.
	DenyCIDRs []string `json:"deny_cidrs"`
}

// The firewall tables a host with egress carries. The inet table filters
// and polices the bridge's routed traffic and masquerades it; the bridge
// table drops traffic bridged between two sandboxes.
const (
	TenantEgressTable    = "mcsbx_sandbox_egress"
	TenantIsolationTable = "mcsbx_sandbox_isolation"
)

// TenantBlockedTCPPorts are refused to every public sandbox: SMTP relay,
// submission over TLS and submission.
var TenantBlockedTCPPorts = []int{25, 465, 587}

// tenantEgressDenied are the IPv4 destinations no sandbox may reach in
// addition to every local address of the host: this-network, RFC 1918,
// CGNAT, loopback, link-local (cloud metadata), IETF protocol assignments,
// documentation, benchmarking, multicast and reserved. IPv6 is not routed.
var tenantEgressDenied = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
}

var bridgeName = regexp.MustCompile(`^[a-z][a-z0-9]{1,14}$`)

// Validate requires a named bridge, a private IPv4 subnet of /16 to /28,
// one to three public IPv4 resolvers, positive limits and canonical IPv4
// deny prefixes.
func (e ProfileEgress) Validate() error {
	if !bridgeName.MatchString(e.Bridge) || e.Bridge == "docker0" {
		return errors.New("egress bridge must be a dedicated interface name of 2-15 lowercase letters and digits")
	}
	subnet, err := netip.ParsePrefix(e.Subnet)
	if err != nil || !subnet.Addr().Is4() || subnet != subnet.Masked() || subnet.Bits() < 16 || subnet.Bits() > 28 || !subnet.Addr().IsPrivate() {
		return errors.New("egress subnet must be a canonical private IPv4 prefix of /16 to /28")
	}
	if len(e.DNS) == 0 || len(e.DNS) > 3 {
		return errors.New("egress dns must list 1-3 resolvers")
	}
	for _, server := range e.DNS {
		addr, err := netip.ParseAddr(server)
		if err != nil || !addr.Is4() || addr.String() != server || TenantDestinationDenied(addr, nil) {
			return errors.New("egress dns entries must be public IPv4 addresses")
		}
	}
	if e.BandwidthMbit <= 0 || e.BandwidthMbit > 10000 || e.NewConnsPerSecond <= 0 || e.NewConnsPerSecond > 10000 {
		return errors.New("egress bandwidth_mbit and new_conns_per_second must be 1..10000")
	}
	if e.DenyCIDRs == nil {
		return errors.New("egress deny_cidrs must be an array")
	}
	for _, entry := range e.DenyCIDRs {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != entry {
			return errors.New("egress deny_cidrs entries must be canonical IPv4 prefixes")
		}
	}
	return nil
}

// Gateway is the bridge's own address, the subnet's first.
func (e ProfileEgress) Gateway() netip.Prefix {
	subnet := netip.MustParsePrefix(e.Subnet)
	return netip.PrefixFrom(subnet.Addr().Next(), subnet.Bits())
}

// TenantDestinationDenied reports whether the firewall refuses addr to a
// public sandbox by prefix (local host addresses are refused separately).
func TenantDestinationDenied(addr netip.Addr, extra []string) bool {
	if !addr.Is4() {
		return true
	}
	for _, entry := range append(append([]string(nil), tenantEgressDenied...), extra...) {
		if netip.MustParsePrefix(entry).Contains(addr) {
			return true
		}
	}
	return false
}

// TenantEgressRuleset is the nft script that atomically replaces both
// tables. Rates are per sandbox address: the bridge only admits a sandbox's
// own subnet as source, and Docker gives each container its own address.
func (e ProfileEgress) TenantEgressRuleset() string {
	bytesPerSecond := e.BandwidthMbit * 125 // kbytes/second
	deny := append(append([]string(nil), tenantEgressDenied...), e.DenyCIDRs...)
	sort.Strings(deny)
	ports := make([]string, len(TenantBlockedTCPPorts))
	for i, port := range TenantBlockedTCPPorts {
		ports[i] = fmt.Sprint(port)
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("table inet %s", TenantEgressTable)
	w("delete table inet %s", TenantEgressTable)
	w("table inet %s {", TenantEgressTable)
	for _, set := range []string{"new_conns", "up_bytes", "down_bytes"} {
		w("  set %s { type ipv4_addr; size 65535; flags dynamic,timeout; timeout 1m; }", set)
	}
	w("  set %s { type ether_addr . ipv4_addr; flags interval; }", TenantAllowlistPairs)
	w("  chain input {")
	w("    type filter hook input priority filter - 10; policy accept;")
	w(`    iifname "%s" ct state established,related accept`, e.Bridge)
	w(`    iifname "%s" counter reject with icmpx admin-prohibited`, e.Bridge)
	w("  }")
	w("  chain forward {")
	w("    type filter hook forward priority filter - 10; policy accept;")
	w(`    oifname "%s" iifname != "%s" ct state established,related update @down_bytes { ip daddr limit rate over %d kbytes/second burst %d kbytes } counter drop`, e.Bridge, e.Bridge, bytesPerSecond, bytesPerSecond)
	w(`    oifname "%s" iifname != "%s" ct state established,related accept`, e.Bridge, e.Bridge)
	w(`    oifname "%s" counter drop`, e.Bridge)
	w(`    iifname "%s" jump egress`, e.Bridge)
	w("  }")
	w("  chain egress {")
	w("    meta nfproto ipv6 counter drop")
	w("    ip saddr != %s counter drop", e.Subnet)
	w("    ether saddr %s-%s ether saddr . ip daddr != @%s counter reject with icmpx admin-prohibited", TenantAllowlistMACFirst, TenantAllowlistMACLast, TenantAllowlistPairs)
	w("    fib daddr type local counter reject with icmpx admin-prohibited")
	w("    ip daddr { %s } counter reject with icmpx admin-prohibited", strings.Join(deny, ", "))
	w("    meta l4proto tcp th dport { %s } counter reject with tcp reset", strings.Join(ports, ", "))
	w("    ct state new add @new_conns { ip saddr limit rate over %d/second burst %d packets } counter drop", e.NewConnsPerSecond, 2*e.NewConnsPerSecond)
	w("    update @up_bytes { ip saddr limit rate over %d kbytes/second burst %d kbytes } counter drop", bytesPerSecond, bytesPerSecond)
	w("    accept")
	w("  }")
	w("  chain postrouting {")
	w("    type nat hook postrouting priority srcnat; policy accept;")
	w(`    ip saddr %s oifname != "%s" masquerade`, e.Subnet, e.Bridge)
	w("  }")
	w("}")
	w("table bridge %s", TenantIsolationTable)
	w("delete table bridge %s", TenantIsolationTable)
	w("table bridge %s {", TenantIsolationTable)
	w("  chain forward {")
	w("    type filter hook forward priority filter; policy accept;")
	w(`    meta ibrname "%s" counter drop`, e.Bridge)
	w("  }")
	w("}")
	return b.String()
}

// TenantForwardAccepts are the iptables rules a host whose FORWARD policy
// is drop (any host running another Docker daemon with iptables) needs in
// DOCKER-USER so the bridge's traffic, already filtered by the inet table,
// is not dropped there.
func (e ProfileEgress) TenantForwardAccepts() [][]string {
	return [][]string{
		{"-i", e.Bridge, "!", "-o", e.Bridge, "-j", "ACCEPT"},
		{"-o", e.Bridge, "!", "-i", e.Bridge, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}
}

// ApplyTenantEgress loads the firewall, adds the DOCKER-USER accepts when
// that chain exists, and checks the bridge carries the gateway address.
// It is idempotent and leaves no partial table: nft applies the script in
// one transaction.
func ApplyTenantEgress(e ProfileEgress) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if err := checkBridge(e); err != nil {
		return err
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(e.TenantEgressRuleset())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("load sandbox egress firewall: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if exec.Command("iptables", "-w", "5", "-S", "DOCKER-USER").Run() != nil {
		return nil
	}
	for _, rule := range e.TenantForwardAccepts() {
		check := append([]string{"-w", "5", "-C", "DOCKER-USER"}, rule...)
		if exec.Command("iptables", check...).Run() == nil {
			continue
		}
		insert := append([]string{"-w", "5", "-I", "DOCKER-USER"}, rule...)
		if out, err := exec.Command("iptables", insert...).CombinedOutput(); err != nil {
			return fmt.Errorf("add DOCKER-USER accept for %s: %w: %s", e.Bridge, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// TenantEgressLoaded reports whether both firewall tables are present.
func TenantEgressLoaded() error {
	for _, table := range [][]string{{"inet", TenantEgressTable}, {"bridge", TenantIsolationTable}} {
		if out, err := exec.Command("nft", "list", "table", table[0], table[1]).CombinedOutput(); err != nil {
			return fmt.Errorf("sandbox egress firewall table %s %s is not loaded: %s", table[0], table[1], strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// Live state that nft prints but that is no part of the loaded rules: the
// counters' running totals and the elements of the dynamic rate sets.
var (
	egressCounterTotals = regexp.MustCompile(`counter packets [0-9]+ bytes [0-9]+`)
	egressSetElements   = regexp.MustCompile(`(?s)\n[ \t]*elements = \{[^{}]*\}`)
)

// NormalizeTenantEgressListing strips from an nft listing of the two tables
// what changes while the rules stay the same, so two listings of one loaded
// ruleset compare equal and a flushed, edited or replaced rule does not.
func NormalizeTenantEgressListing(listing string) string {
	listing = egressSetElements.ReplaceAllString(listing, "")
	listing = egressCounterTotals.ReplaceAllString(listing, "counter")
	var lines []string
	for _, line := range strings.Split(listing, "\n") {
		if line = strings.TrimRight(line, " \t"); line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

// TenantEgressListing returns the normalized listing of both firewall
// tables, to compare with the listing read right after the agent loaded
// them. It fails when a table is missing, or when the DOCKER-USER chain
// exists without both of e's accepts (ApplyTenantEgress adds them only
// where the chain exists).
func TenantEgressListing(e ProfileEgress) (string, error) {
	var listing strings.Builder
	for _, table := range [][]string{{"inet", TenantEgressTable}, {"bridge", TenantIsolationTable}} {
		out, err := exec.Command("nft", "list", "table", table[0], table[1]).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("sandbox egress firewall table %s %s is not loaded: %s", table[0], table[1], strings.TrimSpace(string(out)))
		}
		listing.Write(out)
		listing.WriteByte('\n')
	}
	if exec.Command("iptables", "-w", "5", "-S", "DOCKER-USER").Run() == nil {
		for _, rule := range e.TenantForwardAccepts() {
			check := append([]string{"-w", "5", "-C", "DOCKER-USER"}, rule...)
			if exec.Command("iptables", check...).Run() != nil {
				return "", fmt.Errorf("DOCKER-USER lacks the sandbox egress accept %s", strings.Join(rule, " "))
			}
		}
	}
	return NormalizeTenantEgressListing(listing.String()), nil
}

func checkBridge(e ProfileEgress) error {
	out, err := exec.Command("ip", "-o", "-4", "addr", "show", "dev", e.Bridge).Output()
	if err != nil {
		return fmt.Errorf("sandbox egress bridge %s is missing", e.Bridge)
	}
	if !strings.Contains(string(out), " inet "+e.Gateway().String()+" ") {
		return fmt.Errorf("sandbox egress bridge %s does not carry %s", e.Bridge, e.Gateway())
	}
	return nil
}
