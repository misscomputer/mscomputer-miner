// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxhost

import (
	"net/netip"
	"strings"
	"testing"
)

func bindingEgress() ProfileEgress {
	return ProfileEgress{Bridge: "mcsbxeg0", Subnet: "172.30.0.0/24", DNS: []string{"1.1.1.1"}, BandwidthMbit: 50, NewConnsPerSecond: 20, DenyCIDRs: []string{}}
}

func TestTenantBindingRulesetBindsEachPortAndDropsTheRest(t *testing.T) {
	script, err := bindingEgress().TenantBindingRuleset([]PortBinding{
		{Port: "vethb", MAC: "02:42:ac:1e:00:03", IP: netip.MustParseAddr("172.30.0.3")},
		{Port: "vetha", MAC: "02:42:ac:1e:00:02", IP: netip.MustParseAddr("172.30.0.2")},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table bridge mcsbx_sandbox_antispoof\ndelete table bridge mcsbx_sandbox_antispoof\ntable bridge mcsbx_sandbox_antispoof {\n",
		`elements = { "vetha" . 02:42:ac:1e:00:02 . 172.30.0.2, "vethb" . 02:42:ac:1e:00:03 . 172.30.0.3 }`,
		"type filter hook prerouting priority -300; policy accept;",
		`meta ibrname != "mcsbxeg0" accept`,
		"ether type ip iifname . ether saddr . ip saddr @bound accept",
		"iifname . ether saddr . arp saddr ip @bound iifname . arp saddr ether . arp saddr ip @bound accept",
		`counter name "spoofed" drop`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, script)
		}
	}
	// The final rule of the chain drops: nothing from a bridge port is
	// accepted except by a binding.
	lines := strings.Split(strings.TrimSpace(script), "\n")
	if lines[len(lines)-3] != `    counter name "spoofed" drop` {
		t.Fatalf("chain does not end in drop:\n%s", script)
	}
}

func TestTenantBindingRulesetWithoutBindingsPassesNothing(t *testing.T) {
	script, err := bindingEgress().TenantBindingRuleset(nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "elements") || !strings.Contains(script, `counter name "spoofed" drop`) {
		t.Fatalf("empty ruleset:\n%s", script)
	}
}

func TestTenantBindingRulesetRefusesInvalidOrDuplicateBindings(t *testing.T) {
	good := PortBinding{Port: "vetha", MAC: "02:42:ac:1e:00:02", IP: netip.MustParseAddr("172.30.0.2")}
	for name, bindings := range map[string][]PortBinding{
		"port quote":    {{Port: `veth"a`, MAC: good.MAC, IP: good.IP}},
		"long port":     {{Port: "vethaaaaaaaaaaaa", MAC: good.MAC, IP: good.IP}},
		"multicast mac": {{Port: good.Port, MAC: "03:42:ac:1e:00:02", IP: good.IP}},
		"upper mac":     {{Port: good.Port, MAC: "02:42:AC:1E:00:02", IP: good.IP}},
		"outside":       {{Port: good.Port, MAC: good.MAC, IP: netip.MustParseAddr("10.0.0.2")}},
		"gateway":       {{Port: good.Port, MAC: good.MAC, IP: netip.MustParseAddr("172.30.0.1")}},
		"network":       {{Port: good.Port, MAC: good.MAC, IP: netip.MustParseAddr("172.30.0.0")}},
		"ipv6":          {{Port: good.Port, MAC: good.MAC, IP: netip.MustParseAddr("fd00::2")}},
		"same port":     {good, {Port: good.Port, MAC: "02:42:ac:1e:00:03", IP: netip.MustParseAddr("172.30.0.3")}},
		"same mac":      {good, {Port: "vethb", MAC: good.MAC, IP: netip.MustParseAddr("172.30.0.3")}},
		"same ip":       {good, {Port: "vethb", MAC: "02:42:ac:1e:00:03", IP: good.IP}},
	} {
		if script, err := bindingEgress().TenantBindingRuleset(bindings); err == nil {
			t.Errorf("%s: accepted\n%s", name, script)
		}
	}
}
