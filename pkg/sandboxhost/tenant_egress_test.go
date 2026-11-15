// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxhost

import (
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type egressVectors struct {
	Valid         map[string]any `json:"valid"`
	Egress        map[string]any `json:"egress"`
	EgressDigest  string         `json:"egress_digest"`
	InvalidEgress []struct {
		Name  string   `json:"name"`
		Path  []string `json:"path"`
		Value any      `json:"value"`
	} `json:"invalid_egress"`
}

// egressProfile is the valid vector with the egress member and network
// modes none and public, as a fresh document.
func egressProfile(t *testing.T) (map[string]any, egressVectors) {
	t.Helper()
	raw, err := os.ReadFile("testdata/profile-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v egressVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(encode(t, v.Valid), &doc); err != nil {
		t.Fatal(err)
	}
	doc["egress"] = v.Egress
	doc["per_lease"].(map[string]any)["network_modes"] = []any{"none", "public"}
	return doc, v
}

// The same vectors drive report.py's check_egress.
func TestEgressProfileVectorsMatchPythonReportTool(t *testing.T) {
	doc, v := egressProfile(t)
	profile, err := DecodeProfile(encode(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	if profile.Egress == nil || profile.Egress.Bridge != "mcsbxeg0" || profile.Egress.BandwidthMbit != 50 {
		t.Fatalf("egress decoded as %+v", profile.Egress)
	}
	if digest, err := profile.Digest(); err != nil || digest != v.EgressDigest {
		t.Fatalf("digest %q, %v; want %q", digest, err, v.EgressDigest)
	}
	for _, c := range v.InvalidEgress {
		t.Run(c.Name, func(t *testing.T) {
			doc, _ := egressProfile(t)
			target := doc
			for _, key := range c.Path[:len(c.Path)-1] {
				target = target[key].(map[string]any)
			}
			target[c.Path[len(c.Path)-1]] = c.Value
			if _, err := DecodeProfile(encode(t, doc)); err == nil {
				t.Fatal("profile accepted")
			}
		})
	}
}

func TestTenantDestinationDenied(t *testing.T) {
	for addr, denied := range map[string]bool{
		"169.254.169.254": true, "10.20.30.2": true, "172.19.0.1": true, "192.168.1.1": true, "100.64.0.1": true,
		"127.0.0.1": true, "0.0.0.0": true, "224.0.0.1": true, "255.255.255.255": true, "::1": true, "fe80::1": true,
		"fd00::1": true, "2606:4700::1111": true, "1.1.1.1": false, "151.101.0.223": false, "140.82.112.3": false,
	} {
		if got := TenantDestinationDenied(netip.MustParseAddr(addr), nil); got != denied {
			t.Errorf("%s denied=%v, want %v", addr, got, denied)
		}
	}
	if !TenantDestinationDenied(netip.MustParseAddr("203.0.112.9"), []string{"203.0.112.0/24"}) {
		t.Error("deny_cidrs entry not applied")
	}
}

func testEgress() ProfileEgress {
	return ProfileEgress{Bridge: "mcsbxeg0", Subnet: "10.231.0.0/24", DNS: []string{"1.1.1.1"},
		BandwidthMbit: 50, NewConnsPerSecond: 50, DenyCIDRs: []string{"203.0.112.0/24"}}
}

// The rendered ruleset carries every refusal and limit the profile asks for;
// the nft parser itself checks it in TestTenantEgressRulesetLoads.
func TestTenantEgressRulesetRefusesAndLimits(t *testing.T) {
	e := testEgress()
	if e.Gateway().String() != "10.231.0.1/24" {
		t.Fatalf("gateway %s", e.Gateway())
	}
	rules := e.TenantEgressRuleset()
	for _, want := range []string{
		`iifname "mcsbxeg0" counter reject with icmpx admin-prohibited`,
		`oifname "mcsbxeg0" counter drop`,
		"meta nfproto ipv6 counter drop",
		"ip saddr != 10.231.0.0/24 counter drop",
		"fib daddr type local counter reject",
		"169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "203.0.112.0/24",
		"th dport { 25, 465, 587 } counter reject with tcp reset",
		"limit rate over 50/second burst 100 packets",
		"ip saddr limit rate over 6250 kbytes/second",
		"ip daddr limit rate over 6250 kbytes/second",
		`ip saddr 10.231.0.0/24 oifname != "mcsbxeg0" masquerade`,
		`meta ibrname "mcsbxeg0" counter drop`,
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("ruleset lacks %q", want)
		}
	}
	// The SMTP and destination refusals precede the final accept.
	egress := rules[strings.Index(rules, "chain egress"):]
	if accept := strings.Index(egress, "\n    accept\n"); accept < strings.Index(egress, "dport { 25") || accept < strings.Index(egress, "169.254.0.0/16") {
		t.Error("egress chain accepts before refusing")
	}
}

// The nft parser accepts the ruleset (check mode, in a throwaway user and
// network namespace). Skipped where nft or unprivileged namespaces are
// unavailable.
func TestTenantEgressRulesetLoads(t *testing.T) {
	nft, err := exec.LookPath("nft")
	if err != nil {
		for _, candidate := range []string{"/usr/sbin/nft", "/sbin/nft"} {
			if _, statErr := os.Stat(candidate); statErr == nil {
				nft, err = candidate, nil
			}
		}
	}
	if err != nil {
		t.Skip("nft not installed")
	}
	if exec.Command("unshare", "-rn", "true").Run() != nil {
		t.Skip("unprivileged network namespaces unavailable")
	}
	cmd := exec.Command("unshare", "-rn", nft, "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(testEgress().TenantEgressRuleset())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft rejected the ruleset: %v\n%s", err, out)
	}
}

// Two listings of one loaded ruleset compare equal however its counters
// and rate sets moved; a flushed chain, a deleted or edited rule, or a
// missing table does not. The listing is nft 1.0.9's output on a miner.
func TestNormalizeTenantEgressListing(t *testing.T) {
	raw, err := os.ReadFile("testdata/tenant-egress-listing.txt")
	if err != nil {
		t.Fatal(err)
	}
	loaded := string(raw)
	base := NormalizeTenantEgressListing(loaded)
	if strings.Contains(base, "counter packets") || !strings.Contains(base, "jump egress") || !strings.Contains(base, "table bridge "+TenantIsolationTable) {
		t.Fatalf("normalized listing:\n%s", base)
	}
	busy := strings.Replace(loaded, "counter packets 0 bytes 0 drop\n\t\taccept", "counter packets 917 bytes 1352211 drop\n\t\taccept", 1)
	busy = strings.Replace(busy, "\t\ttimeout 1m\n\t}\n\n\tset up_bytes", "\t\ttimeout 1m\n\t\telements = { 10.231.0.2 limit rate over 50/second burst 100 packets expires 41s,\n\t\t\t     10.231.0.3 limit rate over 50/second burst 100 packets expires 12s }\n\t}\n\n\tset up_bytes", 1)
	if busy == loaded || NormalizeTenantEgressListing(busy) != base {
		t.Fatalf("busy listing differs:\n%s", NormalizeTenantEgressListing(busy))
	}
	for name, changed := range map[string]string{
		"egress chain flushed": strings.Replace(loaded, "\t\taccept\n\t}\n\n\tchain postrouting", "\t}\n\n\tchain postrouting", 1),
		"deny rule deleted":    strings.Replace(loaded, "reject with icmpx admin-prohibited\n\t\ttcp dport", "\n\t\ttcp dport", 1),
		"smtp port dropped":    strings.Replace(loaded, "{ 25, 465, 587 }", "{ 465, 587 }", 1),
		"bridge table gone":    loaded[:strings.Index(loaded, "table bridge")],
		"policy changed":       strings.Replace(loaded, "hook forward priority filter - 10; policy accept;", "hook forward priority filter - 10; policy drop;", 1),
	} {
		if changed == loaded {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if NormalizeTenantEgressListing(changed) == base {
			t.Errorf("%s: listing still matches the loaded one", name)
		}
	}
}
