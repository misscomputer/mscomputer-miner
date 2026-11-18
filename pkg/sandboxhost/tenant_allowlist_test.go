// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxhost

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func allowlists() []TenantAllowlist {
	return []TenantAllowlist{
		{MAC: "06:6d:73:00:00:02", Destinations: []netip.Prefix{
			netip.MustParsePrefix("140.82.112.0/20"), netip.MustParsePrefix("140.82.113.5/32"), // inside the /20
			netip.MustParsePrefix("151.101.0.223/32"), netip.MustParsePrefix("2001:db8::/32"),
		}},
		{MAC: "06:6d:73:00:00:03"},
	}
}

// The egress chain refuses an allowlist-range source every destination
// not paired with it, before any other accept; prefixes are collapsed and
// non-IPv4 ones dropped, so the interval set never sees an overlap.
func TestTenantAllowlistScript(t *testing.T) {
	e := testEgress()
	if rules := e.TenantEgressRuleset(); !strings.Contains(rules, "ip saddr != 10.231.0.0/24 counter drop\n    ether saddr 06:6d:73:00:00:00-06:6d:73:ff:ff:ff ether saddr . ip daddr != @allow_dsts counter reject") {
		t.Fatalf("egress chain does not confine allowlist sources first:\n%s", rules)
	}
	script, err := e.TenantAllowlistScript(allowlists())
	if err != nil {
		t.Fatal(err)
	}
	want := "flush set inet mcsbx_sandbox_egress allow_dsts\n" +
		"add element inet mcsbx_sandbox_egress allow_dsts { 06:6d:73:00:00:02 . 1.1.1.1/32, 06:6d:73:00:00:02 . 140.82.112.0/20, 06:6d:73:00:00:02 . 151.101.0.223/32, 06:6d:73:00:00:03 . 1.1.1.1/32 }\n"
	if script != want {
		t.Fatalf("script:\n%s\nwant:\n%s", script, want)
	}
	if empty, _ := e.TenantAllowlistScript(nil); strings.Contains(empty, "add element") {
		t.Fatalf("empty script adds elements:\n%s", empty)
	}
	for name, lists := range map[string][]TenantAllowlist{
		"address off the range": {{MAC: "02:42:0a:e7:00:02"}},
		"upper-case address":    {{MAC: "06:6D:73:00:00:02"}},
		"duplicate address":     {{MAC: "06:6d:73:00:00:02"}, {MAC: "06:6d:73:00:00:02"}},
	} {
		if _, err := e.TenantAllowlistScript(lists); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A list covering the resolver collapses to one element.
	wide := []TenantAllowlist{{MAC: "06:6d:73:00:00:04", Destinations: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}}
	if script, _ := e.TenantAllowlistScript(wide); !strings.Contains(script, "{ 06:6d:73:00:00:04 . 0.0.0.0/0 }") {
		t.Fatalf("overlap not collapsed:\n%s", script)
	}
}

// Loaded into a real table and fed real packets (in a throwaway network
// namespace: a bridge, a sandbox namespace behind it and an upstream
// dummy), the static rule fails closed: an allowlist-range source reaches
// nothing until its pair is loaded, then only that destination, while an
// ordinary (public) source is unaffected. Skipped without root, nft or ip.
func TestTenantAllowlistFiltersPackets(t *testing.T) {
	nft := "/usr/sbin/nft"
	if path, err := exec.LookPath("nft"); err == nil {
		nft = path
	} else if _, err := os.Stat(nft); err != nil {
		t.Skip("nft not installed")
	}
	if os.Geteuid() != 0 || exec.Command("unshare", "-n", "-m", "true").Run() != nil {
		t.Skip("needs root network namespaces")
	}
	e := testEgress()
	e.Bridge = "mcsbxeg0"
	script, _ := e.TenantAllowlistScript([]TenantAllowlist{{MAC: "06:6d:73:00:00:05", Destinations: []netip.Prefix{netip.MustParsePrefix("198.19.0.0/24")}}})
	shell := fmt.Sprintf(`set -e
export PATH=/usr/sbin:/sbin:$PATH
mount -t tmpfs t /run; mkdir -p /run/netns
ip link add mcsbxeg0 type bridge; ip addr add 10.231.0.1/24 dev mcsbxeg0; ip link set mcsbxeg0 up
ip link add up0 type dummy; ip addr add 198.19.0.1/16 dev up0; ip link set up0 up
ip neigh add 198.19.0.9 lladdr 02:00:00:00:00:09 dev up0; ip neigh add 198.19.1.9 lladdr 02:00:00:00:00:09 dev up0
for n in 5 6; do
  ip netns add s$n; ip link add v$n type veth peer name p$n; ip link set p$n netns s$n; ip link set v$n master mcsbxeg0 up
  ip -n s$n addr add 10.231.0.$n/24 dev p$n; ip -n s$n link set p$n up; ip -n s$n route add default via 10.231.0.1
done
ip -n s5 link set p5 address 06:6d:73:00:00:05
sysctl -qw net.ipv4.ip_forward=1
"$0" -f - <<'RULES'
%s
RULES
"$0" delete table bridge %s
count() { "$0" list chain inet %s egress | grep -c "allow_dsts counter packets $1 " || true; }
send() { ip netns exec $1 ping -c1 -W1 $2 >/dev/null 2>&1 || true; }
send s5 198.19.0.9; send s6 198.19.0.9
[ "$(count 1)" = 1 ] || { echo "before the pair: allowlist source not refused once (public must not match)"; exit 1; }
"$0" -f - <<'RULES'
%sRULES
send s5 198.19.0.9; [ "$(count 1)" = 1 ] || { echo "listed destination refused"; exit 1; }
send s5 198.19.1.9; [ "$(count 2)" = 1 ] || { echo "unlisted destination admitted"; exit 1; }
`, e.TenantEgressRuleset(), TenantIsolationTable, TenantEgressTable, script)
	if out, err := exec.Command("unshare", "-n", "-m", "sh", "-c", shell, nft).CombinedOutput(); err != nil {
		t.Fatalf("allowlist packets: %v\n%s", err, out)
	}
}

// A list that withholds the resolvers (network none at runtime) pairs its
// address with nothing; another list still gets them.
func TestTenantAllowlistScriptNoResolvers(t *testing.T) {
	e := testEgress()
	lists := []TenantAllowlist{{MAC: "06:6d:73:00:00:07", NoResolvers: true}, {MAC: "06:6d:73:00:00:08"}}
	script, err := e.TenantAllowlistScript(lists)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "06:6d:73:00:00:07") || !strings.Contains(script, "06:6d:73:00:00:08 . ") {
		t.Fatalf("script %s", script)
	}
}
