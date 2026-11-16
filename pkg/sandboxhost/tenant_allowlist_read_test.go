// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxhost

import (
	"fmt"
	"testing"
)

// The set is read as nft 1.0.9 lists it (captured from a scratch table):
// prefixes, bare addresses and aligned ranges folded into prefixes.
func TestParseTenantAllowlistPairs(t *testing.T) {
	data := []byte(`{"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "allow_dsts", "table": "mcsbx_sandbox_egress", "type": ["ether_addr", "ipv4_addr"], "handle": 1, "flags": ["interval"], "elem": [{"concat": ["06:6d:73:aa:bb:cc", {"prefix": {"addr": "140.82.112.0", "len": 20}}]}, {"concat": ["06:6d:73:aa:bb:cc", "1.1.1.1"]}, {"concat": ["06:6D:73:00:00:01", {"prefix": {"addr": "151.101.0.0", "len": 29}}]}]}}]}`)
	pairs, unreadable, err := ParseTenantAllowlistPairs(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(unreadable) != 0 {
		t.Fatalf("unreadable %v", unreadable)
	}
	if got := fmt.Sprint(pairs); got != "map[06:6d:73:00:00:01:[151.101.0.0/29] 06:6d:73:aa:bb:cc:[140.82.112.0/20 1.1.1.1/32]]" {
		t.Fatalf("pairs %s", got)
	}
	empty, _, err := ParseTenantAllowlistPairs([]byte(`{"nftables": [{"set": {"name": "allow_dsts", "elem": null}}]}`))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty set = %v, %v", empty, err)
	}
	// A range is skipped, its MAC flagged; other sandboxes still read.
	pairs, unreadable, err = ParseTenantAllowlistPairs([]byte(`{"nftables": [{"set": {"name": "allow_dsts", "elem": [{"concat": ["06:6d:73:aa:bb:cc", {"range": ["1.1.1.1", "1.1.1.9"]}]}, {"concat": ["06:6d:73:00:00:01", "8.8.8.8"]}]}}]}`))
	if err != nil || !unreadable["06:6d:73:aa:bb:cc"] || len(unreadable) != 1 || fmt.Sprint(pairs) != "map[06:6d:73:00:00:01:[8.8.8.8/32]]" {
		t.Fatalf("range element: %v %v %v", pairs, unreadable, err)
	}
	for _, bad := range []string{`{"nftables": []}`, `{"nftables": [{"set": {"name": "allow_dsts", "elem": [{"concat": ["06:6d:73:aa:bb:cc"]}]}}]}`, `{"nftables": [{"set": {"name": "allow_dsts", "elem": [{"concat": [7, "1.1.1.1"]}]}}]}`, `[`} {
		if _, _, err := ParseTenantAllowlistPairs([]byte(bad)); err == nil {
			t.Fatalf("parsed %s", bad)
		}
	}
}
