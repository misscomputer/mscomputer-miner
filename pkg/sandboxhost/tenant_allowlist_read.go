// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxhost

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// LoadedTenantAllowlistPairs reads the egress table's allowlist set as the
// kernel holds it: per interface address, the IPv4 prefixes paired with it,
// and the addresses with an element it could not read.
func LoadedTenantAllowlistPairs() (map[string][]netip.Prefix, map[string]bool, error) {
	out, err := exec.Command("nft", "-j", "list", "set", "inet", TenantEgressTable, TenantAllowlistPairs).Output()
	if err != nil {
		return nil, nil, fmt.Errorf("read sandbox allowlists: %w", err)
	}
	return ParseTenantAllowlistPairs(out)
}

// ParseTenantAllowlistPairs parses `nft -j list set` output of the
// allowlist set (MAC . IPv4 prefix elements). An element whose address
// part it cannot read (a range, say) is skipped and its MAC listed in
// unreadable, so one sandbox's odd element never blocks another's check;
// an element without a readable MAC, or an unreadable listing, is an
// error: a set it cannot read proves nothing.
func ParseTenantAllowlistPairs(data []byte) (pairs map[string][]netip.Prefix, unreadable map[string]bool, err error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Name string            `json:"name"`
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("sandbox allowlists: %w", err)
	}
	pairs, unreadable = map[string][]netip.Prefix{}, map[string]bool{}
	found := false
	for _, item := range doc.Nftables {
		if item.Set == nil || item.Set.Name != TenantAllowlistPairs {
			continue
		}
		found = true
		for _, raw := range item.Set.Elem {
			var elem struct {
				Concat []json.RawMessage `json:"concat"`
				Elem   *struct {
					Val struct {
						Concat []json.RawMessage `json:"concat"`
					} `json:"val"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(raw, &elem); err != nil {
				return nil, nil, fmt.Errorf("sandbox allowlist element %s: %w", raw, err)
			}
			concat := elem.Concat
			if concat == nil && elem.Elem != nil {
				concat = elem.Elem.Val.Concat
			}
			if len(concat) != 2 {
				return nil, nil, fmt.Errorf("sandbox allowlist element %s is not a pair", raw)
			}
			var mac string
			if err := json.Unmarshal(concat[0], &mac); err != nil {
				return nil, nil, fmt.Errorf("sandbox allowlist element %s: %w", raw, err)
			}
			mac = strings.ToLower(mac)
			prefix, err := parseNFTPrefix(concat[1])
			if err != nil {
				unreadable[mac] = true
				continue
			}
			pairs[mac] = append(pairs[mac], prefix)
		}
	}
	if !found {
		return nil, nil, fmt.Errorf("sandbox allowlist set %s is not listed", TenantAllowlistPairs)
	}
	return pairs, unreadable, nil
}

func parseNFTPrefix(raw json.RawMessage) (netip.Prefix, error) {
	var addr string
	if err := json.Unmarshal(raw, &addr); err == nil {
		a, err := netip.ParseAddr(addr)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	var p struct {
		Prefix *struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
	}
	if err := json.Unmarshal(raw, &p); err != nil || p.Prefix == nil {
		return netip.Prefix{}, fmt.Errorf("unreadable address %s", raw)
	}
	a, err := netip.ParseAddr(p.Prefix.Addr)
	if err != nil {
		return netip.Prefix{}, err
	}
	return a.Prefix(p.Prefix.Len)
}
