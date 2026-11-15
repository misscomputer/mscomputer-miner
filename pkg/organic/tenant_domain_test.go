// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package organic_test

import (
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/organic"
)

func TestValidateTenantDomain(t *testing.T) {
	for domain, ok := range map[string]bool{
		"ms.computer": true, "ms.site": true, "sites.example.co.uk": true, "example.co.uk": true,
		"": false, "com": false, "co.uk": false, "on.ms.computer": false, "a.on.ms.computer": false, "github.io": false, "*.ms.computer": false,
		"MS.computer": false, "ms.computer.": false, "-ms.computer": false,
	} {
		if err := organic.ValidateTenantDomain(domain); (err == nil) != ok {
			t.Errorf("ValidateTenantDomain(%q) = %v, want ok=%v", domain, err, ok)
		}
	}
}

func TestRegistrableDomain(t *testing.T) {
	for host, want := range map[string]string{
		"hello-k3902.ms.computer": "ms.computer", "ms.site": "ms.site",
		"a.b.example.co.uk": "example.co.uk", "x.user.github.io": "user.github.io",
	} {
		if got := organic.RegistrableDomain(host); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestRouteHostBindsTheConfiguredDomain(t *testing.T) {
	host := organic.RouteHost("ms.computer", "hello-k3902")
	if host != "hello-k3902.ms.computer" || !organic.ValidRouteHostIn("ms.computer", "hello-k3902", host) {
		t.Fatalf("ms.computer route host %q not admitted", host)
	}
	if organic.ValidRouteHostIn("ms.site", "hello-k3902", host) || !organic.ValidRouteHostIn("ms.site", "hello-k3902", organic.RouteHost("ms.site", "hello-k3902")) {
		t.Fatal("route host not bound to its configured tenant domain")
	}
	if organic.ValidRouteHostIn("", "hello-k3902", "hello-k3902.") || organic.ValidRouteHost("hello-k3902", "hello-k3902.com") {
		t.Fatal("a host outside a valid tenant domain was admitted")
	}
}
