// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import "testing"

func TestEndpointRoutesBindOnce(t *testing.T) {
	routes := NewEndpointRoutes()
	for _, bad := range []string{"", "ftp://127.0.0.1/", "http://u@127.0.0.1/", "http://127.0.0.1/?q", "http://127.0.0.1:0/", "http:///x"} {
		if err := routes.Register("e", bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if err := routes.Register("e", "http://127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	if err := routes.Register("e", "http://127.0.0.1:8080"); err != nil {
		t.Fatalf("same binding refused: %v", err)
	}
	if err := routes.Register("e", "http://127.0.0.1:8081"); err == nil {
		t.Fatal("rebound to another target")
	}
	routes.Unregister("e")
	if _, err := routes.Lookup("e"); err == nil {
		t.Fatal("unregistered endpoint still routed")
	}
}
