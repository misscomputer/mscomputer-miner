// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package protocol_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/organic"
	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/static"
)

func staticTicket(t *testing.T, validator, miner ed25519.PrivateKey) protocol.StaticTicketV1 {
	t.Helper()
	now := time.Now().UTC()
	pin := strings.Repeat("3a", 32)
	site := "sha256:" + strings.Repeat("9d", 32)
	ticket := protocol.StaticTicketV1{
		AssignmentNonce: strings.Repeat("ab", 16), DeploymentID: "hello-k3902",
		IssuedAt: *protocol.StaticTime(now), ExpiresAt: *protocol.StaticTime(now.Add(5 * time.Minute)), Generation: 1,
		MinerID: "5Fminer", ReleaseDigest: "sha256:" + strings.Repeat("9b", 32), RouteHost: "hello-k3902.ms.computer",
		Schema: protocol.StaticTicketSchema, SchemaVersion: 1, ServerImplementationDigest: static.ServerImplementationDigest,
		SiteDigest: site, SiteManifestKey: static.ManifestKey(site), WorkloadKind: static.WorkloadKind,
		Subnet: &protocol.StaticSubnetBindingV1{
			Network: "test", NetUID: 24, ValidatorHotkey: "5Hvalidator", MinerHotkey: "5Fminer",
			MinerAxonURL: "https://8.8.8.8:8091", MinerTransport: "https", MinerTLSCertificateSHA256: &pin,
			ChainBlock: 100, Epoch: 10, ExpiresAtBlock: 125,
			ValidatorServicePublicKey: hex.EncodeToString(validator.Public().(ed25519.PublicKey)),
			MinerServicePublicKey:     hex.EncodeToString(miner.Public().(ed25519.PublicKey)),
		},
	}
	if err := protocol.SignStaticTicketV1(&ticket, validator); err != nil {
		t.Fatal(err)
	}
	return ticket
}

// A static signature is bound to its own domain: neither a v4-style
// signature nor a receipt-domain signature by the same key authorizes a
// static ticket, and a changed site is never authorized.
func TestStaticTicketSignatureIsDomainSeparatedAndBindsTheSite(t *testing.T) {
	_, validator, _ := ed25519.GenerateKey(rand.Reader)
	_, miner, _ := ed25519.GenerateKey(rand.Reader)
	ticket := staticTicket(t, validator, miner)
	key := validator.Public().(ed25519.PublicKey)
	if err := protocol.VerifyStaticTicketV1Signature(ticket, key); err != nil {
		t.Fatal(err)
	}
	changed := ticket
	changed.SiteDigest = "sha256:" + strings.Repeat("00", 32)
	changed.SiteManifestKey = static.ManifestKey(changed.SiteDigest)
	if protocol.VerifyStaticTicketV1Signature(changed, key) == nil {
		t.Fatal("a ticket for another site verified")
	}
	unsigned := ticket
	unsigned.Signature = ""
	v4Style, _ := json.Marshal(unsigned)
	forged := ticket
	forged.Signature = hex.EncodeToString(ed25519.Sign(validator, v4Style))
	if protocol.VerifyStaticTicketV1Signature(forged, key) == nil {
		t.Fatal("an undomained signature verified")
	}
	var members map[string]any
	_ = json.Unmarshal(v4Style, &members)
	delete(members, "signature")
	canonical, err := organic.Canonical(members)
	if err != nil {
		t.Fatal(err)
	}
	for domain, valid := range map[string]bool{protocol.StaticTicketSigningDomain: true, protocol.StaticReceiptSigningDomain: false} {
		forged.Signature = hex.EncodeToString(ed25519.Sign(validator, append(append([]byte(domain), 0), canonical...)))
		if err := protocol.VerifyStaticTicketV1Signature(forged, key); (err == nil) != valid {
			t.Fatalf("domain %s: verify error %v, want valid=%v", domain, err, valid)
		}
	}
}

// Old peers reject a static ticket neutrally: the deployment.v4 decoders
// never accept its bytes (§12).
func TestDeploymentV4DecodersRejectStaticTickets(t *testing.T) {
	_, validator, _ := ed25519.GenerateKey(rand.Reader)
	_, miner, _ := ed25519.GenerateKey(rand.Reader)
	encoded, err := json.Marshal(staticTicket(t, validator, miner))
	if err != nil {
		t.Fatal(err)
	}
	var lifecycle protocol.Ticket
	if json.Unmarshal(encoded, &lifecycle) == nil {
		t.Fatal("deployment.v4 lifecycle decoder accepted a static ticket")
	}
}

// A static ticket and its receipt bind a generated site label's host in a
// valid tenant domain (protocol shape, also checked by miners); binding to the
// one configured tenant domain is ValidRouteHostIn, checked where config is.
// In the ms.computer tenant domain only an unreserved <slug>-<l><dddd> label
// at exactly one level is admitted; the retired on.ms.computer admits none.
func TestStaticTicketAdmitsALabelHostOnlyInItsRouteDomain(t *testing.T) {
	_, validator, _ := ed25519.GenerateKey(rand.Reader)
	_, miner, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		label, host        string
		admitted, inDomain bool
	}{
		{"hello-k3902", "hello-k3902.ms.computer", true, true},
		{"shop-a1234", "shop-a1234.ms.computer", true, true},
		{"shop-a1234", "shop-a1234.ms.site", true, false},
		{"shop-a1234", "shop-a1234.on.ms.computer", false, false},
		{"hello-k3j9x0q2ab", "hello-k3j9x0q2ab.ms.computer", false, false},
		{"shop-a1234", "other-a1234.ms.computer", false, false},
		{"shop-a1234", "shop-a1234.example.com", true, false},
		{"shop-a1234", "x.shop-a1234.ms.computer", false, false},
		{"shop-a1234", "shop-a1234.ms.computer.evil.example", true, false},
		{"shop-a1234", "shop-a1234.co.uk", false, false},
		{"shop-a1234", "shop-a1234.com", false, false},
		{"shop-a1234", "shop-a1234.*.ms.computer", false, false},
	} {
		if got := organic.ValidRouteHostIn(testTenantDomain, tc.label, tc.host); got != tc.inDomain {
			t.Fatalf("ValidRouteHostIn(%s, %s) = %v, want %v", tc.label, tc.host, got, tc.inDomain)
		}
		ticket := staticTicket(t, validator, miner)
		ticket.DeploymentID, ticket.RouteHost, ticket.Signature = tc.label, tc.host, ""
		err := protocol.SignStaticTicketV1(&ticket, validator)
		if (err == nil) != tc.admitted {
			t.Fatalf("%s for %s: sign error %v, want admitted=%v", tc.host, tc.label, err, tc.admitted)
		}
		replica := tc.label + "-" + ticket.MinerID
		receipt := protocol.StaticReceiptV1{
			AssignmentNonce: ticket.AssignmentNonce, DeploymentID: tc.label, Generation: ticket.Generation,
			EndpointID: fmt.Sprintf("%s-g%d-%s", replica, ticket.Generation, ticket.AssignmentNonce), MinerID: ticket.MinerID,
			ReleaseDigest: ticket.ReleaseDigest, ReplicaID: replica, RouteHost: tc.host, Schema: protocol.StaticReceiptSchema,
			SchemaVersion: 1, ServerImplementationDigest: ticket.ServerImplementationDigest, SiteDigest: ticket.SiteDigest,
			Stage: protocol.StageAccepted, Subnet: ticket.Subnet, TicketDigest: "sha256:" + strings.Repeat("7c", 32),
		}
		if err := protocol.SignStaticReceiptV1(&receipt, miner); (err == nil) != tc.admitted {
			t.Fatalf("%s for %s: receipt sign error %v, want admitted=%v", tc.host, tc.label, err, tc.admitted)
		}
		if tc.admitted {
			if err := protocol.VerifyStaticTicketV1Signature(ticket, validator.Public().(ed25519.PublicKey)); err != nil {
				t.Fatalf("%s: %v", tc.host, err)
			}
		}
	}
	if organic.ValidRouteHost("syn-a1234", "syn-a1234.ms.computer") || organic.ValidRouteHostIn(testTenantDomain, "syn-a1234", "syn-a1234.ms.computer") {
		t.Fatal("a reserved label took a public site host")
	}
}

// testTenantDomain is the testnet tenant site domain.
const testTenantDomain = "ms.computer"
