// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package durable

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
)

// A grant nonce is claimed once, survives a reopen of the store until its
// grant expired, and is refused once the lease stopped running or expired.
func TestClaimFileGrantIsSingleUseAndFollowsTheLease(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	leaseID := protocol.SandboxLeaseIDV1(f.lease)
	now := f.clock.read()
	expires := now.Add(10 * time.Minute)
	first := strings.Repeat("a1", 16)
	if code, err := f.leases.ClaimFileGrant(ctx, leaseID, first, expires, now); err != nil || code != "" {
		t.Fatalf("first claim: %q %v", code, err)
	}
	if _, err := f.leases.ClaimFileGrant(ctx, leaseID, first, expires, now.Add(time.Second)); !errors.Is(err, ErrFileGrantReplayed) {
		t.Fatalf("replay: %v", err)
	}
	// Durable: a reopened store still refuses the replay.
	f.store.Close()
	store, err := Open(f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	leases, err := store.EnableSandboxLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leases.ClaimFileGrant(ctx, leaseID, first, expires, now.Add(2*time.Second)); !errors.Is(err, ErrFileGrantReplayed) {
		t.Fatalf("replay after reopen: %v", err)
	}
	// Unknown lease.
	if _, err := leases.ClaimFileGrant(ctx, "lease-unknown", strings.Repeat("b2", 16), expires, now); err == nil {
		t.Fatal("claim on an unknown lease accepted")
	}
	// Past the lease expiry the lease refuses before any nonce is claimed.
	late := strings.Repeat("c3", 16)
	if code, err := leases.ClaimFileGrant(ctx, leaseID, late, sandboxT0.Add(20*time.Minute), sandboxT0.Add(10*time.Minute)); err != nil || code != "lease_expired" {
		t.Fatalf("claim past lease expiry: %q %v", code, err)
	}
	if code, err := leases.LeaseRefusal(ctx, leaseID, now); err != nil || code != "" {
		t.Fatalf("running lease refusal: %q %v", code, err)
	}
	// Released (the kill switch): refused, and LeaseRefusal reports it.
	if _, _, err := leases.Release(ctx, f.parties.release(t, 1, now), now); err != nil {
		t.Fatal(err)
	}
	code, err := leases.ClaimFileGrant(ctx, leaseID, late, expires, now.Add(time.Second))
	if err != nil || code == "" {
		t.Fatalf("claim on a released lease: %q %v", code, err)
	}
	if refusal, err := leases.LeaseRefusal(ctx, leaseID, now.Add(time.Second)); err != nil || refusal == "" {
		t.Fatalf("released lease refusal: %q %v", refusal, err)
	}
	if refusal, _ := leases.LeaseRefusal(ctx, "lease-unknown", now); refusal != "lease_not_found" {
		t.Fatalf("unknown lease refusal: %q", refusal)
	}
}
