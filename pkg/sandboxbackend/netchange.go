// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/miner"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

// networkChanges holds the runtime policies (network_set) of allowlist
// sandboxes. A container's allow label is fixed at create, so a changed
// policy lives here and in one file per lease under dir, written before the
// rules are loaded: after an agent restart the policy in force is the
// changed one, never the create-time one. A file that cannot be read
// confines its sandbox to nothing.
type networkChanges struct {
	dir string
	mu  sync.Mutex // serializes SetNetwork; byLease is guarded by GVisor.allowlists
	// byLease is the changed policy per lease ID.
	byLease map[string]networkChange
}

type networkChange struct {
	IssuedAt time.Time             `json:"issued_at"`
	Policy   sandbox.NetworkPolicy `json:"policy"`
	// unreadable marks a file that did not parse: the lease reaches nothing.
	unreadable bool
}

var publicPrefix = netip.MustParsePrefix("0.0.0.0/0")

// EnableNetworkChanges turns on network_set with dir (created 0700) as the
// durable record of changed policies. Without it every network_set is
// refused as unsupported.
func (b *GVisor) EnableNetworkChanges(dir string) error {
	if b.config.Egress == nil {
		return errors.New("network changes need the egress firewall")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	changes := &networkChanges{dir: dir, byLease: map[string]networkChange{}}
	for _, entry := range entries {
		leaseID, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || entry.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		var change networkChange
		if err == nil {
			err = json.Unmarshal(raw, &change)
		}
		if err == nil {
			err = change.Policy.Validate()
		}
		if err != nil {
			slog.Warn("changed network policy is unreadable; its sandbox reaches nothing", "lease", leaseID, "error", err)
			change = networkChange{unreadable: true}
		}
		changes.byLease[leaseID] = change
	}
	b.allowlists.Lock()
	b.netChanges = changes
	b.allowlists.Unlock()
	return nil
}

// changedAllowlist returns the allowlist of a lease whose policy was
// changed at runtime: ok is false for an unchanged lease. A none policy (or
// an unreadable record) has no destinations and no resolvers.
// The caller holds b.allowlists.
func (b *GVisor) changedAllowlist(leaseID string) (allow []string, resolvers bool, ok bool) {
	if b.netChanges == nil {
		return nil, false, false
	}
	change, ok := b.netChanges.byLease[leaseID]
	if !ok {
		return nil, false, false
	}
	switch {
	case change.unreadable:
		return nil, false, true
	case change.Policy.Mode == sandbox.NetworkPublic:
		return []string{publicPrefix.String()}, true, true
	case change.Policy.Mode == sandbox.NetworkAllowlist:
		return change.Policy.Allow, true, true
	}
	return nil, false, true
}

// pruneNetworkChanges forgets the changed policies of leases with no
// container left. The caller holds b.allowlists.
func (b *GVisor) pruneNetworkChanges(live map[string]bool) {
	if b.netChanges == nil {
		return
	}
	for leaseID := range b.netChanges.byLease {
		if live[leaseID] {
			continue
		}
		if err := os.Remove(filepath.Join(b.netChanges.dir, leaseID+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("remove changed network policy", "lease", leaseID, "error", err)
			continue
		}
		delete(b.netChanges.byLease, leaseID)
	}
}

// SetNetwork replaces the egress policy of the running allowlist sandbox
// instanceID (miner.SandboxNetworkBackend). The change is recorded, loaded
// and verified in the kernel before it returns nil. When it cannot be
// verified the sandbox is left confined to nothing and an error returned.
func (b *GVisor) SetNetwork(ctx context.Context, instanceID, leaseID string, issuedAt time.Time, policy sandbox.NetworkPolicy) error {
	b.allowlists.Lock()
	changes := b.netChanges
	b.allowlists.Unlock()
	if changes == nil || b.config.Egress == nil {
		return miner.ErrNetworkChangeUnsupported
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	changes.mu.Lock()
	defer changes.mu.Unlock()
	c, found, err := b.inspect(ctx, instanceID)
	if err != nil {
		return err
	}
	if !found || !c.State.Running {
		return miner.ErrSandboxNotRunning
	}
	if c.Config.Labels[LabelLeaseID] != leaseID {
		return fmt.Errorf("sandbox %s does not hold lease %s", instanceID, leaseID)
	}
	if _, ok := c.Config.Labels[LabelNetworkAllow]; !ok {
		// Only an allowlist sandbox carries the confined interface address
		// a rule change can retarget.
		return miner.ErrNetworkChangeUnsupported
	}
	b.allowlists.Lock()
	current, had := changes.byLease[leaseID]
	b.allowlists.Unlock()
	if had && !current.unreadable {
		same := current.IssuedAt.Equal(issuedAt) && samePolicy(current.Policy, policy)
		if !same && !issuedAt.After(current.IssuedAt) {
			return miner.ErrNetworkPolicyStale
		}
	}
	change := networkChange{IssuedAt: issuedAt.UTC(), Policy: policy}
	if err := writeNetworkChange(changes.dir, leaseID, change); err != nil {
		return fmt.Errorf("record network policy: %w", err)
	}
	b.allowlists.Lock()
	changes.byLease[leaseID] = change
	b.allowlists.Unlock()
	if err := b.verifyNetworkChange(ctx, leaseID, policy); err != nil {
		b.confineToNothing(leaseID, issuedAt)
		return err
	}
	slog.Info("sandbox network policy changed", "lease", leaseID, "mode", policy.Mode, "allow", len(policy.Allow), "issued_at", issuedAt.UTC().Format(time.RFC3339Nano))
	return nil
}

// verifyNetworkChange loads the allowlist sets and waits until the kernel
// holds exactly what policy needs for the lease's address.
func (b *GVisor) verifyNetworkChange(ctx context.Context, leaseID string, policy sandbox.NetworkPolicy) error {
	mac := allowlistMAC(leaseID)
	var want []netip.Prefix
	switch policy.Mode {
	case sandbox.NetworkPublic:
		want = []netip.Prefix{publicPrefix}
	case sandbox.NetworkAllowlist:
		for _, entry := range policy.Allow {
			if prefix, err := netip.ParsePrefix(entry); err == nil {
				want = append(want, prefix)
			}
		}
	}
	if policy.Mode != sandbox.NetworkNone {
		for _, server := range b.config.Egress.DNS {
			if addr, err := netip.ParseAddr(server); err == nil {
				want = append(want, netip.PrefixFrom(addr, 32))
			}
		}
	}
	deadline := time.Now().Add(allowlistVerifyWait)
	err := b.syncAllowlists(ctx)
	for {
		if err == nil {
			if policy.Mode == sandbox.NetworkNone {
				err = b.checkAllowlistEmpty(mac)
			} else {
				err = b.checkAllowlistActive(mac, want)
			}
			if err == nil {
				return nil
			}
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			return fmt.Errorf("network policy of lease %s not verified: %w", leaseID, err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(allowlistVerifyPoll):
		}
		if err = b.ensureEgress(); err == nil {
			err = b.syncAllowlists(ctx)
		}
	}
}

// checkAllowlistEmpty checks that the tables are the loaded ones and the
// set pairs mac with nothing.
func (b *GVisor) checkAllowlistEmpty(mac string) error {
	listing, err := tenantEgressListing(*b.config.Egress)
	if err != nil {
		return err
	}
	b.egress.mu.Lock()
	loaded := b.egress.loaded
	b.egress.mu.Unlock()
	if loaded == "" || listing != loaded {
		return errors.New("the firewall tables differ from the loaded ruleset")
	}
	pairs, unreadable, err := loadedTenantAllowlistPairs()
	if err != nil {
		return err
	}
	if unreadable[mac] || len(pairs[mac]) != 0 {
		return fmt.Errorf("the allowlist set still holds destinations for %s", mac)
	}
	return nil
}

// confineToNothing records and loads a none policy for a lease whose change
// failed: the sandbox must not keep a policy nobody verified.
func (b *GVisor) confineToNothing(leaseID string, issuedAt time.Time) {
	change := networkChange{IssuedAt: issuedAt.UTC(), Policy: sandbox.NetworkPolicy{Mode: sandbox.NetworkNone, Allow: []string{}}}
	if err := writeNetworkChange(b.netChanges.dir, leaseID, change); err != nil {
		slog.Error("record fail-closed network policy", "lease", leaseID, "error", err)
		change.unreadable = true
	}
	b.allowlists.Lock()
	b.netChanges.byLease[leaseID] = change
	b.allowlists.Unlock()
	if err := b.syncAllowlists(context.Background()); err != nil {
		slog.Error("load fail-closed network policy", "lease", leaseID, "error", err)
	}
}

func samePolicy(a, b sandbox.NetworkPolicy) bool {
	if a.Mode != b.Mode || len(a.Allow) != len(b.Allow) {
		return false
	}
	for i := range a.Allow {
		if a.Allow[i] != b.Allow[i] {
			return false
		}
	}
	return true
}

// writeNetworkChange replaces a lease's record atomically and durably.
func writeNetworkChange(dir, leaseID string, change networkChange) error {
	if strings.ContainsAny(leaseID, "/\x00") || leaseID == "" || leaseID[0] == '.' {
		return errors.New("lease ID is not a file name")
	}
	raw, err := json.Marshal(change)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(raw); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, leaseID+".json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
