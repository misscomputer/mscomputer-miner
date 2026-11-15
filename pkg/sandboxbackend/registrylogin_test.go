// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/registrylogin"
)

type fakeLogin struct {
	err   error
	asked []string
	lease []registrylogin.Lease
}

func (f *fakeLogin) CredentialFor(_ context.Context, repository string, lease registrylogin.Lease) (registrylogin.Credential, bool, error) {
	f.asked = append(f.asked, repository)
	f.lease = append(f.lease, lease)
	if f.err != nil {
		return registrylogin.Credential{}, false, f.err
	}
	if repository != "mirror.example/docker.io/library/busybox" {
		return registrylogin.Credential{}, false, nil
	}
	return registrylogin.Credential{Username: "hk", Password: "pw", ServerAddress: "mirror.example"}, true, nil
}

func mirrorLeaseHost(t *testing.T) (*host, protocol.SandboxLeaseV1) {
	h := newHost(t)
	h.dns["mirror.example"] = []netip.Addr{netip.MustParseAddr("151.101.0.2")}
	image := h.engine.catalog["docker.io/library/busybox@"+testImageDigest]
	image.RepoDigests = append([]string{"mirror.example/docker.io/library/busybox@" + testImageDigest}, image.RepoDigests...)
	h.engine.catalog["mirror.example/docker.io/library/busybox@"+testImageDigest] = image
	lease := testLease(func(l *protocol.SandboxLeaseV1) {
		l.ImageReference = "mirror.example/docker.io/library/busybox@" + testImageDigest
		l.Signature = "cd"
	})
	return h, lease
}

// Pulls from the mirror carry the login's credential for that pull only,
// with the lease named, and other registries get none.
func TestPullsFromTheMirrorCarryTheLoginCredential(t *testing.T) {
	h, lease := mirrorLeaseHost(t)
	b := h.backend()
	login := &fakeLogin{}
	b.EnableRegistryLogin(login)
	if err := b.Create(context.Background(), instanceOf(lease), lease); err != nil {
		t.Fatal(err)
	}
	want := registrylogin.Credential{Username: "hk", Password: "pw", ServerAddress: "mirror.example"}.RegistryAuth()
	if len(h.engine.pullAuths) != 1 || h.engine.pullAuths[0] != want {
		t.Fatalf("pull auth = %q", h.engine.pullAuths)
	}
	if login.lease[0] != (registrylogin.Lease{SandboxID: lease.SandboxID, Signature: "cd"}) {
		t.Fatalf("login lease = %+v", login.lease[0])
	}

	other := testLease(func(l *protocol.SandboxLeaseV1) { l.SandboxID = "sbx-" + "2" + l.SandboxID[5:] })
	if err := b.Create(context.Background(), instanceOf(other), other); err != nil {
		t.Fatal(err)
	}
	if len(h.engine.pullAuths) != 2 || h.engine.pullAuths[1] != "" {
		t.Fatalf("a non-mirror pull carried %q", h.engine.pullAuths)
	}
}

// A failed login does not fail the create: the pull goes ahead without a
// credential and the registry decides (source-address admission still works).
func TestFailedLoginPullsWithoutACredential(t *testing.T) {
	h, lease := mirrorLeaseHost(t)
	b := h.backend()
	b.EnableRegistryLogin(&fakeLogin{err: errors.New("refused")})
	if err := b.Create(context.Background(), instanceOf(lease), lease); err != nil {
		t.Fatal(err)
	}
	if len(h.engine.pullAuths) != 1 || h.engine.pullAuths[0] != "" {
		t.Fatalf("pull auth = %q", h.engine.pullAuths)
	}
}
