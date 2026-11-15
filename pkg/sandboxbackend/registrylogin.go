// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"context"
	"log/slog"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/registrylogin"
)

// RegistryLogin supplies the registry credential for one pull
// (*registrylogin.Client). ok is false for images that need none.
type RegistryLogin interface {
	CredentialFor(ctx context.Context, repository string, lease registrylogin.Lease) (credential registrylogin.Credential, ok bool, err error)
}

// EnableRegistryLogin makes pulls from the login's registry carry a
// short-lived credential. Call it before the backend serves leases.
func (b *GVisor) EnableRegistryLogin(login RegistryLogin) {
	b.registryLogin = login
}

// registryAuth is the X-Registry-Auth for pulling repository under lease,
// or empty. A failed login is logged and the pull goes ahead without a
// credential: the registry decides, and a refusal is the registry's answer
// (image_unavailable), not the miner's fault.
func (b *GVisor) registryAuth(ctx context.Context, repository string, lease protocol.SandboxLeaseV1) string {
	if b.registryLogin == nil {
		return ""
	}
	credential, ok, err := b.registryLogin.CredentialFor(ctx, repository, registrylogin.Lease{SandboxID: lease.SandboxID, Signature: lease.Signature})
	if err != nil {
		slog.Warn("registry login failed; pulling without a credential", "repository", repository, "sandbox_id", lease.SandboxID, "error", err)
		return ""
	}
	if !ok {
		return ""
	}
	return credential.RegistryAuth()
}
