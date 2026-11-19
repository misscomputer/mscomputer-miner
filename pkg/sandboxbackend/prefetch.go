// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"context"

	"github.com/misscomputer/mscomputer-miner/pkg/miner"
	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

// prefetchLease is the image half of a lease: a prefetch pulls through the
// exact create pull path (registry checks, mirror credential, per-image size
// limit, digest and platform verification) without any sandbox identity.
func prefetchLease(reference, digest string) protocol.SandboxLeaseV1 {
	return protocol.SandboxLeaseV1{ImageReference: reference, ImageDigest: digest}
}

// ImageCached reports whether the pinned image is already present and
// verified within the per-image limit.
func (b *GVisor) ImageCached(ctx context.Context, reference, digest string) bool {
	name, err := normalizedRepository(reference)
	if err != nil {
		return false
	}
	_, size, err := b.verifiedImage(ctx, name+"@"+digest, prefetchLease(reference, digest))
	return err == nil && size <= int64(b.config.ImageMaxMiB)<<20
}

// PrefetchImage pulls the pinned image into the warm image cache. Without a
// cache there is nowhere to keep it, so the prefetch is refused as
// unsupported. A *miner.SandboxRefusal reports a condition that is not the
// miner's fault (image_unavailable, image_too_large).
func (b *GVisor) PrefetchImage(ctx context.Context, reference, digest string) error {
	if !b.cacheEnabled() {
		return &miner.SandboxRefusal{Code: sandbox.CapabilityUnsupported}
	}
	defer b.holdDigest(digest)()
	budget, err := b.newCreateBudget(ctx)
	if err != nil {
		return err
	}
	defer budget.close()
	imageID, err := b.pullImage(budget, prefetchLease(reference, digest))
	if err != nil {
		return err
	}
	return b.retainImage(budget.local(), imageID)
}

// PrefetchSupported reports whether a warm image cache keeps prefetched
// images.
func (b *GVisor) PrefetchSupported() bool { return b.cacheEnabled() }
