// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

// SandboxImagePrefetcher is a backend that can warm its image cache ahead of
// a lease. A backend without it refuses every prefetch as unsupported.
type SandboxImagePrefetcher interface {
	// PrefetchSupported reports whether the backend keeps prefetched
	// images (a warm image cache); without it prefetch is not advertised.
	PrefetchSupported() bool
	// ImageCached reports whether the pinned image is present and usable.
	ImageCached(ctx context.Context, reference, digest string) bool
	// PrefetchImage pulls the pinned image into the cache under the create
	// pull rules. A *SandboxRefusal is not the miner's fault.
	PrefetchImage(ctx context.Context, reference, digest string) error
}

const (
	// MaxConcurrentPrefetches bounds the background pulls one lane runs;
	// a request past it is refused as capacity_exhausted.
	MaxConcurrentPrefetches = 2
	// prefetchPullTimeout bounds one background pull.
	prefetchPullTimeout = 10 * time.Minute
	// prefetchCheckTimeout bounds the synchronous cache check.
	prefetchCheckTimeout = 5 * time.Second
)

// prefetches is the lane's in-flight prefetch set, keyed by image digest, so
// a repeated request joins the running pull instead of starting another.
type prefetches struct {
	mu      sync.Mutex
	running map[string]struct{}
}

func (p *prefetches) begin(digest string) (joined, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running == nil {
		p.running = map[string]struct{}{}
	}
	if _, found := p.running[digest]; found {
		return true, true
	}
	if len(p.running) >= MaxConcurrentPrefetches {
		return false, false
	}
	p.running[digest] = struct{}{}
	return false, true
}

func (p *prefetches) end(digest string) {
	p.mu.Lock()
	delete(p.running, digest)
	p.mu.Unlock()
}

// PrefetchImage admits one validator prefetch request and answers at once
// with a signed receipt: cached, pulling (the pull continues in the
// background, bounded by the lane's lifetime) or refused.
func (l *SandboxLane) PrefetchImage(ctx context.Context, request protocol.SandboxImagePrefetchV1, req SandboxRequest) (protocol.SandboxImagePrefetchReceiptV1, error) {
	now := l.now().UTC()
	if err := protocol.VerifyBoundSandboxImagePrefetchV1(request, req.ValidatorKey, now, req.CurrentBlock, req.Network, req.NetUID, req.CallerHotkey, req.MinerHotkey, req.MinerUID); err != nil {
		return protocol.SandboxImagePrefetchReceiptV1{}, err
	}
	if err := l.admit(request.Subnet, request.MinerID); err != nil {
		return protocol.SandboxImagePrefetchReceiptV1{}, err
	}
	select {
	case <-l.closed:
		return protocol.SandboxImagePrefetchReceiptV1{}, ErrSandboxLaneClosed
	default:
	}
	prefetcher, ok := l.backend.(SandboxImagePrefetcher)
	if !ok || !prefetcher.PrefetchSupported() {
		return l.prefetchReceipt(request, protocol.ImagePrefetchRefused, sandbox.CapabilityUnsupported)
	}
	checkCtx, cancel := context.WithTimeout(ctx, prefetchCheckTimeout)
	cached := prefetcher.ImageCached(checkCtx, request.ImageReference, request.ImageDigest)
	cancel()
	if cached {
		return l.prefetchReceipt(request, protocol.ImagePrefetchCached, "")
	}
	joined, ok := l.prefetch.begin(request.ImageDigest)
	if !ok {
		return l.prefetchReceipt(request, protocol.ImagePrefetchRefused, "capacity_exhausted")
	}
	if joined {
		return l.prefetchReceipt(request, protocol.ImagePrefetchPulling, "")
	}
	workCtx, done, err := l.track(l.base)
	if err != nil {
		l.prefetch.end(request.ImageDigest)
		return protocol.SandboxImagePrefetchReceiptV1{}, ErrSandboxLaneClosed
	}
	go func() {
		defer done()
		defer l.prefetch.end(request.ImageDigest)
		pullCtx, cancel := context.WithTimeout(workCtx, prefetchPullTimeout)
		defer cancel()
		err := prefetcher.PrefetchImage(pullCtx, request.ImageReference, request.ImageDigest)
		var refusal *SandboxRefusal
		switch {
		case err == nil:
			slog.Info("sandbox image prefetched", "digest", request.ImageDigest)
		case errors.As(err, &refusal):
			slog.Info("sandbox image prefetch refused", "digest", request.ImageDigest, "code", refusal.Code)
		default:
			slog.Warn("sandbox image prefetch failed", "digest", request.ImageDigest, "error", err)
		}
	}()
	return l.prefetchReceipt(request, protocol.ImagePrefetchPulling, "")
}

func (l *SandboxLane) prefetchReceipt(request protocol.SandboxImagePrefetchV1, state, code string) (protocol.SandboxImagePrefetchReceiptV1, error) {
	digest, err := protocol.SandboxImagePrefetchDigestV1(request)
	if err != nil {
		return protocol.SandboxImagePrefetchReceiptV1{}, err
	}
	receipt := protocol.SandboxImagePrefetchReceiptV1{
		DocumentDigest: digest, ImageDigest: request.ImageDigest, MinerID: request.MinerID,
		ObservedAt: *protocol.StaticTime(l.now().UTC()), Schema: protocol.SandboxImagePrefetchReceiptSchema,
		SchemaVersion: protocol.SandboxImagePrefetchSchemaVersion, State: state, Subnet: request.Subnet,
	}
	if code != "" {
		receipt.ErrorCode = &code
	}
	return receipt, protocol.SignSandboxImagePrefetchReceiptV1(&receipt, l.agent.SigningKey)
}

// ImagePrefetchEnabled reports whether the backend can prefetch images, so
// the agent advertises sandbox-image-prefetch-v1.
func (l *SandboxLane) ImagePrefetchEnabled() bool {
	prefetcher, ok := l.backend.(SandboxImagePrefetcher)
	return ok && prefetcher.PrefetchSupported()
}
