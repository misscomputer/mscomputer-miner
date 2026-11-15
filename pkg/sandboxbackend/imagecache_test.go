// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
)

// cacheLease adds a 4 MiB image n (1..9) to the engine's catalog and returns
// a lease of its own sandbox for it.
func cacheLease(h *host, n int) protocol.SandboxLeaseV1 {
	digest := "sha256:" + strings.Repeat(fmt.Sprint(n), 64)
	h.engine.catalog["docker.io/library/busybox@"+digest] = engineImage{
		ID: cacheImageID(n), RepoDigests: []string{"busybox@" + digest}, Os: "linux", Arch: "amd64", Size: 4 << 20,
		Cmd: []string{"sh"}, PullMessages: []string{`{"status":"Status: Downloaded"}`},
	}
	return testLease(func(l *protocol.SandboxLeaseV1) {
		l.ImageDigest, l.ImageReference = digest, "busybox@"+digest
		l.SandboxID = "sbx-" + strings.Repeat("0", 31) + fmt.Sprint(n)
	})
}

func cacheImageID(n int) string { return "sha256:" + strings.Repeat("e", 63) + fmt.Sprint(n) }

// cachingBackend is the host's backend with a cache budget and a clock that
// advances one minute per reading.
func cachingBackend(h *host, budgetMiB int) *GVisor {
	b := h.backend()
	b.config.ImageCacheMiB = budgetMiB
	clock := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time {
		clock = clock.Add(time.Minute)
		return clock
	}
	return b
}

func readCacheFile(t *testing.T, h *host) map[string]cachedImage {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.config.DataRoot, imageCacheFile))
	if err != nil {
		t.Fatal(err)
	}
	var entries map[string]cachedImage
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}
	return entries
}

// run creates and destroys one sandbox of lease.
func run(t *testing.T, b *GVisor, lease protocol.SandboxLeaseV1) {
	t.Helper()
	ctx := context.Background()
	if err := b.Create(ctx, instanceOf(lease), lease); err != nil {
		t.Fatalf("create %s: %v", lease.ImageDigest, err)
	}
	if err := b.Destroy(ctx, instanceOf(lease)); err != nil {
		t.Fatalf("destroy %s: %v", lease.ImageDigest, err)
	}
}

func (e *fakeEngine) hasImage(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.images[id]
	return ok
}

// A released image stays, recorded unreferenced; the next create of its
// digest uses it without a pull and takes it out of the cache.
func TestImageCacheKeepsReleasedImagesAndReusesThem(t *testing.T) {
	h := newHost(t)
	b := cachingBackend(h, 100)
	lease := cacheLease(h, 1)
	run(t, b, lease)
	if !h.engine.hasImage(cacheImageID(1)) || len(h.engine.containers) != 0 {
		t.Fatalf("after release: image kept %v, %d containers", h.engine.hasImage(cacheImageID(1)), len(h.engine.containers))
	}
	entries := readCacheFile(t, h)
	if entry, ok := entries[lease.ImageDigest]; !ok || entry.ID != cacheImageID(1) || entry.Bytes != 4<<20 || entry.LastUsed.IsZero() {
		t.Fatalf("cache.json = %+v", entries)
	}
	if err := b.Create(context.Background(), instanceOf(lease), lease); err != nil {
		t.Fatal(err)
	}
	if h.engine.pulls != 1 {
		t.Fatalf("engine pulled %d times, want the cached image reused", h.engine.pulls)
	}
	if entries := readCacheFile(t, h); len(entries) != 0 {
		t.Fatalf("an image a sandbox uses stays in cache.json: %+v", entries)
	}
}

// Over budget, the least recently used image goes first; a reuse makes an
// image recent again.
func TestImageCacheEvictsLeastRecentlyUsedOverBudget(t *testing.T) {
	h := newHost(t)
	b := cachingBackend(h, 10) // two 4 MiB images fit, three do not
	one, two, three, four := cacheLease(h, 1), cacheLease(h, 2), cacheLease(h, 3), cacheLease(h, 4)
	run(t, b, one)
	run(t, b, two)
	run(t, b, three)
	if h.engine.hasImage(cacheImageID(1)) || !h.engine.hasImage(cacheImageID(2)) || !h.engine.hasImage(cacheImageID(3)) {
		t.Fatal("the third release did not evict exactly the oldest image")
	}
	run(t, b, two) // a hit: two is now the most recent
	if h.engine.pulls != 3 {
		t.Fatalf("engine pulled %d times, want 3", h.engine.pulls)
	}
	run(t, b, four)
	if h.engine.hasImage(cacheImageID(3)) || !h.engine.hasImage(cacheImageID(2)) || !h.engine.hasImage(cacheImageID(4)) {
		t.Fatal("eviction did not follow recency")
	}
	entries := readCacheFile(t, h)
	if len(entries) != 2 || entries[two.ImageDigest].ID != cacheImageID(2) || entries[four.ImageDigest].ID != cacheImageID(4) {
		t.Fatalf("cache.json = %+v", entries)
	}
}

// Without the free space a pull reserves, every evictable image goes, even
// within budget.
func TestImageCacheEvictsForPullHeadroom(t *testing.T) {
	h := newHost(t)
	b := cachingBackend(h, 100)
	run(t, b, cacheLease(h, 1))
	run(t, b, cacheLease(h, 2))
	b.config.ImageMaxMiB = 1 << 40 // more than any test filesystem has free
	if err := b.evictCache(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if h.engine.hasImage(cacheImageID(1)) || h.engine.hasImage(cacheImageID(2)) || len(readCacheFile(t, h)) != 0 {
		t.Fatal("pull headroom eviction kept a cached image")
	}
}

// An image a live sandbox uses and a pinned image are never removed.
func TestImageCacheNeverEvictsLiveOrPinnedImages(t *testing.T) {
	h := newHost(t)
	b := cachingBackend(h, 1)
	pinned := cacheLease(h, 1)
	if err := b.PinImages([]string{pinned.ImageDigest}); err != nil {
		t.Fatal(err)
	}
	run(t, b, pinned)
	if !h.engine.hasImage(cacheImageID(1)) {
		t.Fatal("a pinned image was removed on release")
	}
	// A cache.json that lists an image a live sandbox uses, and the pinned
	// one, both far over the 1 MiB budget.
	live := cacheLease(h, 2)
	ctx := context.Background()
	if err := b.Create(ctx, instanceOf(live), live); err != nil {
		t.Fatal(err)
	}
	b.cache.mu.Lock()
	b.loadCacheLocked()
	b.cache.entries[live.ImageDigest] = cachedImage{ID: cacheImageID(2), Bytes: 4 << 20}
	b.cache.entries[pinned.ImageDigest] = cachedImage{ID: cacheImageID(1), Bytes: 4 << 20}
	if err := b.saveCacheLocked(); err != nil {
		t.Fatal(err)
	}
	b.cache.mu.Unlock()
	if err := b.evictCache(ctx, true); err != nil {
		t.Fatal(err)
	}
	if !h.engine.hasImage(cacheImageID(1)) || !h.engine.hasImage(cacheImageID(2)) {
		t.Fatal("eviction removed a live or pinned image")
	}
	if entries := readCacheFile(t, h); len(entries) != 1 || entries[pinned.ImageDigest].ID != cacheImageID(1) {
		t.Fatalf("cache.json = %+v, want only the pinned entry (the live image left the cache)", entries)
	}
	if err := b.Reclaim(ctx); err != nil {
		t.Fatal(err)
	}
	if !h.engine.hasImage(cacheImageID(1)) || !h.engine.hasImage(cacheImageID(2)) {
		t.Fatal("reclaim removed a live or pinned image")
	}
	if err := b.PinImages([]string{"latest"}); err == nil {
		t.Fatal("a pin that is not a digest was accepted")
	}
}

// An image whose unpacked size exceeds the per-image limit is refused as
// image_too_large, removed, and not cached.
func TestImageCacheRefusesAndRemovesOversizedImages(t *testing.T) {
	h := newHost(t)
	b := cachingBackend(h, 100)
	lease := cacheLease(h, 1)
	key := "docker.io/library/busybox@" + lease.ImageDigest
	image := h.engine.catalog[key]
	image.Size = int64(b.config.ImageMaxMiB)<<20 + 1
	h.engine.catalog[key] = image
	err := b.Create(context.Background(), instanceOf(lease), lease)
	if got := refusalCode(err); got != "image_too_large" {
		t.Fatalf("create = %v, want refusal image_too_large", err)
	}
	if h.engine.hasImage(cacheImageID(1)) {
		t.Fatal("an oversized image was kept")
	}
	if data, err := os.ReadFile(filepath.Join(h.config.DataRoot, imageCacheFile)); err == nil && strings.Contains(string(data), cacheImageID(1)) {
		t.Fatalf("an oversized image was cached: %s", data)
	}
}

// cache.json survives a restart: Reclaim keeps cached images, removes
// unused images the cache does not know, and a later create hits. A corrupt
// file starts the cache empty, so its images are reclaimed.
func TestImageCachePersistsAcrossRestart(t *testing.T) {
	h := newHost(t)
	b := cachingBackend(h, 100)
	cached := cacheLease(h, 1)
	run(t, b, cached)
	stray := cacheImageID(9)
	h.engine.mu.Lock()
	h.engine.images[stray] = engineImage{ID: stray, RepoDigests: []string{"busybox@sha256:" + strings.Repeat("9", 64)}, Size: 1 << 20}
	h.engine.mu.Unlock()

	restarted := cachingBackend(h, 100)
	ctx := context.Background()
	if err := restarted.Reclaim(ctx); err != nil {
		t.Fatal(err)
	}
	if !h.engine.hasImage(cacheImageID(1)) || h.engine.hasImage(stray) {
		t.Fatal("restart reclaim did not keep exactly the cached image")
	}
	if err := restarted.Create(ctx, instanceOf(cached), cached); err != nil {
		t.Fatal(err)
	}
	if h.engine.pulls != 1 {
		t.Fatalf("engine pulled %d times after restart, want a cache hit", h.engine.pulls)
	}
	if err := restarted.Destroy(ctx, instanceOf(cached)); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(h.config.DataRoot, imageCacheFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cachingBackend(h, 100).Reclaim(ctx); err != nil {
		t.Fatal(err)
	}
	if h.engine.hasImage(cacheImageID(1)) {
		t.Fatal("an image only a corrupt cache.json named was kept")
	}
	if entries := readCacheFile(t, h); len(entries) != 0 {
		t.Fatalf("cache.json after corrupt restart = %+v", entries)
	}
}

// A create that fails after a cache hit returns the image to the cache, so
// that it stays within the budget's accounting and can be evicted.
func TestImageCacheReturnsTheImageOfAFailedCreate(t *testing.T) {
	h := newHost(t)
	b := cachingBackend(h, 100)
	lease := cacheLease(h, 1)
	run(t, b, lease)
	h.engine.mu.Lock()
	h.engine.failCreate = 500
	h.engine.mu.Unlock()
	if err := b.Create(context.Background(), instanceOf(lease), lease); err == nil {
		t.Fatal("create succeeded against a failing engine")
	}
	if h.engine.pulls != 1 {
		t.Fatalf("engine pulled %d times, want the cached image used", h.engine.pulls)
	}
	if entries := readCacheFile(t, h); entries[lease.ImageDigest].ID != cacheImageID(1) {
		t.Fatalf("cache.json after a failed create = %+v, want the image back in it", entries)
	}
	b.config.ImageMaxMiB = 1 << 40
	if err := b.evictCache(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if h.engine.hasImage(cacheImageID(1)) {
		t.Fatal("the image of a failed create could not be evicted")
	}
}

// An image recorded under another of its digests than the one a create
// names is still protected while the create holds its image ID.
func TestImageCacheSkipsImagesACreateHoldsUnderAnotherDigest(t *testing.T) {
	h := newHost(t)
	b := cachingBackend(h, 100)
	lease := cacheLease(h, 2)
	other := "sha256:" + strings.Repeat("1", 64) // sorts first: the cache key
	key := "docker.io/library/busybox@" + lease.ImageDigest
	image := h.engine.catalog[key]
	image.RepoDigests = append(image.RepoDigests, "busybox@"+other)
	h.engine.catalog[key] = image
	run(t, b, lease)
	if entries := readCacheFile(t, h); entries[other].ID != cacheImageID(2) {
		t.Fatalf("cache.json = %+v, want the image under %s", entries, other)
	}
	release := b.holdDigest(cacheImageID(2))
	b.config.ImageMaxMiB = 1 << 40
	if err := b.evictCache(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !h.engine.hasImage(cacheImageID(2)) {
		t.Fatal("eviction removed an image a create holds")
	}
	release()
	if err := b.evictCache(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if h.engine.hasImage(cacheImageID(2)) {
		t.Fatal("a released hold still protects the image")
	}
}

// The inventory lists the images live sandboxes use first, then cached
// images most recently used first; an evicted image leaves it.
func TestImageCacheInventoryOrdersInUseThenMostRecent(t *testing.T) {
	h := newHost(t)
	b := cachingBackend(h, 10) // two 4 MiB images fit, three do not
	ctx := context.Background()
	if digests, err := b.CachedImages(ctx); err != nil || len(digests) != 0 {
		t.Fatalf("empty host inventory = %v, %v", digests, err)
	}
	one, two, three, four := cacheLease(h, 1), cacheLease(h, 2), cacheLease(h, 3), cacheLease(h, 4)
	run(t, b, one)
	run(t, b, two)
	if err := b.Create(ctx, instanceOf(four), four); err != nil {
		t.Fatal(err)
	}
	digests, err := b.CachedImages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{four.ImageDigest, two.ImageDigest, one.ImageDigest}; !slices.Equal(digests, want) {
		t.Fatalf("inventory = %v, want %v", digests, want)
	}
	run(t, b, three) // evicts one, the least recently used
	run(t, b, two)   // two becomes the most recent cached image
	digests, err = b.CachedImages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{four.ImageDigest, two.ImageDigest, three.ImageDigest}; !slices.Equal(digests, want) {
		t.Fatalf("inventory after eviction and reuse = %v, want %v", digests, want)
	}
}
