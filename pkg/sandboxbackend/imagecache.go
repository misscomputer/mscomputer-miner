// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
)

// imageCacheFile, under the data root, records the images the backend keeps
// after their last sandbox was released: the warm image cache.
const imageCacheFile = "cache.json"

// maxImageCacheFile bounds what is read back from imageCacheFile.
const maxImageCacheFile = 4 << 20

var imageDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// cachedImage is one unreferenced image the cache keeps, keyed by its
// repository digest in imageCacheFile.
type cachedImage struct {
	ID       string    `json:"id"`
	Bytes    int64     `json:"bytes"`
	LastUsed time.Time `json:"last_used"`
}

// imageCache is the in-memory copy of imageCacheFile. Only images no
// sandbox uses are in it: a cache hit takes its entry out, a release puts
// it back. The engine stays the truth about which images exist; the file is
// the accounting and recency the eviction order needs.
type imageCache struct {
	mu      sync.Mutex
	loaded  bool
	entries map[string]cachedImage
}

// cacheEnabled reports whether released images are kept: only with a
// positive spare budget (Config.ImageCacheMiB).
func (b *GVisor) cacheEnabled() bool { return b.config.ImageCacheMiB > 0 }

func (b *GVisor) clock() time.Time {
	if b.now != nil {
		return b.now().UTC()
	}
	return time.Now().UTC()
}

// PinImages adds repository digests the cache never evicts and a release
// never removes, such as the sandbox-base or qualification image.
func (b *GVisor) PinImages(digests []string) error {
	for _, digest := range digests {
		if !imageDigestPattern.MatchString(digest) {
			return fmt.Errorf("pinned image digest %q is not sha256:<64 lowercase hex>", digest)
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pinned == nil {
		b.pinned = map[string]bool{}
	}
	for _, digest := range digests {
		b.pinned[digest] = true
	}
	return nil
}

// pinnedImage reports whether any of an image's repository digests is
// pinned.
func (b *GVisor) pinnedImage(repoDigests []string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, reference := range repoDigests {
		if _, digest, ok := strings.Cut(reference, "@"); ok && b.pinned[digest] {
			return true
		}
	}
	return false
}

// holdDigest marks digest (a lease's repository digest or an engine image
// ID) as being created from until the returned function runs; eviction
// skips an entry whose key or image ID is held, so that a create's image is
// not removed between its pull (or cache hit) and its container, whichever
// of the image's digests the cache recorded it under.
func (b *GVisor) holdDigest(digest string) func() {
	b.mu.Lock()
	if b.inflight == nil {
		b.inflight = map[string]int{}
	}
	b.inflight[digest]++
	b.mu.Unlock()
	return func() {
		b.mu.Lock()
		if b.inflight[digest]--; b.inflight[digest] <= 0 {
			delete(b.inflight, digest)
		}
		b.mu.Unlock()
	}
}

// evictable reports whether the cache may remove the entry: not pinned,
// not held by a create, and its image not locked by one.
func (b *GVisor) evictable(digest string, entry cachedImage) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.pinned[digest] && b.inflight[digest] == 0 && b.inflight[entry.ID] == 0 && b.images[entry.ID] == nil
}

func (b *GVisor) cachePath() string { return filepath.Join(b.config.DataRoot, imageCacheFile) }

// loadCacheLocked reads imageCacheFile once. A missing, unreadable or
// corrupt file, and any invalid entry, is dropped: an image the cache does
// not know is never kept by it, and Reclaim removes it when unused.
func (b *GVisor) loadCacheLocked() {
	if b.cache.loaded {
		return
	}
	b.cache.loaded = true
	b.cache.entries = map[string]cachedImage{}
	data, err := readBounded(b.cachePath(), maxImageCacheFile)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("sandbox image cache unreadable; starting empty", "file", b.cachePath(), "err", err)
		}
		return
	}
	var entries map[string]cachedImage
	if err := json.Unmarshal([]byte(data), &entries); err != nil {
		slog.Warn("sandbox image cache corrupt; starting empty", "file", b.cachePath(), "err", err)
		return
	}
	for digest, entry := range entries {
		if imageDigestPattern.MatchString(digest) && strings.HasPrefix(entry.ID, "sha256:") && entry.Bytes >= 0 {
			b.cache.entries[digest] = entry
		}
	}
}

// saveCacheLocked replaces imageCacheFile atomically.
func (b *GVisor) saveCacheLocked() error {
	data, err := json.Marshal(b.cache.entries)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(b.config.DataRoot, imageCacheFile+".tmp-*")
	if err != nil {
		return fmt.Errorf("sandbox image cache: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("sandbox image cache: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sandbox image cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("sandbox image cache: %w", err)
	}
	if err := os.Rename(tmp.Name(), b.cachePath()); err != nil {
		return fmt.Errorf("sandbox image cache: %w", err)
	}
	if dir, err := os.Open(b.config.DataRoot); err == nil {
		_ = dir.Sync()
		dir.Close()
	}
	return nil
}

// takeCached removes imageID from the cache: a sandbox uses it again.
func (b *GVisor) takeCached(imageID string) error {
	b.cache.mu.Lock()
	defer b.cache.mu.Unlock()
	b.loadCacheLocked()
	changed := false
	for digest, entry := range b.cache.entries {
		if entry.ID == imageID {
			delete(b.cache.entries, digest)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return b.saveCacheLocked()
}

// cachedHit returns the image a lease names when the engine already holds
// it, verified as a pull would be and within the per-image limit, and takes
// it out of the cache. It returns "" when the image must be pulled.
func (b *GVisor) cachedHit(ctx context.Context, name string, lease protocol.SandboxLeaseV1, limit int64) string {
	imageID, size, err := b.verifiedImage(ctx, name+"@"+lease.ImageDigest, lease)
	if err != nil || size > limit {
		return ""
	}
	if err := b.takeCached(imageID); err != nil {
		slog.Warn("sandbox image cache not updated on reuse", "image", imageID, "err", err)
	}
	return imageID
}

// retainImage is the release of imageID once a sandbox is destroyed. With
// the cache disabled it removes the image when no container uses it, as
// releaseImage does. With the cache enabled an unused image is kept and
// recorded unreferenced; a pinned image is kept unrecorded. The cache is
// then brought back within its budget.
func (b *GVisor) retainImage(ctx context.Context, imageID string) error {
	if !b.cacheEnabled() {
		return b.releaseImage(ctx, imageID)
	}
	unlock := b.lockImage(imageID)
	used, err := b.imageUsed(ctx, imageID)
	if err != nil || used {
		unlock()
		return err
	}
	var inspected inspectedImage
	err = b.engine.call(ctx, http.MethodGet, "/images/"+imageID+"/json", nil, nil, &inspected)
	unlock()
	if engineStatus(err) == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect image %s: %w", imageID, err)
	}
	if b.pinnedImage(inspected.RepoDigests) {
		return nil
	}
	var digests []string
	for _, reference := range inspected.RepoDigests {
		if _, digest, ok := strings.Cut(reference, "@"); ok && imageDigestPattern.MatchString(digest) {
			digests = append(digests, digest)
		}
	}
	if len(digests) == 0 || inspected.Size < 0 {
		return b.releaseImage(ctx, imageID)
	}
	sort.Strings(digests)
	b.cache.mu.Lock()
	b.loadCacheLocked()
	for digest, entry := range b.cache.entries {
		if entry.ID == imageID {
			delete(b.cache.entries, digest)
		}
	}
	b.cache.entries[digests[0]] = cachedImage{ID: imageID, Bytes: inspected.Size, LastUsed: b.clock()}
	saveErr := b.saveCacheLocked()
	b.cache.mu.Unlock()
	return errors.Join(saveErr, b.evictCache(ctx, false))
}

// imageUsed reports whether any container on the daemon uses imageID.
func (b *GVisor) imageUsed(ctx context.Context, imageID string) (bool, error) {
	filters, _ := json.Marshal(map[string][]string{"ancestor": {imageID}})
	var users []listedContainer
	if err := b.engine.call(ctx, http.MethodGet, "/containers/json", url.Values{"all": {"1"}, "filters": {string(filters)}}, nil, &users); err != nil {
		return false, fmt.Errorf("list users of image %s: %w", imageID, err)
	}
	return len(users) != 0, nil
}

// dataFreeMiB is the space available on the data root.
func (b *GVisor) dataFreeMiB() (int64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(b.config.DataRoot, &stat); err != nil {
		return 0, fmt.Errorf("sandbox data root: %w", err)
	}
	return int64(stat.Bavail) * int64(stat.Bsize) >> 20, nil
}

// evictCache removes least recently used cache entries while the cache
// exceeds Config.ImageCacheMiB and, with forPull, while the data root has
// less free space than the ImageMaxMiB a pull reserves. Pinned entries,
// entries a create holds, and images a container uses are never removed;
// an entry whose image a container uses leaves the cache instead. Victims
// are chosen under the cache lock; the engine is asked outside it.
func (b *GVisor) evictCache(ctx context.Context, forPull bool) error {
	if !b.cacheEnabled() {
		return nil
	}
	budget := int64(b.config.ImageCacheMiB) << 20
	skipped := map[string]bool{}
	var errs []error
	for {
		needSpace := false
		if forPull {
			free, err := b.dataFreeMiB()
			if err != nil {
				return errors.Join(append(errs, err)...)
			}
			needSpace = free < int64(b.config.ImageMaxMiB)
		}
		b.cache.mu.Lock()
		b.loadCacheLocked()
		var total int64
		order := make([]string, 0, len(b.cache.entries))
		for digest, entry := range b.cache.entries {
			order = append(order, digest)
			total += entry.Bytes
		}
		sort.Slice(order, func(i, j int) bool {
			left, right := b.cache.entries[order[i]], b.cache.entries[order[j]]
			if !left.LastUsed.Equal(right.LastUsed) {
				return left.LastUsed.Before(right.LastUsed)
			}
			return order[i] < order[j]
		})
		victim := ""
		if total > budget || needSpace {
			for _, digest := range order {
				if !skipped[digest] && b.evictable(digest, b.cache.entries[digest]) {
					victim = digest
					break
				}
			}
		}
		entry := b.cache.entries[victim]
		b.cache.mu.Unlock()
		if victim == "" {
			return errors.Join(errs...)
		}
		// removeUnused re-checks, under the image lock, that no container
		// uses the image before it is deleted.
		used, err := b.removeUnused(ctx, entry.ID)
		if err != nil {
			errs = append(errs, err)
			skipped[victim] = true
			continue
		}
		b.cache.mu.Lock()
		if current, ok := b.cache.entries[victim]; ok && current.ID == entry.ID {
			delete(b.cache.entries, victim)
			if err := b.saveCacheLocked(); err != nil {
				errs = append(errs, err)
			}
		}
		b.cache.mu.Unlock()
		if !used {
			slog.Info("sandbox image cache evicted", "digest", victim, "image", entry.ID, "bytes", entry.Bytes)
		}
	}
}

// removeUnused removes imageID unless a container uses it, and reports
// whether one did.
func (b *GVisor) removeUnused(ctx context.Context, imageID string) (bool, error) {
	unlock := b.lockImage(imageID)
	defer unlock()
	used, err := b.imageUsed(ctx, imageID)
	if err != nil || used {
		return used, err
	}
	err = b.engine.call(ctx, http.MethodDelete, "/images/"+imageID, url.Values{"force": {"1"}}, nil, nil)
	if err != nil && engineStatus(err) != http.StatusNotFound && engineStatus(err) != http.StatusConflict {
		return false, fmt.Errorf("remove image %s: %w", imageID, err)
	}
	return false, nil
}

type listedImage struct {
	ID          string   `json:"Id"`
	RepoDigests []string `json:"RepoDigests"`
}

// reclaimWithCache is Reclaim with the cache enabled: every unused image is
// removed except cached and pinned ones, cache entries whose image is gone
// are dropped, and the cache is brought within its budget.
func (b *GVisor) reclaimWithCache(ctx context.Context) error {
	var listed []listedImage
	if err := b.engine.call(ctx, http.MethodGet, "/images/json", nil, nil, &listed); err != nil {
		return fmt.Errorf("list images: %w", err)
	}
	b.cache.mu.Lock()
	b.loadCacheLocked()
	present := map[string]bool{}
	for _, image := range listed {
		present[image.ID] = true
	}
	kept := map[string]bool{}
	for digest, entry := range b.cache.entries {
		if !present[entry.ID] {
			delete(b.cache.entries, digest)
			continue
		}
		kept[entry.ID] = true
	}
	// Rewrite the file on every start, so that a corrupt one is replaced.
	errs := []error{b.saveCacheLocked()}
	b.cache.mu.Unlock()
	for _, image := range listed {
		if kept[image.ID] || b.pinnedImage(image.RepoDigests) {
			continue
		}
		if _, err := b.removeUnused(ctx, image.ID); err != nil {
			errs = append(errs, err)
		}
	}
	errs = append(errs, b.evictCache(ctx, false))
	return errors.Join(errs...)
}

// CachedImages is the image inventory a miner reports: the repository
// digests of images its sandboxes use, then the warm cache's unreferenced
// images, most recently used first. Images used by a sandbox count as used
// now and are ordered by digest among themselves. Pinned images that no
// sandbox uses and the cache does not record are not reported.
func (b *GVisor) CachedImages(ctx context.Context) ([]string, error) {
	filters, _ := json.Marshal(map[string][]string{"label": {LabelSandbox}})
	var containers []listedContainer
	if err := b.engine.call(ctx, http.MethodGet, "/containers/json", url.Values{"all": {"1"}, "filters": {string(filters)}}, nil, &containers); err != nil {
		return nil, fmt.Errorf("list sandboxes: %w", err)
	}
	seen := map[string]bool{}
	var inUse []string
	for _, container := range containers {
		digest := container.Labels[LabelImageDigest]
		if imageDigestPattern.MatchString(digest) && !seen[digest] {
			seen[digest] = true
			inUse = append(inUse, digest)
		}
	}
	sort.Strings(inUse)
	b.cache.mu.Lock()
	b.loadCacheLocked()
	type recent struct {
		digest string
		at     time.Time
	}
	cached := make([]recent, 0, len(b.cache.entries))
	for digest, entry := range b.cache.entries {
		if !seen[digest] {
			cached = append(cached, recent{digest, entry.LastUsed})
		}
	}
	b.cache.mu.Unlock()
	sort.Slice(cached, func(i, j int) bool {
		if !cached[i].at.Equal(cached[j].at) {
			return cached[i].at.After(cached[j].at)
		}
		return cached[i].digest < cached[j].digest
	})
	for _, entry := range cached {
		inUse = append(inUse, entry.digest)
	}
	return inUse, nil
}
