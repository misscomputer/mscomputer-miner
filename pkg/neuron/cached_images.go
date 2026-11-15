// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package neuron

import (
	"errors"
	"regexp"
	"slices"
)

// MaxCachedImages bounds the cached_images a miner reports in one
// capability response.
const MaxCachedImages = 64

var cachedImageDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidateCachedImages checks a reported cached_images list: at most
// MaxCachedImages unique sha256:<64 lowercase hex> repository digests. The
// order is the miner's recency order (most recent first) and is not
// verifiable; an absent list is valid and means "nothing reported". A
// validator refuses an invalid list rather than trimming it.
func ValidateCachedImages(digests []string) error {
	if len(digests) > MaxCachedImages {
		return errors.New("cached_images carries too many digests")
	}
	seen := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		if !cachedImageDigestPattern.MatchString(digest) {
			return errors.New("cached_images entries must be sha256:<64 lowercase hex> digests")
		}
		if _, ok := seen[digest]; ok {
			return errors.New("cached_images entries must be unique")
		}
		seen[digest] = struct{}{}
	}
	return nil
}

// NormalizeCachedImages is the report a miner sends from a most-recent-first
// inventory: invalid and repeated digests are dropped, the order is kept,
// and the list is cut at MaxCachedImages. Nil when nothing remains, so that
// the member is omitted.
func NormalizeCachedImages(inventory []string) []string {
	var out []string
	for _, digest := range inventory {
		if len(out) == MaxCachedImages {
			break
		}
		if cachedImageDigestPattern.MatchString(digest) && !slices.Contains(out, digest) {
			out = append(out, digest)
		}
	}
	return out
}
