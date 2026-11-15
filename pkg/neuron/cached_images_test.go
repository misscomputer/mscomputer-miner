// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package neuron

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func digestN(n int) string { return fmt.Sprintf("sha256:%064x", n) }

func capabilitiesResponseFixture(t *testing.T) []byte {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	payload, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "contracts", "fixtures", "capabilities-response.v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func decodeStrict(t *testing.T, payload []byte, out any) error {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

// A response without cached_images decodes, re-encodes byte-identically
// (no new member appears), and one with it round-trips in order.
func TestCachedImagesRoundTripAndOmitEmpty(t *testing.T) {
	payload := capabilitiesResponseFixture(t)
	var plain CapabilitiesResponse
	if err := decodeStrict(t, payload, &plain); err != nil {
		t.Fatal(err)
	}
	if plain.CachedImages != nil || ValidateCachedImages(plain.CachedImages) != nil {
		t.Fatalf("a response without the member reports %v", plain.CachedImages)
	}
	encoded, err := json.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("cached_images")) {
		t.Fatalf("an empty inventory is encoded: %s", encoded)
	}
	plain.CachedImages = []string{}
	if encoded, _ := json.Marshal(plain); bytes.Contains(encoded, []byte("cached_images")) {
		t.Fatalf("an empty inventory is encoded: %s", encoded)
	}

	var withImages map[string]any
	if err := json.Unmarshal(payload, &withImages); err != nil {
		t.Fatal(err)
	}
	want := []string{digestN(3), digestN(1), digestN(2)}
	withImages["cached_images"] = want
	extended, _ := json.Marshal(withImages)
	var decoded CapabilitiesResponse
	if err := decodeStrict(t, extended, &decoded); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(decoded.CachedImages, want) || ValidateCachedImages(decoded.CachedImages) != nil {
		t.Fatalf("cached_images = %v", decoded.CachedImages)
	}
	again, _ := json.Marshal(decoded)
	var roundTripped CapabilitiesResponse
	if err := decodeStrict(t, again, &roundTripped); err != nil || !slices.Equal(roundTripped.CachedImages, want) {
		t.Fatalf("round trip = %v, %v", roundTripped.CachedImages, err)
	}

	local := LocalCapabilities{Protocol: SynapseVersion, CachedImages: want}
	encodedLocal, _ := json.Marshal(local)
	var decodedLocal LocalCapabilities
	if err := decodeStrict(t, encodedLocal, &decodedLocal); err != nil || !slices.Equal(decodedLocal.CachedImages, want) {
		t.Fatalf("local capabilities round trip = %v, %v", decodedLocal.CachedImages, err)
	}
}

func TestValidateCachedImagesRefusesMalformedOrOverCap(t *testing.T) {
	full := make([]string, MaxCachedImages)
	for index := range full {
		full[index] = digestN(index)
	}
	if err := ValidateCachedImages(full); err != nil {
		t.Fatalf("%d digests refused: %v", MaxCachedImages, err)
	}
	for name, digests := range map[string][]string{
		"over cap":     append(slices.Clone(full), digestN(MaxCachedImages)),
		"uppercase":    {"sha256:" + strings.Repeat("A", 64)},
		"short":        {"sha256:" + strings.Repeat("a", 63)},
		"long":         {"sha256:" + strings.Repeat("a", 65)},
		"no algorithm": {strings.Repeat("a", 64)},
		"sha512":       {"sha512:" + strings.Repeat("a", 64)},
		"reference":    {"busybox@" + digestN(1)},
		"tag":          {"busybox:latest"},
		"empty":        {""},
		"newline":      {digestN(1) + "\n"},
		"duplicate":    {digestN(1), digestN(2), digestN(1)},
	} {
		if err := ValidateCachedImages(digests); err == nil {
			t.Errorf("%s: %q accepted", name, digests)
		}
	}
}

// The miner's report keeps the inventory order, drops invalid and repeated
// digests, and stops at the cap.
func TestNormalizeCachedImagesKeepsRecencyOrderWithinCap(t *testing.T) {
	inventory := []string{digestN(9), "latest", digestN(2), digestN(9), digestN(5)}
	if got, want := NormalizeCachedImages(inventory), []string{digestN(9), digestN(2), digestN(5)}; !slices.Equal(got, want) {
		t.Fatalf("normalized = %v, want %v", got, want)
	}
	if got := NormalizeCachedImages([]string{"latest"}); got != nil {
		t.Fatalf("nothing valid normalized to %v, want nil", got)
	}
	long := make([]string, MaxCachedImages+10)
	for index := range long {
		long[index] = digestN(len(long) - index)
	}
	got := NormalizeCachedImages(long)
	if !slices.Equal(got, long[:MaxCachedImages]) || ValidateCachedImages(got) != nil {
		t.Fatalf("over-cap inventory normalized to %d entries", len(got))
	}
}
