// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package static

import (
	"bytes"
	"regexp"
	"testing"
)

// exportTransform mirrors scripts/miner-export/export.sh for Go sources: the
// license-header rewrite and the module-path rewrite (literals split so the
// export cannot rewrite this test into a no-op).
func exportTransform(src []byte) []byte {
	header := regexp.MustCompile(`(?m)^(\S+) SPDX-License-` + `Identifier: AG` + `PL-3\.0-only$`)
	src = header.ReplaceAll(src, []byte("$1 Copyright (c) 2026 Ms. Computer. All rights reserved.\n$1 SPDX-License-"+"Identifier: LicenseRef-MsComputer-Miner"))
	return bytes.ReplaceAll(src, []byte("github.com/misscomputer/mscomputer-"+"subnet"), []byte("github.com/misscomputer/mscomputer-"+"miner"))
}

func stagingTransform(src []byte) []byte {
	return bytes.ReplaceAll(src, []byte("github.com/misscomputer/mscomputer-"+"subnet/pkg/"), []byte("github.com/misscomputer/mscomputer-"+"infra/pkg/"))
}

// Pinned live value: the digest the static release producer signs and the
// running miners implement. Changing it (even through a comment edit in
// handler.go, manifest.go, path.go or serve.go, which are hashed byte for
// byte) is a static-handler.v1 digest roll: producer, origin and every miner
// in one window.
const livePrivateDigest = "sha256:4df9e65e6e31c9b05059967a6549e4661f9f789272b81b98c390e4d9c6d1931d"

func TestPrivateDigestUnchanged(t *testing.T) {
	if ServerImplementationDigest != livePrivateDigest {
		t.Fatalf("digest %s != live %s", ServerImplementationDigest, livePrivateDigest)
	}
}

func TestImplementationDigestStableAcrossExportAndStaging(t *testing.T) {
	for name, transform := range map[string]func([]byte) []byte{"export": exportTransform, "staging": stagingTransform} {
		changed := false
		got := implementationDigestOf(func(file string) ([]byte, error) {
			src, err := implementationSources.ReadFile(file)
			out := transform(src)
			changed = changed || !bytes.Equal(out, src)
			return out, err
		})
		if !changed {
			// Already-exported tree: the pin check above covers it.
			t.Logf("%s transform is a no-op on this tree", name)
			continue
		}
		if got != ServerImplementationDigest {
			t.Fatalf("%s digest %s != private %s", name, got, ServerImplementationDigest)
		}
	}
}
