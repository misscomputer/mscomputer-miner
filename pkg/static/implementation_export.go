// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package static

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/misscomputer/mscomputer-miner/pkg/organic"
)

// This file is deliberately NOT in implementationFiles: handler.go hashes its
// own bytes, so the normalizer for the public miner export lives here, where
// adding it leaves the private ServerImplementationDigest unchanged.
//
// The public export (scripts/miner-export/export.sh) rewrites every Go file's
// license header and the module path. Without this normalization a public
// miner would report a different digest and refuse every static ticket with
// static_server_implementation_mismatch.
func init() { ServerImplementationDigest = implementationDigestOf(implementationSources.ReadFile) }

// normalizeImplementationSource maps the staging and public-export rewrites
// back to the private form. String literals are split so those rewrites
// cannot rewrite the normalizer itself.
func normalizeImplementationSource(source []byte) []byte {
	const mod = "github.com/misscomputer/mscomputer-"
	for _, from := range []string{"infra" + "/pkg/", "miner" + "/pkg/"} {
		source = bytes.ReplaceAll(source, []byte(mod+from), []byte(mod+"subnet"+"/pkg/"))
	}
	publicHeader := "// Copyright (c) 2026 Ms. Computer. All rights reserved.\n" +
		"// SPDX-License-" + "Identifier: LicenseRef-MsComputer-Miner\n"
	if rest, ok := bytes.CutPrefix(source, []byte(publicHeader)); ok {
		source = append([]byte("// SPDX-License-Identifier: AG"+"PL-3.0-only\n"), rest...)
	}
	return source
}

// implementationDigestOf is implementationDigest (handler.go) with the full
// normalizer; on the private tree both return the same value.
func implementationDigestOf(read func(string) ([]byte, error)) string {
	descriptor := implementationDescriptor{
		Handler: HandlerVersion, Schema: organic.SchemaPrefix + "static-handler-implementation", SchemaVersion: 1,
	}
	for _, name := range implementationFiles {
		source, err := read(name)
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(normalizeImplementationSource(source))
		descriptor.Files = append(descriptor.Files, implementationFile{Path: "pkg/static/" + name, SHA256: hex.EncodeToString(sum[:])})
	}
	encoded, err := organic.Canonical(descriptor)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}
