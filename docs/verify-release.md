# Verifying a release

Every release tag `vX.Y.Z` publishes, from GitHub-hosted CI with no secrets:

- `miner-agent-linux-amd64`, `sandbox-ops-helper-linux-amd64`,
  `sandbox-host-observe-linux-amd64`, `mscomputer_miner-*.whl`
- `SHA256SUMS`, plus a Sigstore bundle per file (keyless, GitHub OIDC)
- SLSA build provenance attestation

Verify a downloaded binary:

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify miner-agent-linux-amd64 --repo misscomputer/mscomputer-miner
cosign verify-blob miner-agent-linux-amd64 \
  --bundle miner-agent-linux-amd64.sigstore.json \
  --certificate-identity-regexp '^https://github.com/misscomputer/mscomputer-miner/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Rebuild it yourself (reproducible: Go 1.23.12, `-trimpath`, `CGO_ENABLED=0`,
`-buildvcs=false`) and compare digests:

```bash
git checkout vX.Y.Z
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-mod=readonly \
  go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o miner-agent ./cmd/miner-agent
sha256sum miner-agent
```

`cosign` checks that the file was signed by this repository's release
workflow for a `v*` tag; `gh attestation verify` checks the build provenance.
To also pin the exact tag, use
`--certificate-identity https://github.com/misscomputer/mscomputer-miner/.github/workflows/release.yml@refs/tags/vX.Y.Z`
instead of the regular expression.

## The installer pin

`scripts/miner-install/install.sh` pins a release tag (`PINNED_REF`) and the
agent digest (`PINNED_AGENT_SHA256`). It builds the agent from source at that
tag with the same recipe and refuses a binary whose digest differs. The recipe
embeds no commit or VCS data, so the pinned digest equals the
`miner-agent-linux-amd64` release asset; the release workflow fails if the
tagged `install.sh` pins anything else. To check a pin yourself, verify the
release as above, then compare:

```bash
grep '^readonly PINNED_' scripts/miner-install/install.sh
grep ' miner-agent-linux-amd64$' SHA256SUMS
```

To install a newer release than the one your checkout pins, verify it as
above and run `install.sh install` with `MC_INSTALL_REF=vX.Y.Z` and
`MC_INSTALL_AGENT_SHA256=<its miner-agent-linux-amd64 digest>`.
