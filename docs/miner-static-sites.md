# Miner static sites (`static-site-v1`)

A miner can host verified static sites next to dynamic `oci-image-v1` /
`deployment.v4` replicas. This note describes how the miner agent accepts,
verifies and serves them.

## Enabling

```text
miner-agent ... --static-sites on \
  --static-cache-dir /var/lib/mscomputer/static \
  --static-cache-max-bytes 8589934592 \
  --static-fetch-timeout 2m --static-request-concurrency 64
```

The agent's own default is `--static-sites off`: no static route, no cache,
and the capability `organic-static-v1` is not advertised. The
[installer](miner-installer.md) unit turns it on (cache under the agent state
directory, 8 GiB); to opt out there, set
`MC_AGENT_EXTRA_ARGS=--static-sites off` in `miner.env`. With `on`, the cache
quota must be at least one maximal site (256 MiB). The cache lives only in
`<static-cache-dir>/mscomputer-static-v1/`; startup sweeps that directory and
nothing else. The Docker organic runtime is still required at startup; static
endpoints never use it.

## Wire interfaces

Validator → miner (btauth-signed dendrite, `subnet-static-synapse.v1`):

| Axon route | Request | Response |
|---|---|---|
| `POST /api/v1/static/deploy` | `StaticDeploySynapseV1` (`protocol`, `request_id`, `current_block`, `caller_hotkey`, `validator_binding`, `ticket`) | `StaticDeployResponseV1` (`protocol`, `request_id`, `endpoint_id`, `receipt`, `idempotent`) |
| `POST /api/v1/static/status` | `StaticStatusSynapseV1` (`protocol`, `request_id`, `current_block`, `caller_hotkey`, `endpoint_id`) | `StaticStatusResponseV1` (`protocol`, `request_id`, `status`, `receipt` or `null`) |
| `POST /api/v1/deactivate` | existing `DeactivateSynapse` (kind-neutral) | existing `DeactivateResponse` |
| `/runtime/<endpoint_id>/...` | existing edge-runtime-request v1 ingress | static-handler.v1 response |

The axon applies the organic btauth, metagraph, validator-binding and ticket
subnet checks before any agent contact and forwards the exact ticket as
`LocalStaticAssignRequestV1` to the Go bridge:

| Go bridge route | Request | Response |
|---|---|---|
| `POST /v1/static/assignments` | `LocalStaticAssignRequestV1` (the deploy members plus `binding_verified`) | `StaticDeployResponseV1` |
| `POST /v1/static/status` | `StaticStatusSynapseV1` | `StaticStatusResponseV1` |
| `POST /v1/deactivate` | existing `DeactivateSynapse` | existing `DeactivateResponse` |

`/api/v1/deploy` (v3) never accepts a static ticket and `/api/v1/static/deploy`
never accepts a v3 envelope or a `deployment.v4` ticket (422). A disabled Go
agent answers `501 static_disabled`; the axon keeps that code. `POST
/v1/status` answers `409 static_endpoint` for a static endpoint.

Validators learn that a miner serves static sites from the `features` list of
its capability response (`organic-static-v1`); a miner without it is not sent
static tickets.

Ticket and receipt are `protocol.StaticTicketV1` / `protocol.StaticReceiptV1`,
with domain-separated Ed25519 signatures, `miner_uid` always present,
canonical string timestamps and `static.ReceiptErrorAttribution` codes.
Endpoint identities use the v4 derivation, so runtime paths and endpoint
fences are shared; the one-time `assignment` nonce scope is shared with v4,
so a nonce can never name both a static and a dynamic endpoint.

## Verify-then-serve

1. The bridge applies the shared validator-binding checks; the agent
   verifies the ticket (`VerifyBoundStaticTicketV1`), its miner service key
   and transport pin. Refusals return no receipt and consume no nonce.
2. Admission consumes the nonce and records the exact ticket in
   `static_assignments` (a separate table: v4 decoders and recovery never
   read a static row). A deactivation fence recorded earlier wins.
3. A ticket naming another `server_implementation_digest` fails with
   `static_server_implementation_mismatch`.
4. The manifest is read by `site_manifest_key` (at most 1 MiB), must hash to
   `site_digest` (`static_verify_failed`), and must pass every manifest rule
   (`static_manifest_invalid`) and size limit (`static_limits_exceeded`). An
   oversize object at `site_manifest_key` is `static_verify_failed`.
5. `static.Cache.Pin` reserves the quota (`static_storage_exhausted`), then
   fetches every distinct body (4 concurrent, bounded by
   `--static-fetch-timeout`) into a temp file while hashing, checks length and
   SHA-256, fsyncs, makes it read-only and renames it into the cache. A cached
   body is re-hashed before reuse. A zero-length body is determined by its
   digest and is not fetched. Any failure releases everything; there is no
   partial or lazy pin.
6. Only then is `ready` signed and persisted with `verified_file_count` and
   `verified_total_bytes`, and only after that is the endpoint servable.
   Failures sign a `failed` receipt with its error code.

Serving: after edge-runtime-request verification, the raw path after
`/runtime/<endpoint_id>` (from the unparsed request-target) goes through
`static.ResolveRequest` and `static.WriteResponse`. Bodies are re-hashed while
streaming and the final chunk is withheld unless the digest matches; a
mismatch aborts the connection and removes the endpoint from serving. Each
endpoint has an in-flight bound (fixed `503 Service Unavailable` beyond it).
Signed attestation headers are added as for dynamic replicas (see
[miner-oci-runtime.md](miner-oci-runtime.md#runtime-ingress)), with
`artifact_digest = site_digest`.

Restart: the cache is swept and `RecoverCleanup` fences and retires every
static endpoint, so a restarted miner never serves bytes it has not
re-verified in this process (a new ticket re-pins). The miner binds
`release_digest` into its receipt.

## Reusing the handler

`pkg/static` is the single `static-handler.v1` implementation. An origin
reuses it unchanged:

```go
manifest, err := static.Parse(storedManifestBytes, siteDigest) // verified site
index := static.NewIndex(manifest)
handler := static.NewHandler(index, bodies, routeHost, 64)       // routeHost enables the 421 check
```

`bodies` implements `static.BodySource` (`Open(static.File) (io.ReadCloser,
error)`); it need not be trusted, because `WriteResponse` re-hashes every
body. The origin can use `static.Cache.Pin` + `*static.Site` (which is a
`BodySource`) or its own store. For lower-level use: `static.RawRequestPath`,
`static.ResolveRequest(index, req, rawPath, routeHost)`, `Index.Resolve`,
`Response.Header`, `Response.BodySHA256`, `Response.HeaderSHA256`,
`static.WriteResponse` and `Index.Routes`.

Go's `net/http` rejects some malformed request-targets (for example a bare
`%`) before any handler runs, with its own 400 body; `Index.Resolve` still
returns the fixed 400.

## Server implementation digest

`static.ServerImplementationDigest` is `sha256:` of a canonical JSON
descriptor listing the SHA-256 of `pkg/static/handler.go`,
`pkg/static/manifest.go`, `pkg/static/path.go` and `pkg/static/serve.go`,
computed at init from the embedded handler sources. Any byte change to those
files is a new digest, and tickets naming the released digest are refused
(`static_server_implementation_mismatch`). Run the released code unmodified.
