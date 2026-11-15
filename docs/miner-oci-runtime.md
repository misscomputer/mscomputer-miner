# Miner OCI runtime (organic `deployment.v4`)

This note describes how a miner agent turns an organic `deployment.v4`
ticket into a running replica. The ticket names an artifact-manifest v2 by
digest and the miner runs the customer's OCI image exactly as built and
smoke-tested by the CLI, under the fixed runtime profile `small-v1`.

## Acceptance sequence

1. **Envelope and ticket.** The Python miner accepts `subnet-synapse.v3`
   deploys (`DeploySynapseV3`, strict parse), applies the btauth and
   Bittensor identity checks, and forwards a v3 loopback request. The agent
   (`Agent.AssignBoundV4`) verifies the `protocol.TicketV4` with
   `VerifyTicketV4` (signature by the bound validator service key, window,
   every `deployment.v4` rule including `resources == organic.SmallV1`), then
   network, netuid, hotkeys, UID, chain block, its own service key and its
   transport pin. No nonce is consumed and no receipt is signed for a
   rejected ticket.
2. **Manifest.** `v1/manifests/<hex>.json` is read with the manifest key
   derived from `image_digest` (never trusted separately), bounded at 1 MiB,
   and accepted only as the canonical stored bytes whose SHA-256 is the
   `image_digest` (`artifact.ParseManifestV2`).
3. **Layout.** `artifact.MaterializeOCILayout` streams the OCI manifest, the
   config and every layer from the read-only store into
   `<state>/<instance>.oci/`, re-hashing length and SHA-256 of each blob,
   checking the OCI manifest's descriptors against the artifact manifest,
   the config's platform and `rootfs.diff_ids`, and decompressing gzip
   layers to verify each `diff_id` and `uncompressed_size`. Configs that
   declare `Volumes` or have no entrypoint/command are rejected. Layers are
   never buffered whole in memory.
4. **Load and identity.** The verified layout is streamed as an OCI archive
   into `docker load`, tagged `mscomputer/organic:a-<artifact hex>`. The
   engine's image ID must be either the config digest (classic image store)
   or the OCI manifest digest (containerd image store); both bind exactly
   the verified config. Any other ID is `image_identity_mismatch`. The
   verified blob copies are then discarded.
5. **Run.** The container is started from the verified image ID with the
   exact `small-v1` flags: `--pull never --platform linux/amd64 --cpus 1.000
   --memory 1024m --memory-swap 1024m --pids-limit 256 --read-only --tmpfs
   /tmp:rw,noexec,nosuid,size=64m --user 65532:65532 --cap-drop ALL
   --security-opt no-new-privileges --ipc private --log-driver json-file
   --log-opt max-size=1m --log-opt max-file=2 --rm`, the image `ENV` plus only
   `PORT` and `HOST`, and no restart policy, volumes, devices or host
   namespaces. The container name stays `ms-<prefix>-<12hex>`; its cleanup
   identity is durable before `docker run`.
6. **Startup health.** The agent requests `http://<container IP>:<port><path>`
   directly with `Host: <route_host>`, using the ticket's health fields:
   `startup_timeout_millis` overall, `probe_timeout_millis` per attempt,
   `interval_millis` between attempts, `successes_required` consecutive
   matches of status and (optional) marker within the first 64 KiB.
   Redirects are not followed. A container that is no longer running fails
   immediately as `container_exited`. There is no health loop after `ready`.
7. **Receipt.** The agent signs `protocol.ReceiptV4` (`SignReceiptV4`):
   `ready` with `loaded_image_config_digest` (= artifact `config.digest`) and
   `error_code: null`, or `failed` with one `organic.ReceiptErrorAttribution`
   code and a printable-ASCII `error` of at most 512 bytes that never contains
   container output. Every signed receipt, including failures, is returned as
   `deploy-response.v3` and kept for `status-response.v3`.

Error codes: store unavailability → `artifact_fetch_failed`; any digest,
size, binding or policy mismatch → `artifact_verify_failed`; `docker load`
failure → `image_load_failed`; wrong engine ID → `image_identity_mismatch`;
`docker run`/network attach failure → `container_create_failed`; `ENOSPC`
anywhere → `resource_exhausted`; fence during creation → `deactivated`.

## Network isolation (deny-all egress)

Replicas join one Docker bridge network (default `mscomputer-organic`) that
is `--internal` (no route off the host), has inter-container communication
disabled, IPv6 off, and a fixed host interface name (default
`ms-organic0`). The agent reaches apps at the container IP; no ports are
published.

An internal bridge still lets a container open connections to host services
bound to `0.0.0.0` through the bridge gateway address. The agent therefore
requires the host rule

```text
iptables -I INPUT -i ms-organic0 -m conntrack --ctstate NEW -j DROP
```

which drops container-initiated connections while conntrack admits replies
to the agent's own health and proxy connections. `miner-agent --runtime
docker` creates/validates the network and, with `--host-isolation enforce`
(default), installs the rule when missing; `--host-isolation verify` only
checks for it. Startup fails, and `organic-oci-v1` is never advertised,
unless both checks pass. The real-engine test
`TestDockerOCIRuntimeRunsVerifiedImageUnderSmallV1`
(`MSCOMPUTER_DOCKER_OCI_TEST=1`, root) confirms from inside the container
that the host gateway, another organic container, `169.254.169.254`, RFC 1918
and public addresses are all unreachable.

Docker itself adds `HOSTNAME` and `HOME` to the environment; nothing else is
injected.

## Cleanup and image retention

Deactivation, failed assignments and restart recovery call
`StopCleanup` with the persisted `<instance>` name and `<state>/<instance>.oci`
directory: `docker rm --force`, then — under a per-artifact lock ordered
against concurrent launches — the artifact tag is removed only when no
container on the engine still uses it, and finally the instance directory is
deleted. Every step is idempotent.

## Runtime ingress

For an organic endpoint the agent accepts a `/runtime/<endpoint_id>/...`
request only with exactly one `X-Ms-Edge-Authorization` that
`organic.VerifyEdgeRuntimeRequest` accepts for the request actually received
(method, escaped path after the endpoint, raw query, body SHA-256) under the
addressed ticket's `validator_service_public_key`, fresh within 10 s (+2 s
skew), whose nonce has never been seen (durable replay store, in-memory
without one). Anything else is answered 401 before the container is
contacted. Every `X-Ms-*` header is stripped in both directions, the app
receives `Host: <route_host>` and the edge's `X-Forwarded-*` values, and
bodies are bounded at 1 MiB. There is nothing to configure.

## App budget

Priority on a miner is sandboxes, then app sites (deployment.v4 replicas),
then plain static sites (whose `--static-cache-max-bytes` cache is separate).
The agent sizes an app budget for its host and refuses assignments beyond it:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--system-reserve-mib` | 1536 | memory kept for the system |
| `--sandbox-reserve-mib` | 6144 | memory kept for each sandbox lease group (the declared floor `memory_mib`, which holds one 4 GiB customer sandbox plus overhead) |
| `--app-budget-mib` | 5120 | app budget of a 16 GiB host; 0 disables accounting |
| `--app-copy-mib` | 256 | what one replica counts against the budget |
| `--app-cpu-weight` | 50 | CPUWeight the app slice should have |
| `--app-cgroup-parent` | (derived) | slice replicas run in; empty uses a top-level `--sandbox-deployment-cgroup`, `none` keeps Docker's default |
| `--host-memory-mib`, `--host-vcpus` | 0 (read from the host) | host size used by the plan; memory is MemTotal rounded up to a GiB |
| `--app-budget-print` | false | print the plan and the app slice drop-in, then exit |

With `usable = memory - system reserve`:

- `target = app-budget-mib * usable / (16384 - system reserve)`
- `sandboxes = min(floor((usable - target) / sandbox reserve), floor(vcpus / 2))`,
  raised to 1 when one reserve fits and the host has at least 2 vCPUs
- `app budget = min(target, usable - sandboxes * sandbox reserve)`
- `copies = floor(app budget / app-copy-mib)`

On a 4 vCPU / 16 GiB host this is one 6 GiB sandbox reserve and a 5 GiB budget
of 20 copies. The reserve is not a sandbox size. Every customer sandbox is
1 vCPU / 4 GiB / 10 GiB. A reserve is one sandbox lease group of 2 vCPU and
6 GiB, the minimum a sandbox miner declares (see
[miner-quickstart.md](miner-quickstart.md)).
The plan does not read the sandbox host profile. Keep `--sandbox-reserve-mib`
at least the profile's `aggregate.memory_mib` per sandbox, and note that the
system reserve does not include the sandbox engine slice (1536 MiB with the
installer): on a 16 GiB host keep the defaults; on a tighter host raise
`--system-reserve-mib` to cover it. Each replica keeps its 1 GiB `small-v1` limit as a burst
ceiling; the hard limit of all replicas together is the app slice's
`MemoryMax`, which the operator installs from `--app-budget-print`; until
it is installed, admission is the only bound and the agent logs a warning.
If the slice's `memory.max` is below the budget, the agent advertises fewer
copies. A slice parent needs the organic Docker daemon's systemd cgroup
driver; the agent refuses to start otherwise (use `--app-cgroup-parent none`).
Plain static sites are not part of the plan: their file cache lives in the
page cache and is reclaimable.

The agent advertises the copy count as the capability feature
`organic-app-copies-v1.<n>`. An assignment beyond the budget is refused
before its nonce is admitted or anything is fetched: HTTP 503
`app_budget_exhausted` (retryable), with no receipt, so the validator places
the replica on another miner. An exact replay of a running assignment is
still answered.
