# gVisor sandbox backend (`pkg/sandboxbackend`)

This is the sandbox backend of the miner agent. It runs each sandbox as one
container under a pinned gVisor (`runsc`) runtime on a Docker daemon that is
dedicated to sandboxes. The [installer](miner-installer.md) provisions that
host; this page describes what the agent requires of it and how it runs one
sandbox.

## Activation

`miner-agent --sandbox-leases on` enables the backend (the installer's unit
sets it). With `off` any `--sandbox-*` setting is refused.

With `on`, the agent needs three inputs and starts only if all of the
following hold:

- `--sandbox-host-profile`: the `sandbox-host-profile.v1` document the
  installer wrote (`/var/lib/mcsbx/profile.json`). Every backend value comes
  from it: socket, runtime and sentry pins, data roots, slice, cgroup root,
  aggregate disk, sandbox count, image and log limits, per-lease pids limit,
  and the Docker version pin, which must be this backend's `28.0.4`.
- `--sandbox-deployment-cgroup`: the cgroup v2 path deployment.v4 replicas
  run in. It must be a clean absolute path that exists under the profile's
  cgroup root. It and the agent's own cgroup must be disjoint from the
  sandbox and engine slices. When it is a top-level `/<name>.slice`, the
  agent starts replicas with that slice as their Docker cgroup parent
  (see `--app-cgroup-parent` in [miner-oci-runtime.md](miner-oci-runtime.md)).
- `--sandbox-daemon-config`: the dedicated daemon's configuration file,
  evidence for the two `configured` engine checks.
- **The preflight report passes.** The backend's engine checks (below) and
  `pkg/sandboxhost`'s host checks are merged into one
  `sandbox-host-preflight.v1` report. That report is logged once, and must
  pass: every check `pass`, every `unenforced` entry `gap`.
- **The lane accepts its budget.** The lane is then built with the
  profile's aggregate as its budget and verifies it against the slice.
- **Restart recovery** gets its own 5-minute budget; the shutdown
  recovery, after the lane closes and the replicas are cleaned up, gets 60
  seconds.

On restart, every lease whose sandbox may exist answers
`failed/miner_restart` and is destroyed. Every other sandbox container on the
daemon is destroyed as an orphan, and images no container uses are pruned,
except warm-cache and pinned images (below).

**Warm image cache.** When the profile's `data_fs_mib` exceeds
`disk_mib + sandboxes x (image_max_mib + log_mib) + engine_overhead_mib +
image_reserve_mib`, that slack is the image cache budget. A released image
is kept and recorded unreferenced in `cache.json` under the data root
(`{digest: {id, bytes, last_used}}`, rewritten atomically; a missing or
corrupt file starts empty, and restart recovery then removes the unknown
images). A create whose digest the engine already holds skips the pull.
Least recently used entries are evicted before each pull, until the data
root has `image_max_mib` free, and whenever the cache exceeds its budget.
An image a container uses is never removed, nor one whose digest is listed
in `--sandbox-pinned-images` (for example sandbox-base). Without slack the
cache is off and a released image is removed. After a pull, an image whose
unpacked size exceeds `image_max_mib` is removed and refused
`image_too_large`, a tenant fault.

## Engine checks (no host changes)

`Open` refuses a host on which any of these fails; checks that need the
profile layout or the daemon configuration are skipped without them.

- `engine.socket_dedicated`: the socket is not the default daemon's. With
  the profile, it lies under `run_root` with mode 0660 owned by root, and
  the default daemon's socket (if any) answers with another engine ID.
- `engine.version_pinned`: the server is Docker `28.0.4`.
- `engine.data_root_on_data_fs`: `DockerRootDir` is the profile's
  `docker_data_root`, on the device of `data_root`.
- `engine.storage_overlay2_xfs`: `overlay2` on an XFS backing filesystem
  with d_type.
- `engine.cgroup_driver_systemd_v2`: `systemd` on cgroup v2.
- `engine.containerd_dedicated`: a containerd socket other than the host's
  shared or the daemon-managed default, with namespaces other than the
  default engine's. With the profile, these are the profile's, and the
  metadata store `<data_root>/containerd/io.containerd.metadata.v1.bolt/meta.db`
  is on the data device.
- `engine.network_management_off`: no network beyond `host` and `none`.
- `engine.firewall_management_off` (configured): the daemon configuration
  sets `iptables`, `ip6tables`, `ip-forward` and `ip-masq` false and
  `bridge` to `none`.
- `engine.runtime_runsc_pinned`:
  - runsc is registered at the pinned path, with arguments drawn only from
    `--overlay2=none`, `--systemd-cgroup`, `--platform=systrap` and
    `--platform=kvm`, and including the first two; with the profile, the
    arguments are exactly the profile's;
  - the runsc and sentry binaries match their SHA-256 pins, opened without
    following symlinks.
- `engine.default_bounded_logs` (configured): `LoggingDriver` is
  `json-file`, and the daemon configuration's default log options equal the
  profile's per-lease sizes.
- `engine.insecure_registries_empty`: no insecure registry beyond the
  loopback prefixes Docker always lists, no mirror, and Docker Hub as the
  only, secure index.
- `engine.no_unlabelled_containers`: no container without the sandbox label.

The cgroup, storage, budget, network-egress and kernel checks belong to
`pkg/sandboxhost`. The per-lease pids refusal uses the profile's
`per_lease.pids_max`. A lease's pids are its guest's: the container's
`pids.max` is the lease's pids plus `sandboxhost.GVisorHostPIDs` (176: 48 plus
8 per running exec, up to `MaxRunningExecs`) for the sentry, gofer,
fd-parking and systrap stub processes that share the container cgroup.
Adoption and readback require exactly this `pids.max`, so before upgrading
across a change of `GVisorHostPIDs`, let the running sandboxes end first (and
raise the profile's aggregate pids if they no longer cover
`sandboxes x (pids_max + GVisorHostPIDs)`); containers created with the old
value are refused on adoption. The engine checks run once at startup; a binary
or daemon changed later is caught by the per-sandbox checks below.

Every `Create` decision is logged: one `sandbox instance report` (a
`sandbox-host-preflight.v1` report in instance mode) whatever it decided
(`running`, `exited`, `never_started`, `refused: <code>` or `fault`), and
`sandbox create timing` with the pull's time and the local steps' time.

## What one sandbox is

Refused before anything is pulled (non-fault receipt codes): isolation other
than `gvisor` (`isolation_unsupported`), network other than `none`, `public`
or `allowlist` (`network_policy_unsupported`), more pids than the slice
(`resources_unsupported`), and, in the lane, any `secret_env`
(`secret_delivery_unsupported`).

Registry (`image_unavailable`, before any engine call): any IP literal, any
name that only resolves on the miner's own host or site (`localhost`,
single-label names, absolute names ending in `.`, and the `.localhost`,
`.local`, `.internal` and `.home.arpa` namespaces), and any registry host
(Docker Hub as `registry-1.docker.io`) that does not resolve, or that
resolves to any address in the `pkg/netpolicy` special-purpose prefixes
(loopback, link-local and metadata, RFC 1918, CGNAT, ULA, unspecified and the
rest of that list) or to an address assigned to one of this host's
interfaces, read fresh before every pull. If this host's addresses cannot be
read, the pull is refused as a miner fault. The host-level pull egress policy
(`network.engine_egress_restricted`) is the second layer.

Image: pulled by its exact digest for `linux/amd64`, only while the data
root has the per-image limit free (otherwise a miner fault). The pull is
stopped once the compressed layer sizes exceed the per-image limit
(`image_unavailable`). The image must be `linux/amd64`, within the
stored-size limit, and name a command (otherwise `image_unavailable`), and
declare no `VOLUME` (otherwise `resources_unsupported`). A refused image is
removed. Every registry-side pull failure is `image_unavailable`; a daemon
that gives no answer to the pull request is a miner fault. No registry
credentials are supported.

Deadlines: `Create` gets one create budget. The registry phase runs until
that deadline minus a fixed local-step reserve of 2 minutes; running past it
is `image_unavailable`. The steps after a pull (inspection, container
create, start and readbacks) run under their own fresh deadline of the full
reserve; running past it is a miner fault. Every other Engine API call has a
2-minute answer timeout.

Container: created from the verified engine image ID with runtime runsc,
`NetworkMode=none` (or the egress bridge for `public`/`allowlist`), cgroup
parent the slice, the lease's CPU, memory (swap equal, so none), pids and
writable-layer quota (`StorageOpt size`), `json-file` logs of two files
within the per-sandbox log allowance, `CapDrop ALL` plus exactly Docker's
default capability set, `Privileged` false, `no-new-privileges`, private IPC,
PID, UTS, user and cgroup namespaces, `Init` false (the image's own process
is PID 1), no published ports, mounts, devices, privileges or restart
policy, and labels binding it to the lease ID, lease digest and image. The
image's own entrypoint, command and default user run unchanged; that user may
be root inside the gVisor sentry (virtual capabilities of the sentry, none on
the host).

`Create` reports success only after inspecting the container's full
configuration and the kernel's view of its process: `/proc/<pid>/exe` is the
pinned sentry (or runsc), unchanged, and `/proc/<pid>/cgroup` lies below the
slice with `cpu.max`, `memory.max`, `pids.max` and `memory.swap.max` as the
lease requires. Anything else is a miner fault and the lane destroys the
container.

A workload that exits by itself after it started (any exit code, including an
OOM kill within the lease limit), or an image whose start request the engine
rejects while the container never started, is a tenant outcome, not a miner
fault, provided the engine configuration matched and nothing of the sandbox
is left running on the host. The agent logs each such decision as a
`sandbox exit attribution` or `sandbox start attribution` record. An exited
container is never restarted, and it keeps its lease, writable layer and
logs until release or expiry.

`Create` is idempotent per instance name: a container already made for the
same lease document is started if needed and verified again; one made for
any other document is never adopted. `Destroy` removes the container and its
anonymous volumes, waits until it is gone, then removes its image if no other
container uses it; a missing container is success.

## Tenant egress (network mode `public`)

A profile with the `egress` member (`bridge`, `subnet`, `dns`,
`bandwidth_mbit`, `new_conns_per_second`, `deny_cidrs`; per_lease
`network_modes` then `["none", "public"]`) admits public leases and makes the
agent advertise `sandbox-egress-v1`. The member is mandatory (see
[Mandatory sandbox standard](#mandatory-sandbox-standard)). The host creates
the bridge with the subnet's first address before dockerd starts and names it
as the daemon's default `bridge`; the daemon still sets no firewall rule
(`iptables`, `ip-masq`, `ip-forward` false). A public sandbox runs on that
bridge with the profile's resolvers; runsc keeps its netstack
(`--network=sandbox`). A none sandbox is unchanged.

The agent loads `inet mcsbx_sandbox_egress` and `bridge
mcsbx_sandbox_isolation` in one nft transaction at open, and adds two
DOCKER-USER accepts when that chain exists (another Docker daemon's FORWARD
policy is drop). Before every public create, and at most every 30 s, it
re-verifies both. A missing, flushed or edited firewall is loaded again; one
that cannot be makes the miner unhealthy: the agent logs it at error and
every public create fails with the miner fault
`egress_firewall_unavailable`. A later check that finds the firewall in place
(or reloads it) makes public creates succeed again.

Only new outbound IPv4 connections leave the bridge, masqueraded; nothing
inbound is admitted and no port is ever published. The host itself (every
local address and the gateway), RFC 1918, CGNAT, loopback, link-local and
cloud metadata, documentation, benchmarking, multicast and reserved ranges
and `deny_cidrs` are refused, as are TCP 25, 465 and 587; traffic between two
sandboxes is dropped on the bridge. Each sandbox address is policed to
`bandwidth_mbit` up and down and `new_conns_per_second` new connections
(burst twice that).

## Mandatory sandbox standard

All miners must be able to serve sandboxes that meet the subnet's standard;
there is no miner opt-out. With `--sandbox-leases on` the agent refuses to
start (`sandbox host profile does not meet the sandbox standard`) unless the
host profile, besides being valid:

- has the `egress` member (network mode `public`, `sandbox-egress-v1`), and
- restates in `aggregate.image_max_mib` exactly the network-wide tenant
  image cap the agent runs (`sandbox.MaxTenantImageMiB` = 10240; on a testnet
  only, `--sandbox-max-tenant-image-mib` 1024..10240): the cap cannot be chosen
  per miner;
- declares at least the capacity floor (`sandboxhost.CapacityFloor`:
  `cpu_millis` 2000, `memory_mib` 6144, `disk_mib` 20480, `sandboxes` 1),
  strictly above one standard sandbox (1 vCPU, 4096 MiB, 10240 MiB), and
- has `data_fs_mib` >= cap + floor disk + `log_mib` + `engine_overhead_mib` +
  `image_reserve_mib` (`ProfileAggregate.DataFSFloorMiB`; 31760 MiB for the
  10240 cap with log 16 and 512 + 512 overheads).

`scripts/sandbox-host/report.py check-standard PROFILE [IMAGE_CAP_MIB]` runs
the same check before deployment.

## Known limits

- **Network:** `none`, `public` and `allowlist`. An `allowlist` sandbox is a
  public sandbox whose interface gets a MAC in `06:6d:73:00:00:00-ff:ff:ff`
  (24 bits of its lease ID's hash), set at create. A static rule of the
  egress chain refuses such a source every destination not paired with its
  MAC in the set `allow_dsts`, so confinement fails closed: the pairs are
  loaded before the container exists; a reloaded table (empty set), a failed
  rebuild or an unreadable label leaves the sandbox reaching nothing, never
  everything. The pairs are its CIDRs, the IPv4 addresses its hostnames
  resolve to through each profile resolver (union), and the resolvers;
  prefixes are collapsed, IPv6 entries admit nothing (IPv6 is not routed),
  and every refusal of `public` still applies. The agent rebuilds the set on
  every egress check, so hostnames re-resolve each sweep; a failed rebuild
  makes the host unhealthy. A started sandbox whose interface lacks its MAC
  is removed (`egress_firewall_unavailable`). Sandboxes now report ready
  only after network rules are active: before the create returns, the agent
  reads the kernel's `allow_dsts` set and the egress tables, and requires
  the sandbox's MAC paired with every CIDR of its allowlist and every
  resolver, in the tables it loaded (addresses resolved from hostnames are
  not checked: a name may resolve to nothing). A miss (for example a table
  reload that emptied the set) is refilled and checked again for about
  10 s; then the sandbox is removed and the create fails as
  `egress_firewall_unavailable`. This checks the rules once, at create;
  later reloads are refilled by the agent's sweep as before. Matching is by address, so a
  host sharing an address (a CDN) admits its neighbours; a name with no IPv4
  answer admits nothing. `allowlist` with capability `docker` is refused
  (`network_policy_unsupported`). Miners advertise `sandbox-allowlist-v1`.
- **Exited workloads:** a sandbox whose own command exits (or that is
  OOM-killed) stays leased until expiry or release. Without
  `helper_keepalive` the backend adds no init or keepalive process, so only
  images whose default command keeps running are useful; with it the ops
  helper is PID 1 and the sandbox outlives its image command.
- **Disk:** writable layers are quota-limited per container only on an
  XFS project-quota data root (the engine refuses `StorageOpt size`
  otherwise). Images and logs are bounded per sandbox and reserved on the
  data root, but a pull can transiently exceed its allowance before the
  compressed-size stop or the post-pull size check; it cannot outgrow the
  dedicated data-root filesystem. gVisor's `/tmp` is memory-backed.
- **Secrets, inbound access, GPUs, private registries:** not supported.
- **Host network of the sandbox process:** checked per sandbox by
  `pkg/sandboxhost` (`lease.host_netns_lo_only_no_routes`) when the backend
  is opened from a host profile; the container's recorded `NetworkMode` is
  checked either way.
- **Trust:** the miner operator controls the host; gVisor isolates the host
  from customer code, not customer code from the operator.

## Disposable-host tests

`TestGVisorLaneOnDisposableHost` and
`TestEnginePullOversizedRegistryErrorOnDisposableHost` (skipped unless
`MC_SANDBOX_BACKEND_IT=1`) drive the real lane against a real host: reserve,
commit (real pull and gVisor container), idempotent re-create, release, a
workload that exits by itself, and restart recovery. They need a provisioned
dedicated daemon, runsc registration, slice and an XFS project-quota data
root of at least 5.2 GiB, described by `MC_SANDBOX_DOCKER_HOST`,
`MC_SANDBOX_RUNTIME`, `MC_SANDBOX_RUNSC_PATH`, `MC_SANDBOX_RUNSC_SHA256`,
`MC_SANDBOX_SENTRY_PATH`, `MC_SANDBOX_SENTRY_SHA256`, `MC_SANDBOX_DATA_ROOT`,
`MC_SANDBOX_SLICE` and `MC_SANDBOX_DEPLOYMENT_CGROUP`, and network access to
`registry.k8s.io`. Run them only on an explicitly disposable host, never on a
miner.
