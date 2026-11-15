# Docker leases (sandbox-docker-v1)

A lease with `"capabilities": ["docker"]` runs a sandbox in which the tenant
can run its own Docker engine (`docker run`, `docker compose`). It is still a
gVisor sandbox: the nested engine, its containers and their networks all live
inside the sentry's virtual kernel. The capability changes what the guest
may do inside that boundary. It does not move the boundary.

## Protocol

- `SandboxLeaseV1.capabilities` (`pkg/protocol`), JSON `capabilities`: a
  sorted, unique list of known capabilities. The only one is `docker`
  (`sandbox.CapabilityDocker`). The member is omitted when empty, so a lease
  without capabilities has the same canonical bytes and digest as before.
  A miner that predates the member refuses such a lease as an unknown field,
  so docker leases go only to miners that advertise `sandbox-docker-v1`
  (`sandbox.DockerCapabilityFeature`).
- A miner that cannot provide a capability refuses the lease with
  `capability_unsupported` (`sandbox.CapabilityUnsupported`). This refusal
  is not a miner fault.

## Host profile

The profile's optional `docker` member (`sandboxhost.ProfileDocker`) turns on
the capability:

```json
"docker": {"runtime": "runsc-docker",
           "args": ["--systemd-cgroup", "--overlay2=none", "--net-raw", "--allow-packet-socket-write"],
           "volume_tmpfs_mib": 4096}
```

`runtime` names a second registration of the profile's pinned runsc binary in
the sandbox engine's `daemon.json` (the [installer](miner-installer.md)
registers `runsc-docker`). Its arguments must be exactly
`sandboxhost.DockerRuntimeArgs`. When the backend opens, it checks the
daemon's registration against the member and refuses to start if they differ.
Without the member, every docker lease is refused and nothing else changes.
Other leases keep the base `runsc` runtime, Docker's default capability set (a
strict subset of the docker set) and their existing create requests.

## What a docker lease gets

- The runtime is `runsc-docker`, which is runsc with `--net-raw` and
  `--allow-packet-socket-write`. dockerd 28 needs both for its bridge
  networking.
- It gets 17 capabilities: AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER, FSETID,
  KILL, MKNOD, NET_ADMIN, NET_BIND_SERVICE, NET_RAW, SETFCAP, SETGID, SETPCAP,
  SETUID, SYS_ADMIN, SYS_CHROOT, SYS_PTRACE. These exist only in the sentry,
  and the sandbox process holds none of them on the host. `Privileged` stays
  false, `no-new-privileges` stays set and the drop list is still `ALL`.
  A nested `docker run --privileged` is privileged only inside the sentry.
- Each volume the image declares (at most 8, and none under `/proc`, `/sys`,
  `/dev`, `/etc` or the ops helper path) is covered by a backend-created
  tmpfs. Its size is `min(volume_tmpfs_mib, lease memory)`. tmpfs is sentry
  memory, so the nested engine's storage counts against the lease's memory
  limit. No engine volume or host storage is ever created. The readback
  refuses any other mount.
- The pids, memory and CPU limits and the egress firewall are the same as for
  any other lease. Nested containers are processes in the same sentry, so
  they count against the same limits.

## Port binding table (anti-spoof)

Because packet sockets can be written, the guest can put any Ethernet frame on
the egress bridge. Examples are an ARP reply claiming another sandbox's
address, or IPv4 from a foreign source. On a host with the docker member and
egress, the backend therefore keeps the nft bridge table
`mcsbx_sandbox_antispoof` (`sandboxhost.ApplyTenantBindings`). From a port of
the egress bridge it admits only IPv4 and ARP whose (port, Ethernet source,
IPv4 or ARP sender) is bound to the live sandbox on that port. It drops
everything else, counted in counter `spoofed`. A port without a binding
passes nothing.

The backend rebuilds the table from the engine's live sandboxes in one nft
transaction at these points:

- on every egress check, including the check before every public create;
- after a public sandbox starts, before Create returns;
- after every Destroy.

If the table cannot be loaded, or the new sandbox's own port cannot be
resolved, the create fails as `egress_firewall_unavailable` (a miner fault)
and the sandbox is torn down. Another sandbox whose port cannot be resolved,
such as one that is stopping, stays unbound and logged. It does not make
the host unhealthy. A failed load at Destroy returns an error.

Only containers carrying the sandbox label are bound. Any other container
attached to the egress bridge of a docker host passes nothing.

## Image

Tenants use the subnet's dind image: `docker:28.3.3-dind` pinned by digest,
with the entrypoint replaced by `ms-gvisor-dockerd.sh`. The stock entrypoint
cannot run under gVisor, because dockerd's bridge driver installs iptables
matches the sentry refuses. The wrapper therefore:

- keeps `/var/lib/docker` on tmpfs;
- turns on IPv4 forwarding;
- source-NATs TCP and UDP from nested containers to the sandbox's own
  address, which is the only address the bridge admits from it;
- starts dockerd with `--iptables=false --ip6tables=false`, the interface
  MTU, and only its unix socket (no TCP listener, no TLS material).

Miners do not build or configure this image.

## Host test

`pkg/sandboxbackend/docker_host_test.go` (gated by `MC_SANDBOX_DIND_IT=1`,
disposable host only) checks the runtime registration, the backend's create
request on the real engine, and the port binding table.
