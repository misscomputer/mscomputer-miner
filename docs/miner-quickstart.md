# Miner quickstart

This guide takes a Linux server from a fresh install to a miner that
validators can discover, assign work to, and verify. Read
[getting-started.md](getting-started.md) first for installation and
[keys-and-secrets.md](keys-and-secrets.md) for key handling.

## How a miner works

A miner is **two local processes** on one host:

```text
        internet (validators, public edge)
                     │  HTTPS, self-signed leaf pinned by fingerprint
                     ▼
  mscomputer-miner  (Python axon, default 0.0.0.0:8091)
    - btauth/1 signatures, explicit operator allowlist, metagraph permit + stake
    - hotkey-signs the Go service key binding
                     │  HMAC-signed loopback bridge (shared bridge secret)
                     ▼
  miner-agent        (Go, default 127.0.0.1:9101)
    - verifies deployment.v4 tickets, fetches + re-hashes OCI artifacts
    - runs them in Docker under the small-v1 profile on an isolated network
    - signs receipts and attestations with its Ed25519 service key
```

1. You register a hotkey on the subnet and enroll your **numeric public IP
   and axon port** with a signed endpoint enrollment
   ([miner-endpoint-enrollment.md](miner-endpoint-enrollment.md)). Nothing is
   published on chain.
2. Validators connect to the enrolled address, capture your TLS leaf certificate, and send
   a signed capability request. Your axon answers with a hotkey-signed binding
   that includes the certificate's SHA-256 pin and the Go agent's service key.
   Only miners whose agent advertises `organic-oci-v1` receive assignments.
3. A validator sends a signed `deployment.v4` ticket. The agent verifies it,
   downloads the named artifact from the artifact store, re-hashes every
   blob, loads it into Docker, runs it, checks its health, and returns a
   signed receipt.
4. App traffic arrives through the public edge at
   `https://<your-ip>:<port>/runtime/<endpoint_id>/...`. Keep assigned
   endpoints available.

Protocol detail: [protocol.md](protocol.md). Runtime detail:
[miner-oci-runtime.md](miner-oci-runtime.md).

## Local versus live

| Step | Local only | Live network |
| --- | --- | --- |
| Install, build, unit tests | ✔ | |
| Mock-mode axon smoke test ([getting-started](getting-started.md#local-smoke-test-mock-mode-miner)) | ✔ | |
| TLS certificate generation | ✔ (writes files only) | |
| Hotkey registration | | ✔ transaction, costs TAO |
| Go agent + Python axon with TLS | | ✔ reads the chain, serves the internet |
| Endpoint enrollment (`mscomputer-miner endpoint-enroll`) | | ✔ signed HTTPS request, no transaction |

A full end-to-end assignment needs live validators, the operator's artifact
store, and the public edge; it cannot be reproduced from this repository
alone.

## Prerequisites

- Everything in [getting-started.md](getting-started.md#prerequisites), with
  Python 3.12, Go 1.23, and the Go agent built at `build/miner-agent`.
- **Docker Engine** able to run `linux/amd64` images, with enough disk for
  loaded images and per-replica state.
- **`iptables`** and root (or equivalent `CAP_NET_ADMIN` plus Docker access)
  for the Go agent, which creates an internal Docker network and installs a
  host firewall rule at startup.
- A **static, public, numeric IPv4 or IPv6 address**. Validators reject
  hostnames and private, loopback, or other special-purpose addresses for
  live axons.
- **Inbound TCP 8091 and 8094.** Validators connect directly to your public
  IP: the axon on 8091 and direct files on 8094. Do **not** expose the Go
  agent port.
- A **registered hotkey** on the subnet (below).
- **Artifact store access: nothing to request.** Live assignments name
  content-addressed artifacts in the subnet operator's store. Miners read them
  through the operator's pull gateway, `https://api.ms.computer/v1/miner-artifacts`
  (`--artifact-backend pull`). The agent signs each read with its service key;
  the gateway accepts it while your hotkey is registered and its service
  binding is live (recorded at a successful capability handshake with your
  axon). There are no storage credentials to obtain, store or rotate.
  Access lapses on its own after deregistration, once the last service
  binding expires (at most 6 hours). The host needs
  outbound HTTPS to `api.ms.computer` and to the object store the gateway
  redirects each read to (a short-lived https object URL); allow outbound
  TCP 443.

Each running replica uses the fixed `small-v1` profile: 1 CPU, 1024 MiB
memory (no swap), 256 PIDs, read-only root filesystem with a 64 MiB `/tmp`.
Size the host for the number of replicas you want to carry. The agent caps
the replicas with its app budget (default 5 GiB, 20 replicas, on a 16 GiB
host; see [miner-oci-runtime.md](miner-oci-runtime.md#app-budget)). Static
sites need disk for their cache (`--static-cache-max-bytes`, default 8 GiB;
at least 256 MiB). A sandbox miner needs a larger host; see the next
section.

## Sandbox miners: requirements

SN24 miners serve three kinds of work: static sites (`static-site-v1`),
dynamic apps (`organic-oci-v1`) and sandboxes (`sandbox-lease-v1`). The steps
below start a static/dynamic miner. A sandbox miner needs the extra pieces in
this section.

**Sizes at a glance.** Three different numbers apply; do not mix them up.

| What | Size | Notes |
|------|------|-------|
| Customer sandbox (fixed; the only size) | 1 vCPU, 4 GiB RAM (4096 MiB), 10 GiB disk (10240 MiB) | The public API refuses any other `resources` (`UNSUPPORTED_RESOURCES`). |
| Minimum a sandbox miner must declare (`aggregate` in the host profile) | 2 vCPU (`cpu_millis` 2000), 6 GiB (`memory_mib` 6144), 20 GiB (`disk_mib` 20480), `sandboxes` 1 | `pkg/sandboxhost` `CapacityFloor*`. One 4 GiB sandbox plus its overhead (about 60 MiB of gVisor per sandbox) fits in the 6 GiB lease group; the group (`mcsbxlease.slice`) is capped at that 6 GiB. Host overhead (about 1.1 GiB) is outside the group. |
| Recommended host | 4 vCPU, 16 GiB RAM, about 100 GiB free disk | What a miner serving all three kinds of work needs in practice; see below. The installer refuses less than 4 vCPU or 15360 MiB `MemTotal`. |

Further hard requirements of the declared profile:

| Item | Minimum |
|------|---------|
| Sandbox data filesystem (`data_fs_mib`) | 31760 MiB with the reference overheads (more with more sandboxes); the installer uses 32768 |
| `image_max_mib` | exactly 10240 (the network-wide tenant image cap) |

The agent refuses (exits at sandbox lane start) a profile below these. A
miner that declares exactly one standard sandbox (1 vCPU, 4 GiB, 10 GiB) is
below the floor.

The declared floor is not the host size. Why the host needs 4 vCPU / 16 GiB:

- **Headroom.** The host needs headroom beyond the declared aggregate.
- **Host overheads.** About 1.1 GiB of host overhead was measured beside the
  sandbox (OS, the dedicated containerd/dockerd, the agent and the axon). The
  installer sizes the engine slice at 1536 MiB, and the agent keeps
  `--system-reserve-mib` 1536 for the system.
- **Other work.** The app budget (`--app-budget-mib` 5120 on a 16 GiB host)
  and the static site cache (`--static-cache-max-bytes`, default 8 GiB on disk)
  come on top.
- **Disk.** You need the sandbox data filesystem (32 GiB), the 8 GiB static
  cache, app images in the organic Docker daemon, and room for the OS. About 100 GiB free is
  enough.

A reference host is 4 vCPU, 16 GiB RAM and a 150 GiB disk, with
`--system-reserve-mib 1536 --sandbox-reserve-mib 6144 --app-budget-mib 5120`.
Keep network latency to the internet low and stable.

**Host provisioning.** Sandboxes run under gVisor (`runsc`) in a dedicated
containerd/dockerd, with a quota-enforced data filesystem, an egress bridge
and finite cgroup slices, all described by a `sandbox-host-profile.v1` file
(see [miner-sandbox-gvisor-backend.md](miner-sandbox-gvisor-backend.md)).
Check a profile with
`python3 scripts/sandbox-host/report.py check-standard PROFILE`.
Use the supported installer,
[`scripts/miner-install/install.sh`](miner-installer.md) (Ubuntu 24.04).
It installs and configures the pinned dedicated containerd/dockerd with
runsc, the data filesystem, the slices, the egress tables and bridge, and the
profile. It also installs the agent and axon units with every flag below, and
ends with a self-test.

**Extra flags for a sandbox miner** (on top of Steps 5 and 6):

```bash
# miner-agent
--qualification on --qualification-plot-dir /var/lib/mscomputer-miner/qplot \
--sandbox-leases on --sandbox-ops on \
--sandbox-host-profile /path/profile.json --sandbox-daemon-config /path/daemon.json \
--sandbox-ops-config /path/ops-config.json --sandbox-deployment-cgroup /mcsbxdeploy.slice \
--direct-files-bind 0.0.0.0:8094 --direct-files-tls-cert ... --direct-files-tls-key ... \
--direct-files-per-sandbox 4 \
--response-receipts on
# mscomputer-miner (axon)
--qualification on --qualification-plots on --sandbox-leases on --sandbox-ops on
```

Run with `--response-receipts on`; it is required.

**After registration.** These steps are automatic once the miner is
reachable:

1. Register the hotkey (Step 2) and enroll the endpoint (Step 7).
2. Validators make a signed capability handshake with your axon. A failed handshake is not visible on
   your side, so use Step 8 to check reachability from outside.

Keep the agent running and up to date. Restarting it ends every sandbox it holds.

## Step 1: set your variables

Every later command uses these. The Go agent runs as root, so the simplest
path is to work through Steps 3 to 8 in one root shell (`sudo -i`) and set the
variables there; `sudo` prefixes in the examples are then harmless. Replace
each placeholder:

```bash
export MC_NETWORK=finney                 # SDK network name: finney (mainnet) or test
export MC_NETUID=24                      # SN24 on finney
export MC_WALLET='<wallet-name>'
export MC_HOTKEY='<hotkey-name>'
export MC_OPERATOR_HOTKEY_SS58='<operator-hotkey-ss58>'  # SN24: the value in scripts/miner-install/miner.env.example
export MC_HOTKEY_SS58='<hotkey-ss58-address>'
export MC_PUBLIC_IP='<public-numeric-ip>'
export MC_AXON_PORT=8091
export MC_REPO=/path/to/mscomputer-miner   # clone checked out at a release tag
```

`MC_UID` is added in Step 2 after registration.

## Step 2: register the hotkey (live transaction)

Registration spends TAO from the coldkey. Run it where the coldkey lives
(checked against `btcli` 9.23; confirm with `btcli subnets register --help`):

```bash
btcli subnets register --netuid "$MC_NETUID" --network "$MC_NETWORK" \
  --wallet-name "$MC_WALLET" --hotkey "$MC_HOTKEY"
```

Then read your UID back with the
[read-only chain check](getting-started.md#read-only-chain-check), or with
`btcli subnets show --netuid "$MC_NETUID" --network "$MC_NETWORK"`, and set:

```bash
export MC_UID='<your-uid>'
```

Copy only the hotkey to the server as described in
[keys-and-secrets.md](keys-and-secrets.md#wallet-creation-trusted-workstation).

## Step 3: create directories and the bridge secret

The Go agent needs root for Docker and `iptables`. The example below runs both
processes as root for simplicity; if you run the Python axon as a separate
unprivileged user, make that user own the TLS directory, the bridge secret,
and the axon's state database (root can still read the secret).

```bash
sudo install -d -m 0700 /etc/mscomputer-miner /var/lib/mscomputer-miner \
  /var/lib/mscomputer-miner/oci
sudo sh -c 'umask 077; openssl rand -hex 32 > /etc/mscomputer-miner/bridge.secret'
```

The secret must be at least 32 bytes after trimming whitespace; both processes
must read the **same** file.

## Step 4: issue the TLS certificate

The axon serves a self-signed, non-CA leaf certificate whose only identity is
your numeric IP. Validators pin its SHA-256 fingerprint. Use the bundled
script; it refuses to write inside the repository, requires an absolute root,
and never prints private material:

```bash
sudo "$MC_REPO/scripts/manage-miner-tls.sh" issue /etc/mscomputer-miner/tls "$MC_PUBLIC_IP" 90
```

`DAYS` is optional (default 30, maximum 825). Expected output:

```text
miner TLS issue complete
certificate: /etc/mscomputer-miner/tls/current/miner.crt
private key: /etc/mscomputer-miner/tls/current/miner.key
leaf sha256: <64 lowercase hex characters>
notBefore=...
notAfter=...
restart the miner and require a fresh validator capability handshake
```

Save the pin; the Go agent needs it:

```bash
export MC_TLS_SHA256='<leaf-sha256-from-the-output>'
```

You can print it again at any time with
`sudo "$MC_REPO/scripts/manage-miner-tls.sh" check /etc/mscomputer-miner/tls`.

## Step 5: start the Go agent

Start the agent as root. Artifacts come through the operator's pull gateway,
so no storage credential is needed:

```bash
"$MC_REPO/build/miner-agent" \
  --network "$MC_NETWORK" \
  --netuid "$MC_NETUID" \
  --hotkey "$MC_HOTKEY_SS58" \
  --uid "$MC_UID" \
  --bridge-secret-file /etc/mscomputer-miner/bridge.secret \
  --service-key-file /var/lib/mscomputer-miner/agent-service.key \
  --state-db /var/lib/mscomputer-miner/agent-state.sqlite \
  --docker-state-dir /var/lib/mscomputer-miner/oci \
  --artifact-backend pull \
  --artifact-pull-url https://api.ms.computer/v1/miner-artifacts \
  --tls-certificate-sha256 "$MC_TLS_SHA256"
```

On startup the agent validates its flags, creates the service key if it is
missing (mode `0600`), opens its state database, creates or validates the
internal Docker network `mscomputer-organic` (host interface
`ms-organic0`), installs the host isolation rule if missing, and cleans up
any replicas left from a previous run. Then it logs:

```text
... INFO miner agent ready bind=127.0.0.1:9101 network=<network> netuid=<netuid> hotkey=<ss58>
```

Health (no authentication needed):

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9101/healthz   # 204
sudo iptables -C INPUT -i ms-organic0 -m conntrack --ctstate NEW -j DROP && echo rule-present
docker network inspect mscomputer-organic --format '{{.Internal}}'      # true
```

The agent only advertises `organic-oci-v1` (and so only becomes eligible for
assignments) when the network and host rule checks pass; otherwise it exits
with an error.

## Step 6: start the Python axon

The agent keeps running in the foreground, so use a second root shell (and set
the Step 1 variables there too), or run both under a supervisor as shown in
[Running as services](#running-as-services-example).

```bash
. "$MC_REPO/.venv/bin/activate"

mscomputer-miner \
  --netuid "$MC_NETUID" \
  --subtensor-network "$MC_NETWORK" \
  --wallet-name "$MC_WALLET" \
  --wallet-hotkey "$MC_HOTKEY" \
  --operator-hotkey "$MC_OPERATOR_HOTKEY_SS58" \
  --uid "$MC_UID" \
  --axon-port "$MC_AXON_PORT" \
  --tls-cert-file /etc/mscomputer-miner/tls/current/miner.crt \
  --tls-key-file /etc/mscomputer-miner/tls/current/miner.key \
  --bridge-secret-file /etc/mscomputer-miner/bridge.secret \
  --state-db /var/lib/mscomputer-miner/axon-nonces.sqlite
```

Healthy JSON log lines on stderr include, every `--sync-interval` seconds:

```text
{"timestamp":"...","level":"info","logger":"mscomputer_subnet.miner","message":"metagraph synchronized","hotkey":"<ss58>","block":<n>}
```

Health, from the host:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' "https://127.0.0.1:$MC_AXON_PORT/healthz"   # 204
```

`/healthz` returns `204` once the hotkey is uniquely registered in the
metagraph with the expected UID, and `503` before that. Validators reach a
uniquely registered miner at its enrolled endpoint (Step 7), even when its
weight-update `active` flag is false. Check membership and UID with the
[read-only chain check](getting-started.md#read-only-chain-check)
if the miner never becomes ready. `-k` is needed because the
certificate is self-signed; validators pin it instead.

## Step 7: endpoint enrollment

The miner never publishes an axon on chain (`--axon-publish` accepts only
`off`). Validators learn your address from a signed endpoint
enrollment instead: `mscomputer-miner endpoint-enroll` posts a hotkey-signed
enrollment of your UID, public IP and axon port to
`https://api.ms.computer/v1/miner-endpoint`. Each enrollment is valid for
24 hours; renew it about every 6 hours. The installer sets this up with two
timers: `mscomputer-miner-endpoint-enroll-first.timer` enrolls within about
2 minutes of `enable` and of every boot, and
`mscomputer-miner-endpoint-enroll.timer` renews every 6 hours; for a manual setup, see
[miner-endpoint-enrollment.md](miner-endpoint-enrollment.md). Check it with
`journalctl -u mscomputer-miner-endpoint-enroll`.

After the miner is enrolled and serving, qualification takes about 4 hours
before the miner can earn.

## Step 8: verify from outside

From another machine:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' "https://$MC_PUBLIC_IP:$MC_AXON_PORT/healthz"   # 204

openssl s_client -connect "$MC_PUBLIC_IP:$MC_AXON_PORT" </dev/null 2>/dev/null \
  | openssl x509 -outform DER | openssl dgst -sha256 -r | awk '{print $1}'
# must equal $MC_TLS_SHA256
```

Then re-run the [read-only chain check](getting-started.md#read-only-chain-check)
and confirm your UID and hotkey, and check that the latest enrollment run
succeeded (`journalctl -u mscomputer-miner-endpoint-enroll -n 20`).

Once validators discover you, the axon's access log shows signed
`POST /api/v1/capabilities` requests answered `200`, followed later by
`/api/v1/deploy`, `/api/v1/status`, and `/runtime/...` traffic. Requests from
callers not explicitly configured with `--operator-hotkey`, without a validator
permit, or below `--min-validator-stake` are answered `403`. An unset/empty
operator list denies all signed control requests, including capability discovery;
health checks can still report ready. Configure the SN24 operator hotkey
explicitly (Step 1); stake alone never adds an operator.

## Values that must match

The two processes check each other on every capability request. A mismatch
makes validators see `500 local Go identity is misconfigured`.

| Setting | Python axon | Go agent |
| --- | --- | --- |
| Network name | `--subtensor-network` | `--network` (exactly the same string) |
| Netuid | `--netuid` | `--netuid` |
| Hotkey | wallet selected by `--wallet-*` | `--hotkey` (its SS58 address) |
| UID | from the metagraph (or `--uid`) | `--uid` (must be set to the same UID) |
| Transport pin | fingerprint of `--tls-cert-file` | `--tls-certificate-sha256` |
| Bridge | `--go-agent-url` (default `http://127.0.0.1:9101`) | `--bind` (default `127.0.0.1:9101`) |
| Bridge secret | `--bridge-secret-file` | `--bridge-secret-file` |

## Configuration reference

### `mscomputer-miner`

| Flag | Default | Notes |
| --- | --- | --- |
| `--netuid` | required | |
| `--subtensor-network` | `$BT_NETWORK` or `finney` | |
| `--wallet-name` / `--wallet-hotkey` | `$BT_WALLET` / `$BT_WALLET_HOTKEY`, else `default` | Hotkey only is loaded |
| `--wallet-path` | `$BT_WALLET_PATH` or `~/.bittensor/wallets` | |
| `--uid` | learned from metagraph | If set and different from the metagraph, the miner stays unready |
| `--axon-host` / `--axon-port` | `0.0.0.0` / `8091` | Public HTTPS listener |
| `--tls-cert-file` / `--tls-key-file` | required for live | Regular non-symlink files; key must not be group/world accessible |
| `--go-agent-url` | `http://127.0.0.1:9101` | |
| `--bridge-secret-file` | required | ≥ 32 bytes |
| `--state-db` | required | SQLite nonce/replay store |
| `--operator-hotkey` (repeatable) | `$MC_OPERATOR_HOTKEYS` (comma-separated) or empty | Explicit caller allowlist; CLI replaces env; empty denies all |
| `--min-validator-stake` | `1000.0` | Minimum caller TAO stake (validators also need a permit) |
| `--sync-interval` | `12.0` seconds | Metagraph refresh |
| `--max-concurrency` | `4` | Concurrent deploys; highest-stake callers go first |
| `--qualification-jobs-per-hour` | `4` | Admission limit per caller; keep the default |
| `--log-level` | `INFO` | |
| `--allow-insecure-mock-http`, `--mock-uri`, `--mock-peers`, `--mock-capability-fault-file` | off | Local mock only; refused without `--mock-uri` |

### `miner-agent`

| Flag | Default | Notes |
| --- | --- | --- |
| `--bind` | `127.0.0.1:9101` | Loopback only unless `--allow-non-loopback` (unsafe) |
| `--network` / `--netuid` / `--hotkey` / `--uid` | `local` / `0` / required / `-1` | Must match the axon; set `--network` and `--uid` explicitly |
| `--bridge-secret-file` | none | Falls back to env `MS_BRIDGE_SECRET` (`--bridge-secret-env`) |
| `--service-key-file` | required | Created with mode `0600` if missing |
| `--state-db` | required | SQLite assignment/receipt/replay state; use a different file from the axon's |
| `--artifact-backend` | `file` | `pull` for live mining (with `--artifact-pull-url`); `file` (with `--artifact-dir`) for local tests |
| `--artifact-pull-url` | none | `https://api.ms.computer/v1/miner-artifacts` on SN24. Each read is signed with the service key (`--service-key-file`) and answered with a short-lived object URL; see "Artifact pull gateway" below |
| `--artifact-pull-redirect-suffix` | none | Optional: follow gateway redirects only to hosts ending in this suffix (any https host otherwise; bytes are digest-verified either way) |
| `--image-registry-login-url` | none | `https://mirror.ms.computer/v1/mirror-login` on SN24. Sandbox image pulls from that host carry a short-lived credential obtained with a service-key-signed login; see "Image mirror login" below |
| `--runtime` | `docker` | Only supported value |
| `--docker-state-dir` | `<tmp>/mscomputer-oci` | Set it to a persistent directory |
| `--organic-network` / `--organic-bridge` | `mscomputer-organic` / `ms-organic0` | Bridge name at most 15 characters |
| `--host-isolation` | `enforce` | `enforce` installs the iptables rule if missing; `verify` only checks |
| `--miner-transport` | `https` | `http` only with `--allow-insecure-mock-http` on a `local`/`mock` network |
| `--tls-certificate-sha256` | required for `https` | Lowercase hex pin of the axon's leaf |
| `--direct-files-bind` | none | Sandbox miners: required; e.g. `0.0.0.0:8094`; needs `--sandbox-ops on` |
| `--direct-files-tls-cert` / `--direct-files-tls-key` | none | The axon's own certificate and key files; the leaf must equal `--tls-certificate-sha256` |
| `--direct-files-per-sandbox` / `--direct-files-global` | `4` / `8` | Direct transfers in flight; keep the defaults |

**Sandbox miners: direct files.** Every sandbox miner must serve direct file
transfers (`sandbox-direct-files-v1`).
Add to the agent:

```bash
  --direct-files-bind 0.0.0.0:8094 \
  --direct-files-tls-cert /etc/mscomputer-miner/tls/current/miner.crt \
  --direct-files-tls-key /etc/mscomputer-miner/tls/current/miner.key
```

and allow inbound connections on TCP 8094. There is no opt-out. After a certificate rotation the
agent must be restarted with the new pin, like the axon.

### Artifact pull gateway

With `--artifact-backend pull` the agent sends
`GET <pull-url>/<exact key>` with `X-MS-Miner-Hotkey`, `X-MS-Miner-Timestamp`,
`X-MS-Miner-Nonce` and an Ed25519 `X-MS-Miner-Signature` by its service key
over `mscomputer-miner-artifact-pull-v1`, network, netuid, hotkey, key,
timestamp and nonce (newline-joined). The gateway answers `307` to a
presigned object URL valid for a few minutes, which the agent fetches without
forwarding those headers. The agent still re-hashes every byte against the
signed ticket digest, so the gateway and store cannot change what is served.

### Image mirror login

Sandbox leases name their image on the operator's image mirror. With
`--image-registry-login-url` the agent logs in before such a pull, so the
mirror admits the miner from whatever address it egresses from
(even a different one than it serves on): `POST <login-url>` with no body and the headers
`X-MS-Miner-Hotkey`, `X-MS-Miner-Timestamp`, `X-MS-Miner-Nonce`,
`X-MS-Mirror-Scope` (`pool`, or `lease` with `X-MS-Lease-Id` and
`X-MS-Lease-Signature`: the lease's sandbox id and signature) and an Ed25519
`X-MS-Miner-Signature` by the service key over
`mscomputer-image-mirror-login-v1`, network, netuid, hotkey, scope, lease id,
lease signature, timestamp and nonce (newline-joined; lease fields empty for
`pool`). The answer is a registry login the agent passes to the sandbox
daemon for that one pull (`X-Registry-Auth`); it is never written to disk.
Public images use a `pool` login, reused until shortly before it expires
(about an hour). A private image needs a `lease` login for the lease being
created; it admits only that image and only while the lease is live.

No axon is needed for mirror access: the mirror admits the addresses of
miners enrolled at `https://api.ms.computer/v1/miner-endpoint`
([miner-endpoint-enrollment.md](miner-endpoint-enrollment.md)).

Only the login URL's host ever receives the credential. If a login fails, the
agent logs a warning and pulls without one. `403` means the hotkey is not
registered on the subnet (or, for `lease`, the lease is not this miner's live
lease); `401` has the same causes as for the artifact gateway below.

`401` means the gateway does not (yet) see a live binding of this service key
for your hotkey: check that the axon and agent are up, that the agent uses the
same `--service-key-file` as when it registered, and that the clock is within
two minutes (use NTP). `404` means the artifact is not in the store.

The `file` backend reads artifacts from a local directory with the layout in
[protocol.md](protocol.md#artifact-layout); it is useful for tests and local
development, not for receiving live assignments.

## Running as services (example)

Any supervisor works. A minimal systemd sketch; replace every placeholder and
adjust paths before enabling it. The pull backend needs no secrets in the
environment:

```ini
# /etc/systemd/system/mscomputer-miner-agent.service
[Unit]
Description=Ms. Computer miner Go agent
After=docker.service network-online.target
Requires=docker.service

[Service]
EnvironmentFile=/etc/mscomputer-miner/agent.env
ExecStart=/path/to/mscomputer-miner/build/miner-agent --network finney --netuid <NETUID> --hotkey <hotkey-ss58> --uid <uid> --bridge-secret-file /etc/mscomputer-miner/bridge.secret --service-key-file /var/lib/mscomputer-miner/agent-service.key --state-db /var/lib/mscomputer-miner/agent-state.sqlite --docker-state-dir /var/lib/mscomputer-miner/oci --artifact-backend pull --artifact-pull-url https://api.ms.computer/v1/miner-artifacts --tls-certificate-sha256 <leaf-sha256>
Restart=on-failure
TimeoutStopSec=120

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/mscomputer-miner.service
[Unit]
Description=Ms. Computer miner axon
After=mscomputer-miner-agent.service
Requires=mscomputer-miner-agent.service

[Service]
ExecStart=/path/to/mscomputer-miner/.venv/bin/mscomputer-miner --netuid <NETUID> --subtensor-network finney --wallet-name <wallet-name> --wallet-hotkey <hotkey-name> --operator-hotkey <operator-hotkey-ss58> --uid <uid> --tls-cert-file /etc/mscomputer-miner/tls/current/miner.crt --tls-key-file /etc/mscomputer-miner/tls/current/miner.key --bridge-secret-file /etc/mscomputer-miner/bridge.secret --state-db /var/lib/mscomputer-miner/axon-nonces.sqlite
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

**Stop timeout.** On SIGTERM the agent stops in phases with fixed budgets:
up to 15 seconds to finish in-flight API requests (the sandbox lane closes during the same
window), then up to 30 seconds to clean up replicas, then, with
`--sandbox-leases on`, up to 60 seconds to destroy sandboxes. That is at most
105 seconds. Give the supervisor a stop timeout of at least 120 seconds
(`TimeoutStopSec=120` above; for Docker or Compose, `--stop-timeout` or
`stop_grace_period`). A shorter timeout kills the agent mid-cleanup; the
next start cleans up what it left.

Logs: `journalctl -u mscomputer-miner-agent -f` and
`journalctl -u mscomputer-miner -f`.

## Day-2 operations

**Certificate rotation.** Rotate before expiry (the `check` action fails when
the certificate expires within `WARN_BEFORE_SECONDS`, default one week):

```bash
sudo "$MC_REPO/scripts/manage-miner-tls.sh" rotate /etc/mscomputer-miner/tls "$MC_PUBLIC_IP" 90
```

Update the Go agent's `--tls-certificate-sha256` to the new `leaf sha256`,
then restart the agent and the axon. `rollback` swaps back to the previous
release (update the pin again). Validators pick up the new pin on their next
capability handshake.

Every assignment ticket is bound to the certificate pin that was current when
it was issued, and the agent refuses status, deactivation, and runtime traffic
for a ticket whose pin differs from its own. Combined with the agent restart
below, a rotation therefore ends all current assignments: rotate well before
expiry, in a planned window, and not more often than needed.

**IP change.** Issue a certificate for the new IP (`rotate`), update the pin,
restart both processes, and enroll again (`systemctl start mscomputer-miner-endpoint-enroll`
on installer hosts) so validators dial the new IP.

**Re-registration or UID change.** Update `--uid` on both processes and
restart.

**Restarts and upgrades.** Stop the axon, then the agent. Restarting the agent
is disruptive: on shutdown, and again on the next start, it deactivates every
replica it was running (removing the containers) before it accepts new
assignments, so keep agent restarts rare and planned. The axon can be
restarted on its own without touching replicas. Keep the service key, both
state databases, and the TLS directory across upgrades. On an installer
host, upgrade by running `install.sh install` with `MC_INSTALL_REF=<release
tag or commit>` and `MC_INSTALL_AGENT_SHA256=<matching agent digest>`, then
`install.sh enable`; the installer builds that ref from a clean clone, not
your checkout (see
[miner-installer.md](miner-installer.md#upgrades-and-restarts)). On a
hand-built host, check out the new release tag (see
[verify-release.md](verify-release.md)), reinstall (`python -m pip install -e .`)
and rebuild (`go build -o build/miner-agent ./cmd/miner-agent`).

**Logs.** The axon writes JSON lines with `timestamp`, `level`, `logger`,
`message`, and fields such as `hotkey`, `block`, `endpoint_id`, and
`request_id`; request bodies and credentials are never logged. The agent uses
Go's structured text logger on stderr.

Problems: see [troubleshooting.md](troubleshooting.md).
