# Sandbox miner installer

`scripts/miner-install/install.sh` sets up an SN24 sandbox miner host on
Ubuntu 24.04 (x86_64), the only supported release (22.04 is refused, see
below). Run it as root from a clone of this repository. It builds the miner
software at the release tag pinned in `install.sh` (`PINNED_REF`), or at
`MC_INSTALL_REF` (a release tag or a commit) when set, from a clean clone; what you have checked out
does not choose the build. Running it again converges the host and changes nothing that is
already right.

```bash
git clone https://github.com/misscomputer/mscomputer-miner && cd mscomputer-miner
sudo scripts/miner-install/install.sh preflight   # read-only
sudo scripts/miner-install/install.sh install     # idempotent
sudo scripts/miner-install/install.sh self-test
# register the hotkey, fill in the operator files (below), then
sudo scripts/miner-install/install.sh enable   # serves directly, enrolls the endpoint
```

## Host requirements

| | Preflight fails below | Recommended |
|---|---|---|
| vCPU | 4 | 4 |
| RAM (`MemTotal`) | 15360 MiB (~15 GiB) | 16 GiB |
| Free disk under `/var/lib` | sandbox data filesystem (32768 MiB) + 8 GiB | 100 GiB |
| OS | Ubuntu 24.04, systemd, cgroup v2 unified, kernel 5.15 or newer, not a container | |

The declared sandbox aggregate is only 2 vCPU / 6144 MiB, but the host needs
headroom beyond the declared aggregate, so preflight fails below 4 vCPU or 15360 MiB `MemTotal`.
`MC_INSTALL_ALLOW_UNDERSIZED=1` turns the size checks (CPU, RAM, disk) into
warnings; it is for CI only, never for a miner.

**Ubuntu 22.04 is refused.** Its nftables (1.0.2) prints the set element
`224.0.0.0/3` of the engine egress table as a range in JSON. The miner
agent's host preflight (`network.engine_egress_restricted`) accepts only
prefixes, so on 22.04 the agent refuses to open the sandbox lane. The
installer tests the installed nft in a throwaway network namespace and
refuses before it changes anything.

Every sandbox is the same size: 1 vCPU, 4 GiB RAM and 10 GiB disk; there
are no resource classes. The host declares the SN24 floor: 2 vCPU, 6144 MiB and 20480 MiB disk for one
standard sandbox, with an image cap of exactly 10240 MiB (see
[miner-quickstart.md](miner-quickstart.md)). The installer checks its profile
with `report.py check-standard`. Validators connect directly to the host's
public IP: open inbound TCP 8091 (axon) and TCP 8094 (direct files). You also
need a static public IP.

Preflight refuses a host that already has `/var/lib/mcsbx/profile.json`,
`daemon.json` or a `mscomputer-miner-agent` unit that this installer did not
create. Hand-built hosts are never converged.


## Direct serving and endpoint enrollment

The installer binds the axon to `0.0.0.0:8091` and direct files to
`0.0.0.0:8094`, and runs the axon with `--axon-publish off`: the miner does
not publish an axon on chain, and the installer sets up no tunnel. Validators
learn the address through signed endpoint enrollment instead (see
[miner-endpoint-enrollment.md](miner-endpoint-enrollment.md)).

`enable` starts the agent and the axon, then the enrollment timers:
`mscomputer-miner-endpoint-enroll-first.timer` runs
`mscomputer-miner endpoint-enroll` within about 2 minutes of enable (and of
every boot), and `mscomputer-miner-endpoint-enroll.timer` renews it about
every 6 hours (with a random delay of up to 10 minutes); a failed run is
retried every 5 minutes. To enroll right away,
run `sudo systemctl start mscomputer-miner-endpoint-enroll`. Each run posts a hotkey-signed enrollment to
`https://api.ms.computer/v1/miner-endpoint`. Each enrollment is valid for
24 hours. Check it with:

```bash
journalctl -u mscomputer-miner-endpoint-enroll -n 20
```

Before you run `enable`:

- **Register the hotkey first.** Enrollment is refused for a hotkey that is
  not registered on the subnet.
- **Open inbound TCP 8091 and 8094** in every firewall in front of the host.
  Enrollment fails if the axon is not reachable from the internet.

After `enable`, qualification takes about 4 hours before the miner can earn.

### Hosts that used the retired tunnel

Tunnels are retired; do not run `install.sh tunnel` (it now exits with an error). On a host
that still has `mscomputer-tunnel.service`, upgrade, open inbound 8091/8094,
run `enable`, and once `journalctl -u mscomputer-miner-endpoint-enroll` shows
a successful enrollment, disable the tunnel:

```bash
sudo systemctl disable --now mscomputer-tunnel.service
```

## More than one sandbox

By default the host declares the floor, one standard sandbox. A bigger host
can declare more: each sandbox beyond the first adds one standard sandbox
(1 vCPU, 4096 MiB, 10240 MiB disk) to the declared aggregate and the lease
slice, and its image and logs to the data filesystem.

| `MCSBX_SANDBOXES` | Declared CPU / memory / disk | Data filesystem | Preflight needs (vCPU / `MemTotal`) |
|---|---|---|---|
| 1 | 2000 / 6144 / 20480 | 32768 | 4 / 15360 |
| 2 | 3000 / 10240 / 30720 | 53248 | 5 / 19456 |
| N | 2000+1000(N-1) / 6144+4096(N-1) / 20480+10240(N-1) | grown to fit | 3+N / 15360+4096(N-1) |

```bash
sudo MCSBX_SANDBOXES=2 scripts/miner-install/install.sh install
```

The value is recorded in `install.env`, so plain re-runs keep it. The
declared count is an upper bound, not a promise: validators decide how many of
the declared sandboxes they actually place on your host. On a running miner, `install`
rewrites the profile and the lease slice limits at once; the agent reads the
new profile at its next start (see [Upgrades and restarts](#upgrades-and-restarts)).
An upgraded host that still has `/etc/mscomputer-miner/artifact-store.env` no
longer uses it. It is safe to delete
(`sudo rm /etc/mscomputer-miner/artifact-store.env`); there is nothing to
revoke on your side. `enable` warns while it exists.

## What it installs

All downloads are pinned by version and checked against a SHA-256 digest:

| Component | Pin |
|---|---|
| gVisor `runsc` | `release-20261005.0`, the same pin as `scripts/sandbox-host/lib.sh` |
| Dedicated containerd | static `2.3.6` |
| Dedicated dockerd | static Docker `28.0.4` (`dockerd` digest checked) |
| Go toolchain for the build | `go1.23.12` |
| Miner software | the pinned release tag (`PINNED_REF` in `install.sh`). The miner agent is rebuilt from a clean clone (CGO off, `-trimpath`, `-buildvcs=false`, `-ldflags='-s -w -buildid='`) and must hash to the pinned agent digest (`PINNED_AGENT_SHA256`), which equals the signed `miner-agent-linux-amd64` release asset (see [verify-release.md](verify-release.md)). The sandbox-ops helper and host observer are built at the same tag; the Python axon goes in a venv. |
| Python 3.12 | Ubuntu 24.04's `python3.12` |
| Python dependencies | `scripts/miner-install/python-requirements.lock`: every transitive dependency of the pinned commit and the `hatchling` build backend, pinned with SHA-256 hashes (`uv pip compile --generate-hashes`), installed with `pip --require-hashes --only-binary :all:`. The project itself is installed with `--no-deps`, and `pip check` must pass. |

To install or upgrade to another release, set
`MC_INSTALL_REF=<release tag or commit>` and
`MC_INSTALL_AGENT_SHA256=<matching agent digest>` when running
`install.sh install`. Take the digest from the release's verified
`SHA256SUMS` ([verify-release.md](verify-release.md)). The tag or commit must be present in the clone you run from
(`git fetch --tags` first). The installer
refuses a build whose digest differs. The Python lock covers the pinned
commit; if a newer commit changes its dependencies, `pip check` fails and the
lock must be regenerated in a reviewed change.

The profile is validated with `report.py` from the installed commit itself
(copied into the release), not from the working tree you run the installer
from.

### Install-time settings

`MCSBX_EGRESS_DENY_CIDRS`, `MCSBX_DATA_FS_MIB` and `MCSBX_SANDBOXES` are recorded in
`/etc/mscomputer-miner/install.env` and are the defaults of every later run,
so a plain re-run (an upgrade, say) keeps them:

- Leave a variable unset to keep the installed value.
- A different deny list is refused unless `MC_INSTALL_RECONFIGURE=1` is set
  (an empty value with `MC_INSTALL_RECONFIGURE=1` clears it).
- `MCSBX_DATA_FS_MIB` may only grow; a smaller value is refused.
- `MCSBX_SANDBOXES` (1 to 8, default 1) is how many standard sandboxes the
  host declares at once. See [More than one sandbox](#more-than-one-sandbox).

On a host installed before `install.env` existed, the values in its
`profile.json` are used.

Host layout:

- `/var/lib/mcsbx/data.xfs` is an XFS loop filesystem with project quota,
  mounted at `/var/lib/mcsbx/data`. `/var/lib/mcsbx/run` is a 64 MiB tmpfs.
  The filesystem only grows (`MCSBX_DATA_FS_MIB`, default and minimum 32768).
  It is never shrunk or reformatted.
- `mcsbxcontainerd.service` and `mcsbxdockerd.service` run in
  `mcsbxengine.slice` (1536 MiB, no swap). runsc is the default and only
  runtime, plus a `runsc-docker` variant for Docker-in-sandbox. The daemon
  creates no bridge or iptables rules of its own.
- `mcsbxlease.slice` holds the declared sandbox aggregate (CPUQuota 200%,
  6144 MiB, no swap, 1024 tasks). `mcsbxdeploy.slice` takes app replicas.
  Its MemoryMax comes from `miner-agent --app-budget-print` for this host.
- `mcsbx-engine-egress.service` loads the `mcsbx_engine_egress` nftables
  table. Image pulls may reach only the host resolver and public unicast
  addresses. `mcsbx-egress-bridge.service` creates the `mcsbxeg0` bridge for
  tenant network modes `public` and `allowlist`. At start the agent loads the
  sandbox egress, isolation, anti-spoof and allowlist tables itself. Add
  destinations every sandbox must never reach with
  `MCSBX_EGRESS_DENY_CIDRS="a/b c/d"`.
- The installer writes `/var/lib/mcsbx/profile.json`
  (sandbox-host-profile.v1), `daemon.json` and `ops-config.json`. The ops
  helper sits on a read-only bind mount.
- `mscomputer-miner-agent.service` (root) and
  `mscomputer-miner-neuron.service` (user `mc-miner`) carry every required
  flag: `--qualification on`, `--sandbox-leases on`, `--sandbox-ops on`,
  direct files, the app budget and `--response-receipts on`. They stay
  stopped until `enable`.

Every piece is a persistent systemd unit, so the engine comes back after a
reboot.

## Operator files (not created for you)

The installer generates only the local bridge secret
(`/etc/mscomputer-miner/bridge.secret`, never printed). Everything else comes
from you:

1. A registered hotkey and its UID: see the
   [miner quickstart](miner-quickstart.md).
2. `/etc/mscomputer-miner/miner.env`: copy `/etc/mscomputer-miner/miner.env.example`
   and fill it in (wallet and hotkey names, hotkey SS58, UID, TLS pin; network,
   netuid 24, axon port and the SN24 operator hotkey are filled in already). It
   holds no secret.
3. TLS:
   `sudo scripts/manage-miner-tls.sh issue /etc/mscomputer-miner/tls <public-ip> 90`.
   Put the printed leaf SHA-256 in `MC_TLS_SHA256`.
4. The hotkey only (never the coldkey), at
   `/var/lib/mscomputer-miner/wallets/<wallet>/hotkeys/<hotkey>`. See
   [keys-and-secrets.md](keys-and-secrets.md).

There are no artifact-store credentials to obtain: the agent reads artifacts
through the operator's signed pull gateway
(`--artifact-backend pull --artifact-pull-url https://api.ms.computer/v1/miner-artifacts`)
with its own service key. Sandbox images come from the operator's mirror; the
agent logs in for each pull with the same service key
(`--image-registry-login-url https://mirror.ms.computer/v1/mirror-login`), so
the hotkey must be registered. The mirror admits enrolled miners, so no
published axon is needed. The host needs outbound TCP 443.

`enable` checks these and starts both services. The agent (root) reads the
TLS pair from `/etc/mscomputer-miner/tls`, which stays root-only. The axon
gets a copy in `/etc/mscomputer-miner/axon-tls` (directory `root:mc-miner`
0750, certificate 0644, key `mc-miner` 0600: the axon refuses a key that is
group-readable). `mc-miner` can read its copy but cannot replace the agent's
TLS files. The wallet directory goes to `mc-miner`. After a TLS rotation, run
`enable` again.

## Self-test

`self-test` checks the following, and fails on any miss:

- the engine units and slices, and the lease slice CPU limit;
- the XFS project-quota mount and the tmpfs;
- the engine egress table bound to the engine slice, and the egress bridge;
- the read-only ops helper mount;
- the profile, with `check-profile` and `check-standard`;
- the runsc digest, and the miner-agent binary hashed against the pinned
  agent digest;
- that `install.env`, the profile and the data filesystem agree;
- that the sandbox daemon's default runtime is runsc;
- that the axon venv imports;
- every check of `sandbox-host-observe preflight`. These are the
  `pkg/sandboxhost` observations the agent makes before it opens the
  sandbox lane;
- a real container on the sandbox daemon (`--network none`, lease slice),
  which must report gVisor.

## Upgrades and restarts

Restarting the miner agent ends every sandbox running on the host. `install` never restarts it.

After a restart or upgrade your miner is re-verified automatically: the
validator stops placing sandboxes on it, runs one of its own verification
sandboxes on the restarted miner, and resumes placements once that check
passes. Expect about 5 minutes without new sandboxes. If the check fails it is
retried with backoff (10 minutes, doubling up to 2 hours). There is nothing to
do on your side; keep the agent running and reachable.

Upgrade paths:

- **New release while the miner runs.** If the agent or axon is active and
  the commit differs from the installed one, `install` only builds and stages
  the release under `/opt/mscomputer-miner/releases/` and changes nothing
  else: `current`, the profile, the ops-helper pin and the units stay as they
  are, so a crash restart never silently picks up the new build. Activate it
  when you choose:
  `systemctl stop mscomputer-miner-neuron mscomputer-miner-agent && MC_INSTALL_REF=... MC_INSTALL_AGENT_SHA256=... install.sh install && install.sh enable`.
  `enable` starts the agent and axon again, refreshes the axon's TLS copy and
  (re)enables the enrollment timers, which matters on hosts set up by an
  older release.
- **Unit files changed while the miner runs.** The installer leaves the
  running engine and agent as they are and warns you.
- **Restarts that take the agent down too.** `mscomputer-miner-agent.service`
  has `Requires=` on `docker.service` and `mcsbxdockerd.service`, and
  `mcsbxdockerd` requires `mcsbxcontainerd` and the engine egress unit. So
  `systemctl restart mcsbxdockerd`, `systemctl restart mcsbxcontainerd`, or a
  package upgrade that restarts the host `docker.io`/`containerd` (for
  example by unattended-upgrades) also restarts the agent. Hold those
  packages and upgrade them by hand: `apt-mark hold docker.io containerd runc`,
  or add them to `Unattended-Upgrade::Package-Blacklist`. The dedicated
  sandbox containerd and dockerd are static pinned binaries that apt never
  touches.

## Limits

`MC_INSTALL_ALLOW_UNDERSIZED=1` exists so CI runners with little disk can run
the installer. Never set it on a miner.
