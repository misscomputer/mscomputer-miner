#!/usr/bin/env bash
# Copyright (c) 2026 Ms. Computer. All rights reserved.
# SPDX-License-Identifier: LicenseRef-MsComputer-Miner
#
# Supported installer for an SN24 sandbox miner host (Ubuntu 24.04, x86_64
# only; 22.04 is refused, see nft_json_check). It builds the same host the operator's own sandbox miners run:
#
#   - a dedicated containerd (pinned static release) and dockerd (pinned
#     static Docker 28.0.4) in a finite engine slice, with gVisor runsc
#     (pinned release) as the only and default runtime;
#   - a finite XFS data filesystem with project quota (loop file) and a
#     size-limited tmpfs run root;
#   - finite lease, engine and app (deployment) slices;
#   - the engine egress nftables table and the tenant egress bridge (the
#     miner agent loads the sandbox egress, isolation, anti-spoof and
#     allowlist tables itself at start);
#   - sandbox-host-profile.v1, daemon.json and the sandbox-ops config;
#   - the miner agent, the sandbox-ops helper, the host observer and the
#     Python axon, built from this repository at a pinned commit and checked
#     against the digests of the reviewed reproducible builds;
#   - systemd units for all of it (persistent across reboots).
#
# Subcommands (all as root):
#   preflight   read-only host checks (spec, OS, kernel, cgroup v2, tools)
#   install     preflight + install/converge everything above; idempotent
#   self-test   checks a converged host: profile, Go host preflight
#               observations, a gVisor container on the sandbox daemon,
#               nftables, slices, units
#   enable      check /etc/mscomputer-miner/miner.env, start the agent and
#               the axon on public listeners, without chain advertisement
#   tunnel      retired: connect-out tunnels are gone, validators reach
#               miners directly after endpoint enrollment (always fails)
#   status      unit states and versions
#
# No secret is created by or embedded in this script except the local
# bridge secret, which is generated on the host (openssl rand) and never
# printed. Wallets and TLS certificates are supplied by the operator; there
# are no artifact-store credentials (artifacts come through the operator's
# signed pull gateway). See docs/miner-installer.md.
# pf_ok/say always succeed, so 'A && ok || fail' is if-then-else here.
# shellcheck disable=SC2015
set -euo pipefail
umask 022

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository=$(CDPATH='' cd -- "$here/../.." && pwd -P)

# ---------------------------------------------------------------------------
# Pinned inputs. A change here is a reviewed change to the supported host.
# runsc and containerd are the same pins as scripts/sandbox-host/lib.sh (a
# test keeps them equal); the operator's miners run exactly these builds.
readonly RUNSC_RELEASE=release-20261005.0
readonly RUNSC_ARCHIVE_SHA256=bd4eb2ca0ee74f0fbbb5f5273ba011e79c56a29fbb047393b88b981cd3230ede
readonly RUNSC_SHA256=210b437a9cfae51e8f8c9074ed19b8b5e59477178e2e391a18117d8d6b924f7a
readonly CONTAINERD_VERSION=2.3.6
readonly CONTAINERD_ARCHIVE_SHA256=96eece214bedf3b77d2c2fd04245baaa3de36a1be1d10addf358dca71ae876d2
readonly DOCKER_VERSION=28.0.4
readonly DOCKER_ARCHIVE_SHA256=6b130fa5fb13516620d5ece0b63f63a495cede428bb2f9e24449022e9d72e0cb
readonly DOCKERD_SHA256=91485f066d940af5fbe7299c70eafdc83eb4db7521352c202cba34e0bf64c331
readonly GO_VERSION=go1.23.12
readonly GO_ARCHIVE_SHA256=d3847fef834e9db11bf64e3fb34db9c04db14e068eeb064f49af747010454f90
readonly SELFTEST_IMAGE=docker.io/library/busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f
# The pinned miner software: a git ref (a release tag, or a commit) and the
# digest of its miner agent built by the recipe in build_release (go1.23.12,
# CGO_ENABLED=0, -trimpath, -buildvcs=false, -ldflags='-s -w -buildid=', from
# a clean clone). The recipe embeds no commit or VCS data, so the digest does
# not depend on the commit and a tagged release can carry its own digest (it
# equals the miner-agent-linux-amd64 release asset). The tag only names the
# source; the digest is what is enforced. Override with MC_INSTALL_REF (or the
# older MC_INSTALL_COMMIT) for a newer reviewed release; then
# MC_INSTALL_AGENT_SHA256 must name the reviewed digest, or the build is
# refused. The public export rewrites these two lines to the release tag.
readonly PINNED_REF=unreleased
readonly PINNED_AGENT_SHA256=
# BUILDINFO recipe of builds made by this installer. Builds without it (the
# earlier recipe with VCS stamping) are checked against the earlier pin when
# they are of its commit, otherwise against their own BUILDINFO.
readonly BUILD_RECIPE=2
readonly LEGACY_PINNED_COMMIT=
readonly LEGACY_AGENT_SHA256=
# The operator's signed artifact pull gateway (no storage credentials).
readonly ARTIFACT_PULL_URL=https://api.ms.computer/v1/miner-artifacts
# The image mirror login: sandbox image pulls from the mirror carry a
# short-lived credential the agent obtains with its service key.
readonly IMAGE_REGISTRY_LOGIN_URL=https://mirror.ms.computer/v1/mirror-login
readonly AXON_BIND=0.0.0.0 DIRECT_FILES_BIND=0.0.0.0:8094

# Fixed host layout (the same paths as the operator's miners).
readonly SBX=/var/lib/mcsbx
readonly ETC=/etc/mscomputer-miner
readonly STATE=/var/lib/mscomputer-miner
readonly OPT=/opt/mscomputer-miner
readonly UNITS=/etc/systemd/system
readonly MARKER=$ETC/.installed-by-miner-install
# Install-time settings (deny CIDRs, data filesystem size), reused as the
# defaults of every later run so a plain re-run never drops them.
readonly SETTINGS=$ETC/install.env
readonly LEASE_SLICE=mcsbxlease.slice ENGINE_SLICE=mcsbxengine.slice DEPLOY_SLICE=mcsbxdeploy.slice
readonly EGRESS_BRIDGE=mcsbxeg0 EGRESS_SUBNET=10.231.0.0/24 EGRESS_GATEWAY=10.231.0.1/24
readonly ENGINE_EGRESS_TABLE=mcsbx_engine_egress

# Sizing. With one sandbox the declared aggregate is the SN24 floor: 2 vCPU,
# 6144 MiB, 20480 MiB disk, image cap exactly 10240 MiB. Each further concurrent sandbox (MCSBX_SANDBOXES, 1-8)
# adds one standard sandbox: 1 vCPU, 4096 MiB, 10240 MiB disk, and its image
# and logs on the data filesystem. Overheads are the operator's values.
readonly FLOOR_CPU_MILLIS=2000 FLOOR_MEMORY_MIB=6144 FLOOR_DISK_MIB=20480
readonly SLOT_CPU_MILLIS=1000 SLOT_MEMORY_MIB=4096 SLOT_DISK_MIB=10240 MAX_SANDBOXES=8
SANDBOXES=1 CPU_MILLIS=$FLOOR_CPU_MILLIS LEASE_MEMORY_MIB=$FLOOR_MEMORY_MIB LANE_DISK_MIB=$FLOOR_DISK_MIB LEASE_TASKS=1024
readonly IMAGE_MAX_MIB=10240 IMAGE_RESERVE_MIB=512 ENGINE_OVERHEAD_MIB=512
readonly LOG_MAX_SIZE_MIB=8 LOG_MAX_FILE=2 PIDS_MAX=64 DEFAULT_WRITABLE_MIB=64
readonly RUN_TMPFS_MIB=64 ENGINE_MEMORY_MIB=1536 ENGINE_TASKS=4096 SYSTEM_RESERVE_MIB=1536
readonly DATA_FS_MIB_MIN=32768
DATA_FS_MIB='' EGRESS_DENY_CIDRS=''
ALLOW_UNDERSIZED=${MC_INSTALL_ALLOW_UNDERSIZED:-0}
RECONFIGURE=${MC_INSTALL_RECONFIGURE:-0}
REF=${MC_INSTALL_REF:-${MC_INSTALL_COMMIT:-$PINNED_REF}}
COMMIT=''  # REF resolved to a commit by resolve_ref
AGENT_SHA256=${MC_INSTALL_AGENT_SHA256:-}

die() { echo "miner-install: FAILED: $*" >&2; exit 1; }
say() { echo "miner-install: $*"; }
warn() { echo "miner-install: WARNING: $*" >&2; }

# Temporary paths removed on every exit, including die().
cleanup_paths=()
cleanup() { (( ${#cleanup_paths[@]} == 0 )) || rm -rf -- "${cleanup_paths[@]}"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Install-time settings. MCSBX_EGRESS_DENY_CIDRS and MCSBX_DATA_FS_MIB are
# recorded in $SETTINGS. A later run without them reuses the recorded values
# (on a host installed before $SETTINGS existed: the values in its profile).
# Changing the deny list needs MC_INSTALL_RECONFIGURE=1; the data filesystem
# only grows.
canonical_cidrs() {  # space/comma separated -> sorted canonical, space separated
  python3 - "$1" <<'PY' || die "MCSBX_EGRESS_DENY_CIDRS: not a list of CIDRs: $1"
import ipaddress, sys
nets = {ipaddress.ip_network(i, strict=True) for i in sys.argv[1].replace(',', ' ').split()}
print(' '.join(str(n) for n in sorted(nets, key=lambda n: (n.version, n))))
PY
}
load_settings() {
  local saved_deny='' saved_fs='' saved_sbx='' have_saved=0 file_mib=0
  if [[ -f $SETTINGS ]]; then
    have_saved=1
    saved_deny=$(sed -n 's/^MCSBX_EGRESS_DENY_CIDRS="\([^"]*\)"$/\1/p' "$SETTINGS")
    saved_fs=$(sed -n 's/^MCSBX_DATA_FS_MIB=\([0-9]*\)$/\1/p' "$SETTINGS")
    saved_sbx=$(sed -n 's/^MCSBX_SANDBOXES=\([0-9]*\)$/\1/p' "$SETTINGS")
  elif [[ -e $MARKER && -f $SBX/profile.json ]]; then
    have_saved=1
    saved_deny=$(python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["egress"]["deny_cidrs"]))' "$SBX/profile.json")
    saved_fs=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["aggregate"]["data_fs_mib"])' "$SBX/profile.json")
  fi
  saved_deny=$(canonical_cidrs "$saved_deny")
  if [[ ${MCSBX_EGRESS_DENY_CIDRS+set} ]]; then
    EGRESS_DENY_CIDRS=$(canonical_cidrs "$MCSBX_EGRESS_DENY_CIDRS")
    if (( have_saved )) && [[ $EGRESS_DENY_CIDRS != "$saved_deny" && $RECONFIGURE != 1 ]]; then
      die "MCSBX_EGRESS_DENY_CIDRS='$EGRESS_DENY_CIDRS' differs from the installed deny list '$saved_deny' ($SETTINGS). Leave it unset to keep the installed list, or set MC_INSTALL_RECONFIGURE=1 to replace it"
    fi
  else
    EGRESS_DENY_CIDRS=$saved_deny
  fi
  # Concurrent sandboxes: MCSBX_SANDBOXES, else the installed value, else 1.
  # It may go up or down; the data filesystem still only grows.
  if [[ ${MCSBX_SANDBOXES+set} ]]; then
    SANDBOXES=$MCSBX_SANDBOXES
  elif [[ $saved_sbx =~ ^[1-9][0-9]*$ ]]; then
    SANDBOXES=$saved_sbx
  fi
  [[ $SANDBOXES =~ ^[1-8]$ ]] ||
    die "MCSBX_SANDBOXES=$SANDBOXES must be an integer from 1 to $MAX_SANDBOXES"
  CPU_MILLIS=$(( FLOOR_CPU_MILLIS + (SANDBOXES - 1) * SLOT_CPU_MILLIS ))
  LEASE_MEMORY_MIB=$(( FLOOR_MEMORY_MIB + (SANDBOXES - 1) * SLOT_MEMORY_MIB ))
  LANE_DISK_MIB=$(( FLOOR_DISK_MIB + (SANDBOXES - 1) * SLOT_DISK_MIB ))
  # Every sandbox needs per_lease pids_max plus the gVisor host tasks (176).
  LEASE_TASKS=$(( SANDBOXES * 256 > 1024 ? SANDBOXES * 256 : 1024 ))
  [[ -f $SBX/data.xfs ]] && file_mib=$(( $(stat -c %s "$SBX/data.xfs") / 1048576 ))
  # Smallest data filesystem for the declared disk: disk + sandboxes x
  # (image cap + logs) + engine overhead + image reserve, in whole GiB.
  local need_fs=$(( LANE_DISK_MIB + SANDBOXES * (IMAGE_MAX_MIB + LOG_MAX_SIZE_MIB * LOG_MAX_FILE) + ENGINE_OVERHEAD_MIB + IMAGE_RESERVE_MIB ))
  need_fs=$(( (need_fs + 1023) / 1024 * 1024 ))
  local floor=$DATA_FS_MIB_MIN
  (( need_fs > floor )) && floor=$need_fs
  if [[ $saved_fs =~ ^[0-9]+$ ]] && (( saved_fs > floor )); then floor=$saved_fs; fi
  if (( file_mib > floor )); then floor=$file_mib; fi
  if [[ ${MCSBX_DATA_FS_MIB+set} ]]; then
    [[ $MCSBX_DATA_FS_MIB =~ ^[1-9][0-9]*$ ]] || die "MCSBX_DATA_FS_MIB=$MCSBX_DATA_FS_MIB is not a positive integer"
    (( MCSBX_DATA_FS_MIB >= floor )) ||
      die "MCSBX_DATA_FS_MIB=$MCSBX_DATA_FS_MIB is below the installed ${floor} MiB (minimum $DATA_FS_MIB_MIN); the data filesystem only grows"
    DATA_FS_MIB=$MCSBX_DATA_FS_MIB
  else
    DATA_FS_MIB=$floor
  fi
}
write_settings() {
  put 0644 "$SETTINGS" <<EOF && say "wrote $SETTINGS" || true
# Generated by scripts/miner-install/install.sh: install-time settings, the
# defaults of every later run. Change them through the installer
# (MC_INSTALL_RECONFIGURE=1 for the deny list), not by hand.
MCSBX_EGRESS_DENY_CIDRS="$EGRESS_DENY_CIDRS"
MCSBX_DATA_FS_MIB=$DATA_FS_MIB
MCSBX_SANDBOXES=$SANDBOXES
EOF
}

# ---------------------------------------------------------------------------
# Preflight (read-only).
preflight_failures=0
pf_fail() {
  if [[ $2 == hard || $ALLOW_UNDERSIZED != 1 ]]; then
    echo "  FAIL  $1" >&2; preflight_failures=$((preflight_failures + 1))
  else
    echo "  WARN  $1 (MC_INSTALL_ALLOW_UNDERSIZED=1: not for a production miner)" >&2
  fi
}
pf_ok() { echo "  ok    $1"; }
pf_rec() { echo "  note  $1"; }

# Tools the preflight itself needs before the package step can run. A stock
# Ubuntu 24.04 server has them all; a minimal image may lack python3.
require_base_tools() {
  local t missing=()
  for t in python3 awk sed stat df nproc unshare dpkg-query apt-get; do
    command -v "$t" >/dev/null || missing+=("$t")
  done
  (( ${#missing[@]} == 0 )) ||
    die "required tools not found: ${missing[*]}. Install them first (on Ubuntu 24.04: apt-get install python3), then re-run"
}

preflight() {
  say "preflight"
  [[ $EUID == 0 ]] || die 'run as root'
  require_base_tools
  load_settings
  say "settings: sandboxes ${SANDBOXES} (declared ${CPU_MILLIS} cpu_millis, ${LEASE_MEMORY_MIB} MiB, ${LANE_DISK_MIB} MiB disk), data fs ${DATA_FS_MIB} MiB, egress deny [${EGRESS_DENY_CIDRS}]"
  local id ver arch kernel cpus mem_mib free_mib
  # shellcheck disable=SC1091
  id=$(. /etc/os-release && echo "$ID") ver=$(. /etc/os-release && echo "$VERSION_ID")
  if [[ $id == ubuntu && $ver == 24.04 ]]; then pf_ok "os ubuntu $ver"; else pf_fail "os $id $ver (supported: ubuntu 24.04)" hard; fi
  arch=$(uname -m)
  [[ $arch == x86_64 ]] && pf_ok "arch $arch" || pf_fail "arch $arch (pinned runsc and binaries are x86_64)" hard
  kernel=$(uname -r)
  if [[ $(printf '5.15\n%s\n' "${kernel%%-*}" | sort -V | head -1) == 5.15 ]]; then
    pf_ok "kernel $kernel"
  else
    pf_fail "kernel $kernel (need >= 5.15)" hard
  fi
  [[ -d /run/systemd/system ]] && pf_ok 'systemd is PID 1' || pf_fail 'systemd is not the init system (containers are not supported)' hard
  [[ $(stat -f -c %T /sys/fs/cgroup) == cgroup2fs ]] && pf_ok 'cgroup v2 unified' || pf_fail 'cgroup v2 unified hierarchy required' hard
  if [[ -e /run/.containerenv || -e /.dockerenv ]]; then pf_fail 'running inside a container' hard; fi
  grep -qw memory /sys/fs/cgroup/cgroup.controllers && pf_ok 'memory controller' || pf_fail 'cgroup memory controller missing' hard
  cpus=$(nproc)
  mem_mib=$(( $(awk '/^MemTotal:/ {print $2}' /proc/meminfo) / 1024 ))
  mkdir -p /var/lib
  free_mib=$(( $(df -B1 --output=avail /var/lib | awk 'NR == 2 {print $1}') / 1048576 ))
  local have_fs=0
  [[ -f $SBX/data.xfs ]] && have_fs=$(( $(stat -c %s "$SBX/data.xfs") / 1048576 ))
  local need_disk=$((DATA_FS_MIB - have_fs + 8192))
  # Recommended host minimum: 4 vCPU / 15 GiB (the reference host is 4 vCPU /
  # 16 GiB with about 100 GiB free disk), plus one vCPU and 4 GiB for each
  # sandbox beyond the first.
  local need_cpus=$(( 4 + (SANDBOXES - 1) )) need_mem=$(( 15360 + (SANDBOXES - 1) * SLOT_MEMORY_MIB ))
  (( cpus >= need_cpus )) && pf_ok "vcpus $cpus (need >= $need_cpus for $SANDBOXES sandbox(es))" ||
    pf_fail "vcpus $cpus < $need_cpus: below the recommended minimum for $SANDBOXES sandbox(es); the miner may not be accepted" soft
  (( mem_mib >= need_mem )) && pf_ok "memory ${mem_mib} MiB (need >= $need_mem for $SANDBOXES sandbox(es))" ||
    pf_fail "memory ${mem_mib} MiB < $need_mem: below the recommended minimum for $SANDBOXES sandbox(es); the miner may not be accepted" soft
  (( free_mib >= need_disk )) && pf_ok "free disk on /var/lib ${free_mib} MiB (need >= $need_disk: $(disk_need_why "$have_fs"))" ||
    pf_fail "free disk on /var/lib ${free_mib} MiB < $need_disk MiB needed ($(disk_need_why "$have_fs"))" soft
  (( free_mib >= 102400 )) || pf_rec "recommended: 100 GiB free disk (have ${free_mib} MiB)"
  # The agent pins the ops helper only on a path whose every ancestor is
  # root-owned and not group- or other-writable.
  local d
  for d in / /opt; do
    if [[ $(stat -c %u "$d") != 0 || $(( 0$(stat -c %a "$d") & 022 )) != 0 ]]; then
      pf_fail "$d must be root-owned and not group- or other-writable (mode $(stat -c %a "$d")): the agent refuses the sandbox-ops helper below it" hard
    fi
  done
  # Refuse a host built some other way (for example by hand): converging it
  # would replace a working configuration underneath a running miner.
  if [[ ! -e $MARKER ]]; then
    local p
    for p in $SBX/profile.json $SBX/daemon.json $UNITS/mscomputer-miner-agent.service; do
      [[ -e $p ]] && pf_fail "$p exists but this host was not set up by this installer; refusing to touch it" hard
    done
  fi
  if command -v systemctl >/dev/null && systemctl is-active --quiet mscomputer-miner-agent.service; then
    pf_rec 'mscomputer-miner-agent is running: install never restarts it, and a new release is only staged, not activated (docs/miner-installer.md, "Upgrades and restarts")'
  fi
  if command -v nft >/dev/null; then nft_json_check; else pf_rec 'nftables not installed yet: its JSON check runs after the package step'; fi
  if (( preflight_failures > 0 )); then die "preflight: $preflight_failures check(s) failed"; fi
  say "preflight passed"
}

# The agent's host preflight reads the engine egress table as nft JSON and
# needs every set element printed as a prefix. nftables 1.0.2 (Ubuntu 22.04)
# prints 224.0.0.0/3 as a range, so the agent refuses the sandbox lane there.
# Check the installed nft in a throwaway network namespace.
nft_json_check() {
  local out
  local v4='0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3'
  out=$(unshare --net sh -c "printf '%s\n' 'table inet mcsbx_check { chain c { type filter hook output priority filter; policy accept; ip daddr { $v4 } counter reject with icmpx admin-prohibited; }; }' | nft -f - && nft -j list table inet mcsbx_check" 2>&1) || {
    pf_fail "cannot check nftables JSON output: ${out:0:200}" hard; return; }
  if grep -q '"prefix"' <<<"$out" && ! grep -q '"range"' <<<"$out"; then
    pf_ok "nftables $(nft --version | awk '{print $2}') prints prefixes in JSON"
  else
    pf_fail "nftables $(nft --version | awk '{print $2}') prints 224.0.0.0/3 as a range in JSON; the miner agent's host preflight (network.engine_egress_restricted) rejects that. Known on Ubuntu 22.04 (nftables 1.0.2): use Ubuntu 24.04" hard
  fi
}

# ---------------------------------------------------------------------------
# Helpers.
fetch() {  # url sha256 dest
  local url=$1 sum=$2 dest=$3
  if [[ -f $dest ]] && printf '%s  %s\n' "$sum" "$dest" | sha256sum --check --status; then return 0; fi
  curl --fail --silent --show-error --location --retry 3 --max-time 600 "$url" -o "$dest.part"
  printf '%s  %s\n' "$sum" "$dest.part" | sha256sum --check --status || { rm -f "$dest.part"; die "checksum mismatch for $url"; }
  mv "$dest.part" "$dest"
}
# Write a file only if its content changed; prints "changed" when it did.
put() {  # mode dest  (content on stdin)
  # Errors are fatal here explicitly: callers use put in a condition, where
  # errexit does not apply.
  local mode=$1 dest=$2 tmp
  tmp=$(mktemp "${dest}.XXXXXX") || die "cannot write $dest"
  cat > "$tmp" || die "cannot write $dest"
  chmod "$mode" "$tmp" || die "cannot chmod $dest"
  if [[ -f $dest ]] && cmp -s "$tmp" "$dest"; then rm -f "$tmp"; return 1; fi
  mv "$tmp" "$dest" || die "cannot replace $dest"
  return 0
}
units_changed=0
# Explain the free-disk need: 8 GiB of headroom plus whatever the sandbox
# data filesystem still has to grow (all of it on a fresh host).
disk_need_why() {  # existing data fs MiB
  if (( $1 == 0 )); then echo "new ${DATA_FS_MIB} MiB sandbox data fs + 8 GiB headroom"
  elif (( $1 >= DATA_FS_MIB )); then echo "8 GiB headroom; the ${1} MiB sandbox data fs already exists"
  else echo "$((DATA_FS_MIB - $1)) MiB to grow the sandbox data fs to ${DATA_FS_MIB} MiB + 8 GiB headroom"; fi
}

put_unit() { if put 0644 "$UNITS/$1"; then units_changed=1; say "wrote $UNITS/$1"; fi; }
sha_of() { sha256sum "$1" | awk '{print $1}'; }

install_packages() {
  local pkgs=(curl ca-certificates git tar bzip2 xfsprogs nftables iproute2 iptables openssl python3 jq util-linux)
  local missing=() p
  for p in "${pkgs[@]}"; do dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || missing+=("$p"); done
  # The organic (dynamic app) lane uses the host Docker Engine. Keep an
  # existing one; otherwise install Ubuntu's docker.io.
  command -v dockerd >/dev/null || missing+=(docker.io)
  if (( ${#missing[@]} )); then
    say "apt install ${missing[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "${missing[@]}"
  fi
  preflight_failures=0
  nft_json_check
  (( preflight_failures == 0 )) || die 'nftables is not usable by the miner agent'
  systemctl enable --now docker.service >/dev/null 2>&1 || systemctl start docker.service
  systemctl is-active --quiet docker.service || die 'host docker.service is not active'
}

install_engine_binaries() {
  local dl=$OPT/downloads
  install -d -m 0755 "$OPT" "$dl"
  install -d -m 0700 "$SBX" "$SBX/bin" "$SBX/bin/containerd"
  # gVisor
  fetch "https://github.com/google/gvisor/releases/download/$RUNSC_RELEASE/gvisor-x86_64.tar.bz2" "$RUNSC_ARCHIVE_SHA256" "$dl/gvisor-$RUNSC_RELEASE.tar.bz2"
  if [[ ! -x $SBX/bin/runsc || $(sha_of "$SBX/bin/runsc") != "$RUNSC_SHA256" ]]; then
    tar -xjf "$dl/gvisor-$RUNSC_RELEASE.tar.bz2" -C "$SBX/bin"
    chmod 0755 "$SBX/bin/runsc"
    say "installed runsc $RUNSC_RELEASE"
  fi
  [[ $(sha_of "$SBX/bin/runsc") == "$RUNSC_SHA256" ]] || die 'runsc digest is not the pinned one'
  # containerd
  fetch "https://github.com/containerd/containerd/releases/download/v$CONTAINERD_VERSION/containerd-static-$CONTAINERD_VERSION-linux-amd64.tar.gz" \
    "$CONTAINERD_ARCHIVE_SHA256" "$dl/containerd-$CONTAINERD_VERSION.tar.gz"
  if ! "$SBX/bin/containerd/containerd" --version 2>/dev/null | grep -q " v$CONTAINERD_VERSION "; then
    tar -xzf "$dl/containerd-$CONTAINERD_VERSION.tar.gz" -C "$SBX/bin/containerd" --strip-components=1 bin/containerd bin/containerd-shim-runc-v2 bin/ctr
    say "installed containerd $CONTAINERD_VERSION"
  fi
  # dockerd (static; only dockerd and the docker client are used)
  fetch "https://download.docker.com/linux/static/stable/x86_64/docker-$DOCKER_VERSION.tgz" "$DOCKER_ARCHIVE_SHA256" "$dl/docker-$DOCKER_VERSION.tgz"
  local dd=$OPT/docker-$DOCKER_VERSION
  if [[ ! -x $dd/dockerd || $(sha_of "$dd/dockerd") != "$DOCKERD_SHA256" ]]; then
    install -d -m 0755 "$dd"
    tar -xzf "$dl/docker-$DOCKER_VERSION.tgz" -C "$dd" --strip-components=1
    say "installed static docker $DOCKER_VERSION"
  fi
  [[ $(sha_of "$dd/dockerd") == "$DOCKERD_SHA256" ]] || die 'dockerd digest is not the pinned one'
}

# Build the miner software at the pinned commit from a clean clone of this
# repository, with the pinned Go toolchain, and check the agent digest.
# The venv is built in $rel.tmp and renamed, but venv entry points and
# activate scripts embed the absolute build path. Point them at the final
# path (also repairs a release built before this fix, whose axon entry
# point could not start: 203/EXEC).
fix_venv_paths() {  # final release dir, directory to fix
  local rel=$1 dir=$2 files
  files=$(grep -lIF -- "$rel.tmp/" "$dir"/venv/bin/* "$dir/venv/pyvenv.cfg" 2>/dev/null || true)
  [[ -n $files ]] || return 0
  while IFS= read -r f; do sed -i "s#$rel\.tmp/#$rel/#g" "$f"; done <<< "$files"
  [[ $dir == "$rel" ]] && say "repaired venv paths in $rel" || true
}

# Resolve REF (a tag first, then any commit-ish) to a commit in the repository.
resolve_ref() {
  local c
  c=$(git -C "$repository" rev-parse --verify --quiet "refs/tags/$REF^{commit}" ||
      git -C "$repository" rev-parse --verify --quiet "$REF^{commit}") ||
    die "ref $REF is not in $repository (git fetch --tags first)"
  COMMIT=$c
}

build_release() {
  resolve_ref
  local rel=$OPT/releases/$COMMIT
  if [[ -f $rel/.complete ]]; then fix_venv_paths "$rel" "$rel"; say "release $COMMIT already built"; return 0; fi
  local dl=$OPT/downloads
  fetch "https://go.dev/dl/$GO_VERSION.linux-amd64.tar.gz" "$GO_ARCHIVE_SHA256" "$dl/$GO_VERSION.linux-amd64.tar.gz"
  local goroot=$OPT/toolchain/$GO_VERSION
  if [[ ! -x $goroot/bin/go ]]; then
    install -d -m 0755 "$goroot"
    tar -xzf "$dl/$GO_VERSION.linux-amd64.tar.gz" -C "$goroot" --strip-components=1
  fi
  local expect
  if [[ $REF == "$PINNED_REF" && -z $AGENT_SHA256 ]]; then expect=$PINNED_AGENT_SHA256
  else
    [[ $AGENT_SHA256 =~ ^[0-9a-f]{64}$ ]] || die 'MC_INSTALL_REF needs MC_INSTALL_AGENT_SHA256 (the reviewed agent digest)'
    expect=$AGENT_SHA256
  fi
  [[ $expect =~ ^[0-9a-f]{64}$ ]] || die "no reviewed agent digest for $REF (set MC_INSTALL_REF and MC_INSTALL_AGENT_SHA256)"
  local work
  work=$(mktemp -d /var/tmp/miner-install.XXXXXX)
  cleanup_paths+=("$work" "$rel.tmp")
  rm -rf "$rel.tmp"
  git clone --quiet --no-checkout "$repository" "$work/src"
  git -C "$work/src" -c advice.detachedHead=false checkout --quiet --detach "$COMMIT"
  local env=(env -i HOME="$work/home" PATH="$goroot/bin:/usr/bin:/bin" GOROOT="$goroot" GOTOOLCHAIN=local
             GOPATH="$work/gopath" GOCACHE="$work/gocache" GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH=amd64)
  say "building miner-agent, sandbox-host-observe, sandbox-ops-helper at $REF ($COMMIT) with $GO_VERSION"
  local gobuild=(go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=')
  (cd "$work/src" && "${env[@]}" "${gobuild[@]}" -o "$work/miner-agent" ./cmd/miner-agent)
  (cd "$work/src" && "${env[@]}" "${gobuild[@]}" -o "$work/sandbox-host-observe" ./cmd/sandbox-host-observe)
  (cd "$work/src" && "${env[@]}" sh scripts/sandbox-ops-helper/build.sh "$work/sandbox-ops-helper" >/dev/null)
  local got
  got=$(sha_of "$work/miner-agent")
  [[ $got == "$expect" ]] || die "miner-agent digest $got is not the reviewed $expect (toolchain or source differs)"
  say "miner-agent sha256 $got (matches the reviewed build)"
  # Python axon (Ubuntu 24.04's python3.12). Every dependency, and the
  # hatchling build backend, comes from the hashed lock (wheels only). The
  # project itself is installed without dependencies; pip check proves the
  # lock covers it.
  local py
  py=$(command -v python3.12 || true)
  if [[ -z $py ]] || ! "$py" -c 'import venv, ensurepip' 2>/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends python3.12-venv >/dev/null
    py=$(command -v python3.12)
  fi
  install -d -m 0755 "$rel.tmp" "$rel.tmp/bin" "$rel.tmp/lib"
  "$py" -m venv "$rel.tmp/venv"
  local pip=("$rel.tmp/venv/bin/pip" --disable-pip-version-check --no-cache-dir --quiet)
  "${pip[@]}" install --require-hashes --only-binary :all: -r "$here/python-requirements.lock"
  "${pip[@]}" install --no-deps --no-build-isolation "$work/src"
  "${pip[@]}" check || die "the Python lock $here/python-requirements.lock does not cover commit $COMMIT"
  install -m 0755 "$work/miner-agent" "$work/sandbox-host-observe" "$rel.tmp/bin/"
  # The profile checker of the same commit: the profile is validated against
  # the schema this agent enforces.
  install -m 0644 "$work/src/scripts/sandbox-host/report.py" "$rel.tmp/lib/report.py"
  # The ops helper must sit on a read-only mount with root-owned ancestors.
  install -d -m 0555 "$rel.tmp/ops-helper"
  install -m 0555 "$work/sandbox-ops-helper" "$rel.tmp/ops-helper/sandbox-ops-helper"
  chmod 0555 "$rel.tmp/ops-helper"
  printf 'commit=%s\nagent_sha256=%s\nops_helper_sha256=%s\nobserver_sha256=%s\ngo=%s\npython=%s\nref=%s\nrecipe=%s\n' "$COMMIT" "$got" \
    "$(sha_of "$work/sandbox-ops-helper")" "$(sha_of "$work/sandbox-host-observe")" "$GO_VERSION" "$("$rel.tmp/venv/bin/python" -V)" \
    "$REF" "$BUILD_RECIPE" > "$rel.tmp/BUILDINFO"
  fix_venv_paths "$rel" "$rel.tmp"
  : > "$rel.tmp/.complete"
  rm -rf "$rel"; mv "$rel.tmp" "$rel"
  rm -rf "$work"
}

# report.py of a release's own commit (a release built before it was copied
# in gets it from git).
report_py() {  # release dir
  local rel=$1 commit
  if [[ ! -f $rel/lib/report.py ]]; then
    commit=$(sed -n 's/^commit=//p' "$rel/BUILDINFO")
    install -d -m 0755 "$rel/lib"
    git -C "$repository" show "$commit:scripts/sandbox-host/report.py" > "$rel/lib/report.py.tmp" ||
      die "cannot read scripts/sandbox-host/report.py at $commit from $repository"
    mv "$rel/lib/report.py.tmp" "$rel/lib/report.py"
  fi
  echo "$rel/lib/report.py"
}

# Grow-only: the data filesystem is never shrunk or reformatted.
configure_storage() {
  local f=$SBX/data.xfs
  install -d -m 0700 "$SBX/data" "$SBX/run"
  if [[ ! -f $f ]]; then
    truncate -s "${DATA_FS_MIB}M" "$f"
    mkfs.xfs -q -f "$f"
    say "created ${DATA_FS_MIB} MiB XFS data filesystem $f"
  elif (( $(stat -c %s "$f") < DATA_FS_MIB * 1048576 )); then
    truncate -s "${DATA_FS_MIB}M" "$f"
    say "grew $f to ${DATA_FS_MIB} MiB (the filesystem is grown when mounted)"
  fi
  install -d -m 0755 /usr/local/libexec
  put 0755 /usr/local/libexec/mcsbx-storage <<EOF || true
#!/bin/sh
# Generated by scripts/miner-install/install.sh. Attaches and mounts the
# sandbox data filesystem (XFS, project quota) and the run tmpfs. Idempotent.
set -eu
f=$SBX/data.xfs
loop=\$(losetup -j "\$f" | cut -d: -f1 | head -1)
[ -n "\$loop" ] || loop=\$(losetup --find --show "\$f")
losetup -c "\$loop"
if ! findmnt -n "$SBX/data" >/dev/null; then
  mount -t xfs -o prjquota,nosuid "\$loop" "$SBX/data"
fi
xfs_growfs "$SBX/data" >/dev/null
findmnt -n -o OPTIONS "$SBX/data" | grep -q prjquota
if ! findmnt -n "$SBX/run" >/dev/null; then
  mount -t tmpfs -o size=${RUN_TMPFS_MIB}m,mode=0700,nodev,nosuid mcsbx-run "$SBX/run"
fi
install -d -m 0711 "$SBX/data/docker" "$SBX/data/containerd" "$SBX/run/docker" "$SBX/run/containerd" "$SBX/run/exec"
EOF
}

write_engine_config() {
  put 0644 "$SBX/containerd.toml" <<EOF && say "wrote $SBX/containerd.toml" || true
version = 3
root = "$SBX/data/containerd"
state = "$SBX/run/containerd/state"
disabled_plugins = ["io.containerd.grpc.v1.cri", "io.containerd.cri.v1.runtime", "io.containerd.cri.v1.images"]
[grpc]
  address = "$SBX/run/containerd/containerd.sock"
[ttrpc]
  address = "$SBX/run/containerd/containerd.sock.ttrpc"
[debug]
  address = ""
[metrics]
  address = ""
EOF
  python3 - "$SBX" "$DEFAULT_WRITABLE_MIB" "$LOG_MAX_SIZE_MIB" "$LOG_MAX_FILE" "$LEASE_SLICE" "$EGRESS_BRIDGE" > "$SBX/daemon.json.new" <<'PY'
import json, sys
root, writable, log_size, log_file, lease_slice, bridge = sys.argv[1:]
base = ['--systemd-cgroup', '--overlay2=none']
print(json.dumps({
    'data-root': root + '/data/docker', 'exec-root': root + '/run/exec',
    'pidfile': root + '/run/docker/dockerd.pid',
    'hosts': ['unix://' + root + '/run/docker/docker.sock'], 'group': 'root',
    'storage-driver': 'overlay2', 'storage-opts': ['overlay2.size=' + writable + 'M'],
    'features': {'containerd-snapshotter': False, 'buildkit': False},
    'bridge': bridge, 'iptables': False, 'ip6tables': False, 'ip-forward': False,
    'ip-masq': False, 'userland-proxy': False, 'live-restore': False,
    'exec-opts': ['native.cgroupdriver=systemd'], 'cgroup-parent': lease_slice,
    'default-cgroupns-mode': 'private', 'no-new-privileges': True,
    'log-driver': 'json-file', 'log-opts': {'max-size': log_size + 'm', 'max-file': log_file},
    'default-runtime': 'runsc',
    'runtimes': {
        'runsc': {'path': root + '/bin/runsc', 'runtimeArgs': base},
        'runsc-docker': {'path': root + '/bin/runsc',
                         'runtimeArgs': base + ['--net-raw', '--allow-packet-socket-write']},
    },
}, indent=2, sort_keys=True))
PY
  put 0644 "$SBX/daemon.json" < "$SBX/daemon.json.new" && say "wrote $SBX/daemon.json" || true
  rm -f "$SBX/daemon.json.new"
  # Engine egress: sockets in the engine slice (image pulls) may
  # reach only the host resolver and public unicast addresses. Replaced
  # atomically; matched by cgroup, so it is reloaded after the slice starts.
  put 0644 "$SBX/engine-egress.nft" <<NFT && say "wrote $SBX/engine-egress.nft" || true
table inet $ENGINE_EGRESS_TABLE
delete table inet $ENGINE_EGRESS_TABLE
table inet $ENGINE_EGRESS_TABLE {
  chain output {
    type filter hook output priority filter; policy accept;
    socket cgroupv2 level 1 "$ENGINE_SLICE" ip daddr 127.0.0.53 meta l4proto { tcp, udp } th dport 53 accept
    socket cgroupv2 level 1 "$ENGINE_SLICE" fib daddr type local counter reject with icmpx admin-prohibited
    socket cgroupv2 level 1 "$ENGINE_SLICE" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3 } counter reject with icmpx admin-prohibited
    socket cgroupv2 level 1 "$ENGINE_SLICE" ip6 daddr { ::/127, ::ffff:0:0/96, 64:ff9b::/96, 64:ff9b:1::/48, fc00::/7, fe80::/10, ff00::/8 } counter reject with icmpx admin-prohibited
  }
}
NFT
}

write_profile() {
  local rel=$OPT/releases/$COMMIT
  local helper_sha sentry=$SBX/bin/runsc
  [[ -f $SBX/bin/gvisor-bin/gvisor_sentry ]] && sentry=$SBX/bin/gvisor-bin/gvisor_sentry
  helper_sha=$(sha_of "$rel/ops-helper/sandbox-ops-helper")
  python3 - "$SBX" "$RUNSC_RELEASE" "$(sha_of "$SBX/bin/runsc")" "$sentry" "$(sha_of "$sentry")" "$DOCKER_VERSION" \
    "$ENGINE_EGRESS_TABLE" "$LEASE_SLICE" "$ENGINE_SLICE" "$CPU_MILLIS" "$LEASE_MEMORY_MIB" "$LEASE_TASKS" "$DATA_FS_MIB" \
    "$RUN_TMPFS_MIB" "$IMAGE_RESERVE_MIB" "$ENGINE_OVERHEAD_MIB" "$IMAGE_MAX_MIB" "$((LOG_MAX_SIZE_MIB * LOG_MAX_FILE))" \
    "$LANE_DISK_MIB" "$SANDBOXES" "$DEFAULT_WRITABLE_MIB" "$LOG_MAX_SIZE_MIB" "$LOG_MAX_FILE" "$PIDS_MAX" \
    "$EGRESS_BRIDGE" "$EGRESS_SUBNET" "$EGRESS_DENY_CIDRS" > "$SBX/profile.json.new" <<'PY'
import ipaddress, json, sys
(root, release, runsc_sha, sentry, sentry_sha, docker_version, egress_table, lease, engine, cpu, mem, pids, data_fs,
 run_tmpfs, img_reserve, overhead, img_max, log_mib, disk, sandboxes, writable, log_size, log_file, pids_max,
 bridge, subnet, deny) = sys.argv[1:]
deny_cidrs = []
for item in deny.replace(',', ' ').split():
    deny_cidrs.append(str(ipaddress.ip_network(item, strict=True)))
n = int
args = ['--systemd-cgroup', '--overlay2=none']
print(json.dumps({
    'schema': 'ms.computer/mscomputer-subnet/sandbox-host-profile', 'schema_version': 1,
    'docker_host': 'unix://' + root + '/run/docker/docker.sock',
    'containerd': {'address': root + '/run/containerd/containerd.sock',
                   'namespace': 'mc-sandbox', 'plugins_namespace': 'mc-sandbox-plugins'},
    'data_root': root + '/data', 'docker_data_root': root + '/data/docker', 'run_root': root + '/run',
    'runtime': {'name': 'runsc', 'path': root + '/bin/runsc', 'sha256': runsc_sha, 'sentry_path': sentry,
                'sentry_sha256': sentry_sha, 'args': args, 'release': release},
    'docker': {'runtime': 'runsc-docker', 'args': args + ['--net-raw', '--allow-packet-socket-write'],
               'volume_tmpfs_mib': 4096},
    'engine': {'docker_version': docker_version, 'egress_table': egress_table},
    'cgroup_root': '/sys/fs/cgroup', 'lease_slice': lease, 'engine_slice': engine,
    'aggregate': {'cpu_millis': n(cpu), 'memory_mib': n(mem), 'pids': n(pids), 'data_fs_mib': n(data_fs),
                  'run_tmpfs_mib': n(run_tmpfs), 'image_reserve_mib': n(img_reserve),
                  'engine_overhead_mib': n(overhead), 'image_max_mib': n(img_max), 'log_mib': n(log_mib),
                  'disk_mib': n(disk), 'sandboxes': n(sandboxes)},
    'per_lease': {'default_writable_mib': n(writable), 'log_max_size_mib': n(log_size), 'log_max_file': n(log_file),
                  'pids_max': n(pids_max), 'mounts': 'none', 'image_volumes': 'refuse',
                  'network_modes': ['none', 'public'], 'isolation': ['gvisor']},
    'egress': {'bridge': bridge, 'subnet': subnet, 'dns': ['1.1.1.1', '8.8.8.8'], 'bandwidth_mbit': 50,
               'new_conns_per_second': 50, 'deny_cidrs': deny_cidrs},
}, indent=2, sort_keys=True))
PY
  put 0644 "$SBX/profile.json" < "$SBX/profile.json.new" && say "wrote $SBX/profile.json" || true
  rm -f "$SBX/profile.json.new"
  local report
  report=$(report_py "$rel")
  "$rel/venv/bin/python" "$report" check-profile "$SBX/profile.json" >/dev/null || die 'profile failed check-profile'
  "$rel/venv/bin/python" "$report" check-standard "$SBX/profile.json" >/dev/null || die 'profile is below the SN24 standard floor'
  local hdir=/opt/mcsbx-ops-helper-${helper_sha:0:12}/ops-helper
  if [[ ! -f $hdir/sandbox-ops-helper ]] || [[ $(sha_of "$hdir/sandbox-ops-helper") != "$helper_sha" ]]; then
    install -d -m 0755 "${hdir%/ops-helper}"
    install -d -m 0755 "$hdir"
    install -m 0555 "$rel/ops-helper/sandbox-ops-helper" "$hdir/sandbox-ops-helper"
    chmod 0555 "$hdir"
  fi
  # The pin allows no extended attributes (an inherited default ACL, for
  # example) on the helper directory or binary.
  python3 - "$hdir" "$hdir/sandbox-ops-helper" <<'PY'
import os, sys
for path in sys.argv[1:]:
    for name in os.listxattr(path, follow_symlinks=False):
        os.removexattr(path, name, follow_symlinks=False)
PY
  put 0644 "$SBX/ops-config.json" <<EOF && say "wrote $SBX/ops-config.json" || true
{
  "helper_dir": "$hdir",
  "helper_sha256": "$helper_sha",
  "start_resolution_ms": 15000,
  "state_timeout_ms": 20000,
  "kill_grace_ms": 5000,
  "max_in_flight": 16,
  "max_in_flight_bytes": 4194304,
  "max_outcomes": 256,
  "helper_keepalive": true
}
EOF
  local mount_unit
  mount_unit=$(systemd-escape --path --suffix=mount "$hdir")
  put_unit "$mount_unit" <<EOF
# Generated by scripts/miner-install/install.sh: read-only bind of the pinned sandbox-ops helper.
[Unit]
Description=SN24 sandbox-ops helper ${helper_sha:0:12} (read-only bind)
[Mount]
What=$hdir
Where=$hdir
Type=none
Options=bind,ro
[Install]
WantedBy=multi-user.target
EOF
  echo "$mount_unit" > "$SBX/.ops-helper-mount-unit"
}

write_units() {
  local rel=$OPT/current dd=$OPT/docker-$DOCKER_VERSION hmount
  hmount=$(cat "$SBX/.ops-helper-mount-unit")
  put_unit $ENGINE_SLICE <<EOF
# Generated by scripts/miner-install/install.sh: sandbox engine overhead (daemons, shims, gofers).
[Unit]
Description=SN24 sandbox engine slice
[Slice]
MemoryMax=${ENGINE_MEMORY_MIB}M
MemorySwapMax=0
TasksMax=$ENGINE_TASKS
EOF
  put_unit $LEASE_SLICE <<EOF
# Generated by scripts/miner-install/install.sh: the declared sandbox aggregate.
[Unit]
Description=SN24 sandbox lease slice
[Slice]
CPUQuota=$((CPU_MILLIS / 10))%
MemoryMax=${LEASE_MEMORY_MIB}M
MemorySwapMax=0
TasksMax=$LEASE_TASKS
EOF
  put_unit $DEPLOY_SLICE <<EOF
# Generated by scripts/miner-install/install.sh: app replicas (deployment.v4).
# MemoryMax comes from mcsbxdeploy.slice.d/10-app-budget.conf.
[Unit]
Description=SN24 app deployment slice
[Slice]
MemorySwapMax=0
CPUWeight=50
EOF
  local anchor
  for anchor in lease deploy; do
    put_unit "mcsbx${anchor}anchor.service" <<EOF
# Generated by scripts/miner-install/install.sh: keeps mcsbx${anchor}.slice active.
[Unit]
Description=SN24 mcsbx${anchor}.slice anchor
[Service]
Type=oneshot
RemainAfterExit=yes
Slice=mcsbx${anchor}.slice
ExecStart=/bin/true
[Install]
WantedBy=multi-user.target
EOF
  done
  put_unit mcsbx-storage.service <<EOF
# Generated by scripts/miner-install/install.sh.
[Unit]
Description=SN24 sandbox data filesystem and run tmpfs
DefaultDependencies=no
After=local-fs.target
Before=mcsbxcontainerd.service shutdown.target
Conflicts=shutdown.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/libexec/mcsbx-storage
[Install]
WantedBy=multi-user.target
EOF
  put_unit mcsbx-egress-bridge.service <<EOF
# Generated by scripts/miner-install/install.sh: tenant egress bridge (network mode public/allowlist).
[Unit]
Description=SN24 sandbox egress bridge $EGRESS_BRIDGE
Before=mcsbxdockerd.service mscomputer-miner-agent.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'ip link show $EGRESS_BRIDGE >/dev/null 2>&1 || ip link add $EGRESS_BRIDGE type bridge; ip addr replace $EGRESS_GATEWAY dev $EGRESS_BRIDGE; ip link set $EGRESS_BRIDGE up'
[Install]
WantedBy=multi-user.target
EOF
  put_unit mcsbxcontainerd.service <<EOF
# Generated by scripts/miner-install/install.sh: dedicated containerd (CRI off) for the sandbox engine.
[Unit]
Description=SN24 sandbox containerd $CONTAINERD_VERSION
Requires=mcsbx-storage.service
After=mcsbx-storage.service
[Service]
Slice=$ENGINE_SLICE
KillMode=control-group
TasksMax=infinity
Environment=PATH=$SBX/bin/containerd:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$SBX/bin/containerd/containerd --config $SBX/containerd.toml
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
  put_unit mcsbx-engine-egress.service <<EOF
# Generated by scripts/miner-install/install.sh: engine egress nftables table.
# The rule matches $ENGINE_SLICE by cgroup, so it loads once the slice exists.
[Unit]
Description=SN24 sandbox engine egress table $ENGINE_EGRESS_TABLE
After=mcsbxcontainerd.service
Requires=mcsbxcontainerd.service
Before=mcsbxdockerd.service
PartOf=mcsbxcontainerd.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/bin/test -d /sys/fs/cgroup/$ENGINE_SLICE
ExecStart=/usr/sbin/nft -f $SBX/engine-egress.nft
[Install]
WantedBy=multi-user.target
EOF
  put_unit mcsbxdockerd.service <<EOF
# Generated by scripts/miner-install/install.sh: dedicated sandbox dockerd (runsc default, no bridge/iptables of its own).
[Unit]
Description=SN24 sandbox dockerd $DOCKER_VERSION
Requires=mcsbxcontainerd.service mcsbx-engine-egress.service mcsbx-egress-bridge.service mcsbxleaseanchor.service
After=mcsbxcontainerd.service mcsbx-engine-egress.service mcsbx-egress-bridge.service mcsbxleaseanchor.service
[Service]
Slice=$ENGINE_SLICE
KillMode=control-group
TasksMax=infinity
Environment=PATH=$dd:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$dd/dockerd --config-file $SBX/daemon.json --containerd $SBX/run/containerd/containerd.sock --containerd-namespace mc-sandbox --containerd-plugins-namespace mc-sandbox-plugins
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
  put_unit mscomputer-miner-agent.service <<EOF
# Generated by scripts/miner-install/install.sh. Operator values come from
# $ETC/miner.env. Artifacts come through the signed pull gateway (no credentials).
[Unit]
Description=Ms. Computer SN24 miner Go agent
After=network-online.target docker.service mcsbxdockerd.service $hmount
Wants=network-online.target
Requires=docker.service mcsbxdockerd.service mcsbxdeployanchor.service $hmount
ConditionPathExists=$ETC/miner.env
[Service]
Type=simple
EnvironmentFile=$ETC/miner.env
UMask=0077
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectHome=true
ExecStart=$rel/bin/miner-agent --bind 127.0.0.1:9101 \\
  --network \${MC_NETWORK} --netuid \${MC_NETUID} --hotkey \${MC_HOTKEY_SS58} --uid \${MC_UID} \\
  --bridge-secret-file $ETC/bridge.secret --service-key-file $STATE/agent-service.key --state-db $STATE/agent-state.sqlite \\
  --miner-transport https --tls-certificate-sha256 \${MC_TLS_SHA256} \\
  --artifact-backend pull --artifact-pull-url $ARTIFACT_PULL_URL \\
  --image-registry-login-url $IMAGE_REGISTRY_LOGIN_URL \\
  --runtime docker --docker-state-dir $STATE/oci \\
  --static-sites on --static-cache-dir $STATE/static-cache --static-cache-max-bytes 8589934592 \\
  --qualification on --qualification-plot-dir $STATE/qplot --qualification-plot-workers 2 \\
  --sandbox-leases on --sandbox-host-profile $SBX/profile.json --sandbox-daemon-config $SBX/daemon.json \\
  --sandbox-deployment-cgroup /$DEPLOY_SLICE --sandbox-ops on --sandbox-ops-config $SBX/ops-config.json \\
  --direct-files-bind $DIRECT_FILES_BIND --direct-files-tls-cert $ETC/tls/current/miner.crt \\
  --direct-files-tls-key $ETC/tls/current/miner.key --direct-files-per-sandbox 4 \\
  --system-reserve-mib $SYSTEM_RESERVE_MIB --sandbox-reserve-mib $LEASE_MEMORY_MIB --app-budget-mib 5120 --app-copy-mib 256 \\
  --app-cpu-weight 50 --response-receipts on \$MC_AGENT_EXTRA_ARGS
[Install]
WantedBy=multi-user.target
EOF
  put_unit mscomputer-miner-neuron.service <<EOF
# Generated by scripts/miner-install/install.sh. Operator values come from $ETC/miner.env.
[Unit]
Description=Ms. Computer SN24 miner axon (Python)
After=network-online.target mscomputer-miner-agent.service
Wants=network-online.target
Requires=mscomputer-miner-agent.service
ConditionPathExists=$ETC/miner.env
[Service]
Type=simple
User=mc-miner
Group=mc-miner
EnvironmentFile=$ETC/miner.env
UMask=0077
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectHome=true
ExecStart=$rel/venv/bin/mscomputer-miner --subtensor-network \${MC_NETWORK} --netuid \${MC_NETUID} \\
  --wallet-name \${MC_WALLET} --wallet-hotkey \${MC_HOTKEY} --wallet-path $STATE/wallets --uid \${MC_UID} \\
  --axon-host $AXON_BIND --axon-port \${MC_AXON_PORT} --axon-publish off \\
  --tls-cert-file $ETC/axon-tls/miner.crt --tls-key-file $ETC/axon-tls/miner.key \\
  --go-agent-url http://127.0.0.1:9101 --bridge-secret-file $ETC/bridge.secret --state-db $STATE/axon/axon-nonces.sqlite \\
  --operator-hotkey \${MC_OPERATOR_HOTKEY_SS58} --min-validator-stake 1 \\
  --qualification on --qualification-plots on --sandbox-leases on --sandbox-ops on \$MC_NEURON_EXTRA_ARGS
[Install]
WantedBy=multi-user.target
EOF
  # Private endpoint enrollment: the hotkey and the axon TLS key sign this
  # miner's direct address for the operator; nothing is published on chain.
  # Runs at enable and every 6 h (each enrollment is valid for 24 h).
  put_unit mscomputer-miner-endpoint-enroll.service <<EOF
# Generated by scripts/miner-install/install.sh. Operator values come from $ETC/miner.env.
[Unit]
Description=Ms. Computer SN24 private endpoint enrollment
After=network-online.target mscomputer-miner-neuron.service
Wants=network-online.target
ConditionPathExists=$ETC/miner.env
[Service]
Type=oneshot
User=mc-miner
Group=mc-miner
Environment=MC_PUBLIC_IP=auto
EnvironmentFile=$ETC/miner.env
UMask=0077
NoNewPrivileges=true
ProtectHome=true
# A failed enrollment is retried in 5 minutes, not at the next 6 h renewal.
Restart=on-failure
RestartSec=5min
ExecStart=$rel/venv/bin/mscomputer-miner endpoint-enroll --subtensor-network \${MC_NETWORK} --netuid \${MC_NETUID} \\
  --uid \${MC_UID} --operator-hotkey \${MC_OPERATOR_HOTKEY_SS58} --ip \${MC_PUBLIC_IP} --port \${MC_AXON_PORT} \\
  --wallet-name \${MC_WALLET} --wallet-hotkey \${MC_HOTKEY} --wallet-path $STATE/wallets \\
  --tls-cert-file $ETC/axon-tls/miner.crt --tls-key-file $ETC/axon-tls/miner.key --ttl 86400
EOF
  # Two timers drive the one enrollment service: -first enrolls promptly
  # (90 s after enable or boot, no random delay); the renewal timer then runs
  # it every 6 h with a random delay so miners do not renew in lockstep.
  put_unit mscomputer-miner-endpoint-enroll-first.timer <<EOF
# Generated by scripts/miner-install/install.sh.
[Unit]
Description=Enroll the Ms. Computer SN24 private endpoint after enable or boot
[Timer]
OnActiveSec=90s
AccuracySec=5s
Unit=mscomputer-miner-endpoint-enroll.service
[Install]
WantedBy=timers.target
EOF
  put_unit mscomputer-miner-endpoint-enroll.timer <<EOF
# Generated by scripts/miner-install/install.sh.
[Unit]
Description=Renew the Ms. Computer SN24 private endpoint enrollment
[Timer]
OnUnitActiveSec=6h
RandomizedDelaySec=10min
[Install]
WantedBy=timers.target
EOF
}

write_app_budget() {
  local out
  out=$("$OPT/current/bin/miner-agent" --app-budget-print --system-reserve-mib "$SYSTEM_RESERVE_MIB" \
    --sandbox-reserve-mib "$LEASE_MEMORY_MIB" --app-budget-mib 5120 --app-copy-mib 256 --app-cpu-weight 50)
  install -d -m 0755 "$UNITS/$DEPLOY_SLICE.d"
  put_unit "$DEPLOY_SLICE.d/10-app-budget.conf" < <(
    echo '# Generated by scripts/miner-install/install.sh from miner-agent --app-budget-print.'
    printf '%s\n' "$out" | sed -n '/^\[Slice\]/,$p')
}

prepare_operator_dirs() {
  getent group mc-miner >/dev/null || groupadd --system mc-miner
  id mc-miner >/dev/null 2>&1 || useradd --system --gid mc-miner --home-dir "$STATE/axon" --shell /usr/sbin/nologin mc-miner
  install -d -m 0750 -o root -g mc-miner "$ETC"
  install -d -m 0700 "$STATE" "$STATE/oci" "$STATE/static-cache" "$STATE/qplot"
  chmod 0711 "$STATE"
  install -d -m 0700 -o mc-miner -g mc-miner "$STATE/axon" "$STATE/wallets"
  if [[ ! -s $ETC/bridge.secret ]]; then
    (umask 027; openssl rand -hex 32 > "$ETC/bridge.secret")
    say "generated $ETC/bridge.secret (not printed)"
  fi
  chown root:mc-miner "$ETC/bridge.secret"; chmod 0640 "$ETC/bridge.secret"
  [[ -f $ETC/miner.env.example ]] && cmp -s "$here/miner.env.example" "$ETC/miner.env.example" ||
    install -m 0640 -g mc-miner "$here/miner.env.example" "$ETC/miner.env.example"
}

cmd_install() {
  preflight
  install_packages
  install -d -m 0750 "$ETC"; : > "$MARKER"
  install_engine_binaries
  build_release
  # $OPT/staged: the newest built release (it may not be current yet).
  ln -sfn "$OPT/releases/$COMMIT" "$OPT/staged.new" && mv -T "$OPT/staged.new" "$OPT/staged"
  (( units_changed )) && systemctl daemon-reload
  # Never switch the release (current, and the helper pin in ops-config.json)
  # under a running miner: a Restart=on-failure would silently pick up the
  # new build, and the running axon would import from the new venv.
  local cur
  cur=$(readlink "$OPT/current" 2>/dev/null || true)
  if [[ -n $cur && $cur != "$OPT/releases/$COMMIT" ]] &&
     { systemctl is-active --quiet mscomputer-miner-agent.service || systemctl is-active --quiet mscomputer-miner-neuron.service; }; then
    say "staged release $COMMIT in $OPT/releases; the running miner keeps $cur"
    say "activate it when convenient (the restart interrupts sandbox work in progress):"
    say "  systemctl stop mscomputer-miner-neuron mscomputer-miner-agent && $0 install && $0 enable"
    return 0
  fi
  ln -sfn "$OPT/releases/$COMMIT" "$OPT/current.new" && mv -T "$OPT/current.new" "$OPT/current"
  write_settings
  configure_storage
  write_engine_config
  write_profile
  write_units
  write_app_budget
  prepare_operator_dirs
  systemctl daemon-reload
  # A host enabled by an older release has only the renewal timer, which no
  # longer arms by itself after a boot: enable the first-run timer with it.
  if systemctl is-enabled --quiet mscomputer-miner-endpoint-enroll.timer 2>/dev/null &&
     [[ $(miner_env_value MC_ENDPOINT_ENROLL) != off ]]; then
    systemctl enable mscomputer-miner-endpoint-enroll-first.timer >/dev/null
  fi
  local u
  for u in "$(cat "$SBX/.ops-helper-mount-unit")" mcsbxleaseanchor.service mcsbxdeployanchor.service \
    mcsbx-storage.service mcsbx-egress-bridge.service mcsbxcontainerd.service mcsbx-engine-egress.service mcsbxdockerd.service; do
    systemctl enable "$u" >/dev/null 2>&1 || true
  done
  systemctl start mcsbx-storage.service
  /usr/local/libexec/mcsbx-storage   # applies a grown size on an existing mount
  systemctl start "$(cat "$SBX/.ops-helper-mount-unit")" mcsbxleaseanchor.service mcsbxdeployanchor.service
  if (( units_changed )) && systemctl is-active --quiet mscomputer-miner-agent.service; then
    warn 'unit files changed while the miner runs; the running engine and agent are left as they are. Restarting mcsbxdockerd or mcsbxcontainerd also restarts the miner agent (Requires=), which interrupts sandbox work in progress: apply when convenient'
  fi
  systemctl start mcsbxcontainerd.service mcsbx-engine-egress.service mcsbxdockerd.service
  # Re-apply the engine egress table in place (one atomic nft transaction).
  # Never restart its unit: dockerd Requires= it and would restart too.
  nft -f "$SBX/engine-egress.nft"
  for _ in $(seq 60); do DOCKER_HOST=unix://$SBX/run/docker/docker.sock "$OPT/docker-$DOCKER_VERSION/docker" info >/dev/null 2>&1 && break; sleep 1; done
  note_legacy_tunnel
  say "install complete: $(tr '\n' ' ' < "$OPT/current/BUILDINFO")"
  say "next: fill in $ETC/miner.env (from miner.env.example), the TLS certificate and the wallet hotkey, then: $0 self-test && $0 enable"
}

# ---------------------------------------------------------------------------
# Self-test.
st_fail=0
st() { if "${@:2}" >/dev/null 2>&1; then echo "  pass  $1"; else echo "  FAIL  $1" >&2; st_fail=$((st_fail + 1)); fi; }

cmd_self_test() {
  [[ $EUID == 0 ]] || die 'run as root'
  [[ -e $MARKER ]] || die 'this host was not set up by this installer'
  say "self-test"
  # Check the installed settings only, never ones from the environment.
  unset MCSBX_SANDBOXES MCSBX_DATA_FS_MIB MCSBX_EGRESS_DENY_CIDRS
  load_settings
  local u docker="$OPT/docker-$DOCKER_VERSION/docker" sock=unix://$SBX/run/docker/docker.sock
  for u in mcsbx-storage mcsbx-egress-bridge mcsbxcontainerd mcsbx-engine-egress mcsbxdockerd mcsbxleaseanchor mcsbxdeployanchor docker; do
    st "unit $u active" systemctl is-active --quiet "$u.service"
  done
  for u in $ENGINE_SLICE $LEASE_SLICE $DEPLOY_SLICE; do st "slice $u has a finite memory limit" test "$(cat "/sys/fs/cgroup/$u/memory.max")" != max; done
  st "lease slice cpu.max is ${CPU_MILLIS}m" grep -qx "$((CPU_MILLIS * 100)) 100000" "/sys/fs/cgroup/$LEASE_SLICE/cpu.max"
  st 'data filesystem is XFS with project quota' sh -c "findmnt -n -o FSTYPE,OPTIONS $SBX/data | grep -q '^xfs .*prjquota'"
  st 'run root is a size-limited tmpfs' sh -c "findmnt -n -o FSTYPE,OPTIONS $SBX/run | grep -q '^tmpfs .*size='"
  st "engine egress table $ENGINE_EGRESS_TABLE loaded and bound to the slice" sh -c "nft list table inet $ENGINE_EGRESS_TABLE | grep -q '\"$ENGINE_SLICE\"'"
  st "egress bridge $EGRESS_BRIDGE up" sh -c "ip -br addr show $EGRESS_BRIDGE | grep -q '${EGRESS_GATEWAY%/*}'"
  st 'ops helper on a read-only mount' sh -c "findmnt -n -o OPTIONS --target \"\$(python3 -c 'import json;print(json.load(open(\"$SBX/ops-config.json\"))[\"helper_dir\"])')\" | grep -q '^ro'"
  local report rel commit want_agent recipe
  rel=$(readlink -f "$OPT/current")
  report=$(report_py "$rel")
  st 'profile check-profile (report.py of the installed commit)' "$rel/venv/bin/python" "$report" check-profile "$SBX/profile.json"
  st 'profile meets the SN24 standard floor (check-standard)' "$rel/venv/bin/python" "$report" check-standard "$SBX/profile.json"
  st "runsc is the pinned build" test "$(sha_of "$SBX/bin/runsc")" = "$RUNSC_SHA256"
  commit=$(sed -n 's/^commit=//p' "$rel/BUILDINFO")
  want_agent=$(sed -n 's/^agent_sha256=//p' "$rel/BUILDINFO")
  recipe=$(sed -n 's/^recipe=//p' "$rel/BUILDINFO")
  if [[ $recipe == "$BUILD_RECIPE" && $(sed -n 's/^ref=//p' "$rel/BUILDINFO") == "$PINNED_REF" ]]; then
    want_agent=$PINNED_AGENT_SHA256
  elif [[ -z $recipe && -n $LEGACY_PINNED_COMMIT && $commit == "$LEGACY_PINNED_COMMIT" ]]; then
    want_agent=$LEGACY_AGENT_SHA256
  fi
  st "miner-agent binary hashes to the reviewed ${want_agent:0:12}" test "$(sha_of "$rel/bin/miner-agent")" = "$want_agent"
  st "installed settings match the profile (deny list, data fs)" check_settings_match
  st 'sandbox dockerd default runtime is runsc' sh -c "DOCKER_HOST=$sock $docker info --format '{{.DefaultRuntime}}' | grep -qx runsc"
  st 'axon venv imports' "$OPT/current/venv/bin/python" -c 'import mscomputer_subnet.miner'
  st 'axon entry point starts (mscomputer-miner --help)' "$OPT/current/venv/bin/mscomputer-miner" --help
  # The Go host preflight: the same observations the agent makes before it
  # starts the sandbox lane.
  local obs
  obs=$(mktemp)
  cleanup_paths+=("$obs")
  if "$OPT/current/bin/sandbox-host-observe" -profile "$SBX/profile.json" preflight > "$obs" 2>&1; then
    python3 - "$obs" <<'PY' || st_fail=$((st_fail + 1))
import json, sys
# Same rule as sandboxhost.deriveVerdict: enforced checks must pass,
# unenforced ones are recorded gaps.
checks = json.load(open(sys.argv[1]))
bad = 0
for c in checks:
    want = 'gap' if c['class'] == 'unenforced' else 'pass'
    ok = c['status'] == want
    bad += not ok
    print(f"  {'pass ' if ok else 'FAIL '} observe {c['id']}: {c['status']}" + ('' if ok else f" ({c['evidence'][:200]})"))
sys.exit(1 if bad or not checks else 0)
PY
  else
    echo "  FAIL  sandbox-host-observe preflight: $(head -c 400 "$obs")" >&2; st_fail=$((st_fail + 1))
  fi
  rm -f "$obs"
  # A real gVisor sandbox on the dedicated daemon, network none, inside the
  # lease slice.
  local out name=mcsbx-selftest-$$
  if DOCKER_HOST=$sock "$docker" pull -q "$SELFTEST_IMAGE" >/dev/null 2>&1; then
    out=$(DOCKER_HOST=$sock "$docker" run --rm --name "$name" --network none --pids-limit 64 --memory 256m "$SELFTEST_IMAGE" dmesg 2>&1 || true)
    if grep -qi 'gvisor' <<<"$out"; then echo '  pass  container runs under gVisor (network none, lease slice)'
    else echo "  FAIL  container did not run under gVisor: ${out:0:300}" >&2; st_fail=$((st_fail + 1)); fi
    DOCKER_HOST=$sock "$docker" rmi -f "$SELFTEST_IMAGE" >/dev/null 2>&1 || true
  else
    echo '  FAIL  could not pull the self-test image through the sandbox daemon (engine egress or network)' >&2; st_fail=$((st_fail + 1))
  fi
  if [[ -f $ETC/miner.env ]]; then
    st 'miner.env complete' check_miner_env
  else
    echo "  note  $ETC/miner.env not present yet (the agent and axon stay stopped)"
  fi
  (( st_fail == 0 )) || die "self-test: $st_fail check(s) failed"
  say 'self-test passed'
}

check_settings_match() {
  local deny fs
  deny=$(sed -n 's/^MCSBX_EGRESS_DENY_CIDRS="\([^"]*\)"$/\1/p' "$SETTINGS")
  fs=$(sed -n 's/^MCSBX_DATA_FS_MIB=\([0-9]*\)$/\1/p' "$SETTINGS")
  python3 - "$SBX/profile.json" "$deny" "$fs" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
assert ' '.join(p['egress']['deny_cidrs']) == sys.argv[2], 'deny_cidrs'
assert p['aggregate']['data_fs_mib'] == int(sys.argv[3]), 'data_fs_mib'
PY
  (( $(stat -c %s "$SBX/data.xfs") >= fs * 1048576 ))
}

check_miner_env() {
  local v
  # shellcheck disable=SC1090,SC1091
  ( set -a; . "$ETC/miner.env"
    for v in MC_NETWORK MC_NETUID MC_HOTKEY_SS58 MC_UID MC_WALLET MC_HOTKEY MC_AXON_PORT MC_TLS_SHA256 MC_OPERATOR_HOTKEY_SS58; do
      [[ -n ${!v:-} && ${!v} != *'<'* ]] || { echo "$v is unset in $ETC/miner.env" >&2; exit 1; }
    done
    [[ $MC_TLS_SHA256 =~ ^[0-9a-f]{64}$ ]] || { echo 'MC_TLS_SHA256 must be 64 lowercase hex' >&2; exit 1; }
    [[ ${MC_PUBLIC_IP-auto} == auto || ${MC_PUBLIC_IP-} =~ ^[0-9a-fA-F.:]{2,45}$ ]] || { echo 'MC_PUBLIC_IP must be auto or a numeric IP' >&2; exit 1; }
    [[ ${MC_ENDPOINT_ENROLL-on} == on || ${MC_ENDPOINT_ENROLL-} == off ]] || { echo 'MC_ENDPOINT_ENROLL must be on or off' >&2; exit 1; }
    [[ -f $ETC/tls/current/miner.crt && -f $ETC/tls/current/miner.key ]] || { echo "no TLS certificate under $ETC/tls (scripts/manage-miner-tls.sh issue)" >&2; exit 1; }
    [[ -d $STATE/wallets/$MC_WALLET/hotkeys && -f $STATE/wallets/$MC_WALLET/hotkeys/$MC_HOTKEY ]] || { echo "hotkey $MC_WALLET/$MC_HOTKEY not under $STATE/wallets" >&2; exit 1; }
  )
}

cmd_enable() {
  [[ $EUID == 0 ]] || die 'run as root'
  [[ -e $MARKER ]] || die 'this host was not set up by this installer'
  [[ -f $ETC/miner.env ]] || die "create $ETC/miner.env from $ETC/miner.env.example first"
  check_miner_env || die "$ETC/miner.env is incomplete"
  [[ ! -e $ETC/artifact-store.env ]] || warn "$ETC/artifact-store.env is no longer used (artifacts come through the pull gateway) and is safe to delete: rm $ETC/artifact-store.env (nothing to revoke on your side)"
  # The agent (root) reads the TLS pair from $ETC/tls, which stays root-only
  # (manage-miner-tls.sh layout). The axon gets its own copy in a root-owned
  # directory it can read but not write ($ETC/axon-tls, root:mc-miner 0750);
  # the copied key must be owned by mc-miner 0600 because the axon refuses a
  # group-readable key. A compromised mc-miner can therefore not replace the
  # agent's TLS identity. Run enable again after a TLS rotation.
  chown -R root:root "$ETC/tls"
  install -d -m 0750 -o root -g mc-miner "$ETC/axon-tls"
  install -m 0644 -o root -g mc-miner "$ETC/tls/current/miner.crt" "$ETC/axon-tls/miner.crt"
  install -m 0600 -o mc-miner -g mc-miner "$ETC/tls/current/miner.key" "$ETC/axon-tls/miner.key"
  chown -R mc-miner:mc-miner "$STATE/wallets"
  chmod 0640 "$ETC/miner.env"; chgrp mc-miner "$ETC/miner.env"
  systemctl enable mscomputer-miner-agent.service mscomputer-miner-neuron.service >/dev/null
  systemctl start mscomputer-miner-agent.service mscomputer-miner-neuron.service
  # Enroll the direct address privately (in ~90 s, then every 6 h). Opt out
  # with MC_ENDPOINT_ENROLL=off in miner.env and ask the operator instead.
  # The restart re-arms the 90 s first-run countdown on every enable.
  if [[ $(miner_env_value MC_ENDPOINT_ENROLL) == off ]]; then
    systemctl disable --now mscomputer-miner-endpoint-enroll-first.timer mscomputer-miner-endpoint-enroll.timer >/dev/null 2>&1 || true
  else
    systemctl enable mscomputer-miner-endpoint-enroll-first.timer mscomputer-miner-endpoint-enroll.timer >/dev/null
    systemctl restart mscomputer-miner-endpoint-enroll-first.timer mscomputer-miner-endpoint-enroll.timer
  fi
  say 'agent and axon started (direct serving, publication off); follow: journalctl -fu mscomputer-miner-agent -u mscomputer-miner-neuron'
  note_legacy_tunnel
  say "direct miner enabled; private endpoint enrollment runs within ~2 min (to enroll now: systemctl start mscomputer-miner-endpoint-enroll; log: journalctl -u mscomputer-miner-endpoint-enroll)"
}

miner_env_value() {  # name
  # shellcheck disable=SC1090,SC1091
  (set -a; . "$ETC/miner.env"; printf '%s' "${!1:-}")
}

readonly TUNNEL_RETIRED='connect-out tunnels are retired; validators reach miners directly after endpoint enrollment (docs/miner-endpoint-enrollment.md)'

cmd_tunnel() {
  die "$TUNNEL_RETIRED"
}

# A legacy connect-out tunnel unit is left as it is (never stopped here).
note_legacy_tunnel() {
  [[ -e $UNITS/mscomputer-tunnel.service ]] || return 0
  warn "legacy $UNITS/mscomputer-tunnel.service found: $TUNNEL_RETIRED. It is left untouched; once endpoint enrollment succeeds (journalctl -u mscomputer-miner-endpoint-enroll), disable it: systemctl disable --now mscomputer-tunnel.service"
}

cmd_status() {
  local u
  for u in mcsbx-storage mcsbx-egress-bridge mcsbxcontainerd mcsbx-engine-egress mcsbxdockerd mscomputer-miner-agent mscomputer-miner-neuron; do
    printf '%-28s %s\n' "$u" "$(systemctl is-active "$u.service" 2>/dev/null || true)"
  done
  for u in endpoint-enroll-first endpoint-enroll; do
    printf '%-28s %s\n' "$u.timer" "$(systemctl is-enabled mscomputer-miner-$u.timer 2>/dev/null || true)/$(systemctl is-active mscomputer-miner-$u.timer 2>/dev/null || true)"
  done
  local last
  last=$(systemctl show -P ExecMainExitTimestamp mscomputer-miner-endpoint-enroll.service 2>/dev/null || true)
  if [[ -n $last ]]; then
    last="$(systemctl show -P Result mscomputer-miner-endpoint-enroll.service 2>/dev/null || true) at $last"
  else
    last='not run yet'
  fi
  printf '%-28s %s\n' endpoint-enroll.last "$last"
  [[ -f $OPT/current/BUILDINFO ]] && cat "$OPT/current/BUILDINFO"
  # Any non-loopback client in the axon access log reached it directly.
  local log direct
  log=$(journalctl -u mscomputer-miner-neuron --since -30min -o cat --no-pager 2>/dev/null | grep -F 'uvicorn.access' || true)
  direct=$(grep -E '[0-9a-f.:]+:[1-9][0-9]* - ' <<<"$log" | grep -cvE '"(127\.[0-9.]+|::1):' || true)
  echo "axon requests in the last 30 min: direct $direct"
  return 0
}

case ${1:-} in
  preflight) preflight ;;
  install) cmd_install ;;
  self-test) cmd_self_test ;;
  enable) cmd_enable ;;
  tunnel) cmd_tunnel ;;
  status) cmd_status ;;
  *) echo "usage: $0 preflight|install|self-test|enable|tunnel (retired)|status" >&2; exit 2 ;;
esac
