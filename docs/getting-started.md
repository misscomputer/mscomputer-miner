# Getting started

This page gets a fresh machine from `git clone` to a verified install.
The optional chain check reads a public network; nothing on this page
registers a key, spends TAO, or sends a transaction. Miner setup continues in
the [miner quickstart](miner-quickstart.md).

## What runs where

| Step | Where it runs | Touches a live network? |
| --- | --- | --- |
| Install, lint, unit tests | your machine | no |
| Mock-mode miner smoke test (below) | your machine, loopback only | no |
| Read-only chain check (below) | your machine | reads public chain state only |
| Wallet creation | your machine | no |
| Hotkey registration | your machine | **yes: sends transactions** |
| Miner services | your server | **yes** |

## Prerequisites

| Requirement | Version | Why |
| --- | --- | --- |
| Linux, x86_64 | any current distribution | Miner workloads run as `linux/amd64` containers; the miner TLS loader uses `memfd_create`, which is Linux-only |
| Python | **3.12 exactly** (`requires-python = "==3.12.*"`) | Python miner axon |
| Go | 1.23.x (`go.mod` toolchain `go1.23.12`) | Builds the miner's Go agent |
| `git`, `openssl`, `curl`, `sha256sum` | any | Install, TLS certificates, health checks, digests |
| Docker Engine and `iptables` | current | Runs assigned workloads; see the [miner quickstart](miner-quickstart.md) |
| `btcli` (package `bittensor-cli`) | current | Wallet creation and registration; installed separately from this repository |

The Python package pins its runtime dependencies exactly, including
`bittensor==11.1.0`. Install it into its own virtual environment so those pins
do not collide with other Bittensor tooling on the same host. Install `btcli`
into a separate environment for the same reason.

## Install

Use a release tag (`vX.Y.Z`); see [verify-release.md](verify-release.md) to
check the published artifacts.

```bash
git clone https://github.com/misscomputer/mscomputer-miner.git
cd mscomputer-miner
git checkout vX.Y.Z

python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip check
```

`python -m pip check` should print `No broken requirements found.`

The install adds the `mscomputer-miner` console script to `.venv/bin`: the
public HTTPS miner axon, which talks to the local Go agent. It prints normal
`--help` output.

Build the Go agent:

```bash
go build -o build/miner-agent ./cmd/miner-agent
./build/miner-agent -h
```

`build/` is ignored by git.

## Run the repository checks (optional, local)

These need the development extras:

```bash
python -m pip install -e '.[dev]'
ruff check src tests
ruff format --check src tests
mypy src
pytest -q
go vet ./...
go test ./...
```

No test contacts a live chain. The real-engine Docker test is opt-in and
skipped by default: it needs `MSCOMPUTER_DOCKER_OCI_TEST=1` and root (see
[`miner-oci-runtime.md`](miner-oci-runtime.md)).

## Local smoke test: mock-mode miner

This starts only the Python miner axon against an in-process mock chain, on
loopback, over plain HTTP. It needs no wallet, no Go agent, no Docker, and no
network access. It proves the install works and shows what healthy logs look
like.

```bash
mkdir -p /tmp/mc-smoke && cd /tmp/mc-smoke
(umask 077; openssl rand -hex 32 > bridge.secret)

cat > peers.json <<'EOF'
[
  {"uri": "//Alice", "uid": 0, "axon": "127.0.0.1:8091"},
  {"uri": "//Bob", "uid": 1, "validator_permit": true, "tao_stake": 5000}
]
EOF

mscomputer-miner \
  --netuid 1 --subtensor-network mock \
  --mock-uri //Alice --mock-peers ./peers.json \
  --allow-insecure-mock-http \
  --axon-host 127.0.0.1 --axon-port 18091 \
  --bridge-secret-file ./bridge.secret \
  --state-db ./miner-nonces.sqlite
```

`//Alice` and `//Bob` are the well-known public development keys; they are not
secrets and must never hold funds. In a second terminal:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18091/healthz
```

Expected: `204`. This health-only smoke test intentionally configures no
operator hotkeys, so all signed control requests are denied. A real serving
setup configures the operator hotkey explicitly (see the
[miner quickstart](miner-quickstart.md)).
The miner logs one JSON object per line on stderr, including:

```text
{"timestamp":"...","level":"info","logger":"mscomputer_subnet.miner","message":"metagraph synchronized","hotkey":"<alice-ss58>","block":...}
```

Stop it with Ctrl+C. If you change `--mock-uri` to a key that is not in
`peers.json` (for example `//Charlie`), `/healthz` returns `503` and the log
shows `miner hotkey is not uniquely registered`; that is the same signal a live miner
gives before its hotkey is registered.

Mock mode is a local development aid only. `--allow-insecure-mock-http`
refuses to start without `--mock-uri`, and a live miner refuses to start
without TLS files.

## Read-only chain check

Before and after registering, confirm what the chain reports for a hotkey. This
uses the same chain adapter as the miner, reads the finalized head, and sends
no transaction:

```bash
python - <<'EOF'
import asyncio

from mscomputer_subnet.chain import BittensorChain

NETWORK = "finney"             # or "test"
NETUID = 0                     # replace with the subnet netuid
HOTKEY = "<hotkey-ss58>"       # public address only


async def main() -> None:
    chain = BittensorChain(network=NETWORK, netuid=NETUID)
    await chain.open()
    try:
        snapshot = await chain.sync()
        print(f"block={snapshot.block} finalized={snapshot.finalized} tempo={snapshot.tempo}")
        record = snapshot.by_hotkey(HOTKEY)
        if record is None:
            print("hotkey is not registered on this subnet")
        else:
            print(
                f"uid={record.uid} active={record.active} "
                f"validator_permit={record.validator_permit} "
                f"tao_stake={record.tao_stake} axon={record.axon}"
            )
    finally:
        await chain.close()


asyncio.run(main())
EOF
```

Expected output looks like `block=<n> finalized=True tempo=<n>` followed by
either your UID line or `hotkey is not registered on this subnet`. The miner
accepts a uniquely registered record even when `active` is `False`. Miners do
not publish an axon on chain, so `axon=` shows no address (or an old one);
validators use the enrolled endpoint
([miner-endpoint-enrollment.md](miner-endpoint-enrollment.md)).

## Networks and netuids

- The Bittensor SDK network names are `finney` (mainnet) and `test`
  (testnet). `mscomputer-miner` defaults `--subtensor-network` to
  `BT_NETWORK` when set, otherwise `finney`.
- This repository does not publish a testnet deployment or netuid. Always pass
  `--netuid` explicitly and take the value from the subnet's official
  announcements (mainnet is subnet 24).

## Next steps

- Keys and secret files: [keys-and-secrets.md](keys-and-secrets.md)
- Run a miner: [miner-quickstart.md](miner-quickstart.md)
- Something failed: [troubleshooting.md](troubleshooting.md)
