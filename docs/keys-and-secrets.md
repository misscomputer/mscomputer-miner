# Keys, secrets, and state files

Every credential and durable state file a miner uses, where it comes from, and
how to protect it. The software refuses several unsafe configurations on its
own (noted below), but it cannot protect a key you have already copied
somewhere unsafe.

## Ground rules

- **Never commit** a wallet, hotkey, private key, bridge secret, certificate,
  or state database. Keep all of these files outside the repository
  checkout.
- **Never paste** a mnemonic, private key, or secret file into an
  issue, chat, log excerpt, or AI assistant prompt. Share public SS58
  addresses, certificate fingerprints, and SHA-256 digests instead.
- **Keep the coldkey off servers.** The miner processes load only the hotkey
  (`bt.Wallet(name, hotkey, path=...)` resolved to a hotkey signer). Create
  and register the wallet on a trusted workstation and copy only the hotkey
  files to the server.
- **One value per host.** Generate bridge secrets per host; never reuse them.
- Examples in these docs use placeholders such as `<hotkey-ss58>` or
  `<NETUID>`. Replace them with your own values; never with a value copied
  from another operator.

## Inventory

| Item | Created by | Required protection | Loss/rotation impact |
| --- | --- | --- | --- |
| Coldkey (wallet) | `btcli wallet new-coldkey` | Offline or on a trusted workstation; encrypted; mnemonic backed up offline | Controls funds and registration. Not needed on the server |
| Hotkey (wallet) | `btcli wallet new-hotkey` | Owner-only files under the wallet path on the server | Identity on the subnet; a new hotkey needs a new registration |
| Miner TLS private key | `scripts/manage-miner-tls.sh issue` | Mode `0600`, never group/world readable (the miner refuses to start otherwise) | Rotate any time; validators re-pin after a fresh capability handshake |
| Miner TLS certificate | same | Public; its SHA-256 is the transport pin | Must list the public IP the miner enrolls with `endpoint-enroll` |
| Bridge secret | you, e.g. `openssl rand -hex 32` | Owner-only; ≥ 32 bytes after trimming whitespace; different per host | Both local processes must read the same value; rotate by replacing it and restarting both |
| Go service key | auto-created by `miner-agent` at `--service-key-file` (mode `0600`) | Owner-only; the agent refuses a group/world-accessible key | Signs receipts and attestations. A new key is picked up through the next hotkey-signed handshake; keep it persistent and backed up to avoid churn |
| Artifact access | none | Miners use `--artifact-backend pull` and hold no storage credential | Reads are signed with the agent service key |
| Miner state databases | the processes | Owner-only | Nonce/replay and assignment state; keep across restarts |

## Wallet creation (trusted workstation)

`btcli` is a separate package (`pip install bittensor-cli` in its own virtual
environment). Commands below were checked against `btcli` 9.23; confirm with
`btcli <command> --help` for your version.

```bash
btcli wallet new-coldkey --wallet-name '<wallet-name>'
btcli wallet new-hotkey --wallet-name '<wallet-name>' --hotkey '<hotkey-name>'
```

Write the mnemonics down offline. Then copy only the hotkey to the server,
keeping the default layout so `--wallet-name`, `--wallet-hotkey`, and
`--wallet-path` resolve it:

```text
~/.bittensor/wallets/<wallet-name>/hotkeys/<hotkey-name>
```

Restrict it to the account that runs the miner:

```bash
chmod 700 ~/.bittensor ~/.bittensor/wallets ~/.bittensor/wallets/<wallet-name> \
  ~/.bittensor/wallets/<wallet-name>/hotkeys
chmod 600 ~/.bittensor/wallets/<wallet-name>/hotkeys/<hotkey-name>
```

`btcli` creates hotkeys without a password by default, which the unattended
miner needs; coldkeys are password-protected by default, so keep them that
way. Registration is a chain transaction paid from the coldkey, so run it
where the coldkey lives. The miner publishes nothing on chain; it enrolls its
endpoint with a hotkey-signed request from the server (see
[miner-endpoint-enrollment.md](miner-endpoint-enrollment.md)).

## Secret files: create them safely

Create secret files with a restrictive umask so they are never briefly
world-readable:

```bash
(umask 077; openssl rand -hex 32 > /etc/mscomputer-miner/bridge.secret)
```

Pass secrets by **file path** (`--bridge-secret-file`) rather than on the
command line, where they would appear in process listings and shell history.
The Go agent can fall back to the `MS_BRIDGE_SECRET` environment variable, but
a file is preferred.

## Backups

- Back up wallets (mnemonics offline) and the miner Go service key.
- Take backups of state databases only while the miner is stopped,
  preserving owner, mode, and bytes.
