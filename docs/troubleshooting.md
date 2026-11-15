# Troubleshooting

Messages below are quoted from the code so you can search for them verbatim.
Start with the health checks, then find the exact message.

## Quick health checks

| Check | Command | Healthy |
| --- | --- | --- |
| Miner Go agent up | `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9101/healthz` | `204` |
| Miner axon synced | `curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:8091/healthz` | `204` (`503` = not registered, wrong UID, or chain sync failing) |
| Miner reachable from outside | same `curl -sk` against `https://<public-ip>:<port>/healthz` from another host | `204` |
| Miner TLS pin | `sudo scripts/manage-miner-tls.sh check /etc/mscomputer-miner/tls` | `leaf sha256` equals the agent's `--tls-certificate-sha256` |
| Organic network | `docker network inspect mscomputer-organic --format '{{.Internal}}'` | `true` |
| Host isolation rule | `sudo iptables -C INPUT -i ms-organic0 -m conntrack --ctstate NEW -j DROP` | exit `0` |
| Sandbox host (installer hosts) | `sudo scripts/miner-install/install.sh self-test` | exit `0` |
| Chain registration | [read-only chain check](getting-started.md#read-only-chain-check) | unique UID/hotkey (`axon=` is not used) |
| Endpoint enrolled (installer hosts) | `journalctl -u mscomputer-miner-endpoint-enroll -n 5 -o cat` | a recent `{"expires": ..., "ip": ..., "port": ..., "uid": ...}` or `already enrolled with this address recently; nothing to do` line |
| Image mirror admits this host | `curl -s -o /dev/null -w '%{http_code}\n' https://mirror.ms.computer/v2/` from the miner host | `200` (`401` = this address is not admitted, see [Image mirror access](#image-mirror-access)) |

## `mscomputer-miner` refuses to start

| Message | Cause and fix |
| --- | --- |
| `live miner startup requires --tls-cert-file and --tls-key-file` | Live mode always needs TLS. Issue a certificate with `scripts/manage-miner-tls.sh issue` ([miner quickstart, Step 4](miner-quickstart.md#step-4-issue-the-tls-certificate)). |
| `--allow-insecure-mock-http requires --mock-uri` | Plain HTTP is only for the local mock chain. Remove the flag for live use. |
| `mock HTTP cannot be combined with TLS certificate options` | Choose mock HTTP *or* TLS, not both. |
| `TLS private key permissions must not grant group or other access` | `chmod 600` the key and make sure the user running the axon owns it. |
| `TLS files must be regular non-symlink files` | Point at the files inside the release (`.../tls/current/miner.crt` works; the file itself must not be a symlink). |
| `TLS leaf certificate is expired` / `... is not yet valid` | Rotate the certificate; check the host clock. |
| `TLS leaf certificate must declare CA=false` / `... must not be a CA certificate` | Use the bundled script; it issues the required non-CA leaf. |
| `TLS certificate and private key do not match` / `... do not form a loadable pair` | Certificate and key come from different releases. Use the same `current/` directory for both. |
| `bridge secret must contain at least 32 bytes` | Regenerate: `openssl rand -hex 32` into the secret file. |
| `FileNotFoundError: keyfile at '.../hotkeys/<name>' does not exist` | Wrong `--wallet-name`, `--wallet-hotkey`, or `--wallet-path`, or the hotkey file was not copied to the server. |

## Axon runs but `/healthz` is `503`

| Log message | Cause and fix |
| --- | --- |
| `miner hotkey is not uniquely registered` | The hotkey is missing or duplicated in the metagraph of `--netuid` on `--subtensor-network`. Check wallet, network, and netuid, then register if absent. `active=False` alone does not make the miner unready. |
| `miner UID identity conflicts` | Another metagraph record has the same UID. Resolve the chain identity conflict before serving. |
| `configured UID differs from metagraph` | `--uid` is stale (for example after re-registration). Set it to the UID shown by the chain check, on both processes. |
| `metagraph synchronization failed` (with exception) | The chain read failed. Check network access to the chain endpoint and the `--subtensor-network` value. |

## Validators reach you but nothing is assigned

Look at the status codes in the axon's access log (`uvicorn.access` lines):

| Response | Meaning and fix |
| --- | --- |
| `503 metagraph is not ready` | See the `503` table above. |
| `401` | btauth signature, nonce, or freshness failure. Usually the caller's problem; if every request fails, check the host clock. |
| `403 caller is not uniquely registered on this subnet` / `caller lacks a validator permit` / `caller stake is below policy minimum` | Normal filtering of absent or ambiguous hotkeys, non-validators, or low-stake callers (`--min-validator-stake`, default `1000`). |
| `429 validator request rate exceeded` | One caller exceeded 120 requests per 60 seconds. |
| `409 request block is stale or from the future` | Your chain view and the validator's differ by more than two blocks. Check sync logs and `--sync-interval`. |
| `500 local Go identity is misconfigured` | The axon and agent disagree on network, netuid, hotkey, UID, transport, or TLS pin. Compare every row of [Values that must match](miner-quickstart.md#values-that-must-match). A common cause is starting the agent without `--uid` or with the default `--network local`. |
| `403 ticket Bittensor identity mismatch` | The ticket was issued for a different UID, pin, or block window than you are serving now (for example right after a certificate rotation or re-registration). New tickets after the next handshake will match. |
| `502 runtime unavailable` | The axon cannot reach the Go agent. Check the agent process and `--go-agent-url`. |

Also check:

- The enrolled IP is public and numeric, TCP 8091 and 8094 are open inbound,
  and the certificate was issued for exactly that IP. Validators connect to
  the enrolled address, never to private addresses; check the latest
  enrollment with `journalctl -u mscomputer-miner-endpoint-enroll -n 20` (see
  [miner-endpoint-enrollment.md](miner-endpoint-enrollment.md)).
- The agent started without errors; it advertises `organic-oci-v1` only after
  its Docker network and host isolation checks passed. Without that feature
  the miner receives no app assignments.

## `miner-agent` refuses to start

| Message | Cause and fix |
| --- | --- |
| `network, hotkey, service-key-file, and state-db are required` | Pass `--network`, `--hotkey`, `--service-key-file`, and `--state-db`. |
| `HTTPS miner transport requires a canonical lowercase TLS certificate SHA-256` | Pass `--tls-certificate-sha256` with the 64-character lowercase `leaf sha256` printed by the TLS script. |
| `pinless HTTP miner transport requires --allow-insecure-mock-http on an explicit local/mock network` | `--miner-transport http` is for local mocks only. Use the default `https` live. |
| `refusing non-loopback bridge bind without explicit override` | Keep `--bind` on loopback. `--allow-non-loopback` is unsafe unless the bridge is isolated some other way. |
| `bridge secret must contain at least 32 bytes` | Same secret file as the axon, at least 32 bytes. |
| `service signing key file must not be group/world accessible` | `chmod 600` the service key. |
| `service signing key file is invalid` | The file is not a hex Ed25519 key written by the agent. Restore it from backup; delete it only if you accept a new service key. |
| `invalid artifact pull configuration: ...` | `--artifact-backend pull` needs an `https` `--artifact-pull-url` and no `--artifact-dir`. The public agent has no `--s3-*` flags: remove any from hand-written units (`flag provided but not defined`). |
| `s3 resolve "...": HTTP 401 (authentication)` | The pull gateway sees no live service binding for this hotkey and key: axon and agent up, same `--service-key-file`, clock in sync (NTP). |
| `artifact directory is required for filesystem backend` | `--artifact-backend file` needs `--artifact-dir`. |
| `create organic network: ...` / `inspect organic network: ...` | Docker is not running or the agent lacks Docker access. Run the agent as root or with Docker access. |
| `organic network mscomputer-organic is "...", want "bridge true false false ms-organic0"` | A network with that name exists with other settings. Remove it (`docker network rm mscomputer-organic`) when no replicas use it, and restart. |
| `install host isolation rule: ...` | The agent cannot run `iptables`. Run it as root (or with `CAP_NET_ADMIN`). |
| `host isolation rule is missing (iptables -I INPUT -i ms-organic0 -m conntrack --ctstate NEW -j DROP)` | You used `--host-isolation verify` without installing the rule. Install it, or use the default `enforce`. |
| `restart cleanup: ...` | Removing replicas from the previous run failed. Check `docker ps -a` and Docker's health, then restart; failed cleanups are retried. |
| `sandbox host profile does not meet the sandbox standard` | The host profile lacks the `egress` member, restates another image cap, or declares less than the floor. See [miner-sandbox-gvisor-backend.md](miner-sandbox-gvisor-backend.md#mandatory-sandbox-standard); re-run the installer. |
| `netuid or UID exceeds uint16` | Check `--netuid` and `--uid`. |

## Bridge authentication failures

Every call between the axon and the agent is HMAC-signed. The agent answers
`401` with code `unauthorized` and one of these messages:

| Message | Fix |
| --- | --- |
| `invalid bridge signature` | The two processes read different secrets. Point both at the same file and restart both. |
| `stale bridge request` | Requests older than 10 seconds or more than 2 seconds in the future. Fix the host clock. |
| `replayed bridge request` | A nonce was reused; should not happen with the shipped client. |

## Assignments fail

The agent returns a signed `failed` receipt with one error code
(details in [miner-oci-runtime.md](miner-oci-runtime.md)):

| Code | Typical cause |
| --- | --- |
| `artifact_fetch_failed` | Artifact store or pull gateway unreachable, or the gateway refused the read (see the agent log). |
| `artifact_verify_failed` | A digest, size, or policy check failed. Never retried with different bytes. |
| `image_load_failed` | `docker load` failed. |
| `image_identity_mismatch` | The engine reported an unexpected image ID. |
| `container_create_failed` | `docker run` or network attach failed. |
| `resource_exhausted` | Disk full (`ENOSPC`). Free space under `--docker-state-dir` and Docker's data root. |
| `deactivated` | The assignment was deactivated while it was starting. |
| `app_budget_exhausted` (HTTP 503, no receipt) | The host's app budget is full; see [App budget](miner-oci-runtime.md#app-budget). |

## Static sites fail

| Code or log | Typical cause and fix |
| --- | --- |
| `static_server_implementation_mismatch` | The ticket names a different static-handler digest than the one this miner was built with: the log line reads `ticket names handler sha256:<A>, this miner implements sha256:<B>`. The build is not the released one (modified `pkg/static` sources, or a hand build from an unreleased commit). Reinstall the current release with the installer, which checks the agent digest, then confirm `sha256sum /opt/mscomputer-miner/current/bin/miner-agent` equals the release's `SHA256SUMS` entry ([verify-release.md](verify-release.md)). See [Server implementation digest](miner-static-sites.md#server-implementation-digest). |

Find static refusals with
`journalctl -u mscomputer-miner-agent --since -1h -o cat | grep static_`.

## Image mirror access

Sandbox images come from `mirror.ms.computer`, which only admits addresses of
miners with a current endpoint enrollment (admission follows a new enrollment
within a few minutes). From the miner host:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://mirror.ms.computer/v2/
```

- `200`: this host's outbound address is admitted.
- `401`: not admitted. Check that enrollment succeeded
  (`journalctl -u mscomputer-miner-endpoint-enroll -n 20`), enroll again with
  `sudo systemctl start mscomputer-miner-endpoint-enroll`, and wait a few
  minutes. If the host's outbound address differs from the address it
  enrolled (`MC_PUBLIC_IP`), the mirror sees the outbound one; it must be the
  enrolled address.

The check is read-only and uses no credentials; the agent's own pulls still
log in with the service key.

## Sandboxes fail

| Code or log | Typical cause and fix |
| --- | --- |
| `egress_firewall_unavailable` | The agent could not load or verify its nft tables. Check the agent log at error level and that `nft` works; restart the agent if the tables cannot be reloaded. |
| `image_unavailable`, `image_too_large`, `isolation_unsupported`, `network_policy_unsupported`, `capability_unsupported` | Tenant-side refusals; no action needed. |
| `failed/miner_restart` | The agent restarted while the sandbox existed. Avoid restarts while sandboxes run (see [Upgrades and restarts](miner-installer.md#upgrades-and-restarts)). |
