# Ms. Computer SN24 miner

Miner software for Bittensor subnet 24 (Ms. Computer): the Python axon
(`mscomputer-miner`) and the Go miner agent (`cmd/miner-agent`) that run
customer workloads in an isolated sandbox runtime on your host.

| Goal | Guide |
| --- | --- |
| Install and verify locally | [docs/getting-started.md](docs/getting-started.md) |
| Keys, wallets and TLS | [docs/keys-and-secrets.md](docs/keys-and-secrets.md) |
| Run a miner | [docs/miner-quickstart.md](docs/miner-quickstart.md) |
| One-command installer | [docs/miner-installer.md](docs/miner-installer.md) |
| Endpoint enrollment | [docs/miner-endpoint-enrollment.md](docs/miner-endpoint-enrollment.md) |
| Verify a release | [docs/verify-release.md](docs/verify-release.md) |
| Troubleshooting | [docs/troubleshooting.md](docs/troubleshooting.md) |

Validators continuously check that registered miners run the published agent
with the resources they advertise and serve work correctly. Miners serve
directly on their public IP (inbound TCP 8091 and 8094), publish no axon on
chain and need no tunnel; validators learn the address through signed endpoint
enrollment. After `enable`, qualification takes about 4 hours before a miner
can earn. Keep the agent running, keep it up to date, and do not modify it.

Proprietary, source-available: you may build and run it unmodified to mine SN24 (see `LICENSE`). Security reports: see `SECURITY.md`.
