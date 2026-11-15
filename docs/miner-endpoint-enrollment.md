# Private endpoint enrollment

Validators reach your miner directly at its public IP and axon port, but the
address is never published on chain. Instead the miner privately enrolls its
address with the subnet operator at `https://api.ms.computer/v1/miner-endpoint`,
and the enrollment expires unless it is renewed.

Enrollment also admits the miner's address to the operator's image mirror,
so a miner that publishes no axon can still pull sandbox images.

## Installer (default)

`install.sh enable` starts two timers for one service: it enrolls within
about 2 minutes of enable (and of every boot), then renews every 6 hours;
a failed run is retried every 5 minutes (until it succeeds, so fix a
persistent refusal such as an unregistered hotkey or opt out).
To enroll right away, run
`sudo systemctl start mscomputer-miner-endpoint-enroll`. Each enrollment is
valid for 24 hours, so a miner that stays down for a day drops out of routing
by itself. Check it with:

```sh
systemctl list-timers 'mscomputer-miner-endpoint-enroll*'
journalctl -u mscomputer-miner-endpoint-enroll -n 20
```

A successful run prints `{"expires": ..., "ip": ..., "port": ..., "uid": ...}`.

Optional settings in `/etc/mscomputer-miner/miner.env`:

- `MC_PUBLIC_IP=<ip>`: the public IP validators should dial. The default,
  `auto`, uses the address the enrollment request comes from. Set it when your
  outbound traffic leaves through a different address than the one the axon
  listens on.
- `MC_ENDPOINT_ENROLL=off`: disables the timer. Run `install.sh enable` again
  after changing either setting.

## Manual or custom setups

Run this as the user that can read the hotkey and the axon TLS key:

```sh
mscomputer-miner endpoint-enroll --netuid 24 --uid <your uid> \
  --operator-hotkey <operator hotkey from miner.env.example> \
  --port <public axon port> [--ip <public ip>] \
  --wallet-name <wallet> --wallet-hotkey <hotkey> \
  --tls-cert-file <axon cert> --tls-key-file <axon key>
```

Re-run it at least every 24 hours (`--ttl`, 600 s to 7 days) from cron or a
systemd timer. `--dry-run` prints the message that would be signed and sends
nothing.

## What the operator checks

The request has two signatures: the hotkey signs the enrollment, and the axon
TLS key signs a possession proof bound to it. The enrollment binds the network,
netuid, UID, hotkey, operator, IP, port, TLS certificate SHA-256, a random
nonce, a timestamp and an expiry. The operator then:

- requires the hotkey to be the one currently registered for that UID;
- requires a public unicast IP;
- connects to `ip:port` and requires the served TLS certificate to match the
  enrolled hash and the possession proof;
- rejects replays, older enrollments and clocks more than 5 minutes off;
- limits each hotkey to one attempt per minute and each source IP to a few
  attempts per hour.

Your route is removed when the enrollment expires, when the hotkey
deregisters, or when the UID is reassigned. Rotating the TLS certificate
requires a new enrollment. `install.sh enable` re-copies the certificate and
the timer re-enrolls within 6 hours; start the service yourself to apply it
immediately.

## Errors

| Code | Meaning |
| --- | --- |
| `not_registered` | the UID is not registered to this hotkey (yet) |
| `bad_signature` | the hotkey signature does not verify |
| `clock_skew` | the system clock is more than 5 minutes off (enable NTP) |
| `address_not_allowed` | the IP is private, reserved or otherwise not public |
| `endpoint_unreachable` | the operator could not open TLS to `ip:port` (firewall?) |
| `possession_failed` | the served certificate differs from the enrolled one |
| `rate_limited` | retry after a minute (the CLI waits by itself) |
| `enrollment_disabled` | enrollment is not open yet; keep the timer, it retries |
