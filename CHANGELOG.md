# Changelog

## v0.3.0

- Docker-capable sandboxes come with nested Docker address pools preset, so
  projects with many networks (for example large compose files) start
  without restarting the inner engine. An image's own
  `/etc/docker/daemon.json` is never replaced.
- New sandbox op `lease_usage`: reports a running sandbox's host-side CPU,
  peak memory, disk and network use. Informational only.
- New sandbox op `network_set`: changes a running `allowlist` sandbox's
  egress policy in place.
- Image prefetch (`sandbox-image-prefetch-v1`): the agent accepts signed,
  digest-pinned prefetch requests and pulls the image into its warm image
  cache ahead of use, through the same checks as a create.

## v0.2.1

- Sandboxes now report ready only after network rules are active. An
  `allowlist` sandbox's create returns only once the agent has read its
  rules back from the kernel (its MAC paired with every allowlist CIDR and
  resolver in `allow_dsts`, in the egress tables it loaded). A miss is
  refilled and checked again for about 10 s; then the sandbox is removed and
  the create fails as `egress_firewall_unavailable`, instead of reporting
  ready before its rules are in place.

## v0.2.0

- First public release.
