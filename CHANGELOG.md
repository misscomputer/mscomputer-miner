# Changelog

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
