# Copyright (c) 2026 Ms. Computer. All rights reserved.
# SPDX-License-Identifier: LicenseRef-MsComputer-Miner
"""Strict parsing of ``msc-endpoint/v1`` chain commitments.

A commitment is the single ``Raw`` field of a commitments-pallet
``CommitmentInfo`` written by a miner hotkey::

    msc-endpoint/v1 https://<fqdn>

Endpoint URLs are deliberately narrow: ``https`` only, a public multi-label
DNS name, no explicit port, no userinfo, path, query or fragment. This module
only parses; it never writes to the chain.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Any, Final

COMMITMENT_PREFIX: Final = "msc-endpoint/v1 "
#: The commitments pallet ``Data::Raw`` variant carries at most 128 bytes.
MAX_COMMITMENT_BYTES: Final = 128
ENDPOINT_PORT: Final = 443

_LABEL: Final = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_TLD: Final = re.compile(r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})")
#: Names that are never public DNS (RFC 6761/6762/8375, de facto private
#: suffixes). A name equal to one of these or ending in ``.<suffix>`` fails.
_PRIVATE_SUFFIXES: Final = frozenset(
    {
        "localhost",
        "localdomain",
        "local",
        "internal",
        "intranet",
        "private",
        "corp",
        "home",
        "lan",
        "home.arpa",
        "arpa",
        "test",
        "invalid",
        "example",
        "onion",
        "alt",
    }
)


class EndpointError(ValueError):
    """An endpoint URL, commitment or resolution is refused."""


@dataclass(frozen=True, slots=True)
class EndpointURL:
    host: str

    @property
    def url(self) -> str:
        return f"https://{self.host}"


@dataclass(frozen=True, slots=True)
class EndpointCommitment:
    endpoint: EndpointURL
    #: Block at which the commitment was written (``CommitmentOf.block``).
    block: int


def validate_public_hostname(value: str) -> str:
    """Return ``value`` when it is a canonical public DNS name, else raise.

    Refused: IP literals in any spelling (dotted, decimal, octal, hex, short
    forms, IPv6), single labels, trailing dots, upper case, underscores,
    private suffixes, numeric or hex-looking top-level labels.
    """

    if not isinstance(value, str) or not value or len(value) > 253:
        raise EndpointError("endpoint host must be a DNS name of at most 253 bytes")
    if value != value.lower() or not value.isascii():
        raise EndpointError("endpoint host must be lower-case ASCII (punycode for IDN)")
    if value.startswith("[") or ":" in value:
        raise EndpointError("endpoint host must not be an IP literal")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise EndpointError("endpoint host must not be an IP literal")
    try:
        socket.inet_aton(value)
    except OSError:
        pass
    else:
        # inet_aton accepts decimal, octal, hex and short IPv4 spellings.
        raise EndpointError("endpoint host must not be an IP literal")
    labels = value.split(".")
    if len(labels) < 2:
        raise EndpointError("endpoint host must be a multi-label DNS name")
    if any(not _LABEL.fullmatch(label) for label in labels):
        raise EndpointError("endpoint host has an invalid DNS label")
    if not _TLD.fullmatch(labels[-1]):
        raise EndpointError("endpoint host top-level label is not a public DNS label")
    for size in range(1, len(labels) + 1):
        if ".".join(labels[-size:]) in _PRIVATE_SUFFIXES:
            raise EndpointError("endpoint host is not a public DNS name")
    return value


def parse_endpoint_url(value: str) -> EndpointURL:
    """Parse the canonical ``https://<fqdn>`` form and nothing else."""

    if not isinstance(value, str) or not value.startswith("https://"):
        raise EndpointError("endpoint must be an https:// URL")
    host = value[len("https://") :]
    if any(character in host for character in "/?#@\\%") or any(
        ord(character) < 0x21 or ord(character) == 0x7F for character in host
    ):
        raise EndpointError("endpoint must not carry userinfo, port, path, query or fragment")
    if ":" in host and not host.startswith("["):
        raise EndpointError(f"endpoint must not carry a port (the tunnel serves {ENDPOINT_PORT})")
    return EndpointURL(host=validate_public_hostname(host))


def parse_commitment(data: bytes) -> EndpointURL:
    """Strictly parse the committed bytes (no whitespace, no trailing data)."""

    if not isinstance(data, bytes) or not data or len(data) > MAX_COMMITMENT_BYTES:
        raise EndpointError("endpoint commitment size is invalid")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EndpointError("endpoint commitment is not ASCII") from exc
    if not text.startswith(COMMITMENT_PREFIX):
        raise EndpointError("commitment is not an msc-endpoint/v1 record")
    return parse_endpoint_url(text[len(COMMITMENT_PREFIX) :])


def commitment_raw_bytes(fields: Any) -> bytes:
    """The bytes of exactly one ``Raw<N>`` field of a ``CommitmentInfo``.

    Values may be decoded as ``0x`` hex text, bytes or a list of ints. Any
    other shape (several fields, non-Raw variants, length mismatch) fails.
    """

    if isinstance(fields, tuple):
        fields = list(fields)
    # Some decoders keep the BoundedVec as a one-element nesting.
    if isinstance(fields, list) and len(fields) == 1 and isinstance(fields[0], list | tuple):
        fields = list(fields[0])
    if not isinstance(fields, list) or len(fields) != 1 or not isinstance(fields[0], dict):
        raise EndpointError("endpoint commitment must carry exactly one field")
    entry = fields[0]
    if len(entry) != 1:
        raise EndpointError("endpoint commitment field is malformed")
    ((variant, value),) = entry.items()
    match = re.fullmatch(r"Raw([0-9]{1,3})", str(variant))
    if match is None:
        raise EndpointError("endpoint commitment field is not Raw")
    if isinstance(value, str):
        text = value.removeprefix("0x")
        try:
            raw = bytes.fromhex(text)
        except ValueError as exc:
            raise EndpointError("endpoint commitment Raw value is malformed") from exc
    elif isinstance(value, bytes | bytearray):
        raw = bytes(value)
    elif isinstance(value, list | tuple) and all(
        isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255 for item in value
    ):
        raw = bytes(value)
    else:
        raise EndpointError("endpoint commitment Raw value is malformed")
    if len(raw) != int(match.group(1)):
        raise EndpointError("endpoint commitment Raw length differs from its variant")
    return raw
