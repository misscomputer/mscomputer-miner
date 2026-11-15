# Copyright (c) 2026 Ms. Computer. All rights reserved.
# SPDX-License-Identifier: LicenseRef-MsComputer-Miner
"""Signed, miner-initiated private endpoint enrollment.

Miners do not advertise their axon publicly. Instead a miner sends the
operator one enrollment, signed by its registered hotkey (sr25519 over the
raw ASCII bytes, no ``<Bytes>`` wrapping), of exactly::

    mscomputer-miner-endpoint/v1
    network=<network>
    netuid=<netuid>
    operator=<operator hotkey ss58>
    hotkey=<miner hotkey ss58>
    uid=<uid>
    ip=<canonical public IP | auto>
    port=<port>
    certificate_sha256=<64 lowercase hex: the axon TLS leaf>
    nonce=<64 lowercase hex>
    timestamp=<unix seconds>
    expires=<unix seconds>

(lines joined by ``\\n``, no trailing newline). ``ip=auto`` asks the operator
to use the address the request came from.

The TLS leaf key additionally signs
:func:`mscomputer_subnet.tls.transport_possession_message` with
``challenge = sha256(enrollment message)``, ``validator_hotkey = operator``.
The operator fetches the leaf from ``ip:port``, requires its SHA-256 to equal
``certificate_sha256`` and verifies that signature, so an enrollment proves
the hotkey owns the UID and holds the key the address serves. Nobody can
point another miner's address at their own hotkey, or their hotkey at an
address they do not serve.

The operator side is two processes:

* the unprivileged enrollment service verifies requests and keeps the signed
  records (``mscomputer-miner-endpoint serve``);
* a root composer re-verifies every stored record against a fresh finalized
  metagraph and writes the private endpoint inventory read by
  :mod:`mscomputer_subnet.private_endpoints` (``mscomputer-miner-endpoint
  compose``). It never writes a file the loader would reject and keeps the
  last good file when the chain read fails or looks implausible.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time
from dataclasses import dataclass
from typing import Final

import bittensor as bt

from .netpolicy import canonical_public_address
from .tls import (
    MAX_TRANSPORT_POSSESSION_SIGNATURE_BYTES,
    transport_possession_message,
)

PROTOCOL: Final = "mscomputer-miner-endpoint/v1"
RECORDS_FORMAT: Final = "mscomputer-miner-endpoint-records/v1"
AUTO_IP: Final = "auto"
MAX_SKEW_SECONDS: Final = 300
MIN_TTL_SECONDS: Final = 600
MAX_TTL_SECONDS: Final = 7 * 24 * 3600
DEFAULT_TTL_SECONDS: Final = 24 * 3600
MAX_MESSAGE_BYTES: Final = 1024
MAX_REQUEST_BYTES: Final = 8192
MAX_LEAF_BYTES: Final = 16 << 10
MAX_RECORDS: Final = 1024
MAX_RECORDS_FILE_BYTES: Final = 64 << 20
INVENTORY_MAX_ROWS: Final = 4096

_NETWORK: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_HEX64: Final = re.compile(r"[0-9a-f]{64}")
_INT: Final = r"(0|[1-9][0-9]{0,18})"
_MESSAGE: Final = re.compile(
    re.escape(PROTOCOL)
    + r"\nnetwork=([^\n]*)\nnetuid=([^\n]*)\noperator=([^\n]*)\nhotkey=([^\n]*)"
    + r"\nuid=([^\n]*)\nip=([^\n]*)\nport=([^\n]*)\ncertificate_sha256=([^\n]*)"
    + r"\nnonce=([^\n]*)\ntimestamp=([^\n]*)\nexpires=([^\n]*)"
)


def valid_hotkey(value: object) -> bool:
    """True for a canonical Bittensor SS58 address."""

    if not isinstance(value, str) or not value or len(value) > 64:
        return False
    if not value.isascii() or not value.isalnum():
        return False
    try:
        return bool(bt.sp_core.ss58_encode(bt.sp_core.ss58_decode(value)) == value)
    except (ValueError, TypeError):
        return False


def valid_network(value: object) -> bool:
    return isinstance(value, str) and _NETWORK.fullmatch(value) is not None


def _int(text: str, low: int, high: int) -> int:
    if re.fullmatch(_INT, text) is None:
        raise ValueError("integer field is not canonical")
    value = int(text)
    if not low <= value <= high:
        raise ValueError("integer field is out of range")
    return value


def address_key(ip: str, port: int) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


@dataclass(frozen=True, slots=True)
class Enrollment:
    network: str
    netuid: int
    operator: str
    hotkey: str
    uid: int
    ip: str
    port: int
    certificate_sha256: str
    nonce: str
    timestamp: int
    expires: int

    def message(self) -> bytes:
        return (
            f"{PROTOCOL}\nnetwork={self.network}\nnetuid={self.netuid}"
            f"\noperator={self.operator}\nhotkey={self.hotkey}\nuid={self.uid}"
            f"\nip={self.ip}\nport={self.port}\ncertificate_sha256={self.certificate_sha256}"
            f"\nnonce={self.nonce}\ntimestamp={self.timestamp}\nexpires={self.expires}"
        ).encode("ascii")

    def possession_message(self) -> bytes:
        return transport_possession_message(
            network=self.network,
            netuid=self.netuid,
            challenge=hashlib.sha256(self.message()).hexdigest(),
            miner_hotkey=self.hotkey,
            validator_hotkey=self.operator,
            certificate_sha256=self.certificate_sha256,
        )


def new_enrollment(
    *,
    network: str,
    netuid: int,
    operator: str,
    hotkey: str,
    uid: int,
    ip: str,
    port: int,
    certificate_sha256: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: float | None = None,
) -> Enrollment:
    """A fresh enrollment (new 32-byte nonce, current second)."""

    timestamp = int(time.time() if now is None else now)
    enrollment = Enrollment(
        network=network,
        netuid=netuid,
        operator=operator,
        hotkey=hotkey,
        uid=uid,
        ip=ip if ip == AUTO_IP else canonical_public_address(ip),
        port=port,
        certificate_sha256=certificate_sha256,
        nonce=secrets.token_hex(32),
        timestamp=timestamp,
        expires=timestamp + ttl_seconds,
    )
    # Round-trip through the parser: never sign something the operator refuses.
    if parse_message(enrollment.message()) != enrollment:
        raise ValueError("enrollment is not canonical")
    if not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
        raise ValueError("enrollment TTL is out of range")
    return enrollment


def parse_message(message: bytes) -> Enrollment:
    """Parse the exact canonical enrollment message and nothing else."""

    if not isinstance(message, bytes) or len(message) > MAX_MESSAGE_BYTES:
        raise ValueError("enrollment message is too large")
    try:
        text = message.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("enrollment message is not ASCII") from exc
    match = _MESSAGE.fullmatch(text)
    if match is None:
        raise ValueError("enrollment message is not canonical")
    (network, netuid, operator, hotkey, uid, ip, port, pin, nonce, timestamp, expires) = (
        match.groups()
    )
    if not valid_network(network):
        raise ValueError("enrollment network is invalid")
    if not valid_hotkey(operator) or not valid_hotkey(hotkey):
        raise ValueError("enrollment hotkey is invalid")
    if _HEX64.fullmatch(pin) is None or _HEX64.fullmatch(nonce) is None:
        raise ValueError("enrollment pin or nonce is invalid")
    if ip != AUTO_IP and canonical_public_address(ip) != ip:
        raise ValueError("enrollment ip is not a canonical public address")
    enrollment = Enrollment(
        network=network,
        netuid=_int(netuid, 0, 65_535),
        operator=operator,
        hotkey=hotkey,
        uid=_int(uid, 0, 65_535),
        ip=ip,
        port=_int(port, 1, 65_535),
        certificate_sha256=pin,
        nonce=nonce,
        timestamp=_int(timestamp, 0, 2**62),
        expires=_int(expires, 0, 2**62),
    )
    if enrollment.message() != message:
        raise ValueError("enrollment message is not canonical")
    return enrollment


def request_body(message: bytes, signature: bytes, possession_signature: bytes) -> dict[str, str]:
    """The ``POST /v1/miner-endpoint`` JSON object."""

    if len(signature) != 64:
        raise ValueError("sr25519 signatures are 64 bytes")
    if not 0 < len(possession_signature) <= MAX_TRANSPORT_POSSESSION_SIGNATURE_BYTES:
        raise ValueError("possession signature size is invalid")
    return {
        "protocol": PROTOCOL,
        "message": message.decode("ascii"),
        "signature": signature.hex(),
        "possession_signature": base64.b64encode(possession_signature).decode("ascii"),
    }
