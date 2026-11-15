# Copyright (c) 2026 Ms. Computer. All rights reserved.
# SPDX-License-Identifier: LicenseRef-MsComputer-Miner
"""PROVISIONAL, default-off miner qualification wire types (Python mirror).

The documents, axon synapses and responses of the miner qualification
protocol, mirrored byte for byte from Go ``pkg/qualification``, with the
pieces both the miner axon and the validator use: parsing, the fill and plot
primitives, the network payload generator, and the signature and Merkle
checks the miner applies to its agent's answers before relaying them. The
shared vectors are in ``pkg/qualification/testdata/qualification-vectors.v1.json``
and ``qualification-plot-vectors.v1.json``.

It covers the validator-built ``miner-qualification-challenge.v1``, the
round-one ``miner-qualification-commitment.v1`` (the Merkle root of a
memory-hard fill), the validator's ``miner-qualification-openings-request.v1``,
the round-two ``miner-qualification-openings.v1``, and the disk plot:
``miner-qualification-plot-challenge.v1``, the signed
``miner-qualification-plot-commitment.v1``, the seal and spot requests and the
signed ``miner-qualification-plot-seal.v1`` and
``miner-qualification-plot-spot.v1``.

The validator-only gVisor lease-path assessor lives in
:mod:`~.qualification_contracts`, which re-exports every name here.

This module is pure. It uses no clock, network, file, process, environment,
wallet, chain or randomness.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Iterator, Sequence
from typing import Annotated, Final, Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, StringConstraints, model_validator

from .contract_codec import StrictFrozenModel, canonical_json, model_document, parse_model
from .ed25519_trust import Ed25519PublicKeyValidationError, decode_ed25519_public_key_hex

SCHEMA_PREFIX: Final = "ms.computer/mscomputer-subnet/"
CHALLENGE_SCHEMA: Final = SCHEMA_PREFIX + "miner-qualification-challenge.v1"
COMMITMENT_SCHEMA: Final = SCHEMA_PREFIX + "miner-qualification-commitment.v1"
OPENINGS_REQUEST_SCHEMA: Final = SCHEMA_PREFIX + "miner-qualification-openings-request.v1"
OPENINGS_SCHEMA: Final = SCHEMA_PREFIX + "miner-qualification-openings.v1"
COMMITMENT_SIGNING_DOMAIN: Final = SCHEMA_PREFIX + "miner-qualification-commitment/v1/ed25519"
OPENINGS_SIGNING_DOMAIN: Final = SCHEMA_PREFIX + "miner-qualification-openings/v1/ed25519"
SYNAPSE_VERSION: Final = "subnet-qualification-synapse.v1"
PLOT_CHALLENGE_SCHEMA: Final = SCHEMA_PREFIX + "miner-qualification-plot-challenge.v1"
PLOT_COMMITMENT_SCHEMA: Final = SCHEMA_PREFIX + "miner-qualification-plot-commitment.v1"
PLOT_SEAL_REQUEST_SCHEMA: Final = SCHEMA_PREFIX + "miner-qualification-plot-seal-request.v1"
PLOT_SEAL_SCHEMA: Final = SCHEMA_PREFIX + "miner-qualification-plot-seal.v1"
PLOT_SPOT_REQUEST_SCHEMA: Final = SCHEMA_PREFIX + "miner-qualification-plot-spot-request.v1"
PLOT_SPOT_SCHEMA: Final = SCHEMA_PREFIX + "miner-qualification-plot-spot.v1"
PLOT_COMMITMENT_SIGNING_DOMAIN: Final = (
    SCHEMA_PREFIX + "miner-qualification-plot-commitment/v1/ed25519"
)
PLOT_SEAL_SIGNING_DOMAIN: Final = SCHEMA_PREFIX + "miner-qualification-plot-seal/v1/ed25519"
PLOT_SPOT_SIGNING_DOMAIN: Final = SCHEMA_PREFIX + "miner-qualification-plot-spot/v1/ed25519"

SLICES: Final = 4
BLOCK_SIZE: Final = 16 << 10
MAX_WINDOW_SECONDS: Final = 300
MAX_LANES: Final = 64
MIN_BLOCKS_PER_SLICE: Final = 2
MAX_FILL_BLOCKS: Final = 1 << 21
MAX_OPENINGS: Final = 256
MAX_OPENINGS_PER_REQUEST: Final = 8
# Openings one fill serves beyond its budget, re-requests included.
OPENINGS_SERVED_SLACK: Final = MAX_OPENINGS_PER_REQUEST
# PROVISIONAL; kept low while the axon's per-validator rate limit is the
# only other bound on payload egress.
MAX_PAYLOAD_BYTES: Final = 64 << 20
MAX_ELAPSED_MS: Final = 3_600_000
MAX_REQUEST_BYTES: Final = 16 << 10
MAX_RESPONSE_BYTES: Final = 1 << 20
_MAX_UNIX: Final = 1 << 62
# Plot bounds (PROVISIONAL): a chunk is at most 4 x 16384 blocks (1 GiB).
MAX_PLOT_CHUNKS: Final = 4096
MAX_PLOT_BLOCKS_PER_SLICE: Final = 16384
MAX_PLOT_BUILD_SECONDS: Final = 24 * 3600
_MAX_PLOT_ELAPSED_MS: Final = 2 * MAX_PLOT_BUILD_SECONDS * 1000
_MAX_PLOT_PATH: Final = 12
# Layers of a plot chunk; only the top one is stored.
PLOT_LAYERS: Final = 16
# A seal request opens one block of every lower layer and up to 3 of the top.
MAX_SEAL_TOP_OPENINGS: Final = 3
MAX_SEAL_OPENINGS: Final = PLOT_LAYERS - 1 + MAX_SEAL_TOP_OPENINGS
# One seal answer (about 1.7 MB at 18 openings) and one kept seal file.
MAX_PLOT_SEAL_BYTES: Final = 4 << 20
MAX_SPOT_PICKS: Final = 8
_MAX_PATH: Final = 32

CODE_CHALLENGE_INVALID: Final = "qualification_challenge_invalid"
CODE_COMMITMENT_INVALID: Final = "qualification_commitment_invalid"
CODE_REQUEST_INVALID: Final = "qualification_openings_request_invalid"
CODE_OPENINGS_INVALID: Final = "qualification_openings_invalid"
CODE_CHALLENGE_MISMATCH: Final = "qualification_challenge_mismatch"
CODE_ROOT_MISMATCH: Final = "qualification_root_mismatch"
CODE_UNREQUESTED: Final = "qualification_opening_unrequested"
CODE_SIGNER_MISMATCH: Final = "qualification_signer_mismatch"
CODE_SIGNATURE_INVALID: Final = "qualification_signature_invalid"
CODE_PATH_INVALID: Final = "qualification_opening_path_invalid"
CODE_REF_INVALID: Final = "qualification_opening_ref_invalid"
CODE_BLOCK_INVALID: Final = "qualification_opening_block_invalid"
CODE_PLOT_CHALLENGE_INVALID: Final = "qualification_plot_challenge_invalid"
CODE_PLOT_COMMITMENT_INVALID: Final = "qualification_plot_commitment_invalid"
CODE_PLOT_REQUEST_INVALID: Final = "qualification_plot_request_invalid"
CODE_PLOT_ANSWER_INVALID: Final = "qualification_plot_answer_invalid"
CODE_PLOT_CHALLENGE_MISMATCH: Final = "qualification_plot_challenge_mismatch"
CODE_PLOT_ROOT_MISMATCH: Final = "qualification_plot_root_mismatch"
CODE_PLOT_UNREQUESTED: Final = "qualification_plot_unrequested"
CODE_PLOT_CHUNK_PATH_INVALID: Final = "qualification_plot_chunk_path_invalid"
CODE_PLOT_PATH_INVALID: Final = "qualification_plot_block_path_invalid"
CODE_PLOT_REF_INVALID: Final = "qualification_plot_ref_invalid"
CODE_PLOT_BLOCK_INVALID: Final = "qualification_plot_block_invalid"

_FILL_DOMAIN: Final = b"mcq-fill-v2\x00"
_PAYLOAD_DOMAIN: Final = b"mcq-payload-v1\x00"
_PLOT_DOMAIN: Final = b"mcq-plot-v3\x00"
_PLOT_LOWER_DOMAIN: Final = b"mcq-plot-v3-lower\x00"
_ZERO_BLOCK: Final = bytes(BLOCK_SIZE)
_BLOCK_BASE64_LENGTH: Final = 4 * ((BLOCK_SIZE + 2) // 3)

QualificationCode = Literal[
    "qualification_challenge_invalid",
    "qualification_commitment_invalid",
    "qualification_openings_request_invalid",
    "qualification_openings_invalid",
    "qualification_challenge_mismatch",
    "qualification_root_mismatch",
    "qualification_opening_unrequested",
    "qualification_signer_mismatch",
    "qualification_signature_invalid",
    "qualification_opening_path_invalid",
    "qualification_opening_ref_invalid",
    "qualification_opening_block_invalid",
    "qualification_gvisor_pins_invalid",
    "qualification_gvisor_nonce_invalid",
    "qualification_gvisor_lease_missing",
    "qualification_gvisor_image_mismatch",
    "qualification_gvisor_lease_not_released",
    "qualification_gvisor_upload_missing",
    "qualification_gvisor_upload_mismatch",
    "qualification_gvisor_exec_missing",
    "qualification_gvisor_exit_nonzero",
    "qualification_gvisor_answer_invalid",
    "qualification_gvisor_nonce_mismatch",
    "qualification_gvisor_mac_invalid",
    "qualification_gvisor_probe_mismatch",
    "qualification_gvisor_sentry_mismatch",
    "qualification_gvisor_syslog_mismatch",
    "qualification_plot_challenge_invalid",
    "qualification_plot_commitment_invalid",
    "qualification_plot_request_invalid",
    "qualification_plot_answer_invalid",
    "qualification_plot_challenge_mismatch",
    "qualification_plot_root_mismatch",
    "qualification_plot_unrequested",
    "qualification_plot_chunk_path_invalid",
    "qualification_plot_block_path_invalid",
    "qualification_plot_ref_invalid",
    "qualification_plot_block_invalid",
]


class QualificationError(ValueError):
    """Stable rejection, the same code the Go verifier returns."""

    def __init__(self, code: QualificationCode) -> None:
        super().__init__(code)
        self.code: QualificationCode = code


Hex64 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Hex128 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$")]
Hotkey = Annotated[str, StringConstraints(pattern=r"^[1-9A-HJ-NP-Za-km-z]{46,48}$")]
Network = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._:/-]{1,128}$")]
RequestID = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._:-]{1,128}$")]
Block64 = Annotated[
    str, StringConstraints(min_length=_BLOCK_BASE64_LENGTH, max_length=_BLOCK_BASE64_LENGTH)
]
Uint16 = Annotated[int, Field(ge=0, le=65535)]
FillIndex = Annotated[int, Field(ge=0, lt=MAX_FILL_BLOCKS)]
Path = Annotated[list[Hex64], Field(max_length=_MAX_PATH)]


class Fill(StrictFrozenModel):
    lanes: int = Field(ge=1, le=MAX_LANES)
    blocks_per_slice: int = Field(ge=MIN_BLOCKS_PER_SLICE, le=MAX_FILL_BLOCKS)

    @property
    def blocks(self) -> int:
        return self.lanes * SLICES * self.blocks_per_slice

    @model_validator(mode="after")
    def _bounded(self) -> Self:
        if self.blocks > MAX_FILL_BLOCKS:
            raise ValueError("fill_too_large")
        return self


class QualificationChallenge(StrictFrozenModel):
    schema_: Literal["ms.computer/mscomputer-subnet/miner-qualification-challenge.v1"] = Field(
        alias="schema"
    )
    network: Network
    netuid: Uint16
    validator_hotkey: Hotkey
    miner_hotkey: Hotkey
    miner_uid: Uint16
    challenge_id: Hex64
    nonce: Hex64
    issued_at_unix: int = Field(ge=1, le=_MAX_UNIX)
    expires_at_unix: int = Field(ge=1, le=_MAX_UNIX)
    fill: Fill
    openings: int = Field(ge=1, le=MAX_OPENINGS)
    payload_bytes: int = Field(ge=1, le=MAX_PAYLOAD_BYTES)

    @model_validator(mode="after")
    def _window(self) -> Self:
        if not (
            self.issued_at_unix < self.expires_at_unix <= self.issued_at_unix + MAX_WINDOW_SECONDS
        ):
            raise ValueError("challenge_window_invalid")
        if self.openings > self.fill.blocks:
            raise ValueError("challenge_openings_invalid")
        return self


class QualificationCommitment(StrictFrozenModel):
    schema_: Literal["ms.computer/mscomputer-subnet/miner-qualification-commitment.v1"] = Field(
        alias="schema"
    )
    challenge_sha256: Hex64
    challenge_id: Hex64
    network: Network
    netuid: Uint16
    validator_hotkey: Hotkey
    miner_hotkey: Hotkey
    service_public_key: Hex64
    root: Hex64
    blocks: int = Field(ge=1, le=MAX_FILL_BLOCKS)
    fill_elapsed_ms: int = Field(ge=0, le=MAX_ELAPSED_MS)
    signature: Hex128


class OpeningsRequest(StrictFrozenModel):
    schema_: Literal["ms.computer/mscomputer-subnet/miner-qualification-openings-request.v1"] = (
        Field(alias="schema")
    )
    challenge_id: Hex64
    challenge_sha256: Hex64
    root: Hex64
    indices: list[FillIndex] = Field(min_length=1, max_length=MAX_OPENINGS_PER_REQUEST)

    @model_validator(mode="after")
    def _ascending(self) -> Self:
        if any(b <= a for a, b in zip(self.indices, self.indices[1:], strict=False)):
            raise ValueError("indices_not_strictly_ascending")
        return self


class OpenedBlock(StrictFrozenModel):
    index: FillIndex
    block: Block64
    path: Path


class Opening(StrictFrozenModel):
    index: FillIndex
    block: Block64
    path: Path
    prev: OpenedBlock | None
    ref: OpenedBlock | None

    @model_validator(mode="after")
    def _paired(self) -> Self:
        if (self.prev is None) != (self.ref is None):
            raise ValueError("opening_prev_ref_unpaired")
        return self


class QualificationOpenings(StrictFrozenModel):
    schema_: Literal["ms.computer/mscomputer-subnet/miner-qualification-openings.v1"] = Field(
        alias="schema"
    )
    challenge_sha256: Hex64
    challenge_id: Hex64
    service_public_key: Hex64
    root: Hex64
    request_sha256: Hex64
    openings: list[Opening] = Field(min_length=1, max_length=MAX_OPENINGS_PER_REQUEST)
    signature: Hex128


def _parse[ModelT: StrictFrozenModel](
    raw: bytes,
    model_type: type[ModelT],
    code: QualificationCode,
    maximum_bytes: int,
    *,
    canonical: bool = False,
) -> ModelT:
    """Strict parse. With ``canonical`` the bytes must also be exactly the
    document's canonical JSON (no whitespace, sorted keys, no trailing
    newline), so their length is fixed by the content and cannot be padded."""

    def canonicalizer(model: ModelT) -> bytes:
        return canonical_json(model_document(model)) if canonical else raw

    try:
        return parse_model(raw, model_type, canonicalizer, maximum_bytes=maximum_bytes)
    except ValueError as exc:
        raise QualificationError(code) from exc


def parse_challenge(raw: bytes) -> QualificationChallenge:
    """Strictly parse one challenge: unknown, missing, null and coerced members refused."""

    return _parse(raw, QualificationChallenge, CODE_CHALLENGE_INVALID, MAX_REQUEST_BYTES)


def parse_commitment(raw: bytes) -> QualificationCommitment:
    """Strictly parse one commitment in its exact canonical bytes."""

    return _parse(
        raw, QualificationCommitment, CODE_COMMITMENT_INVALID, MAX_REQUEST_BYTES, canonical=True
    )


def parse_openings_request(raw: bytes) -> OpeningsRequest:
    return _parse(raw, OpeningsRequest, CODE_REQUEST_INVALID, MAX_REQUEST_BYTES)


def parse_openings(raw: bytes) -> QualificationOpenings:
    """Strictly parse one openings answer under the one-MiB bridge body bound."""

    return _parse(
        raw, QualificationOpenings, CODE_OPENINGS_INVALID, MAX_RESPONSE_BYTES, canonical=True
    )


def max_openings_served(openings: int) -> int:
    """Openings, repeats included, one fill answers: the budget plus one
    request of slack. Counted per opening, so one index per call is allowed."""

    return openings + OPENINGS_SERVED_SLACK


def challenge_document(challenge: QualificationChallenge) -> dict[str, object]:
    return model_document(challenge)


def challenge_sha256(challenge: QualificationChallenge) -> str:
    """Lowercase hex SHA-256 of the challenge's canonical JSON."""

    return hashlib.sha256(canonical_json(model_document(challenge))).hexdigest()


def request_sha256(request: OpeningsRequest) -> str:
    """Lowercase hex SHA-256 of the openings request's canonical JSON."""

    return hashlib.sha256(canonical_json(model_document(request))).hexdigest()


def signing_message(domain: str, document: StrictFrozenModel) -> bytes:
    """``domain || 0x00 || canonical_json(document minus signature)``."""

    unsigned = model_document(document, exclude={"signature"})
    return domain.encode("ascii") + b"\x00" + canonical_json(unsigned)


def _verify_signer(
    domain: str,
    document: QualificationCommitment
    | QualificationOpenings
    | PlotCommitment
    | PlotSeal
    | PlotSpot,
    bound: str,
) -> None:
    if document.service_public_key != bound:
        raise QualificationError(CODE_SIGNER_MISMATCH)
    try:
        key = Ed25519PublicKey.from_public_bytes(decode_ed25519_public_key_hex(bound))
    except (Ed25519PublicKeyValidationError, ValueError) as exc:
        raise QualificationError(CODE_SIGNER_MISMATCH) from exc
    try:
        key.verify(bytes.fromhex(document.signature), signing_message(domain, document))
    except InvalidSignature as exc:
        raise QualificationError(CODE_SIGNATURE_INVALID) from exc


def verify_commitment(
    commitment: QualificationCommitment,
    challenge: QualificationChallenge,
    bound_service_key_hex: str,
) -> None:
    """Accept ``commitment`` only as the bound miner key's round-one answer.

    Not a qualification signal by itself; use the validator-side
    driver, which also times the
    round against D1.

    Raises :class:`QualificationError` with the same code, in the same check
    order, as Go ``qualification.VerifyCommitment``.
    """

    if (
        commitment.challenge_sha256 != challenge_sha256(challenge)
        or commitment.challenge_id != challenge.challenge_id
        or commitment.network != challenge.network
        or commitment.netuid != challenge.netuid
        or commitment.validator_hotkey != challenge.validator_hotkey
        or commitment.miner_hotkey != challenge.miner_hotkey
        or commitment.blocks != challenge.fill.blocks
    ):
        raise QualificationError(CODE_CHALLENGE_MISMATCH)
    _verify_signer(COMMITMENT_SIGNING_DOMAIN, commitment, bound_service_key_hex)


def verify_openings(
    openings: QualificationOpenings,
    request: OpeningsRequest,
    commitment: QualificationCommitment,
    challenge: QualificationChallenge,
    bound_service_key_hex: str,
) -> None:
    """Accept ``openings`` only as the bound key's answer to ``request`` under
    the verified ``commitment``, checking every opening: Merkle paths,
    reference derivation and G. Same codes and order as Go
    ``qualification.VerifyOpenings``.

    Not a qualification signal by itself; use the validator-side
    driver, which also draws
    uniform indices after the root, enforces the openings budget and times
    the round against D2."""

    verify_commitment(commitment, challenge, bound_service_key_hex)
    if (
        openings.challenge_sha256 != commitment.challenge_sha256
        or openings.challenge_id != commitment.challenge_id
        or request.challenge_id != commitment.challenge_id
        or request.challenge_sha256 != commitment.challenge_sha256
    ):
        raise QualificationError(CODE_CHALLENGE_MISMATCH)
    if openings.root != commitment.root or request.root != commitment.root:
        raise QualificationError(CODE_ROOT_MISMATCH)
    if openings.request_sha256 != request_sha256(request) or [
        opening.index for opening in openings.openings
    ] != list(request.indices):
        raise QualificationError(CODE_UNREQUESTED)
    _verify_signer(OPENINGS_SIGNING_DOMAIN, openings, bound_service_key_hex)
    root = bytes.fromhex(commitment.root)
    nonce = bytes.fromhex(challenge.nonce)
    for opening in openings.openings:
        _verify_opening(opening, challenge.fill, nonce, root)


def _decode_block(value: str) -> bytes:
    try:
        block = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise QualificationError(CODE_OPENINGS_INVALID) from exc
    if len(block) != BLOCK_SIZE or base64.b64encode(block).decode("ascii") != value:
        raise QualificationError(CODE_OPENINGS_INVALID)
    return block


def _verify_opening(opening: Opening, fill: Fill, nonce: bytes, root: bytes) -> None:
    n = fill.blocks
    if opening.index >= n:
        raise QualificationError(CODE_UNREQUESTED)
    lane, column = position(fill, opening.index)
    block = _decode_block(opening.block)
    if not verify_path(opening.index, n, leaf_hash(block), opening.path, root):
        raise QualificationError(CODE_PATH_INVALID)
    if column == 0:
        if opening.prev is not None or opening.ref is not None:
            raise QualificationError(CODE_REF_INVALID)
        if block != g_block(None, None, nonce, lane, 0):
            raise QualificationError(CODE_BLOCK_INVALID)
        return
    if opening.prev is None or opening.ref is None:
        raise QualificationError(CODE_REF_INVALID)
    prev = _decode_block(opening.prev.block)
    ref = _decode_block(opening.ref.block)
    if opening.prev.index != opening.index - 1:
        raise QualificationError(CODE_REF_INVALID)
    if opening.ref.index != ref_index(prev, fill, lane, column):
        raise QualificationError(CODE_REF_INVALID)
    if not verify_path(opening.prev.index, n, leaf_hash(prev), opening.prev.path, root) or not (
        verify_path(opening.ref.index, n, leaf_hash(ref), opening.ref.path, root)
    ):
        raise QualificationError(CODE_PATH_INVALID)
    if block != g_block(prev, ref, nonce, lane, column):
        raise QualificationError(CODE_BLOCK_INVALID)


def position(fill: Fill, index: int) -> tuple[int, int]:
    """The (lane, column) of a lane-major global fill index."""

    return divmod(index, SLICES * fill.blocks_per_slice)


def fill_index(fill: Fill, lane: int, column: int) -> int:
    return lane * SLICES * fill.blocks_per_slice + column


def g_block(prev: bytes | None, ref: bytes | None, nonce: bytes, lane: int, column: int) -> bytes:
    """G: Expand(SHA-256(domain || 0x00 || nonce || u32be(lane) || u32be(column)
    || (prev XOR ref))) XOR prev XOR ref, Expand being the SHA-256 counter
    stream over k = 0..511. Every byte of prev and ref enters the output. A
    lane's first block uses the zero block for both."""

    prev_block = _ZERO_BLOCK if prev is None else prev
    ref_block = _ZERO_BLOCK if ref is None else ref
    mixed = (int.from_bytes(prev_block, "big") ^ int.from_bytes(ref_block, "big")).to_bytes(
        BLOCK_SIZE, "big"
    )
    seed = hashlib.sha256(
        _FILL_DOMAIN + nonce + lane.to_bytes(4, "big") + column.to_bytes(4, "big") + mixed
    ).digest()
    sha256 = hashlib.sha256
    expanded = b"".join(
        sha256(seed + k.to_bytes(4, "big")).digest() for k in range(BLOCK_SIZE // 32)
    )
    value = int.from_bytes(expanded, "big") ^ int.from_bytes(mixed, "big")
    return value.to_bytes(BLOCK_SIZE, "big")


def ref_index(prev: bytes, fill: Fill, lane: int, column: int) -> int:
    """Global index of the reference block of (lane, column), column >= 1.

    J1 (prev bytes 0..3, big-endian) picks the position with Argon2's
    non-uniform map; J2 (bytes 4..7) picks the lane, which in slice 0 is the
    block's own. The set is every earlier block of the same lane, or every
    block of the completed slices of another lane.
    """

    j1 = int.from_bytes(prev[0:4], "big")
    j2 = int.from_bytes(prev[4:8], "big")
    current_slice = column // fill.blocks_per_slice
    ref_lane = lane if current_slice == 0 else j2 % fill.lanes
    size = column if ref_lane == lane else current_slice * fill.blocks_per_slice
    x = (j1 * j1) >> 32
    y = (size * x) >> 32
    return fill_index(fill, ref_lane, size - 1 - y)


def leaf_hash(block: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + block).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_levels(leaves: Sequence[bytes]) -> list[list[bytes]]:
    """The tree over ``leaves``; an unpaired last node is promoted unchanged."""

    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        levels.append(
            [
                _node(current[i], current[i + 1]) if i + 1 < len(current) else current[i]
                for i in range(0, len(current), 2)
            ]
        )
    return levels


def merkle_path(levels: Sequence[Sequence[bytes]], index: int) -> list[str]:
    path = []
    for level in levels[:-1]:
        if (index ^ 1) < len(level):
            path.append(level[index ^ 1].hex())
        index //= 2
    return path


def verify_path(index: int, n: int, leaf: bytes, path: Sequence[str], root: bytes) -> bool:
    """Whether ``leaf`` at ``index`` of an ``n``-leaf tree hashes to ``root``
    along ``path``, consuming every node."""

    if not 0 <= index < n:
        return False
    value, used, width = leaf, 0, n
    while width > 1:
        if (index ^ 1) < width:
            if used >= len(path):
                return False
            node = bytes.fromhex(path[used])
            used += 1
            value = _node(value, node) if index % 2 == 0 else _node(node, value)
        index //= 2
        width = (width + 1) // 2
    return used == len(path) and value == root


def fill_blocks(nonce_hex: str, fill: Fill) -> list[bytes]:
    """Reference fill, sequential. Only for small fills (tests and vectors)."""

    nonce = bytes.fromhex(nonce_hex)
    blocks: list[bytes] = [b""] * fill.blocks
    width = SLICES * fill.blocks_per_slice
    for current_slice in range(SLICES):
        for lane in range(fill.lanes):
            start = current_slice * fill.blocks_per_slice
            for column in range(start, start + fill.blocks_per_slice):
                index = lane * width + column
                if column == 0:
                    blocks[index] = g_block(None, None, nonce, lane, 0)
                    continue
                prev = blocks[index - 1]
                ref = blocks[ref_index(prev, fill, lane, column)]
                blocks[index] = g_block(prev, ref, nonce, lane, column)
    return blocks


def _nonce(nonce_hex: str) -> bytes:
    nonce = bytes.fromhex(nonce_hex)
    if len(nonce) != 32 or nonce.hex() != nonce_hex:
        raise ValueError("nonce_invalid")
    return nonce


def payload_block(nonce_hex: str, index: int) -> bytes:
    """``SHA256("mcq-payload-v1" || 0x00 || nonce || u64be(index))``."""

    return hashlib.sha256(_PAYLOAD_DOMAIN + _nonce(nonce_hex) + index.to_bytes(8, "big")).digest()


def payload_chunk(nonce_hex: str, start_block: int, size: int) -> bytes:
    """``size`` payload bytes starting at 32-byte block ``start_block``."""

    if start_block < 0 or size < 0 or size > MAX_PAYLOAD_BYTES:
        raise ValueError("payload_size_invalid")
    prefix = _PAYLOAD_DOMAIN + _nonce(nonce_hex)
    sha256 = hashlib.sha256
    blocks = (size + 31) // 32
    chunk = b"".join(
        sha256(prefix + (start_block + offset).to_bytes(8, "big")).digest()
        for offset in range(blocks)
    )
    return chunk[:size]


def iter_payload(nonce_hex: str, size: int, chunk_bytes: int = 1 << 20) -> Iterator[bytes]:
    """Yield the first ``size`` payload bytes in chunks of ``chunk_bytes``."""

    if size < 0 or size > MAX_PAYLOAD_BYTES or chunk_bytes < 32 or chunk_bytes % 32:
        raise ValueError("payload_size_invalid")
    offset = 0
    while offset < size:
        take = min(size - offset, chunk_bytes)
        yield payload_chunk(nonce_hex, offset // 32, take)
        offset += take


class PlotChallenge(StrictFrozenModel):
    """``miner-qualification-plot-challenge.v1``: validator-built, unsigned,
    bound by ``plot_challenge_sha256``."""

    schema_: Literal["ms.computer/mscomputer-subnet/miner-qualification-plot-challenge.v1"] = Field(
        alias="schema"
    )
    network: Network
    netuid: Uint16
    validator_hotkey: Hotkey
    miner_hotkey: Hotkey
    miner_uid: Uint16
    plot_id: Hex64
    seed: Hex64
    chunks: int = Field(ge=1, le=MAX_PLOT_CHUNKS)
    chunk_blocks_per_slice: int = Field(ge=MIN_BLOCKS_PER_SLICE, le=MAX_PLOT_BLOCKS_PER_SLICE)
    issued_at_unix: int = Field(ge=1, le=_MAX_UNIX)
    build_expires_at_unix: int = Field(ge=1, le=_MAX_UNIX)

    @model_validator(mode="after")
    def _window(self) -> Self:
        if not (
            self.issued_at_unix
            < self.build_expires_at_unix
            <= self.issued_at_unix + MAX_PLOT_BUILD_SECONDS
        ):
            raise ValueError("plot_challenge_window_invalid")
        return self

    @property
    def chunk_fill(self) -> Fill:
        return Fill(lanes=1, blocks_per_slice=self.chunk_blocks_per_slice)

    @property
    def blocks_per_chunk(self) -> int:
        return SLICES * self.chunk_blocks_per_slice

    @property
    def chunk_mib(self) -> int:
        """One chunk's stored size in MiB, rounded down."""

        return self.blocks_per_chunk * BLOCK_SIZE >> 20


class PlotCommitment(StrictFrozenModel):
    schema_: Literal["ms.computer/mscomputer-subnet/miner-qualification-plot-commitment.v1"] = (
        Field(alias="schema")
    )
    plot_challenge_sha256: Hex64
    plot_id: Hex64
    network: Network
    netuid: Uint16
    validator_hotkey: Hotkey
    miner_hotkey: Hotkey
    service_public_key: Hex64
    root: Hex64
    chunks: int = Field(ge=1, le=MAX_PLOT_CHUNKS)
    blocks_per_chunk: int = Field(
        ge=SLICES * MIN_BLOCKS_PER_SLICE, le=SLICES * MAX_PLOT_BLOCKS_PER_SLICE
    )
    build_elapsed_ms: int = Field(ge=0, le=_MAX_PLOT_ELAPSED_MS)
    signature: Hex128


PlotIndex = Annotated[int, Field(ge=0, lt=SLICES * MAX_PLOT_BLOCKS_PER_SLICE)]
PlotChunkIndex = Annotated[int, Field(ge=0, lt=MAX_PLOT_CHUNKS)]
ChunkPath = Annotated[list[Hex64], Field(max_length=_MAX_PLOT_PATH)]


PlotLayer = Annotated[int, Field(ge=0, lt=PLOT_LAYERS)]


class PlotSealPoint(StrictFrozenModel):
    layer: PlotLayer
    index: PlotIndex


class PlotSealRequest(StrictFrozenModel):
    """Openings of up to MAX_SEAL_OPENINGS (layer, index) blocks of one
    chunk, strictly ascending by (layer, index)."""

    schema_: Literal["ms.computer/mscomputer-subnet/miner-qualification-plot-seal-request.v1"] = (
        Field(alias="schema")
    )
    plot_id: Hex64
    plot_challenge_sha256: Hex64
    root: Hex64
    request_id: Hex64
    chunk: PlotChunkIndex
    openings: list[PlotSealPoint] = Field(min_length=1, max_length=MAX_SEAL_OPENINGS)

    @model_validator(mode="after")
    def _ascending(self) -> Self:
        points = [(o.layer, o.index) for o in self.openings]
        if any(b <= a for a, b in zip(points, points[1:], strict=False)):
            raise ValueError("openings_not_strictly_ascending")
        return self


class SealOpening(StrictFrozenModel):
    """Block (layer, index) with its inputs under their layer roots: the
    predecessor (none only for block 0 of layer 0), and for layer >= 1 the
    block below and the reference block of the layer below."""

    layer: PlotLayer
    index: FillIndex
    block: Block64
    path: Path
    prev: OpenedBlock | None
    below: OpenedBlock | None
    ref: OpenedBlock | None


class PlotSeal(StrictFrozenModel):
    schema_: Literal["ms.computer/mscomputer-subnet/miner-qualification-plot-seal.v1"] = Field(
        alias="schema"
    )
    request_sha256: Hex64
    plot_id: Hex64
    service_public_key: Hex64
    root: Hex64
    chunk: PlotChunkIndex
    layer_roots: list[Hex64] = Field(min_length=PLOT_LAYERS, max_length=PLOT_LAYERS)
    chunk_path: ChunkPath
    openings: list[SealOpening] = Field(min_length=1, max_length=MAX_SEAL_OPENINGS)
    signature: Hex128


class PlotPick(StrictFrozenModel):
    chunk: PlotChunkIndex
    index: PlotIndex


class PlotSpotRequest(StrictFrozenModel):
    schema_: Literal["ms.computer/mscomputer-subnet/miner-qualification-plot-spot-request.v1"] = (
        Field(alias="schema")
    )
    plot_id: Hex64
    plot_challenge_sha256: Hex64
    root: Hex64
    request_id: Hex64
    picks: list[PlotPick] = Field(min_length=1, max_length=MAX_SPOT_PICKS)


class PlotSpotItem(StrictFrozenModel):
    chunk: PlotChunkIndex
    lower_digest: Hex64
    top_root: Hex64
    chunk_path: ChunkPath
    index: FillIndex
    block: Block64
    path: Path


class PlotSpot(StrictFrozenModel):
    schema_: Literal["ms.computer/mscomputer-subnet/miner-qualification-plot-spot.v1"] = Field(
        alias="schema"
    )
    request_sha256: Hex64
    plot_id: Hex64
    service_public_key: Hex64
    root: Hex64
    items: list[PlotSpotItem] = Field(min_length=1, max_length=MAX_SPOT_PICKS)
    signature: Hex128


def parse_plot_challenge(raw: bytes) -> PlotChallenge:
    return _parse(raw, PlotChallenge, CODE_PLOT_CHALLENGE_INVALID, MAX_REQUEST_BYTES)


def parse_plot_commitment(raw: bytes) -> PlotCommitment:
    """Strictly parse one plot commitment in its exact canonical bytes."""

    return _parse(
        raw, PlotCommitment, CODE_PLOT_COMMITMENT_INVALID, MAX_REQUEST_BYTES, canonical=True
    )


def parse_plot_seal_request(raw: bytes) -> PlotSealRequest:
    return _parse(raw, PlotSealRequest, CODE_PLOT_REQUEST_INVALID, MAX_REQUEST_BYTES)


def parse_plot_seal(raw: bytes) -> PlotSeal:
    """Strictly parse one seal answer in its exact canonical bytes."""

    return _parse(raw, PlotSeal, CODE_PLOT_ANSWER_INVALID, MAX_PLOT_SEAL_BYTES, canonical=True)


def parse_plot_spot_request(raw: bytes) -> PlotSpotRequest:
    return _parse(raw, PlotSpotRequest, CODE_PLOT_REQUEST_INVALID, MAX_REQUEST_BYTES)


def parse_plot_spot(raw: bytes) -> PlotSpot:
    """Strictly parse one spot answer in its exact canonical bytes."""

    return _parse(raw, PlotSpot, CODE_PLOT_ANSWER_INVALID, MAX_RESPONSE_BYTES, canonical=True)


def plot_challenge_sha256(challenge: PlotChallenge) -> str:
    return hashlib.sha256(canonical_json(model_document(challenge))).hexdigest()


def plot_request_sha256(request: PlotSealRequest | PlotSpotRequest) -> str:
    return hashlib.sha256(canonical_json(model_document(request))).hexdigest()


def plot_chunk_nonce(seed_hex: str, chunk: int) -> bytes:
    """``SHA256("mcq-plot-v3" || 0x00 || seed || u32be(chunk))``."""

    return hashlib.sha256(_PLOT_DOMAIN + _nonce(seed_hex) + chunk.to_bytes(4, "big")).digest()


def plot_ref_index(prev: bytes, n: int) -> int:
    """The reference, in the layer below, of a block whose predecessor is
    ``prev``: ``(u32be(prev[0..4]) * n) >> 32``, uniform over the n blocks."""

    return int.from_bytes(prev[0:4], "big") * n >> 32


def _xor(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(BLOCK_SIZE, "big")


def plot_block(
    prev: bytes | None,
    below: bytes | None,
    ref: bytes | None,
    nonce: bytes,
    layer: int,
    index: int,
) -> bytes:
    """Block ``index`` of ``layer``: ``G(prev, zero, nonce, 0, index)`` on
    layer 0 (prev is zero, passed as None, for index 0), otherwise
    ``G(prev XOR below, ref, nonce, layer, index)``."""

    if layer == 0:
        return g_block(prev, None, nonce, 0, index)
    assert prev is not None and below is not None and ref is not None
    return g_block(_xor(prev, below), ref, nonce, layer, index)


def plot_lower_digest(lower_roots: Sequence[bytes]) -> bytes:
    """``SHA256("mcq-plot-v3-lower" || 0x00 || root_0 || ... || root_{k-2})``."""

    return hashlib.sha256(_PLOT_LOWER_DOMAIN + b"".join(lower_roots)).digest()


def chunk_leaf(lower_digest: bytes, top_root: bytes) -> bytes:
    return leaf_hash(lower_digest + top_root)


def plot_chunk_layers(seed_hex: str, chunk: int, blocks_per_slice: int) -> list[list[bytes]]:
    """Reference: every layer of one chunk. Only for small chunks."""

    nonce = plot_chunk_nonce(seed_hex, chunk)
    n = SLICES * blocks_per_slice
    layers: list[list[bytes]] = []
    for layer in range(PLOT_LAYERS):
        below = layers[-1] if layers else None
        blocks: list[bytes] = []
        for index in range(n):
            prev = blocks[index - 1] if index else (below[n - 1] if below else None)
            if below is None:
                blocks.append(plot_block(prev, None, None, nonce, 0, index))
            else:
                assert prev is not None
                ref = below[plot_ref_index(prev, n)]
                blocks.append(plot_block(prev, below[index], ref, nonce, layer, index))
        layers.append(blocks)
    return layers


def plot_levels(chunk_leaves: Sequence[bytes]) -> list[list[bytes]]:
    """The plot tree over the chunk leaves."""

    return merkle_levels(chunk_leaves)


def verify_plot_commitment(
    commitment: PlotCommitment, challenge: PlotChallenge, bound_service_key_hex: str
) -> None:
    """Accept ``commitment`` only as the bound miner key's plot root for this
    challenge. Same codes and order as Go ``qualification.VerifyPlotCommitment``.

    Not a qualification signal by itself; use the driver, which also seals
    the plot and times the spot checks."""

    if (
        commitment.plot_challenge_sha256 != plot_challenge_sha256(challenge)
        or commitment.plot_id != challenge.plot_id
        or commitment.network != challenge.network
        or commitment.netuid != challenge.netuid
        or commitment.validator_hotkey != challenge.validator_hotkey
        or commitment.miner_hotkey != challenge.miner_hotkey
        or commitment.chunks != challenge.chunks
        or commitment.blocks_per_chunk != challenge.blocks_per_chunk
    ):
        raise QualificationError(CODE_PLOT_CHALLENGE_MISMATCH)
    _verify_signer(PLOT_COMMITMENT_SIGNING_DOMAIN, commitment, bound_service_key_hex)


def _verify_answer_head(
    commitment: PlotCommitment,
    challenge: PlotChallenge,
    bound: str,
    request: PlotSealRequest | PlotSpotRequest,
    answer: PlotSeal | PlotSpot,
) -> None:
    verify_plot_commitment(commitment, challenge, bound)
    if (
        request.plot_challenge_sha256 != commitment.plot_challenge_sha256
        or request.plot_id != commitment.plot_id
        or answer.plot_id != commitment.plot_id
    ):
        raise QualificationError(CODE_PLOT_CHALLENGE_MISMATCH)
    if answer.root != commitment.root or request.root != commitment.root:
        raise QualificationError(CODE_PLOT_ROOT_MISMATCH)
    if answer.request_sha256 != plot_request_sha256(request):
        raise QualificationError(CODE_PLOT_UNREQUESTED)


def _verify_chunk_path(
    chunk: int,
    lower_digest: bytes,
    top_root: bytes,
    path: Sequence[str],
    commitment: PlotCommitment,
) -> None:
    leaf = chunk_leaf(lower_digest, top_root)
    if not verify_path(chunk, commitment.chunks, leaf, path, bytes.fromhex(commitment.root)):
        raise QualificationError(CODE_PLOT_CHUNK_PATH_INVALID)


def _plot_block(value: str) -> bytes:
    try:
        return _decode_block(value)
    except QualificationError as exc:
        raise QualificationError(CODE_PLOT_ANSWER_INVALID) from exc


def _opened_under(opened: OpenedBlock, index: int, n: int, root: bytes) -> bytes:
    if opened.index != index:
        raise QualificationError(CODE_PLOT_REF_INVALID)
    block = _plot_block(opened.block)
    if not verify_path(index, n, leaf_hash(block), opened.path, root):
        raise QualificationError(CODE_PLOT_PATH_INVALID)
    return block


def _verify_seal_opening(
    opening: SealOpening, n: int, roots: Sequence[bytes], nonce: bytes
) -> None:
    block = _plot_block(opening.block)
    if not verify_path(opening.index, n, leaf_hash(block), opening.path, roots[opening.layer]):
        raise QualificationError(CODE_PLOT_PATH_INVALID)
    first = opening.layer == 0 and opening.index == 0
    if (
        (opening.prev is None) != first
        or (opening.below is None) != (opening.layer == 0)
        or (opening.ref is None) != (opening.layer == 0)
    ):
        raise QualificationError(CODE_PLOT_REF_INVALID)
    prev = below = ref = None
    if opening.prev is not None:
        prev_index, prev_root = opening.index - 1, roots[opening.layer]
        if opening.index == 0:
            prev_index, prev_root = n - 1, roots[opening.layer - 1]
        prev = _opened_under(opening.prev, prev_index, n, prev_root)
    if opening.below is not None and opening.ref is not None:
        assert prev is not None
        below = _opened_under(opening.below, opening.index, n, roots[opening.layer - 1])
        ref = _opened_under(opening.ref, plot_ref_index(prev, n), n, roots[opening.layer - 1])
    if block != plot_block(prev, below, ref, nonce, opening.layer, opening.index):
        raise QualificationError(CODE_PLOT_BLOCK_INVALID)


def verify_plot_seal(
    seal: PlotSeal,
    request: PlotSealRequest,
    commitment: PlotCommitment,
    challenge: PlotChallenge,
    bound_service_key_hex: str,
) -> None:
    """Accept ``seal`` only as the bound key's answer to ``request``: the
    layer roots hashed into the chunk leaf and its path, then for each
    opening the block's path under its layer root, its predecessor, the
    block below and the reference derived from the predecessor (each under
    the right layer root) and the G relation. Same codes and order as Go
    ``qualification.VerifyPlotSeal``."""

    _verify_answer_head(commitment, challenge, bound_service_key_hex, request, seal)
    n = commitment.blocks_per_chunk
    if (
        seal.chunk != request.chunk
        or request.chunk >= commitment.chunks
        or [(o.layer, o.index) for o in seal.openings]
        != [(o.layer, o.index) for o in request.openings]
        or any(opening.index >= n for opening in seal.openings)
    ):
        raise QualificationError(CODE_PLOT_UNREQUESTED)
    _verify_signer(PLOT_SEAL_SIGNING_DOMAIN, seal, bound_service_key_hex)
    roots = [bytes.fromhex(root) for root in seal.layer_roots]
    _verify_chunk_path(
        seal.chunk, plot_lower_digest(roots[:-1]), roots[-1], seal.chunk_path, commitment
    )
    nonce = plot_chunk_nonce(challenge.seed, seal.chunk)
    for opening in seal.openings:
        _verify_seal_opening(opening, n, roots, nonce)


def verify_plot_spot(
    spot: PlotSpot,
    request: PlotSpotRequest,
    commitment: PlotCommitment,
    challenge: PlotChallenge,
    bound_service_key_hex: str,
) -> None:
    """Accept ``spot`` only as the bound key's answer to ``request``: every
    pick answered in order, each block's path under its chunk's top root and
    each chunk's path under the plot root. The seal proved the content; a
    spot proves the miner still holds it. Same codes and order as Go
    ``qualification.VerifyPlotSpot``.

    Not a qualification signal by itself; use the driver, which draws the
    picks after the root and times the call."""

    _verify_answer_head(commitment, challenge, bound_service_key_hex, request, spot)
    if len(spot.items) != len(request.picks) or any(
        item.chunk != pick.chunk
        or item.index != pick.index
        or pick.chunk >= commitment.chunks
        or pick.index >= commitment.blocks_per_chunk
        for item, pick in zip(spot.items, request.picks, strict=False)
    ):
        raise QualificationError(CODE_PLOT_UNREQUESTED)
    _verify_signer(PLOT_SPOT_SIGNING_DOMAIN, spot, bound_service_key_hex)
    for item in spot.items:
        top_root = bytes.fromhex(item.top_root)
        _verify_chunk_path(
            item.chunk, bytes.fromhex(item.lower_digest), top_root, item.chunk_path, commitment
        )
        block = _plot_block(item.block)
        if not verify_path(
            item.index, commitment.blocks_per_chunk, leaf_hash(block), item.path, top_root
        ):
            raise QualificationError(CODE_PLOT_PATH_INVALID)


class QualificationSynapseV1(StrictFrozenModel):
    """Round one at the axon: one challenge, validator to miner neuron."""

    protocol: Literal["subnet-qualification-synapse.v1"]
    request_id: RequestID
    caller_hotkey: Hotkey
    challenge: QualificationChallenge


class OpeningsSynapseV1(StrictFrozenModel):
    """Round two at the axon: one openings request."""

    protocol: Literal["subnet-qualification-synapse.v1"]
    request_id: RequestID
    caller_hotkey: Hotkey
    request: OpeningsRequest


class CommitmentResponseV1(StrictFrozenModel):
    protocol: Literal["subnet-qualification-synapse.v1"]
    request_id: RequestID
    commitment: QualificationCommitment


class OpeningsResponseV1(StrictFrozenModel):
    protocol: Literal["subnet-qualification-synapse.v1"]
    request_id: RequestID
    openings: QualificationOpenings


def parse_synapse(raw: bytes) -> QualificationSynapseV1:
    return _parse(raw, QualificationSynapseV1, CODE_CHALLENGE_INVALID, MAX_REQUEST_BYTES)


def parse_openings_synapse(raw: bytes) -> OpeningsSynapseV1:
    return _parse(raw, OpeningsSynapseV1, CODE_REQUEST_INVALID, MAX_REQUEST_BYTES)


def parse_commitment_response(raw: bytes) -> CommitmentResponseV1:
    """Round one's answer in its exact canonical bytes."""

    return _parse(
        raw, CommitmentResponseV1, CODE_COMMITMENT_INVALID, MAX_REQUEST_BYTES, canonical=True
    )


def parse_openings_response(raw: bytes) -> OpeningsResponseV1:
    """Round two's answer in its exact canonical bytes: its length is a
    function of the requested indices alone, never of the miner's choice."""

    return _parse(
        raw, OpeningsResponseV1, CODE_OPENINGS_INVALID, MAX_RESPONSE_BYTES, canonical=True
    )


class PlotSynapseV1(StrictFrozenModel):
    """Plot start or status at the axon: one plot challenge."""

    protocol: Literal["subnet-qualification-synapse.v1"]
    request_id: RequestID
    caller_hotkey: Hotkey
    challenge: PlotChallenge


class PlotSealSynapseV1(StrictFrozenModel):
    """One seal request at the axon, with the plot challenge so a restarted
    axon can still verify the answer; the agent receives only the request."""

    protocol: Literal["subnet-qualification-synapse.v1"]
    request_id: RequestID
    caller_hotkey: Hotkey
    challenge: PlotChallenge
    request: PlotSealRequest


class PlotSpotSynapseV1(StrictFrozenModel):
    """One spot read at the axon, with the plot challenge (see the seal)."""

    protocol: Literal["subnet-qualification-synapse.v1"]
    request_id: RequestID
    caller_hotkey: Hotkey
    challenge: PlotChallenge
    request: PlotSpotRequest


class PlotStatusResponseV1(StrictFrozenModel):
    """``building`` with ``chunks_done`` and no commitment, or ``complete``
    with the signed commitment."""

    protocol: Literal["subnet-qualification-synapse.v1"]
    request_id: RequestID
    state: Literal["building", "complete"]
    chunks_done: int = Field(ge=0, le=MAX_PLOT_CHUNKS)
    commitment: PlotCommitment | None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if (self.state == "complete") != (self.commitment is not None):
            raise ValueError("plot_status_inconsistent")
        if self.commitment is not None and self.chunks_done != self.commitment.chunks:
            raise ValueError("plot_status_inconsistent")
        return self


class PlotSealResponseV1(StrictFrozenModel):
    protocol: Literal["subnet-qualification-synapse.v1"]
    request_id: RequestID
    seal: PlotSeal


class PlotSpotResponseV1(StrictFrozenModel):
    protocol: Literal["subnet-qualification-synapse.v1"]
    request_id: RequestID
    spot: PlotSpot


def parse_plot_synapse(raw: bytes) -> PlotSynapseV1:
    return _parse(raw, PlotSynapseV1, CODE_PLOT_CHALLENGE_INVALID, MAX_REQUEST_BYTES)


def parse_plot_seal_synapse(raw: bytes) -> PlotSealSynapseV1:
    return _parse(raw, PlotSealSynapseV1, CODE_PLOT_REQUEST_INVALID, MAX_REQUEST_BYTES)


def parse_plot_spot_synapse(raw: bytes) -> PlotSpotSynapseV1:
    return _parse(raw, PlotSpotSynapseV1, CODE_PLOT_REQUEST_INVALID, MAX_REQUEST_BYTES)


def parse_plot_status_response(raw: bytes) -> PlotStatusResponseV1:
    """A plot status answer in its exact canonical bytes."""

    return _parse(
        raw,
        PlotStatusResponseV1,
        CODE_PLOT_COMMITMENT_INVALID,
        MAX_REQUEST_BYTES,
        canonical=True,
    )


def parse_plot_seal_response(raw: bytes) -> PlotSealResponseV1:
    """A seal answer in its exact canonical bytes."""

    return _parse(
        raw, PlotSealResponseV1, CODE_PLOT_ANSWER_INVALID, MAX_PLOT_SEAL_BYTES, canonical=True
    )


def parse_plot_spot_response(raw: bytes) -> PlotSpotResponseV1:
    """A spot answer in its exact canonical bytes: its length is fixed by
    the picks, never by the miner's choice."""

    return _parse(
        raw, PlotSpotResponseV1, CODE_PLOT_ANSWER_INVALID, MAX_RESPONSE_BYTES, canonical=True
    )
