# Copyright (c) 2026 Ms. Computer. All rights reserved.
# SPDX-License-Identifier: LicenseRef-MsComputer-Miner
"""PROVISIONAL, default-off miner qualification routes of the miner axon.

Registered only with ``--qualification on``:

* ``POST /api/v1/qualification/jobs`` (round one) authenticates the
  validator (btauth/1), binds the challenge to the caller and this miner,
  and forwards it to the Go agent. The agent computes one memory-hard fill
  at a time and answers the signed Merkle commitment.
* ``POST /api/v1/qualification/openings`` (round two) forwards the
  validator's openings request for a relayed challenge until it expires.
* ``GET /api/v1/qualification/payload?challenge_id=`` streams, once, the
  nonce-derived payload of a challenge the agent just answered, to that
  challenge's validator only, until a short grace after its expiry.
* ``GET /api/v1/qualification/ping`` answers an authenticated ping.

With ``--qualification-plots on`` as well (default off), the disk plot routes
forward to the agent, with the same btauth and identity checks and their own
PROVISIONAL per-validator limits:

* ``POST /api/v1/qualification/plots`` starts or resumes a plot build;
* ``POST /api/v1/qualification/plots/status`` answers ``building`` or the
  signed plot commitment, verified before it is relayed;
* ``POST /api/v1/qualification/plot-seals`` answers one seal request (the
  one-time proof that the layers were computed), verified before it is
  relayed;
* ``POST /api/v1/qualification/plot-spots`` answers one spot read of up to 8
  stored blocks, verified under the plot commitment before it is relayed.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections import OrderedDict, deque
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal

from fastapi import HTTPException, Request, Response
from fastapi.responses import StreamingResponse

from . import qualification_wire as contracts
from .auth import BridgeError, qualification_ping_message
from .contract_codec import canonical_json, model_document

if TYPE_CHECKING:
    from .miner import Caller, MinerNeuron

ISSUE_SKEW_SECONDS: Final = 30
PAYLOAD_GRACE_SECONDS: Final = 120
MAX_PAYLOAD_GRANTS: Final = 16
PAYLOAD_CHUNK_BYTES: Final = 1 << 20
QUALIFICATION_BUSY: Final = "qualification_busy"
PAYLOAD_UNAVAILABLE: Final = "qualification_payload_unavailable"
AGENT_ANSWER_INVALID: Final = "qualification_agent_answer_invalid"
FILL_ABSENT: Final = "qualification_fill_absent"
OPENINGS_SERVED_EXHAUSTED: Final = "qualification_openings_served_exhausted"
POLICY_REFUSED: Final = "qualification_policy_refused"
RATE_LIMITED: Final = "qualification_rate_limited"
# PROVISIONAL server-side policy defaults, mirrored by the Go agent.
DEFAULT_MAX_FILL_MIB: Final = 16384
DEFAULT_JOBS_PER_HOUR: Final = 4
JOBS_WINDOW_SECONDS: Final = 3600.0
PINGS_PER_WINDOW: Final = 120
PING_WINDOW_SECONDS: Final = 60.0
PAYLOAD_RATE_EXCEEDED: Final = "qualification_payload_rate_exceeded"
# PROVISIONAL per-validator payload egress bound: at most this many
# downloads in any PAYLOAD_RATE_WINDOW_SECONDS.
PAYLOAD_DOWNLOADS_PER_WINDOW: Final = 4
PAYLOAD_RATE_WINDOW_SECONDS: Final = 3600.0
PLOT_BUSY: Final = "qualification_plot_busy"
PLOT_REQUEST_MISMATCH: Final = "qualification_plot_spot_request_mismatch"
PLOT_BUILDING: Final = "qualification_plot_building"
# PROVISIONAL per-validator plot limits: (requests, window seconds).
PLOT_STARTS_PER_WINDOW: Final = (4, 86_400.0)
PLOT_STATUS_PER_WINDOW: Final = (240, 3_600.0)
PLOT_SPOTS_PER_WINDOW: Final = (512, 3_600.0)
# A seal is one call per chunk (twice with the pending retry), once per plot.
PLOT_SEALS_PER_WINDOW: Final = (16_384, 86_400.0)
MAX_PLOT_COMMITMENTS: Final = 16
_CHALLENGE_ID: Final = re.compile(r"[0-9a-f]{64}")
_PING_NONCE: Final = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class PayloadGrant:
    validator_hotkey: str
    nonce: str
    size: int
    available_until: int


class QualificationIngress:
    """The qualification routes of one miner neuron."""

    def __init__(
        self,
        neuron: MinerNeuron,
        clock: Callable[[], float] = time.time,
        *,
        max_fill_mib: int = DEFAULT_MAX_FILL_MIB,
        jobs_per_hour: int = DEFAULT_JOBS_PER_HOUR,
        plots: bool = False,
    ) -> None:
        if not 1 <= max_fill_mib * 64 <= contracts.MAX_FILL_BLOCKS or jobs_per_hour < 1:
            raise ValueError("qualification policy is out of range")
        self.neuron = neuron
        self.clock = clock
        self.max_fill_blocks = max_fill_mib * 64
        self.jobs_per_hour = jobs_per_hour
        self.job_history: dict[str, deque[float]] = {}
        self.ping_history: dict[str, deque[float]] = {}
        self.lock = asyncio.Lock()
        self.grants: OrderedDict[str, PayloadGrant] = OrderedDict()
        self.openings_lock = asyncio.Lock()
        self.opened: dict[str, int] = {}
        self.payload_downloads: dict[str, deque[float]] = {}
        self.commitments: OrderedDict[
            str, tuple[contracts.QualificationChallenge, contracts.QualificationCommitment]
        ] = OrderedDict()
        self.plots = plots
        self.plot_history: dict[str, dict[str, deque[float]]] = {
            "starts": {},
            "status": {},
            "spots": {},
            "seals": {},
        }
        self.plot_lock = asyncio.Lock()
        self.plot_commitments: OrderedDict[str, tuple[str, contracts.PlotCommitment]] = (
            OrderedDict()
        )

    def register(self) -> None:
        app = self.neuron.app
        app.add_api_route(
            "/api/v1/qualification/jobs", self.jobs, methods=["POST"], response_model=None
        )
        app.add_api_route(
            "/api/v1/qualification/openings", self.openings, methods=["POST"], response_model=None
        )
        app.add_api_route(
            "/api/v1/qualification/payload", self.payload, methods=["GET"], response_model=None
        )
        app.add_api_route(
            "/api/v1/qualification/ping", self.ping, methods=["GET"], response_model=None
        )
        if not self.plots:
            return
        app.add_api_route(
            "/api/v1/qualification/plots", self.plot_start, methods=["POST"], response_model=None
        )
        app.add_api_route(
            "/api/v1/qualification/plots/status",
            self.plot_status,
            methods=["POST"],
            response_model=None,
        )
        app.add_api_route(
            "/api/v1/qualification/plot-spots",
            self.plot_spot,
            methods=["POST"],
            response_model=None,
        )
        app.add_api_route(
            "/api/v1/qualification/plot-seals",
            self.plot_seal,
            methods=["POST"],
            response_model=None,
        )

    async def _identified(self, request: Request, body: bytes) -> Caller:
        """btauth plus the operator, permit and stake checks. Qualification
        routes are counted in their own per-validator limits, not in the
        neuron's default window, which one check's sequential openings would
        exhaust."""

        neuron = self.neuron
        return await neuron.authorization.identify(await neuron._verified_hotkey(request, body))

    def _bind(self, synapse: contracts.QualificationSynapseV1, caller: str) -> None:
        challenge = synapse.challenge
        neuron = self.neuron
        if (
            synapse.caller_hotkey != caller
            or challenge.validator_hotkey != caller
            or challenge.miner_hotkey != neuron.hotkey
            or neuron.uid is None
            or challenge.miner_uid != neuron.uid
            or challenge.network != neuron.network
            or challenge.netuid != neuron.netuid
        ):
            raise HTTPException(status_code=403, detail="qualification_identity_mismatch")
        now = self.clock()
        if now < challenge.issued_at_unix - ISSUE_SKEW_SECONDS or now >= challenge.expires_at_unix:
            raise HTTPException(status_code=410, detail="qualification_challenge_expired")
        if challenge.fill.blocks > self.max_fill_blocks:
            raise HTTPException(status_code=422, detail=POLICY_REFUSED)

    def _admit(
        self, histories: dict[str, deque[float]], hotkey: str, limit: int, window: float
    ) -> None:
        """Count one request of ``hotkey``; refuse past ``limit`` per ``window``."""

        now = self.clock()
        history = histories.setdefault(hotkey, deque())
        while history and history[0] <= now - window:
            history.popleft()
        if len(history) >= limit:
            raise HTTPException(status_code=429, detail=RATE_LIMITED)
        history.append(now)

    async def jobs(self, request: Request) -> Response:
        neuron = self.neuron
        body = await neuron._body(request)
        caller = await self._identified(request, body)
        try:
            synapse = contracts.parse_synapse(body)
        except contracts.QualificationError as exc:
            raise HTTPException(status_code=422, detail=exc.code) from exc
        self._bind(synapse, caller.hotkey)
        if self.lock.locked():
            raise HTTPException(status_code=429, detail=QUALIFICATION_BUSY)
        self._admit(self.job_history, caller.hotkey, self.jobs_per_hour, JOBS_WINDOW_SECONDS)
        async with self.lock:
            try:
                answer = await neuron.bridge.request(
                    "POST",
                    "/v1/qualification/jobs",
                    value={
                        "protocol": contracts.SYNAPSE_VERSION,
                        "request_id": synapse.request_id,
                        "caller_hotkey": caller.hotkey,
                        "challenge": contracts.challenge_document(synapse.challenge),
                    },
                )
            except BridgeError as exc:
                raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        try:
            response = contracts.parse_commitment_response(canonical_json(answer))
            commitment = response.commitment
            if response.request_id != synapse.request_id:
                raise ValueError("request_id")
            # Only self-consistency under the commitment's own key: binding
            # that key to this miner is the validator's obligation, and a
            # validator that skips it trusts a miner-chosen key.
            contracts.verify_commitment(
                commitment, synapse.challenge, commitment.service_public_key
            )
        except (contracts.QualificationError, ValueError) as exc:
            raise HTTPException(status_code=502, detail=AGENT_ANSWER_INVALID) from exc
        self._grant(synapse.challenge)
        self.commitments[synapse.challenge.challenge_id] = (synapse.challenge, commitment)
        while len(self.commitments) > MAX_PAYLOAD_GRANTS:
            evicted, _ = self.commitments.popitem(last=False)
            self.opened.pop(evicted, None)
        return Response(
            content=canonical_json(response.model_dump(mode="json", by_alias=True)),
            media_type="application/json",
        )

    async def openings(self, request: Request) -> Response:
        """Round two: forward one openings request of a challenge this axon
        relayed, from its validator, until the challenge expires. The agent's
        answer is verified under the relayed commitment before it is
        returned."""

        neuron = self.neuron
        body = await neuron._body(request)
        caller = await self._identified(request, body)
        try:
            synapse = contracts.parse_openings_synapse(body)
        except contracts.QualificationError as exc:
            raise HTTPException(status_code=422, detail=exc.code) from exc
        challenge_id = synapse.request.challenge_id
        held = self.commitments.get(challenge_id)
        if synapse.caller_hotkey != caller.hotkey or (
            held is not None and held[0].validator_hotkey != caller.hotkey
        ):
            raise HTTPException(status_code=403, detail="qualification_identity_mismatch")
        if held is None or self.clock() >= held[0].expires_at_unix:
            raise HTTPException(status_code=404, detail=FILL_ABSENT)
        challenge, commitment = held
        opened = self.opened.get(challenge_id, 0) + len(synapse.request.indices)
        if opened > contracts.max_openings_served(challenge.openings):
            raise HTTPException(status_code=429, detail=OPENINGS_SERVED_EXHAUSTED)
        if self.openings_lock.locked():
            raise HTTPException(status_code=429, detail=QUALIFICATION_BUSY)
        self.opened[challenge_id] = opened
        async with self.openings_lock:
            try:
                answer = await neuron.bridge.request(
                    "POST",
                    "/v1/qualification/openings",
                    value={
                        "protocol": contracts.SYNAPSE_VERSION,
                        "request_id": synapse.request_id,
                        "caller_hotkey": caller.hotkey,
                        "request": model_document(synapse.request),
                    },
                )
            except BridgeError as exc:
                # The agent served nothing: return the budget.
                self.opened[challenge_id] = opened - len(synapse.request.indices)
                raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        try:
            response = contracts.parse_openings_response(canonical_json(answer))
            if response.request_id != synapse.request_id:
                raise ValueError("request_id")
            contracts.verify_openings(
                response.openings,
                synapse.request,
                commitment,
                challenge,
                commitment.service_public_key,
            )
        except (contracts.QualificationError, ValueError) as exc:
            raise HTTPException(status_code=502, detail=AGENT_ANSWER_INVALID) from exc
        return Response(
            content=canonical_json(response.model_dump(mode="json", by_alias=True)),
            media_type="application/json",
        )

    def _grant(self, challenge: contracts.QualificationChallenge) -> None:
        self.grants[challenge.challenge_id] = PayloadGrant(
            validator_hotkey=challenge.validator_hotkey,
            nonce=challenge.nonce,
            size=challenge.payload_bytes,
            available_until=challenge.expires_at_unix + PAYLOAD_GRACE_SECONDS,
        )
        while len(self.grants) > MAX_PAYLOAD_GRANTS:
            self.grants.popitem(last=False)

    async def payload(self, request: Request) -> StreamingResponse:
        neuron = self.neuron
        caller = await self._identified(request, await neuron._body(request))
        challenge_id = request.query_params.get("challenge_id", "")
        if set(request.query_params) != {"challenge_id"} or not _CHALLENGE_ID.fullmatch(
            challenge_id
        ):
            raise HTTPException(status_code=400, detail="qualification_payload_request_invalid")
        grant = self.grants.get(challenge_id)
        if (
            grant is None
            or grant.validator_hotkey != caller.hotkey
            or self.clock() > grant.available_until
        ):
            raise HTTPException(status_code=404, detail=PAYLOAD_UNAVAILABLE)
        now = self.clock()
        history = self.payload_downloads.setdefault(caller.hotkey, deque())
        while history and history[0] <= now - PAYLOAD_RATE_WINDOW_SECONDS:
            history.popleft()
        if len(history) >= PAYLOAD_DOWNLOADS_PER_WINDOW:
            raise HTTPException(status_code=429, detail=PAYLOAD_RATE_EXCEEDED)
        history.append(now)
        # Served once: a second download would be free amplification.
        del self.grants[challenge_id]
        return StreamingResponse(
            _stream(grant),
            media_type="application/octet-stream",
            headers={"Content-Length": str(grant.size), "Cache-Control": "no-store"},
        )

    async def ping(self, request: Request) -> Response:
        started = time.monotonic_ns()
        caller = await self._identified(request, await self.neuron._body(request))
        self._admit(self.ping_history, caller.hotkey, PINGS_PER_WINDOW, PING_WINDOW_SECONDS)
        nonce = request.query_params.get("nonce")
        if nonce is None:
            # Validators that send no nonce get the exact prior answer.
            return Response(
                content=canonical_json({"ok": True, "protocol": contracts.SYNAPSE_VERSION}),
                media_type="application/json",
            )
        if not _PING_NONCE.fullmatch(nonce) or len(request.query_params.multi_items()) != 1:
            raise HTTPException(status_code=422, detail="ping nonce must be 64 lower-case hex")
        # Server time before signing: what the miner spent answering, so the
        # validator can tell compute latency from transport latency.
        elapsed = time.monotonic_ns() - started
        neuron = self.neuron
        signature = neuron.hotkey_signer.sign_qualification_ping(
            qualification_ping_message(
                nonce=nonce,
                validator_hotkey=caller.hotkey,
                miner_hotkey=neuron.hotkey,
                server_elapsed_ns=elapsed,
            )
        )
        return Response(
            content=canonical_json(
                {
                    "ok": True,
                    "protocol": contracts.SYNAPSE_VERSION,
                    "nonce": nonce,
                    "server_elapsed_ns": elapsed,
                    "signature": signature.hex(),
                }
            ),
            media_type="application/json",
        )

    def _bind_plot(
        self, challenge: contracts.PlotChallenge, synapse_caller: str, caller: str
    ) -> None:
        neuron = self.neuron
        if (
            synapse_caller != caller
            or challenge.validator_hotkey != caller
            or challenge.miner_hotkey != neuron.hotkey
            or neuron.uid is None
            or challenge.miner_uid != neuron.uid
            or challenge.network != neuron.network
            or challenge.netuid != neuron.netuid
        ):
            raise HTTPException(status_code=403, detail="qualification_identity_mismatch")

    def _admit_plot(self, kind: str, hotkey: str) -> None:
        limit, window = {
            "starts": PLOT_STARTS_PER_WINDOW,
            "status": PLOT_STATUS_PER_WINDOW,
            "spots": PLOT_SPOTS_PER_WINDOW,
            "seals": PLOT_SEALS_PER_WINDOW,
        }[kind]
        self._admit(self.plot_history[kind], hotkey, limit, window)

    async def _forward(
        self, path: str, value: dict[str, object], max_bytes: int | None = None
    ) -> object:
        try:
            if max_bytes is not None:
                return await self.neuron.bridge.request(
                    "POST", path, value=value, max_bytes=max_bytes
                )
            return await self.neuron.bridge.request("POST", path, value=value)
        except BridgeError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc

    async def _plot_status_answer(
        self, path: str, synapse: contracts.PlotSynapseV1, caller: str
    ) -> contracts.PlotStatusResponseV1:
        """Forward a plot challenge; verify a returned commitment under its
        own key (binding that key is the validator's obligation) and keep it
        for the spot route."""

        answer = await self._forward(
            path,
            {
                "protocol": contracts.SYNAPSE_VERSION,
                "request_id": synapse.request_id,
                "caller_hotkey": caller,
                "challenge": model_document(synapse.challenge),
            },
        )
        try:
            response = contracts.parse_plot_status_response(canonical_json(answer))
            if response.request_id != synapse.request_id:
                raise ValueError("request_id")
            if response.commitment is not None:
                contracts.verify_plot_commitment(
                    response.commitment, synapse.challenge, response.commitment.service_public_key
                )
        except (contracts.QualificationError, ValueError) as exc:
            raise HTTPException(status_code=502, detail=AGENT_ANSWER_INVALID) from exc
        if response.commitment is not None:
            digest = contracts.plot_challenge_sha256(synapse.challenge)
            self.plot_commitments[synapse.challenge.plot_id] = (digest, response.commitment)
            self.plot_commitments.move_to_end(synapse.challenge.plot_id)
            while len(self.plot_commitments) > MAX_PLOT_COMMITMENTS:
                self.plot_commitments.popitem(last=False)
        return response

    async def _plot_challenge_route(self, request: Request, kind: str, path: str) -> Response:
        neuron = self.neuron
        body = await neuron._body(request)
        caller = await self._identified(request, body)
        try:
            synapse = contracts.parse_plot_synapse(body)
        except contracts.QualificationError as exc:
            raise HTTPException(status_code=422, detail=exc.code) from exc
        self._bind_plot(synapse.challenge, synapse.caller_hotkey, caller.hotkey)
        if kind == "starts":
            now = self.clock()
            challenge = synapse.challenge
            if (
                now < challenge.issued_at_unix - ISSUE_SKEW_SECONDS
                or now >= challenge.build_expires_at_unix
            ):
                raise HTTPException(status_code=410, detail="qualification_challenge_expired")
        self._admit_plot(kind, caller.hotkey)
        response = await self._plot_status_answer(path, synapse, caller.hotkey)
        return Response(
            content=canonical_json(model_document(response)), media_type="application/json"
        )

    async def plot_start(self, request: Request) -> Response:
        """Start or resume the plot build of one plot challenge."""

        return await self._plot_challenge_route(request, "starts", "/v1/qualification/plots")

    async def plot_status(self, request: Request) -> Response:
        """``building`` (with ``chunks_done``) or the verified commitment."""

        return await self._plot_challenge_route(request, "status", "/v1/qualification/plots/status")

    async def plot_spot(self, request: Request) -> Response:
        """One spot read of up to 8 stored blocks, one at a time, verified
        under the plot commitment before it is relayed."""

        return await self._plot_answer(request, "spot")

    async def plot_seal(self, request: Request) -> Response:
        """One seal request, verified (the opened layer blocks' G relations) before it is
        relayed. The agent's first answer for a chunk is the retryable
        ``qualification_plot_seal_pending``."""

        return await self._plot_answer(request, "seal")

    async def _plot_answer(self, request: Request, kind: Literal["seal", "spot"]) -> Response:
        neuron = self.neuron
        body = await neuron._body(request)
        caller = await self._identified(request, body)
        synapse: contracts.PlotSealSynapseV1 | contracts.PlotSpotSynapseV1
        try:
            synapse = (
                contracts.parse_plot_seal_synapse(body)
                if kind == "seal"
                else contracts.parse_plot_spot_synapse(body)
            )
        except contracts.QualificationError as exc:
            raise HTTPException(status_code=422, detail=exc.code) from exc
        challenge, plot_request = synapse.challenge, synapse.request
        self._bind_plot(challenge, synapse.caller_hotkey, caller.hotkey)
        digest = contracts.plot_challenge_sha256(challenge)
        if (
            plot_request.plot_id != challenge.plot_id
            or plot_request.plot_challenge_sha256 != digest
        ):
            raise HTTPException(status_code=409, detail=PLOT_REQUEST_MISMATCH)
        self._admit_plot("seals" if kind == "seal" else "spots", caller.hotkey)
        if self.plot_lock.locked():
            raise HTTPException(status_code=429, detail=PLOT_BUSY)
        async with self.plot_lock:
            held = self.plot_commitments.get(challenge.plot_id)
            if held is None or held[0] != digest:
                status = await self._plot_status_answer(
                    "/v1/qualification/plots/status",
                    contracts.PlotSynapseV1(
                        protocol=synapse.protocol,
                        request_id=synapse.request_id,
                        caller_hotkey=synapse.caller_hotkey,
                        challenge=challenge,
                    ),
                    caller.hotkey,
                )
                if status.commitment is None:
                    raise HTTPException(status_code=409, detail=PLOT_BUILDING)
                commitment = status.commitment
            else:
                commitment = held[1]
            answer = await self._forward(
                "/v1/qualification/plot-seals"
                if kind == "seal"
                else "/v1/qualification/plot-spots",
                {
                    "protocol": contracts.SYNAPSE_VERSION,
                    "request_id": synapse.request_id,
                    "caller_hotkey": caller.hotkey,
                    "request": model_document(plot_request),
                },
                # A seal answer opens every layer: up to MAX_PLOT_SEAL_BYTES.
                contracts.MAX_PLOT_SEAL_BYTES if kind == "seal" else None,
            )
        response: contracts.PlotSealResponseV1 | contracts.PlotSpotResponseV1
        try:
            if isinstance(plot_request, contracts.PlotSealRequest):
                response = contracts.parse_plot_seal_response(canonical_json(answer))
                contracts.verify_plot_seal(
                    response.seal,
                    plot_request,
                    commitment,
                    challenge,
                    commitment.service_public_key,
                )
            else:
                response = contracts.parse_plot_spot_response(canonical_json(answer))
                contracts.verify_plot_spot(
                    response.spot,
                    plot_request,
                    commitment,
                    challenge,
                    commitment.service_public_key,
                )
            if response.request_id != synapse.request_id:
                raise ValueError("request_id")
        except (contracts.QualificationError, ValueError) as exc:
            raise HTTPException(status_code=502, detail=AGENT_ANSWER_INVALID) from exc
        return Response(
            content=canonical_json(model_document(response)), media_type="application/json"
        )


async def _stream(grant: PayloadGrant) -> AsyncIterator[bytes]:
    offset = 0
    while offset < grant.size:
        take = min(grant.size - offset, PAYLOAD_CHUNK_BYTES)
        yield await asyncio.to_thread(contracts.payload_chunk, grant.nonce, offset // 32, take)
        offset += take
