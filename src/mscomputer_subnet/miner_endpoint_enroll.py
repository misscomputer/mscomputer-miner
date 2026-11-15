# Copyright (c) 2026 Ms. Computer. All rights reserved.
# SPDX-License-Identifier: LicenseRef-MsComputer-Miner
"""``mscomputer-miner endpoint-enroll``: privately register this miner's direct address.

Signs one :mod:`mscomputer_subnet.miner_endpoint` enrollment with the hotkey
and the axon TLS key and POSTs it to the operator. Nothing is published on
chain. Re-run before ``--ttl`` runs out (the installer's timer does).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections.abc import Callable, Sequence
from typing import Any, Final

import bittensor as bt
import httpx

from . import miner_endpoint as me
from .auth import HotkeySigningFacade
from .tls import validate_miner_tls_files

COMMAND: Final = "endpoint-enroll"
DEFAULT_URL: Final = "https://api.ms.computer/v1/miner-endpoint"
_RETRY_STATUSES: Final = frozenset({429, 500, 502, 503, 504})
_MAX_RETRY_AFTER: Final = 300.0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=f"mscomputer-miner {COMMAND}",
        description="Privately register this miner's direct axon address with the operator."
        " Signed by the hotkey and the axon TLS key; nothing is published on chain.",
    )
    parser.add_argument("--url", default=os.getenv("MC_MINER_ENDPOINT_URL", DEFAULT_URL))
    parser.add_argument("--netuid", type=int, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--subtensor-network", default=os.getenv("BT_NETWORK", "finney"))
    parser.add_argument("--operator-hotkey", required=True, help="the operator (validator) hotkey")
    parser.add_argument(
        "--ip",
        default=me.AUTO_IP,
        help="public IP validators dial; 'auto' (default) = the address this request comes from",
    )
    parser.add_argument("--port", type=int, required=True, help="public axon port")
    parser.add_argument("--tls-cert-file", required=True)
    parser.add_argument("--tls-key-file", required=True)
    parser.add_argument("--wallet-name", default=os.getenv("BT_WALLET", "default"))
    parser.add_argument("--wallet-hotkey", default=os.getenv("BT_WALLET_HOTKEY", "default"))
    parser.add_argument(
        "--wallet-path", default=os.getenv("BT_WALLET_PATH", "~/.bittensor/wallets")
    )
    parser.add_argument("--ttl", type=int, default=me.DEFAULT_TTL_SECONDS, help="seconds")
    parser.add_argument("--attempts", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument(
        "--dry-run", action="store_true", help="print the unsigned request; send nothing"
    )
    return parser


def _url(value: str) -> str:
    parsed = httpx.URL(value)
    if (
        parsed.scheme != "https"
        or not parsed.host
        or parsed.userinfo
        or parsed.query
        or parsed.fragment
        or any(ord(character) <= 0x20 for character in value)
    ):
        raise ValueError("--url must be an https:// URL without credentials, query or fragment")
    return value


def _error_code(response: httpx.Response) -> tuple[str, bool | None]:
    try:
        error = response.json()["error"]
        code, retryable = error["code"], error.get("retryable")
    except (ValueError, KeyError, TypeError):
        return "", None
    if not isinstance(code, str) or not re.fullmatch(r"[a-z0-9_]{1,64}", code):
        code = ""
    return code, retryable if isinstance(retryable, bool) else None


def main(
    argv: Sequence[str],
    *,
    signer: HotkeySigningFacade | None = None,
    transport: httpx.BaseTransport | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    args = build_parser().parse_args(list(argv))
    try:
        url = _url(args.url)
        if not 1 <= args.attempts <= 20 or not 0 < args.timeout <= 300:
            raise ValueError("--attempts must be 1-20 and --timeout in (0, 300]")
        if not me.MIN_TTL_SECONDS <= args.ttl <= me.MAX_TTL_SECONDS:
            raise ValueError(f"--ttl must be {me.MIN_TTL_SECONDS}-{me.MAX_TTL_SECONDS}")
        tls = validate_miner_tls_files(args.tls_cert_file, args.tls_key_file)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if signer is None:
        signer = HotkeySigningFacade(
            bt.Wallet(
                args.wallet_name, args.wallet_hotkey, path=os.path.expanduser(args.wallet_path)
            )
        )

    def fresh() -> me.Enrollment:
        return me.new_enrollment(
            network=args.subtensor_network,
            netuid=args.netuid,
            operator=args.operator_hotkey,
            hotkey=signer.hotkey,
            uid=args.uid,
            ip=args.ip,
            port=args.port,
            certificate_sha256=tls.fingerprint_sha256,
            ttl_seconds=args.ttl,
        )

    try:
        first = fresh()
    except ValueError as exc:
        print(f"enrollment fields are invalid: {exc}", file=sys.stderr)
        return 2
    if args.dry_run:
        print(
            json.dumps(
                {"dry_run": True, "url": url, "message": first.message().decode("ascii")},
                sort_keys=True,
            ),
            flush=True,
        )
        return 0

    def body() -> dict[str, Any]:
        enrollment = fresh()
        message = enrollment.message()
        return me.request_body(
            message,
            signer.sign_miner_endpoint_enrollment(message),
            tls.sign_transport_possession(enrollment.possession_message()),
        )

    with httpx.Client(
        transport=transport, timeout=args.timeout, follow_redirects=False, trust_env=False
    ) as client:
        for attempt in range(1, args.attempts + 1):
            delay = float(min(2**attempt, 60))
            try:
                response = client.post(url, json=body(), headers={"Accept": "application/json"})
            except httpx.HTTPError as exc:
                print(f"attempt {attempt}: request failed ({type(exc).__name__})", file=sys.stderr)
            else:
                if response.status_code == 200:
                    try:
                        answer = response.json()
                        ok = (
                            isinstance(answer, dict)
                            and answer.get("protocol") == me.PROTOCOL
                            and answer.get("uid") == args.uid
                            and answer.get("hotkey") == signer.hotkey
                            and answer.get("port") == args.port
                        )
                    except ValueError:
                        ok = False
                    if not ok:
                        print("enrollment answer refused", file=sys.stderr)
                        return 1
                    print(
                        json.dumps(
                            {k: answer[k] for k in ("uid", "ip", "port", "expires")},
                            sort_keys=True,
                        ),
                        flush=True,
                    )
                    return 0
                code, retryable = _error_code(response)
                if response.status_code == 429 and code == "too_soon":
                    print("already enrolled with this address recently; nothing to do", flush=True)
                    return 0
                print(
                    f"attempt {attempt}: enrollment refused: status {response.status_code}"
                    + (f" {code}" if code else ""),
                    file=sys.stderr,
                    flush=True,
                )
                if retryable is False or (
                    retryable is None and response.status_code not in _RETRY_STATUSES
                ):
                    return 1
                value = response.headers.get("Retry-After", "")
                if value.isascii() and value.isdigit():
                    delay = min(float(value), _MAX_RETRY_AFTER)
                if response.status_code in (422, 429):
                    # The operator admits one attempt per hotkey per minute.
                    delay = max(delay, 65.0)
            if attempt < args.attempts:
                sleep(delay)
    print("enrollment did not succeed", file=sys.stderr)
    return 1
