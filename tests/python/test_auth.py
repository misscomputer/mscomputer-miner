# Copyright (c) 2026 Ms. Computer. All rights reserved.
# SPDX-License-Identifier: LicenseRef-MsComputer-Miner
from __future__ import annotations

import httpx
import pytest

from mscomputer_subnet.auth import (
    BridgeClient,
    BridgeError,
    loopback_bridge_url,
)


def test_bridge_client_url_cannot_send_hmac_off_host() -> None:
    assert loopback_bridge_url("http://127.0.0.1:9101/") == "http://127.0.0.1:9101"
    assert loopback_bridge_url("http://[::1]:9201") == "http://[::1]:9201"
    for value in (
        "http://localhost:9101",
        "http://10.0.0.2:9101",
        "https://127.0.0.1:9101",
        "http://user@127.0.0.1:9101",
        "http://127.0.0.1:9101/path",
    ):
        with pytest.raises(ValueError, match="loopback"):
            loopback_bridge_url(value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        b"not-json-" + b"untrusted-marker" * 4096,
        b"[]",
        b"[" * 10_000 + b"0" + b"]" * 10_000,
        b'{"error":' + b"9" * 5_000 + b"}",
    ],
)
async def test_bridge_client_maps_malformed_error_bodies_without_reflection(body: bytes) -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(httpx.codes.BAD_GATEWAY, content=body)

    client = BridgeClient(
        "http://127.0.0.1:9101",
        b"s" * 32,
        retries=0,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(BridgeError) as raised:
        await client.request("GET", "/v1/capabilities")
    error = raised.value
    assert error.code == "bridge_error"
    assert error.status_code == httpx.codes.BAD_GATEWAY
    assert error.retryable is False
    assert str(error) == "bridge_error: HTTP 502"
    assert "untrusted-marker" not in str(error)


@pytest.mark.asyncio
async def test_bridge_client_bounds_structured_error_fields() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            httpx.codes.BAD_REQUEST,
            json={
                "error": {
                    "code": "c" * 1024,
                    "message": "m" * 4096,
                    "retryable": "true",
                }
            },
        )

    client = BridgeClient(
        "http://127.0.0.1:9101",
        b"s" * 32,
        retries=0,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(BridgeError) as raised:
        await client.request("GET", "/v1/capabilities")
    assert len(raised.value.code) == 128
    assert len(str(raised.value)) == 128 + 2 + 1024
    assert raised.value.retryable is False


@pytest.mark.asyncio
async def test_bridge_client_keeps_a_retryable_error_after_its_retries() -> None:
    calls = 0

    async def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            httpx.codes.CONFLICT,
            json={
                "error": {
                    "code": "qualification_plot_seal_pending",
                    "message": "pending",
                    "retryable": True,
                }
            },
        )

    client = BridgeClient(
        "http://127.0.0.1:9101",
        b"s" * 32,
        retries=1,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(BridgeError) as raised:
        await client.request("POST", "/v1/qualification/plot-seals", value={})
    assert calls == 2
    assert raised.value.code == "qualification_plot_seal_pending"
    assert raised.value.status_code == 409 and raised.value.retryable


@pytest.mark.asyncio
async def test_bridge_client_transport_failure_stays_a_runtime_error() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = BridgeClient(
        "http://127.0.0.1:9101",
        b"s" * 32,
        retries=1,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(RuntimeError, match="bridge request failed"):
        await client.request("GET", "/v1/capabilities")


@pytest.mark.asyncio
async def test_bridge_client_reuses_one_verifying_ssl_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ssl

    built: list[ssl.SSLContext] = []
    real_create = httpx.create_ssl_context

    def counting_create(*args: object, **kwargs: object) -> ssl.SSLContext:
        ctx = real_create(*args, **kwargs)  # type: ignore[arg-type]
        built.append(ctx)
        return ctx

    monkeypatch.setattr(httpx, "create_ssl_context", counting_create)
    seen: list[object] = []
    real_client = httpx.AsyncClient

    def recording_client(*args: object, **kwargs: object) -> httpx.AsyncClient:
        seen.append(kwargs.get("verify"))
        return real_client(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx, "AsyncClient", recording_client)

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    client = BridgeClient(
        "http://127.0.0.1:9101", b"s" * 32, transport=httpx.MockTransport(handler)
    )
    for _ in range(3):
        assert await client.request("POST", "/v1/qualification/openings", value={}) == {"ok": True}
    assert len(built) == 1
    assert len(seen) == 3 and all(v is built[0] for v in seen)
    assert built[0].verify_mode == ssl.CERT_REQUIRED and built[0].check_hostname
