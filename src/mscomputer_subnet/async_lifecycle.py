# Copyright (c) 2026 Ms. Computer. All rights reserved.
# SPDX-License-Identifier: LicenseRef-MsComputer-Miner
"""Cancellation-safe flushing of application-owned asynchronous resources."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any


async def settle_cleanup[T](operation: Coroutine[Any, Any, T], *, name: str) -> T:
    """Finish cleanup despite repeated caller cancellation, then propagate it.

    The owned task is never detached: its result/exception is always retrieved.
    Callers already unwinding a primary failure should preserve that failure
    when this cleanup reports an error or a later cancellation.
    """

    task = asyncio.create_task(operation, name=name)
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
    result = task.result()
    if cancelled:
        raise asyncio.CancelledError
    return result
