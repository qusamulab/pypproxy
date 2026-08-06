from __future__ import annotations

import asyncio
import base64
import time
from dataclasses import dataclass, field
from typing import Any

from pypproxy.core.http import build_url, elapsed_ms, flatten_headers
from pypproxy.core.http import client as http_client
from pypproxy.store.models import Entry


@dataclass
class BulkPayload:
    label: str = ""
    override_body: bytes = b""
    override_headers: dict[str, str] = field(default_factory=dict)
    override_path: str = ""


@dataclass
class BulkResult:
    label: str
    status_code: int = 0
    body: bytes = b""
    duration_ms: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "status_code": self.status_code,
            "body": base64.b64encode(self.body).decode() if self.body else "",
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


async def bulk_send(
    entry: Entry,
    payloads: list[BulkPayload],
    timeout: int = 30,
    concurrency: int = 10,
) -> list[BulkResult]:
    """Send multiple variants of the same request concurrently."""
    sem = asyncio.Semaphore(concurrency)

    async def _one(payload: BulkPayload) -> BulkResult:
        async with sem:
            return await _send(entry, payload, timeout)

    return await asyncio.gather(*[_one(p) for p in payloads])


async def _send(entry: Entry, payload: BulkPayload, timeout: int) -> BulkResult:
    path = payload.override_path or entry.path
    url = build_url(entry.scheme, entry.host, path, entry.query)

    headers = flatten_headers(entry.req_headers)
    headers.update(payload.override_headers)
    body = payload.override_body or entry.req_body

    start = time.monotonic()
    try:
        async with http_client(timeout) as client:
            resp = await client.request(
                method=entry.method,
                url=url,
                headers=headers,
                content=body,
            )
        return BulkResult(
            label=payload.label,
            status_code=resp.status_code,
            body=resp.content,
            duration_ms=elapsed_ms(start),
        )
    except Exception as e:
        return BulkResult(
            label=payload.label,
            duration_ms=elapsed_ms(start),
            error=str(e),
        )


async def race_send(
    entry: Entry,
    count: int = 10,
    timeout: int = 30,
) -> list[BulkResult]:
    """Send the same request `count` times simultaneously (race condition test)."""
    payloads = [BulkPayload(label=f"race-{i}") for i in range(count)]
    return await bulk_send(entry, payloads, timeout=timeout, concurrency=count)
