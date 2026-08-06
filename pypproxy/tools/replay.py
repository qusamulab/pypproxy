from __future__ import annotations

import asyncio
import base64
import time
from dataclasses import dataclass, field

from pypproxy.core.http import build_url, elapsed_ms, flatten_headers
from pypproxy.core.http import client as http_client
from pypproxy.store.models import Entry


@dataclass
class ReplayOptions:
    override_host: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 30
    count: int = 1


@dataclass
class ReplayResult:
    entry_id: int
    status_code: int = 0
    body: bytes = b""
    duration_ms: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "status_code": self.status_code,
            "body": base64.b64encode(self.body).decode() if self.body else "",
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


async def replay_one(entry: Entry, opts: ReplayOptions) -> ReplayResult:
    host = opts.override_host or entry.host
    url = build_url(entry.scheme, host, entry.path, entry.query)

    headers = flatten_headers(entry.req_headers)
    headers.update(opts.extra_headers)

    start = time.monotonic()
    try:
        async with http_client(opts.timeout_seconds) as client:
            resp = await client.request(
                method=entry.method,
                url=url,
                headers=headers,
                content=entry.req_body,
            )
        dur = elapsed_ms(start)
        return ReplayResult(
            entry_id=entry.id,
            status_code=resp.status_code,
            body=resp.content,
            duration_ms=dur,
        )
    except Exception as e:
        dur = elapsed_ms(start)
        return ReplayResult(entry_id=entry.id, duration_ms=dur, error=str(e))


async def replay_many(entry: Entry, opts: ReplayOptions) -> list[ReplayResult]:
    count = max(1, opts.count)
    tasks = [replay_one(entry, opts) for _ in range(count)]
    return await asyncio.gather(*tasks)
