from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass

from pypproxy.core.http import (
    REPLAY_DROP_HEADERS,
    build_url,
    elapsed_ms,
    flatten_headers,
)
from pypproxy.core.http import client as http_client
from pypproxy.store.models import Entry


@dataclass
class ABResult:
    endpoint_a: str
    endpoint_b: str
    method: str
    status_a: int
    status_b: int
    body_a: bytes
    body_b: bytes
    duration_a_ms: int
    duration_b_ms: int
    error_a: str = ""
    error_b: str = ""

    @property
    def status_diff(self) -> bool:
        return self.status_a != self.status_b

    @property
    def body_diff(self) -> bool:
        return self.body_a != self.body_b

    def to_dict(self) -> dict:
        return {
            "endpoint_a": self.endpoint_a,
            "endpoint_b": self.endpoint_b,
            "method": self.method,
            "status_a": self.status_a,
            "status_b": self.status_b,
            "body_a": base64.b64encode(self.body_a).decode() if self.body_a else "",
            "body_b": base64.b64encode(self.body_b).decode() if self.body_b else "",
            "duration_a_ms": self.duration_a_ms,
            "duration_b_ms": self.duration_b_ms,
            "error_a": self.error_a,
            "error_b": self.error_b,
            "status_diff": self.status_diff,
            "body_diff": self.body_diff,
        }

    def diff_summary(self) -> str:
        lines: list[str] = []
        if self.status_diff:
            lines.append(f"Status: A={self.status_a} B={self.status_b}")
        else:
            lines.append(f"Status: both {self.status_a}")
        if self.body_diff:
            lines.append(f"Body differs ({len(self.body_a):,} B vs {len(self.body_b):,} B)")
            # Try JSON diff summary
            try:
                da = json.loads(self.body_a)
                db = json.loads(self.body_b)
                if isinstance(da, dict) and isinstance(db, dict):
                    added = set(db) - set(da)
                    removed = set(da) - set(db)
                    changed = {k for k in da if k in db and da[k] != db[k]}
                    if added:
                        lines.append(f"  + fields added: {', '.join(sorted(added)[:5])}")
                    if removed:
                        lines.append(f"  - fields removed: {', '.join(sorted(removed)[:5])}")
                    if changed:
                        lines.append(f"  ~ fields changed: {', '.join(sorted(changed)[:5])}")
            except Exception:
                pass
        else:
            lines.append("Body: identical")
        lines.append(f"Latency: A={self.duration_a_ms}ms B={self.duration_b_ms}ms")
        return "\n".join(lines)


async def run_ab_test(
    entry: Entry,
    override_host_b: str,
    override_scheme_b: str = "",
    timeout: int = 30,
) -> ABResult:
    """Send the same request to two different hosts and compare responses."""
    headers = flatten_headers(entry.req_headers, drop=REPLAY_DROP_HEADERS)
    body = entry.req_body

    url_a = entry.url
    url_b = build_url(override_scheme_b or entry.scheme, override_host_b, entry.path, entry.query)

    async def _fetch(url: str) -> tuple[int, bytes, int, str]:
        start = time.monotonic()
        try:
            h = dict(headers)
            h["host"] = url.split("/")[2].split(":")[0]
            async with http_client(timeout) as client:
                resp = await client.request(method=entry.method, url=url, headers=h, content=body)
            return resp.status_code, resp.content, elapsed_ms(start), ""
        except Exception as e:
            return 0, b"", elapsed_ms(start), str(e)

    (status_a, body_a, dur_a, err_a), (status_b, body_b, dur_b, err_b) = await asyncio.gather(
        _fetch(url_a), _fetch(url_b)
    )

    return ABResult(
        endpoint_a=url_a,
        endpoint_b=url_b,
        method=entry.method,
        status_a=status_a,
        status_b=status_b,
        body_a=body_a,
        body_b=body_b,
        duration_a_ms=dur_a,
        duration_b_ms=dur_b,
        error_a=err_a,
        error_b=err_b,
    )
