from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode

from pypproxy.core.http import REPLAY_DROP_HEADERS, elapsed_ms, flatten_headers
from pypproxy.core.http import client as http_client
from pypproxy.store.models import Entry


@dataclass
class IDORResult:
    param: str
    original_value: str
    test_value: str
    status_code: int = 0
    response_body: bytes = b""
    duration_ms: int = 0
    vulnerable: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "param": self.param,
            "original_value": self.original_value,
            "test_value": self.test_value,
            "status_code": self.status_code,
            "body_preview": base64.b64encode(self.response_body[:256]).decode()
            if self.response_body
            else "",
            "duration_ms": self.duration_ms,
            "vulnerable": self.vulnerable,
            "reason": self.reason,
        }


_ID_PATTERNS = [
    r"^\d+$",
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    r"^[0-9a-f]{24}$",  # MongoDB ObjectId
    r"^[A-Za-z0-9_-]{20,}$",  # opaque ID
]


def _looks_like_id(value: str) -> bool:
    return any(re.match(pat, value, re.IGNORECASE) for pat in _ID_PATTERNS)


def _generate_test_ids(original: str) -> list[str]:
    tests: list[str] = []
    if re.match(r"^\d+$", original):
        n = int(original)
        for delta in (1, -1, 2, -2, 0, 99, 100, 1000):
            candidate = str(n + delta)
            if candidate != original and int(candidate) > 0:
                tests.append(candidate)
        tests.append("1")
        tests.append("2")
    elif re.match(r"^[0-9a-f]{8}-", original, re.IGNORECASE):
        # UUID: increment last segment
        parts = original.split("-")
        try:
            last = int(parts[-1], 16)
            for delta in (1, -1):
                new_last = format((last + delta) % (16 ** len(parts[-1])), f"0{len(parts[-1])}x")
                tests.append("-".join(parts[:-1] + [new_last]))
        except Exception:
            pass
    else:
        tests.extend(["1", "2", "admin", "test", "0"])
    return tests[:6]


def _extract_id_params(entry: Entry) -> dict[str, str]:
    params: dict[str, str] = {}
    # Path segments
    for seg in entry.path.split("/"):
        if _looks_like_id(seg):
            params[f"path:{seg}"] = seg
    # Query params
    if entry.query:
        for k, vs in parse_qs(entry.query).items():
            if vs and _looks_like_id(vs[0]):
                params[f"query:{k}"] = vs[0]
    # JSON body
    if entry.req_body:
        try:
            data = json.loads(entry.req_body)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, str | int) and _looks_like_id(str(v)):
                        params[f"body:{k}"] = str(v)
        except Exception:
            pass
    return params


def _apply_id(entry: Entry, param_key: str, new_value: str) -> tuple[str, bytes]:
    url = entry.base_url

    if param_key.startswith("path:"):
        old_seg = param_key[5:]
        new_path = entry.path.replace(old_seg, new_value, 1)
        url = f"{entry.scheme}://{entry.host}{new_path}"
        if entry.query:
            url += f"?{entry.query}"
        return url, entry.req_body

    if param_key.startswith("query:"):
        key = param_key[6:]
        qs = parse_qs(entry.query)
        qs[key] = [new_value]
        url = f"{entry.scheme}://{entry.host}{entry.path}?{urlencode(qs, doseq=True)}"
        return url, entry.req_body

    if param_key.startswith("body:"):
        key = param_key[5:]
        if entry.query:
            url += f"?{entry.query}"
        try:
            data = json.loads(entry.req_body)
            data[key] = new_value
            return url, json.dumps(data).encode()
        except Exception:
            return url, entry.req_body

    if entry.query:
        url += f"?{entry.query}"
    return url, entry.req_body


async def run_idor_checks(
    entry: Entry,
    baseline_status: int = 0,
    timeout: int = 15,
) -> list[IDORResult]:
    id_params = _extract_id_params(entry)
    if not id_params:
        return []

    req_headers = flatten_headers(entry.req_headers, drop=REPLAY_DROP_HEADERS)

    results: list[IDORResult] = []

    for param_key, original_value in id_params.items():
        for test_value in _generate_test_ids(original_value):
            url, body = _apply_id(entry, param_key, test_value)
            start = time.monotonic()
            try:
                async with http_client(timeout) as client:
                    resp = await client.request(
                        method=entry.method,
                        url=url,
                        headers=req_headers,
                        content=body,
                    )
                status = resp.status_code
                resp_body = resp.content[:512]
                dur = elapsed_ms(start)

                # Vulnerable: different ID returns 2xx (possible IDOR)
                vulnerable = (
                    status in range(200, 300)
                    and (
                        baseline_status in (401, 403, 404, 0) or baseline_status in range(200, 300)
                    )
                    and test_value != original_value
                )
                reason = ""
                if vulnerable and baseline_status in (401, 403):
                    reason = f"Returns {status} with different ID (baseline was {baseline_status})"
                elif vulnerable:
                    reason = f"Returns {status} with different ID {test_value!r}"

                results.append(
                    IDORResult(
                        param=param_key,
                        original_value=original_value,
                        test_value=test_value,
                        status_code=status,
                        response_body=resp_body,
                        duration_ms=dur,
                        vulnerable=vulnerable,
                        reason=reason,
                    )
                )
            except Exception as e:
                results.append(
                    IDORResult(
                        param=param_key,
                        original_value=original_value,
                        test_value=test_value,
                        duration_ms=elapsed_ms(start),
                        reason=str(e),
                    )
                )

    return results
