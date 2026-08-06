from __future__ import annotations

import base64
import contextlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode

from pypproxy.core.http import client as http_client
from pypproxy.core.http import elapsed_ms, flatten_headers
from pypproxy.store.models import Entry


@dataclass
class OverflowPayload:
    label: str
    description: str
    value: Any


@dataclass
class OverflowResult:
    param: str
    payload: OverflowPayload
    status_code: int = 0
    response_body: bytes = b""
    duration_ms: int = 0
    error: str = ""
    suspicious: bool = False

    def to_dict(self) -> dict:
        return {
            "param": self.param,
            "label": self.payload.label,
            "description": self.payload.description,
            "value": str(self.payload.value),
            "status_code": self.status_code,
            "response_body": base64.b64encode(self.response_body).decode()
            if self.response_body
            else "",
            "duration_ms": self.duration_ms,
            "error": self.error,
            "suspicious": self.suspicious,
        }


_INT_PAYLOADS = [
    OverflowPayload("plus_one", "+1 from original", None),  # filled dynamically
    OverflowPayload("minus_one", "-1 from original", None),
    OverflowPayload("zero", "Zero value", 0),
    OverflowPayload("negative", "Large negative", -2147483648),
    OverflowPayload("max_int32", "Max int32", 2147483647),
    OverflowPayload("max_int32_plus1", "Max int32 + 1 (overflow)", 2147483648),
    OverflowPayload("max_int64", "Max int64", 9223372036854775807),
    OverflowPayload("max_uint32", "Max uint32", 4294967295),
    OverflowPayload("long_num", "Very long number", 99999999999999999999),
    OverflowPayload("float", "Float (0.1)", 0.1),
    OverflowPayload("neg_float", "Negative float", -0.1),
    OverflowPayload("sci_notation", "Scientific notation", "1e308"),
    OverflowPayload("nan", "NaN string", "NaN"),
    OverflowPayload("inf", "Infinity string", "Infinity"),
]


def _extract_int_params(entry: Entry) -> dict[str, int]:
    """Find integer-valued parameters in query string and JSON body."""
    params: dict[str, int] = {}

    # query string
    if entry.query:
        for k, vs in parse_qs(entry.query).items():
            for v in vs:
                with contextlib.suppress(ValueError):
                    params[f"query:{k}"] = int(v)

    # JSON body
    if entry.req_body:
        try:
            data = json.loads(entry.req_body.decode("utf-8", errors="replace"))
            _collect_ints(data, "", params)
        except Exception:
            pass

    return params


def _collect_ints(obj: Any, prefix: str, out: dict[str, int]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            _collect_ints(v, f"body:{prefix}{k}", out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _collect_ints(v, f"{prefix}[{i}].", out)
    elif isinstance(obj, int) and not isinstance(obj, bool):
        out[prefix.rstrip(".")] = obj


def _apply_to_query(query: str, param_key: str, new_value: Any) -> str:
    key = param_key.removeprefix("query:")
    qs = parse_qs(query)
    qs[key] = [str(new_value)]
    return urlencode(qs, doseq=True)


def _apply_to_body(body: bytes, param_key: str, new_value: Any) -> bytes:
    key_path = param_key.removeprefix("body:")
    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
        _set_nested(data, key_path, new_value)
        return json.dumps(data).encode()
    except Exception:
        return body


def _set_nested(obj: Any, key_path: str, value: Any) -> None:
    parts = re.split(r"[.\[\]]", key_path)
    parts = [p for p in parts if p]
    for part in parts[:-1]:
        if isinstance(obj, dict):
            obj = obj.get(part, {})
        elif isinstance(obj, list):
            obj = obj[int(part)]
    last = parts[-1]
    if isinstance(obj, dict):
        obj[last] = value


async def run_checks(entry: Entry, timeout: int = 30) -> list[OverflowResult]:
    int_params = _extract_int_params(entry)
    if not int_params:
        return []

    results: list[OverflowResult] = []
    url_base = entry.base_url
    req_headers = flatten_headers(entry.req_headers)

    for param_key, original_value in int_params.items():
        payloads = []
        for p in _INT_PAYLOADS:
            pl = OverflowPayload(p.label, p.description, p.value)
            if p.label == "plus_one":
                pl.value = original_value + 1
            elif p.label == "minus_one":
                pl.value = original_value - 1
            payloads.append(pl)

        for payload in payloads:
            if param_key.startswith("query:"):
                new_query = _apply_to_query(entry.query, param_key, payload.value)
                url = url_base + ("?" + new_query if new_query else "")
                req_body = entry.req_body
            else:
                url = url_base + ("?" + entry.query if entry.query else "")
                req_body = _apply_to_body(entry.req_body, param_key, payload.value)

            start = time.monotonic()
            try:
                async with http_client(timeout) as client:
                    resp = await client.request(
                        method=entry.method,
                        url=url,
                        headers=req_headers,
                        content=req_body,
                    )
                status_code = resp.status_code
                resp_body = resp.content[:512]
                error = ""
                suspicious = status_code in (500, 502, 503)
            except Exception as e:
                status_code = 0
                resp_body = b""
                error = str(e)
                suspicious = False

            dur = elapsed_ms(start)
            results.append(
                OverflowResult(
                    param=param_key,
                    payload=payload,
                    status_code=status_code,
                    response_body=resp_body,
                    duration_ms=dur,
                    error=error,
                    suspicious=suspicious,
                )
            )

    return results
