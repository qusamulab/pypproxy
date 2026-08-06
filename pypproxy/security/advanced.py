from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode

import httpx

from pypproxy.core.http import REPLAY_DROP_HEADERS, flatten_headers
from pypproxy.core.http import client as http_client
from pypproxy.store.models import Entry


@dataclass
class CheckResult:
    check: str
    vulnerable: bool
    detail: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "vulnerable": self.vulnerable,
            "detail": self.detail,
            "evidence": self.evidence,
        }


# ---- CORS checker ----


async def check_cors(entry: Entry, timeout: int = 10) -> CheckResult:
    """Test CORS by injecting a foreign Origin header."""
    url = entry.url
    headers = flatten_headers(entry.req_headers, drop=REPLAY_DROP_HEADERS)
    headers["origin"] = "https://evil.attacker.example.com"
    headers["access-control-request-method"] = entry.method

    try:
        async with http_client(timeout) as client:
            resp = await client.options(url, headers=headers)
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

        if acao == "*":
            return CheckResult(
                "CORS",
                True,
                "Wildcard ACAO — any origin allowed",
                f"Access-Control-Allow-Origin: {acao}",
            )
        if "evil.attacker.example.com" in acao:
            detail = "Reflected Origin"
            if acac.lower() == "true":
                detail += " + Allow-Credentials: true (critical)"
            return CheckResult("CORS", True, detail, f"ACAO: {acao}, ACAC: {acac}")
        return CheckResult("CORS", False, f"ACAO: {acao!r} — not vulnerable", acao)
    except Exception as e:
        return CheckResult("CORS", False, f"Request failed: {e}")


# ---- Open Redirect ----

_REDIRECT_PAYLOADS = [
    "https://evil.attacker.example.com",
    "//evil.attacker.example.com",
    "/\\evil.attacker.example.com",
    "https:evil.attacker.example.com",
    "%2Fevil.attacker.example.com",
]


async def check_open_redirect(entry: Entry, timeout: int = 10) -> list[CheckResult]:
    """Inject redirect payloads into URL parameters."""
    results: list[CheckResult] = []
    if not entry.query:
        return [CheckResult("Open Redirect", False, "No query parameters to test")]

    params = parse_qs(entry.query, keep_blank_values=True)
    url_params = [
        k for k, vs in params.items() if any(v.startswith(("http", "/", "//")) for v in vs)
    ]

    if not url_params:
        return [CheckResult("Open Redirect", False, "No URL-like parameters found")]

    req_headers = flatten_headers(entry.req_headers, drop=REPLAY_DROP_HEADERS)

    for param in url_params:
        for payload in _REDIRECT_PAYLOADS[:3]:  # limit to 3 payloads per param
            test_params = dict(params)
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            url = f"{entry.scheme}://{entry.host}{entry.path}?{new_query}"
            try:
                async with httpx.AsyncClient(
                    verify=False, timeout=timeout, follow_redirects=False, http2=True
                ) as client:
                    resp = await client.request(entry.method, url, headers=req_headers)
                loc = resp.headers.get("location", "")
                if resp.status_code in range(300, 400) and "evil.attacker" in loc:
                    results.append(
                        CheckResult(
                            "Open Redirect",
                            True,
                            f"param={param!r} redirects to attacker domain",
                            f"Location: {loc}",
                        )
                    )
                    break
            except Exception:
                pass

    return results or [
        CheckResult("Open Redirect", False, "No redirect to attacker domain detected")
    ]


# ---- SSRF probes ----

_SSRF_PAYLOADS = [
    ("localhost", "http://localhost/"),
    ("127.0.0.1", "http://127.0.0.1/"),
    ("metadata AWS", "http://169.254.169.254/latest/meta-data/"),
    ("metadata GCP", "http://metadata.google.internal/computeMetadata/v1/"),
    ("0.0.0.0", "http://0.0.0.0/"),
    ("[::]", "http://[::]/"),
]


async def check_ssrf(entry: Entry, timeout: int = 10) -> list[CheckResult]:
    """Inject SSRF payloads into URL-like parameters."""
    results: list[CheckResult] = []
    if not entry.query:
        return [CheckResult("SSRF", False, "No query parameters to test")]

    params = parse_qs(entry.query, keep_blank_values=True)
    url_params = [
        k for k, vs in params.items() if any(v.startswith(("http", "/", "//")) for v in vs)
    ]

    if not url_params:
        return [CheckResult("SSRF", False, "No URL-like parameters found")]

    req_headers = flatten_headers(entry.req_headers, drop=REPLAY_DROP_HEADERS)

    for param in url_params[:2]:
        for label, payload in _SSRF_PAYLOADS:
            test_params = dict(params)
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            url = f"{entry.scheme}://{entry.host}{entry.path}?{new_query}"
            start = time.monotonic()
            try:
                async with http_client(timeout) as client:
                    resp = await client.request(
                        entry.method, url, headers=req_headers, follow_redirects=False
                    )
                dur = time.monotonic() - start
                # Signs of SSRF: 200 from internal, unusual response, slow response
                if resp.status_code == 200 and dur > 2:
                    results.append(
                        CheckResult(
                            "SSRF",
                            True,
                            f"param={param!r} payload={label!r} returned 200 with {dur:.1f}s delay",
                            f"URL: {url}",
                        )
                    )
                elif resp.status_code == 200 and len(resp.content) > 100:
                    text = resp.text[:200]
                    if any(
                        kw in text.lower() for kw in ("ami-id", "instance", "hostname", "local")
                    ):
                        results.append(
                            CheckResult(
                                "SSRF",
                                True,
                                f"param={param!r} payload={label!r} returned metadata indicators",
                                f"Body snippet: {text[:100]}",
                            )
                        )
            except Exception:
                pass

    return results or [CheckResult("SSRF", False, "No SSRF indicators detected")]


# ---- Rate limit tester ----


async def check_rate_limit(entry: Entry, count: int = 20, timeout: int = 10) -> CheckResult:
    """Send N rapid requests and check if rate limiting kicks in."""
    url = entry.url
    headers = flatten_headers(entry.req_headers, drop=REPLAY_DROP_HEADERS)

    status_codes: list[int] = []
    sem = asyncio.Semaphore(count)

    async def _one() -> int:
        async with sem:
            try:
                async with http_client(timeout) as client:
                    resp = await client.request(
                        entry.method, url, headers=headers, content=entry.req_body
                    )
                return resp.status_code
            except Exception:
                return 0

    status_codes = await asyncio.gather(*[_one() for _ in range(count)])
    codes = list(status_codes)
    rate_limited = sum(1 for c in codes if c == 429)
    errors = sum(1 for c in codes if c in (503, 503, 502, 0))
    first_success = next((i for i, c in enumerate(codes) if 200 <= c < 300), -1)

    if rate_limited > 0:
        return CheckResult(
            "Rate Limit",
            False,
            f"Rate limiting detected after {first_success + 1} requests ({rate_limited}/{count} got 429)",
            f"Status codes: {dict(zip(*zip(*[(c, codes.count(c)) for c in set(codes)], strict=False), strict=False))}",
        )
    if errors > count // 2:
        return CheckResult(
            "Rate Limit",
            True,
            f"Server errors suggest overload ({errors}/{count} errors) — possible DoS",
            "",
        )
    return CheckResult(
        "Rate Limit",
        True,
        f"No rate limiting detected — all {count} requests succeeded",
        f"All status codes: {sorted(set(codes))}",
    )


# ---- Cookie security audit ----


def audit_cookies(entries: list[Entry]) -> list[dict]:
    """Collect all Set-Cookie headers and check for missing flags."""
    results: list[dict] = []
    seen: set[str] = set()

    for e in entries:
        cookies = e.resp_headers.get("set-cookie", [])
        for cookie in cookies:
            name_match = re.match(r"([^=;]+)=", cookie)
            name = name_match.group(1).strip() if name_match else "unknown"
            key = f"{e.host}:{name}"
            if key in seen:
                continue
            seen.add(key)
            lower = cookie.lower()
            issues = []
            if "secure" not in lower:
                issues.append("missing Secure")
            if "httponly" not in lower:
                issues.append("missing HttpOnly")
            if "samesite" not in lower:
                issues.append("missing SameSite")
            results.append(
                {
                    "host": e.host,
                    "name": name,
                    "issues": issues,
                    "value": cookie[:80],
                    "safe": len(issues) == 0,
                }
            )

    return results
