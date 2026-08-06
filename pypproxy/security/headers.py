from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass


@dataclass
class HeaderCheckResult:
    header: str
    present: bool
    value: str
    passed: bool
    severity: str  # info, low, medium, high
    detail: str

    def to_dict(self) -> dict:
        return {
            "header": self.header,
            "present": self.present,
            "value": self.value,
            "passed": self.passed,
            "severity": self.severity,
            "detail": self.detail,
        }


def check_security_headers(resp_headers: dict[str, list[str]]) -> list[HeaderCheckResult]:
    """Analyse response headers for security issues."""
    flat = {k.lower(): ", ".join(v) for k, v in resp_headers.items()}
    results: list[HeaderCheckResult] = []

    results.extend(
        [
            _check_hsts(flat),
            _check_csp(flat),
            _check_x_frame(flat),
            _check_x_content_type(flat),
            _check_x_xss(flat),
            _check_referrer_policy(flat),
            _check_permissions_policy(flat),
            _check_cors(flat),
            _check_server(flat),
            _check_x_powered_by(flat),
            _check_cache_control(flat),
            _check_set_cookie(flat),
        ]
    )

    return results


def _check_hsts(h: dict) -> HeaderCheckResult:
    key = "strict-transport-security"
    val = h.get(key, "")
    if not val:
        return HeaderCheckResult(
            key,
            False,
            "",
            False,
            "high",
            "Missing HSTS header. Clients may connect over plain HTTP.",
        )
    max_age = 0
    for part in val.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            with contextlib.suppress(ValueError):
                max_age = int(part.split("=")[1])
    passed = max_age >= 31536000
    return HeaderCheckResult(
        key,
        True,
        val,
        passed,
        "medium" if not passed else "info",
        f"max-age={max_age} ({'≥1 year OK' if passed else '<1 year, consider increasing'})",
    )


def _check_csp(h: dict) -> HeaderCheckResult:
    key = "content-security-policy"
    val = h.get(key, "")
    if not val:
        return HeaderCheckResult(
            key, False, "", False, "high", "Missing CSP. XSS attacks are not mitigated."
        )
    issues = []
    if "unsafe-inline" in val:
        issues.append("'unsafe-inline' allows inline scripts")
    if "unsafe-eval" in val:
        issues.append("'unsafe-eval' allows eval()")
    if "default-src *" in val or "script-src *" in val:
        issues.append("Wildcard source too permissive")
    passed = len(issues) == 0
    detail = "OK" if passed else "; ".join(issues)
    return HeaderCheckResult(
        key, True, val[:80], passed, "medium" if not passed else "info", detail
    )


def _check_x_frame(h: dict) -> HeaderCheckResult:
    key = "x-frame-options"
    val = h.get(key, "")
    if not val:
        # check CSP frame-ancestors instead
        csp = h.get("content-security-policy", "")
        if "frame-ancestors" in csp:
            return HeaderCheckResult(
                key,
                False,
                "",
                True,
                "info",
                "Not present, but CSP frame-ancestors found (acceptable)",
            )
        return HeaderCheckResult(
            key,
            False,
            "",
            False,
            "medium",
            "Missing X-Frame-Options. Clickjacking may be possible.",
        )
    val_up = val.upper()
    passed = "DENY" in val_up or "SAMEORIGIN" in val_up
    return HeaderCheckResult(
        key,
        True,
        val,
        passed,
        "info" if passed else "medium",
        "OK" if passed else f"Unexpected value: {val}",
    )


def _check_x_content_type(h: dict) -> HeaderCheckResult:
    key = "x-content-type-options"
    val = h.get(key, "")
    passed = val.lower() == "nosniff"
    if not val:
        return HeaderCheckResult(
            key, False, "", False, "low", "Missing. Browser may MIME-sniff responses."
        )
    return HeaderCheckResult(
        key,
        True,
        val,
        passed,
        "info" if passed else "low",
        "OK" if passed else f"Should be 'nosniff', got: {val}",
    )


def _check_x_xss(h: dict) -> HeaderCheckResult:
    key = "x-xss-protection"
    val = h.get(key, "")
    if not val:
        return HeaderCheckResult(
            key,
            False,
            "",
            True,
            "info",
            "Not present (modern browsers ignore this; rely on CSP instead)",
        )
    passed = "1; mode=block" in val or val == "0"
    return HeaderCheckResult(
        key, True, val, passed, "info", "OK" if passed else f"Unusual value: {val}"
    )


def _check_referrer_policy(h: dict) -> HeaderCheckResult:
    key = "referrer-policy"
    val = h.get(key, "")
    safe = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    passed = any(s in val.lower() for s in safe)
    if not val:
        return HeaderCheckResult(
            key, False, "", False, "low", "Missing. Full URL may be leaked in Referer header."
        )
    return HeaderCheckResult(
        key,
        True,
        val,
        passed,
        "info" if passed else "low",
        "OK" if passed else f"Consider stricter policy, got: {val}",
    )


def _check_permissions_policy(h: dict) -> HeaderCheckResult:
    key = "permissions-policy"
    val = h.get(key, h.get("feature-policy", ""))
    present = bool(val)
    return HeaderCheckResult(
        key,
        present,
        val[:80] if val else "",
        present,
        "info" if present else "low",
        "OK" if present else "Consider adding Permissions-Policy to restrict browser features",
    )


def _check_cors(h: dict) -> HeaderCheckResult:
    key = "access-control-allow-origin"
    val = h.get(key, "")
    if not val:
        return HeaderCheckResult(
            key, False, "", True, "info", "Not present (CORS not enabled for this endpoint)"
        )
    passed = val != "*"
    return HeaderCheckResult(
        key,
        True,
        val,
        passed,
        "high" if not passed else "info",
        "Wildcard ACAO allows cross-origin access from any domain" if not passed else "OK",
    )


def _check_server(h: dict) -> HeaderCheckResult:
    key = "server"
    val = h.get(key, "")
    if not val:
        return HeaderCheckResult(key, False, "", True, "info", "Server header not exposed (good)")
    # Check for version disclosure

    has_version = bool(re.search(r"[0-9]+\.[0-9]+", val))
    passed = not has_version
    return HeaderCheckResult(
        key,
        True,
        val,
        passed,
        "low" if not passed else "info",
        "Version number disclosed in Server header" if not passed else "No version disclosed",
    )


def _check_x_powered_by(h: dict) -> HeaderCheckResult:
    key = "x-powered-by"
    val = h.get(key, "")
    passed = not val
    return HeaderCheckResult(
        key,
        bool(val),
        val,
        passed,
        "low" if not passed else "info",
        "Technology stack disclosed" if not passed else "Not present (good)",
    )


def _check_cache_control(h: dict) -> HeaderCheckResult:
    key = "cache-control"
    val = h.get(key, "")
    if not val:
        return HeaderCheckResult(
            key,
            False,
            "",
            False,
            "low",
            "Missing Cache-Control. Sensitive responses may be cached.",
        )
    sensitive_ok = "no-store" in val or "private" in val
    return HeaderCheckResult(
        key,
        True,
        val,
        True,
        "info",
        f"{'Contains no-store/private' if sensitive_ok else 'Consider no-store for sensitive endpoints'}",
    )


def _check_set_cookie(h: dict) -> HeaderCheckResult:
    key = "set-cookie"
    val = h.get(key, "")
    if not val:
        return HeaderCheckResult(key, False, "", True, "info", "No Set-Cookie header")
    issues = []
    val_lower = val.lower()
    if "secure" not in val_lower:
        issues.append("Missing 'Secure' flag (cookie sent over HTTP)")
    if "httponly" not in val_lower:
        issues.append("Missing 'HttpOnly' flag (accessible via JavaScript)")
    if "samesite" not in val_lower:
        issues.append("Missing 'SameSite' attribute (CSRF risk)")
    passed = len(issues) == 0
    return HeaderCheckResult(
        key,
        True,
        val[:80],
        passed,
        "medium" if not passed else "info",
        "; ".join(issues) if issues else "OK",
    )
