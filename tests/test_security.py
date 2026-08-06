from __future__ import annotations

import base64
import json

from pypproxy.security.headers import check_security_headers
from pypproxy.security.jwt import (
    _parse_jwt,
    extract_jwt_from_headers,
    generate_test_tokens,
)
from pypproxy.security.plugin import PluginManager
from pypproxy.security.randomness import analyse_token
from pypproxy.store.models import Entry

# ---- helpers ----


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_test_jwt(alg: str = "HS256", extra_payload: dict | None = None) -> str:
    header = {"alg": alg, "typ": "JWT"}
    payload = {"sub": "user123", "exp": 9999999999, "role": "user"}
    if extra_payload:
        payload.update(extra_payload)
    h = _b64url(json.dumps(header).encode())
    p = _b64url(json.dumps(payload).encode())
    return f"{h}.{p}.fakesig"


# ---- JWT checker ----


def test_parse_jwt_valid():
    token = _make_test_jwt()
    result = _parse_jwt(token)
    assert result is not None
    header, payload, sig = result
    assert header["alg"] == "HS256"
    assert payload["sub"] == "user123"


def test_parse_jwt_invalid():
    assert _parse_jwt("not.a.valid.jwt.token") is None
    assert _parse_jwt("onlytwoparts") is None


def test_generate_test_tokens_none_alg():
    token = _make_test_jwt()
    tokens = generate_test_tokens(token)
    labels = [t[0] for t in tokens]
    assert "none_alg" in labels
    assert "none_alg_None" in labels
    assert "none_alg_NONE" in labels


def test_generate_test_tokens_empty_sig():
    token = _make_test_jwt()
    tokens = generate_test_tokens(token)
    labels = [t[0] for t in tokens]
    assert "empty_sig" in labels


def test_generate_test_tokens_exp_manipulation():
    token = _make_test_jwt()
    tokens = generate_test_tokens(token)
    labels = [t[0] for t in tokens]
    assert "no_exp" in labels
    assert "extended_exp" in labels


def test_generate_test_tokens_priv_escalation():
    token = _make_test_jwt(extra_payload={"role": "user"})
    tokens = generate_test_tokens(token)
    labels = [t[0] for t in tokens]
    assert any("priv_escalation" in lbl for lbl in labels)


def test_generate_test_tokens_jku_injection():
    token = _make_test_jwt()
    tokens = generate_test_tokens(token)
    labels = [t[0] for t in tokens]
    assert "jku_injection" in labels
    assert "kid_sqli" in labels


def test_extract_jwt_from_bearer():
    token = _make_test_jwt()
    headers = {"authorization": [f"Bearer {token}"]}
    result = extract_jwt_from_headers(headers)
    assert result == token


def test_extract_jwt_missing():
    assert extract_jwt_from_headers({}) is None
    assert extract_jwt_from_headers({"authorization": ["Basic abc123"]}) is None


# ---- Security headers ----


def test_header_checker_missing_hsts():
    results = check_security_headers({})
    hsts = next(r for r in results if r.header == "strict-transport-security")
    assert not hsts.present
    assert not hsts.passed
    assert hsts.severity == "high"


def test_header_checker_good_hsts():
    results = check_security_headers(
        {"strict-transport-security": ["max-age=31536000; includeSubDomains"]}
    )
    hsts = next(r for r in results if r.header == "strict-transport-security")
    assert hsts.passed


def test_header_checker_csp_unsafe_inline():
    results = check_security_headers(
        {"content-security-policy": ["default-src 'self'; script-src 'unsafe-inline'"]}
    )
    csp = next(r for r in results if r.header == "content-security-policy")
    assert not csp.passed


def test_header_checker_cors_wildcard():
    results = check_security_headers({"access-control-allow-origin": ["*"]})
    cors = next(r for r in results if r.header == "access-control-allow-origin")
    assert not cors.passed
    assert cors.severity == "high"


def test_header_checker_cookie_flags():
    results = check_security_headers({"set-cookie": ["session=abc123; Path=/"]})
    cookie = next(r for r in results if r.header == "set-cookie")
    assert not cookie.passed  # missing Secure, HttpOnly, SameSite


def test_header_checker_good_cookie():
    results = check_security_headers(
        {"set-cookie": ["session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"]}
    )
    cookie = next(r for r in results if r.header == "set-cookie")
    assert cookie.passed


# ---- Randomness ----


def test_randomness_analyse_returns_results():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc123"
    results = analyse_token(token)
    assert len(results) > 0
    for r in results:
        assert r.test_name
        assert isinstance(r.passed, bool)
        assert 0.0 <= r.score <= 1.0 or r.score >= 0


def test_randomness_low_entropy_token():
    token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    results = analyse_token(token)
    entropy = next(r for r in results if r.test_name == "Shannon entropy")
    assert not entropy.passed


def test_randomness_high_entropy_token():
    import os

    token = base64.urlsafe_b64encode(os.urandom(32)).decode()
    results = analyse_token(token)
    passed = sum(1 for r in results if r.passed)
    assert passed >= 3  # most tests should pass for random data


# ---- Plugin system ----


def test_plugin_manager_empty():
    mgr = PluginManager()
    assert mgr.list() == []


def test_plugin_manager_load_file(tmp_path):
    plugin_file = tmp_path / "test_plugin.py"
    plugin_file.write_text("""
from pypproxy.security.plugin import PluginBase

class MyPlugin(PluginBase):
    name = "test-plugin"
    version = "1.0.0"
    description = "Test plugin"
""")
    mgr = PluginManager()
    plugin = mgr.load_file(str(plugin_file))
    assert plugin.name == "test-plugin"
    assert len(mgr.list()) == 1


def test_plugin_manager_on_request_passthrough():
    mgr = PluginManager()
    entry = Entry(method="GET", host="example.com", path="/", protocol="https")
    entry.id = 1
    result = mgr.run_on_request(entry)
    assert result is entry  # no plugins, returns unchanged


def test_plugin_run_on_request(tmp_path):
    plugin_file = tmp_path / "modifier.py"
    plugin_file.write_text("""
from pypproxy.security.plugin import PluginBase

class Modifier(PluginBase):
    name = "modifier"
    def on_request(self, entry):
        entry.tags.append("plugin-tested")
        return entry
""")
    mgr = PluginManager()
    mgr.load_file(str(plugin_file))
    entry = Entry(method="GET", host="example.com", path="/", protocol="https")
    entry.id = 2
    result = mgr.run_on_request(entry)
    assert "plugin-tested" in result.tags


def test_plugin_unload(tmp_path):
    plugin_file = tmp_path / "unload_plugin.py"
    plugin_file.write_text("""
from pypproxy.security.plugin import PluginBase
class P(PluginBase):
    name = "to-unload"
""")
    mgr = PluginManager()
    mgr.load_file(str(plugin_file))
    assert len(mgr.list()) == 1
    mgr.unload("to-unload")
    assert len(mgr.list()) == 0
