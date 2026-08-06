from __future__ import annotations

import json

import pytest

from pypproxy.exchange.importer import import_har, import_json
from pypproxy.store.models import Entry
from pypproxy.store.scope import ScopeManager, ScopeRule
from pypproxy.store.store import Store

# ---- HAR importer ----


def _make_har(entries: list[dict]) -> str:
    return json.dumps({"log": {"entries": entries}})


def _make_har_entry(
    url: str = "https://example.com/test", method: str = "GET", status: int = 200
) -> dict:
    return {
        "startedDateTime": "2026-01-01T00:00:00Z",
        "time": 100,
        "request": {
            "method": method,
            "url": url,
            "headers": [{"name": "host", "value": "example.com"}],
            "queryString": [],
            "cookies": [],
            "headersSize": -1,
            "bodySize": 0,
        },
        "response": {
            "status": status,
            "statusText": "OK",
            "headers": [{"name": "content-type", "value": "application/json"}],
            "cookies": [],
            "content": {"size": 13, "mimeType": "application/json", "text": '{"ok": true}'},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": 13,
        },
        "cache": {},
        "timings": {"send": 0, "wait": 100, "receive": 0},
    }


def test_import_har_basic():
    from pypproxy.store.models import Filter

    store = Store()
    har = _make_har([_make_har_entry(), _make_har_entry("https://other.com/api")])
    count = import_har(har, store)
    assert count == 2
    _, total = store.list(Filter(), 0, 10)
    assert total == 2


def test_import_har_single_entry():
    store = Store()
    har = _make_har([_make_har_entry("https://api.example.com/v1/users", "POST", 201)])
    count = import_har(har, store)
    assert count == 1
    entry = store.get(1)
    assert entry is not None
    assert entry.method == "POST"
    assert entry.host == "api.example.com"
    assert entry.path == "/v1/users"
    assert entry.status_code == 201


def test_import_har_response_body():
    store = Store()
    har = _make_har([_make_har_entry()])
    import_har(har, store)
    entry = store.get(1)
    assert entry is not None
    assert b"ok" in entry.resp_body


def test_import_json_basic():
    store = Store()
    entries_data = [
        {
            "method": "GET",
            "scheme": "https",
            "host": "example.com",
            "path": "/test",
            "query": "",
            "req_headers": {},
            "req_body": "",
            "status_code": 200,
            "resp_headers": {},
            "resp_body": "",
            "duration_ms": 50,
            "protocol": "https",
            "tags": [],
            "modified": False,
        }
    ]
    count = import_json(json.dumps(entries_data), store)
    assert count == 1
    entry = store.get(1)
    assert entry is not None
    assert entry.host == "example.com"


def test_import_json_with_entries_key():
    store = Store()
    data = json.dumps(
        {
            "entries": [
                _make_har_entry.__wrapped__ if hasattr(_make_har_entry, "__wrapped__") else {}
            ]
        }
    )
    # Should not raise even if data is malformed entries
    count = import_json(data, store)
    assert isinstance(count, int)


# ---- Scope manager ----


def test_scope_disabled_allows_all():
    mgr = ScopeManager()
    assert not mgr.enabled
    assert mgr.is_in_scope("anything.com")
    assert mgr.is_in_scope("other.com")


def test_scope_enabled_empty_allows_all():
    mgr = ScopeManager()
    mgr.set_enabled(True)
    assert mgr.is_in_scope("anything.com")


def test_scope_glob_pattern():
    mgr = ScopeManager()
    mgr.set_enabled(True)
    mgr.add(ScopeRule(pattern="*.example.com", mode="glob"))
    assert mgr.is_in_scope("api.example.com")
    assert mgr.is_in_scope("auth.example.com")
    assert not mgr.is_in_scope("other.com")


def test_scope_exact_match():
    mgr = ScopeManager()
    mgr.set_enabled(True)
    mgr.add(ScopeRule(pattern="api.example.com", mode="glob"))
    assert mgr.is_in_scope("api.example.com")
    assert not mgr.is_in_scope("other.example.com")


def test_scope_regex_pattern():
    mgr = ScopeManager()
    mgr.set_enabled(True)
    mgr.add(ScopeRule(pattern=r"^.*\.example\.com$", mode="regex"))
    assert mgr.is_in_scope("api.example.com")
    assert not mgr.is_in_scope("example.org")


def test_scope_multiple_rules():
    mgr = ScopeManager()
    mgr.set_enabled(True)
    mgr.add(ScopeRule(pattern="api.example.com"))
    mgr.add(ScopeRule(pattern="auth.example.com"))
    assert mgr.is_in_scope("api.example.com")
    assert mgr.is_in_scope("auth.example.com")
    assert not mgr.is_in_scope("other.com")


def test_scope_remove_rule():
    mgr = ScopeManager()
    mgr.set_enabled(True)
    mgr.add(ScopeRule(pattern="example.com"))
    mgr.add(ScopeRule(pattern="other.com"))
    mgr.remove("example.com")
    assert not mgr.is_in_scope("example.com")
    assert mgr.is_in_scope("other.com")


def test_scope_disabled_rule():
    mgr = ScopeManager()
    mgr.set_enabled(True)
    mgr.add(ScopeRule(pattern="example.com", enabled=False))
    # disabled rule doesn't match
    assert not mgr.is_in_scope("example.com")


# ---- Scanner payloads ----


def test_scanner_payloads_non_empty():
    from pypproxy.security.scanner import ALL_PAYLOADS

    assert "xss" in ALL_PAYLOADS
    assert "sqli" in ALL_PAYLOADS
    assert len(ALL_PAYLOADS["xss"]) >= 5
    assert len(ALL_PAYLOADS["sqli"]) >= 5


def test_scanner_extract_params_query():
    from pypproxy.security.scanner import _extract_params

    e = Entry(
        method="GET",
        scheme="https",
        host="example.com",
        path="/search",
        query="q=hello&page=1",
        protocol="https",
    )
    e.id = 1
    params = _extract_params(e)
    assert "query:q" in params
    assert "query:page" in params


def test_scanner_extract_params_json_body():
    from pypproxy.security.scanner import _extract_params

    e = Entry(method="POST", scheme="https", host="example.com", path="/api", protocol="https")
    e.id = 2
    e.req_body = json.dumps({"username": "alice", "age": 30}).encode()
    params = _extract_params(e)
    assert "body:username" in params


def test_scanner_apply_payload_query():
    from pypproxy.security.scanner import _apply_payload

    e = Entry(
        method="GET",
        scheme="https",
        host="example.com",
        path="/search",
        query="q=hello",
        protocol="https",
    )
    e.id = 1
    url, body = _apply_payload(e, "query:q", "<script>alert(1)</script>")
    assert "alert" in url


# ---- WS intercept ----


def test_ws_intercept_disabled_passthrough():
    from pypproxy.protocols.ws_intercept import WSInterceptManager

    mgr = WSInterceptManager()
    assert not mgr.enabled


@pytest.mark.asyncio
async def test_ws_intercept_passthrough_when_disabled():
    from pypproxy.protocols.ws_intercept import WSFrame, WSInterceptManager

    mgr = WSInterceptManager()
    frame = WSFrame(direction="client", opcode=1, payload=b"hello", entry_id=1)
    result = await mgr.intercept(frame)
    assert result == b"hello"


@pytest.mark.asyncio
async def test_ws_intercept_forward():
    import asyncio

    from pypproxy.protocols.ws_intercept import WSFrame, WSInterceptManager

    mgr = WSInterceptManager()
    mgr.set_enabled(True)
    frame = WSFrame(direction="client", opcode=1, payload=b"original", entry_id=2)

    async def _intercept_task() -> bytes:
        return await mgr.intercept(frame)

    async def _forward_task() -> None:
        await asyncio.sleep(0.05)
        pending = mgr.list_pending()
        assert len(pending) == 1
        mgr.forward(pending[0]["id"], b"modified")

    result, _ = await asyncio.gather(_intercept_task(), _forward_task())
    assert result == b"modified"
