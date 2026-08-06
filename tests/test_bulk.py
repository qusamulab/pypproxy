from __future__ import annotations

import pytest

from pypproxy.store.models import Entry
from pypproxy.tools.bulk import BulkPayload, bulk_send, race_send


def make_entry() -> Entry:
    e = Entry(
        method="GET",
        scheme="http",
        host="httpbin.org",
        path="/get",
        protocol="http",
    )
    e.id = 1
    return e


@pytest.mark.asyncio
async def test_bulk_send_error_handling():
    """Bulk send to an unreachable host should return error results, not raise."""
    entry = Entry(method="GET", scheme="http", host="127.0.0.1", path="/notexist", protocol="http")
    entry.id = 1
    payloads = [BulkPayload(label="p1"), BulkPayload(label="p2")]
    results = await bulk_send(entry, payloads, timeout=2)
    assert len(results) == 2
    for r in results:
        assert r.error != "" or r.status_code > 0


@pytest.mark.asyncio
async def test_race_send_returns_correct_count():
    """race_send should return exactly N results."""
    entry = Entry(method="GET", scheme="http", host="127.0.0.1", path="/race", protocol="http")
    entry.id = 2
    results = await race_send(entry, count=5, timeout=2)
    assert len(results) == 5


def test_bulk_payload_defaults():
    p = BulkPayload(label="test")
    assert p.override_body == b""
    assert p.override_headers == {}
    assert p.override_path == ""


def test_bulk_result_to_dict():
    import base64

    from pypproxy.tools.bulk import BulkResult

    r = BulkResult(label="r1", status_code=200, body=b"hello", duration_ms=42)
    d = r.to_dict()
    assert d["label"] == "r1"
    assert d["status_code"] == 200
    assert base64.b64decode(d["body"]) == b"hello"
    assert d["duration_ms"] == 42
    assert d["error"] == ""
