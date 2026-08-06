from __future__ import annotations

import json

import pytest

from pypproxy.reporting.report import generate_html, generate_markdown
from pypproxy.security.idor import _extract_id_params, _generate_test_ids
from pypproxy.session import SessionManager
from pypproxy.store.models import Entry
from pypproxy.tools.ab_test import ABResult
from pypproxy.tools.macro import (
    MacroStep,
    macro_from_entries,
    macro_from_json,
    macro_to_json,
)


def make_entry(**kwargs) -> Entry:
    e = Entry(
        method="GET",
        scheme="https",
        host="api.example.com",
        path="/v1/users/123",
        status_code=200,
        protocol="https",
    )
    for k, v in kwargs.items():
        setattr(e, k, v)
    e.id = kwargs.get("id", 1)
    return e


# ---- Report ----


def test_generate_html_basic():
    entries = [make_entry(), make_entry(id=2, host="other.com")]
    html = generate_html(entries, "Test Report")
    assert "<html" in html
    assert "Test Report" in html
    assert "api.example.com" in html
    assert "other.com" in html


def test_generate_html_with_findings():
    entries = [make_entry()]
    findings = [
        {
            "vulnerable": True,
            "check": "CORS",
            "param": "/api",
            "detail": "Wildcard ACAO",
            "evidence": "*",
        }
    ]
    html = generate_html(entries, scan_results=findings)
    assert "CORS" in html
    assert "Findings" in html


def test_generate_markdown_basic():
    entries = [make_entry()]
    md = generate_markdown(entries, "My Report")
    assert "# My Report" in md
    assert "api.example.com" in md
    assert "| # |" in md


def test_generate_markdown_with_vulns():
    entries = [make_entry()]
    vulns = [
        {
            "vulnerable": True,
            "check": "SQLi",
            "param": "id",
            "detail": "Error-based",
            "evidence": "",
        }
    ]
    md = generate_markdown(entries, scan_results=vulns)
    assert "SQLi" in md
    assert "Findings" in md


# ---- Session manager ----


def test_session_create_and_list(tmp_path):
    mgr = SessionManager(str(tmp_path))
    sess = mgr.create("Test Session")
    assert sess.name == "Test Session"
    sessions = mgr.list()
    assert len(sessions) == 1
    assert sessions[0].name == "Test Session"


def test_session_add_entry(tmp_path):
    mgr = SessionManager(str(tmp_path))
    sess = mgr.create("Session A")
    mgr.add_entry(sess.id, 42)
    mgr.add_entry(sess.id, 99)
    loaded = mgr.get(sess.id)
    assert 42 in loaded.entry_ids
    assert 99 in loaded.entry_ids


def test_session_delete(tmp_path):
    mgr = SessionManager(str(tmp_path))
    sess = mgr.create("To Delete")
    mgr.delete(sess.id)
    assert mgr.get(sess.id) is None
    assert len(mgr.list()) == 0


def test_session_active(tmp_path):
    mgr = SessionManager(str(tmp_path))
    sess = mgr.create("Active")
    assert mgr.active_id is None
    mgr.set_active(sess.id)
    assert mgr.active_id == sess.id
    assert mgr.get_active().name == "Active"
    mgr.set_active(None)
    assert mgr.active_id is None


def test_session_rename(tmp_path):
    mgr = SessionManager(str(tmp_path))
    sess = mgr.create("Old Name")
    mgr.rename(sess.id, "New Name")
    assert mgr.get(sess.id).name == "New Name"


def test_session_persistence(tmp_path):
    mgr1 = SessionManager(str(tmp_path))
    sess = mgr1.create("Persisted")
    mgr1.add_entry(sess.id, 1)
    # Load in new manager
    mgr2 = SessionManager(str(tmp_path))
    loaded = mgr2.get(sess.id)
    assert loaded is not None
    assert loaded.name == "Persisted"
    assert 1 in loaded.entry_ids


# ---- Macro runner ----


def test_macro_step_from_entry():
    e = make_entry(method="POST", path="/login", query="")
    e.req_body = b'{"user":"alice"}'
    step = MacroStep.from_entry(e, "Login step")
    assert step.name == "Login step"
    assert step.method == "POST"
    assert "alice" in step.body


def test_macro_from_entries():
    entries = [make_entry(id=i) for i in range(3)]
    steps = macro_from_entries(entries)
    assert len(steps) == 3
    assert all(isinstance(s, MacroStep) for s in steps)


def test_macro_to_json_roundtrip():
    entries = [make_entry()]
    steps = macro_from_entries(entries)
    json_str = macro_to_json(steps)
    parsed = json.loads(json_str)
    assert isinstance(parsed, list)
    restored = macro_from_json(json_str)
    assert len(restored) == len(steps)
    assert restored[0].method == steps[0].method


def test_macro_step_substitution():
    from pypproxy.tools.macro import MacroRunner

    runner = MacroRunner()
    runner.set_variable("token", "abc123")
    step = MacroStep(
        name="test",
        method="GET",
        url="https://api.example.com/profile",
        headers={"Authorization": "Bearer {{token}}"},
    )
    result = runner._substitute(step.headers["Authorization"])
    assert result == "Bearer abc123"


@pytest.mark.asyncio
async def test_macro_run_error_handling():
    from pypproxy.tools.macro import MacroRunner

    runner = MacroRunner()
    steps = [MacroStep(name="fail", method="GET", url="http://127.0.0.1:1/unreachable")]
    results = await runner.run(steps, timeout=2)
    assert len(results) == 1
    assert results[0].error != ""


# ---- IDOR ----


def test_extract_id_params_path():
    e = make_entry(path="/users/123/posts/456")
    params = _extract_id_params(e)
    assert any("123" in v for v in params.values())
    assert any("456" in v for v in params.values())


def test_extract_id_params_uuid():
    e = make_entry(path="/items/550e8400-e29b-41d4-a716-446655440000")
    params = _extract_id_params(e)
    assert len(params) > 0


def test_extract_id_params_query():
    e = make_entry(path="/search", query="user_id=789&page=1")
    params = _extract_id_params(e)
    assert "query:user_id" in params


def test_extract_id_params_json_body():
    e = make_entry(method="POST", path="/delete")
    e.req_body = json.dumps({"item_id": "42", "reason": "test"}).encode()
    params = _extract_id_params(e)
    assert "body:item_id" in params


def test_generate_test_ids_numeric():
    ids = _generate_test_ids("100")
    assert "101" in ids
    assert "99" in ids
    assert len(ids) >= 4


def test_generate_test_ids_uuid():
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    ids = _generate_test_ids(uuid)
    assert len(ids) > 0
    assert uuid not in ids


# ---- A/B Test result ----


def test_ab_result_diff_detection():
    result = ABResult(
        endpoint_a="https://a.com/api",
        endpoint_b="https://b.com/api",
        method="GET",
        status_a=200,
        status_b=403,
        body_a=b'{"data":"a"}',
        body_b=b'{"error":"forbidden"}',
        duration_a_ms=100,
        duration_b_ms=200,
    )
    assert result.status_diff
    assert result.body_diff


def test_ab_result_no_diff():
    body = b'{"ok": true}'
    result = ABResult(
        endpoint_a="https://a.com",
        endpoint_b="https://b.com",
        method="GET",
        status_a=200,
        status_b=200,
        body_a=body,
        body_b=body,
        duration_a_ms=50,
        duration_b_ms=60,
    )
    assert not result.status_diff
    assert not result.body_diff


def test_ab_result_diff_summary():
    result = ABResult(
        endpoint_a="https://a.com",
        endpoint_b="https://b.com",
        method="GET",
        status_a=200,
        status_b=404,
        body_a=b"ok",
        body_b=b"not found",
        duration_a_ms=10,
        duration_b_ms=20,
    )
    summary = result.diff_summary()
    assert "Status" in summary
    assert "200" in summary
    assert "404" in summary


@pytest.mark.asyncio
async def test_ab_run_unreachable():
    from pypproxy.tools.ab_test import run_ab_test

    e = make_entry(scheme="http", host="127.0.0.1:1")
    result = await run_ab_test(e, "127.0.0.1:2", timeout=2)
    assert result.error_a != "" or result.error_b != ""
