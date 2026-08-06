from __future__ import annotations

import json

from pypproxy.reporting.analytics import compute_from_entries
from pypproxy.reporting.openapi import generate, to_json, to_yaml
from pypproxy.store.models import Entry
from pypproxy.tools.codegen import to_curl, to_fetch, to_httpie, to_python_requests


def make_entry(**kwargs) -> Entry:
    defaults = {
        "method": "GET",
        "scheme": "https",
        "host": "api.example.com",
        "path": "/v1/users",
        "query": "page=1",
        "protocol": "https",
        "status_code": 200,
        "req_headers": {"content-type": ["application/json"], "authorization": ["Bearer token123"]},
    }
    defaults.update(kwargs)
    e = Entry(**defaults)
    e.id = kwargs.get("id", 1)
    return e


# ---- Code generation ----


def test_to_curl_get():
    e = make_entry()
    result = to_curl(e)
    assert "curl" in result
    assert "api.example.com" in result
    assert "/v1/users" in result


def test_to_curl_post_with_body():
    e = make_entry(method="POST", query="")
    e.req_body = json.dumps({"name": "alice"}).encode()
    result = to_curl(e)
    assert "POST" in result
    assert "alice" in result


def test_to_python_requests_get():
    e = make_entry()
    result = to_python_requests(e)
    assert "import requests" in result
    assert "requests.get" in result
    assert "api.example.com" in result


def test_to_python_requests_post_json():
    e = make_entry(method="POST", query="")
    e.req_body = json.dumps({"username": "alice"}).encode()
    result = to_python_requests(e)
    assert "requests.post" in result
    assert "json_data" in result
    assert "alice" in result


def test_to_fetch_get():
    e = make_entry()
    result = to_fetch(e)
    assert "fetch(" in result
    assert "api.example.com" in result


def test_to_fetch_post():
    e = make_entry(method="POST", query="")
    e.req_body = b'{"x": 1}'
    result = to_fetch(e)
    assert '"method": "POST"' in result


def test_to_httpie_get():
    e = make_entry()
    result = to_httpie(e)
    assert "http" in result
    assert "GET" in result
    assert "api.example.com" in result


# ---- OpenAPI generator ----


def test_generate_basic():
    entries = [make_entry(), make_entry(method="POST", query="")]
    spec = generate(entries)
    assert spec["openapi"] == "3.0.3"
    assert "/v1/users" in spec["paths"]


def test_generate_path_params():
    e = make_entry(path="/api/users/123", query="")
    spec = generate([e])
    paths = list(spec["paths"].keys())
    assert any("{" in p for p in paths)  # ID replaced with {id0}


def test_generate_query_params():
    e = make_entry(query="page=1&limit=20")
    spec = generate([e])
    path_spec = spec["paths"].get("/v1/users", {})
    get_spec = path_spec.get("get", {})
    params = get_spec.get("parameters", [])
    param_names = [p["name"] for p in params]
    assert "page" in param_names


def test_generate_request_body():
    e = make_entry(method="POST", query="")
    e.req_body = json.dumps({"name": "alice", "email": "a@example.com"}).encode()
    e.req_headers = {"content-type": ["application/json"]}
    spec = generate([e])
    path_spec = spec["paths"].get("/v1/users", {})
    post_spec = path_spec.get("post", {})
    assert "requestBody" in post_spec


def test_generate_response_schema():
    e = make_entry()
    e.resp_body = json.dumps({"id": 1, "name": "alice"}).encode()
    e.resp_headers = {"content-type": ["application/json"]}
    spec = generate([e])
    path_spec = spec["paths"].get("/v1/users", {})
    get_spec = path_spec.get("get", {})
    responses = get_spec.get("responses", {})
    assert "200" in responses


def test_generate_to_yaml():
    spec = generate([make_entry()])
    yaml_str = to_yaml(spec)
    assert "openapi:" in yaml_str
    assert "paths:" in yaml_str


def test_generate_to_json():
    spec = generate([make_entry()])
    json_str = to_json(spec)
    parsed = json.loads(json_str)
    assert parsed["openapi"] == "3.0.3"


def test_generate_multiple_methods():
    entries = [
        make_entry(method="GET", id=1),
        make_entry(method="POST", query="", id=2),
        make_entry(method="DELETE", query="", id=3),
    ]
    spec = generate(entries)
    path = spec["paths"].get("/v1/users", {})
    assert "get" in path
    assert "post" in path
    assert "delete" in path


def test_generate_deduplicates():
    entries = [make_entry(id=i) for i in range(5)]  # 5 identical GET requests
    spec = generate(entries)
    path = spec["paths"].get("/v1/users", {})
    assert len(path) == 1  # only one GET


# ---- Analytics ----


def test_stats_empty():
    summary = compute_from_entries([])
    assert summary.total == 0


def test_stats_basic():
    entries = [
        make_entry(status_code=200, id=1),
        make_entry(status_code=200, id=2),
        make_entry(status_code=404, id=3),
        make_entry(status_code=500, id=4),
    ]
    for i, e in enumerate(entries):
        e.duration_ms = (i + 1) * 100
    summary = compute_from_entries(entries)
    assert summary.total == 4
    assert "2xx" in summary.status_distribution
    assert "4xx" in summary.status_distribution
    assert "5xx" in summary.status_distribution


def test_stats_host_aggregation():
    entries = [
        make_entry(host="a.com", id=1),
        make_entry(host="a.com", id=2),
        make_entry(host="b.com", id=3),
    ]
    summary = compute_from_entries(entries)
    hosts = {h.host: h.count for h in summary.hosts}
    assert hosts["a.com"] == 2
    assert hosts["b.com"] == 1


def test_stats_percentiles():
    entries = [make_entry(id=i) for i in range(100)]
    for i, e in enumerate(entries):
        e.duration_ms = i + 1
    summary = compute_from_entries(entries)
    assert summary.p95_duration_ms >= 90
    assert summary.p99_duration_ms >= 95
    assert 0 < summary.avg_duration_ms < 100


def test_stats_error_rate():
    entries = [
        make_entry(status_code=200, id=1),
        make_entry(status_code=500, id=2),
        make_entry(status_code=500, id=3),
        make_entry(status_code=500, id=4),
    ]
    summary = compute_from_entries(entries)
    host = next(h for h in summary.hosts if h.host == "api.example.com")
    assert host.error_rate == 0.75


def test_stats_to_dict():
    summary = compute_from_entries([make_entry()])
    d = summary.to_dict()
    assert "total" in d
    assert "hosts" in d
    assert "status_distribution" in d


# ---- Cookie audit ----


def test_cookie_audit():
    from pypproxy.security.advanced import audit_cookies

    e = make_entry()
    e.resp_headers = {"set-cookie": ["session=abc; Path=/"]}  # missing Secure/HttpOnly
    results = audit_cookies([e])
    assert len(results) > 0
    assert not results[0]["safe"]
    assert "missing Secure" in results[0]["issues"]


def test_cookie_audit_safe():
    from pypproxy.security.advanced import audit_cookies

    e = make_entry()
    e.resp_headers = {"set-cookie": ["session=abc; Path=/; Secure; HttpOnly; SameSite=Strict"]}
    results = audit_cookies([e])
    assert results[0]["safe"]
