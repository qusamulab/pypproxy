from __future__ import annotations

from pypproxy.core.http import (
    FORWARD_DROP_HEADERS,
    REPLAY_DROP_HEADERS,
    build_url,
    elapsed_ms,
    flatten_headers,
)
from pypproxy.store.models import Entry


def test_flatten_headers_joins_multiple_values():
    assert flatten_headers({"accept": ["a", "b"]}) == {"accept": "a, b"}


def test_flatten_headers_drop_is_case_insensitive():
    headers = {"Host": ["x"], "Content-Length": ["3"], "accept": ["json"]}
    assert flatten_headers(headers, drop=REPLAY_DROP_HEADERS) == {"accept": "json"}


def test_forward_drop_keeps_host_but_strips_hop_by_hop():
    headers = {
        "host": ["example.com"],
        "proxy-connection": ["keep-alive"],
        "transfer-encoding": ["chunked"],
        "content-length": ["7"],
    }
    assert flatten_headers(headers, drop=FORWARD_DROP_HEADERS) == {"host": "example.com"}


def test_build_url_omits_empty_query():
    assert build_url("https", "e.com", "/a") == "https://e.com/a"
    assert build_url("https", "e.com", "/a", "x=1") == "https://e.com/a?x=1"


def test_elapsed_ms_is_non_negative():
    import time

    assert elapsed_ms(time.monotonic()) >= 0


def test_entry_url_helpers():
    e = Entry(id=7, method="POST", scheme="https", host="e.com", path="/api", query="x=1")
    assert e.base_url == "https://e.com/api"
    assert e.url == "https://e.com/api?x=1"
    assert e.summary() == "#7 POST https://e.com/api"


def test_entry_url_without_query():
    e = Entry(scheme="http", host="e.com", path="/")
    assert e.url == "http://e.com/"
