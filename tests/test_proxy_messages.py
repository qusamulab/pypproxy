from __future__ import annotations

import asyncio

from pypproxy.proxy.messages import (
    build_response,
    content_length,
    error_response,
    parse_headers,
    parse_request_line,
    read_headers,
    wants_close,
)


def test_parse_request_line():
    line = parse_request_line(b"GET /a?b=1 HTTP/1.1")
    assert line is not None
    assert (line.method, line.target) == ("GET", "/a?b=1")


def test_parse_request_line_rejects_short_line():
    assert parse_request_line(b"GET") is None


def test_parse_headers_lowercases_and_groups():
    raw = b"Host: e.com\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n"
    assert parse_headers(raw) == {"host": ["e.com"], "set-cookie": ["a=1", "b=2"]}


def test_content_length_tolerates_garbage():
    assert content_length({"content-length": ["12"]}) == 12
    assert content_length({"content-length": ["nope"]}) == 0
    assert content_length({}) == 0


def test_wants_close():
    assert wants_close({"connection": ["close"]})
    assert not wants_close({"connection": ["keep-alive"]})
    assert not wants_close({})


def test_build_response_recomputes_content_length():
    """Upstream framing headers must not survive: the client would see two lengths."""
    raw = build_response(
        200,
        [("content-length", "999"), ("transfer-encoding", "chunked"), ("x-a", "1")],
        b"hello",
    )
    head, _, body = raw.partition(b"\r\n\r\n")
    text = head.decode()
    assert body == b"hello"
    assert text.count("Content-Length") == 1
    assert "Content-Length: 5" in text
    assert "transfer-encoding" not in text.lower()
    assert "x-a: 1" in text


def test_build_response_unknown_status_reason():
    assert build_response(599, [], b"").startswith(b"HTTP/1.1 599 Unknown")


def test_error_response():
    raw = error_response(403, "blocked")
    assert raw.startswith(b"HTTP/1.1 403 Forbidden")
    assert raw.endswith(b"blocked")


async def test_read_headers_stops_at_blank_line():
    reader = asyncio.StreamReader()
    reader.feed_data(b"A: 1\r\nB: 2\r\n\r\nBODY")
    reader.feed_eof()
    assert await read_headers(reader) == b"A: 1\r\nB: 2\r\n\r\n"
    assert await reader.read() == b"BODY"
