"""End-to-end checks that a request survives the round trip through the proxy."""

from __future__ import annotations

import asyncio
import http.server
import socketserver
import threading
from collections.abc import Iterator

import httpx
import pytest

from pypproxy import bootstrap
from pypproxy.core.config import Config


class _Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        body = f"echo:{self.path}".encode()
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def origin() -> Iterator[int]:
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture
def context(tmp_path):
    cfg = Config.default()
    cfg.ca.cert_path = str(tmp_path / "ca-cert.pem")
    cfg.ca.key_path = str(tmp_path / "ca-key.pem")
    return bootstrap.build(cfg, ca_dir=str(tmp_path), persist=False)


async def test_plain_http_query_string_is_not_duplicated(origin, context):
    """The absolute-form target carries the query; appending it again corrupts the URL."""
    context.store.set_loop(asyncio.get_running_loop())
    server = await asyncio.start_server(context.proxy.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    try:
        async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}") as client:
            resp = await client.get(f"http://127.0.0.1:{origin}/hello?a=1&b=2")
    finally:
        server.close()
        await server.wait_closed()

    assert resp.status_code == 200
    assert resp.text == "echo:/hello?a=1&b=2"

    entry = context.store.get(1)
    assert entry is not None
    assert entry.path == "/hello"
    assert entry.query == "a=1&b=2"
    assert entry.url == f"http://127.0.0.1:{origin}/hello?a=1&b=2"


async def test_response_has_exactly_one_content_length(origin, context):
    context.store.set_loop(asyncio.get_running_loop())
    server = await asyncio.start_server(context.proxy.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    try:
        async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}") as client:
            resp = await client.get(f"http://127.0.0.1:{origin}/x")
    finally:
        server.close()
        await server.wait_closed()

    lengths = [v for k, v in resp.headers.multi_items() if k.lower() == "content-length"]
    assert lengths == [str(len(resp.content))]
