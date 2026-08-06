from __future__ import annotations

import asyncio
import logging
import ssl
import time
from urllib.parse import urlparse

from pypproxy.cert.ca import CA
from pypproxy.core.codec import decode_body
from pypproxy.core.http import FORWARD_DROP_HEADERS, build_url, flatten_headers
from pypproxy.core.http import client as http_client
from pypproxy.protocols import grpc as grpc_proto
from pypproxy.protocols import ws as ws_proto
from pypproxy.proxy.intercept import InterceptManager
from pypproxy.proxy.interceptor import Interceptor
from pypproxy.proxy.messages import (
    CONNECT_ESTABLISHED,
    build_response,
    content_length,
    error_response,
    parse_headers,
    parse_request_line,
    read_headers,
    wants_close,
)
from pypproxy.script import ScriptEngine
from pypproxy.store.models import Entry
from pypproxy.store.store import Store

logger = logging.getLogger(__name__)

TUNNEL_CHUNK = 65536
UPSTREAM_TIMEOUT = 30
TLS_HANDSHAKE_TIMEOUT = 10


class Proxy:
    def __init__(
        self,
        ca: CA,
        interceptor: Interceptor,
        store: Store,
        script: ScriptEngine | None = None,
        ignore: set[str] | None = None,
        intercept_manager: InterceptManager | None = None,
    ) -> None:
        self._ca = ca
        self._interceptor = interceptor
        self._store = store
        self._script = script
        self._ignore = ignore or set()
        self._intercept = intercept_manager

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            request_line = await reader.readline()
            if not request_line:
                return
            headers = parse_headers(await read_headers(reader))

            line = parse_request_line(request_line)
            if line is None:
                return

            if line.method == "CONNECT":
                await self._handle_connect(reader, writer, line.target)
            else:
                await self._handle_http(reader, writer, line.method, line.target, headers)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    # --- CONNECT / TLS ---

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: str,
    ) -> None:
        host, _, port_str = target.partition(":")
        port = int(port_str) if port_str else 443

        if host in self._ignore:
            await self._tunnel(reader, writer, host, port)
            return

        writer.write(CONNECT_ESTABLISHED)
        await writer.drain()

        try:
            tls_reader, tls_writer = await asyncio.wait_for(
                self._upgrade_server_tls(writer, self._ca.ssl_context_for(host)),
                timeout=TLS_HANDSHAKE_TIMEOUT,
            )
        except (TimeoutError, ssl.SSLError, OSError) as e:
            logger.debug("TLS handshake failed for %s: %s", host, e)
            return

        try:
            await self._serve_decrypted(tls_reader, tls_writer, host, port)
        finally:
            tls_writer.close()

    async def _upgrade_server_tls(
        self,
        writer: asyncio.StreamWriter,
        ssl_ctx: ssl.SSLContext,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        transport = writer.transport
        loop = asyncio.get_event_loop()
        tls_transport = await loop.start_tls(
            transport, transport.get_protocol(), ssl_ctx, server_side=True
        )
        tls_reader = asyncio.StreamReader()
        tls_protocol = asyncio.StreamReaderProtocol(tls_reader)
        tls_transport.set_protocol(tls_protocol)
        tls_writer = asyncio.StreamWriter(tls_transport, tls_protocol, tls_reader, loop)
        return tls_reader, tls_writer

    async def _serve_decrypted(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        while True:
            request_line = await reader.readline()
            if not request_line:
                return
            headers_raw = await read_headers(reader)
            headers = parse_headers(headers_raw)

            if ws_proto.is_upgrade(headers):
                await self._handle_websocket(reader, writer, host, port, request_line, headers_raw)
                return

            line = parse_request_line(request_line)
            if line is None:
                return

            body = await self._read_body(reader, headers)
            path, _, query = line.target.partition("?")
            full_host = f"{host}:{port}" if port != 443 else host

            response = await self._forward(
                line.method, "https", full_host, path, query, headers, body
            )
            writer.write(response)
            await writer.drain()

            if wants_close(headers):
                return

    # --- plain HTTP ---

    async def _handle_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        method: str,
        target: str,
        headers: dict[str, list[str]],
    ) -> None:
        parsed = urlparse(target if target.startswith("http") else f"http://{target}")
        host = parsed.netloc or parsed.hostname or target

        body = await self._read_body(reader, headers)
        response = await self._forward(
            method, "http", host, parsed.path or "/", parsed.query, headers, body
        )
        writer.write(response)
        await writer.drain()

    async def _read_body(
        self,
        reader: asyncio.StreamReader,
        headers: dict[str, list[str]],
    ) -> bytes:
        length = content_length(headers)
        return await reader.readexactly(length) if length > 0 else b""

    # --- upstream ---

    async def _forward(
        self,
        method: str,
        scheme: str,
        host: str,
        path: str,
        query: str,
        headers: dict[str, list[str]],
        body: bytes,
    ) -> bytes:
        if self._script:
            body = self._script.on_request(method, host, path, body)

        # Manual intercept — pause until the user forwards or drops.
        if self._intercept:
            headers, body, drop = await self._intercept.intercept(
                method, scheme, host, path, headers, body
            )
            if drop:
                return error_response(403, "dropped")

        entry, blocked = self._interceptor.process_request(
            method, scheme, host, path, query, headers, body
        )
        if blocked:
            return error_response(403, "blocked")

        url = build_url(scheme, host, path, query)
        start = time.monotonic()
        try:
            async with http_client(UPSTREAM_TIMEOUT) as client:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=flatten_headers(headers, drop=FORWARD_DROP_HEADERS),
                    content=entry.req_body,
                )
        except Exception as e:
            logger.warning("upstream error %s %s: %s", method, url, e)
            return error_response(502, str(e))

        raw_body = resp.content
        decoded_body, applied_encoding = decode_body(
            raw_body, resp.headers.get("content-encoding", "")
        )

        if self._script:
            decoded_body = self._script.on_response(resp.status_code, decoded_body)

        if grpc_proto.is_grpc({k: [v] for k, v in resp.headers.items()}):
            grpc_proto.log_frames(entry.id, "response", decoded_body)

        resp_headers: dict[str, list[str]] = {}
        for k, v in resp.headers.multi_items():
            resp_headers.setdefault(k.lower(), []).append(v)

        # Record the decoded body so the UI can show plain text.
        self._interceptor.process_response(
            entry, resp.status_code, resp_headers, decoded_body, start
        )

        # Only a script rewrites the body; otherwise relay the bytes untouched so
        # the client can decompress them exactly as the origin intended.
        forward_headers = list(resp.headers.multi_items())
        if self._script:
            forward_body = decoded_body
            if applied_encoding:
                forward_headers = [
                    (k, v) for k, v in forward_headers if k.lower() != "content-encoding"
                ]
        else:
            forward_body = raw_body

        return build_response(resp.status_code, forward_headers, forward_body)

    # --- WebSocket / opaque tunnel ---

    async def _handle_websocket(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        host: str,
        port: int,
        request_line: bytes,
        headers_raw: bytes,
    ) -> None:
        try:
            server_reader, server_writer = await asyncio.open_connection(
                host, port, ssl=ssl.create_default_context()
            )
        except Exception as e:
            logger.warning("ws: cannot connect to %s:%d: %s", host, port, e)
            return

        server_writer.write(request_line + headers_raw + b"\r\n")
        await server_writer.drain()

        resp_line = await server_reader.readline()
        resp_headers_raw = await read_headers(server_reader)
        client_writer.write(resp_line + resp_headers_raw + b"\r\n")
        await client_writer.drain()

        entry = self._store.add(
            Entry(
                method="GET",
                scheme="wss",
                host=host,
                path="/",
                protocol="ws",
                tags=["websocket"],
            )
        )

        await ws_proto.relay_frames(
            client_reader,
            client_writer,
            server_reader,
            server_writer,
            entry,
            self._store,
        )

    async def _tunnel(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        writer.write(CONNECT_ESTABLISHED)
        await writer.drain()
        try:
            server_reader, server_writer = await asyncio.open_connection(host, port)
        except OSError:
            return

        await asyncio.gather(
            _pipe(reader, server_writer),
            _pipe(server_reader, writer),
        )


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(TUNNEL_CHUNK)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
