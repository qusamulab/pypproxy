from __future__ import annotations

import asyncio
import logging
import socket
import struct

logger = logging.getLogger(__name__)

DNS_PORT = 53153  # unprivileged default; use 53 with sudo


class DNSServer:
    """
    Minimal DNS server that spoofs configured domains to a target IP.
    All other queries are forwarded to an upstream resolver.
    """

    def __init__(
        self,
        overrides: dict[str, str],
        upstream: str = "8.8.8.8",
        port: int = DNS_PORT,
    ) -> None:
        self._overrides = {k.lower().rstrip("."): v for k, v in overrides.items()}
        self._upstream = upstream
        self._port = port
        self._transport: asyncio.BaseTransport | None = None

    async def start(self) -> None:
        loop = asyncio.get_event_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _DNSProtocol(self._overrides, self._upstream),
            local_addr=("0.0.0.0", self._port),
        )
        logger.info("DNS server listening on UDP :%d (upstream: %s)", self._port, self._upstream)

    def stop(self) -> None:
        if self._transport:
            self._transport.close()

    def set_overrides(self, overrides: dict[str, str]) -> None:
        self._overrides = {k.lower().rstrip("."): v for k, v in overrides.items()}
        if self._transport:
            proto = self._transport.get_protocol()
            if hasattr(proto, "overrides"):
                proto.overrides = self._overrides  # type: ignore[attr-defined]


class _DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, overrides: dict[str, str], upstream: str) -> None:
        self.overrides = overrides
        self._upstream = upstream
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        asyncio.ensure_future(self._handle(data, addr))

    async def _handle(self, data: bytes, addr: tuple) -> None:
        try:
            name, qtype = _parse_query(data)
        except Exception:
            return

        name_lower = name.lower().rstrip(".")
        logger.debug("DNS query: %s (type=%d) from %s", name, qtype, addr)

        if qtype == 1 and name_lower in self.overrides:
            ip = self.overrides[name_lower]
            logger.info("DNS spoof: %s -> %s", name, ip)
            reply = _build_reply(data, name, ip)
            if self._transport:
                self._transport.sendto(reply, addr)
            return

        # Forward to upstream
        try:
            reply = await _forward(data, self._upstream)
            if self._transport and reply:
                self._transport.sendto(reply, addr)
        except Exception as e:
            logger.debug("DNS forward error: %s", e)


def _parse_query(data: bytes) -> tuple[str, int]:
    offset = 12  # skip header
    labels: list[str] = []
    while offset < len(data):
        length = data[offset]
        offset += 1
        if length == 0:
            break
        labels.append(data[offset : offset + length].decode())
        offset += length
    qtype = struct.unpack_from(">H", data, offset)[0]
    return ".".join(labels), qtype


def _build_reply(query: bytes, name: str, ip: str) -> bytes:
    # Header: copy transaction ID, set QR=1, AA=1, QDCOUNT=1, ANCOUNT=1
    tid = query[:2]
    flags = b"\x81\x80"
    counts = b"\x00\x01\x00\x01\x00\x00\x00\x00"
    header = tid + flags + counts

    # Question section (copy from query, up to and including QTYPE+QCLASS)
    question_end = 12
    while question_end < len(query):
        length = query[question_end]
        question_end += 1
        if length == 0:
            question_end += 4  # QTYPE + QCLASS
            break
        question_end += length
    question = query[12:question_end]

    # Answer: name pointer, A record, TTL=60, RDATA=ip
    answer = b"\xc0\x0c"  # pointer to question name
    answer += b"\x00\x01"  # TYPE A
    answer += b"\x00\x01"  # CLASS IN
    answer += b"\x00\x00\x00\x3c"  # TTL 60
    answer += b"\x00\x04"  # RDLENGTH 4
    answer += socket.inet_aton(ip)

    return header + question + answer


async def _forward(data: bytes, upstream: str) -> bytes | None:
    loop = asyncio.get_event_loop()
    fut: asyncio.Future[bytes] = loop.create_future()

    class _Forwarder(asyncio.DatagramProtocol):
        def datagram_received(self, d: bytes, _: tuple) -> None:
            if not fut.done():
                fut.set_result(d)

        def error_received(self, exc: Exception) -> None:
            if not fut.done():
                fut.set_exception(exc)

    transport, _ = await loop.create_datagram_endpoint(_Forwarder, remote_addr=(upstream, 53))
    transport.sendto(data)
    try:
        return await asyncio.wait_for(fut, timeout=3)
    finally:
        transport.close()
