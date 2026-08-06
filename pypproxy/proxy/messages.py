"""Reading and writing raw HTTP/1.1 messages on a stream.

The proxy speaks HTTP/1.1 to the client by hand (httpx handles the upstream
leg), so these helpers own the wire format: where a header block ends, how a
header line maps onto the multi-value dict `Entry` stores, and how a response
is framed on the way back out.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from pypproxy.core.http import BODY_HEADERS, HOP_BY_HOP_HEADERS

CONNECT_ESTABLISHED = b"HTTP/1.1 200 Connection Established\r\n\r\n"

#: Headers that frame *this* hop's message. The proxy re-derives them, so
#: relaying the upstream copy would leave the client with two answers.
_FRAMING_HEADERS = HOP_BY_HOP_HEADERS | BODY_HEADERS

STATUS_REASONS = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}


@dataclass(frozen=True)
class RequestLine:
    method: str
    target: str


def parse_request_line(raw: bytes) -> RequestLine | None:
    """Parse `METHOD target HTTP/x.y`. Returns None if the line is malformed."""
    parts = raw.decode(errors="replace").split()
    if len(parts) < 2:
        return None
    return RequestLine(method=parts[0], target=parts[1])


async def read_headers(reader: asyncio.StreamReader) -> bytes:
    """Read the raw header block, terminating blank line included."""
    buf = bytearray()
    while True:
        line = await reader.readline()
        buf += line
        if line in (b"\r\n", b"\n", b""):
            return bytes(buf)


def parse_headers(raw: bytes) -> dict[str, list[str]]:
    """Parse a raw header block into lowercased name -> values."""
    headers: dict[str, list[str]] = {}
    for line in raw.split(b"\r\n"):
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        key = name.strip().decode(errors="replace").lower()
        headers.setdefault(key, []).append(value.strip().decode(errors="replace"))
    return headers


def content_length(headers: dict[str, list[str]]) -> int:
    try:
        return int(headers.get("content-length", ["0"])[0] or 0)
    except ValueError:
        return 0


def wants_close(headers: dict[str, list[str]]) -> bool:
    return headers.get("connection", [""])[0].lower() == "close"


def build_response(status: int, headers: list[tuple[str, str]], body: bytes) -> bytes:
    """Serialize an HTTP/1.1 response with a freshly computed Content-Length."""
    lines = [f"HTTP/1.1 {status} {STATUS_REASONS.get(status, 'Unknown')}"]
    lines += [f"{k}: {v}" for k, v in headers if k.lower() not in _FRAMING_HEADERS]
    lines.append(f"Content-Length: {len(body)}")
    lines += ["", ""]
    return "\r\n".join(lines).encode() + body


def error_response(status: int, message: str) -> bytes:
    return build_response(status, [("content-type", "text/plain")], message.encode())
