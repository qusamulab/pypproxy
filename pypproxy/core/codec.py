from __future__ import annotations

import base64
import gzip
import json
import logging
import re
import struct
import zlib
from urllib.parse import parse_qsl, unquote_plus

logger = logging.getLogger(__name__)


# ---- content-encoding decode/encode ----


def decode_body(body: bytes, content_encoding: str) -> tuple[bytes, str]:
    """Decompress body according to Content-Encoding.
    Returns (decoded_bytes, applied_encoding). Falls back to original on error.
    """
    if not body or not content_encoding:
        return body, ""
    encoding = content_encoding.lower().strip()
    try:
        if encoding == "gzip":
            return gzip.decompress(body), "gzip"
        if encoding == "br":
            import brotli  # type: ignore[import-untyped]

            return brotli.decompress(body), "br"
        if encoding in ("deflate", "zlib"):
            try:
                return zlib.decompress(body), encoding
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS), encoding
    except Exception as e:
        logger.debug("decode_body failed (encoding=%s): %s", encoding, e)
    return body, ""


def encode_body(body: bytes, encoding: str) -> bytes:
    if not encoding:
        return body
    try:
        if encoding == "gzip":
            return gzip.compress(body)
        if encoding == "br":
            import brotli  # type: ignore[import-untyped]

            return brotli.compress(body)
        if encoding in ("deflate", "zlib"):
            return zlib.compress(body)
    except Exception as e:
        logger.debug("encode_body failed (encoding=%s): %s", encoding, e)
    return body


# ---- binary protocol decode ----


def decode_msgpack(data: bytes) -> str:
    """Decode MessagePack bytes to a pretty-printed JSON string."""
    try:
        import msgpack

        obj = msgpack.unpackb(data, raw=False, strict_map_key=False)
        return json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        return f"<msgpack decode error: {e}>"


def decode_cbor(data: bytes) -> str:
    """Decode CBOR bytes to a pretty-printed JSON string."""
    try:
        import cbor2

        obj = cbor2.loads(data)
        return json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        return f"<cbor decode error: {e}>"


def decode_protobuf_raw(data: bytes) -> str:
    """Decode raw protobuf bytes using wire-type heuristics (no schema needed)."""
    try:
        return _decode_proto_fields(data, indent=0)
    except Exception as e:
        return f"<protobuf decode error: {e}>"


def _decode_proto_fields(data: bytes, indent: int) -> str:
    lines: list[str] = []
    pos = 0
    pad = "  " * indent
    while pos < len(data):
        if pos >= len(data):
            break
        # read varint for tag+wire_type
        tag_wire, pos = _read_varint(data, pos)
        if tag_wire is None:
            break
        field_num = tag_wire >> 3
        wire_type = tag_wire & 0x7
        if wire_type == 0:  # varint
            val, pos = _read_varint(data, pos)
            lines.append(f"{pad}field {field_num} (varint): {val}")
        elif wire_type == 1:  # 64-bit
            if pos + 8 > len(data):
                break
            val = struct.unpack_from("<Q", data, pos)[0]
            pos += 8
            lines.append(f"{pad}field {field_num} (64-bit): {val}")
        elif wire_type == 2:  # length-delimited
            length, pos = _read_varint(data, pos)
            if length is None or pos + length > len(data):
                break
            payload = data[pos : pos + length]
            pos += length
            # try nested message
            try:
                nested = _decode_proto_fields(payload, indent + 1)
                lines.append(f"{pad}field {field_num} (embedded):")
                lines.append(nested)
            except Exception:
                try:
                    lines.append(f"{pad}field {field_num} (string): {payload.decode()!r}")
                except Exception:
                    lines.append(f"{pad}field {field_num} (bytes): {payload.hex()}")
        elif wire_type == 5:  # 32-bit
            if pos + 4 > len(data):
                break
            val = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            lines.append(f"{pad}field {field_num} (32-bit): {val}")
        else:
            lines.append(f"{pad}field {field_num} (unknown wire type {wire_type})")
            break
    return "\n".join(lines)


def _read_varint(data: bytes, pos: int) -> tuple[int | None, int]:
    result, shift = 0, 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return result, pos
    return None, pos


# ---- URL encoding ----


def decode_url_encoded(body: bytes) -> str:
    """Decode application/x-www-form-urlencoded body into key=value pairs."""
    try:
        text = body.decode("utf-8", errors="replace")
        pairs = parse_qsl(text, keep_blank_values=True)
        if not pairs:
            return unquote_plus(text)
        lines = [f"{unquote_plus(k)} = {unquote_plus(v)}" for k, v in pairs]
        return "\n".join(lines)
    except Exception as e:
        return f"<url-decode error: {e}>"


def decode_url_params(query: str) -> str:
    """Pretty-print a URL query string."""
    try:
        pairs = parse_qsl(query, keep_blank_values=True)
        if not pairs:
            return unquote_plus(query)
        lines = [f"{unquote_plus(k)} = {unquote_plus(v)}" for k, v in pairs]
        return "\n".join(lines)
    except Exception as e:
        return f"<url-param decode error: {e}>"


# ---- Base64 ----


def decode_base64_body(body: bytes) -> str:
    """Try to decode body as Base64 and return the decoded content."""
    text = body.decode("utf-8", errors="replace").strip()
    # strip url-safe chars, padding
    clean = re.sub(r"[^A-Za-z0-9+/=_-]", "", text)
    # try standard then urlsafe
    for variant in (base64.b64decode, base64.urlsafe_b64decode):
        for padded in (clean, clean + "=" * (-len(clean) % 4)):
            try:
                decoded = variant(padded)
                # Try to show as UTF-8 text
                try:
                    return decoded.decode("utf-8")
                except Exception:
                    # show hex if binary
                    return _hex_dump(decoded)
            except Exception:
                pass
    return "<base64 decode failed>"


def is_likely_base64(data: bytes) -> bool:
    """Heuristic: is this data likely Base64-encoded?"""
    if len(data) < 8:
        return False
    text = data.decode("utf-8", errors="replace").strip()
    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")
    ratio = sum(1 for c in text if c in b64_chars) / len(text)
    return ratio > 0.95 and len(text) % 4 in (0, 2, 3)


# ---- multipart/form-data ----


def decode_multipart(body: bytes, content_type: str) -> str:
    """Parse multipart/form-data body and return human-readable representation."""
    boundary_match = re.search(r"boundary=([^\s;]+)", content_type)
    if not boundary_match:
        return "<multipart: no boundary found>"

    boundary = boundary_match.group(1).strip('"')
    delimiter = b"--" + boundary.encode()
    parts = body.split(delimiter)
    result: list[str] = []

    for i, part in enumerate(parts):
        part = part.strip(b"\r\n")
        if not part or part == b"--":
            continue
        # split headers from body
        if b"\r\n\r\n" in part:
            header_raw, _, part_body = part.partition(b"\r\n\r\n")
        elif b"\n\n" in part:
            header_raw, _, part_body = part.partition(b"\n\n")
        else:
            result.append(f"--- Part {i} ---\n{part.decode(errors='replace')}")
            continue

        headers = header_raw.decode("utf-8", errors="replace")
        # extract name and filename
        name_match = re.search(r'name="([^"]*)"', headers)
        file_match = re.search(r'filename="([^"]*)"', headers)
        name = name_match.group(1) if name_match else f"part{i}"
        filename = file_match.group(1) if file_match else ""

        label = f"--- {name}"
        if filename:
            label += f" (file: {filename})"
        label += " ---"

        # show body
        printable = sum(1 for b in part_body[:256] if 0x20 <= b < 0x7F or b in (9, 10, 13))
        if len(part_body) > 0 and printable / min(len(part_body), 256) > 0.7:
            body_str = part_body.decode("utf-8", errors="replace")
        else:
            body_str = f"<binary {len(part_body)} bytes: {part_body[:32].hex()}...>"

        result.append(f"{label}\n{body_str}")

    return "\n\n".join(result) if result else "<multipart: no parts>"


# ---- JWT ----


def decode_jwt(token: str) -> str:
    """Decode a JWT and return header + payload as pretty JSON."""
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return f"<not a valid JWT: expected 3 parts, got {len(parts)}>"

    result: list[str] = []
    labels = ["Header", "Payload"]
    for label, part in zip(labels, parts[:2], strict=False):
        padded = part + "=" * (-len(part) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded)
            parsed = json.loads(decoded)
            result.append(f"=== {label} ===\n{json.dumps(parsed, indent=2, ensure_ascii=False)}")
        except Exception as e:
            result.append(f"=== {label} ===\n<decode error: {e}>")

    result.append(f"=== Signature ===\n{parts[2]}")
    return "\n\n".join(result)


def extract_jwt_from_body(body: bytes, headers: dict) -> str | None:
    """Try to find a JWT in the body or Authorization header."""
    # Check Authorization header first
    auth = headers.get("authorization", [""])[0]
    m = re.search(r"Bearer\s+([\w\-_.]+\.[\w\-_.]+\.[\w\-_.]*)", auth, re.IGNORECASE)
    if m:
        return m.group(1)
    # Check body
    text = body.decode("utf-8", errors="replace")
    m = re.search(r"([\w\-_.]+\.[\w\-_.]+\.[\w\-_.]+)", text)
    if m:
        candidate = m.group(1)
        if candidate.count(".") == 2:
            return candidate
    return None


# ---- XML / HTML ----


def decode_xml(body: bytes) -> str:
    """Pretty-print XML or HTML."""
    try:
        import xml.dom.minidom

        text = body.decode("utf-8", errors="replace")
        dom = xml.dom.minidom.parseString(text.encode())
        return dom.toprettyxml(indent="  ")
    except Exception:
        # fallback: just return decoded text
        return body.decode("utf-8", errors="replace")


# ---- chunked transfer ----


def decode_chunked(body: bytes) -> bytes:
    """Reassemble a chunked transfer-encoding body."""
    result = bytearray()
    pos = 0
    try:
        while pos < len(body):
            # find chunk size line
            end = body.index(b"\r\n", pos)
            size_str = body[pos:end].split(b";")[0].strip()
            chunk_size = int(size_str, 16)
            if chunk_size == 0:
                break
            pos = end + 2
            result.extend(body[pos : pos + chunk_size])
            pos += chunk_size + 2  # skip trailing \r\n
    except Exception:
        return body
    return bytes(result)


# ---- WebSocket permessage-deflate ----


def decode_ws_deflate(payload: bytes) -> bytes:
    """Decompress a permessage-deflate compressed WebSocket payload."""
    try:
        # append 4-byte tail required by deflate spec
        return zlib.decompress(payload + b"\x00\x00\xff\xff", -zlib.MAX_WBITS)
    except Exception as e:
        logger.debug("ws deflate decompress failed: %s", e)
        return payload


# ---- character encoding ----


def decode_charset(body: bytes, charset: str) -> str:
    """Decode bytes using the specified charset, fallback to UTF-8."""
    try:
        return body.decode(charset)
    except Exception:
        try:
            return body.decode("utf-8", errors="replace")
        except Exception:
            return body.decode("latin-1", errors="replace")


def detect_charset(content_type: str) -> str:
    """Extract charset from Content-Type header."""
    m = re.search(r"charset=([^\s;]+)", content_type, re.IGNORECASE)
    return m.group(1).strip('"') if m else "utf-8"


# ---- helper ----


def _hex_dump(data: bytes, width: int = 16) -> str:
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def sniff_content_type(body: bytes, content_type: str) -> str:
    """Return a hint for how to display the body."""
    ct = content_type.lower()
    if "json" in ct:
        return "json"
    if "xml" in ct:
        return "xml"
    if "html" in ct:
        return "html"
    if "grpc" in ct or "protobuf" in ct:
        return "proto"
    if "msgpack" in ct:
        return "msgpack"
    if "cbor" in ct:
        return "cbor"
    if "x-www-form-urlencoded" in ct:
        return "form"
    if "multipart" in ct:
        return "multipart"
    if not body:
        return "text"
    # heuristic: try JSON
    try:
        json.loads(body.decode("utf-8", errors="strict"))
        return "json"
    except Exception:
        pass
    # check binary
    printable = sum(1 for b in body[:256] if 0x20 <= b < 0x7F or b in (9, 10, 13))
    if len(body) > 0 and printable / min(len(body), 256) < 0.7:
        return "binary"
    return "text"
