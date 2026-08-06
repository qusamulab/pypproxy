from __future__ import annotations

import gzip
import json

from pypproxy.core.codec import (
    decode_body,
    decode_cbor,
    decode_msgpack,
    decode_protobuf_raw,
    encode_body,
    sniff_content_type,
)


def test_decode_gzip():
    original = b"hello world"
    compressed = gzip.compress(original)
    decoded, enc = decode_body(compressed, "gzip")
    assert decoded == original
    assert enc == "gzip"


def test_decode_identity():
    body = b"plain text"
    decoded, enc = decode_body(body, "")
    assert decoded == body
    assert enc == ""


def test_decode_unknown_encoding_fallback():
    body = b"data"
    decoded, enc = decode_body(body, "unknown-encoding")
    assert decoded == body


def test_decode_empty():
    decoded, enc = decode_body(b"", "gzip")
    assert decoded == b""
    assert enc == ""


def test_encode_gzip_roundtrip():
    original = b"compress me"
    compressed = encode_body(original, "gzip")
    assert compressed != original
    restored, _ = decode_body(compressed, "gzip")
    assert restored == original


def test_sniff_json():
    body = json.dumps({"key": "value"}).encode()
    assert sniff_content_type(body, "application/json") == "json"


def test_sniff_json_auto():
    body = json.dumps({"x": 1}).encode()
    assert sniff_content_type(body, "") == "json"


def test_sniff_grpc():
    assert sniff_content_type(b"\x00\x00\x00\x00\x05hello", "application/grpc") == "proto"


def test_sniff_binary():
    body = bytes(range(256))
    assert sniff_content_type(body, "") == "binary"


def test_sniff_text():
    body = b"hello plain text response"
    assert sniff_content_type(body, "text/plain") in ("text", "json")


def test_decode_msgpack_roundtrip():
    import msgpack

    data = {"name": "pypproxy", "version": 1}
    packed = msgpack.packb(data)
    result = decode_msgpack(packed)
    parsed = json.loads(result)
    assert parsed["name"] == "pypproxy"


def test_decode_cbor_roundtrip():
    import cbor2

    data = {"tool": "pypproxy", "active": True}
    packed = cbor2.dumps(data)
    result = decode_cbor(packed)
    parsed = json.loads(result)
    assert parsed["tool"] == "pypproxy"


def test_decode_msgpack_invalid():
    result = decode_msgpack(b"\xff\xff\xff")
    assert "error" in result.lower()


def test_decode_protobuf_varint():
    # field 1, wire type 0 (varint), value 42
    data = bytes([0x08, 0x2A])
    result = decode_protobuf_raw(data)
    assert "field 1" in result
    assert "42" in result


def test_decode_protobuf_string():
    # field 2, wire type 2 (length-delimited), value "hi"
    payload = b"hi"
    data = bytes([0x12, len(payload)]) + payload
    result = decode_protobuf_raw(data)
    assert "field 2" in result
