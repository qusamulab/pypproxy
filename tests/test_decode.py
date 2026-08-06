from __future__ import annotations

import base64
import json
import zlib

from pypproxy.core.codec import (
    decode_base64_body,
    decode_charset,
    decode_chunked,
    decode_jwt,
    decode_multipart,
    decode_url_encoded,
    decode_url_params,
    decode_ws_deflate,
    decode_xml,
    detect_charset,
    extract_jwt_from_body,
    is_likely_base64,
    sniff_content_type,
)

# ---- URL encoding ----


def test_decode_url_encoded_simple():
    body = b"username=alice&password=secret"
    result = decode_url_encoded(body)
    assert "username = alice" in result
    assert "password = secret" in result


def test_decode_url_encoded_percent():
    body = b"q=hello+world&tag=%23test"
    result = decode_url_encoded(body)
    assert "q = hello world" in result
    assert "tag = #test" in result


def test_decode_url_params():
    result = decode_url_params("page=1&limit=20&sort=desc")
    assert "page = 1" in result
    assert "limit = 20" in result


def test_sniff_form():
    assert sniff_content_type(b"a=1&b=2", "application/x-www-form-urlencoded") == "form"


# ---- Base64 ----


def test_decode_base64_text():
    encoded = base64.b64encode(b"hello world").decode()
    result = decode_base64_body(encoded.encode())
    assert "hello world" in result


def test_decode_base64_url_safe():
    encoded = base64.urlsafe_b64encode(b"test data").decode()
    result = decode_base64_body(encoded.encode())
    assert "test data" in result


def test_is_likely_base64_true():
    encoded = base64.b64encode(b"some binary data here").decode().encode()
    assert is_likely_base64(encoded)


def test_is_likely_base64_false():
    assert not is_likely_base64(b"hello world plain text!")


def test_decode_base64_invalid():
    result = decode_base64_body(b"not base64 !@#$%")
    assert "failed" in result.lower() or len(result) >= 0  # should not raise


# ---- multipart ----


def _make_multipart(boundary: str, parts: list[tuple[str, str, bytes]]) -> bytes:
    body = b""
    for name, filename, content in parts:
        body += f"--{boundary}\r\n".encode()
        cd = f'Content-Disposition: form-data; name="{name}"'
        if filename:
            cd += f'; filename="{filename}"'
        body += (cd + "\r\n\r\n").encode()
        body += content + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return body


def test_decode_multipart_text_field():
    boundary = "abc123"
    body = _make_multipart(boundary, [("username", "", b"alice")])
    ct = f"multipart/form-data; boundary={boundary}"
    result = decode_multipart(body, ct)
    assert "username" in result
    assert "alice" in result


def test_decode_multipart_file():
    boundary = "xyz"
    body = _make_multipart(boundary, [("file", "test.txt", b"file contents")])
    ct = f"multipart/form-data; boundary={boundary}"
    result = decode_multipart(body, ct)
    assert "test.txt" in result
    assert "file contents" in result


def test_decode_multipart_no_boundary():
    result = decode_multipart(b"data", "multipart/form-data")
    assert "no boundary" in result


def test_sniff_multipart():
    assert (
        sniff_content_type(b"--boundary", "multipart/form-data; boundary=boundary") == "multipart"
    )


# ---- JWT ----


def _make_jwt(header: dict, payload: dict) -> str:
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.fakesig"


def test_decode_jwt_basic():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user123", "role": "admin"})
    result = decode_jwt(token)
    assert "Header" in result
    assert "Payload" in result
    assert "HS256" in result
    assert "user123" in result


def test_decode_jwt_bearer_prefix():
    token = _make_jwt({"alg": "HS256"}, {"sub": "x"})
    result = decode_jwt(f"Bearer {token}")
    assert "Header" in result


def test_decode_jwt_invalid():
    result = decode_jwt("not.a.valid")
    # should still show 3 parts (header/payload/sig sections)
    assert "Header" in result or "error" in result.lower()


def test_extract_jwt_from_body_bearer():
    token = _make_jwt({"alg": "HS256"}, {"sub": "u"})
    headers = {"authorization": [f"Bearer {token}"]}
    result = extract_jwt_from_body(b"", headers)
    assert result == token


def test_extract_jwt_from_body_none():
    assert extract_jwt_from_body(b"no jwt here", {}) is None


# ---- XML ----


def test_decode_xml_valid():
    xml = b"<root><item>hello</item></root>"
    result = decode_xml(xml)
    assert "root" in result
    assert "hello" in result


def test_decode_xml_invalid_fallback():
    result = decode_xml(b"not xml at all")
    assert "not xml" in result


def test_sniff_xml():
    assert sniff_content_type(b"<root/>", "application/xml") == "xml"
    assert sniff_content_type(b"<html/>", "text/html") == "html"


# ---- chunked transfer ----


def test_decode_chunked_basic():
    body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    result = decode_chunked(body)
    assert result == b"hello world"


def test_decode_chunked_empty():
    body = b"0\r\n\r\n"
    result = decode_chunked(body)
    assert result == b""


def test_decode_chunked_invalid_fallback():
    body = b"not chunked data"
    result = decode_chunked(body)
    assert result == body  # falls back to original


# ---- WebSocket deflate ----


def test_decode_ws_deflate():
    original = b"hello websocket"
    compressed = zlib.compress(original)[2:-4]  # strip zlib header/trailer
    result = decode_ws_deflate(compressed)
    assert result == original


def test_decode_ws_deflate_invalid():
    result = decode_ws_deflate(b"not compressed")
    assert result == b"not compressed"  # fallback


# ---- charset ----


def test_detect_charset_utf8():
    assert detect_charset("text/html; charset=utf-8") == "utf-8"


def test_detect_charset_shiftjis():
    assert detect_charset("text/html; charset=Shift_JIS") == "Shift_JIS"


def test_detect_charset_default():
    assert detect_charset("text/plain") == "utf-8"


def test_decode_charset_latin1():
    data = "café".encode("latin-1")
    result = decode_charset(data, "latin-1")
    assert "caf" in result


def test_decode_charset_fallback():
    result = decode_charset(b"hello", "invalid-charset-xyz")
    assert "hello" in result


# ---- sniff ----


def test_sniff_json_auto():
    body = json.dumps({"key": "value"}).encode()
    assert sniff_content_type(body, "") == "json"


def test_sniff_binary():
    body = bytes(range(256))
    assert sniff_content_type(body, "") == "binary"


def test_sniff_text():
    assert sniff_content_type(b"plain text response", "text/plain") == "text"
