from __future__ import annotations

import json

from nicegui import ui

from pypproxy.core.codec import (
    decode_base64_body,
    decode_cbor,
    decode_charset,
    decode_chunked,
    decode_jwt,
    decode_msgpack,
    decode_multipart,
    decode_protobuf_raw,
    decode_url_encoded,
    decode_xml,
    detect_charset,
    extract_jwt_from_body,
    is_likely_base64,
    sniff_content_type,
)
from pypproxy.core.http import client as http_client
from pypproxy.core.http import flatten_headers
from pypproxy.store.models import Entry

_VIEW_MODES = [
    "Auto",
    "Text",
    "JSON",
    "XML/HTML",
    "Hex",
    "URL-encoded",
    "Multipart",
    "Base64",
    "JWT",
    "Protobuf",
    "MessagePack",
    "CBOR",
]


def render_detail(entry: Entry | None, container: ui.element) -> None:
    container.clear()
    if entry is None:
        with (
            container,
            ui.element("div").style(
                "display:flex; flex-direction:column; align-items:center; justify-content:center; height:100%; color:var(--pp-muted)"
            ),
        ):
            ui.html(
                '<span class="material-icons" style="font-size:36px; opacity:0.2; margin-bottom:8px">preview</span>'
            )
            ui.element("div").style("font-size:13px").text = "Select a request to inspect"
        return

    with container:
        # --- request ---
        with ui.element("div").classes("pp-detail-section"):
            url = entry.base_url
            if entry.query:
                url += "?" + entry.query
            with ui.row().classes("items-center gap-2 q-mb-sm"):
                ui.html(f'<span class="m-pill m-{entry.method.lower()}">{entry.method}</span>')
                ui.element("div").classes("pp-url-bar").style("flex:1").text = url

        with ui.expansion("Request", value=True).classes("w-full"):
            if entry.query:
                ui.element("div").classes("pp-section-title").text = "QUERY"
                _render_query_params(entry.query)

            if entry.req_headers:
                ui.element("div").classes("pp-section-title").style(
                    "margin-top:8px"
                ).text = "HEADERS"
                _render_headers(entry.req_headers)

            if entry.req_body:
                ui.element("div").classes("pp-section-title").style("margin-top:8px").text = "BODY"
                ct = entry.req_headers.get("content-type", [""])[0]
                te = entry.req_headers.get("transfer-encoding", [""])[0]
                body = decode_chunked(entry.req_body) if "chunked" in te.lower() else entry.req_body
                _render_body_with_selector(body, ct, entry.req_headers)

        ui.separator()

        # --- response ---
        with ui.expansion("Response", value=True).classes("w-full"):
            if entry.status_code:
                with ui.row().classes("items-center gap-2 q-mb-sm"):
                    ui.html(
                        f'<span class="s-pill s-{entry.status_code // 100}">{entry.status_code}</span>'
                    )
                    ui.element("span").style(
                        "font-size:11px; color:var(--pp-muted)"
                    ).text = f"{entry.duration_ms} ms"
                    if entry.resp_body:
                        ui.element("span").classes(
                            "pp-size-chip"
                        ).text = f"{len(entry.resp_body):,} B"

            if entry.resp_headers:
                ui.element("div").classes("pp-section-title").text = "HEADERS"
                _render_headers(entry.resp_headers)

            if entry.resp_body:
                ui.element("div").classes("pp-section-title").style("margin-top:8px").text = "BODY"
                ct = entry.resp_headers.get("content-type", [""])[0]
                te = entry.resp_headers.get("transfer-encoding", [""])[0]
                body = (
                    decode_chunked(entry.resp_body) if "chunked" in te.lower() else entry.resp_body
                )
                charset = detect_charset(ct)
                _render_body_with_selector(body, ct, entry.resp_headers, charset)

        # --- replay ---
        with ui.element("div").style("padding:10px 14px"):
            ui.button("Replay", icon="replay", on_click=lambda: _replay(entry)).props(
                "color=primary size=sm"
            )


def _render_query_params(query: str) -> None:
    from pypproxy.core.codec import decode_url_params

    text = decode_url_params(query)
    ui.element("pre").classes("paxy-body-pre").text = text


def _render_body_with_selector(
    raw: bytes,
    content_type: str,
    headers: dict | None = None,
    charset: str = "utf-8",
) -> None:
    sniffed = sniff_content_type(raw, content_type)

    # Check for JWT in headers
    jwt_token = extract_jwt_from_body(b"", headers or {}) if headers else None

    default_mode = {
        "json": "JSON",
        "xml": "XML/HTML",
        "html": "XML/HTML",
        "proto": "Protobuf",
        "msgpack": "MessagePack",
        "cbor": "CBOR",
        "binary": "Hex",
        "form": "URL-encoded",
        "multipart": "Multipart",
    }.get(sniffed, "Auto")

    # Override: if JWT found in auth header, suggest JWT view
    if jwt_token and default_mode == "Auto":
        default_mode = "JWT"

    # Override: if likely base64 and binary
    if sniffed == "binary" and is_likely_base64(raw):
        default_mode = "Base64"

    body_area = ui.element("div").classes("w-full")

    def _update(mode: str) -> None:
        body_area.clear()
        with body_area:
            text = _decode_as(raw, mode, content_type, headers or {}, charset)
            ui.element("pre").classes("paxy-body-pre").text = text

    with ui.row().classes("items-center gap-2 q-mb-xs"):
        view_select = (
            ui.select(_VIEW_MODES, value=default_mode, label="View")
            .props("dense outlined dark")
            .classes("w-36")
        )
        # size badge
        size = len(raw)
        if size > 0:
            ui.label(f"{size:,} bytes").classes("text-caption text-grey")

        view_select.on("update:model-value", lambda e: _update(e.args))

    _update(default_mode)


def _decode_as(
    raw: bytes,
    mode: str,
    content_type: str,
    headers: dict,
    charset: str = "utf-8",
) -> str:
    if mode == "Hex":
        return _to_hex(raw)
    if mode == "Protobuf":
        return decode_protobuf_raw(raw)
    if mode == "MessagePack":
        return decode_msgpack(raw)
    if mode == "CBOR":
        return decode_cbor(raw)
    if mode == "URL-encoded":
        return decode_url_encoded(raw)
    if mode == "Multipart":
        return decode_multipart(raw, content_type)
    if mode == "Base64":
        return decode_base64_body(raw)
    if mode == "JWT":
        # Try to find JWT in Authorization header or body
        token = extract_jwt_from_body(raw, headers)
        if token:
            return decode_jwt(token)
        # fallback: try raw body as JWT
        return decode_jwt(raw.decode("utf-8", errors="replace"))
    if mode == "XML/HTML":
        return decode_xml(raw)
    if mode == "JSON":
        try:
            text = decode_charset(raw, charset)
            return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except Exception:
            return decode_charset(raw, charset)
    if mode == "Text":
        return decode_charset(raw, charset)
    # Auto
    return _smart_decode(raw, content_type, headers, charset)


def _smart_decode(
    raw: bytes,
    content_type: str,
    headers: dict | None = None,
    charset: str = "utf-8",
) -> str:
    sniffed = sniff_content_type(raw, content_type)
    if sniffed == "json":
        try:
            text = decode_charset(raw, charset)
            return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except Exception:
            pass
    if sniffed in ("xml", "html"):
        return decode_xml(raw)
    if sniffed == "proto":
        return decode_protobuf_raw(raw)
    if sniffed == "msgpack":
        return decode_msgpack(raw)
    if sniffed == "cbor":
        return decode_cbor(raw)
    if sniffed == "form":
        return decode_url_encoded(raw)
    if sniffed == "multipart":
        return decode_multipart(raw, content_type)
    if sniffed == "binary":
        if is_likely_base64(raw):
            return decode_base64_body(raw)
        return _to_hex(raw)
    return decode_charset(raw, charset)


def _to_hex(raw: bytes, width: int = 16) -> str:
    lines: list[str] = []
    for i in range(0, len(raw), width):
        chunk = raw[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def _render_headers(headers: dict[str, list[str]]) -> None:
    with ui.element("div").classes("pp-headers"):
        for k, vs in sorted(headers.items()):
            with ui.element("div").classes("pp-hrow"):
                ui.element("div").classes("pp-hkey").text = k
                ui.element("div").classes("pp-hval").text = ", ".join(vs)


async def _replay(entry: Entry) -> None:
    url = entry.base_url
    if entry.query:
        url += "?" + entry.query
    headers = flatten_headers(entry.req_headers)
    try:
        async with http_client(30) as client:
            resp = await client.request(
                method=entry.method,
                url=url,
                headers=headers,
                content=entry.req_body,
            )
        ui.notify(f"Replay: {resp.status_code} ({len(resp.content)} bytes)", type="positive")
    except Exception as e:
        ui.notify(f"Replay failed: {e}", type="negative")
