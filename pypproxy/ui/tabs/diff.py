from __future__ import annotations

import difflib

from nicegui import ui

from pypproxy.store.models import Entry
from pypproxy.store.store import Store
from pypproxy.ui.components import tab_container


def build_diff_view(store: Store) -> dict:
    """Side-by-side diff of two captured entries, chosen from the traffic list."""
    with tab_container():
        ui.label("Diff View").classes("text-subtitle2 q-mb-sm")
        ui.label("Select two entries from the traffic list (right-click → Compare)").classes(
            "text-grey text-caption"
        )
        diff_container = ui.element("div").classes("w-full")

    def set_entries(left: Entry, right: Entry) -> None:
        _render_diff(left, right, diff_container)

    return {"set_entries": set_entries}


def _render_diff(left: Entry, right: Entry, container: ui.element) -> None:
    container.clear()
    with container:
        with ui.tabs() as tabs:
            req_tab = ui.tab("Request")
            resp_tab = ui.tab("Response")
            headers_tab = ui.tab("Headers")

        with ui.tab_panels(tabs, value=req_tab).classes("w-full"):
            with ui.tab_panel(req_tab):
                _render_text_diff(
                    _entry_req_text(left),
                    _entry_req_text(right),
                    f"#{left.id} {left.method} {left.path}",
                    f"#{right.id} {right.method} {right.path}",
                )
            with ui.tab_panel(resp_tab):
                _render_text_diff(
                    _decode(left.resp_body),
                    _decode(right.resp_body),
                    f"#{left.id} {left.status_code}",
                    f"#{right.id} {right.status_code}",
                )
            with ui.tab_panel(headers_tab):
                _render_text_diff(
                    _headers_text(left.req_headers),
                    _headers_text(right.req_headers),
                    f"#{left.id} req headers",
                    f"#{right.id} req headers",
                )


def _render_text_diff(a: str, b: str, label_a: str, label_b: str) -> None:
    diff = list(
        difflib.unified_diff(
            a.splitlines(keepends=True),
            b.splitlines(keepends=True),
            fromfile=label_a,
            tofile=label_b,
            lineterm="",
        )
    )

    if not diff:
        ui.label("No differences").classes("text-grey q-pa-sm")
        return

    html_parts: list[str] = []
    for line in diff:
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            cls = "color:#888"
        elif line.startswith("+"):
            cls = "color:#4caf50;background:#1b2e1b"
        elif line.startswith("-"):
            cls = "color:#f44336;background:#2e1b1b"
        else:
            cls = "color:#ccc"
        escaped = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        html_parts.append(f'<span style="{cls}">{escaped}</span>')

    html = (
        "<pre style='font-size:12px;line-height:1.4;overflow:auto;padding:8px;background:#111'>"
        + "\n".join(html_parts)
        + "</pre>"
    )
    ui.html(html).classes("w-full")


def _entry_req_text(e: Entry) -> str:
    parts = [f"{e.method} {e.path} HTTP/1.1", f"Host: {e.host}"]
    for k, vs in e.req_headers.items():
        parts.append(f"{k}: {', '.join(vs)}")
    parts.append("")
    if e.req_body:
        parts.append(_decode(e.req_body))
    return "\n".join(parts)


def _headers_text(headers: dict) -> str:
    return "\n".join(f"{k}: {', '.join(v)}" for k, v in sorted(headers.items()))


def _decode(b: bytes) -> str:
    if not b:
        return ""
    try:
        return b.decode("utf-8", errors="replace")
    except Exception:
        return b.hex()
