from __future__ import annotations

import json

from nicegui import ui

from pypproxy.core.http import client as http_client
from pypproxy.store.models import Entry
from pypproxy.store.store import Store


def build_resender_tab(store: Store) -> None:
    """Render the Resender tab content."""
    state: dict = {"tabs": [], "active": None}

    with ui.column().classes("w-full h-full"):
        # Tab bar
        with ui.row().classes("items-center gap-2 q-pa-sm").style("border-bottom:1px solid #333"):
            ui.label("Resender").classes("text-subtitle2")
            ui.button("+ New", icon="add", on_click=lambda: _new_tab(state, tab_panels)).props(
                "size=sm flat color=primary"
            )

        # Tab panels
        with ui.element("div").classes("w-full flex-1 overflow-auto") as tab_panels:
            ui.label("Click '+ New' or drag an entry here to create a resender tab.").classes(
                "text-grey q-pa-md"
            )

    # expose method to open entry
    tab_panels._open_entry = lambda e: _open_entry(e, state, tab_panels)  # type: ignore[attr-defined]


def open_entry_in_resender(entry: Entry, panel: ui.element) -> None:
    fn = getattr(panel, "_open_entry", None)
    if fn:
        fn(entry)


def _new_tab(state: dict, container: ui.element, entry: Entry | None = None) -> None:
    tab_id = len(state["tabs"])
    tab_state: dict = {
        "id": tab_id,
        "method": entry.method if entry else "GET",
        "url": entry.base_url if entry else "https://",
        "headers": "\n".join(f"{k}: {', '.join(v)}" for k, v in (entry.req_headers or {}).items())
        if entry
        else "",
        "body": entry.req_body.decode(errors="replace") if (entry and entry.req_body) else "",
        "result": "",
    }
    state["tabs"].append(tab_state)
    state["active"] = tab_id
    container.clear()
    _render_tabs(state, container)


def _open_entry(entry: Entry, state: dict, container: ui.element) -> None:
    _new_tab(state, container, entry)


def _render_tabs(state: dict, container: ui.element) -> None:
    container.clear()
    with container:
        for tab in state["tabs"]:
            _render_tab(tab, state, container)


def _render_tab(tab: dict, state: dict, container: ui.element) -> None:
    with ui.card().classes("w-full q-mb-sm"):
        # Method + URL row
        with ui.row().classes("items-center gap-2 w-full"):
            method_input = (
                ui.select(
                    ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
                    value=tab["method"],
                )
                .props("dense outlined dark")
                .classes("w-28")
            )
            url_input = ui.input(value=tab["url"]).props("dense outlined dark").classes("flex-1")
            send_btn = ui.button("Send", icon="send").props("color=primary size=sm")

        # Headers
        ui.label("Headers").classes("text-caption text-weight-bold q-mt-xs")
        headers_input = (
            ui.textarea(value=tab["headers"])
            .props("outlined dense rows=4")
            .classes("w-full font-mono text-xs")
        )

        # Body
        ui.label("Body").classes("text-caption text-weight-bold")
        body_input = (
            ui.textarea(value=tab["body"])
            .props("outlined dense rows=5")
            .classes("w-full font-mono text-xs")
        )

        # Result
        ui.label("Response").classes("text-caption text-weight-bold")
        result_area = (
            ui.textarea(value=tab["result"])
            .props("outlined dense rows=8 readonly")
            .classes("w-full font-mono text-xs")
        )

        async def _send() -> None:
            method = method_input.value
            url = url_input.value
            headers: dict[str, str] = {}
            for line in headers_input.value.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip()] = v.strip()
            body = body_input.value.encode()
            try:
                async with http_client(30) as client:
                    resp = await client.request(
                        method=method, url=url, headers=headers, content=body
                    )
                ct = resp.headers.get("content-type", "")
                try:
                    if "json" in ct:
                        body_text = json.dumps(resp.json(), indent=2, ensure_ascii=False)
                    else:
                        body_text = resp.text
                except Exception:
                    body_text = resp.text
                result_area.value = (
                    f"HTTP {resp.status_code} ({resp.elapsed.total_seconds() * 1000:.0f}ms)\n"
                    + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                    + f"\n\n{body_text}"
                )
                ui.notify(f"{resp.status_code}", type="positive")
            except Exception as e:
                result_area.value = f"Error: {e}"
                ui.notify(str(e), type="negative")

        send_btn.on("click", _send)
