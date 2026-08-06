from __future__ import annotations

import asyncio

from nicegui import ui

from pypproxy.proxy.intercept import InterceptManager, PendingRequest


def build_intercept_panel(mgr: InterceptManager, container: ui.element) -> None:
    """Render the intercept panel inside container. Polls for pending requests."""

    async def _poller() -> None:
        q = mgr.subscribe()
        try:
            while True:
                try:
                    req: PendingRequest = q.get_nowait()
                    _show_dialog(req, mgr)
                except asyncio.QueueEmpty:
                    pass
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            mgr.unsubscribe(q)

    asyncio.ensure_future(_poller())


def _show_dialog(req: PendingRequest, mgr: InterceptManager) -> None:
    with ui.dialog() as dlg, ui.card().classes("w-full").style("min-width:700px"):
        ui.label(f"Intercepted: {req.method} {req.scheme}://{req.host}{req.path}").classes(
            "text-subtitle1 text-weight-bold"
        )

        # Headers editor
        ui.label("Headers").classes("text-caption text-weight-bold q-mt-sm")
        headers_text = "\n".join(f"{k}: {', '.join(v)}" for k, v in req.headers.items())
        headers_input = (
            ui.textarea(value=headers_text)
            .props("outlined dense rows=8")
            .classes("w-full font-mono text-xs")
        )

        # Body editor
        ui.label("Body").classes("text-caption text-weight-bold q-mt-sm")
        body_text = req.body.decode(errors="replace")
        body_input = (
            ui.textarea(value=body_text)
            .props("outlined dense rows=6")
            .classes("w-full font-mono text-xs")
        )

        def _forward() -> None:
            # Parse edited headers back
            edited_headers: dict[str, list[str]] = {}
            for line in headers_input.value.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    edited_headers.setdefault(k.strip().lower(), []).append(v.strip())
            edited_body = body_input.value.encode()
            mgr.forward(req.id, edited_headers, edited_body)
            dlg.close()
            ui.notify("Forwarded", type="positive")

        def _drop() -> None:
            mgr.drop(req.id)
            dlg.close()
            ui.notify("Dropped", type="warning")

        with ui.row().classes("q-mt-sm gap-2"):
            ui.button("Forward", icon="send", on_click=_forward).props("color=positive size=sm")
            ui.button("Drop", icon="block", on_click=_drop).props("color=negative size=sm")

    dlg.open()
