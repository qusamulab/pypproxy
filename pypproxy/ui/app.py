"""The GUI shell: sidebar navigation, toolbar, and the live traffic feed."""

from __future__ import annotations

import asyncio

from nicegui import app as nicegui_app
from nicegui import ui

from pypproxy import __version__
from pypproxy.bootstrap import AppContext
from pypproxy.store.models import Filter
from pypproxy.ui.intercept_dialog import build_intercept_panel
from pypproxy.ui.pages import DEFAULT_PAGE, NAV, PAGES
from pypproxy.ui.theme import PALETTE, apply_dark_theme
from pypproxy.ui.traffic import update_table
from pypproxy.ui.workspace import Workspace

FILTER_PLACEHOLDER = "host == example.com && method == POST"
FILTER_HELP = (
    "Fields: host path method status protocol request response full_text"
    "  |  Ops: == != contains ~  |  Logic: && ||"
)
#: How often the live feed drains the store's subscription queue.
POLL_INTERVAL_SECONDS = 0.2


def build_ui(ctx: AppContext) -> None:
    from pypproxy.ui.settings import build_settings_page

    build_settings_page(
        cfg=ctx.config,
        rules=ctx.rules,
        cert_mgr=ctx.client_certs,
        scope_mgr=ctx.scope,
    )

    @ui.page("/")
    async def index() -> None:
        apply_dark_theme()
        ui.dark_mode().enable()
        _build_shell(ctx)


def _build_shell(ctx: AppContext) -> None:
    ws = Workspace(store=ctx.store, intercept=ctx.intercept)
    nav_items: dict[str, ui.element] = {}

    with ui.row().classes("w-full").style("height:100vh; overflow:hidden; gap:0"):
        with ui.element("div").classes("pp-sidebar"):
            _build_logo(ctx)
            for section in NAV:
                with ui.element("div").classes("pp-nav-section"):
                    ui.element("div").classes("pp-nav-section-label").text = section.title
                    for page in section.pages:
                        nav_items[page.id] = _build_nav_item(page.label, page.icon)
            _build_settings_link()

        with ui.element("div").classes("pp-main"):
            filter_input = _build_toolbar(ws)
            page_container = ui.element("div").style(
                "flex:1; overflow:hidden; display:flex; flex-direction:column"
            )
            if ws.intercept is not None:
                build_intercept_panel(ws.intercept, page_container)

    def open_page(page_id: str) -> None:
        page = PAGES[page_id]
        ws.active_page = page_id
        for item in nav_items.values():
            item.classes(remove="active")
        nav_items[page_id].classes("active")

        page_container.clear()
        with page_container:
            state = page.build(ws)
        ws.page_state[page_id] = state or {}

        # Deliver an entry queued by the traffic context menu.
        if ws.pending_entry is not None and state and "open_entry" in state:
            state["open_entry"](ws.pending_entry)
            ws.pending_entry = None

    ws.page_state["nav"] = {"open": open_page}

    for page_id, item in nav_items.items():
        item.on("click", lambda pid=page_id: open_page(pid))

    def apply_filter() -> None:
        ws.traffic_filter = Filter(expression=filter_input.value or "")
        if ws.active_page == DEFAULT_PAGE:
            open_page(DEFAULT_PAGE)

    filter_input.on("update:model-value", lambda: apply_filter())

    open_page(DEFAULT_PAGE)
    _start_live_feed(ws)


def _build_logo(ctx: AppContext) -> None:
    with ui.element("div").classes("pp-logo"):
        ui.element("div").classes("pp-logo-name").text = "pypproxy"
        with ui.row().classes("items-center gap-2").style("margin-top:4px"):
            ui.element("div").classes("pp-status-dot").tooltip("Proxy running")
            ui.element("div").classes(
                "pp-logo-sub"
            ).text = f"v{__version__} · :{ctx.config.proxy.port}"


def _build_nav_item(label: str, icon: str) -> ui.element:
    item = ui.element("div").classes("pp-nav-item")
    with item:
        ui.html(f'<span class="material-icons pp-nav-icon">{icon}</span>')
        ui.label(label).style("font-size:13.5px")
    return item


def _build_settings_link() -> None:
    ui.element("div").style("flex:1")
    with ui.element("div").style("padding:12px 18px 16px; border-top:1px solid var(--pp-border)"):
        item = ui.element("div").classes("pp-nav-item").style("padding:6px 0")
        with item:
            ui.html(
                '<span class="material-icons pp-nav-icon" style="font-size:14px">settings</span>'
            )
            ui.label("Settings").style("font-size:12px")
        item.on("click", lambda: ui.navigate.to("/settings"))


def _build_toolbar(ws: Workspace) -> ui.input:
    with ui.element("div").classes("pp-toolbar"):
        filter_input = (
            ui.input(placeholder=FILTER_PLACEHOLDER)
            .props("dense outlined dark")
            .classes("pp-filter-wrap")
            .tooltip(FILTER_HELP)
        )

        ui.element("div").style("flex:1")

        if ws.intercept is not None:
            intercept = ws.intercept
            toggle = (
                ui.switch("Intercept").props("dense dark color=warning").tooltip("Pause requests")
            )
            toggle.on("update:model-value", lambda e: intercept.set_enabled(e.args))

        ui.button(icon="delete_sweep", on_click=lambda: _clear_traffic(ws)).props(
            "flat dense size=sm color=negative"
        ).tooltip("Clear traffic")
        ui.button(
            icon="light_mode",
            on_click=lambda: ui.run_javascript(
                "const t = ppToggleTheme(); "
                "document.querySelector('.pp-theme-btn .material-icons').textContent = "
                "t === 'light' ? 'dark_mode' : 'light_mode';"
            ),
        ).props("flat dense size=sm").classes("pp-theme-btn").style(
            f"color:{PALETTE['text_muted']}"
        ).tooltip("Toggle light/dark mode")
        ui.button(icon="settings", on_click=lambda: ui.navigate.to("/settings")).props(
            "flat dense size=sm"
        ).style(f"color:{PALETTE['text_muted']}").tooltip("Settings")

    return filter_input


def _start_live_feed(ws: Workspace) -> None:
    queue = ws.store.subscribe()

    async def poll() -> None:
        try:
            while True:
                _drain(ws, queue)
                await asyncio.sleep(POLL_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            ws.store.unsubscribe(queue)

    nicegui_app.on_shutdown(lambda: ws.store.unsubscribe(queue))
    asyncio.ensure_future(poll())


def _drain(ws: Workspace, queue: asyncio.Queue) -> None:
    """Fold every buffered entry into the traffic table in a single repaint."""
    dirty = False
    while True:
        try:
            entry = queue.get_nowait()
        except asyncio.QueueEmpty:
            break
        if ws.active_page == DEFAULT_PAGE and ws.traffic_filter.matches(entry):
            dirty = True

    page = ws.page_state.get(DEFAULT_PAGE)
    if dirty and page:
        update_table(ws.visible_entries(), page["table"])


def _clear_traffic(ws: Workspace) -> None:
    ws.store.clear()
    if ws.active_page == DEFAULT_PAGE:
        page = ws.page_state.get(DEFAULT_PAGE)
        if page:
            page["refresh"]()
    ui.notify("Cleared", type="info")
