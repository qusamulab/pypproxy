"""The traffic list: request table, row context menu, and detail pane."""

from __future__ import annotations

from nicegui import ui

from pypproxy.store.models import Entry
from pypproxy.ui.workspace import Workspace

#: Row highlight colours offered in the context menu, paired with their labels.
ROW_COLORS = (
    ("", "None"),
    ("#b91c1c", "Red"),
    ("#166534", "Green"),
    ("#1e40af", "Blue"),
    ("#b45309", "Yellow"),
    ("#6b21a8", "Purple"),
)

_COLUMNS = [
    {
        "name": "id",
        "label": "#",
        "field": "id",
        "align": "right",
        "style": "width:42px; color:var(--pp-muted)",
    },
    {
        "name": "method",
        "label": "Method",
        "field": "method",
        "align": "center",
        "style": "width:72px",
    },
    {"name": "host", "label": "Host", "field": "host", "align": "left"},
    {"name": "path", "label": "Path", "field": "path", "align": "left"},
    {
        "name": "status",
        "label": "Status",
        "field": "status_code",
        "align": "center",
        "style": "width:64px",
    },
    {
        "name": "size",
        "label": "Size",
        "field": "size",
        "align": "right",
        "style": "width:64px; color:var(--pp-muted)",
    },
    {
        "name": "ms",
        "label": "ms",
        "field": "duration_ms",
        "align": "right",
        "style": "width:52px; color:var(--pp-muted)",
    },
]

_BODY_SLOT = r"""
<q-tr :props="props"
      :class="{'pp-row-selected': props.row._selected}"
      :style="props.row.color ? 'border-left:2px solid ' + props.row.color : ''"
      @click="$emit('row-click', $event, props.row)"
      @contextmenu.prevent="$emit('row-contextmenu', $event, props.row)"
      style="cursor:pointer">
  <q-td key="id"     :props="props" style="color:var(--pp-muted); font-size:11px; font-family:monospace">{{ props.row.id }}</q-td>
  <q-td key="method" :props="props">
    <span :class="'m-pill m-' + props.row.method.toLowerCase()">{{ props.row.method }}</span>
  </q-td>
  <q-td key="host"   :props="props" style="font-size:12px; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap">{{ props.row.host }}</q-td>
  <q-td key="path"   :props="props" style="font-size:12px; font-family:monospace; max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap">{{ props.row.path }}</q-td>
  <q-td key="status" :props="props">
    <span v-if="props.row.status_code" :class="'s-pill s-' + Math.floor(props.row.status_code/100)">{{ props.row.status_code }}</span>
  </q-td>
  <q-td key="size"   :props="props" style="font-size:11px; font-family:monospace">{{ props.row.size }}</q-td>
  <q-td key="ms"     :props="props" style="font-size:11px; font-family:monospace">{{ props.row.duration_ms }}</q-td>
</q-tr>
"""

#: Context-menu shortcuts: icon, label, target page id.
_SEND_TO = (
    ("send", "Resender", "resender"),
    ("dynamic_feed", "Bulk Sender", "bulk"),
    ("playlist_play", "Macro", "macro"),
    ("compare", "A/B Test", "ab"),
    ("code", "Generate Code", "codegen"),
    ("security", "Security Check", "security"),
    ("shield", "Adv Security", "advsec"),
    ("search", "Active Scan", "scan"),
    ("adb", "Frida Hook", "frida"),
)


def build_traffic_page(ws: Workspace) -> dict:
    with ui.splitter(value=58).classes("w-full").style("height:calc(100vh - 48px)") as sp:
        with sp.before:
            table = _build_table(ws)
        with sp.after, ui.element("div").classes("pp-detail"):
            detail_col = ui.column().classes("w-full h-full")
            render_empty_detail(detail_col)

    def refresh() -> None:
        update_table(ws.visible_entries(), table)

    def show(entry: Entry) -> None:
        from pypproxy.ui.detail import render_detail

        render_detail(entry, detail_col)

    return {"table": table, "detail": detail_col, "refresh": refresh, "open_entry": show}


def _build_table(ws: Workspace) -> ui.table:
    table = (
        ui.table(columns=_COLUMNS, rows=[], row_key="id")
        .classes("w-full pp-traffic")
        .props("dense flat dark virtual-scroll")
        .style("height:calc(100vh - 48px); overflow-y:auto")
    )
    table.add_slot("body", _BODY_SLOT)
    update_table(ws.visible_entries(), table)

    def clicked_entry(e) -> Entry | None:  # noqa: ANN001 — NiceGUI event payload
        try:
            row = e.args[1] if isinstance(e.args, list) else e.args
            return ws.store.get(int(row["id"]))
        except (IndexError, KeyError, TypeError, ValueError):
            return None

    async def on_row_click(e) -> None:  # noqa: ANN001
        entry = clicked_entry(e)
        if entry is None:
            return
        for row in table.rows:
            row["_selected"] = row["id"] == entry.id
        table.update()

        page = ws.page_state.get("traffic")
        if page:
            page["open_entry"](entry)

    async def on_row_contextmenu(e) -> None:  # noqa: ANN001
        entry = clicked_entry(e)
        if entry is not None:
            _show_context_menu(entry, ws)

    table.on("row-click", on_row_click)
    table.on("row-contextmenu", on_row_contextmenu)
    return table


def _show_context_menu(entry: Entry, ws: Workspace) -> None:
    open_page = ws.page_state.get("nav", {}).get("open")

    with ui.menu() as menu:
        for icon, label, page_id in _SEND_TO:
            _menu_item(icon, label, lambda pid=page_id: _send_to(pid, entry, ws, open_page))
        if "graphql" in (entry.tags or []):
            _menu_item("account_tree", "GraphQL", lambda: _send_to("graphql", entry, ws, open_page))
        _menu_item("folder", "Add to Session", lambda: _add_to_session(entry))

        ui.separator()
        _menu_item("difference", "Set Diff left", lambda: _set_diff_left(entry, ws))
        if ws.diff_left is not None:
            _menu_item("difference", "Diff with left", lambda: _diff_with_left(entry, ws))

        ui.separator()
        ui.element("div").style(
            "font-size:10px; color:var(--pp-muted); padding:4px 12px 2px; "
            "font-weight:700; text-transform:uppercase; letter-spacing:0.07em"
        ).text = "Color"
        with ui.row().classes("q-px-sm q-pb-xs gap-1"):
            for color, label in ROW_COLORS:

                def pick(c=color) -> None:
                    ws.store.set_color(entry.id, c)
                    _refresh(ws)
                    menu.close()

                dot = (
                    ui.element("div")
                    .style(
                        f"width:16px; height:16px; border-radius:3px; cursor:pointer; "
                        f"background:{color or 'var(--pp-surface2)'}; "
                        f"border:1px solid var(--pp-border)"
                    )
                    .tooltip(label)
                )
                dot.on("click", pick)
    menu.open()


def _menu_item(icon: str, label: str, handler) -> None:  # noqa: ANN001
    with ui.menu_item(on_click=handler), ui.row().classes("items-center gap-2"):
        ui.html(
            f'<span class="material-icons" style="font-size:14px; '
            f'color:var(--pp-muted)">{icon}</span>'
        )
        ui.element("span").style("font-size:13px").text = label


def _send_to(page_id: str, entry: Entry, ws: Workspace, open_page) -> None:  # noqa: ANN001
    ws.pending_entry = entry
    if open_page is not None:
        open_page(page_id)


def _add_to_session(entry: Entry) -> None:
    from pypproxy.ui.tabs.session import get_session_manager

    mgr = get_session_manager()
    active = mgr.get_active()
    if active is None:
        ui.notify("No active session", type="warning")
        return
    mgr.add_entry(active.id, entry.id)
    ui.notify(f"Added to '{active.name}'", type="positive")


def _set_diff_left(entry: Entry, ws: Workspace) -> None:
    ws.diff_left = entry
    ui.notify(f"#{entry.id} set as diff left", type="info")


def _diff_with_left(entry: Entry, ws: Workspace) -> None:
    diff = ws.page_state.get("diff")
    if ws.diff_left is None:
        return
    if diff is None:
        ui.notify("Open the Diff page first", type="warning")
        return
    diff["set_entries"](ws.diff_left, entry)


def _refresh(ws: Workspace) -> None:
    page = ws.page_state.get("traffic")
    if page:
        page["refresh"]()


# --- rendering helpers, also used by the live poller in `app` ---


def update_table(entries: list[Entry], table: ui.table) -> None:
    table.rows = [entry_to_row(e) for e in entries]
    table.update()


def entry_to_row(e: Entry) -> dict:
    size = len(e.resp_body)
    return {
        "id": e.id,
        "method": e.method,
        "host": e.host,
        "path": e.path + (f"?{e.query}" if e.query else ""),
        "status_code": e.status_code,
        "size": f"{size:,}" if size else "",
        "duration_ms": e.duration_ms or "",
        "protocol": e.protocol,
        "color": e.color,
        "_selected": False,
    }


def render_empty_detail(container: ui.element) -> None:
    container.clear()
    with (
        container,
        ui.element("div").classes("pp-empty").style("height:100%; justify-content:center"),
    ):
        ui.html(
            '<span class="material-icons" style="font-size:40px; '
            'color:var(--pp-muted); opacity:0.3">preview</span>'
        )
        ui.element("div").style(
            "font-size:13px; color:var(--pp-muted)"
        ).text = "Click a request to inspect"
