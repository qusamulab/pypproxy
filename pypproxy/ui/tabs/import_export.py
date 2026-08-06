from __future__ import annotations

import json

from nicegui import ui

from pypproxy.store.store import Store


def build_import_tab(store: Store) -> None:
    """Build the Import tab content."""
    with ui.column().classes("w-full h-full overflow-auto q-pa-md"):
        ui.label("Import Traffic").classes("text-subtitle2 q-mb-sm")

        # --- File upload ---
        ui.label("Upload HAR or paxy JSON file:").classes("text-caption text-grey q-mb-xs")

        async def _handle_upload(e) -> None:  # noqa: ANN001
            from pypproxy.exchange.importer import import_har, import_json

            try:
                data = e.content.read()
                # Auto-detect format
                parsed = json.loads(data)
                if "log" in parsed and "entries" in parsed.get("log", {}):
                    count = import_har(data, store)
                    ui.notify(f"Imported {count} entries from HAR", type="positive")
                else:
                    count = import_json(data, store)
                    ui.notify(f"Imported {count} entries from JSON", type="positive")
            except Exception as err:
                ui.notify(f"Import failed: {err}", type="negative")

        ui.upload(
            label="Drop HAR/JSON here",
            on_upload=_handle_upload,
            auto_upload=True,
        ).props("accept=.har,.json flat").classes("w-full q-mb-md")

        ui.separator()

        # --- Paste JSON ---
        ui.label("Or paste HAR/JSON directly:").classes("text-caption text-grey q-mb-xs")
        paste_area = (
            ui.textarea(placeholder='{"log": {"entries": [...]}} or [{"method": "GET", ...}]')
            .props("outlined dense rows=10")
            .classes("w-full font-mono text-xs")
        )

        async def _import_paste() -> None:
            from pypproxy.exchange.importer import import_har, import_json

            text = paste_area.value.strip()
            if not text:
                ui.notify("Nothing to import", type="warning")
                return
            try:
                parsed = json.loads(text)
                if "log" in parsed and "entries" in parsed.get("log", {}):
                    count = import_har(text, store)
                    ui.notify(f"Imported {count} entries from HAR", type="positive")
                else:
                    count = import_json(text, store)
                    ui.notify(f"Imported {count} entries from JSON", type="positive")
                paste_area.value = ""
            except Exception as err:
                ui.notify(f"Import failed: {err}", type="negative")

        ui.button("Import", icon="upload", on_click=_import_paste).props("color=primary q-mt-sm")

        ui.separator().classes("q-my-md")

        # --- Full-text search ---
        ui.label("Full-text search").classes("text-subtitle2 q-mb-sm")
        ui.label("Search across all captured request/response bodies, headers, and URLs.").classes(
            "text-caption text-grey q-mb-xs"
        )

        with ui.row().classes("gap-2 items-center w-full"):
            search_input = (
                ui.input(placeholder="Search term…").props("dense outlined dark").classes("flex-1")
            )
            search_btn = ui.button("Search", icon="search").props("color=primary size=sm")

        search_label = ui.label("").classes("text-caption text-grey q-mt-xs")
        search_table = (
            ui.table(
                columns=[
                    {
                        "name": "id",
                        "label": "ID",
                        "field": "entry_id",
                        "align": "right",
                        "style": "width:60px",
                    },
                    {"name": "snippet", "label": "Match", "field": "snippet", "align": "left"},
                    {
                        "name": "rank",
                        "label": "Score",
                        "field": "rank",
                        "align": "right",
                        "style": "width:80px",
                    },
                ],
                rows=[],
                row_key="entry_id",
            )
            .classes("w-full")
            .props("dense flat dark")
        )

        async def _search() -> None:
            q = search_input.value.strip()
            if not q:
                return
            db = getattr(store, "_db", None)
            if db is None:
                # fallback to in-memory
                from pypproxy.store.models import Filter

                entries, total = store.list(Filter(search=q), 0, 50)
                rows = [
                    {"entry_id": e.id, "rank": 0.0, "snippet": f"{e.host}{e.path}"} for e in entries
                ]
                search_label.text = f"{total} results (in-memory search)"
            else:
                results = await db.search(q, limit=50)
                rows = [r.to_dict() for r in results]
                search_label.text = f"{len(rows)} results"
            search_table.rows = rows
            search_table.update()

        search_btn.on("click", _search)
        search_input.on("keydown.enter", _search)
