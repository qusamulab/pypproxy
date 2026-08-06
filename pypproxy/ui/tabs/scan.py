from __future__ import annotations

from nicegui import ui

from pypproxy.store.models import Entry
from pypproxy.store.store import Store
from pypproxy.ui.components import entry_label as make_entry_label
from pypproxy.ui.components import set_entry_label


def build_scan_tab(store: Store) -> dict:
    """Build the Active Scan tab. Returns state with open_entry method."""
    state: dict = {"entry": None}

    with ui.column().classes("w-full h-full overflow-auto q-pa-md"):
        entry_label = make_entry_label()

        with ui.row().classes("items-center gap-4 q-mb-md"):
            cats = (
                ui.select(
                    ["xss", "sqli", "cmdi", "ssti", "path_traversal"],
                    multiple=True,
                    value=["xss", "sqli"],
                    label="Categories",
                )
                .props("dense outlined dark")
                .classes("w-72")
            )
            conc = (
                ui.number(label="Concurrency", value=5, min=1, max=20)
                .props("dense outlined dark")
                .classes("w-24")
            )
            run_btn = ui.button("Scan", icon="search").props("color=negative")

        summary_label = ui.label("").classes("text-caption text-grey q-mb-xs")

        results_table = (
            ui.table(
                columns=[
                    {"name": "param", "label": "Param", "field": "param", "align": "left"},
                    {"name": "cat", "label": "Category", "field": "category", "align": "center"},
                    {"name": "payload", "label": "Payload", "field": "payload", "align": "left"},
                    {
                        "name": "status",
                        "label": "Status",
                        "field": "status_code",
                        "align": "center",
                    },
                    {"name": "ms", "label": "ms", "field": "duration_ms", "align": "right"},
                    {"name": "suspicious", "label": "⚠", "field": "suspicious", "align": "center"},
                    {"name": "reason", "label": "Reason", "field": "reason", "align": "left"},
                ],
                rows=[],
                row_key="payload",
            )
            .classes("w-full")
            .props("dense flat dark")
        )
        results_table.add_slot(
            "body-cell-suspicious",
            """
            <q-td :props="props">
              <q-badge v-if="props.value" color="negative" label="!" />
            </q-td>
        """,
        )

        async def _scan() -> None:
            from pypproxy.security.scanner import run_scan

            entry = state.get("entry")
            if not entry:
                ui.notify("No entry selected", type="warning")
                return
            run_btn.props("loading")
            try:
                results = await run_scan(
                    entry,
                    categories=list(cats.value) if cats.value else None,
                    concurrency=int(conc.value or 5),
                )
                results_table.rows = [r.to_dict() for r in results]
                results_table.update()
                suspicious = sum(1 for r in results if r.suspicious)
                summary_label.text = f"{len(results)} tests — {suspicious} findings"
                if suspicious:
                    ui.notify(f"⚠ {suspicious} potential findings!", type="warning")
                else:
                    ui.notify(f"Scan complete — {len(results)} tests, no findings", type="positive")
            finally:
                run_btn.props(remove="loading")

        run_btn.on("click", _scan)

    def open_entry(entry: Entry) -> None:
        state["entry"] = entry
        set_entry_label(entry_label, entry)

    return {"open_entry": open_entry}
