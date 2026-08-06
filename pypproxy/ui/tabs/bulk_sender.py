from __future__ import annotations

import json

from nicegui import ui

from pypproxy.store.models import Entry
from pypproxy.store.store import Store
from pypproxy.tools.bulk import BulkPayload, bulk_send, race_send
from pypproxy.ui.components import entry_label as make_entry_label
from pypproxy.ui.components import set_entry_label, tab_container


def build_bulk_sender(store: Store) -> dict:
    """Send many variants of one request, or the same request many times at once."""
    state: dict = {"entry": None}

    with tab_container():
        ui.label("Bulk Sender").classes("text-subtitle2 q-mb-sm")
        entry_label = make_entry_label()

        ui.separator()

        # Mode selector
        with ui.row().classes("items-center gap-4 q-mb-sm"):
            mode = (
                ui.select(["Payload list", "Race condition"], value="Payload list", label="Mode")
                .props("dense outlined dark")
                .classes("w-48")
            )
            count_input = (
                ui.number(label="Count", value=10, min=1, max=500)
                .props("dense outlined dark")
                .classes("w-24")
            )
            concurrency_input = (
                ui.number(label="Concurrency", value=10, min=1, max=100)
                .props("dense outlined dark")
                .classes("w-24")
            )

        # Payload editor (for payload list mode)
        ui.label("Payloads (one per line, JSON or plain text):").classes("text-caption")
        payload_input = (
            ui.textarea(placeholder='{"key": "value1"}\n{"key": "value2"}')
            .props("outlined dense rows=6")
            .classes("w-full font-mono text-xs")
        )

        send_btn = ui.button("Send", icon="send").props("color=primary")
        ui.separator()

        # Results table
        results_label = ui.label("").classes("text-caption text-grey")
        results_table = (
            ui.table(
                columns=[
                    {"name": "label", "label": "Label", "field": "label", "align": "left"},
                    {
                        "name": "status",
                        "label": "Status",
                        "field": "status_code",
                        "align": "center",
                    },
                    {"name": "ms", "label": "ms", "field": "duration_ms", "align": "right"},
                    {"name": "error", "label": "Error", "field": "error", "align": "left"},
                ],
                rows=[],
                row_key="label",
            )
            .classes("w-full")
            .props("dense flat dark")
        )

        async def _send() -> None:
            entry = state.get("entry")
            if not entry:
                ui.notify("No entry selected", type="warning")
                return

            send_btn.props("loading")
            try:
                if mode.value == "Race condition":
                    results = await race_send(
                        entry,
                        count=int(count_input.value),
                        timeout=30,
                    )
                else:
                    payloads: list[BulkPayload] = []
                    for i, line in enumerate(payload_input.value.splitlines()):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            body = json.dumps(obj).encode()
                        except Exception:
                            body = line.encode()
                        payloads.append(BulkPayload(label=f"payload-{i}", override_body=body))
                    if not payloads:
                        ui.notify("No payloads entered", type="warning")
                        return
                    results = await bulk_send(
                        entry,
                        payloads,
                        concurrency=int(concurrency_input.value),
                    )

                results_table.rows = [r.to_dict() for r in results]
                results_table.update()
                status_counts: dict[int, int] = {}
                for r in results:
                    status_counts[r.status_code] = status_counts.get(r.status_code, 0) + 1
                summary = ", ".join(f"{s}: {c}" for s, c in sorted(status_counts.items()))
                results_label.text = f"{len(results)} requests — {summary}"
                ui.notify(f"Done: {len(results)} requests", type="positive")
            finally:
                send_btn.props(remove="loading")

        send_btn.on("click", _send)

    def open_entry(entry: Entry) -> None:
        state["entry"] = entry
        set_entry_label(entry_label, entry)

    return {"open_entry": open_entry}
