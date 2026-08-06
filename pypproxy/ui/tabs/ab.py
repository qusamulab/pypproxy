from __future__ import annotations

import json

from nicegui import ui

from pypproxy.store.models import Entry
from pypproxy.store.store import Store
from pypproxy.ui.components import entry_label as make_entry_label
from pypproxy.ui.components import set_entry_label


def build_ab_tab(store: Store) -> dict:
    state: dict = {"entry": None}

    with ui.column().classes("w-full h-full overflow-auto q-pa-md"):
        ui.label("A/B Test").classes("text-subtitle2 q-mb-xs")
        ui.label("Send the same request to two endpoints and compare responses.").classes(
            "text-caption text-grey q-mb-md"
        )

        entry_label = make_entry_label()

        with ui.row().classes("gap-2 items-end q-mb-sm flex-wrap"):
            host_a = (
                ui.input(label="Host A (from entry)").props("dense outlined dark").classes("w-56")
            )
            host_b = (
                ui.input(label="Host B (override)").props("dense outlined dark").classes("w-56")
            )
            scheme_b = (
                ui.select(["", "http", "https"], value="", label="Scheme B")
                .props("dense outlined dark")
                .classes("w-24")
            )
            run_btn = ui.button("Run A/B", icon="compare").props("color=primary")

        summary_label = ui.label("").classes("text-caption text-grey q-mb-sm")

        with ui.row().classes("gap-2 w-full"):
            with ui.column().classes("flex-1"):
                ui.label("Host A").classes("text-caption text-weight-bold")
                status_a = ui.label("").classes("text-caption")
                body_a = (
                    ui.textarea()
                    .props("outlined dense rows=14 readonly")
                    .classes("w-full font-mono text-xs")
                )

            with ui.column().classes("flex-1"):
                ui.label("Host B").classes("text-caption text-weight-bold")
                status_b = ui.label("").classes("text-caption")
                body_b = (
                    ui.textarea()
                    .props("outlined dense rows=14 readonly")
                    .classes("w-full font-mono text-xs")
                )

        ui.label("Diff summary:").classes("text-caption text-weight-bold q-mt-sm")
        diff_area = (
            ui.textarea()
            .props("outlined dense rows=8 readonly")
            .classes("w-full font-mono text-xs")
        )

        async def _run() -> None:
            entry = state.get("entry")
            if not entry:
                ui.notify("Select an entry from Traffic first", type="warning")
                return
            b_host = host_b.value.strip()
            if not b_host:
                ui.notify("Enter Host B", type="warning")
                return

            run_btn.props("loading")
            try:
                from pypproxy.tools.ab_test import run_ab_test

                result = await run_ab_test(entry, b_host, scheme_b.value or "")

                status_a.text = f"Status: {result.status_a}  ({result.duration_a_ms} ms)"
                status_b.text = f"Status: {result.status_b}  ({result.duration_b_ms} ms)"

                def _fmt(b: bytes) -> str:
                    try:
                        parsed = json.loads(b)
                        return json.dumps(parsed, indent=2, ensure_ascii=False)
                    except Exception:
                        return b.decode("utf-8", errors="replace")

                text_a = _fmt(result.body_a)
                text_b = _fmt(result.body_b)
                body_a.value = text_a
                body_b.value = text_b

                diff_area.value = result.diff_summary()

                summary_label.text = (
                    f"Status diff: {'YES ⚠' if result.status_diff else 'no'}  |  "
                    f"Body diff: {'YES ⚠' if result.body_diff else 'no'}"
                )

                if result.status_diff or result.body_diff:
                    ui.notify("Differences found!", type="warning")
                else:
                    ui.notify("Responses are identical", type="positive")
            finally:
                run_btn.props(remove="loading")

        run_btn.on("click", _run)

    def open_entry(entry: Entry) -> None:
        state["entry"] = entry
        set_entry_label(entry_label, entry)
        host_a.value = entry.host

    return {"open_entry": open_entry}
