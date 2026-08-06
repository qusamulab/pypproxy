from __future__ import annotations

import json

from nicegui import ui

from pypproxy.store.models import Entry
from pypproxy.store.store import Store


def build_macro_tab(store: Store) -> dict:
    with ui.column().classes("w-full h-full overflow-auto q-pa-md"):
        ui.label("Macro Runner").classes("text-subtitle2 q-mb-xs")
        ui.label(
            "Chain multiple requests in sequence. Use {{var}} placeholders — values are extracted from responses."
        ).classes("text-caption text-grey q-mb-sm")

        with ui.row().classes("gap-2 items-center q-mb-sm"):
            run_btn = ui.button("Run Macro", icon="play_arrow").props("color=primary")
            clear_btn = ui.button("Clear Steps", icon="delete_sweep").props(
                "flat color=negative size=sm"
            )
            ui.button("Import JSON", icon="upload").props("flat size=sm")
            export_btn = ui.button("Export JSON", icon="download").props("flat size=sm")

        steps_label = ui.label("0 steps").classes("text-caption text-grey")

        # Steps editor
        ui.label("Steps (JSON):").classes("text-caption text-weight-bold q-mt-sm")
        steps_area = (
            ui.textarea(
                placeholder='[\n  {\n    "name": "Login",\n    "method": "POST",\n    "url": "https://api.example.com/login",\n    "body": "{\\"username\\":\\"alice\\",\\"password\\":\\"secret\\"}",\n    "extract": {"token": "data.access_token"},\n    "assert_status": 200\n  },\n  {\n    "name": "Get profile",\n    "method": "GET",\n    "url": "https://api.example.com/profile",\n    "headers": {"Authorization": "Bearer {{token}}"},\n    "assert_status": 200\n  }\n]'
            )
            .props("outlined dense rows=14")
            .classes("w-full font-mono text-xs")
        )

        # Variables display
        ui.label("Extracted variables:").classes("text-caption text-weight-bold q-mt-sm")
        vars_label = ui.label("(none yet)").classes("text-caption text-grey font-mono q-mb-sm")

        # Results
        ui.label("Results:").classes("text-caption text-weight-bold")
        results_table = (
            ui.table(
                columns=[
                    {"name": "step", "label": "Step", "field": "step", "align": "left"},
                    {
                        "name": "status",
                        "label": "Status",
                        "field": "status_code",
                        "align": "center",
                    },
                    {"name": "ms", "label": "ms", "field": "duration_ms", "align": "right"},
                    {
                        "name": "ok",
                        "label": "Assert",
                        "field": "assertion_passed",
                        "align": "center",
                    },
                    {
                        "name": "extracted",
                        "label": "Extracted",
                        "field": "extracted_str",
                        "align": "left",
                    },
                    {"name": "error", "label": "Error", "field": "error", "align": "left"},
                ],
                rows=[],
                row_key="step",
            )
            .classes("w-full")
            .props("dense flat dark")
        )
        results_table.add_slot(
            "body-cell-ok",
            """
            <q-td :props="props">
              <q-badge :color="props.value ? 'positive' : 'negative'" :label="props.value ? '✓' : '✗'" />
            </q-td>
        """,
        )
        results_table.add_slot(
            "body-cell-status",
            """
            <q-td :props="props">
              <q-badge v-if="props.value"
                :color="props.value < 300 ? 'positive' : props.value < 400 ? 'info' : 'negative'"
                :label="props.value" rounded />
            </q-td>
        """,
        )

        async def _run_macro() -> None:
            from pypproxy.tools.macro import MacroRunner, macro_from_json

            try:
                steps = macro_from_json(steps_area.value)
            except Exception as e:
                ui.notify(f"Invalid JSON: {e}", type="negative")
                return
            if not steps:
                ui.notify("No steps to run", type="warning")
                return

            run_btn.props("loading")
            steps_label.text = f"Running {len(steps)} steps…"
            results_table.rows = []
            results_table.update()

            try:
                runner = MacroRunner()
                results = await runner.run(steps)
                rows = []
                for r in results:
                    rows.append(
                        {
                            "step": r.step_name,
                            "status_code": r.status_code,
                            "duration_ms": r.duration_ms,
                            "assertion_passed": r.assertion_passed,
                            "extracted_str": ", ".join(
                                f"{k}={v[:20]}" for k, v in r.extracted.items()
                            ),
                            "error": r.error[:60] if r.error else "",
                        }
                    )
                results_table.rows = rows
                results_table.update()

                # Show extracted vars
                all_extracted: dict[str, str] = {}
                for r in results:
                    all_extracted.update(r.extracted)
                vars_label.text = (
                    json.dumps(all_extracted, ensure_ascii=False) if all_extracted else "(none)"
                )

                fails = sum(1 for r in results if not r.assertion_passed or r.error)
                steps_label.text = f"{len(steps)} steps — {fails} failed"
                if fails:
                    ui.notify(f"{fails} step(s) failed", type="warning")
                else:
                    ui.notify("All steps passed", type="positive")
            finally:
                run_btn.props(remove="loading")

        def _clear() -> None:
            steps_area.value = ""
            results_table.rows = []
            results_table.update()
            vars_label.text = "(none yet)"
            steps_label.text = "0 steps"

        def _export() -> None:
            if steps_area.value.strip():
                ui.download(steps_area.value.encode(), "macro.json")

        run_btn.on("click", _run_macro)
        clear_btn.on("click", _clear)
        export_btn.on("click", _export)

    def open_entries(entries: list[Entry]) -> None:
        from pypproxy.tools.macro import macro_from_entries, macro_to_json

        steps = macro_from_entries(entries)
        steps_area.value = macro_to_json(steps)
        steps_label.text = f"{len(steps)} steps loaded"
        ui.notify(f"Loaded {len(steps)} steps from traffic", type="info")

    return {"open_entries": open_entries}
