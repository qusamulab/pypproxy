from __future__ import annotations

from nicegui import ui

from pypproxy.store.models import Entry
from pypproxy.store.store import Store
from pypproxy.ui.components import entry_label as make_entry_label
from pypproxy.ui.components import set_entry_label


def build_codegen_tab(store: Store) -> dict:
    state: dict = {"entry": None}

    with ui.column().classes("w-full h-full overflow-auto q-pa-md"):
        entry_label = make_entry_label()

        with ui.row().classes("items-center gap-2 q-mb-sm"):
            lang_select = (
                ui.select(
                    ["curl", "Python requests", "JavaScript fetch", "HTTPie"],
                    value="curl",
                    label="Language",
                )
                .props("dense outlined dark")
                .classes("w-48")
            )
            gen_btn = ui.button("Generate", icon="code").props("color=primary size=sm")

        code_area = (
            ui.textarea()
            .props("outlined dense rows=20 readonly")
            .classes("w-full font-mono text-xs")
        )

        with ui.row().classes("gap-2"):
            copy_btn = ui.button("Copy", icon="content_copy").props("flat size=sm")
            copy_btn.on(
                "click",
                lambda: (
                    ui.run_javascript(f"navigator.clipboard.writeText({code_area.value!r})")
                    or ui.notify("Copied!", type="positive")
                ),
            )

        def _generate() -> None:
            entry = state.get("entry")
            if not entry:
                ui.notify("Select an entry first", type="warning")
                return
            from pypproxy.tools.codegen import to_curl, to_fetch, to_httpie, to_python_requests

            lang = lang_select.value
            if lang == "curl":
                code_area.value = to_curl(entry)
            elif lang == "Python requests":
                code_area.value = to_python_requests(entry)
            elif lang == "JavaScript fetch":
                code_area.value = to_fetch(entry)
            elif lang == "HTTPie":
                code_area.value = to_httpie(entry)

        gen_btn.on("click", _generate)

    def open_entry(entry: Entry) -> None:
        state["entry"] = entry
        set_entry_label(entry_label, entry)
        _generate()

    return {"open_entry": open_entry}
