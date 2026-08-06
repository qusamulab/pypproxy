from __future__ import annotations

from nicegui import ui

from pypproxy.store.models import Filter
from pypproxy.store.store import Store


def build_openapi_tab(store: Store) -> None:
    with ui.column().classes("w-full h-full overflow-auto q-pa-md"):
        ui.label("OpenAPI Generator").classes("text-subtitle2 q-mb-xs")
        ui.label("Generate an OpenAPI 3.0 spec from captured traffic.").classes(
            "text-caption text-grey q-mb-md"
        )

        with ui.row().classes("items-center gap-4 q-mb-sm"):
            title_input = (
                ui.input(label="API Title", placeholder="auto-detect from hostname")
                .props("dense outlined dark")
                .classes("w-64")
            )
            version_input = (
                ui.input(label="Version", value="1.0.0")
                .props("dense outlined dark")
                .classes("w-28")
            )
            fmt_select = (
                ui.select(["YAML", "JSON"], value="YAML", label="Format")
                .props("dense outlined dark")
                .classes("w-24")
            )
            host_filter = (
                ui.input(label="Filter host (optional)")
                .props("dense outlined dark")
                .classes("w-48")
            )
            gen_btn = ui.button("Generate", icon="description").props("color=primary")

        summary_label = ui.label("").classes("text-caption text-grey q-mb-xs")
        spec_area = (
            ui.textarea()
            .props("outlined dense rows=30 readonly")
            .classes("w-full font-mono text-xs")
        )

        with ui.row().classes("gap-2"):
            copy_btn = ui.button("Copy", icon="content_copy").props("flat size=sm")
            copy_btn.on(
                "click",
                lambda: (
                    ui.run_javascript(f"navigator.clipboard.writeText({spec_area.value!r})")
                    or ui.notify("Copied!", type="positive")
                ),
            )

        def _generate() -> None:
            from pypproxy.reporting.openapi import generate, to_json, to_yaml

            f = Filter(host=host_filter.value.strip()) if host_filter.value.strip() else Filter()
            entries, total = store.list(f, 0, 0)
            if not entries:
                ui.notify("No entries to generate from", type="warning")
                return
            spec = generate(
                entries,
                title=title_input.value.strip() or "",
                version=version_input.value.strip() or "1.0.0",
            )
            if fmt_select.value == "YAML":
                spec_area.value = to_yaml(spec)
            else:
                spec_area.value = to_json(spec)
            path_count = len(spec.get("paths", {}))
            summary_label.text = f"Generated from {total} entries — {path_count} paths"
            ui.notify(f"Generated: {path_count} paths", type="positive")

        gen_btn.on("click", _generate)
