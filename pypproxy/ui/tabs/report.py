from __future__ import annotations

from nicegui import ui

from pypproxy.store.models import Filter
from pypproxy.store.store import Store


def build_report_tab(store: Store) -> None:
    with ui.column().classes("w-full h-full overflow-auto q-pa-md"):
        ui.label("Report Generator").classes("text-subtitle2 q-mb-xs")
        ui.label("Export captured traffic and findings as HTML or Markdown.").classes(
            "text-caption text-grey q-mb-md"
        )

        with ui.row().classes("gap-4 items-end q-mb-md flex-wrap"):
            title_input = (
                ui.input(label="Report title", value="pypproxy Report")
                .props("dense outlined dark")
                .classes("w-64")
            )
            fmt_select = (
                ui.select(["HTML", "Markdown"], value="HTML", label="Format")
                .props("dense outlined dark")
                .classes("w-28")
            )
            host_filter = (
                ui.input(label="Filter host (optional)")
                .props("dense outlined dark")
                .classes("w-48")
            )
            gen_btn = ui.button("Generate", icon="description").props("color=primary")

        summary_label = ui.label("").classes("text-caption text-grey q-mb-xs")
        report_area = (
            ui.textarea()
            .props("outlined dense rows=28 readonly")
            .classes("w-full font-mono text-xs")
        )

        with ui.row().classes("gap-2"):
            ui.button(
                "Copy",
                icon="content_copy",
                on_click=lambda: (
                    ui.run_javascript(f"navigator.clipboard.writeText({report_area.value!r})"),
                    ui.notify("Copied!", type="positive"),
                ),
            ).props("flat size=sm")
            ui.button(
                "Download",
                icon="download",
                on_click=lambda: ui.download(
                    report_area.value.encode(),
                    f"report.{'html' if fmt_select.value == 'HTML' else 'md'}",
                ),
            ).props("flat size=sm")

        def _generate() -> None:
            from pypproxy.reporting.report import generate_html, generate_markdown

            f = Filter(host=host_filter.value.strip()) if host_filter.value.strip() else Filter()
            entries, total = store.list(f, 0, 0)
            if not entries:
                ui.notify("No entries", type="warning")
                return
            title = title_input.value or "pypproxy Report"
            if fmt_select.value == "HTML":
                report_area.value = generate_html(entries, title)
            else:
                report_area.value = generate_markdown(entries, title)
            summary_label.text = f"Generated from {total} entries"
            ui.notify(f"Report ready ({total} requests)", type="positive")

        gen_btn.on("click", _generate)
