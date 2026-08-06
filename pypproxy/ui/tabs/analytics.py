from __future__ import annotations

from nicegui import ui

from pypproxy.store.models import Filter
from pypproxy.store.store import Store


def build_analytics_tab(store: Store) -> None:
    with ui.column().classes("w-full h-full overflow-auto q-pa-md"):
        ui.label("Traffic Analytics").classes("text-subtitle2 q-mb-xs")

        with ui.row().classes("items-center gap-2 q-mb-sm"):
            host_filter = (
                ui.input(label="Filter host (optional)")
                .props("dense outlined dark")
                .classes("w-48")
            )
            refresh_btn = ui.button("Analyse", icon="analytics").props("color=primary size=sm")

        stats_container = ui.column().classes("w-full")

        def _analyse() -> None:
            from pypproxy.reporting.analytics import compute

            f = Filter(host=host_filter.value.strip()) if host_filter.value.strip() else Filter()
            summary = compute(store, f)
            stats_container.clear()
            with stats_container:
                if summary.total == 0:
                    ui.label("No traffic captured yet").classes("text-grey")
                    return

                # Overview cards
                with ui.row().classes("gap-4 q-mb-md"):
                    _stat_card("Total Requests", str(summary.total), "list")
                    _stat_card("Avg Latency", f"{summary.avg_duration_ms:.0f} ms", "timer")
                    _stat_card("P95 Latency", f"{summary.p95_duration_ms} ms", "speed")
                    _stat_card("P99 Latency", f"{summary.p99_duration_ms} ms", "speed")

                # Status distribution
                with ui.row().classes("gap-4 q-mb-md w-full"):
                    with ui.card().classes("flex-1"):
                        ui.label("Status Distribution").classes("text-subtitle2 q-mb-xs")
                        for bucket, count in sorted(summary.status_distribution.items()):
                            color = {
                                "2xx": "positive",
                                "3xx": "info",
                                "4xx": "warning",
                                "5xx": "negative",
                            }.get(bucket, "grey")
                            with ui.row().classes("items-center gap-2"):
                                ui.badge(bucket, color=color)
                                pct = count / summary.total * 100
                                ui.linear_progress(pct / 100).classes("flex-1")
                                ui.label(f"{count} ({pct:.1f}%)").classes("text-caption")

                    with ui.card().classes("flex-1"):
                        ui.label("Method Distribution").classes("text-subtitle2 q-mb-xs")
                        for method, count in sorted(
                            summary.method_distribution.items(), key=lambda x: -x[1]
                        ):
                            color = {
                                "GET": "blue",
                                "POST": "green",
                                "PUT": "orange",
                                "DELETE": "red",
                            }.get(method, "grey")
                            with ui.row().classes("items-center gap-2"):
                                ui.badge(method, color=color)
                                pct = count / summary.total * 100
                                ui.linear_progress(pct / 100).classes("flex-1")
                                ui.label(f"{count} ({pct:.1f}%)").classes("text-caption")

                # Top hosts
                ui.label("Top Hosts").classes("text-subtitle2 q-mt-md q-mb-xs")
                (
                    ui.table(
                        columns=[
                            {"name": "host", "label": "Host", "field": "host", "align": "left"},
                            {
                                "name": "count",
                                "label": "Requests",
                                "field": "count",
                                "align": "right",
                            },
                            {
                                "name": "avg",
                                "label": "Avg ms",
                                "field": "avg_duration_ms",
                                "align": "right",
                            },
                            {
                                "name": "max",
                                "label": "Max ms",
                                "field": "max_duration_ms",
                                "align": "right",
                            },
                            {
                                "name": "err",
                                "label": "Error rate",
                                "field": "error_rate",
                                "align": "right",
                            },
                        ],
                        rows=[
                            {
                                "host": h.host,
                                "count": h.count,
                                "avg_duration_ms": f"{h.avg_duration_ms:.0f}",
                                "max_duration_ms": h.max_duration_ms,
                                "error_rate": f"{h.error_rate * 100:.1f}%",
                            }
                            for h in summary.hosts
                        ],
                        row_key="host",
                    )
                    .classes("w-full")
                    .props("dense flat dark")
                )

                # Top endpoints
                ui.label("Top Endpoints").classes("text-subtitle2 q-mt-md q-mb-xs")
                ui.table(
                    columns=[
                        {"name": "method", "label": "Method", "field": "method", "align": "center"},
                        {"name": "path", "label": "Path", "field": "path", "align": "left"},
                        {"name": "count", "label": "Count", "field": "count", "align": "right"},
                        {
                            "name": "avg",
                            "label": "Avg ms",
                            "field": "avg_duration_ms",
                            "align": "right",
                        },
                        {
                            "name": "err",
                            "label": "Error %",
                            "field": "error_rate",
                            "align": "right",
                        },
                    ],
                    rows=[
                        {
                            "method": e.method,
                            "path": e.path,
                            "count": e.count,
                            "avg_duration_ms": f"{e.avg_duration_ms:.0f}",
                            "error_rate": f"{e.error_rate * 100:.1f}%",
                        }
                        for e in summary.top_endpoints
                    ],
                    row_key="path",
                ).classes("w-full").props("dense flat dark")

                # Server errors
                if summary.errors:
                    ui.label("Server Errors (5xx)").classes("text-subtitle2 q-mt-md q-mb-xs")
                    for err in summary.errors[:5]:
                        with ui.row().classes("items-center gap-2"):
                            ui.badge(str(err["status"]), color="negative")
                            ui.label(f"{err['method']} {err['host']}{err['path']}").classes(
                                "text-caption font-mono"
                            )

        refresh_btn.on("click", _analyse)


def _stat_card(title: str, value: str, icon: str) -> None:
    with ui.card().classes("q-pa-md"):
        with ui.row().classes("items-center gap-2"):
            ui.icon(icon).classes("text-primary")
            ui.label(title).classes("text-caption text-grey")
        ui.label(value).classes("text-h6 text-weight-bold")
