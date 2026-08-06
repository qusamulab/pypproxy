from __future__ import annotations

from nicegui import ui

from pypproxy.store.models import Entry
from pypproxy.store.store import Store
from pypproxy.ui.components import entry_label as make_entry_label
from pypproxy.ui.components import set_entry_label


def build_advanced_security_tab(store: Store) -> dict:
    state: dict = {"entry": None}

    with ui.column().classes("w-full h-full overflow-auto q-pa-md"):
        entry_label = make_entry_label()

        with ui.tabs().props("dense dark") as tabs:
            cors_tab = ui.tab("CORS", icon="share")
            redirect_tab = ui.tab("Open Redirect", icon="open_in_new")
            ssrf_tab = ui.tab("SSRF", icon="cloud")
            ratelimit_tab = ui.tab("Rate Limit", icon="speed")
            cookie_tab = ui.tab("Cookie Audit", icon="cookie")

        with ui.tab_panels(tabs, value=cors_tab).classes("w-full"):
            # --- CORS ---
            with ui.tab_panel(cors_tab):
                ui.label("Test CORS by injecting a foreign Origin header.").classes(
                    "text-caption text-grey q-mb-sm"
                )
                cors_btn = ui.button("Check CORS", icon="play_arrow").props("color=primary size=sm")
                cors_result = ui.label("").classes("q-mt-sm")
                cors_detail = ui.element("pre").classes("paxy-body-pre q-mt-xs")

                async def _check_cors() -> None:
                    entry = state.get("entry")
                    if not entry:
                        ui.notify("Select an entry first", type="warning")
                        return
                    from pypproxy.security.advanced import check_cors

                    cors_btn.props("loading")
                    try:
                        r = await check_cors(entry)
                        cors_result.text = (
                            f"{'⚠ VULNERABLE' if r.vulnerable else '✓ Safe'}: {r.detail}"
                        )
                        cors_result.classes(remove="text-positive text-negative")
                        cors_result.classes("text-negative" if r.vulnerable else "text-positive")
                        cors_detail.text = r.evidence
                        if r.vulnerable:
                            ui.notify("CORS vulnerability found!", type="warning")
                        else:
                            ui.notify("No CORS vulnerability", type="positive")
                    finally:
                        cors_btn.props(remove="loading")

                cors_btn.on("click", _check_cors)

            # --- Open Redirect ---
            with ui.tab_panel(redirect_tab):
                ui.label("Inject attacker URLs into redirect parameters.").classes(
                    "text-caption text-grey q-mb-sm"
                )
                redir_btn = ui.button("Check Redirects", icon="play_arrow").props(
                    "color=primary size=sm"
                )
                redir_table = (
                    ui.table(
                        columns=[
                            {"name": "check", "label": "Check", "field": "check", "align": "left"},
                            {
                                "name": "vulnerable",
                                "label": "Vulnerable",
                                "field": "vulnerable",
                                "align": "center",
                            },
                            {
                                "name": "detail",
                                "label": "Detail",
                                "field": "detail",
                                "align": "left",
                            },
                        ],
                        rows=[],
                        row_key="detail",
                    )
                    .classes("w-full")
                    .props("dense flat dark")
                )
                redir_table.add_slot(
                    "body-cell-vulnerable",
                    """
                    <q-td :props="props">
                      <q-badge :color="props.value ? 'negative' : 'positive'" :label="props.value ? '⚠ YES' : '✓ No'" />
                    </q-td>
                """,
                )

                async def _check_redirect() -> None:
                    entry = state.get("entry")
                    if not entry:
                        ui.notify("Select an entry first", type="warning")
                        return
                    from pypproxy.security.advanced import check_open_redirect

                    redir_btn.props("loading")
                    try:
                        results = await check_open_redirect(entry)
                        redir_table.rows = [r.to_dict() for r in results]
                        redir_table.update()
                        vulns = sum(1 for r in results if r.vulnerable)
                        if vulns:
                            ui.notify(f"⚠ {vulns} redirect vulnerability found!", type="warning")
                        else:
                            ui.notify("No redirect vulnerabilities", type="positive")
                    finally:
                        redir_btn.props(remove="loading")

                redir_btn.on("click", _check_redirect)

            # --- SSRF ---
            with ui.tab_panel(ssrf_tab):
                ui.label("Inject internal/cloud metadata URLs into parameters.").classes(
                    "text-caption text-grey q-mb-sm"
                )
                ssrf_btn = ui.button("Check SSRF", icon="play_arrow").props("color=primary size=sm")
                ssrf_table = (
                    ui.table(
                        columns=[
                            {
                                "name": "vulnerable",
                                "label": "⚠",
                                "field": "vulnerable",
                                "align": "center",
                            },
                            {
                                "name": "detail",
                                "label": "Detail",
                                "field": "detail",
                                "align": "left",
                            },
                            {
                                "name": "evidence",
                                "label": "Evidence",
                                "field": "evidence",
                                "align": "left",
                            },
                        ],
                        rows=[],
                        row_key="detail",
                    )
                    .classes("w-full")
                    .props("dense flat dark")
                )

                async def _check_ssrf() -> None:
                    entry = state.get("entry")
                    if not entry:
                        ui.notify("Select an entry first", type="warning")
                        return
                    from pypproxy.security.advanced import check_ssrf

                    ssrf_btn.props("loading")
                    try:
                        results = await check_ssrf(entry)
                        ssrf_table.rows = [r.to_dict() for r in results]
                        ssrf_table.update()
                        vulns = sum(1 for r in results if r.vulnerable)
                        if vulns:
                            ui.notify("⚠ SSRF indicator found!", type="warning")
                        else:
                            ui.notify("No SSRF indicators", type="positive")
                    finally:
                        ssrf_btn.props(remove="loading")

                ssrf_btn.on("click", _check_ssrf)

            # --- Rate Limit ---
            with ui.tab_panel(ratelimit_tab):
                ui.label("Send N rapid requests to check rate limiting.").classes(
                    "text-caption text-grey q-mb-sm"
                )
                with ui.row().classes("items-center gap-2"):
                    count_input = (
                        ui.number(label="Request count", value=20, min=5, max=100)
                        .props("dense outlined dark")
                        .classes("w-28")
                    )
                    rl_btn = ui.button("Test Rate Limit", icon="play_arrow").props(
                        "color=primary size=sm"
                    )
                rl_result = ui.label("").classes("q-mt-sm text-subtitle2")

                async def _check_rl() -> None:
                    entry = state.get("entry")
                    if not entry:
                        ui.notify("Select an entry first", type="warning")
                        return
                    from pypproxy.security.advanced import check_rate_limit

                    rl_btn.props("loading")
                    try:
                        r = await check_rate_limit(entry, count=int(count_input.value or 20))
                        rl_result.text = (
                            f"{'⚠ No rate limit' if r.vulnerable else '✓ Rate limited'}: {r.detail}"
                        )
                        rl_result.classes(remove="text-positive text-negative text-warning")
                        rl_result.classes("text-warning" if r.vulnerable else "text-positive")
                    finally:
                        rl_btn.props(remove="loading")

                rl_btn.on("click", _check_rl)

            # --- Cookie Audit ---
            with ui.tab_panel(cookie_tab):
                ui.label("Audit Set-Cookie headers across all captured responses.").classes(
                    "text-caption text-grey q-mb-sm"
                )
                audit_btn = ui.button("Audit Cookies", icon="cookie").props("color=primary size=sm")
                cookie_table = (
                    ui.table(
                        columns=[
                            {"name": "safe", "label": "OK", "field": "safe", "align": "center"},
                            {"name": "host", "label": "Host", "field": "host", "align": "left"},
                            {"name": "name", "label": "Cookie", "field": "name", "align": "left"},
                            {
                                "name": "issues",
                                "label": "Issues",
                                "field": "issues",
                                "align": "left",
                            },
                        ],
                        rows=[],
                        row_key="name",
                    )
                    .classes("w-full")
                    .props("dense flat dark")
                )
                cookie_table.add_slot(
                    "body-cell-safe",
                    """
                    <q-td :props="props">
                      <q-badge :color="props.value ? 'positive' : 'negative'" :label="props.value ? '✓' : '✗'" />
                    </q-td>
                """,
                )
                summary_label = ui.label("").classes("text-caption text-grey q-mt-xs")

                def _audit() -> None:
                    from pypproxy.security.advanced import audit_cookies
                    from pypproxy.store.models import Filter

                    entries, _ = store.list(Filter(), 0, 0)
                    results = audit_cookies(entries)
                    rows = [
                        {
                            "safe": r["safe"],
                            "host": r["host"],
                            "name": r["name"],
                            "issues": ", ".join(r["issues"]) if r["issues"] else "OK",
                        }
                        for r in results
                    ]
                    cookie_table.rows = rows
                    cookie_table.update()
                    issues = sum(1 for r in results if not r["safe"])
                    summary_label.text = f"{len(results)} cookies audited — {issues} with issues"
                    if issues:
                        ui.notify(f"{issues} cookie security issues found", type="warning")
                    else:
                        ui.notify("All cookies look secure", type="positive")

                audit_btn.on("click", _audit)

    def open_entry(entry: Entry) -> None:
        state["entry"] = entry
        set_entry_label(entry_label, entry)

    return {"open_entry": open_entry}
