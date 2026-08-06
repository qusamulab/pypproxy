from __future__ import annotations

from nicegui import ui

from pypproxy.security.headers import check_security_headers
from pypproxy.security.jwt import extract_jwt_from_headers
from pypproxy.security.jwt import run_checks as jwt_run_checks
from pypproxy.security.randomness import analyse_token
from pypproxy.store.models import Entry
from pypproxy.store.store import Store
from pypproxy.ui.components import entry_label as make_entry_label
from pypproxy.ui.components import set_entry_label, tab_container


def build_security_tab(store: Store) -> dict:
    """Build the security tools tab. Returns state with open_entry method."""
    state: dict = {"entry": None}

    with tab_container():
        entry_label = make_entry_label()

        with ui.tabs().props("dense dark") as sec_tabs:
            jwt_tab = ui.tab("JWT Checker", icon="key")
            header_tab = ui.tab("Security Headers", icon="shield")
            randomness_tab = ui.tab("Token Randomness", icon="casino")
            overflow_tab = ui.tab("Int Overflow", icon="numbers")

        with ui.tab_panels(sec_tabs, value=jwt_tab).classes("w-full"):
            # --- JWT Checker ---
            with ui.tab_panel(jwt_tab):
                ui.label("JWT Vulnerability Checker").classes("text-subtitle2 q-mb-xs")
                ui.label(
                    "Automatically extracts the JWT from the Authorization header and tests common attack vectors."
                ).classes("text-caption text-grey q-mb-md")

                token_input = (
                    ui.input(label="JWT Token (auto-filled from entry)")
                    .props("outlined dense dark")
                    .classes("w-full font-mono text-xs q-mb-sm")
                )
                jwt_run_btn = ui.button("Run JWT Checks", icon="play_arrow").props("color=primary")
                jwt_results_label = ui.label("").classes("text-caption text-grey q-my-xs")
                jwt_table = (
                    ui.table(
                        columns=[
                            {
                                "name": "vector",
                                "label": "Vector",
                                "field": "vector",
                                "align": "left",
                            },
                            {
                                "name": "status",
                                "label": "Status",
                                "field": "status_code",
                                "align": "center",
                            },
                            {"name": "ms", "label": "ms", "field": "duration_ms", "align": "right"},
                            {
                                "name": "suspicious",
                                "label": "Suspicious",
                                "field": "suspicious",
                                "align": "center",
                            },
                            {
                                "name": "desc",
                                "label": "Description",
                                "field": "description",
                                "align": "left",
                            },
                        ],
                        rows=[],
                        row_key="vector",
                    )
                    .classes("w-full")
                    .props("dense flat dark")
                )
                jwt_table.add_slot(
                    "body-cell-suspicious",
                    """
                    <q-td :props="props">
                      <q-badge v-if="props.value" color="negative" label="⚠ YES" />
                      <q-badge v-else color="grey" label="no" />
                    </q-td>
                """,
                )

                async def _run_jwt() -> None:
                    entry = state.get("entry")
                    token = token_input.value.strip()
                    if not token or not entry:
                        ui.notify("No token or entry", type="warning")
                        return
                    jwt_run_btn.props("loading")
                    try:
                        results = await jwt_run_checks(
                            token=token,
                            entry_id=entry.id,
                            method=entry.method,
                            scheme=entry.scheme,
                            host=entry.host,
                            path=entry.path,
                            query=entry.query,
                            headers=entry.req_headers,
                            body=entry.req_body,
                        )
                        jwt_table.rows = [r.to_dict() for r in results]
                        jwt_table.update()
                        suspicious = sum(1 for r in results if r.suspicious)
                        jwt_results_label.text = (
                            f"{len(results)} vectors tested — {suspicious} suspicious"
                        )
                        if suspicious:
                            ui.notify(f"⚠ {suspicious} suspicious responses!", type="warning")
                        else:
                            ui.notify("Done — no obvious vulnerabilities detected", type="positive")
                    finally:
                        jwt_run_btn.props(remove="loading")

                jwt_run_btn.on("click", _run_jwt)

            # --- Security Headers ---
            with ui.tab_panel(header_tab):
                ui.label("Security Header Checker").classes("text-subtitle2 q-mb-xs")
                ui.label(
                    "Checks the response headers of the selected entry for common security misconfigurations."
                ).classes("text-caption text-grey q-mb-md")

                hdr_run_btn = ui.button("Check Headers", icon="shield").props("color=primary")
                hdr_results_label = ui.label("").classes("text-caption text-grey q-my-xs")
                hdr_table = (
                    ui.table(
                        columns=[
                            {
                                "name": "header",
                                "label": "Header",
                                "field": "header",
                                "align": "left",
                            },
                            {
                                "name": "present",
                                "label": "Present",
                                "field": "present",
                                "align": "center",
                            },
                            {"name": "passed", "label": "OK", "field": "passed", "align": "center"},
                            {
                                "name": "severity",
                                "label": "Severity",
                                "field": "severity",
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
                        row_key="header",
                    )
                    .classes("w-full")
                    .props("dense flat dark")
                )
                hdr_table.add_slot(
                    "body-cell-passed",
                    """
                    <q-td :props="props">
                      <q-badge :color="props.value ? 'positive' : 'negative'" :label="props.value ? '✓' : '✗'" />
                    </q-td>
                """,
                )
                hdr_table.add_slot(
                    "body-cell-severity",
                    """
                    <q-td :props="props">
                      <q-badge :color="{'high':'negative','medium':'warning','low':'orange','info':'grey'}[props.value] || 'grey'"
                               :label="props.value" />
                    </q-td>
                """,
                )

                def _run_headers() -> None:
                    entry = state.get("entry")
                    if not entry or not entry.resp_headers:
                        ui.notify("No response headers in selected entry", type="warning")
                        return
                    results = check_security_headers(entry.resp_headers)
                    hdr_table.rows = [r.to_dict() for r in results]
                    hdr_table.update()
                    fails = sum(1 for r in results if not r.passed)
                    hdr_results_label.text = f"{len(results)} headers checked — {fails} issues"
                    if fails:
                        ui.notify(f"{fails} security header issues found", type="warning")
                    else:
                        ui.notify("All security headers look good", type="positive")

                hdr_run_btn.on("click", _run_headers)

            # --- Token Randomness ---
            with ui.tab_panel(randomness_tab):
                ui.label("Token Randomness Analyser").classes("text-subtitle2 q-mb-xs")
                ui.label(
                    "Statistical entropy tests on tokens extracted from the selected entry."
                ).classes("text-caption text-grey q-mb-md")

                rand_token_input = (
                    ui.input(label="Token (auto-filled from entry)")
                    .props("outlined dense dark")
                    .classes("w-full font-mono text-xs q-mb-sm")
                )
                rand_run_btn = ui.button("Analyse", icon="casino").props("color=primary")
                rand_table = (
                    ui.table(
                        columns=[
                            {
                                "name": "test",
                                "label": "Test",
                                "field": "test_name",
                                "align": "left",
                            },
                            {
                                "name": "passed",
                                "label": "Passed",
                                "field": "passed",
                                "align": "center",
                            },
                            {"name": "score", "label": "Score", "field": "score", "align": "right"},
                            {
                                "name": "detail",
                                "label": "Detail",
                                "field": "detail",
                                "align": "left",
                            },
                        ],
                        rows=[],
                        row_key="test_name",
                    )
                    .classes("w-full")
                    .props("dense flat dark")
                )
                rand_table.add_slot(
                    "body-cell-passed",
                    """
                    <q-td :props="props">
                      <q-badge :color="props.value ? 'positive' : 'negative'" :label="props.value ? '✓' : '✗'" />
                    </q-td>
                """,
                )

                def _run_randomness() -> None:
                    token = rand_token_input.value.strip()
                    if not token:
                        ui.notify("Enter a token", type="warning")
                        return
                    results = analyse_token(token)
                    rand_table.rows = [r.to_dict() for r in results]
                    rand_table.update()
                    fails = sum(1 for r in results if not r.passed)
                    if fails:
                        ui.notify(
                            f"{fails} randomness tests failed — token may be weak", type="warning"
                        )
                    else:
                        ui.notify("Token appears sufficiently random", type="positive")

                rand_run_btn.on("click", _run_randomness)

            # --- Int Overflow ---
            with ui.tab_panel(overflow_tab):
                ui.label("Integer Overflow / Boundary Tester").classes("text-subtitle2 q-mb-xs")
                ui.label(
                    "Finds integer parameters in the selected entry and tests boundary values."
                ).classes("text-caption text-grey q-mb-md")

                overflow_run_btn = ui.button("Run Tests", icon="numbers").props("color=primary")
                overflow_label = ui.label("").classes("text-caption text-grey q-my-xs")
                overflow_table = (
                    ui.table(
                        columns=[
                            {"name": "param", "label": "Param", "field": "param", "align": "left"},
                            {
                                "name": "label",
                                "label": "Payload",
                                "field": "label",
                                "align": "left",
                            },
                            {"name": "value", "label": "Value", "field": "value", "align": "right"},
                            {
                                "name": "status",
                                "label": "Status",
                                "field": "status_code",
                                "align": "center",
                            },
                            {"name": "ms", "label": "ms", "field": "duration_ms", "align": "right"},
                            {
                                "name": "suspicious",
                                "label": "⚠",
                                "field": "suspicious",
                                "align": "center",
                            },
                        ],
                        rows=[],
                        row_key="label",
                    )
                    .classes("w-full")
                    .props("dense flat dark")
                )
                overflow_table.add_slot(
                    "body-cell-suspicious",
                    """
                    <q-td :props="props">
                      <q-badge v-if="props.value" color="negative" label="!" />
                    </q-td>
                """,
                )

                async def _run_overflow() -> None:
                    from pypproxy.security.int_overflow import run_checks as overflow_run_checks

                    entry = state.get("entry")
                    if not entry:
                        ui.notify("No entry selected", type="warning")
                        return
                    overflow_run_btn.props("loading")
                    try:
                        results = await overflow_run_checks(entry)
                        if not results:
                            ui.notify("No integer parameters found in this entry", type="info")
                            return
                        overflow_table.rows = [r.to_dict() for r in results]
                        overflow_table.update()
                        suspicious = sum(1 for r in results if r.suspicious)
                        overflow_label.text = (
                            f"{len(results)} tests — {suspicious} suspicious (5xx responses)"
                        )
                        if suspicious:
                            ui.notify(f"⚠ {suspicious} server errors triggered!", type="warning")
                        else:
                            ui.notify("Done", type="positive")
                    finally:
                        overflow_run_btn.props(remove="loading")

                overflow_run_btn.on("click", _run_overflow)

    def open_entry(entry: Entry) -> None:
        state["entry"] = entry
        set_entry_label(entry_label, entry)
        # Auto-fill JWT token
        token = extract_jwt_from_headers(entry.req_headers)
        if token:
            token_input.value = token
            rand_token_input.value = token

    return {"open_entry": open_entry}
