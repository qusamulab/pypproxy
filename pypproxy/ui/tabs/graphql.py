from __future__ import annotations

import json

from nicegui import ui

from pypproxy.core.http import REPLAY_DROP_HEADERS, flatten_headers
from pypproxy.core.http import client as http_client
from pypproxy.store.models import Entry
from pypproxy.store.store import Store
from pypproxy.ui.components import entry_label as make_entry_label
from pypproxy.ui.components import set_entry_label


def build_graphql_tab(store: Store) -> dict:
    """Build the GraphQL tab. Returns state with open_entry method."""
    state: dict = {"entry": None, "schema": None}

    with ui.column().classes("w-full h-full overflow-auto q-pa-md"):
        # --- Introspection section ---
        with ui.expansion("Schema Introspection", icon="schema", value=True).classes(
            "w-full q-mb-md"
        ):
            ui.label("Fetch the GraphQL schema from an endpoint using introspection.").classes(
                "text-caption text-grey q-mb-sm"
            )

            with ui.row().classes("gap-2 items-center w-full"):
                url_input = (
                    ui.input(
                        label="GraphQL endpoint URL", placeholder="https://api.example.com/graphql"
                    )
                    .props("dense outlined dark")
                    .classes("flex-1")
                )
                introspect_btn = ui.button("Introspect", icon="search").props(
                    "color=primary size=sm"
                )

            schema_status = ui.label("").classes("text-caption text-grey q-mt-xs")

            schema_tree = (
                ui.tree(
                    [],
                    label_key="label",
                    children_key="children",
                )
                .props("dark dense")
                .classes("w-full q-mt-sm")
            )

            async def _introspect() -> None:
                url = url_input.value.strip()
                if not url:
                    ui.notify("Enter a URL", type="warning")
                    return
                introspect_btn.props("loading")
                try:
                    from pypproxy.graphql.introspection import fetch_schema

                    req_headers: dict[str, str] = {}
                    entry = state.get("entry")
                    if entry:
                        req_headers = flatten_headers(entry.req_headers, drop=REPLAY_DROP_HEADERS)

                    schema = await fetch_schema(url, req_headers)
                    if schema is None:
                        ui.notify("Introspection failed or not supported", type="negative")
                        return

                    state["schema"] = schema
                    schema_status.text = (
                        f"Schema loaded: {len(schema.types)} types, "
                        f"Query: {schema.query_type}, Mutation: {schema.mutation_type}"
                    )

                    # Build tree
                    nodes = []
                    for t in schema.types:
                        if t.name.startswith("__") or not t.fields:
                            continue
                        children = [
                            {"id": f"{t.name}.{f.name}", "label": f"{f.name}: {f.type_name}"}
                            for f in t.fields
                        ]
                        nodes.append(
                            {
                                "id": t.name,
                                "label": f"{t.name} ({t.kind})",
                                "children": children,
                            }
                        )
                    schema_tree.nodes = nodes
                    schema_tree.update()
                    ui.notify(f"Schema loaded: {len(schema.types)} types", type="positive")
                finally:
                    introspect_btn.props(remove="loading")

            introspect_btn.on("click", _introspect)

        # --- Query editor ---
        with ui.expansion("Query Editor", icon="code", value=True).classes("w-full q-mb-md"):
            entry_label = make_entry_label()

            with ui.row().classes("gap-2 items-center q-mb-xs"):
                op_type_badge = ui.badge("", color="grey").props("rounded")
                op_name_label = ui.label("").classes("text-caption")

            query_input = (
                ui.textarea(placeholder="query { ... }\n\nOr paste a GraphQL query here")
                .props("outlined dense rows=8")
                .classes("w-full font-mono text-xs")
            )

            ui.label("Variables (JSON):").classes("text-caption q-mt-xs")
            vars_input = (
                ui.textarea(placeholder='{"id": "123"}')
                .props("outlined dense rows=3")
                .classes("w-full font-mono text-xs")
            )

            run_btn = ui.button("Run Query", icon="play_arrow").props("color=primary")
            result_label = ui.label("").classes("text-caption text-grey q-mt-xs")
            result_area = (
                ui.textarea()
                .props("outlined dense rows=10 readonly")
                .classes("w-full font-mono text-xs q-mt-xs")
            )

            async def _run_query() -> None:
                entry = state.get("entry")
                if not entry:
                    ui.notify(
                        "No entry selected — right-click a GraphQL request in Traffic",
                        type="warning",
                    )
                    return

                url = entry.base_url
                req_headers = flatten_headers(entry.req_headers, drop=REPLAY_DROP_HEADERS)

                query = query_input.value.strip()
                if not query:
                    ui.notify("Enter a query", type="warning")
                    return

                variables: dict = {}
                if vars_input.value.strip():
                    try:
                        variables = json.loads(vars_input.value)
                    except Exception:
                        ui.notify("Variables must be valid JSON", type="warning")
                        return

                run_btn.props("loading")
                try:
                    async with http_client(30) as client:
                        resp = await client.post(
                            url,
                            json={"query": query, "variables": variables},
                            headers=req_headers,
                        )
                    try:
                        body = json.dumps(resp.json(), indent=2, ensure_ascii=False)
                    except Exception:
                        body = resp.text
                    result_label.text = f"Status: {resp.status_code}"
                    result_area.value = body
                    ui.notify(
                        f"{resp.status_code}",
                        type="positive" if resp.status_code < 400 else "warning",
                    )
                except Exception as e:
                    result_area.value = str(e)
                    ui.notify(str(e), type="negative")
                finally:
                    run_btn.props(remove="loading")

            run_btn.on("click", _run_query)

        # --- Operation analysis ---
        with ui.expansion("Operation Analysis", icon="analytics").classes("w-full"):
            ui.label("Analyse a captured GraphQL request.").classes(
                "text-caption text-grey q-mb-sm"
            )

            analyse_btn = ui.button("Analyse selected entry", icon="analytics").props(
                "color=secondary size=sm"
            )
            analysis_area = (
                ui.textarea()
                .props("outlined dense rows=12 readonly")
                .classes("w-full font-mono text-xs q-mt-xs")
            )

            def _analyse() -> None:
                entry = state.get("entry")
                if not entry or "graphql" not in entry.tags:
                    ui.notify("Select a GraphQL entry from Traffic", type="warning")
                    return

                from pypproxy.graphql.detector import (
                    extract_field_names,
                    extract_operation_name,
                    extract_operation_type,
                    parse_operation,
                )

                op = parse_operation(entry.req_body)
                query = op.get("query", "")
                lines = [
                    f"Operation type : {extract_operation_type(query)}",
                    f"Operation name : {extract_operation_name(query) or '(anonymous)'}",
                    f"Fields detected: {', '.join(extract_field_names(query)) or '(none)'}",
                    "",
                    "--- Variables ---",
                    json.dumps(op.get("variables", {}), indent=2),
                    "",
                    "--- Query ---",
                    query,
                ]
                analysis_area.value = "\n".join(lines)

                # Try to find schema for this host
                schema = state.get("schema")
                if schema:
                    root = schema.root_fields()
                    lines.append("")
                    lines.append(f"--- Schema root fields ({schema.query_type}) ---")
                    lines.extend(f"  {f.name}: {f.type_name}" for f in root)
                    analysis_area.value = "\n".join(lines)

            analyse_btn.on("click", _analyse)

    def open_entry(entry: Entry) -> None:
        state["entry"] = entry
        set_entry_label(entry_label, entry)
        op_type_badge.text = entry.graphql_op_type or ""
        op_name_label.text = entry.graphql_operation or ""
        if entry.graphql_op_type == "mutation":
            op_type_badge.props("color=warning")
        elif entry.graphql_op_type == "subscription":
            op_type_badge.props("color=info")
        else:
            op_type_badge.props("color=positive")

        # Auto-fill query and variables from entry
        from pypproxy.graphql.detector import parse_operation

        op = parse_operation(entry.req_body)
        query_input.value = op.get("query", "")
        vars_input.value = (
            json.dumps(op.get("variables", {}), indent=2) if op.get("variables") else ""
        )

        # Auto-set introspection URL
        url_input.value = entry.base_url

    return {"open_entry": open_entry}
