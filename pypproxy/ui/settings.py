from __future__ import annotations

from nicegui import ui

from pypproxy.cert.client_cert import ClientCert, ClientCertManager
from pypproxy.core.config import Config
from pypproxy.dns import DNSServer
from pypproxy.rules import RuleManager


def build_settings_page(
    cfg: Config,
    rules: RuleManager,
    cert_mgr: ClientCertManager,
    dns_server: DNSServer | None = None,
    scope_mgr=None,
) -> None:
    @ui.page("/settings")
    async def settings() -> None:
        ui.dark_mode().enable()

        with ui.header().classes("items-center q-px-md gap-4").style("background:#1a1a2e"):
            ui.button(icon="arrow_back", on_click=lambda: ui.navigate.to("/")).props("flat dark")
            ui.label("Settings").classes("text-h6 text-weight-bold")

        with ui.tabs().props("dense dark").classes("bg-dark") as tabs:
            rules_tab = ui.tab("Rules", icon="rule")
            scope_tab = ui.tab("Scope", icon="target")
            passthrough_tab = ui.tab("SSL Passthrough", icon="lock_open")
            dns_tab = ui.tab("DNS Overwrite", icon="dns")
            ports_tab = ui.tab("Listen Ports", icon="router")
            certs_tab = ui.tab("Client Certs", icon="badge")

        with (
            ui.tab_panels(tabs, value=rules_tab)
            .classes("w-full")
            .style("height:calc(100vh - 96px)")
        ):
            # --- Rules tab ---
            with ui.tab_panel(rules_tab).classes("q-pa-md"):
                _build_rules_panel(rules)

            # --- Scope tab ---
            with ui.tab_panel(scope_tab).classes("q-pa-md"):
                _build_scope_panel(scope_mgr)

            # --- SSL Passthrough tab ---
            with ui.tab_panel(passthrough_tab).classes("q-pa-md"):
                _build_passthrough_panel(cfg)

            # --- DNS Overwrite tab ---
            with ui.tab_panel(dns_tab).classes("q-pa-md"):
                _build_dns_panel(cfg, dns_server)

            # --- Listen Ports tab ---
            with ui.tab_panel(ports_tab).classes("q-pa-md"):
                _build_ports_panel(cfg)

            # --- Client Certs tab ---
            with ui.tab_panel(certs_tab).classes("q-pa-md"):
                _build_certs_panel(cert_mgr)


def _build_scope_panel(scope_mgr) -> None:  # noqa: ANN001
    from pypproxy.store.scope import ScopeRule

    ui.label("Scope").classes("text-subtitle1 q-mb-sm")
    ui.label(
        "When enabled, only in-scope hosts are captured. All others are proxied without recording."
    ).classes("text-caption text-grey q-mb-md")

    if scope_mgr is None:
        ui.label("Scope manager not initialized.").classes("text-grey")
        return

    enabled_toggle = ui.switch("Enable scope filtering", value=scope_mgr.enabled).props(
        "dense dark color=primary"
    )
    enabled_toggle.on("update:model-value", lambda e: scope_mgr.set_enabled(e.args))

    ui.separator().classes("q-my-md")
    container = ui.column().classes("w-full")

    def _refresh() -> None:
        container.clear()
        with container:
            for rule in scope_mgr.list():
                with ui.row().classes("items-center gap-2"):
                    ui.badge(rule.mode, color="grey-7")
                    ui.label(rule.pattern).classes("flex-1 font-mono")
                    ui.button(
                        icon="remove",
                        on_click=lambda p=rule.pattern: (scope_mgr.remove(p), _refresh()),
                    ).props("flat dense color=negative size=sm")

    _refresh()

    with ui.row().classes("gap-2 items-center q-mt-sm"):
        pattern_input = (
            ui.input(label="Pattern (e.g. *.example.com)")
            .props("dense outlined dark")
            .classes("w-64")
        )
        mode_select = (
            ui.select(["glob", "regex"], value="glob", label="Mode")
            .props("dense outlined dark")
            .classes("w-24")
        )

        def _add() -> None:
            p = pattern_input.value.strip()
            if p:
                scope_mgr.add(ScopeRule(pattern=p, mode=mode_select.value))
                pattern_input.value = ""
                _refresh()

        ui.button("Add", icon="add", on_click=_add).props("color=primary size=sm")


def _build_rules_panel(rules: RuleManager) -> None:
    ui.label("Intercept Rules").classes("text-subtitle1 q-mb-sm")
    ui.label("Rules are evaluated in priority order. Higher number = higher priority.").classes(
        "text-caption text-grey q-mb-md"
    )

    rules_container = ui.column().classes("w-full")

    def _refresh() -> None:
        rules_container.clear()
        with rules_container:
            for rule in rules.list():
                with (
                    ui.card().classes("w-full q-mb-xs"),
                    ui.row().classes("items-center gap-2 w-full"),
                ):
                    ui.switch(value=rule.enabled).on(
                        "update:model-value",
                        lambda v, r=rule: (setattr(r, "enabled", v.args), rules.update(r)),
                    )
                    ui.label(rule.name).classes("text-weight-medium flex-1")
                    ui.badge(
                        rule.action.value,
                        color={
                            "block": "negative",
                            "modify": "warning",
                            "redirect": "info",
                            "passthrough": "positive",
                        }.get(rule.action.value, "grey"),
                    )
                    ui.label(f"p={rule.priority}").classes("text-caption text-grey")
                    ui.button(
                        icon="delete",
                        on_click=lambda r=rule: (rules.delete(r.id), _refresh()),
                    ).props("flat dense color=negative size=sm")

    _refresh()

    ui.separator().classes("q-my-md")
    ui.label("Add Rule").classes("text-subtitle2")
    with ui.row().classes("gap-2 items-end q-mt-sm"):
        name_input = ui.input(label="Name").props("dense outlined dark").classes("w-48")
        action_select = (
            ui.select(
                ["block", "passthrough", "modify", "redirect"],
                value="block",
                label="Action",
            )
            .props("dense outlined dark")
            .classes("w-32")
        )
        priority_input = (
            ui.number(label="Priority", value=0).props("dense outlined dark").classes("w-24")
        )
        field_select = (
            ui.select(
                ["host", "path", "method", "header", "body"],
                value="host",
                label="Field",
            )
            .props("dense outlined dark")
            .classes("w-24")
        )
        op_select = (
            ui.select(
                ["contains", "equals", "prefix", "regex"],
                value="contains",
                label="Op",
            )
            .props("dense outlined dark")
            .classes("w-28")
        )
        value_input = ui.input(label="Value").props("dense outlined dark").classes("w-48")

        def _add() -> None:
            from pypproxy.rules import Condition, MatchField, Rule

            if not name_input.value or not value_input.value:
                ui.notify("Name and Value are required", type="warning")
                return
            rule = Rule(
                name=name_input.value,
                enabled=True,
                priority=int(priority_input.value or 0),
                action=action_select.value,
                conditions=[
                    Condition(
                        field=MatchField(field_select.value),
                        op=op_select.value,
                        value=value_input.value,
                    )
                ],
            )
            rules.add(rule)
            name_input.value = ""
            value_input.value = ""
            _refresh()
            ui.notify(f"Rule '{rule.name}' added", type="positive")

        ui.button("Add", icon="add", on_click=_add).props("color=primary size=sm")


def _build_passthrough_panel(cfg: Config) -> None:
    ui.label("SSL Passthrough").classes("text-subtitle1 q-mb-sm")
    ui.label(
        "Hosts listed here will be tunneled without TLS interception (for certificate pinning, etc.)."
    ).classes("text-caption text-grey q-mb-md")

    container = ui.column().classes("w-full")

    def _refresh() -> None:
        container.clear()
        with container:
            for host in cfg.proxy.ignore:
                with ui.row().classes("items-center gap-2"):
                    ui.label(host).classes("flex-1 font-mono")
                    ui.button(
                        icon="remove",
                        on_click=lambda h=host: (cfg.proxy.ignore.remove(h), _refresh()),
                    ).props("flat dense color=negative size=sm")

    _refresh()

    with ui.row().classes("gap-2 items-center q-mt-sm"):
        host_input = ui.input(label="Host").props("dense outlined dark").classes("w-64")

        def _add() -> None:
            h = host_input.value.strip()
            if h and h not in cfg.proxy.ignore:
                cfg.proxy.ignore.append(h)
                host_input.value = ""
                _refresh()

        ui.button("Add", icon="add", on_click=_add).props("color=primary size=sm")


def _build_dns_panel(cfg: Config, dns_server: DNSServer | None) -> None:
    ui.label("DNS Overwrite").classes("text-subtitle1 q-mb-sm")
    ui.label(
        "Redirect specific domains to a target IP. Start the DNS server and point devices to this machine."
    ).classes("text-caption text-grey q-mb-md")

    overrides: dict[str, str] = {}
    container = ui.column().classes("w-full")

    with ui.row().classes("items-center gap-2 q-mb-md"):
        dns_status = ui.badge("Stopped", color="grey")
        if dns_server:
            ui.button(
                "Start DNS",
                icon="play_arrow",
                on_click=lambda: _start_dns(dns_server, dns_status, overrides),
            ).props("size=sm color=positive")
        ui.label("Port 53153 (use iptables/pfctl to redirect port 53)").classes(
            "text-caption text-grey"
        )

    def _refresh() -> None:
        container.clear()
        with container:
            for domain, ip in overrides.items():
                with ui.row().classes("items-center gap-2"):
                    ui.label(domain).classes("flex-1 font-mono")
                    ui.label("→").classes("text-grey")
                    ui.label(ip).classes("font-mono text-positive")
                    ui.button(
                        icon="remove",
                        on_click=lambda d=domain: (
                            overrides.pop(d, None),
                            _refresh_dns(dns_server, overrides),
                            _refresh(),
                        ),
                    ).props("flat dense color=negative size=sm")

    _refresh()

    with ui.row().classes("gap-2 items-center q-mt-sm"):
        domain_input = ui.input(label="Domain").props("dense outlined dark").classes("w-48")
        ip_input = ui.input(label="Target IP").props("dense outlined dark").classes("w-36")

        def _add() -> None:
            d, ip = domain_input.value.strip(), ip_input.value.strip()
            if d and ip:
                overrides[d] = ip
                domain_input.value = ""
                ip_input.value = ""
                _refresh_dns(dns_server, overrides)
                _refresh()

        ui.button("Add", icon="add", on_click=_add).props("color=primary size=sm")


async def _start_dns(server: DNSServer, badge: ui.badge, overrides: dict) -> None:
    try:
        server.set_overrides(overrides)
        await server.start()
        badge.text = "Running"
        badge.props("color=positive")
        ui.notify("DNS server started on :53153", type="positive")
    except Exception as e:
        ui.notify(f"Failed to start DNS: {e}", type="negative")


def _refresh_dns(server: DNSServer | None, overrides: dict) -> None:
    if server:
        server.set_overrides(overrides)


def _build_ports_panel(cfg: Config) -> None:
    ui.label("Listen Ports").classes("text-subtitle1 q-mb-sm")
    ui.label("Configure proxy listen address and port.").classes("text-caption text-grey q-mb-md")

    with ui.row().classes("gap-4 items-end"):
        addr_input = (
            ui.input(label="Proxy Address", value=cfg.proxy.addr)
            .props("dense outlined dark")
            .classes("w-48")
        )
        port_input = (
            ui.number(label="Proxy Port", value=cfg.proxy.port)
            .props("dense outlined dark")
            .classes("w-28")
        )
        ui_port_input = (
            ui.number(label="UI Port", value=cfg.ui.port)
            .props("dense outlined dark")
            .classes("w-28")
        )

        def _save() -> None:
            cfg.proxy.addr = addr_input.value
            cfg.proxy.port = int(port_input.value or 8080)
            cfg.ui.port = int(ui_port_input.value or 8081)
            ui.notify("Port settings saved (takes effect on restart)", type="info")

        ui.button("Save", icon="save", on_click=_save).props("color=primary size=sm")

    ui.label("Note: Port changes take effect after restarting paxy.").classes(
        "text-caption text-grey q-mt-sm"
    )


def _build_certs_panel(cert_mgr: ClientCertManager) -> None:
    ui.label("Client Certificates").classes("text-subtitle1 q-mb-sm")
    ui.label("Client certificates are sent to matching hosts during TLS handshake.").classes(
        "text-caption text-grey q-mb-md"
    )

    container = ui.column().classes("w-full")

    def _refresh() -> None:
        container.clear()
        with container:
            for cert in cert_mgr.list():
                with ui.card().classes("w-full q-mb-xs"), ui.row().classes("items-center gap-2"):
                    ui.icon("badge").classes("text-primary")
                    with ui.column().classes("flex-1"):
                        ui.label(cert.name).classes("text-weight-medium")
                        ui.label(f"{cert.host_pattern}  •  {cert.cert_path}").classes(
                            "text-caption text-grey"
                        )
                    ui.button(
                        icon="delete",
                        on_click=lambda n=cert.name: (cert_mgr.remove(n), _refresh()),
                    ).props("flat dense color=negative size=sm")

    _refresh()

    ui.separator().classes("q-my-md")
    ui.label("Add Client Certificate").classes("text-subtitle2")
    with ui.grid(columns=2).classes("gap-2 q-mt-sm"):
        name_input = ui.input(label="Name").props("dense outlined dark")
        pattern_input = ui.input(label="Host Pattern", value="*").props("dense outlined dark")
        cert_input = ui.input(label="Certificate Path (.pem)").props("dense outlined dark")
        key_input = ui.input(label="Key Path (.pem)").props("dense outlined dark")

    def _add() -> None:
        if not name_input.value or not cert_input.value or not key_input.value:
            ui.notify("All fields are required", type="warning")
            return
        cert_mgr.add(
            ClientCert(
                name=name_input.value,
                cert_path=cert_input.value,
                key_path=key_input.value,
                host_pattern=pattern_input.value or "*",
            )
        )
        for inp in (name_input, cert_input, key_input):
            inp.value = ""
        _refresh()
        ui.notify("Certificate added", type="positive")

    ui.button("Add", icon="add", on_click=_add).props("color=primary size=sm q-mt-sm")
