from __future__ import annotations

from nicegui import ui

from pypproxy.frida.device import FridaManager
from pypproxy.store.models import Entry, Filter
from pypproxy.store.store import Store
from pypproxy.ui.components import entry_label as make_entry_label
from pypproxy.ui.components import set_entry_label

_mgr = FridaManager()


def build_frida_tab(store: Store) -> dict:
    state: dict = {"entry": None, "device_id": None, "target": None}

    with ui.column().classes("w-full h-full overflow-auto q-pa-md"):
        if not _mgr.is_available():
            ui.label("frida is not installed.").classes("text-warning text-subtitle2")
            ui.label("Run: pip install 'pypproxy[frida]' or pip install frida").classes(
                "text-caption text-grey q-mb-md"
            )
            ui.separator()

        with ui.tabs().props("dense dark") as tabs:
            bypass_tab = ui.tab("SSL Bypass", icon="lock_open")
            inject_tab = ui.tab("Inject", icon="play_arrow")
            hooks_tab = ui.tab("Request Hooks", icon="code")
            traffic_tab_btn = ui.tab("Traffic Hooks", icon="wifi")

        with ui.tab_panels(tabs, value=bypass_tab).classes("w-full"):
            # ================================================================
            # SSL Bypass — テンプレート表示＋ワンクリック注入
            # ================================================================
            with ui.tab_panel(bypass_tab):
                ui.label("Certificate Pinning Bypass").classes("text-subtitle2 q-mb-xs")

                with ui.row().classes("gap-2 items-center q-mb-sm flex-wrap"):
                    from pypproxy.frida.pinning_bypass import list_templates

                    template_select = (
                        ui.select(list_templates(), value=list_templates()[0], label="Template")
                        .props("dense outlined dark")
                        .classes("w-72")
                    )

                    # Device selector
                    device_select = (
                        ui.select([], label="Device", value=None)
                        .props("dense outlined dark")
                        .classes("w-48")
                    )
                    ui.button(
                        icon="refresh", on_click=lambda: _refresh_devices(device_select)
                    ).props("flat dense size=sm")

                    # Target app input
                    target_input = (
                        ui.input(label="Bundle ID / Package", placeholder="com.example.app")
                        .props("dense outlined dark")
                        .classes("w-56")
                    )

                    spawn_toggle = ui.switch("Spawn", value=True).props("dense dark")
                    inject_bypass_btn = ui.button("Inject", icon="play_arrow").props(
                        "color=warning size=sm"
                    )

                bypass_area = (
                    ui.textarea()
                    .props("outlined dense rows=14 readonly")
                    .classes("w-full font-mono text-xs")
                )

                # Console output
                ui.label("Console output:").classes("text-caption text-grey q-mt-sm")
                bypass_console = (
                    ui.textarea()
                    .props("outlined dense rows=6 readonly")
                    .classes("w-full font-mono text-xs")
                )

                with ui.row().classes("gap-2"):
                    ui.button(
                        "Copy script",
                        icon="content_copy",
                        on_click=lambda: (
                            ui.run_javascript(
                                f"navigator.clipboard.writeText({bypass_area.value!r})"
                            ),
                            ui.notify("Copied!", type="positive"),
                        ),
                    ).props("flat size=sm")
                    detach_bypass_btn = ui.button("Detach", icon="stop").props(
                        "flat color=negative size=sm"
                    )

                def _load_template() -> None:
                    from pypproxy.frida.pinning_bypass import get_template

                    bypass_area.value = get_template(template_select.value)

                template_select.on("update:model-value", lambda: _load_template())
                _load_template()

                async def _inject_bypass() -> None:
                    dev = device_select.value
                    target = target_input.value.strip()
                    if not dev or not target:
                        ui.notify("Select a device and enter a target", type="warning")
                        return
                    state["device_id"] = dev
                    state["target"] = target
                    inject_bypass_btn.props("loading")
                    bypass_console.value = ""
                    try:

                        def _log(msg: str) -> None:
                            bypass_console.value = (bypass_console.value + msg + "\n")[-3000:]

                        sess = await _mgr.inject(
                            dev,
                            target,
                            bypass_area.value,
                            on_message=_log,
                            spawn=spawn_toggle.value,
                        )
                        if sess.error:
                            ui.notify(f"Injection failed: {sess.error}", type="negative")
                            bypass_console.value += f"\n[ERROR] {sess.error}"
                        else:
                            ui.notify(f"Injected into {target}", type="positive")
                    finally:
                        inject_bypass_btn.props(remove="loading")

                inject_bypass_btn.on("click", _inject_bypass)
                detach_bypass_btn.on(
                    "click",
                    lambda: (
                        _mgr.detach(state.get("device_id", ""), state.get("target", "")),
                        ui.notify("Detached", type="info"),
                    ),
                )

            # ================================================================
            # Inject — 任意スクリプトを直接注入
            # ================================================================
            with ui.tab_panel(inject_tab):
                ui.label("Script Injector").classes("text-subtitle2 q-mb-xs")
                ui.label("Write or paste a Frida script and inject it directly.").classes(
                    "text-caption text-grey q-mb-sm"
                )

                with ui.row().classes("gap-2 items-center q-mb-sm flex-wrap"):
                    inj_device_select = (
                        ui.select([], label="Device", value=None)
                        .props("dense outlined dark")
                        .classes("w-48")
                    )
                    ui.button(
                        icon="refresh", on_click=lambda: _refresh_devices(inj_device_select)
                    ).props("flat dense size=sm")
                    inj_target_input = (
                        ui.input(label="Bundle ID / Package / pid:<n>")
                        .props("dense outlined dark")
                        .classes("w-64")
                    )
                    inj_spawn_toggle = ui.switch("Spawn", value=False).props("dense dark")
                    inj_btn = ui.button("Inject", icon="play_arrow").props("color=primary size=sm")
                    inj_detach_btn = ui.button("Detach", icon="stop").props(
                        "flat color=negative size=sm"
                    )

                inj_script_area = (
                    ui.textarea(
                        value='// Write your Frida script here\nJava.perform(function() {\n  console.log("[pypproxy] Hello from Frida!");\n});'
                    )
                    .props("outlined dense rows=14")
                    .classes("w-full font-mono text-xs")
                )

                ui.label("Console output:").classes("text-caption text-grey q-mt-sm")
                inj_console = (
                    ui.textarea()
                    .props("outlined dense rows=8 readonly")
                    .classes("w-full font-mono text-xs")
                )

                async def _do_inject() -> None:
                    dev = inj_device_select.value
                    target = inj_target_input.value.strip()
                    if not dev or not target:
                        ui.notify("Select device and enter target", type="warning")
                        return
                    inj_btn.props("loading")
                    inj_console.value = ""
                    state["device_id"] = dev
                    state["target"] = target
                    try:

                        def _log(msg: str) -> None:
                            inj_console.value = (inj_console.value + msg + "\n")[-4000:]

                        sess = await _mgr.inject(
                            dev,
                            target,
                            inj_script_area.value,
                            on_message=_log,
                            spawn=inj_spawn_toggle.value,
                        )
                        if sess.error:
                            ui.notify(f"Failed: {sess.error}", type="negative")
                            inj_console.value += f"\n[ERROR] {sess.error}"
                        else:
                            ui.notify(f"Injected into {target}", type="positive")
                    finally:
                        inj_btn.props(remove="loading")

                inj_btn.on("click", _do_inject)
                inj_detach_btn.on(
                    "click",
                    lambda: (
                        _mgr.detach(state.get("device_id", ""), state.get("target", "")),
                        ui.notify("Detached", type="info"),
                    ),
                )

            # ================================================================
            # Request Hooks
            # ================================================================
            with ui.tab_panel(hooks_tab):
                ui.label("Request Hook Generator").classes("text-subtitle2 q-mb-xs")
                entry_label = make_entry_label()

                with ui.row().classes("gap-2 items-center q-mb-sm flex-wrap"):
                    hook_device_select = (
                        ui.select([], label="Device", value=None)
                        .props("dense outlined dark")
                        .classes("w-48")
                    )
                    ui.button(
                        icon="refresh", on_click=lambda: _refresh_devices(hook_device_select)
                    ).props("flat dense size=sm")
                    hook_target_input = (
                        ui.input(label="Bundle ID / Package")
                        .props("dense outlined dark")
                        .classes("w-56")
                    )
                    target_select = (
                        ui.select(
                            ["okhttp3", "nsurlsession", "fetch"], value="okhttp3", label="Target"
                        )
                        .props("dense outlined dark")
                        .classes("w-36")
                    )
                    gen_hook_btn = ui.button("Generate", icon="code").props(
                        "color=secondary size=sm"
                    )
                    hook_inject_btn = ui.button("Inject", icon="play_arrow").props(
                        "color=primary size=sm"
                    )

                hook_area = (
                    ui.textarea()
                    .props("outlined dense rows=12 readonly")
                    .classes("w-full font-mono text-xs")
                )
                ui.label("Console output:").classes("text-caption text-grey q-mt-sm")
                hook_console = (
                    ui.textarea()
                    .props("outlined dense rows=6 readonly")
                    .classes("w-full font-mono text-xs")
                )

                def _gen_hook() -> None:
                    entry = state.get("entry")
                    if not entry:
                        ui.notify("Select an entry from Traffic first", type="warning")
                        return
                    from pypproxy.frida.hook_generator import generate_parameter_hook

                    hook_area.value = generate_parameter_hook(entry, target_select.value)

                async def _inject_hook() -> None:
                    dev = hook_device_select.value
                    target = hook_target_input.value.strip()
                    if not dev or not target or not hook_area.value:
                        ui.notify(
                            "Generate a hook and select a device/target first", type="warning"
                        )
                        return
                    hook_inject_btn.props("loading")
                    hook_console.value = ""
                    state["device_id"] = dev
                    state["target"] = target
                    try:

                        def _log(msg: str) -> None:
                            hook_console.value = (hook_console.value + msg + "\n")[-4000:]

                        sess = await _mgr.inject(
                            dev, target, hook_area.value, on_message=_log, spawn=False
                        )
                        if sess.error:
                            ui.notify(f"Failed: {sess.error}", type="negative")
                        else:
                            ui.notify(f"Hook injected into {target}", type="positive")
                    finally:
                        hook_inject_btn.props(remove="loading")

                gen_hook_btn.on("click", _gen_hook)
                hook_inject_btn.on("click", _inject_hook)

            # ================================================================
            # Traffic Hooks
            # ================================================================
            with ui.tab_panel(traffic_tab_btn):
                ui.label("Traffic-based Hook Generator").classes("text-subtitle2 q-mb-xs")

                with ui.row().classes("gap-2 items-center q-mb-sm flex-wrap"):
                    th_device_select = (
                        ui.select([], label="Device", value=None)
                        .props("dense outlined dark")
                        .classes("w-48")
                    )
                    ui.button(
                        icon="refresh", on_click=lambda: _refresh_devices(th_device_select)
                    ).props("flat dense size=sm")
                    th_target_input = (
                        ui.input(label="Bundle ID / Package")
                        .props("dense outlined dark")
                        .classes("w-56")
                    )
                    host_input = (
                        ui.input(label="Filter host (optional)")
                        .props("dense outlined dark")
                        .classes("w-48")
                    )
                    traffic_target = (
                        ui.select(
                            ["okhttp3", "nsurlsession", "fetch"], value="okhttp3", label="Target"
                        )
                        .props("dense outlined dark")
                        .classes("w-36")
                    )
                    gen_traffic_btn = ui.button("Generate", icon="refresh").props(
                        "color=secondary size=sm"
                    )
                    th_inject_btn = ui.button("Inject", icon="play_arrow").props(
                        "color=primary size=sm"
                    )

                traffic_hook_area = (
                    ui.textarea()
                    .props("outlined dense rows=12 readonly")
                    .classes("w-full font-mono text-xs")
                )
                traffic_summary = ui.label("").classes("text-caption text-grey")
                ui.label("Console output:").classes("text-caption text-grey q-mt-sm")
                traffic_console = (
                    ui.textarea()
                    .props("outlined dense rows=6 readonly")
                    .classes("w-full font-mono text-xs")
                )

                def _gen_traffic_hooks() -> None:
                    from pypproxy.frida.hook_generator import generate_request_logger

                    f = (
                        Filter(host=host_input.value.strip())
                        if host_input.value.strip()
                        else Filter()
                    )
                    entries, total = store.list(f, 0, 0)
                    traffic_hook_area.value = generate_request_logger(entries, traffic_target.value)
                    hosts = len({e.host for e in entries if e.host})
                    eps = len({(e.method, e.path) for e in entries})
                    traffic_summary.text = f"{total} entries — {hosts} hosts, {eps} endpoints"
                    ui.notify(f"Generated from {total} entries", type="positive")

                async def _inject_traffic() -> None:
                    dev = th_device_select.value
                    target = th_target_input.value.strip()
                    if not dev or not target or not traffic_hook_area.value:
                        ui.notify("Generate hooks and select device/target first", type="warning")
                        return
                    th_inject_btn.props("loading")
                    traffic_console.value = ""
                    state["device_id"] = dev
                    state["target"] = target
                    try:

                        def _log(msg: str) -> None:
                            traffic_console.value = (traffic_console.value + msg + "\n")[-4000:]

                        sess = await _mgr.inject(
                            dev, target, traffic_hook_area.value, on_message=_log, spawn=False
                        )
                        if sess.error:
                            ui.notify(f"Failed: {sess.error}", type="negative")
                        else:
                            ui.notify(f"Traffic hook injected into {target}", type="positive")
                    finally:
                        th_inject_btn.props(remove="loading")

                gen_traffic_btn.on("click", _gen_traffic_hooks)
                th_inject_btn.on("click", _inject_traffic)

        # Initial device refresh
        _refresh_devices(device_select)
        _refresh_devices(inj_device_select)
        _refresh_devices(hook_device_select)
        _refresh_devices(th_device_select)

    def open_entry(entry: Entry) -> None:
        state["entry"] = entry
        set_entry_label(entry_label, entry)

    return {"open_entry": open_entry}


def _refresh_devices(select_widget: ui.select) -> None:
    devices = _mgr.list_devices()
    options = {d.id: f"{d.name} ({d.type})" for d in devices}
    select_widget.options = options
    if options and not select_widget.value:
        select_widget.value = next(iter(options))
    select_widget.update()
    if not devices:
        ui.notify(
            "No Frida devices found. Connect a device via USB or start frida-server.",
            type="warning",
        )
