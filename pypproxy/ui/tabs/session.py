from __future__ import annotations

from nicegui import ui

from pypproxy.session import SessionManager
from pypproxy.store.models import Entry
from pypproxy.store.store import Store

_session_mgr: SessionManager | None = None


def get_session_manager() -> SessionManager:
    global _session_mgr
    if _session_mgr is None:
        _session_mgr = SessionManager()
    return _session_mgr


def build_session_tab(store: Store) -> dict:
    mgr = get_session_manager()

    with ui.column().classes("w-full h-full overflow-auto q-pa-md"):
        ui.label("Sessions").classes("text-subtitle2 q-mb-xs")
        ui.label("Group and save entries into named sessions.").classes(
            "text-caption text-grey q-mb-sm"
        )

        # Create new session
        with ui.row().classes("gap-2 items-center q-mb-md"):
            name_input = (
                ui.input(label="Session name", placeholder="e.g. Login flow")
                .props("dense outlined dark")
                .classes("w-56")
            )
            create_btn = ui.button("New Session", icon="add").props("color=primary size=sm")

        sessions_container = ui.column().classes("w-full")

        def _refresh_sessions() -> None:
            sessions_container.clear()
            with sessions_container:
                sessions = mgr.list()
                if not sessions:
                    ui.label("No sessions yet").classes("text-grey text-caption")
                    return
                for sess in sessions:
                    active = mgr.active_id == sess.id
                    with (
                        ui.card().classes(f"w-full q-mb-xs {'bg-blue-grey-10' if active else ''}"),
                        ui.row().classes("items-center gap-2"),
                    ):
                        if active:
                            ui.badge("active", color="primary").props("rounded")
                        ui.label(sess.name).classes("text-weight-medium flex-1")
                        ui.label(f"{len(sess.entry_ids)} entries").classes("text-caption text-grey")
                        ui.button(
                            icon="radio_button_checked" if active else "radio_button_unchecked",
                            on_click=lambda sid=sess.id: (
                                _set_active(sid),
                                _refresh_sessions(),
                            ),
                        ).props("flat dense size=sm color=primary").tooltip("Set active")
                        ui.button(
                            icon="delete",
                            on_click=lambda sid=sess.id: (mgr.delete(sid), _refresh_sessions()),
                        ).props("flat dense size=sm color=negative")

        def _set_active(session_id: str) -> None:
            if mgr.active_id == session_id:
                mgr.set_active(None)
            else:
                mgr.set_active(session_id)

        def _create_session() -> None:
            name = name_input.value.strip()
            if not name:
                ui.notify("Enter a name", type="warning")
                return
            mgr.create(name)
            name_input.value = ""
            _refresh_sessions()
            ui.notify(f"Session '{name}' created", type="positive")

        create_btn.on("click", _create_session)
        _refresh_sessions()

    def add_entry_to_active(entry: Entry) -> None:
        active = mgr.get_active()
        if active:
            mgr.add_entry(active.id, entry.id)
            ui.notify(f"Added to session '{active.name}'", type="positive")
        else:
            ui.notify("No active session — create or activate one first", type="warning")

    return {"add_entry_to_active": add_entry_to_active, "manager": mgr}
