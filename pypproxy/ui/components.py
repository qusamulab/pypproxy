"""Small NiceGUI building blocks shared by the tool tabs."""

from __future__ import annotations

from nicegui import ui

from pypproxy.store.models import Entry

NO_ENTRY = "No entry selected"


def entry_label() -> ui.label:
    """The `No entry selected` caption every entry-driven tab starts with."""
    return ui.label(NO_ENTRY).classes("text-grey text-caption q-mb-sm")


def set_entry_label(label: ui.label, entry: Entry | None) -> None:
    label.text = entry.summary() if entry else NO_ENTRY


def tab_container() -> ui.column:
    """The standard scrollable, padded column a tab renders itself into."""
    return ui.column().classes("w-full h-full overflow-auto q-pa-md")
