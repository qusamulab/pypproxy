"""The page registry behind the sidebar.

Each entry pairs the nav item the user clicks with the builder that renders it.
Builders are imported lazily: a tab like Frida pulls in heavy optional deps, and
nobody should pay for them just by opening the traffic list.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pypproxy.ui.workspace import Workspace

#: A builder renders into the current NiceGUI container and returns either None
#: or a state dict exposing hooks such as `open_entry` / `set_entries`.
Builder = Callable[..., dict[str, Any] | None]


@dataclass(frozen=True)
class Page:
    id: str
    label: str
    icon: str
    _load: Callable[[], Builder]
    #: Tabs only need the store; the traffic view drives shared workspace state.
    wants_workspace: bool = False

    def build(self, workspace: Workspace) -> dict[str, Any] | None:
        builder = self._load()
        return builder(workspace) if self.wants_workspace else builder(workspace.store)


@dataclass(frozen=True)
class Section:
    title: str
    pages: tuple[Page, ...]


def _traffic() -> Builder:
    from pypproxy.ui.traffic import build_traffic_page

    return build_traffic_page


def _lazy(module: str, attr: str) -> Callable[[], Builder]:
    def load() -> Builder:
        import importlib

        return getattr(importlib.import_module(f"pypproxy.ui.tabs.{module}"), attr)

    return load


NAV: tuple[Section, ...] = (
    Section(
        "Traffic",
        (Page("traffic", "Traffic", "list", _traffic, wants_workspace=True),),
    ),
    Section(
        "Tools",
        (
            Page("resender", "Resender", "send", _lazy("resender", "build_resender_tab")),
            Page("bulk", "Bulk Sender", "dynamic_feed", _lazy("bulk_sender", "build_bulk_sender")),
            Page("macro", "Macro", "playlist_play", _lazy("macro", "build_macro_tab")),
            Page("diff", "Diff", "difference", _lazy("diff", "build_diff_view")),
            Page("ab", "A/B Test", "compare", _lazy("ab", "build_ab_tab")),
        ),
    ),
    Section(
        "Security",
        (
            Page("security", "Security", "security", _lazy("security", "build_security_tab")),
            Page(
                "advsec",
                "Adv Security",
                "shield",
                _lazy("advanced_security", "build_advanced_security_tab"),
            ),
            Page("scan", "Scan", "search", _lazy("scan", "build_scan_tab")),
        ),
    ),
    Section(
        "Analysis",
        (
            Page("graphql", "GraphQL", "account_tree", _lazy("graphql", "build_graphql_tab")),
            Page("analytics", "Analytics", "bar_chart", _lazy("analytics", "build_analytics_tab")),
            Page("openapi", "OpenAPI", "description", _lazy("openapi", "build_openapi_tab")),
        ),
    ),
    Section(
        "Dev",
        (
            Page("codegen", "Code Gen", "code", _lazy("codegen", "build_codegen_tab")),
            Page("frida", "Frida", "adb", _lazy("frida", "build_frida_tab")),
            Page("sessions", "Sessions", "folder", _lazy("session", "build_session_tab")),
            Page("report", "Report", "summarize", _lazy("report", "build_report_tab")),
        ),
    ),
    Section(
        "Data",
        (Page("import", "Import/Search", "upload", _lazy("import_export", "build_import_tab")),),
    ),
)

PAGES: dict[str, Page] = {page.id: page for section in NAV for page in section.pages}

DEFAULT_PAGE = "traffic"
