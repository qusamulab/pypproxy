"""State shared across the GUI's pages.

Pages are torn down and rebuilt on every nav click, so anything that must
outlive a click — the active filter, which entry the user sent to a tool, the
left-hand side of a pending diff — lives here rather than in a page.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pypproxy.proxy.intercept import InterceptManager
from pypproxy.store.models import Entry, Filter
from pypproxy.store.store import Store

#: How many entries the traffic table holds in view at once.
TRAFFIC_PAGE_SIZE = 500


@dataclass
class Workspace:
    store: Store
    intercept: InterceptManager | None = None

    active_page: str = "traffic"
    traffic_filter: Filter = field(default_factory=Filter)

    #: Entry queued by a context-menu action, consumed by the page it targets.
    pending_entry: Entry | None = None
    #: Left-hand side of a diff, set from the traffic context menu.
    diff_left: Entry | None = None

    #: Whatever each page's builder returned, keyed by page id.
    page_state: dict[str, dict] = field(default_factory=dict)

    def visible_entries(self) -> list[Entry]:
        """Entries matching the active filter, newest first."""
        entries, _ = self.store.list(self.traffic_filter, 0, TRAFFIC_PAGE_SIZE)
        return list(reversed(entries))
