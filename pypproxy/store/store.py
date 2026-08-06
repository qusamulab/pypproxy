from __future__ import annotations

import asyncio
import contextlib
import threading

from .models import Entry, Filter


class Store:
    """In-memory traffic store with optional SQLite persistence."""

    def __init__(self) -> None:
        self._entries: list[Entry] = []
        self._by_id: dict[int, Entry] = {}
        self._counter = 0
        self._lock = threading.Lock()
        self._subscribers: list[asyncio.Queue] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._db: object | None = None  # paxy.store.db.Database

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def set_db(self, db: object) -> None:
        self._db = db

    @property
    def database(self) -> object | None:
        """The attached `store.db.Database`, or None when persistence is off."""
        return self._db

    # --- write ---

    def add(self, entry: Entry) -> Entry:
        with self._lock:
            self._counter += 1
            entry.id = self._counter
            self._entries.append(entry)
            self._by_id[entry.id] = entry
        self._publish(entry)
        self._db_insert(entry)
        return entry

    def update(self, entry: Entry) -> None:
        with self._lock:
            self._by_id[entry.id] = entry
            # update in-place in list
            for i, e in enumerate(self._entries):
                if e.id == entry.id:
                    self._entries[i] = entry
                    break
        self._publish(entry)
        self._db_update(entry)

    def set_color(self, entry_id: int, color: str) -> None:
        with self._lock:
            e = self._by_id.get(entry_id)
        if e:
            e.color = color
            self.update(e)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._by_id.clear()
        if self._loop and self._db:
            asyncio.run_coroutine_threadsafe(self._db.clear(), self._loop)

    # --- read ---

    def get(self, entry_id: int) -> Entry | None:
        return self._by_id.get(entry_id)

    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    def list(self, f: Filter, offset: int = 0, limit: int = 100) -> tuple[list[Entry], int]:
        with self._lock:
            filtered = [e for e in self._entries if f.matches(e)]
        total = len(filtered)
        if limit == 0:
            return filtered[offset:], total
        return filtered[offset : offset + limit], total

    # --- pub/sub ---

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=512)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with self._lock, contextlib.suppress(ValueError):
            self._subscribers.remove(q)

    def _publish(self, entry: Entry) -> None:
        if self._loop is None:
            return
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            with contextlib.suppress(asyncio.QueueFull):
                self._loop.call_soon_threadsafe(q.put_nowait, entry)

    # --- DB helpers (fire-and-forget) ---

    def _db_insert(self, entry: Entry) -> None:
        if self._loop and self._db:
            asyncio.run_coroutine_threadsafe(self._db.insert(entry), self._loop)

    def _db_update(self, entry: Entry) -> None:
        if self._loop and self._db:
            asyncio.run_coroutine_threadsafe(self._db.update(entry), self._loop)

    # --- restore from DB on startup ---

    async def load_from_db(self) -> None:
        if not self._db:
            return
        entries, _ = await self._db.list(Filter(), offset=0, limit=0)
        with self._lock:
            for e in entries:
                self._entries.append(e)
                self._by_id[e.id] = e
                if e.id > self._counter:
                    self._counter = e.id
