from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class Session:
    id: str
    name: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    entry_ids: list[int] = field(default_factory=list)
    notes: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at,
            "entry_ids": self.entry_ids,
            "notes": self.notes,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Session:
        return cls(
            id=d["id"],
            name=d["name"],
            created_at=d.get("created_at", ""),
            entry_ids=d.get("entry_ids", []),
            notes=d.get("notes", ""),
            tags=d.get("tags", []),
        )


class SessionManager:
    def __init__(self, sessions_dir: str = "") -> None:
        self._sessions: dict[str, Session] = {}
        self._active_id: str | None = None
        self._lock = threading.Lock()
        self._sessions_dir = (
            Path(sessions_dir) if sessions_dir else Path.home() / ".pypproxy" / "sessions"
        )
        self._sessions_dir.mkdir(parents=True, exist_ok=True)
        self._load_all()

    # --- CRUD ---

    def create(self, name: str, notes: str = "") -> Session:
        sess = Session(id=str(uuid.uuid4())[:8], name=name, notes=notes)
        with self._lock:
            self._sessions[sess.id] = sess
        self._save(sess)
        return sess

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def list(self) -> list[Session]:
        with self._lock:
            return sorted(self._sessions.values(), key=lambda s: s.created_at, reverse=True)

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)
            if self._active_id == session_id:
                self._active_id = None
        path = self._sessions_dir / f"{session_id}.json"
        if path.exists():
            path.unlink()

    def rename(self, session_id: str, name: str) -> None:
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess:
                sess.name = name
                self._save(sess)

    def update_notes(self, session_id: str, notes: str) -> None:
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess:
                sess.notes = notes
                self._save(sess)

    # --- Active session ---

    @property
    def active_id(self) -> str | None:
        return self._active_id

    def set_active(self, session_id: str | None) -> None:
        self._active_id = session_id

    def get_active(self) -> Session | None:
        if self._active_id:
            return self.get(self._active_id)
        return None

    # --- Entry management ---

    def add_entry(self, session_id: str, entry_id: int) -> None:
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess and entry_id not in sess.entry_ids:
                sess.entry_ids.append(entry_id)
                self._save(sess)

    def remove_entry(self, session_id: str, entry_id: int) -> None:
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess and entry_id in sess.entry_ids:
                sess.entry_ids.remove(entry_id)
                self._save(sess)

    # --- Persistence ---

    def _save(self, sess: Session) -> None:
        path = self._sessions_dir / f"{sess.id}.json"
        with open(path, "w") as f:
            json.dump(sess.to_dict(), f, indent=2)

    def _load_all(self) -> None:
        for path in self._sessions_dir.glob("*.json"):
            try:
                with open(path) as f:
                    data = json.load(f)
                sess = Session.from_dict(data)
                self._sessions[sess.id] = sess
            except Exception:
                pass
