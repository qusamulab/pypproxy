"""Shared state and FastAPI dependencies for the HTTP API.

The API is served two different ways — standalone under uvicorn in CUI mode,
mounted into NiceGUI's app in GUI mode — so the routers cannot own their
collaborators. `configure()` installs them once at startup and the routers pull
them back out through `Depends`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException

from pypproxy.graphql.schema_store import SchemaStore
from pypproxy.rules import RuleManager
from pypproxy.store.models import Entry
from pypproxy.store.scope import ScopeManager
from pypproxy.store.store import Store


@dataclass(frozen=True)
class ApiState:
    store: Store
    rules: RuleManager
    scope: ScopeManager
    schemas: SchemaStore


_state: ApiState | None = None


def configure(state: ApiState) -> None:
    global _state
    _state = state


def get_state() -> ApiState:
    if _state is None:
        raise HTTPException(status_code=503, detail="API not initialised")
    return _state


State = Annotated[ApiState, Depends(get_state)]


def require_entry(state: ApiState, entry_id: int) -> Entry:
    entry = state.store.get(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="entry not found")
    return entry
