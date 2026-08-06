"""Reading, searching and streaming captured traffic."""

from __future__ import annotations

import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, Response

from pypproxy.api.deps import State, get_state, require_entry
from pypproxy.store.models import Filter

router = APIRouter(prefix="/api", tags=["traffic"])


@router.get("/traffic")
async def list_traffic(
    state: State,
    offset: int = 0,
    limit: int = 100,
    method: str = "",
    host: str = "",
    search: str = "",
    protocol: str = "",
) -> JSONResponse:
    f = Filter(method=method, host=host, search=search, protocol=protocol)
    entries, total = state.store.list(f, offset, limit)
    return JSONResponse(
        {
            "entries": [e.to_dict() for e in entries],
            "total": total,
            "offset": offset,
            "limit": limit,
        }
    )


@router.get("/traffic/{entry_id}")
async def get_traffic(state: State, entry_id: int) -> JSONResponse:
    return JSONResponse(require_entry(state, entry_id).to_dict())


@router.get("/search")
async def fts_search(state: State, q: str = "", limit: int = 50) -> JSONResponse:
    if not q:
        return JSONResponse([])

    db = state.store.database
    if db is None:
        # No SQLite attached — degrade to a substring match over memory.
        entries, _ = state.store.list(Filter(search=q), 0, limit)
        return JSONResponse(
            [{"entry_id": e.id, "rank": 0.0, "snippet": e.host + e.path} for e in entries]
        )

    results = await db.search(q, limit)
    return JSONResponse([r.to_dict() for r in results])


@router.post("/clear")
async def clear(state: State) -> Response:
    state.store.clear()
    return Response(status_code=204)


ws_router = APIRouter(tags=["traffic"])


@ws_router.websocket("/ws")
async def ws_endpoint(websocket: WebSocket) -> None:
    state = get_state()
    await websocket.accept()
    q = state.store.subscribe()
    try:
        while True:
            entry = await q.get()
            await websocket.send_text(json.dumps(entry.to_dict()))
    except WebSocketDisconnect:
        pass
    finally:
        state.store.unsubscribe(q)
