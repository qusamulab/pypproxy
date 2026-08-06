"""Import and export of captured traffic and rules."""

from __future__ import annotations

import json

from fastapi import APIRouter
from fastapi.responses import JSONResponse, PlainTextResponse

from pypproxy.api.deps import State
from pypproxy.exchange.exporter import export_all, export_har, import_rules
from pypproxy.exchange.importer import import_har, import_json
from pypproxy.store.models import Filter

router = APIRouter(prefix="/api", tags=["exchange"])

JSON_MEDIA_TYPE = "application/json"


@router.get("/export/json")
async def export_json(state: State) -> PlainTextResponse:
    entries, _ = state.store.list(Filter(), 0, 0)
    return PlainTextResponse(export_all(entries, state.rules), media_type=JSON_MEDIA_TYPE)


@router.get("/export/har")
async def export_har_endpoint(state: State) -> PlainTextResponse:
    entries, _ = state.store.list(Filter(), 0, 0)
    return PlainTextResponse(export_har(entries), media_type=JSON_MEDIA_TYPE)


@router.post("/import/rules")
async def import_rules_endpoint(state: State, data: dict) -> JSONResponse:
    count = import_rules(json.dumps(data.get("rules", data)), state.rules)
    return JSONResponse({"imported": count})


@router.post("/import/har")
async def import_har_endpoint(state: State, data: dict) -> JSONResponse:
    return JSONResponse({"imported": import_har(json.dumps(data), state.store)})


@router.post("/import/json")
async def import_json_endpoint(state: State, data: dict) -> JSONResponse:
    count = import_json(json.dumps(data.get("entries", data)), state.store)
    return JSONResponse({"imported": count})
