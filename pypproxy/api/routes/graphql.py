"""GraphQL schema introspection and operation replay."""

from __future__ import annotations

import contextlib
import json
import time
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, Response

from pypproxy.api.deps import State, require_entry
from pypproxy.api.schemas import GQLReplayRequest, IntrospectRequest
from pypproxy.core.http import DEFAULT_TIMEOUT, elapsed_ms, flatten_headers
from pypproxy.core.http import client as http_client
from pypproxy.graphql.introspection import fetch_schema

router = APIRouter(prefix="/api/graphql", tags=["graphql"])


@router.post("/introspect")
async def graphql_introspect(state: State, req: IntrospectRequest) -> JSONResponse:
    schema = await fetch_schema(req.url, req.headers)
    if schema is None:
        raise HTTPException(status_code=502, detail="Introspection failed or not supported")
    state.schemas.set(urlparse(req.url).netloc, schema)
    return JSONResponse(schema.to_dict())


@router.get("/schemas")
async def graphql_list_schemas(state: State) -> JSONResponse:
    return JSONResponse(
        [
            {"host": host, "query_type": s.query_type, "mutation_type": s.mutation_type}
            for host, s in state.schemas.all().items()
        ]
    )


@router.get("/schema/{host}")
async def graphql_get_schema(state: State, host: str) -> JSONResponse:
    schema = state.schemas.get(host)
    if schema is None:
        raise HTTPException(status_code=404, detail=f"no schema for {host}")
    return JSONResponse(schema.to_dict())


@router.delete("/schema/{host}")
async def graphql_delete_schema(state: State, host: str) -> Response:
    state.schemas.delete(host)
    return Response(status_code=204)


@router.post("/replay")
async def graphql_replay(state: State, req: GQLReplayRequest) -> JSONResponse:
    entry = require_entry(state, req.entry_id)

    body: dict = {}
    if entry.req_body:
        with contextlib.suppress(Exception):
            body = json.loads(entry.req_body)
    if req.query:
        body["query"] = req.query
    if req.variables:
        body["variables"] = req.variables
    if req.operation_name:
        body["operationName"] = req.operation_name

    start = time.monotonic()
    try:
        async with http_client(DEFAULT_TIMEOUT) as client:
            resp = await client.post(
                entry.base_url, json=body, headers=flatten_headers(entry.req_headers)
            )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=502)

    is_json = "json" in resp.headers.get("content-type", "")
    return JSONResponse(
        {
            "status_code": resp.status_code,
            "duration_ms": elapsed_ms(start),
            "body": resp.json() if is_json else resp.text,
        }
    )
