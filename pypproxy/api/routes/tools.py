"""Request-manipulation tools: replay, bulk send, macro, A/B test."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from pypproxy.api.deps import State, require_entry
from pypproxy.api.schemas import ABTestRequest, BulkRequest, MacroRunRequest, ReplayRequest
from pypproxy.tools.ab_test import run_ab_test
from pypproxy.tools.bulk import BulkPayload, bulk_send, race_send
from pypproxy.tools.macro import MacroRunner, MacroStep
from pypproxy.tools.replay import ReplayOptions, replay_many

router = APIRouter(prefix="/api", tags=["tools"])


@router.post("/replay")
async def replay(state: State, req: ReplayRequest) -> JSONResponse:
    entry = require_entry(state, req.entry_id)
    opts = ReplayOptions(
        override_host=req.options.get("override_host", ""),
        extra_headers=req.options.get("extra_headers", {}),
        timeout_seconds=req.options.get("timeout_seconds", 30),
        count=req.options.get("count", 1),
    )
    results = await replay_many(entry, opts)
    return JSONResponse([r.to_dict() for r in results])


@router.post("/bulk")
async def bulk(state: State, req: BulkRequest) -> JSONResponse:
    entry = require_entry(state, req.entry_id)
    if req.mode == "race":
        results = await race_send(entry, count=req.count)
    else:
        payloads = [
            BulkPayload(
                label=p.get("label", f"payload-{i}"),
                override_body=p.get("body", "").encode() if p.get("body") else b"",
                override_headers=p.get("headers", {}),
                override_path=p.get("path", ""),
            )
            for i, p in enumerate(req.payloads)
        ]
        results = await bulk_send(entry, payloads, concurrency=req.concurrency)
    return JSONResponse([r.to_dict() for r in results])


@router.post("/macro/run")
async def run_macro(req: MacroRunRequest) -> JSONResponse:
    steps = [MacroStep.from_dict(s) for s in req.steps]
    results = await MacroRunner().run(steps, timeout=req.timeout)
    return JSONResponse([r.to_dict() for r in results])


@router.post("/ab")
async def ab_test(state: State, req: ABTestRequest) -> JSONResponse:
    entry = require_entry(state, req.entry_id)
    result = await run_ab_test(entry, req.host_b, req.scheme_b)
    return JSONResponse(result.to_dict())
