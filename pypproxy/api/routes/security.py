"""Active scanning and authorization checks."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from pypproxy.api.deps import State, require_entry
from pypproxy.api.schemas import ScanRequest
from pypproxy.security.idor import run_idor_checks
from pypproxy.security.scanner import run_scan

router = APIRouter(prefix="/api", tags=["security"])


@router.post("/scan")
async def active_scan(state: State, req: ScanRequest) -> JSONResponse:
    entry = require_entry(state, req.entry_id)
    results = await run_scan(entry, categories=req.categories or None, concurrency=req.concurrency)
    return JSONResponse([r.to_dict() for r in results])


@router.post("/idor")
async def idor_check(state: State, data: dict) -> JSONResponse:
    entry_id = data.get("entry_id")
    if not entry_id:
        raise HTTPException(status_code=400, detail="entry_id required")
    entry = require_entry(state, entry_id)
    results = await run_idor_checks(entry, baseline_status=data.get("baseline_status", 0))
    return JSONResponse([r.to_dict() for r in results])
