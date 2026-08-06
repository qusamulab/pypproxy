"""Rendered summaries of captured traffic."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from pypproxy.api.deps import State
from pypproxy.reporting.report import generate_html, generate_markdown
from pypproxy.store.models import Filter

router = APIRouter(prefix="/api/report", tags=["reporting"])

DEFAULT_TITLE = "pypproxy Report"


@router.get("/html")
async def report_html(
    state: State, host: str = "", title: str = DEFAULT_TITLE
) -> PlainTextResponse:
    entries, _ = state.store.list(Filter(host=host), 0, 0)
    return PlainTextResponse(generate_html(entries, title), media_type="text/html")


@router.get("/markdown")
async def report_markdown(
    state: State, host: str = "", title: str = DEFAULT_TITLE
) -> PlainTextResponse:
    entries, _ = state.store.list(Filter(host=host), 0, 0)
    return PlainTextResponse(generate_markdown(entries, title), media_type="text/markdown")
