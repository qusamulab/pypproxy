"""Request bodies accepted by the HTTP API."""

from __future__ import annotations

from pydantic import BaseModel


class ReplayRequest(BaseModel):
    entry_id: int
    options: dict = {}


class BulkRequest(BaseModel):
    entry_id: int
    payloads: list[dict] = []
    count: int = 10
    concurrency: int = 10
    mode: str = "payloads"  # "payloads" or "race"


class ScanRequest(BaseModel):
    entry_id: int
    categories: list[str] = []
    concurrency: int = 5


class MacroRunRequest(BaseModel):
    steps: list[dict] = []
    timeout: int = 30


class ABTestRequest(BaseModel):
    entry_id: int
    host_b: str
    scheme_b: str = ""


class IntrospectRequest(BaseModel):
    url: str
    headers: dict[str, str] = {}


class GQLReplayRequest(BaseModel):
    entry_id: int
    query: str = ""
    variables: dict = {}
    operation_name: str = ""
