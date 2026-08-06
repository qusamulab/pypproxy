from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs

import yaml

from pypproxy.store.models import Entry


@dataclass
class PathOperation:
    method: str
    path: str
    path_params: list[str]
    query_params: list[str]
    request_body: dict | None
    request_content_type: str
    response_schemas: dict[int, dict]  # status_code -> schema
    tags: list[str] = field(default_factory=list)
    count: int = 1


def _infer_path_template(path: str) -> tuple[str, list[str]]:
    """Replace UUID/numeric segments with {param} placeholders."""
    params: list[str] = []
    parts = path.split("/")
    new_parts: list[str] = []
    param_idx = 0
    for part in parts:
        if re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", part, re.I
        ) or re.match(r"^\d+$", part):
            name = f"id{param_idx}"
            params.append(name)
            new_parts.append(f"{{{name}}}")
            param_idx += 1
        else:
            new_parts.append(part)
    return "/".join(new_parts), params


def _json_to_schema(value: Any, depth: int = 0) -> dict:
    if depth > 5:
        return {}
    if isinstance(value, bool):
        return {"type": "boolean", "example": value}
    if isinstance(value, int):
        return {"type": "integer", "example": value}
    if isinstance(value, float):
        return {"type": "number", "example": value}
    if isinstance(value, str):
        schema: dict = {"type": "string", "example": value}
        if re.match(r"\d{4}-\d{2}-\d{2}", value):
            schema["format"] = "date"
        elif re.match(r"[0-9a-f]{8}-[0-9a-f]{4}", value, re.I):
            schema["format"] = "uuid"
        return schema
    if isinstance(value, list):
        if value:
            return {"type": "array", "items": _json_to_schema(value[0], depth + 1)}
        return {"type": "array", "items": {}}
    if isinstance(value, dict):
        props = {k: _json_to_schema(v, depth + 1) for k, v in value.items()}
        return {"type": "object", "properties": props}
    return {}


def _body_to_schema(body: bytes, content_type: str) -> dict | None:
    if not body:
        return None
    ct = content_type.lower()
    if "json" in ct:
        try:
            data = json.loads(body)
            return _json_to_schema(data)
        except Exception:
            pass
    return {"type": "string"}


def _extract_tag(host: str, path: str) -> str:
    parts = [
        p
        for p in path.split("/")
        if p and not re.match(r"^\d+$", p) and not re.match(r"^[0-9a-f-]{36}$", p, re.I)
    ]
    return parts[0] if parts else host


def generate(entries: list[Entry], title: str = "", version: str = "1.0.0") -> dict:
    if not title:
        hosts = {e.host for e in entries if e.host}
        title = next(iter(hosts), "API") if hosts else "API"

    ops: dict[tuple[str, str], PathOperation] = {}

    for e in entries:
        if not e.host or not e.method or not e.path:
            continue
        if e.protocol not in ("http", "https", "graphql"):
            continue

        path_tmpl, path_params = _infer_path_template(e.path)
        key = (path_tmpl, e.method.upper())

        ct_req = e.req_headers.get("content-type", [""])[0]
        ct_resp = e.resp_headers.get("content-type", [""])[0]
        req_schema = _body_to_schema(e.req_body, ct_req)

        resp_schema = _body_to_schema(e.resp_body, ct_resp) if e.resp_body else None

        query_params: list[str] = []
        if e.query:
            query_params = list(parse_qs(e.query).keys())

        tag = _extract_tag(e.host, path_tmpl)

        if key not in ops:
            ops[key] = PathOperation(
                method=e.method.upper(),
                path=path_tmpl,
                path_params=path_params,
                query_params=query_params,
                request_body=req_schema,
                request_content_type=ct_req,
                response_schemas={e.status_code: resp_schema} if e.status_code else {},
                tags=[tag],
            )
        else:
            op = ops[key]
            op.count += 1
            for qp in query_params:
                if qp not in op.query_params:
                    op.query_params.append(qp)
            if e.status_code and e.status_code not in op.response_schemas:
                op.response_schemas[e.status_code] = resp_schema

    # Build OpenAPI structure
    paths: dict[str, dict] = defaultdict(dict)

    for (path_tmpl, method), op in sorted(ops.items()):
        method_lower = method.lower()
        operation: dict = {
            "tags": op.tags,
            "summary": f"{method} {path_tmpl}",
            "operationId": _make_operation_id(method, path_tmpl),
            "parameters": [],
            "responses": {},
        }

        # Path params
        for p in op.path_params:
            operation["parameters"].append(
                {
                    "name": p,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                }
            )

        # Query params
        for q in op.query_params:
            operation["parameters"].append(
                {
                    "name": q,
                    "in": "query",
                    "required": False,
                    "schema": {"type": "string"},
                }
            )

        # Request body
        if op.request_body and method in ("POST", "PUT", "PATCH"):
            ct = op.request_content_type or "application/json"
            if not ct:
                ct = "application/json"
            operation["requestBody"] = {
                "required": True,
                "content": {ct: {"schema": op.request_body}},
            }

        # Responses
        for status, schema in sorted(op.response_schemas.items()):
            if not status:
                continue
            resp: dict = {"description": _status_description(status)}
            if schema:
                ct = "application/json"
                resp["content"] = {ct: {"schema": schema}}
            operation["responses"][str(status)] = resp

        if not operation["responses"]:
            operation["responses"]["200"] = {"description": "OK"}

        if not operation["parameters"]:
            del operation["parameters"]

        paths[path_tmpl][method_lower] = operation

    return {
        "openapi": "3.0.3",
        "info": {"title": title, "version": version},
        "paths": dict(paths),
    }


def to_yaml(spec: dict) -> str:
    return yaml.dump(spec, default_flow_style=False, allow_unicode=True, sort_keys=False)


def to_json(spec: dict) -> str:
    return json.dumps(spec, indent=2, ensure_ascii=False)


def _make_operation_id(method: str, path: str) -> str:
    parts = [method.lower()]
    for seg in path.split("/"):
        if seg.startswith("{"):
            parts.append("By" + seg[1:-1].capitalize())
        elif seg:
            parts.append(seg.replace("-", "_").replace(".", "_"))
    return "".join(p.capitalize() if i > 0 else p for i, p in enumerate(parts))


def _status_description(code: int) -> str:
    return {
        200: "OK",
        201: "Created",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found",
        304: "Not Modified",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        422: "Unprocessable Entity",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
    }.get(code, "Response")
