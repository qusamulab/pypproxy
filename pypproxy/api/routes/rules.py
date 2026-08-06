"""Rule engine and scope configuration."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse, Response

from pypproxy.api.deps import State
from pypproxy.rules import Rule
from pypproxy.store.scope import ScopeRule

router = APIRouter(prefix="/api", tags=["rules"])


@router.get("/rules")
async def list_rules(state: State) -> JSONResponse:
    return JSONResponse([r.to_dict() for r in state.rules.list()])


@router.post("/rules")
async def create_rule(state: State, data: dict) -> JSONResponse:
    rule = Rule.from_dict(data)
    state.rules.add(rule)
    return JSONResponse(rule.to_dict())


@router.put("/rules/{rule_id}")
async def update_rule(state: State, rule_id: int, data: dict) -> JSONResponse:
    rule = Rule.from_dict({**data, "id": rule_id})
    state.rules.update(rule)
    return JSONResponse(rule.to_dict())


@router.delete("/rules/{rule_id}")
async def delete_rule(state: State, rule_id: int) -> Response:
    state.rules.delete(rule_id)
    return Response(status_code=204)


def _scope_payload(state: State) -> dict:
    return {
        "enabled": state.scope.enabled,
        "rules": [r.to_dict() for r in state.scope.list()],
    }


@router.get("/scope")
async def list_scope(state: State) -> JSONResponse:
    return JSONResponse(_scope_payload(state))


@router.post("/scope")
async def update_scope(state: State, data: dict) -> JSONResponse:
    if "enabled" in data:
        state.scope.set_enabled(bool(data["enabled"]))
    if "add" in data:
        state.scope.add(
            ScopeRule(
                pattern=data["add"].get("pattern", ""),
                mode=data["add"].get("mode", "glob"),
            )
        )
    if "remove" in data:
        state.scope.remove(data["remove"])
    return JSONResponse(_scope_payload(state))
