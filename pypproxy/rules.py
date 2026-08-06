from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


class Action(StrEnum):
    PASSTHROUGH = "passthrough"
    MODIFY = "modify"
    BLOCK = "block"
    REDIRECT = "redirect"


class MatchField(StrEnum):
    HOST = "host"
    PATH = "path"
    METHOD = "method"
    HEADER = "header"
    BODY = "body"


@dataclass
class Condition:
    field: MatchField
    op: str  # equals, contains, prefix, regex
    value: str
    negate: bool = False
    _compiled: re.Pattern | None = field(default=None, init=False, repr=False)

    def matches(self, ctx: MatchContext) -> bool:
        val = self._extract(ctx)
        result = self._apply_op(val)
        return not result if self.negate else result

    def _extract(self, ctx: MatchContext) -> str:
        if self.field == MatchField.HOST:
            return ctx.host
        if self.field == MatchField.PATH:
            return ctx.path
        if self.field == MatchField.METHOD:
            return ctx.method
        if self.field == MatchField.BODY:
            return ctx.body.decode(errors="replace")
        if self.field == MatchField.HEADER:
            name = (
                self.value.split(":")[0].strip().lower()
                if ":" in self.value
                else self.value.lower()
            )
            for k, vs in ctx.headers.items():
                if k.lower() == name:
                    return ", ".join(vs)
        return ""

    def _apply_op(self, val: str) -> bool:
        if self.op == "equals":
            return val == self.value
        if self.op == "contains":
            return self.value in val
        if self.op == "prefix":
            return val.startswith(self.value)
        if self.op == "regex":
            if self._compiled is None:
                self._compiled = re.compile(self.value)
            return bool(self._compiled.search(val))
        return self.value in val


@dataclass
class Modification:
    target: str  # req_header, resp_header, req_body, resp_body
    operation: str  # set, delete, append, replace, find_replace
    key: str = ""
    value: str = ""
    find: str = ""
    replace: str = ""


@dataclass
class Rule:
    id: int = 0
    name: str = ""
    enabled: bool = True
    priority: int = 0
    conditions: list[Condition] = field(default_factory=list)
    action: Action = Action.PASSTHROUGH
    modifications: list[Modification] = field(default_factory=list)
    redirect_url: str = ""

    def matches(self, ctx: MatchContext) -> bool:
        return all(c.matches(ctx) for c in self.conditions)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "enabled": self.enabled,
            "priority": self.priority,
            "conditions": [
                {
                    "field": c.field.value,
                    "op": c.op,
                    "value": c.value,
                    "negate": c.negate,
                }
                for c in self.conditions
            ],
            "action": self.action.value,
            "modifications": [
                {
                    "target": m.target,
                    "operation": m.operation,
                    "key": m.key,
                    "value": m.value,
                    "find": m.find,
                    "replace": m.replace,
                }
                for m in self.modifications
            ],
            "redirect_url": self.redirect_url,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Rule:
        rule = cls(
            id=data.get("id", 0),
            name=data.get("name", ""),
            enabled=data.get("enabled", True),
            priority=data.get("priority", 0),
            action=Action(data.get("action", "passthrough")),
            redirect_url=data.get("redirect_url", ""),
        )
        for c in data.get("conditions", []):
            rule.conditions.append(
                Condition(
                    field=MatchField(c["field"]),
                    op=c.get("op", "contains"),
                    value=c.get("value", ""),
                    negate=c.get("negate", False),
                )
            )
        for m in data.get("modifications", []):
            rule.modifications.append(
                Modification(
                    target=m["target"],
                    operation=m.get("operation", "set"),
                    key=m.get("key", ""),
                    value=m.get("value", ""),
                    find=m.get("find", ""),
                    replace=m.get("replace", ""),
                )
            )
        return rule


@dataclass
class MatchContext:
    method: str
    host: str
    path: str
    headers: dict[str, list[str]]
    body: bytes


class RuleManager:
    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._counter = 0

    def add(self, rule: Rule) -> Rule:
        self._counter += 1
        rule.id = self._counter
        self._rules.append(rule)
        self._sort()
        return rule

    def update(self, rule: Rule) -> None:
        for i, r in enumerate(self._rules):
            if r.id == rule.id:
                self._rules[i] = rule
                self._sort()
                return

    def delete(self, rule_id: int) -> None:
        self._rules = [r for r in self._rules if r.id != rule_id]

    def list(self) -> list[Rule]:
        return list(self._rules)

    def match(self, ctx: MatchContext) -> Rule | None:
        for rule in self._rules:
            if rule.enabled and rule.matches(ctx):
                return rule
        return None

    def _sort(self) -> None:
        self._rules.sort(key=lambda r: r.priority, reverse=True)
