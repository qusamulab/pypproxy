from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from pypproxy.core.http import REPLAY_DROP_HEADERS, elapsed_ms, flatten_headers
from pypproxy.core.http import client as http_client
from pypproxy.store.models import Entry


@dataclass
class MacroStep:
    name: str
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    extract: dict[str, str] = field(default_factory=dict)  # var_name -> jsonpath-like
    assert_status: int = 0
    delay_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "extract": self.extract,
            "assert_status": self.assert_status,
            "delay_ms": self.delay_ms,
        }

    @classmethod
    def from_dict(cls, d: dict) -> MacroStep:
        return cls(
            name=d.get("name", ""),
            method=d.get("method", "GET"),
            url=d.get("url", ""),
            headers=d.get("headers", {}),
            body=d.get("body", ""),
            extract=d.get("extract", {}),
            assert_status=d.get("assert_status", 0),
            delay_ms=d.get("delay_ms", 0),
        )

    @classmethod
    def from_entry(cls, entry: Entry, name: str = "") -> MacroStep:
        url = entry.url
        headers = flatten_headers(entry.req_headers, drop=REPLAY_DROP_HEADERS)
        body = entry.req_body.decode("utf-8", errors="replace") if entry.req_body else ""
        return cls(
            name=name or f"{entry.method} {entry.path}",
            method=entry.method,
            url=url,
            headers=headers,
            body=body,
        )


@dataclass
class StepResult:
    step_name: str
    status_code: int = 0
    body: str = ""
    duration_ms: int = 0
    error: str = ""
    extracted: dict[str, str] = field(default_factory=dict)
    assertion_passed: bool = True

    def to_dict(self) -> dict:
        return {
            "step": self.step_name,
            "status_code": self.status_code,
            "body_preview": self.body[:200],
            "duration_ms": self.duration_ms,
            "error": self.error,
            "extracted": self.extracted,
            "assertion_passed": self.assertion_passed,
        }


class MacroRunner:
    def __init__(self) -> None:
        self._variables: dict[str, str] = {}

    def set_variable(self, name: str, value: str) -> None:
        self._variables[name] = value

    def get_variables(self) -> dict[str, str]:
        return dict(self._variables)

    def _substitute(self, text: str) -> str:
        """Replace {{var}} placeholders with variable values."""

        def _replace(m: re.Match) -> str:
            return self._variables.get(m.group(1).strip(), m.group(0))

        return re.sub(r"\{\{(.+?)\}\}", _replace, text)

    def _extract_value(self, body: str, path: str) -> str:
        """Extract a value from JSON response body using dot-notation path."""
        try:
            data = json.loads(body)
            parts = path.strip(".").split(".")
            for part in parts:
                data = data[int(part)] if isinstance(data, list) else data[part]
            return str(data)
        except Exception:
            return ""

    async def run(
        self,
        steps: list[MacroStep],
        timeout: int = 30,
        on_step: Any = None,  # callback(step_name, result)
    ) -> list[StepResult]:
        results: list[StepResult] = []

        for step in steps:
            if step.delay_ms > 0:
                await asyncio.sleep(step.delay_ms / 1000)

            url = self._substitute(step.url)
            body = self._substitute(step.body)
            headers = {k: self._substitute(v) for k, v in step.headers.items()}

            result = StepResult(step_name=step.name)
            start = time.monotonic()

            try:
                async with http_client(timeout) as client:
                    resp = await client.request(
                        method=step.method,
                        url=url,
                        headers=headers,
                        content=body.encode() if body else b"",
                    )
                result.status_code = resp.status_code
                result.duration_ms = elapsed_ms(start)
                try:
                    result.body = resp.text
                except Exception:
                    result.body = ""

                # Extract variables
                for var_name, path in step.extract.items():
                    val = self._extract_value(result.body, path)
                    if val:
                        self._variables[var_name] = val
                        result.extracted[var_name] = val

                # Assert status
                if step.assert_status and resp.status_code != step.assert_status:
                    result.assertion_passed = False
                    result.error = f"Expected {step.assert_status}, got {resp.status_code}"

            except Exception as e:
                result.error = str(e)
                result.duration_ms = elapsed_ms(start)

            results.append(result)

            if on_step:
                on_step(step.name, result)

        return results


def macro_from_entries(entries: list[Entry]) -> list[MacroStep]:
    """Convert a list of captured entries into macro steps."""
    return [
        MacroStep.from_entry(e, name=f"Step {i + 1}: {e.method} {e.path}")
        for i, e in enumerate(entries)
    ]


def macro_to_json(steps: list[MacroStep]) -> str:
    return json.dumps([s.to_dict() for s in steps], indent=2, ensure_ascii=False)


def macro_from_json(data: str) -> list[MacroStep]:
    return [MacroStep.from_dict(d) for d in json.loads(data)]
