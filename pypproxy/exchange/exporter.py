from __future__ import annotations

import base64
import json
from typing import Any

from pypproxy import __version__
from pypproxy.core.http import flatten_headers
from pypproxy.rules import RuleManager
from pypproxy.store.models import Entry


def export_entries(entries: list[Entry]) -> str:
    """Export entries to JSON string."""
    return json.dumps(
        [e.to_dict() for e in entries],
        indent=2,
        ensure_ascii=False,
    )


def export_rules(rules: RuleManager) -> str:
    """Export rules to JSON string."""
    return json.dumps(
        [r.to_dict() for r in rules.list()],
        indent=2,
        ensure_ascii=False,
    )


def export_all(entries: list[Entry], rules: RuleManager) -> str:
    """Export everything to a single JSON string."""
    return json.dumps(
        {
            "version": 1,
            "entries": [e.to_dict() for e in entries],
            "rules": [r.to_dict() for r in rules.list()],
        },
        indent=2,
        ensure_ascii=False,
    )


def import_rules(data: str, rules: RuleManager) -> int:
    """Import rules from JSON string. Returns count of imported rules."""
    from pypproxy.rules import Rule

    parsed: list[dict[str, Any]] = json.loads(data)
    if isinstance(parsed, dict):
        parsed = parsed.get("rules", [])
    count = 0
    for item in parsed:
        rule = Rule.from_dict(item)
        rules.add(rule)
        count += 1
    return count


def _har_headers(headers: dict[str, list[str]]) -> list[dict[str, str]]:
    return [{"name": k, "value": v} for k, v in flatten_headers(headers).items()]


def export_har(entries: list[Entry]) -> str:
    """Export entries in HAR (HTTP Archive) format."""
    har_entries = []
    for e in entries:
        req_headers = _har_headers(e.req_headers)
        resp_headers = _har_headers(e.resp_headers)
        body_text = ""
        if e.resp_body:
            try:
                body_text = e.resp_body.decode("utf-8", errors="replace")
            except Exception:
                body_text = base64.b64encode(e.resp_body).decode()

        url = e.url

        har_entries.append(
            {
                "startedDateTime": e.created_at.isoformat(),
                "time": e.duration_ms,
                "request": {
                    "method": e.method,
                    "url": url,
                    "httpVersion": "HTTP/1.1",
                    "headers": req_headers,
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": len(e.req_body),
                    "postData": {
                        "mimeType": e.req_headers.get("content-type", [""])[0],
                        "text": e.req_body.decode("utf-8", errors="replace") if e.req_body else "",
                    },
                },
                "response": {
                    "status": e.status_code,
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": resp_headers,
                    "cookies": [],
                    "content": {
                        "size": len(e.resp_body),
                        "mimeType": e.resp_headers.get("content-type", [""])[0],
                        "text": body_text,
                    },
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": len(e.resp_body),
                },
                "cache": {},
                "timings": {"send": 0, "wait": e.duration_ms, "receive": 0},
            }
        )

    return json.dumps(
        {
            "log": {
                "version": "1.2",
                "creator": {"name": "pypproxy", "version": __version__},
                "entries": har_entries,
            }
        },
        indent=2,
        ensure_ascii=False,
    )
