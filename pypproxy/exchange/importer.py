from __future__ import annotations

import base64
import contextlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from pypproxy.store.models import Entry
from pypproxy.store.store import Store

logger = logging.getLogger(__name__)


def import_har(data: str | bytes, store: Store) -> int:
    """Import entries from a HAR file string/bytes. Returns count imported."""
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")

    har = json.loads(data)
    entries = har.get("log", har).get("entries", [])
    count = 0

    for item in entries:
        try:
            entry = _har_entry_to_entry(item)
            store.add(entry)
            count += 1
        except Exception as e:
            logger.debug("Skipping HAR entry: %s", e)

    return count


def import_json(data: str | bytes, store: Store) -> int:
    """Import entries from a paxy JSON export. Returns count imported."""
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")

    parsed = json.loads(data)
    items = parsed.get("entries", []) if isinstance(parsed, dict) else parsed

    count = 0
    for item in items:
        try:
            entry = _json_to_entry(item)
            store.add(entry)
            count += 1
        except Exception as e:
            logger.debug("Skipping entry: %s", e)

    return count


def import_file(path: str, store: Store) -> int:
    """Auto-detect format from file extension and import."""
    p = Path(path)
    data = p.read_bytes()
    if p.suffix.lower() == ".har":
        return import_har(data, store)
    # Try HAR first, then paxy JSON
    try:
        parsed = json.loads(data)
        if "log" in parsed and "entries" in parsed.get("log", {}):
            return import_har(data, store)
        return import_json(data, store)
    except Exception as e:
        raise ValueError(f"Cannot parse {path}: {e}") from e


def _har_entry_to_entry(item: dict) -> Entry:
    req = item.get("request", {})
    resp = item.get("response", {})

    # Parse URL
    url = req.get("url", "")
    scheme, _, rest = url.partition("://")
    host, _, path_q = rest.partition("/")
    path, _, query = ("/" + path_q).partition("?")
    query = query or ""

    # Request headers
    req_headers: dict[str, list[str]] = {}
    for h in req.get("headers", []):
        req_headers.setdefault(h["name"].lower(), []).append(h["value"])

    # Request body
    req_body = b""
    if post_data := req.get("postData", {}):
        text = post_data.get("text", "")
        req_body = text.encode() if text else b""

    # Response headers
    resp_headers: dict[str, list[str]] = {}
    for h in resp.get("headers", []):
        resp_headers.setdefault(h["name"].lower(), []).append(h["value"])

    # Response body
    resp_body = b""
    content = resp.get("content", {})
    if text := content.get("text", ""):
        if content.get("encoding") == "base64":
            resp_body = base64.b64decode(text)
        else:
            resp_body = text.encode("utf-8", errors="replace")

    # Timestamp
    started = item.get("startedDateTime", "")
    try:
        created_at = datetime.fromisoformat(started.replace("Z", "+00:00"))
    except Exception:
        created_at = datetime.now(UTC)

    return Entry(
        method=req.get("method", "GET"),
        scheme=scheme or "https",
        host=host,
        path=path or "/",
        query=query,
        req_headers=req_headers,
        req_body=req_body,
        status_code=resp.get("status", 0),
        resp_headers=resp_headers,
        resp_body=resp_body,
        duration_ms=int(item.get("time", 0)),
        protocol="https" if scheme == "https" else "http",
        created_at=created_at,
    )


def _json_to_entry(item: dict) -> Entry:
    req_body = b""
    if rb := item.get("req_body", ""):
        try:
            req_body = base64.b64decode(rb)
        except Exception:
            req_body = rb.encode()

    resp_body = b""
    if rsb := item.get("resp_body", ""):
        try:
            resp_body = base64.b64decode(rsb)
        except Exception:
            resp_body = rsb.encode()

    created_at = datetime.now(UTC)
    if ts := item.get("created_at", ""):
        with contextlib.suppress(Exception):
            created_at = datetime.fromisoformat(ts)

    return Entry(
        method=item.get("method", "GET"),
        scheme=item.get("scheme", "https"),
        host=item.get("host", ""),
        path=item.get("path", "/"),
        query=item.get("query", ""),
        req_headers=item.get("req_headers", {}),
        req_body=req_body,
        status_code=item.get("status_code", 0),
        resp_headers=item.get("resp_headers", {}),
        resp_body=resp_body,
        duration_ms=item.get("duration_ms", 0),
        protocol=item.get("protocol", "https"),
        tags=item.get("tags", []),
        modified=item.get("modified", False),
        created_at=created_at,
    )
