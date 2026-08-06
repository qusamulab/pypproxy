from __future__ import annotations

import json
import shlex

from pypproxy.core.http import REPLAY_DROP_HEADERS, flatten_headers
from pypproxy.store.models import Entry


def to_curl(entry: Entry) -> str:
    url = entry.url

    parts = ["curl", "-s"]

    if entry.method != "GET":
        parts += ["-X", entry.method]

    for k, vs in entry.req_headers.items():
        kl = k.lower()
        if kl in ("host", "content-length", "connection", "proxy-connection"):
            continue
        parts += ["-H", f"{k}: {', '.join(vs)}"]

    if entry.req_body:
        try:
            text = entry.req_body.decode("utf-8")
            parts += ["--data-raw", text]
        except Exception:
            parts += ["--data-binary", f"@- <<< '{entry.req_body.hex()}'"]

    parts.append(shlex.quote(url))
    return " \\\n  ".join(parts)


def to_python_requests(entry: Entry) -> str:
    url = entry.url

    headers = flatten_headers(entry.req_headers, drop=REPLAY_DROP_HEADERS)

    lines = ["import requests", ""]
    lines.append(f"url = {url!r}")

    if headers:
        lines.append(f"headers = {json.dumps(headers, indent=4)}")
    else:
        lines.append("headers = {}")

    ct = entry.req_headers.get("content-type", [""])[0].lower()
    method = entry.method.lower()

    if entry.req_body:
        if "json" in ct:
            try:
                data = json.loads(entry.req_body)
                lines.append(f"json_data = {json.dumps(data, indent=4)}")
                lines.append(f"\nresp = requests.{method}(url, headers=headers, json=json_data)")
            except Exception:
                lines.append(f"data = {entry.req_body!r}")
                lines.append(f"\nresp = requests.{method}(url, headers=headers, data=data)")
        elif "x-www-form-urlencoded" in ct:
            lines.append(f"data = {entry.req_body.decode(errors='replace')!r}")
            lines.append(f"\nresp = requests.{method}(url, headers=headers, data=data)")
        else:
            lines.append(f"data = {entry.req_body!r}")
            lines.append(f"\nresp = requests.{method}(url, headers=headers, data=data)")
    else:
        lines.append(f"\nresp = requests.{method}(url, headers=headers)")

    lines += ["", "print(resp.status_code)", "print(resp.text)"]
    return "\n".join(lines)


def to_fetch(entry: Entry) -> str:
    url = entry.url

    headers = flatten_headers(entry.req_headers, drop=REPLAY_DROP_HEADERS)

    opts: dict = {"method": entry.method, "headers": headers}

    ct = entry.req_headers.get("content-type", [""])[0].lower()
    if entry.req_body:
        if "json" in ct:
            try:
                opts["body"] = json.dumps(json.loads(entry.req_body))
            except Exception:
                opts["body"] = entry.req_body.decode(errors="replace")
        else:
            opts["body"] = entry.req_body.decode(errors="replace")

    opts_json = json.dumps(opts, indent=2)
    return f"const resp = await fetch({url!r}, {opts_json});\nconst data = await resp.json();\nconsole.log(data);"


def to_httpie(entry: Entry) -> str:
    url = entry.url

    parts = ["http", entry.method, shlex.quote(url)]

    for k, vs in entry.req_headers.items():
        kl = k.lower()
        if kl in ("host", "content-length", "connection"):
            continue
        parts.append(f"{k}:{', '.join(vs)}")

    ct = entry.req_headers.get("content-type", [""])[0].lower()
    if entry.req_body and "json" in ct:
        try:
            data = json.loads(entry.req_body)
            for k, v in data.items() if isinstance(data, dict) else []:
                if isinstance(v, str):
                    parts.append(f"{k}={v!r}")
                else:
                    parts.append(f"{k}:={json.dumps(v)}")
        except Exception:
            pass

    return " \\\n  ".join(parts)
