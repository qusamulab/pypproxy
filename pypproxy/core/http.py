"""Shared HTTP plumbing for every outbound request pypproxy makes.

Replay, bulk sending, scanning and the proxy itself all talk to upstream hosts
under the same constraints: certificates are whatever the target presents (we
are the MITM, so verification is meaningless), HTTP/2 must be negotiable, and
redirects must not be followed silently or the tool would hide the very
response the user asked about.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping

import httpx

DEFAULT_TIMEOUT = 30

#: Headers that describe a single hop and must not be replayed upstream.
HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

#: Headers that describe the *original* body and go stale once it is rewritten.
BODY_HEADERS = frozenset({"content-length"})

#: Headers the proxy must strip before relaying a request upstream. Host is
#: deliberately kept: the client picked the virtual host and we are not entitled
#: to second-guess it.
FORWARD_DROP_HEADERS = HOP_BY_HOP_HEADERS | BODY_HEADERS

#: Headers a replayed request must let the client library re-derive, not copy
#: verbatim from the capture — otherwise the replay targets the original host or
#: advertises a body length that no longer matches.
REPLAY_DROP_HEADERS = HOP_BY_HOP_HEADERS | BODY_HEADERS | frozenset({"host"})


def client(timeout: float = DEFAULT_TIMEOUT, **kwargs: object) -> httpx.AsyncClient:
    """An `httpx.AsyncClient` configured the way every pypproxy caller wants it."""
    kwargs.setdefault("verify", False)
    kwargs.setdefault("http2", True)
    kwargs.setdefault("follow_redirects", False)
    return httpx.AsyncClient(timeout=timeout, **kwargs)  # type: ignore[arg-type]


def flatten_headers(
    headers: Mapping[str, list[str]],
    *,
    drop: Iterable[str] = (),
) -> dict[str, str]:
    """Collapse the multi-value header map used by `Entry` into httpx's flat form."""
    dropped = {name.lower() for name in drop}
    return {k: ", ".join(v) for k, v in headers.items() if k.lower() not in dropped}


def build_url(scheme: str, host: str, path: str, query: str = "") -> str:
    return f"{scheme}://{host}{path}" + (f"?{query}" if query else "")


def elapsed_ms(start: float) -> int:
    """Milliseconds since a `time.monotonic()` reading."""
    return int((time.monotonic() - start) * 1000)
