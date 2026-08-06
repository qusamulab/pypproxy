from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class PendingRequest:
    id: int
    method: str
    scheme: str
    host: str
    path: str
    headers: dict[str, list[str]]
    body: bytes
    # modified versions (user edits)
    edited_headers: dict[str, list[str]] = field(default_factory=dict)
    edited_body: bytes = b""
    _event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    _decision: str = "forward"  # forward | drop

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "method": self.method,
            "scheme": self.scheme,
            "host": self.host,
            "path": self.path,
            "headers": self.headers,
            "body": base64.b64encode(self.body).decode() if self.body else "",
        }


class InterceptManager:
    """Controls whether requests are paused for manual review."""

    def __init__(self) -> None:
        self._enabled = False
        self._pending: dict[int, PendingRequest] = {}
        self._counter = 0
        self._lock = asyncio.Lock()
        self._subscribers: list[asyncio.Queue] = []

    @property
    def enabled(self) -> bool:
        return self._enabled

    def set_enabled(self, value: bool) -> None:
        self._enabled = value
        if not value:
            # release all pending requests
            for req in list(self._pending.values()):
                req._decision = "forward"
                req._event.set()

    async def intercept(
        self,
        method: str,
        scheme: str,
        host: str,
        path: str,
        headers: dict[str, list[str]],
        body: bytes,
    ) -> tuple[dict[str, list[str]], bytes, bool]:
        """Pause the request for manual review.

        Returns (headers, body, drop) where drop=True means the request should be blocked.
        If interception is disabled, returns immediately with original values.
        """
        if not self._enabled:
            return headers, body, False

        async with self._lock:
            self._counter += 1
            req_id = self._counter

        req = PendingRequest(
            id=req_id,
            method=method,
            scheme=scheme,
            host=host,
            path=path,
            headers=dict(headers),
            body=body,
            edited_headers=dict(headers),
            edited_body=body,
        )

        async with self._lock:
            self._pending[req_id] = req
        self._notify(req)

        logger.debug("intercept: waiting for decision on %s %s%s", method, host, path)
        await req._event.wait()

        async with self._lock:
            self._pending.pop(req_id, None)

        drop = req._decision == "drop"
        return req.edited_headers, req.edited_body, drop

    def forward(self, req_id: int, headers: dict | None = None, body: bytes | None = None) -> None:
        req = self._pending.get(req_id)
        if req:
            if headers is not None:
                req.edited_headers = headers
            if body is not None:
                req.edited_body = body
            req._decision = "forward"
            req._event.set()

    def drop(self, req_id: int) -> None:
        req = self._pending.get(req_id)
        if req:
            req._decision = "drop"
            req._event.set()

    def list_pending(self) -> list[PendingRequest]:
        return list(self._pending.values())

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=64)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with contextlib.suppress(ValueError):
            self._subscribers.remove(q)

    def _notify(self, req: PendingRequest) -> None:
        for q in self._subscribers:
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(req)
