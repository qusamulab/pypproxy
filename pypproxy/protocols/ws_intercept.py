from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class WSFrame:
    direction: str  # client | server
    opcode: int
    payload: bytes
    entry_id: int

    def text(self) -> str:
        if self.opcode == 1:
            return self.payload.decode("utf-8", errors="replace")
        return f"<binary {len(self.payload)} bytes>"

    def to_dict(self) -> dict:
        return {
            "direction": self.direction,
            "opcode": self.opcode,
            "payload": base64.b64encode(self.payload).decode() if self.payload else "",
            "text": self.text(),
            "entry_id": self.entry_id,
        }


class WSInterceptManager:
    """
    Intercepts WebSocket frames for manual review, similar to HTTP intercept.
    """

    def __init__(self) -> None:
        self._enabled = False
        self._pending: dict[int, tuple[WSFrame, asyncio.Event, list[bytes]]] = {}
        self._counter = 0
        self._lock = asyncio.Lock()
        self._subscribers: list[asyncio.Queue] = []

    @property
    def enabled(self) -> bool:
        return self._enabled

    def set_enabled(self, value: bool) -> None:
        self._enabled = value
        if not value:
            # release all pending frames
            for frame_id in list(self._pending):
                _, event, _ = self._pending[frame_id]
                event.set()

    async def intercept(self, frame: WSFrame) -> bytes:
        """
        Pause the frame for manual review.
        Returns the (possibly edited) payload.
        """
        if not self._enabled:
            return frame.payload

        async with self._lock:
            self._counter += 1
            frame_id = self._counter
            event = asyncio.Event()
            result: list[bytes] = [frame.payload]
            self._pending[frame_id] = (frame, event, result)

        self._notify(frame_id, frame)

        await event.wait()

        async with self._lock:
            _, _, result = self._pending.pop(frame_id, (None, None, [frame.payload]))

        return result[0]

    def forward(self, frame_id: int, payload: bytes | None = None) -> None:
        entry = self._pending.get(frame_id)
        if entry:
            frame, event, result = entry
            if payload is not None:
                result[0] = payload
            event.set()

    def drop(self, frame_id: int) -> None:
        entry = self._pending.get(frame_id)
        if entry:
            frame, event, result = entry
            result[0] = b""  # empty = drop
            event.set()

    def list_pending(self) -> list[dict]:
        return [{"id": fid, **frame.to_dict()} for fid, (frame, _, _) in self._pending.items()]

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=128)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with contextlib.suppress(ValueError):
            self._subscribers.remove(q)

    def _notify(self, frame_id: int, frame: WSFrame) -> None:
        data = {"id": frame_id, **frame.to_dict()}
        for q in self._subscribers:
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(data)
