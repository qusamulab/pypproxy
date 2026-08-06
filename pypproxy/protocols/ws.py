from __future__ import annotations

import asyncio
import logging
import struct

from pypproxy.store.models import Entry
from pypproxy.store.store import Store

logger = logging.getLogger(__name__)

OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA


def is_upgrade(headers: dict) -> bool:
    upgrade = headers.get("upgrade", [""])[0].lower()
    return upgrade == "websocket"


async def relay_frames(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    server_reader: asyncio.StreamReader,
    server_writer: asyncio.StreamWriter,
    entry: Entry,
    store: Store,
) -> None:
    async def _relay(
        src_r: asyncio.StreamReader,
        dst_w: asyncio.StreamWriter,
        direction: str,
    ) -> None:
        try:
            while True:
                frame = await read_frame(src_r)
                if frame is None:
                    break
                fin, opcode, payload = frame
                log_frame(entry.id, direction, opcode, payload)
                await write_frame(dst_w, fin, opcode, payload, mask=False)
                if opcode == OPCODE_CLOSE:
                    break
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass

    await asyncio.gather(
        _relay(client_reader, server_writer, "client"),
        _relay(server_reader, client_writer, "server"),
    )


async def read_frame(
    reader: asyncio.StreamReader,
) -> tuple[bool, int, bytes] | None:
    try:
        header = await reader.readexactly(2)
    except asyncio.IncompleteReadError:
        return None

    fin = bool(header[0] & 0x80)
    opcode = header[0] & 0x0F
    masked = bool(header[1] & 0x80)
    payload_len = header[1] & 0x7F

    if payload_len == 126:
        ext = await reader.readexactly(2)
        payload_len = struct.unpack(">H", ext)[0]
    elif payload_len == 127:
        ext = await reader.readexactly(8)
        payload_len = struct.unpack(">Q", ext)[0]

    mask_key = b""
    if masked:
        mask_key = await reader.readexactly(4)

    payload = await reader.readexactly(payload_len)
    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    return fin, opcode, payload


async def write_frame(
    writer: asyncio.StreamWriter,
    fin: bool,
    opcode: int,
    payload: bytes,
    mask: bool = False,
) -> None:
    b0 = (0x80 if fin else 0x00) | opcode
    length = len(payload)

    if length < 126:
        b1 = length
        header = bytes([b0, b1])
    elif length < 65536:
        b1 = 126
        header = bytes([b0, b1]) + struct.pack(">H", length)
    else:
        b1 = 127
        header = bytes([b0, b1]) + struct.pack(">Q", length)

    writer.write(header + payload)
    await writer.drain()


def log_frame(entry_id: int, direction: str, opcode: int, payload: bytes) -> None:
    if opcode == OPCODE_TEXT:
        logger.debug(
            "ws frame entry=%d dir=%s text=%s",
            entry_id,
            direction,
            payload.decode(errors="replace")[:200],
        )
    elif opcode == OPCODE_BINARY:
        logger.debug("ws frame entry=%d dir=%s binary len=%d", entry_id, direction, len(payload))
