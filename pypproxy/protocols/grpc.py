from __future__ import annotations

import logging
import struct
from typing import NamedTuple

logger = logging.getLogger(__name__)


class GrpcFrame(NamedTuple):
    compressed: bool
    data: bytes


def is_grpc(headers: dict) -> bool:
    ct = headers.get("content-type", [""])[0]
    return ct.startswith("application/grpc")


def decode_frames(data: bytes) -> list[GrpcFrame]:
    frames: list[GrpcFrame] = []
    offset = 0
    while offset + 5 <= len(data):
        compressed = bool(data[offset])
        length = struct.unpack_from(">I", data, offset + 1)[0]
        offset += 5
        if offset + length > len(data):
            break
        frames.append(GrpcFrame(compressed=compressed, data=data[offset : offset + length]))
        offset += length
    return frames


def encode_frame(frame: GrpcFrame) -> bytes:
    header = struct.pack(">BI", int(frame.compressed), len(frame.data))
    return header + frame.data


def log_frames(entry_id: int, direction: str, data: bytes) -> None:
    for i, frame in enumerate(decode_frames(data)):
        logger.debug(
            "grpc frame entry=%d dir=%s index=%d compressed=%s len=%d",
            entry_id,
            direction,
            i,
            frame.compressed,
            len(frame.data),
        )
