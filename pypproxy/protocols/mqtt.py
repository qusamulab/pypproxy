from __future__ import annotations

import logging
import struct
from typing import NamedTuple

logger = logging.getLogger(__name__)

PACKET_TYPES = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
}


class MQTTFrame(NamedTuple):
    packet_type: int
    packet_name: str
    flags: int
    payload: bytes
    topic: str
    qos: int


def is_mqtt(data: bytes) -> bool:
    """Heuristic: check if data looks like an MQTT CONNECT packet."""
    if len(data) < 10:
        return False
    packet_type = (data[0] >> 4) & 0x0F
    if packet_type != 1:
        return False
    try:
        proto_len = struct.unpack_from(">H", data, 2)[0]
        proto_name = data[4 : 4 + proto_len]
        return proto_name in (b"MQTT", b"MQIsdp")
    except Exception:
        return False


def decode_frames(data: bytes) -> list[MQTTFrame]:
    frames: list[MQTTFrame] = []
    offset = 0
    while offset < len(data):
        result = _read_frame(data, offset)
        if result is None:
            break
        f, consumed = result
        frames.append(f)
        offset += consumed
    return frames


def _read_frame(data: bytes, offset: int) -> tuple[MQTTFrame, int] | None:
    if offset >= len(data):
        return None
    byte0 = data[offset]
    packet_type = (byte0 >> 4) & 0x0F
    flags = byte0 & 0x0F
    offset += 1

    remaining_length = 0
    multiplier = 1
    len_bytes = 0
    for _ in range(4):
        if offset >= len(data):
            return None
        b = data[offset]
        offset += 1
        len_bytes += 1
        remaining_length += (b & 0x7F) * multiplier
        multiplier *= 128
        if not (b & 0x80):
            break

    if offset + remaining_length > len(data):
        return None

    payload = data[offset : offset + remaining_length]
    consumed = 1 + len_bytes + remaining_length

    topic = ""
    qos = (flags >> 1) & 0x03
    if packet_type == 3 and len(payload) >= 2:
        topic_len = struct.unpack_from(">H", payload, 0)[0]
        if 2 + topic_len <= len(payload):
            topic = payload[2 : 2 + topic_len].decode(errors="replace")

    return MQTTFrame(
        packet_type=packet_type,
        packet_name=PACKET_TYPES.get(packet_type, f"UNKNOWN({packet_type})"),
        flags=flags,
        payload=payload,
        topic=topic,
        qos=qos,
    ), consumed


def log_frames(entry_id: int, direction: str, data: bytes) -> None:
    for frame in decode_frames(data):
        logger.debug(
            "mqtt frame entry=%d dir=%s type=%s topic=%r qos=%d len=%d",
            entry_id,
            direction,
            frame.packet_name,
            frame.topic,
            frame.qos,
            len(frame.payload),
        )
