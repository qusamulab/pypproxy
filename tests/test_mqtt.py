from __future__ import annotations

import struct

from pypproxy.protocols.mqtt import decode_frames, is_mqtt


def _make_connect_packet() -> bytes:
    proto_name = b"\x00\x04MQTT"
    proto_level = b"\x04"
    connect_flags = b"\x02"  # clean session
    keepalive = b"\x00\x3c"  # 60s
    client_id = struct.pack(">H", len(b"pypproxy-test")) + b"pypproxy-test"
    payload = proto_name + proto_level + connect_flags + keepalive + client_id
    remaining = len(payload)
    return bytes([0x10, remaining]) + payload


def _make_publish_packet(topic: str, message: bytes, qos: int = 0) -> bytes:
    topic_bytes = topic.encode()
    topic_len = struct.pack(">H", len(topic_bytes))
    payload = topic_len + topic_bytes + message
    flags = (qos & 0x03) << 1
    byte0 = 0x30 | flags
    remaining = len(payload)
    return bytes([byte0, remaining]) + payload


def test_is_mqtt_connect():
    packet = _make_connect_packet()
    assert is_mqtt(packet)


def test_is_mqtt_false_for_http():
    assert not is_mqtt(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")


def test_is_mqtt_too_short():
    assert not is_mqtt(b"\x10\x0a")


def test_decode_publish_frame():
    packet = _make_publish_packet("sensors/temp", b"22.5")
    frames = decode_frames(packet)
    assert len(frames) == 1
    assert frames[0].packet_name == "PUBLISH"
    assert frames[0].topic == "sensors/temp"


def test_decode_publish_qos1():
    packet = _make_publish_packet("test/topic", b"hello", qos=1)
    frames = decode_frames(packet)
    assert frames[0].qos == 1


def test_decode_multiple_frames():
    connect = _make_connect_packet()
    publish = _make_publish_packet("t", b"v")
    data = connect + publish
    frames = decode_frames(data)
    assert len(frames) == 2
    assert frames[0].packet_name == "CONNECT"
    assert frames[1].packet_name == "PUBLISH"


def test_decode_empty():
    assert decode_frames(b"") == []


def test_decode_truncated_frame():
    # Truncated payload — should not crash
    frames = decode_frames(b"\x30\x10\x00\x05senso")
    assert isinstance(frames, list)
