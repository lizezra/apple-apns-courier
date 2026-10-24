from __future__ import annotations

import hashlib
import struct

import pytest

from apple_apns_courier.protocol import (
    CourierProtocolError,
    MAX_FRAME_SIZE,
    Packet,
    encode_packet,
    read_packet,
    topic_hash,
)


class BytesSocket:
    def __init__(self, data: bytes, chunk_size: int = 3) -> None:
        self.data = data
        self.position = 0
        self.chunk_size = chunk_size

    def recv(self, size: int) -> bytes:
        if self.position >= len(self.data):
            return b""
        count = min(size, self.chunk_size, len(self.data) - self.position)
        result = self.data[self.position : self.position + count]
        self.position += count
        return result


def test_packet_round_trip() -> None:
    wire = encode_packet(17, [(1, b"base"), (2, b"topic")])
    packet = read_packet(BytesSocket(wire))
    assert packet.command == 17
    assert packet.fields == ((1, b"base"), (2, b"topic"))
    assert packet.raw == wire


def test_packet_uses_big_endian_lengths() -> None:
    wire = encode_packet(7, [(5, b"\x00\x00\x00\x41")])
    assert wire[:5] == struct.pack(">BI", 7, 7)
    assert wire[5:8] == struct.pack(">BH", 5, 4)


def test_duplicate_fields_are_rejected_on_lookup() -> None:
    packet = Packet(8, ((1, b"\x00"), (1, b"\x00")), b"")
    with pytest.raises(CourierProtocolError):
        packet.field_map()


def test_truncated_field_is_rejected() -> None:
    wire = struct.pack(">BI", 8, 4) + struct.pack(">BH", 1, 2) + b"\x00"
    with pytest.raises(CourierProtocolError):
        read_packet(BytesSocket(wire))


def test_oversized_frame_is_rejected_before_body_read() -> None:
    wire = struct.pack(">BI", 8, MAX_FRAME_SIZE + 1)
    with pytest.raises(CourierProtocolError):
        read_packet(BytesSocket(wire))


def test_oversized_outbound_field_is_rejected() -> None:
    with pytest.raises(ValueError):
        encode_packet(7, [(1, b"x" * 65536)])


def test_topic_hash_is_sha1_of_utf8() -> None:
    topic = "com.example.application"
    assert topic_hash(topic) == hashlib.sha1(topic.encode()).digest()
