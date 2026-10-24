"""Courier wire framing."""

from __future__ import annotations

import hashlib
import socket
import struct
from dataclasses import dataclass
from typing import Iterable


MAX_FRAME_SIZE = 1_048_576
MAX_FIELD_SIZE = 0xFFFF

CONNECT = 7
CONNECT_ACK = 8
FILTER = 9
MESSAGE = 10
RECEIPT = 11
KEEPALIVE = 12
KEEPALIVE_ACK = 13
SCOPED_TOKEN_REQUEST = 17
SCOPED_TOKEN_RESPONSE = 18
SET_STATE = 20


class CourierProtocolError(ValueError):
    """The peer sent a malformed or unsupported Courier frame."""


@dataclass(frozen=True)
class Packet:
    command: int
    fields: tuple[tuple[int, bytes], ...]
    raw: bytes

    def field_map(self) -> dict[int, bytes]:
        result: dict[int, bytes] = {}
        for field_id, value in self.fields:
            if field_id in result:
                raise CourierProtocolError(f"duplicate field {field_id}")
            result[field_id] = value
        return result


def encode_packet(command: int, fields: Iterable[tuple[int, bytes]]) -> bytes:
    if not 0 <= command <= 0xFF:
        raise ValueError("command must fit in one byte")
    body = bytearray()
    for field_id, value in fields:
        if not 0 <= field_id <= MAX_FIELD_SIZE:
            raise ValueError("field id must fit in two bytes")
        value = bytes(value)
        if len(value) > MAX_FIELD_SIZE:
            raise ValueError(f"field {field_id} exceeds {MAX_FIELD_SIZE} bytes")
        body.extend(struct.pack(">BH", field_id, len(value)))
        body.extend(value)
    if len(body) > MAX_FRAME_SIZE:
        raise ValueError("packet exceeds the Courier frame limit")
    return struct.pack(">BI", command, len(body)) + body


def read_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError("Courier connection closed")
        result.extend(chunk)
    return bytes(result)


def read_packet(sock: socket.socket) -> Packet:
    header = read_exact(sock, 5)
    command, body_size = struct.unpack(">BI", header)
    if body_size > MAX_FRAME_SIZE:
        raise CourierProtocolError(f"oversized Courier frame: {body_size}")
    body = read_exact(sock, body_size)
    fields: list[tuple[int, bytes]] = []
    position = 0
    while position < len(body):
        if position + 3 > len(body):
            raise CourierProtocolError("truncated field header")
        field_id, size = struct.unpack_from(">BH", body, position)
        position += 3
        if position + size > len(body):
            raise CourierProtocolError(f"truncated field {field_id}")
        fields.append((field_id, body[position : position + size]))
        position += size
    return Packet(command=command, fields=tuple(fields), raw=header + body)


def topic_hash(topic: str | bytes) -> bytes:
    if isinstance(topic, str):
        topic = topic.encode("utf-8")
    if not topic:
        raise ValueError("topic must not be empty")
    return hashlib.sha1(topic).digest()
