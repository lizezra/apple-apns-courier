"""Device-side Apple Courier client."""

from __future__ import annotations

import json
import secrets
import select
import socket
import time
from dataclasses import dataclass
from pathlib import Path

from .identity import ActivationIdentity
from .protocol import (
    CONNECT,
    CONNECT_ACK,
    FILTER,
    KEEPALIVE,
    KEEPALIVE_ACK,
    MESSAGE,
    RECEIPT,
    SCOPED_TOKEN_REQUEST,
    SCOPED_TOKEN_RESPONSE,
    SET_STATE,
    Packet,
    encode_packet,
    read_packet,
    topic_hash,
)
from .protocol import CourierProtocolError as WireProtocolError
from .transport import CourierTransport, TLSInfo


class APNsCourierError(RuntimeError):
    """An APNs operation failed."""


class CourierConnectError(APNsCourierError):
    """The Courier Connect exchange was rejected."""


class CourierProtocolError(APNsCourierError):
    """A response did not satisfy the Courier protocol."""


@dataclass(frozen=True)
class ScopedToken:
    topic: str
    topic_hash: bytes
    token: bytes


@dataclass(frozen=True)
class Notification:
    topic: str
    destination: bytes
    message_id: bytes
    payload: dict
    raw_payload: bytes
    frame: bytes


def _status(fields: dict[int, bytes]) -> int:
    value = fields.get(1, b"\xff")
    if len(value) != 1:
        raise CourierProtocolError("status field must be one byte")
    return value[0]


class CourierClient:
    def __init__(
        self,
        sock: socket.socket,
        identity: ActivationIdentity,
        tls: TLSInfo,
        base_token: bytes,
    ) -> None:
        self._sock = sock
        self.identity = identity
        self.tls = tls
        self.base_token = bytes(base_token)

    @classmethod
    def connect(
        cls,
        identity: ActivationIdentity,
        host: str = "1-courier.push.apple.com",
        port: int = 5223,
        timeout: float = 20,
        ca_file: str | Path | None = None,
        base_token: bytes | None = None,
    ) -> "CourierClient":
        sock, tls = CourierTransport.connect(
            host=host,
            port=port,
            timeout=timeout,
            ca_file=ca_file,
        )
        try:
            nonce = (
                b"\x00"
                + int(time.time() * 1000).to_bytes(8, "big")
                + secrets.token_bytes(8)
            )
            signature = identity.sign_sha1_pkcs1v15(nonce)
            identity.verify_sha1_pkcs1v15(signature, nonce)
            fields: list[tuple[int, bytes]] = []
            if base_token is not None:
                fields.append((1, base_token))
            fields.extend(
                [
                    (2, b"\x01"),
                    (5, (65).to_bytes(4, "big")),
                    (12, identity.certificate_der),
                    (13, nonce),
                    (14, b"\x01\x01" + signature),
                    (16, (11).to_bytes(2, "big")),
                ]
            )
            sock.sendall(encode_packet(CONNECT, fields))
            ack = cls._wait_for_type(sock, CONNECT_ACK, max_frames=16)
            ack_fields = ack.field_map()
            status = _status(ack_fields)
            if status != 0:
                raise CourierConnectError(f"Courier Connect failed with status {status}")
            returned_token = ack_fields.get(3, base_token)
            if not returned_token:
                raise CourierConnectError("Courier Connect returned no base token")
            client = cls(sock, identity, tls, returned_token)
            client.keepalive()
            return client
        except BaseException:
            sock.close()
            raise

    @staticmethod
    def _wait_for_type(
        sock: socket.socket,
        expected: int,
        max_frames: int = 32,
    ) -> Packet:
        for _ in range(max_frames):
            try:
                packet = read_packet(sock)
            except WireProtocolError as error:
                raise CourierProtocolError(str(error)) from error
            if packet.command == expected:
                return packet
        raise CourierProtocolError(f"Courier response type {expected} not received")

    def keepalive(self) -> None:
        self._sock.sendall(encode_packet(KEEPALIVE, []))
        response = self._wait_for_type(self._sock, KEEPALIVE_ACK, max_frames=16)
        if response.fields:
            raise CourierProtocolError("unexpected payload in Courier keepalive response")

    def request_scoped_token(self, topic: str) -> ScopedToken:
        topic_digest = topic_hash(topic)
        request = encode_packet(
            SCOPED_TOKEN_REQUEST,
            [(1, self.base_token), (2, topic_digest)],
        )
        self._sock.sendall(request)
        response = self._wait_for_type(
            self._sock,
            SCOPED_TOKEN_RESPONSE,
            max_frames=16,
        ).field_map()
        status = _status(response)
        if status != 0:
            raise APNsCourierError(f"scoped token request failed with status {status}")
        token = response.get(2)
        if not token:
            raise CourierProtocolError("scoped token response omitted the token")
        if response.get(3) != topic_digest:
            raise CourierProtocolError("scoped token response topic hash mismatch")
        return ScopedToken(topic=topic, topic_hash=topic_digest, token=bytes(token))

    def subscribe(self, topic: str) -> None:
        digest = topic_hash(topic)
        self._sock.sendall(
            encode_packet(FILTER, [(1, self.base_token), (2, digest)])
        )
        self._sock.sendall(
            encode_packet(
                SET_STATE,
                [(1, b"\x01"), (2, (0x7FFFFFFF).to_bytes(4, "big"))],
            )
        )
        self.keepalive()

    def wait_for_notification(
        self,
        topic: str,
        scoped_token: bytes,
        timeout: float = 120,
    ) -> Notification:
        digest = topic_hash(topic)
        scoped_token = bytes(scoped_token)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("no matching APNs notification received")
            ready, _, _ = select.select([self._sock], [], [], remaining)
            if not ready:
                raise TimeoutError("no matching APNs notification received")
            try:
                packet = read_packet(self._sock)
            except WireProtocolError as error:
                raise CourierProtocolError(str(error)) from error
            if packet.command != MESSAGE:
                continue
            fields = packet.field_map()
            if fields.get(1) != scoped_token:
                continue
            if fields.get(2) != digest:
                continue
            raw_payload = fields.get(3)
            message_id = fields.get(4)
            if raw_payload is None or message_id is None:
                raise CourierProtocolError("notification omitted payload or message id")
            try:
                payload = json.loads(raw_payload)
            except Exception as error:
                raise CourierProtocolError("notification payload is not JSON") from error
            if not isinstance(payload, dict):
                raise CourierProtocolError("notification JSON root must be an object")
            self._sock.sendall(
                encode_packet(
                    RECEIPT,
                    [(1, scoped_token), (4, message_id), (8, b"\x00")],
                )
            )
            return Notification(
                topic=topic,
                destination=scoped_token,
                message_id=message_id,
                payload=payload,
                raw_payload=raw_payload,
                frame=packet.raw,
            )

    def close(self) -> None:
        self._sock.close()

    def __enter__(self) -> "CourierClient":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
