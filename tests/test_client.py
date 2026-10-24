from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from apple_apns_courier.client import CourierClient
from apple_apns_courier.identity import ActivationIdentity
from apple_apns_courier.protocol import (
    CONNECT,
    CONNECT_ACK,
    KEEPALIVE,
    KEEPALIVE_ACK,
    encode_packet,
    read_packet,
)
from apple_apns_courier.transport import TLSInfo


class FakeSocket:
    def __init__(self, incoming: bytes) -> None:
        self.incoming = incoming
        self.position = 0
        self.outgoing = bytearray()

    def recv(self, size: int) -> bytes:
        if self.position >= len(self.incoming):
            return b""
        chunk = self.incoming[self.position : self.position + size]
        self.position += len(chunk)
        return chunk

    def sendall(self, data: bytes) -> None:
        self.outgoing.extend(data)

    def close(self) -> None:
        pass


def make_identity():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Courier Test")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return ActivationIdentity.from_objects(certificate, key)


def packet_from_prefix(data: bytes):
    top = read_packet(FakeSocket(data))
    return top, len(top.raw)


def test_connect_builds_valid_packet_and_reads_base_token() -> None:
    identity = make_identity()
    base_token = b"b" * 32
    incoming = (
        encode_packet(CONNECT_ACK, [(1, b"\x00"), (3, base_token)])
        + encode_packet(KEEPALIVE_ACK, [])
    )
    sock = FakeSocket(incoming)
    tls = TLSInfo(
        host="test",
        port=5223,
        tls_version="TLSv1.3",
        alpn_protocol=None,
        peer_certificate_sha256="0" * 64,
    )
    with patch(
        "apple_apns_courier.client.CourierTransport.connect",
        return_value=(sock, tls),
    ):
        client = CourierClient.connect(identity, timeout=1)

    first, consumed = packet_from_prefix(bytes(sock.outgoing))
    fields = first.field_map()
    assert first.command == CONNECT
    assert fields[2] == b"\x01"
    assert fields[5] == (65).to_bytes(4, "big")
    assert fields[12] == identity.certificate_der
    assert fields[14][:2] == b"\x01\x01"
    identity.verify_sha1_pkcs1v15(fields[14][2:], fields[13])
    keepalive = read_packet(FakeSocket(bytes(sock.outgoing[consumed:])))
    assert keepalive.command == KEEPALIVE
    assert keepalive.fields == ()
    assert client.base_token == base_token
    client.close()
