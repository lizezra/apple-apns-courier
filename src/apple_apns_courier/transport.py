"""TLS transport for Apple's Courier service."""

from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path


DEFAULT_HOST = "1-courier.push.apple.com"
DEFAULT_PORT = 5223
COURIER_TLS_NAME = "courier.push.apple.com"
COURIER_ALPN = "apns-security-v3"


class CourierTransportError(OSError):
    """A TLS or TCP Courier connection failed."""


@dataclass(frozen=True)
class TLSInfo:
    host: str
    port: int
    tls_version: str | None
    alpn_protocol: str | None
    peer_certificate_sha256: str


class CourierTransport:
    @staticmethod
    def connect(
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        timeout: float = 20,
        ca_file: str | Path | None = None,
    ) -> tuple[ssl.SSLSocket, TLSInfo]:
        context = ssl.create_default_context()
        if ca_file:
            context.load_verify_locations(cafile=str(ca_file))
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.set_alpn_protocols([COURIER_ALPN])

        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            sock = context.wrap_socket(raw, server_hostname=COURIER_TLS_NAME)
        except BaseException:
            raw.close()
            raise

        alpn = sock.selected_alpn_protocol()
        if alpn not in (None, COURIER_ALPN):
            sock.close()
            raise CourierTransportError(f"unexpected Courier ALPN: {alpn}")
        certificate = sock.getpeercert(binary_form=True)
        if not certificate:
            sock.close()
            raise CourierTransportError("Courier did not present a certificate")
        info = TLSInfo(
            host=host,
            port=port,
            tls_version=sock.version(),
            alpn_protocol=alpn,
            peer_certificate_sha256=hashlib.sha256(certificate).hexdigest(),
        )
        return sock, info
