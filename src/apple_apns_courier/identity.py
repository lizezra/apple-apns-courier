"""Activation certificate and private-key loading."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class IdentityError(ValueError):
    """The supplied activation identity is invalid or mismatched."""


def _load_certificate(data: bytes) -> x509.Certificate:
    if b"-----BEGIN CERTIFICATE-----" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def _load_private_key(data: bytes, password: bytes | None):
    if b"-----BEGIN" in data:
        return serialization.load_pem_private_key(data, password=password)
    return serialization.load_der_private_key(data, password=password)


def _public_der(key) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@dataclass(frozen=True)
class ActivationIdentity:
    certificate_der: bytes
    certificate: x509.Certificate
    private_key: rsa.RSAPrivateKey

    @classmethod
    def from_files(
        cls,
        certificate_path: str | Path,
        private_key_path: str | Path,
        password: bytes | None = None,
    ) -> "ActivationIdentity":
        certificate = _load_certificate(Path(certificate_path).read_bytes())
        private_key = _load_private_key(
            Path(private_key_path).read_bytes(),
            password=password,
        )
        return cls.from_objects(certificate, private_key)

    @classmethod
    def from_bytes(
        cls,
        certificate_data: bytes,
        private_key_data: bytes,
        password: bytes | None = None,
    ) -> "ActivationIdentity":
        certificate = _load_certificate(certificate_data)
        private_key = _load_private_key(private_key_data, password=password)
        return cls.from_objects(certificate, private_key)

    @classmethod
    def from_objects(cls, certificate, private_key) -> "ActivationIdentity":
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise IdentityError("activation private key must be RSA")
        cert_public = certificate.public_key()
        if not isinstance(cert_public, rsa.RSAPublicKey):
            raise IdentityError("activation certificate must use an RSA key")
        if _public_der(cert_public) != _public_der(private_key.public_key()):
            raise IdentityError("private key does not match certificate")
        return cls(
            certificate_der=certificate.public_bytes(serialization.Encoding.DER),
            certificate=certificate,
            private_key=private_key,
        )

    @property
    def key_size(self) -> int:
        return self.private_key.key_size

    def sign_sha1_pkcs1v15(self, data: bytes) -> bytes:
        return self.private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA1(),
        )

    def verify_sha1_pkcs1v15(self, signature: bytes, data: bytes) -> None:
        self.certificate.public_key().verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA1(),
        )

    @property
    def certificate_sha256(self) -> str:
        return hashlib.sha256(self.certificate_der).hexdigest()
