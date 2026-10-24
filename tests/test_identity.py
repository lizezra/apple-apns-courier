from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from apple_apns_courier.identity import ActivationIdentity, IdentityError


def identity_pair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Identity")])
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
    return certificate, key


def test_identity_validates_matching_pair() -> None:
    certificate, key = identity_pair()
    identity = ActivationIdentity.from_objects(certificate, key)
    assert identity.key_size == 1024
    assert len(identity.certificate_der) > 0


def test_identity_signs_and_verifies() -> None:
    certificate, key = identity_pair()
    identity = ActivationIdentity.from_objects(certificate, key)
    data = b"synthetic nonce"
    signature = identity.sign_sha1_pkcs1v15(data)
    identity.verify_sha1_pkcs1v15(signature, data)
    assert len(signature) == 128


def test_identity_rejects_mismatched_key() -> None:
    certificate, _ = identity_pair()
    _, other_key = identity_pair()
    with pytest.raises(IdentityError):
        ActivationIdentity.from_objects(certificate, other_key)


def test_identity_loads_der_sources() -> None:
    certificate, key = identity_pair()
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    key_der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    identity = ActivationIdentity.from_bytes(certificate_der, key_der)
    assert identity.certificate_sha256 == identity.certificate_sha256.lower()
