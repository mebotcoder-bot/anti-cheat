#!/usr/bin/env python3
"""
Key generation and at-rest storage.

EC P-256 (NIST prime256v1) keys — the same curve TPM attestation keys use.
Private keys are written PKCS#8 PEM, optionally encrypted with a passphrase
(from ACHEAT_KEY_PASSPHRASE) so a stolen key file is not directly usable.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def generate() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _passphrase() -> bytes | None:
    p = os.environ.get("ACHEAT_KEY_PASSPHRASE")
    return p.encode() if p else None


def save(key: ec.EllipticCurvePrivateKey, path: str) -> None:
    pw = _passphrase()
    enc = (
        serialization.BestAvailableEncryption(pw)
        if pw
        else serialization.NoEncryption()
    )
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8, enc))
    os.chmod(path, 0o600)


def load(path: str) -> ec.EllipticCurvePrivateKey:
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=_passphrase())


def load_or_create(path: str) -> ec.EllipticCurvePrivateKey:
    if os.path.exists(path):
        return load(path)
    key = generate()
    save(key, path)
    return key


def public_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
