#!/usr/bin/env python3
"""
Minimal X.509 PKI for client attestation identity.

Enrollment is now certificate-based, not trust-on-first-use raw keys:
  * the server runs a CA (self-signed root).
  * a client generates a keypair and a CSR; the server issues a client cert.
  * every attestation carries the client cert; the server verifies the cert
    chains to its CA before trusting the key that signed the report.

This is how real fleets bind an identity to a key. The verdict signing key is
also a cert under the same CA so the client can authenticate the server.
"""
from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_DAY = datetime.timedelta(days=1)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def create_ca(cn: str, key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _DAY)
        .not_valid_after(now + 3650 * _DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )


def make_csr(key: ec.EllipticCurvePrivateKey, cn: str) -> x509.CertificateSigningRequest:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(_name(cn))
        .sign(key, hashes.SHA256())
    )


def issue_cert(ca_key: ec.EllipticCurvePrivateKey, ca_cert: x509.Certificate,
               csr: x509.CertificateSigningRequest, days: int = 30) -> x509.Certificate:
    if not csr.is_signature_valid:
        raise ValueError("CSR self-signature invalid")
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _DAY)
        .not_valid_after(now + days * _DAY)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )


def verify_chain(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """Cert is signed by the CA and currently within its validity window."""
    now = datetime.datetime.now(datetime.timezone.utc)
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        return False
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
        return True
    except (InvalidSignature, ValueError):
        return False


# --- PEM (de)serialization helpers ------------------------------------------
def cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def cert_from_pem(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode("ascii"))


def csr_to_pem(csr: x509.CertificateSigningRequest) -> str:
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def csr_from_pem(pem: str) -> x509.CertificateSigningRequest:
    return x509.load_pem_x509_csr(pem.encode("ascii"))
