#!/usr/bin/env python3
"""
Client attestation identity and quoting.

Two modes:

  * hardware (production): the signing key is a TPM 2.0 restricted key and the
    report carries a `tpm2_quote` over the boot PCRs, using the server nonce as
    qualifying data. The server verifies the quote against a known-good PCR
    policy — this is what a rooted OS cannot forge.

  * software (dev/off-target): an on-disk EC P-256 key stands in for the TPM so
    the challenge/response/verify protocol can be exercised end to end. Clearly
    NOT secure against a machine that can read the key file; used only for tests.

The public key is registered with the server at enrollment (trust-on-first-use).
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,  # noqa: F401  (kept for parity/debugging)
)

_KEY_PATH_DEFAULT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "state", "agent_key.pem"
)


def _key_path() -> str:
    """Resolved at call time so tests can point distinct clients at distinct keys."""
    return os.environ.get("ACHEAT_KEY_PATH", _KEY_PATH_DEFAULT)


def _tpm_available() -> bool:
    from shutil import which

    return which("tpm2_quote") is not None and os.path.exists("/dev/tpmrm0")


class SoftwareIdentity:
    """EC P-256 signer persisted to disk. Stand-in for a TPM restricted key."""

    mode = "software"

    def __init__(self, key_path: str | None = None):
        self.key_path = key_path or _key_path()
        self._key = self._load_or_create()

    def _load_or_create(self) -> ec.EllipticCurvePrivateKey:
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as fh:
                return serialization.load_pem_private_key(fh.read(), password=None)
        key = ec.generate_private_key(ec.SECP256R1())
        os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
        with open(self.key_path, "wb") as fh:
            fh.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
        os.chmod(self.key_path, 0o600)
        return key

    def public_pem(self) -> str:
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data, ec.ECDSA(hashes.SHA256()))

    def quote(self, nonce: str) -> dict:
        """No hardware quote in software mode; the signature is the whole proof."""
        return {"mode": "software", "note": "no TPM quote; report signature only"}


class TpmIdentity:
    """Production identity backed by tpm2-tools. Wired for Linux+TPM targets."""

    mode = "tpm"

    def __init__(self, pcrs: str = "sha256:0,1,4,7"):
        self.pcrs = pcrs
        # In production the AK is created/persisted once via tpm2_createak and its
        # public part is enrolled with the server. Left as the deployment step.

    def public_pem(self) -> str:  # pragma: no cover - requires hardware
        raise NotImplementedError("enroll the TPM AK public key at provisioning time")

    def sign(self, data: bytes) -> bytes:  # pragma: no cover - requires hardware
        raise NotImplementedError("TPM signing happens inside tpm2_quote below")

    def quote(self, nonce: str) -> dict:  # pragma: no cover - requires hardware
        import base64
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            msg, sig, pcr = (os.path.join(d, n) for n in ("q.msg", "q.sig", "q.pcr"))
            subprocess.run(
                ["tpm2_quote", "-c", "ak.ctx", "-l", self.pcrs, "-q", nonce,
                 "-m", msg, "-s", sig, "-o", pcr, "-g", "sha256"],
                check=True,
            )
            enc = lambda p: base64.b64encode(open(p, "rb").read()).decode()  # noqa: E731
            return {"mode": "tpm", "pcrs": self.pcrs,
                    "message": enc(msg), "signature": enc(sig), "pcr_values": enc(pcr)}


def get_identity():
    """Pick the strongest identity available on this machine."""
    return TpmIdentity() if _tpm_available() else SoftwareIdentity()
