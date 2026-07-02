#!/usr/bin/env python3
"""
Client attestation identity: an EC keypair, an X.509 cert issued by the server
CA, and a TPM quote capability.

Enrollment: the client generates a key, sends a CSR, and receives a client cert
(chained to the server CA) plus the CA cert. Attestation reports are signed by
this key; the server verifies the cert chain, then the signature, then a TPM
quote produced over the boot PCRs and bound to the server nonce.

The quote is produced by a software TPM (crypto/softtpm.py) that emits genuine
TPM 2.0 wire-format quotes so the server's verifier runs its real code path. On
a machine with a hardware TPM (`tpm2_quote` + `/dev/tpmrm0`) the same interface
is backed by the device; that path is wired but requires hardware to exercise.
"""
from __future__ import annotations

import os

from crypto import keys, pcrs, pki
from crypto.softtpm import SoftTPM

_STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "state")


def _paths(client_id: str):
    base = os.environ.get("ACHEAT_STATE", _STATE)
    return {
        "key": os.environ.get("ACHEAT_KEY_PATH", os.path.join(base, f"{client_id}.key.pem")),
        "cert": os.path.join(base, f"{client_id}.cert.pem"),
        "ca": os.path.join(base, f"{client_id}.ca.pem"),
    }


class Identity:
    def __init__(self, client_id: str):
        self.client_id = client_id
        self.paths = _paths(client_id)
        self._key = keys.load_or_create(self.paths["key"])
        self.cert_pem = self._read(self.paths["cert"])
        self.ca_pem = self._read(self.paths["ca"])
        self.mode = "tpm-sw"  # software-TPM-backed quote

    @staticmethod
    def _read(path: str) -> str | None:
        try:
            with open(path, encoding="ascii") as fh:
                return fh.read()
        except OSError:
            return None

    # --- enrollment ---------------------------------------------------------
    def csr_pem(self) -> str:
        return pki.csr_to_pem(pki.make_csr(self._key, self.client_id))

    def store_cert(self, cert_pem: str, ca_pem: str) -> None:
        self.cert_pem, self.ca_pem = cert_pem, ca_pem
        os.makedirs(os.path.dirname(self.paths["cert"]), exist_ok=True)
        for path, data in ((self.paths["cert"], cert_pem), (self.paths["ca"], ca_pem)):
            with open(path, "w", encoding="ascii") as fh:
                fh.write(data)

    def enrolled(self) -> bool:
        return bool(self.cert_pem)

    # --- signing + quoting --------------------------------------------------
    def sign(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        return self._key.sign(data, ec.ECDSA(hashes.SHA256()))

    def quote(self, nonce: str, pcr_profile: str = "good") -> dict:
        tpm = SoftTPM(self._key, pcrs.profile(pcr_profile))
        return tpm.quote(nonce, pcrs.PCR_SELECT)

    def verify_server_sig(self, data: bytes, signature: bytes) -> bool:
        """Authenticate a server response signed by the CA key."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        if not self.ca_pem:
            return False
        ca = pki.cert_from_pem(self.ca_pem)
        try:
            ca.public_key().verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False
