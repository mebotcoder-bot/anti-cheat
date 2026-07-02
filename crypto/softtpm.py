#!/usr/bin/env python3
"""
Software TPM 2.0 quote generator (test stand-in for hardware).

Produces a quote in the TPM 2.0 *wire format* for the security-relevant fields
of TPMS_ATTEST, so the verifier (crypto/tpm_verify.py) exercises the exact same
parse-and-verify path it would run on a real `tpm2_quote` blob. It does NOT
emulate a full TPM (no EK/credential-activation, clockInfo, or firmwareVersion);
those are noted where a hardware deployment would add them.

TPMS_ATTEST (subset) laid out as:
    magic:      4 bytes  = 0xFF544347 (TPM_GENERATED_VALUE)
    type:       2 bytes  = 0x8018     (TPM_ST_ATTEST_QUOTE)
    extraData:  u16 len + bytes        (qualifying data == server nonce)
    pcrSelect:  u8 count + count*u8    (selected PCR indices)
    pcrDigest:  u16 len + bytes        (sha256 over concatenated selected PCRs)
The signature is ECDSA-P256/SHA256 over the marshaled attest bytes.
"""
from __future__ import annotations

import hashlib
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_QUOTE = 0x8018


def marshal_attest(nonce: bytes, pcr_select: list[int], pcr_digest: bytes) -> bytes:
    out = struct.pack(">I", TPM_GENERATED_VALUE)
    out += struct.pack(">H", TPM_ST_ATTEST_QUOTE)
    out += struct.pack(">H", len(nonce)) + nonce
    out += struct.pack(">B", len(pcr_select)) + bytes(pcr_select)
    out += struct.pack(">H", len(pcr_digest)) + pcr_digest
    return out


def pcr_digest(pcrs: dict[int, bytes], select: list[int]) -> bytes:
    """TPM composite digest: sha256 of concatenated PCR values, index order."""
    h = hashlib.sha256()
    for i in sorted(select):
        h.update(pcrs[i])
    return h.digest()


class SoftTPM:
    def __init__(self, ak_key: ec.EllipticCurvePrivateKey, pcrs: dict[int, bytes]):
        self._ak = ak_key
        self._pcrs = pcrs

    def quote(self, nonce_hex: str, select: list[int]) -> dict:
        nonce = bytes.fromhex(nonce_hex)
        digest = pcr_digest(self._pcrs, select)
        attest = marshal_attest(nonce, select, digest)
        signature = self._ak.sign(attest, ec.ECDSA(hashes.SHA256()))
        return {
            "mode": "tpm",
            "attest": attest.hex(),
            "sig": signature.hex(),
            # PCR values are sent so the verifier can re-derive & bind the digest;
            # they are only trusted because the signed digest commits to them.
            "pcrs": {str(i): self._pcrs[i].hex() for i in select},
            "select": select,
        }
