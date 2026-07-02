#!/usr/bin/env python3
"""
TPM 2.0 quote verification.

Given an attestation key public part, the quote blob, the nonce we issued, and
the known-good PCR policy, decide whether the quote proves a good boot state.
This is the real check a hardware quote gets:

  1. signature over the marshaled TPMS_ATTEST verifies under the AK.
  2. magic == TPM_GENERATED_VALUE (a genuine TPM structure, not app data).
  3. type == TPM_ST_ATTEST_QUOTE.
  4. extraData == the nonce we issued (anti-replay / freshness).
  5. the signed pcrDigest matches the digest recomputed from the supplied PCR
     values (binds the values to the signature).
  6. every selected PCR value equals the server's known-good value (policy).

Any failure means the boot state is not attestable as good.
"""
from __future__ import annotations

import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from crypto.softtpm import (
    TPM_GENERATED_VALUE,
    TPM_ST_ATTEST_QUOTE,
    pcr_digest,
)


def _unmarshal_attest(blob: bytes) -> dict:
    off = 0
    (magic,) = struct.unpack_from(">I", blob, off); off += 4
    (typ,) = struct.unpack_from(">H", blob, off); off += 2
    (nlen,) = struct.unpack_from(">H", blob, off); off += 2
    nonce = blob[off:off + nlen]; off += nlen
    (count,) = struct.unpack_from(">B", blob, off); off += 1
    select = list(blob[off:off + count]); off += count
    (dlen,) = struct.unpack_from(">H", blob, off); off += 2
    digest = blob[off:off + dlen]; off += dlen
    return {"magic": magic, "type": typ, "nonce": nonce,
            "select": select, "digest": digest}


def verify_quote(ak_pub: ec.EllipticCurvePublicKey, quote: dict,
                 expected_nonce: str, known_good: dict[str, str]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    try:
        attest = bytes.fromhex(quote["attest"])
        sig = bytes.fromhex(quote["sig"])
    except (KeyError, ValueError):
        return False, ["malformed quote"]

    # 1. signature
    try:
        ak_pub.verify(sig, attest, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False, ["TPM quote signature invalid"]

    a = _unmarshal_attest(attest)

    # 2 + 3. structure sanity
    if a["magic"] != TPM_GENERATED_VALUE:
        return False, ["not a genuine TPM structure (bad magic)"]
    if a["type"] != TPM_ST_ATTEST_QUOTE:
        return False, ["attestation is not a quote"]

    # 4. freshness
    if a["nonce"] != bytes.fromhex(expected_nonce):
        return False, ["quote nonce does not match issued nonce (stale/replay)"]

    # 5. bind supplied PCR values to the signed digest
    supplied = {int(k): bytes.fromhex(v) for k, v in quote.get("pcrs", {}).items()}
    if pcr_digest(supplied, a["select"]) != a["digest"]:
        return False, ["PCR values do not match signed digest"]

    # 6. policy: PCRs must equal known-good
    bad = []
    for i in a["select"]:
        want = known_good.get(str(i))
        if want is None or supplied.get(i, b"").hex() != want:
            bad.append(i)
    if bad:
        reasons.append(f"PCRs {bad} differ from known-good boot state")
        return False, reasons

    return True, ["TPM quote valid: fresh, signed, PCRs match known-good boot"]
