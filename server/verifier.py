#!/usr/bin/env python3
"""
Attestation verifier — the authoritative trust decision.

Order matters: cryptographic gates first (signature, nonce, enrollment). If the
report is not a fresh, authentic statement from an enrolled client, nothing else
is worth evaluating and we hard-fail. Only then do we score the integrity signals.
"""
from __future__ import annotations

import base64
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protocol import Report, Verdict, canonical_bytes  # noqa: E402
from server import policy  # noqa: E402


def _verify_signature(pubkey_pem: str, data: bytes, signature_b64: str) -> bool:
    try:
        pub = serialization.load_pem_public_key(pubkey_pem.encode("ascii"))
        pub.verify(base64.b64decode(signature_b64), data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def _kernel_tuple(kernel: dict) -> tuple[int, int, int, int] | None:
    try:
        maj, minr, mic = (int(x) for x in kernel["base_version"].split("."))
        return (maj, minr, mic, int(kernel["abi"]))
    except (KeyError, ValueError, AttributeError):
        return None


def verify(report_dict: dict, signature_b64: str, enrolled_pubkey: str | None,
           nonce_ok: bool) -> Verdict:
    report = Report.from_dict(report_dict)
    score = 100
    reasons: list[str] = []

    # --- Cryptographic gates (any failure = hard fail) -------------------------
    if enrolled_pubkey is None:
        return Verdict("FAIL", 0, ["client is not enrolled"])

    if not nonce_ok:
        return Verdict("FAIL", 0, ["nonce invalid, expired, or replayed"])

    if not _verify_signature(enrolled_pubkey, canonical_bytes(report.to_dict()), signature_b64):
        return Verdict("FAIL", 0, ["report signature does not verify"])

    reasons.append("signature + nonce verified (authentic, fresh)")

    # --- TPM strength ----------------------------------------------------------
    tpm_mode = report.tpm.get("mode")
    if tpm_mode == "tpm":
        # Production: verify the quote signature and PCR digests here against
        # policy.KNOWN_GOOD_PCRS. (Requires the enrolled AK + reference PCRs.)
        reasons.append("TPM quote present (hardware-rooted)")
    else:
        score -= policy.WEIGHTS["no_tpm"]
        reasons.append("software attestation only (no TPM) -15")

    # --- Kernel flavour + version ---------------------------------------------
    kernel = report.kernel
    if kernel.get("flavour_official") is False:
        score -= policy.WEIGHTS["kernel_flavour"]
        reasons.append(f"non-official kernel flavour {kernel.get('flavour')!r} -40")

    kt = _kernel_tuple(kernel)
    if kt is not None and kt < policy.MIN_KERNEL:
        score -= policy.WEIGHTS["kernel_version"]
        reasons.append(f"kernel older than policy minimum {policy.MIN_KERNEL} -30")

    # --- Integrity signals -----------------------------------------------------
    sig = report.signals

    taint = sig.get("taint", {})
    if taint.get("available") and not taint.get("clean", True):
        score -= policy.WEIGHTS["taint"]
        reasons.append(f"kernel tainted (mask={taint.get('value')}) -25")

    sb = sig.get("secure_boot", {})
    if sb.get("available") and sb.get("enabled") is False:
        score -= policy.WEIGHTS["secure_boot"]
        reasons.append("Secure Boot disabled -20")

    mods = sig.get("modules", {})
    if mods.get("available"):
        bad = sorted(set(mods.get("loaded", [])) & policy.BANNED_MODULES)
        if bad:
            score -= policy.WEIGHTS["banned_module"]
            reasons.append(f"banned modules loaded: {bad} -60")

    dm = sig.get("dev_mem", {})
    if dm.get("exposed"):
        score -= policy.WEIGHTS["dev_mem"]
        reasons.append(f"raw memory devices exposed: {dm.get('exposed')} -25")

    ld = sig.get("ld_preload", {})
    if ld.get("ld_preload"):
        score -= policy.WEIGHTS["ld_preload"]
        reasons.append(f"LD_PRELOAD injection: {ld.get('ld_preload')!r} -30")

    dbg = sig.get("debugger", {})
    if dbg.get("available") and not dbg.get("clean", True):
        score -= policy.WEIGHTS["debugger"]
        reasons.append(f"debugger attached (TracerPid={dbg.get('tracer_pid')}) -35")

    score = max(0, score)
    if score >= policy.PASS_AT:
        verdict = "PASS"
    elif score >= policy.FLAG_AT:
        verdict = "FLAG"
    else:
        verdict = "FAIL"

    return Verdict(verdict, score, reasons)
