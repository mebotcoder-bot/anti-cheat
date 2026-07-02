#!/usr/bin/env python3
"""
Attestation verifier — the authoritative trust decision.

Gate order (fail-closed): a report is only worth scoring if it is a fresh,
authentic statement from a certificate the server's CA issued, carrying a valid
TPM quote of a known-good boot. Cryptographic failures hard-fail immediately;
only then are the integrity signals scored.
"""
from __future__ import annotations

import base64
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protocol import Report, Verdict, canonical_bytes  # noqa: E402
from server import policy  # noqa: E402
from crypto import pki  # noqa: E402
from crypto.tpm_verify import verify_quote  # noqa: E402


def _kernel_tuple(kernel: dict):
    try:
        maj, minr, mic = (int(x) for x in kernel["base_version"].split("."))
        return (maj, minr, mic, int(kernel["abi"]))
    except (KeyError, ValueError, AttributeError):
        return None


def verify(report_dict: dict, signature_b64: str, cert_pem: str | None,
           ca_cert: Certificate, nonce_ok: bool) -> Verdict:
    report = Report.from_dict(report_dict)
    reasons: list[str] = []

    # --- Cryptographic gates (hard fail) --------------------------------------
    if not cert_pem:
        return Verdict("FAIL", 0, ["no client certificate presented"])
    try:
        cert = pki.cert_from_pem(cert_pem)
    except ValueError:
        return Verdict("FAIL", 0, ["client certificate unparseable"])

    if not pki.verify_chain(cert, ca_cert):
        return Verdict("FAIL", 0, ["client certificate does not chain to CA / expired"])

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if cn != report.client_id:
        return Verdict("FAIL", 0, [f"cert CN {cn!r} != client_id {report.client_id!r}"])

    if not nonce_ok:
        return Verdict("FAIL", 0, ["nonce invalid, expired, or replayed"])

    pub = cert.public_key()
    try:
        pub.verify(base64.b64decode(signature_b64),
                   canonical_bytes(report.to_dict()), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return Verdict("FAIL", 0, ["report signature does not verify"])

    reasons.append("cert chain + report signature + nonce verified")

    score = 100

    # --- TPM quote ------------------------------------------------------------
    tpm = report.tpm
    if tpm.get("mode") == "tpm":
        ok, qreasons = verify_quote(pub, tpm, report.nonce, policy.KNOWN_GOOD_PCRS)
        if ok:
            reasons.append(qreasons[-1])
        elif any("known-good" in r for r in qreasons):
            score -= policy.WEIGHTS["tpm_pcr_policy"]
            reasons.append(f"{qreasons[-1]} -{policy.WEIGHTS['tpm_pcr_policy']}")
        else:
            # signature / magic / nonce failure inside the quote == forgery
            return Verdict("FAIL", 0, [f"TPM quote invalid: {qreasons[-1]}"])
    else:
        score -= policy.WEIGHTS["no_tpm"]
        reasons.append(f"no TPM quote (software attestation) -{policy.WEIGHTS['no_tpm']}")

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

    t = sig.get("taint", {})
    if t.get("available") and not t.get("clean", True):
        score -= policy.WEIGHTS["taint"]
        reasons.append(f"kernel tainted (mask={t.get('value')}) -25")

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
