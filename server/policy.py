#!/usr/bin/env python3
"""
Server-side trust policy.

This is where "what a good machine looks like" is defined. In production the
known-good PCR set and module allowlist come from your own reference images;
here they are sane Ubuntu defaults. Everything is server-owned so the client
cannot influence the bar it must clear.
"""
from __future__ import annotations

# Minimum acceptable Ubuntu kernel (major, minor, micro, abi). Kernels older than
# this are treated as downgrades/unofficial. Bump as you ship security updates.
MIN_KERNEL = (6, 8, 0, 45)

# Kernel modules that must never appear on a trusted client (cheat drivers,
# raw-memory shims, known injectors). Extend from real detections.
BANNED_MODULES = {
    "wireguard_cheat",   # example placeholder
    "vboxdrv_hook",
    "memflow",
    "kvm_cheat",
}

# Known-good TPM PCR digests (sha256) for measured boot. In production these come
# from a reference image via `tpm2_pcrread`; here they are the deterministic demo
# profile so the verifier's real quote-checking path can be exercised.
import os as _os  # noqa: E402
import sys as _sys  # noqa: E402

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
from crypto.pcrs import known_good_hex as _known_good_hex  # noqa: E402

KNOWN_GOOD_PCRS: dict[str, str] = _known_good_hex()

# Scoring weights: each failed check subtracts from a starting score of 100.
WEIGHTS = {
    "signature_invalid": 100,   # cannot trust anything -> hard fail
    "nonce_invalid": 100,       # replay / stale -> hard fail
    "not_enrolled": 100,
    "kernel_flavour": 40,
    "kernel_version": 30,
    "taint": 25,
    "secure_boot": 20,
    "banned_module": 60,
    "dev_mem": 25,
    "ld_preload": 30,
    "debugger": 35,
    "no_tpm": 15,               # software attestation is weaker, not fatal
    "tpm_pcr_policy": 50,       # PCRs differ from known-good boot (bad boot state)
}

# Verdict thresholds on the final score.
PASS_AT = 85
FLAG_AT = 60  # >=FLAG_AT and <PASS_AT => FLAG (allow but watch); below => FAIL
