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

# Known-good TPM PCR digests (sha256) for measured boot. Empty here because they
# are image-specific; populate from a reference machine with tpm2_pcrread.
KNOWN_GOOD_PCRS: dict[str, str] = {
    # "0": "<sha256 hex>", "4": "<sha256 hex>", "7": "<sha256 hex>",
}

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
}

# Verdict thresholds on the final score.
PASS_AT = 85
FLAG_AT = 60  # >=FLAG_AT and <PASS_AT => FLAG (allow but watch); below => FAIL
